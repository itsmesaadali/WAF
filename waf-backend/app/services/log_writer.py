"""Writes logs on a background thread, so visitors never wait for the database."""
from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass
from typing import Any

from ..db import session_scope
from ..models import Incident, IpBan, RequestLog

MAX_QUEUE = 20_000
BATCH_SIZE = 200
FLUSH_SECONDS = 0.5
RETRY_SECONDS = 3.0
_TABLES = {"request": RequestLog, "incident": Incident, "ban": IpBan}


@dataclass
class WriterStats:
    written: int = 0
    dropped: int = 0
    failures: int = 0
    last_error: str | None = None
    last_write_at: float | None = None


class LogWriter:
    def __init__(self) -> None:
        self._queue: queue.Queue[tuple[str, dict[str, Any]]] = queue.Queue(MAX_QUEUE)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._idle = threading.Event()
        self._idle.set()
        self.stats = WriterStats()

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="waf-log-writer", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 10.0) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout)

    def enqueue(self, kind: str, row: dict[str, Any]) -> None:
        """Never blocks. If the database is down long enough to fill the queue, it counts the loss."""
        try:
            self._idle.clear()
            self._queue.put_nowait((kind, row))
        except queue.Full:
            self.stats.dropped += 1

    @property
    def pending(self) -> int:
        return self._queue.qsize()

    def flush(self, timeout: float = 15.0) -> bool:
        """Wait until queued rows are saved. Used by tests and the attack simulator."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._queue.empty() and self._idle.is_set():
                return True
            time.sleep(0.05)
        return False

    def _take_batch(self) -> list[tuple[str, dict[str, Any]]]:
        batch: list[tuple[str, dict[str, Any]]] = []
        try:
            batch.append(self._queue.get(timeout=FLUSH_SECONDS))
            while len(batch) < BATCH_SIZE:
                batch.append(self._queue.get_nowait())
        except queue.Empty:
            pass
        return batch

    def _write(self, batch: list[tuple[str, dict[str, Any]]]) -> None:
        grouped: dict[str, list[dict[str, Any]]] = {}
        for kind, row in batch:
            grouped.setdefault(kind, []).append(row)
        with session_scope() as session:
            for kind, rows in grouped.items():
                session.bulk_insert_mappings(_TABLES[kind], rows)
        self.stats.written += len(batch)
        self.stats.last_write_at = time.time()
        self.stats.last_error = None

    def _run(self) -> None:
        while True:
            batch = self._take_batch()
            if not batch:
                if self._queue.empty():
                    self._idle.set()
                if self._stop.is_set():
                    return
                continue
            # A failed batch is retried, because it stays in memory until saved or shutdown.
            while True:
                try:
                    self._write(batch)
                    break
                except Exception as exc:  # noqa: BLE001 - the writer must outlive database outages
                    self.stats.failures += 1
                    self.stats.last_error = exc.__class__.__name__
                    if self._stop.is_set():
                        self.stats.dropped += len(batch)
                        return
                    time.sleep(RETRY_SECONDS)
            if self._queue.empty():
                self._idle.set()
