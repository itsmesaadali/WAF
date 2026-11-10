"""Per-IP activity tracking: rate limiting, strikes and behaviour numbers for the ML model."""
from __future__ import annotations

import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field

WINDOW_SECONDS = 60.0
STRIKE_WINDOW_SECONDS = 600.0
MAX_TRACKED_IPS = 50_000
MAX_EVENTS_PER_IP = 5_000
INCIDENT_DEDUPE_SECONDS = 60.0


@dataclass
class _IpState:
    hits: deque[tuple[float, int]] = field(default_factory=lambda: deque(maxlen=MAX_EVENTS_PER_IP))
    errors: deque[float] = field(default_factory=lambda: deque(maxlen=MAX_EVENTS_PER_IP))
    strikes: deque[float] = field(default_factory=deque)
    last_incident: dict[str, float] = field(default_factory=dict)


@dataclass(frozen=True)
class IpSnapshot:
    requests_last_minute: int
    unique_paths_last_minute: int
    error_ratio_last_minute: float


class IpActivity:
    """In-memory sliding windows. Memory use is capped, oldest idle IPs are dropped first."""

    def __init__(self, clock=time.monotonic) -> None:  # noqa: ANN001
        self._ips: OrderedDict[str, _IpState] = OrderedDict()
        self._clock = clock

    def _state(self, ip: str) -> _IpState:
        state = self._ips.get(ip)
        if state is None:
            state = _IpState()
            self._ips[ip] = state
            if len(self._ips) > MAX_TRACKED_IPS:
                self._ips.popitem(last=False)
        else:
            self._ips.move_to_end(ip)
        return state

    def record(self, ip: str, path: str) -> IpSnapshot:
        """Record a request and return this IP's recent behaviour, including this request."""
        now = self._clock()
        state = self._state(ip)
        cutoff = now - WINDOW_SECONDS
        while state.hits and state.hits[0][0] < cutoff:
            state.hits.popleft()
        while state.errors and state.errors[0] < cutoff:
            state.errors.popleft()
        state.hits.append((now, hash(path)))
        count = len(state.hits)
        return IpSnapshot(count, len({h for _, h in state.hits}), min(1.0, len(state.errors) / count))

    def record_error(self, ip: str) -> None:
        self._state(ip).errors.append(self._clock())

    def add_strike(self, ip: str) -> int:
        """Record a bad event and return how many happened in the last 10 minutes."""
        now = self._clock()
        strikes = self._state(ip).strikes
        strikes.append(now)
        while strikes and strikes[0] < now - STRIKE_WINDOW_SECONDS:
            strikes.popleft()
        return len(strikes)

    def clear_strikes(self, ip: str) -> None:
        state = self._ips.get(ip)
        if state:
            state.strikes.clear()
            state.hits.clear()

    def should_report(self, ip: str, kind: str) -> bool:
        """Limit repeated incidents of one kind from one IP, so floods don't flood the log."""
        now = self._clock()
        last = self._state(ip).last_incident
        if now - last.get(kind, -INCIDENT_DEDUPE_SECONDS) < INCIDENT_DEDUPE_SECONDS:
            return False
        last[kind] = now
        return True
