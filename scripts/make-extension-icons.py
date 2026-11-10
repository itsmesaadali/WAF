"""Draw the extension's shield icons as PNG files, using only the standard library."""
import struct
import zlib
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "browser-extension" / "icons"
BLUE = (42, 120, 214)
WHITE = (255, 255, 255)


def inside_shield(u: float, v: float) -> bool:
    # u from -1 to 1 across, v from 0 (top) to 1 (bottom).
    if v < 0.06 or v > 0.96:
        return False
    if v < 0.55:
        return abs(u) <= 0.82
    t = (v - 0.55) / 0.41
    return abs(u) <= 0.82 * (1 - t ** 1.6)


def on_check(u: float, v: float) -> bool:
    # Thick tick mark: two line segments.
    def near(ax, ay, bx, by, w=0.11):
        dx, dy = bx - ax, by - ay
        t = max(0.0, min(1.0, ((u - ax) * dx + (v - ay) * dy) / (dx * dx + dy * dy)))
        px, py = ax + t * dx, ay + t * dy
        return (u - px) ** 2 + (v - py) ** 2 <= w * w
    return near(-0.42, 0.46, -0.1, 0.68) or near(-0.1, 0.68, 0.45, 0.28)


def draw(size: int) -> bytes:
    sample = 4
    rows = []
    for y in range(size):
        row = bytearray([0])
        for x in range(size):
            shield = tick = 0
            for sy in range(sample):
                for sx in range(sample):
                    u = ((x + (sx + 0.5) / sample) / size) * 2 - 1
                    v = (y + (sy + 0.5) / sample) / size
                    if inside_shield(u, v):
                        shield += 1
                        if on_check(u, v):
                            tick += 1
            total = sample * sample
            alpha = shield / total
            mix = tick / shield if shield else 0
            color = [round(BLUE[i] * (1 - mix) + WHITE[i] * mix) for i in range(3)]
            row += bytes(color + [round(alpha * 255)])
        rows.append(bytes(row))
    raw = zlib.compress(b"".join(rows), 9)

    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    header = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", raw) + chunk(b"IEND", b"")


OUT.mkdir(parents=True, exist_ok=True)
for size in (16, 32, 48, 128):
    (OUT / f"icon{size}.png").write_bytes(draw(size))
print("icons written")
