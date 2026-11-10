"""Draws File Locker's icons with the standard library only.

Writes PNG files and multi-size .ico files into crates/flk-app/assets/:
  app.ico / app.png        locked padlock on a blue tile (app, vault files)
  tray-locked.ico          the same, for the tray when every vault is locked
  tray-unlocked.ico        open padlock on a green tile, while any vault is unlocked

Run: py -3 tools/make_icons.py
"""

import math
import struct
import zlib
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "crates" / "flk-app" / "assets"
BLUE = (37, 99, 235)
GREEN = (22, 163, 74)
WHITE = (255, 255, 255)
SAMPLES = 4  # supersampling per axis


def rounded_rect(x, y, cx, cy, hw, hh, r):
    """Signed distance to a rounded rectangle (negative inside)."""
    qx = abs(x - cx) - (hw - r)
    qy = abs(y - cy) - (hh - r)
    outside = math.hypot(max(qx, 0.0), max(qy, 0.0))
    inside = min(max(qx, qy), 0.0)
    return outside + inside - r


def shackle(x, y, cx, top, radius, thickness, leg_bottom, open_):
    """Inside test for the padlock shackle: a half ring plus two legs."""
    half = thickness / 2
    shift = radius * 0.55 if open_ else 0.0
    cy = top + radius - shift
    # Upper half ring.
    if y <= cy:
        d = abs(math.hypot(x - cx, y - cy) - radius)
        return d <= half
    # Legs.
    left_bottom = leg_bottom - shift - (radius * 0.9 if open_ else 0.0)
    for lx, bottom in ((cx - radius, left_bottom), (cx + radius, leg_bottom)):
        if abs(x - lx) <= half and y <= bottom:
            return True
    return False


def pixel(x, y, size, tile, open_):
    """Colour (r, g, b, a) of one sample point in [0, size)."""
    s = size
    if rounded_rect(x, y, s / 2, s / 2, s / 2, s / 2, s * 0.22) > 0:
        return None
    color = tile
    body_cx, body_cy = s / 2, s * 0.64
    body_hw, body_hh = s * 0.28, s * 0.20
    in_body = rounded_rect(x, y, body_cx, body_cy, body_hw, body_hh, s * 0.06) <= 0
    radius, thickness = s * 0.17, s * 0.085
    if shackle(x, y, s / 2, s * 0.17, radius, thickness, body_cy - body_hh + s * 0.02, open_):
        color = WHITE
    if in_body:
        color = WHITE
        # Keyhole: a circle over a narrow slot.
        kx, ky = s / 2, body_cy - s * 0.03
        if math.hypot(x - kx, y - ky) <= s * 0.055 or (
            abs(x - kx) <= s * 0.024 and ky <= y <= ky + s * 0.11
        ):
            color = tile
    return color


def render(size, tile, open_):
    rows = []
    for py in range(size):
        row = bytearray()
        for px in range(size):
            acc = [0.0, 0.0, 0.0, 0.0]
            for sy in range(SAMPLES):
                for sx in range(SAMPLES):
                    c = pixel(px + (sx + 0.5) / SAMPLES, py + (sy + 0.5) / SAMPLES, size, tile, open_)
                    if c is not None:
                        acc[0] += c[0]
                        acc[1] += c[1]
                        acc[2] += c[2]
                        acc[3] += 1
            n = SAMPLES * SAMPLES
            if acc[3]:
                row += bytes((round(acc[0] / acc[3]), round(acc[1] / acc[3]), round(acc[2] / acc[3]), round(255 * acc[3] / n)))
            else:
                row += bytes(4)
        rows.append(bytes(row))
    return rows


def png(rows, size):
    raw = b"".join(b"\x00" + r for r in rows)

    def chunk(tag, data):
        body = tag + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")


def ico(images):
    """images: list of (size, png bytes). Vista+ reads PNG entries in .ico files."""
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries, blobs = b"", b""
    for size, data in images:
        dim = 0 if size >= 256 else size
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(data), offset)
        blobs += data
        offset += len(data)
    return header + entries + blobs


def make(name, tile, open_, sizes):
    images = [(s, png(render(s, tile, open_), s)) for s in sizes]
    (OUT / f"{name}.ico").write_bytes(ico(images))
    return dict(images)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    app = make("app", BLUE, False, [16, 20, 24, 32, 40, 48, 64, 256])
    (OUT / "app.png").write_bytes(app[256])
    make("tray-locked", BLUE, False, [16, 20, 24, 32, 40, 48])
    make("tray-unlocked", GREEN, True, [16, 20, 24, 32, 40, 48])
    (OUT / "unlocked.png").write_bytes(png(render(256, GREEN, True), 256))
    print(f"icons written to {OUT}")


if __name__ == "__main__":
    main()
