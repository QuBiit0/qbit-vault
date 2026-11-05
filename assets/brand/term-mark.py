"""Render the QBit Vault mark (assets/brand/qbit-vault-mark.svg geometry) for a
truecolor terminal using half blocks: each cell holds two square pixels, the
top one in the foreground color and the bottom one in the background color.

Usage: python term-mark.py SIZE [ansi|html] [--no-orbits]
SIZE is the width in pixels (= terminal columns); the height is SIZE/2 rows.
"""
import math
import sys

BG = (0x02, 0x08, 0x0D)                              # terminal background
Q_A, Q_B = (0x7F, 0xD0, 0xEC), (0x91, 0xEC, 0xC5)   # mark gradient
O_A, O_B = (0x2E, 0x9B, 0xE0), (0x2F, 0xBF, 0x78)   # orbit gradient


def lerp(a, b, t):
    return tuple(a[i] + (b[i] - a[i]) * t for i in range(3))


def seg_dist(px, py, ax, ay, bx, by):
    dx, dy = bx - ax, by - ay
    t = max(0, min(1, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)))
    return math.hypot(px - ax - t * dx, py - ay - t * dy)


def rrect_dist(px, py, x, y, w, h, r):
    """Signed distance to a rounded rectangle (negative inside)."""
    cx, cy = x + w / 2, y + h / 2
    qx, qy = abs(px - cx) - (w / 2 - r), abs(py - cy) - (h / 2 - r)
    return math.hypot(max(qx, 0), max(qy, 0)) + min(max(qx, qy), 0) - r


def in_trap(px, py):
    # keyhole body: (181,180) (174,214) (206,214) (199,180)
    if py < 180 or py > 214:
        return False
    t = (py - 180) / 34
    return 181 - 7 * t <= px <= 199 + 7 * t


def keyhole(px, py, k):
    """Keyhole scaled by k around its center (optical size correction)."""
    kx, ky = 190 + (px - 190) / k, 191 + (py - 191) / k
    return math.hypot(kx - 190, ky - 168) <= 18 or in_trap(kx, ky)


def ellipse_dist(px, py, rot):
    """Approximate distance to an orbit (rx 170, ry 58, rotated rot degrees)."""
    a = math.radians(-rot)
    x, y = px - 190, py - 190
    u = x * math.cos(a) - y * math.sin(a)
    v = x * math.sin(a) + y * math.cos(a)
    f = (u / 170) ** 2 + (v / 58) ** 2 - 1
    gx, gy = 2 * u / 170 ** 2, 2 * v / 58 ** 2
    return abs(f) / max(1e-9, math.hypot(gx, gy))


def sample(px, py, orbits, k):
    """Color and coverage weight of one sub-sample, in viewBox units."""
    t = max(0, min(1, (px + py - 200) / 360))
    q = lerp(Q_A, Q_B, t)
    ring = rrect_dist(px, py, 104, 96, 172, 172, 58)
    if abs(ring) <= 10 or seg_dist(px, py, 232, 226, 282, 282) <= 10 or keyhole(px, py, k):
        return q, 1.0
    if ring < 0 or not orbits:
        return BG, 0.0  # the orbits pass behind the Q: its counter stays clean
    for ex, ey, er, c in ((334, 110, 8, Q_B), (52, 104, 7, Q_A)):
        if math.hypot(px - ex, py - ey) <= er:
            return c, 1.0
    for rot in (-28, 32):
        if ellipse_dist(px, py, rot) <= 3.5:
            return lerp(O_A, O_B, px / 380), 0.8
    return BG, 0.0


def raster(size, orbits=True, ss=4):
    # With orbits the whole viewBox; without them the Q and its tail.
    x0, y0, span = (0, 0, 380) if orbits else (88, 80, 212)
    # Small marks enlarge the keyhole so it still reads as one.
    q_px = size * 172 / span
    k = 1.0 if q_px >= 22 else min(1.6, 22 / q_px)
    pix = []
    for j in range(size):
        row = []
        for i in range(size):
            acc = [0.0, 0.0, 0.0]
            for sj in range(ss):
                for si in range(ss):
                    px = x0 + (i + (si + 0.5) / ss) * span / size
                    py = y0 + (j + (sj + 0.5) / ss) * span / size
                    c, w = sample(px, py, orbits, k)
                    for n in range(3):
                        acc[n] += c[n] * w + BG[n] * (1 - w)
            row.append(tuple(round(v / ss ** 2) for v in acc))
        pix.append(row)
    return trim(pix)


def trim(pix):
    """Drop empty pixel-row pairs at top and bottom."""
    empty = lambda r: all(c == BG for c in r)
    while len(pix) > 2 and empty(pix[0]) and empty(pix[1]):
        pix = pix[2:]
    while len(pix) > 2 and empty(pix[-1]) and empty(pix[-2]):
        pix = pix[:-2]
    return pix


def to_ansi(pix):
    out = []
    for j in range(0, len(pix) - 1, 2):
        line = "".join("\x1b[38;2;%d;%d;%dm\x1b[48;2;%d;%d;%dm\u2580" % (top + bot)
                       for top, bot in zip(pix[j], pix[j + 1]))
        out.append(line + "\x1b[0m")
    return "\n".join(out)


def to_html(pix, cell=8):
    """Preview with real terminal cell geometry (width:height = 1:2), so each
    half-block pixel is square, as in a terminal."""
    out = ['<div class="tmark" style="display:grid;grid-template-columns:repeat(%d,%dpx);grid-auto-rows:%dpx" aria-hidden="true">'
           % (len(pix[0]), cell, cell * 2)]
    for j in range(0, len(pix) - 1, 2):
        for top, bot in zip(pix[j], pix[j + 1]):
            out.append('<i style="background:linear-gradient(#%02X%02X%02X 50%%,#%02X%02X%02X 50%%)"></i>' % (top + bot))
    out.append("</div>")
    return "".join(out)


if __name__ == "__main__":
    size = int(sys.argv[1])
    fmt = sys.argv[2] if len(sys.argv) > 2 else "ansi"
    cell = 8
    for a in sys.argv[3:]:
        if a.startswith("--cell="):
            cell = int(a[7:])
    pix = raster(size, orbits="--no-orbits" not in sys.argv)
    sys.stdout.reconfigure(encoding="utf-8")
    print(to_html(pix, cell) if fmt == "html" else to_ansi(pix))
