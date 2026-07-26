"""Reach marketplace avatar — 440x440, square corners, no face.

Reach answers a question by going out into the live internet, reading what it finds, and returning a
report where every claim is tied to a source it actually opened.

The mark is ARIADNE'S THREAD THROUGH THE LABYRINTH, under a night sky. The labyrinth is the classical
figure for a search whose path cannot be seen from inside it. The thread is what makes the path
*retraceable*: Theseus could return, and could show others the route. That is exactly what a citation
is — a research answer without its sources is a claim from inside the maze; with them, anyone can walk
the path again and check it.

Set at night rather than at dawn (Aletheia's hour), and built from square orthogonal geometry rather
than curves, so the two marks cannot be mistaken for one another at thumbnail size.

Atmosphere is rendered as LIGHT — gradients, haze, stars, bloom — not as imitation brushwork. An earlier
attempt stamped tens of thousands of impasto strokes and produced convincing texture with an
unconvincing picture: uniform stroke fields read as wood grain or textile.

NO HUMAN FIGURE AND NO FACE anywhere: a human head in profile is a documented instant rejection here.

Spec: exactly 440x440, RGB (never RGBA — alpha is what renders as rounded corners), under 1 MB, no text.

    python scripts/make_avatar_440.py
"""
from __future__ import annotations

import math
import os
import sys

from PIL import Image, ImageDraw, ImageFilter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from atmos import (bloom, grain, haze_bands, lerp, radial_light, screen,  # noqa: E402
                   stars, vertical_sky)

SIZE = 440
SS = 3
W = SIZE * SS
C = W // 2

NIGHT = (8, 12, 26)
DEEP = (14, 26, 46)
TEAL_DEEP = (18, 48, 62)
HORIZON = (46, 92, 96)
WALL = (150, 122, 70)          # the labyrinth walls: the obstacle, not the subject
WALL_HI = (208, 172, 104)
THREAD = (72, 232, 178)        # Ariadne's thread
THREAD_HI = (196, 255, 236)
GOLD = (246, 208, 132)         # the centre reached

RINGS = 7
GAP = W * 0.047
OPENINGS = ("S", "E", "N", "W", "S", "E", "N")


def _walls(d: ImageDraw.ImageDraw) -> None:
    """Concentric square walls, each with one opening. The openings alternate side so no straight line
    crosses the figure — that is what makes it a labyrinth rather than a set of nested boxes."""
    for k in range(RINGS):
        half = GAP * (k + 1.35)
        x0, y0, x1, y1 = C - half, C - half, C + half, C + half
        lum = 0.50 + 0.50 * (k / (RINGS - 1))
        col = lerp(WALL, WALL_HI, lum)
        wid = int(3.0 * SS)
        gate = half * 0.30
        side = OPENINGS[k % len(OPENINGS)]
        for edge, a, b in (("N", (x0, y0), (x1, y0)), ("S", (x0, y1), (x1, y1)),
                           ("W", (x0, y0), (x0, y1)), ("E", (x1, y0), (x1, y1))):
            if edge != side:
                d.line([*a, *b], fill=col, width=wid)
                continue
            if edge in ("N", "S"):
                d.line([a[0], a[1], C - gate, a[1]], fill=col, width=wid)
                d.line([C + gate, b[1], b[0], b[1]], fill=col, width=wid)
            else:
                d.line([a[0], a[1], a[0], C - gate], fill=col, width=wid)
                d.line([b[0], C + gate, b[0], b[1]], fill=col, width=wid)


def _thread_path() -> list[tuple[float, float]]:
    """The route: in from outside the maze, through each opening in turn, to the centre. Orthogonal
    throughout, so it reads as a path traced along corridors rather than as a decorative spiral."""
    def gate(k: int) -> tuple[float, float]:
        half = GAP * (k + 1.35)
        return {"N": (C, C - half), "S": (C, C + half),
                "W": (C - half, C), "E": (C + half, C)}[OPENINGS[k % len(OPENINGS)]]

    outer = GAP * (RINGS - 1 + 1.35)
    first = OPENINGS[(RINGS - 1) % len(OPENINGS)]
    entry = {"N": (C, C - outer - GAP * 1.5), "S": (C, C + outer + GAP * 1.5),
             "W": (C - outer - GAP * 1.5, C), "E": (C + outer + GAP * 1.5, C)}[first]
    pts = [entry]
    prev = entry
    for k in range(RINGS - 1, -1, -1):
        g = gate(k)
        if abs(prev[0] - g[0]) > 1 and abs(prev[1] - g[1]) > 1:
            pts.append((prev[0], g[1]) if abs(prev[1] - g[1]) < abs(prev[0] - g[0]) else (g[0], prev[1]))
        pts.append(g)
        f = 1 - 0.22 / (k + 1.35)
        pts.append((C + (g[0] - C) * f, C + (g[1] - C) * f))
        prev = pts[-1]
    pts.append((C, C))
    return pts


def build() -> Image.Image:
    # 1. Night sky, warming very slightly to a teal horizon at the base.
    img = vertical_sky(W, [(0.0, NIGHT), (0.34, DEEP), (0.66, TEAL_DEEP),
                           (0.86, lerp(TEAL_DEEP, HORIZON, 0.55)), (1.0, lerp(HORIZON, NIGHT, 0.45))])
    img = screen(img, haze_bands(W, 12, lerp(TEAL_DEEP, HORIZON, 0.5), count=9,
                                 blur=int(12 * SS), strength=0.34))

    # 2. Stars, cleared of the maze so they read as sky behind it rather than dust across it.
    stars(ImageDraw.Draw(img), W, 21, 190, (226, 240, 255), y_max=0.72,
          avoid=(C, C, GAP * (RINGS + 1.0)))

    # 3. A cool glow at the heart, so the centre feels like a destination before the eye finds it.
    img = screen(img, radial_light(W, C, C, W * 0.30, (36, 120, 104), falloff=2.4))

    # 4. The maze, then the thread over it.
    _walls(ImageDraw.Draw(img))
    path = _thread_path()
    glow = Image.new("RGB", (W, W), (0, 0, 0))
    ImageDraw.Draw(glow).line(path, fill=(24, 118, 92), width=int(13 * SS), joint="curve")
    img = screen(img, glow.filter(ImageFilter.GaussianBlur(int(7 * SS))))
    d = ImageDraw.Draw(img)
    d.line(path, fill=THREAD, width=int(5.4 * SS), joint="curve")
    d.line(path, fill=THREAD_HI, width=int(2.0 * SS), joint="curve")

    # 5. The centre reached, and the outer end of the thread — a thread has two ends, and the outer one
    #    is how you get back out.
    for r, col in ((int(19 * SS), (26, 54, 48)), (int(12 * SS), GOLD), (int(5.5 * SS), (255, 250, 232))):
        d.ellipse([C - r, C - r, C + r, C + r], fill=col)
    ex, ey = path[0]
    er = int(7 * SS)
    d.ellipse([ex - er, ey - er, ex + er, ey + er], fill=THREAD_HI)

    img = bloom(img, radius=int(8 * SS), strength=0.42, threshold=170)
    out = img.resize((SIZE, SIZE), Image.LANCZOS)
    grain(out, seed=5, amount=5)
    return out


def main() -> None:
    out_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "brand")
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, "reach_avatar_440.png")
    img = build()
    img.save(out, "PNG", optimize=True)
    px = img.load()
    print(f"wrote {out}")
    print(f"  {img.size[0]}x{img.size[1]} {img.mode}  bytes {os.path.getsize(out):,}")
    print(f"  corners {[px[x, y] for x, y in ((0, 0), (SIZE - 1, 0), (0, SIZE - 1), (SIZE - 1, SIZE - 1))]}")
    for n in (96, 48):
        img.resize((n, n), Image.LANCZOS).resize((n * 4, n * 4), Image.NEAREST).save(
            os.path.join(out_dir, f"_check_{n}.png"))


if __name__ == "__main__":
    main()
