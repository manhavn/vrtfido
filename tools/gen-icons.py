#!/usr/bin/env python3
"""VrtFido logo - the single source of truth for every icon the project ships.

The mark is the one the browser extension has always used: a dark navy rounded
square, a sky-blue ring, a sky-blue shield outline and a white key inside it.
This file holds the geometry, and derives every raster, vector and raw asset the
four consumers need, so the tray, the Web CMS, the extension and the Android app
cannot drift apart:

    extension/icons/icon-{16,32,48,128}.png   extension (manifest + popup)
    assets/vrtfido.svg                        Web CMS header, /icon.svg
    assets/favicon.ico                        Web CMS, /favicon.ico (16+32+48)
    assets/icon-192.png                       Web CMS, /icon-192.png
    assets/tray-{24,48}.argb                  Linux StatusNotifier pixmap
    android/.../res/mipmap-*/ic_launcher*.png Android launcher, API < 26
    android/.../res/mipmap-anydpi-v26/*.xml   Android launcher, API >= 26
    android/.../res/values/ic_launcher_colors.xml
    android/.../res/drawable/ic_notification.xml  notification silhouette
    android/.../res/drawable/ic_launcher_monochrome.xml  themed launcher icon

Usage:  python3 tools/gen-icons.py
It only needs the standard library (no Pillow, no ImageMagick); the generated
files are committed, so building VrtFido never runs this script.

Geometry is expressed in 128x128 design units and was measured off the original
extension artwork, so the regenerated set is the same drawing with clean edges
(the originals carry stray alpha and glow artifacts from whatever produced
them).
"""

from __future__ import annotations

import math
import os
import struct
import zlib

# ---------------------------------------------------------------------------
# Palette - the same three colours the Web CMS stylesheet uses
# ---------------------------------------------------------------------------
ACCENT = (0x38, 0xBD, 0xF8)  # sky-400: ring, shield outline, key bow hole
BODY = (0x0F, 0x17, 0x2A)  # slate-900: the rounded square, the key bow hole
SHIELD = (0x14, 0x23, 0x3C)  # the plate the key sits on
KEY = (0xFF, 0xFF, 0xFF)

# ---------------------------------------------------------------------------
# Geometry - 128x128 design canvas
# ---------------------------------------------------------------------------
CANVAS = 128

# Rounded square: outer edge on 3.9..124.1 with a 23.4 corner radius, drawn as a
# ring by painting the outer shape and then a 7.1..120.9 inner shape on top.
BODY_OUT = (3.9, 124.1, 23.4)  # x0, x1, corner radius
BODY_IN = (7.1, 120.9, 19.9)

# A disc of the same outer size, for the round launcher icon: a round icon that
# kept the square body would only show a square ring with its corners cut off by
# the device's circular mask, which reads as a mistake rather than a design.
DISC_CENTRE = 64.0
DISC_OUTER_R = (BODY_OUT[1] - BODY_OUT[0]) / 2
DISC_INNER_R = DISC_OUTER_R - (BODY_IN[0] - BODY_OUT[0])

# Shield: flat top, vertical sides down to y=67, then a straight taper to the
# point at (64, 103.6). The inner pentagon is the outer one offset inward by the
# stroke width, which is what makes it a hollow outline.
SHIELD_OUTER = [
    (29.7, 28.2),
    (98.3, 28.2),
    (98.3, 67.0),
    (64.0, 103.6),
    (29.7, 67.0),
]
SHIELD_STROKE = 4.8

# Key: bow ring, shaft, two teeth, and the accent dot that fills the bow hole.
BOW = (64.0, 52.0, 12.3)  # cx, cy, outer radius
BOW_HOLE_R = 8.0
SHAFT = (62.4, 54.0, 3.5, 88.5)  # x, y, width, bottom
TOOTH_RIGHT = 72.4
TOOTH_SHORT = 70.5
TOOTH_1 = (78.0, 82.0)
TOOTH_2 = (84.0, 88.5)
DOT = (61.5, 49.5, 4.0, 5.0, 1.3)  # x, y, w, h, corner radius


def rounded_rect(x0: float, y0: float, x1: float, y1: float, r: float, steps: int = 24):
    """Corner-flattened rounded rectangle, clockwise, as a polygon."""
    pts = []
    corners = [
        (x1 - r, y1 - r, 0.0, 90.0),  # bottom right
        (x0 + r, y1 - r, 90.0, 180.0),  # bottom left
        (x0 + r, y0 + r, 180.0, 270.0),  # top left
        (x1 - r, y0 + r, 270.0, 360.0),  # top right
    ]
    for cx, cy, a0, a1 in corners:
        for i in range(steps + 1):
            a = math.radians(a0 + (a1 - a0) * i / steps)
            pts.append((cx + r * math.cos(a), cy + r * math.sin(a)))
    return pts


def offset_convex(poly, d: float):
    """Inward offset of a convex polygon by `d`, with miter joints.

    Each edge is pushed along its inward normal; the new vertex under the
    original one is where the two neighbouring offset lines cross. The inward
    side follows the winding order, so the caller does not have to know it.
    """
    n = len(poly)
    area = sum(
        poly[i][0] * poly[(i + 1) % n][1] - poly[(i + 1) % n][0] * poly[i][1]
        for i in range(n)
    )
    turn = 1.0 if area > 0 else -1.0
    lines = []
    for i in range(n):
        x0, y0 = poly[i]
        x1, y1 = poly[(i + 1) % n]
        ex, ey = x1 - x0, y1 - y0
        length = math.hypot(ex, ey)
        nx, ny = turn * -ey / length, turn * ex / length
        lines.append((nx, ny, nx * x0 + ny * y0 + d))
    out = []
    for i in range(n):
        ax, ay, ac = lines[(i - 1) % n]
        bx, by, bc = lines[i]
        det = ax * by - ay * bx
        if abs(det) < 1e-9:
            out.append(poly[i])
            continue
        out.append(((ac * by - bc * ay) / det, (ax * bc - bx * ac) / det))
    return out


def circle(cx: float, cy: float, r: float, steps: int = 192):
    return [
        (cx + r * math.cos(2 * math.pi * i / steps), cy + r * math.sin(2 * math.pi * i / steps))
        for i in range(steps)
    ]


def rect(x0: float, y0: float, x1: float, y1: float):
    return [(x0, y0), (x1, y0), (x1, y1), (x0, y1)]


def body_steps(round_body: bool = False):
    """The container the mark sits on: rounded square, or disc for a round icon."""
    if round_body:
        return [
            ("body disc", circle(DISC_CENTRE, DISC_CENTRE, DISC_OUTER_R), ACCENT),
            ("body ring cut", circle(DISC_CENTRE, DISC_CENTRE, DISC_INNER_R), BODY),
        ]
    return [
        ("body", rounded_rect(BODY_OUT[0], BODY_OUT[0], BODY_OUT[1], BODY_OUT[1], BODY_OUT[2]), ACCENT),
        ("body ring cut", rounded_rect(BODY_IN[0], BODY_IN[0], BODY_IN[1], BODY_IN[1], BODY_IN[2]), BODY),
    ]


def paint_steps(round_body: bool = False):
    """The logo, in painter's order: (name, polygon, colour)."""
    sx0, sy0, sw, sbot = SHAFT
    dx, dy, dw, dh, dr = DOT
    return body_steps(round_body) + [
        ("shield", SHIELD_OUTER, ACCENT),
        ("shield plate", offset_convex(SHIELD_OUTER, SHIELD_STROKE), SHIELD),
        ("key shaft", rect(sx0, sy0, sx0 + sw, sbot), KEY),
        ("key tooth 1", rect(64.0, TOOTH_1[0], TOOTH_RIGHT, TOOTH_1[1]), KEY),
        ("key tooth 2", rect(64.0, TOOTH_2[0], TOOTH_SHORT, TOOTH_2[1]), KEY),
        ("key bow", circle(*BOW), KEY),
        ("key bow hole", circle(BOW[0], BOW[1], BOW_HOLE_R), BODY),
        ("key bow dot", rounded_rect(dx, dy, dx + dw, dy + dh, dr, 8), ACCENT),
    ]


def key_silhouette():
    """The key as disjoint polygons: bow, bow hole, shaft and teeth.

    Nothing overlaps anything else, which is what lets the Android status-bar
    glyph cut the bow hole with a single evenOdd path: the bow and the blade
    only touch at y = 64.3 instead of crossing, so neither cancels the other.
    """
    sx0, _sy0, sw, sbot = SHAFT
    sx1 = sx0 + sw
    bow_bottom = BOW[1] + BOW[2]
    return [
        circle(*BOW),
        circle(BOW[0], BOW[1], BOW_HOLE_R),
        [
            (sx0, bow_bottom),
            (sx1, bow_bottom),
            (sx1, TOOTH_1[0]),
            (TOOTH_RIGHT, TOOTH_1[0]),
            (TOOTH_RIGHT, TOOTH_1[1]),
            (sx1, TOOTH_1[1]),
            (sx1, TOOTH_2[0]),
            (TOOTH_SHORT, TOOTH_2[0]),
            (TOOTH_SHORT, TOOTH_2[1]),
            (sx0, sbot),
        ],
    ]


# ---------------------------------------------------------------------------
# Rasteriser: premultiplied float RGBA, analytic horizontal coverage and
# `SUBSAMPLES` sub-scanlines per row.
# ---------------------------------------------------------------------------
SUBSAMPLES = 16

# Coverage is a linear quantity, so the blend runs in linear light and the
# result is encoded back to sRGB at the end. Blending the encoded values
# instead darkens every partly covered pixel, which is exactly the case for
# thin strokes (the key's bow ring at 16px is barely one pixel wide).
_SRGB_TO_LINEAR = tuple(
    ((c / 255.0) / 12.92 if c / 255.0 <= 0.04045 else (((c / 255.0) + 0.055) / 1.055) ** 2.4)
    for c in range(256)
)


def linear_to_srgb(value: float) -> float:
    if value <= 0.0031308:
        return value * 12.92
    return 1.055 * value ** (1.0 / 2.4) - 0.055


def raster(size: int, steps):
    """Render `steps` (name, polygon, colour) at `size`."""
    px = [0.0] * (size * size * 4)
    scale = size / CANVAS
    inv = 1.0 / SUBSAMPLES

    for _name, poly, colour in steps:
        pts = [(x * scale, y * scale) for x, y in poly]
        edges = []
        n = len(pts)
        for i in range(n):
            x0, y0 = pts[i]
            x1, y1 = pts[(i + 1) % n]
            if y0 == y1:
                continue
            if y1 < y0:
                x0, y0, x1, y1 = x1, y1, x0, y0
            edges.append((y0, y1, (x1 - x0) / (y1 - y0), x0))

        y_lo = max(0, int(math.floor(min(p[1] for p in pts))))
        y_hi = min(size, int(math.ceil(max(p[1] for p in pts))))

        src = (0.0, 0.0, 0.0, 0.0) if colour is None else (
            _SRGB_TO_LINEAR[colour[0]],
            _SRGB_TO_LINEAR[colour[1]],
            _SRGB_TO_LINEAR[colour[2]],
            1.0,
        )

        for row in range(y_lo, y_hi):
            cov = [0.0] * size
            any_cov = False
            for k in range(SUBSAMPLES):
                yc = row + (k + 0.5) * inv
                xs = []
                for y0, y1, slope, x0 in edges:
                    if y0 <= yc < y1:
                        xs.append(x0 + (yc - y0) * slope)
                if len(xs) < 2:
                    continue
                xs.sort()
                for j in range(0, len(xs) - 1, 2):
                    a, b = xs[j], xs[j + 1]
                    if b <= 0.0 or a >= size:
                        continue
                    a = max(a, 0.0)
                    b = min(b, float(size))
                    ia, ib = int(a), int(b)
                    if ib >= size:
                        ib = size - 1
                        b = float(size)
                    if ia == ib:
                        cov[ia] += (b - a) * inv
                    else:
                        cov[ia] += (ia + 1 - a) * inv
                        for i in range(ia + 1, ib):
                            cov[i] += inv
                        cov[ib] += (b - ib) * inv
                    any_cov = True
            if not any_cov:
                continue
            base = row * size
            for x in range(size):
                c = cov[x]
                if c <= 0.0:
                    continue
                i = (base + x) * 4
                if c >= 1.0:
                    px[i], px[i + 1], px[i + 2], px[i + 3] = src[0], src[1], src[2], src[3]
                    continue
                inv_c = 1.0 - c
                px[i] = src[0] * c + px[i] * inv_c
                px[i + 1] = src[1] * c + px[i + 1] * inv_c
                px[i + 2] = src[2] * c + px[i + 2] * inv_c
                px[i + 3] = src[3] * c + px[i + 3] * inv_c

    out = bytearray(size * size * 4)
    for i in range(0, len(px), 4):
        a = px[i + 3]
        if a <= 0.0:
            continue
        out[i] = clamp8(linear_to_srgb(px[i] / a))
        out[i + 1] = clamp8(linear_to_srgb(px[i + 1] / a))
        out[i + 2] = clamp8(linear_to_srgb(px[i + 2] / a))
        out[i + 3] = clamp8(a)
    return bytes(out)


def clamp8(v: float) -> int:
    n = int(round(v * 255.0))
    return 0 if n < 0 else (255 if n > 255 else n)


# ---------------------------------------------------------------------------
# Encoders
# ---------------------------------------------------------------------------
def png(size: int, rgba: bytes) -> bytes:
    raw = bytearray()
    stride = size * 4
    for y in range(size):
        raw.append(0)  # filter: none
        raw += rgba[y * stride : (y + 1) * stride]

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
        + chunk(b"IEND", b"")
    )


def ico(images):
    """PNG-compressed ICO container; `images` is a list of (size, png bytes)."""
    count = len(images)
    header = struct.pack("<HHH", 0, 1, count)
    entries = b""
    offset = 6 + 16 * count
    for size, data in images:
        entries += struct.pack(
            "<BBBBHHII",
            size if size < 256 else 0,
            size if size < 256 else 0,
            0,
            0,
            1,
            32,
            len(data),
            offset,
        )
        offset += len(data)
    return header + entries + b"".join(data for _, data in images)


def argb(size: int, rgba: bytes) -> bytes:
    """ARGB32 in network byte order, which is what StatusNotifierItem wants."""
    out = bytearray(size * size * 4)
    for i in range(0, len(rgba), 4):
        out[i] = rgba[i + 3]
        out[i + 1] = rgba[i]
        out[i + 2] = rgba[i + 1]
        out[i + 3] = rgba[i + 2]
    return bytes(out)


def hex_of(colour):
    return "#%02X%02X%02X" % colour


def svg() -> str:
    """Vector master, written with primitives so it stays hand-editable."""
    def path(poly):
        head = "M%.2f %.2f" % poly[0]
        return head + "".join(" L%.2f %.2f" % p for p in poly[1:]) + " Z"

    bow_cx, bow_cy, bow_r = BOW
    sx0, sy0, sw, sbot = SHAFT
    dx, dy, dw, dh, dr = DOT
    plate = offset_convex(SHIELD_OUTER, SHIELD_STROKE)
    lines = [
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128">',
        '  <title>VrtFido</title>',
        '  <!-- Generated by tools/gen-icons.py: edit the geometry there, not here. -->',
        '  <rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" rx="%.1f" fill="%s"/>'
        % (BODY_OUT[0], BODY_OUT[0], BODY_OUT[1] - BODY_OUT[0], BODY_OUT[1] - BODY_OUT[0],
           BODY_OUT[2], hex_of(ACCENT)),
        '  <rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" rx="%.1f" fill="%s"/>'
        % (BODY_IN[0], BODY_IN[0], BODY_IN[1] - BODY_IN[0], BODY_IN[1] - BODY_IN[0],
           BODY_IN[2], hex_of(BODY)),
        '  <path d="%s" fill="%s"/>' % (path(SHIELD_OUTER), hex_of(ACCENT)),
        '  <path d="%s" fill="%s"/>' % (path(plate), hex_of(SHIELD)),
        '  <rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" fill="#FFFFFF"/>'
        % (sx0, sy0, sw, sbot - sy0),
        '  <rect x="64" y="%.1f" width="%.1f" height="%.1f" fill="#FFFFFF"/>'
        % (TOOTH_1[0], TOOTH_RIGHT - 64, TOOTH_1[1] - TOOTH_1[0]),
        '  <rect x="64" y="%.1f" width="%.1f" height="%.1f" fill="#FFFFFF"/>'
        % (TOOTH_2[0], TOOTH_SHORT - 64, TOOTH_2[1] - TOOTH_2[0]),
        '  <circle cx="%.1f" cy="%.1f" r="%.1f" fill="#FFFFFF"/>' % (bow_cx, bow_cy, bow_r),
        '  <circle cx="%.1f" cy="%.1f" r="%.1f" fill="%s"/>' % (bow_cx, bow_cy, BOW_HOLE_R, hex_of(BODY)),
        '  <rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" rx="%.1f" fill="%s"/>'
        % (dx, dy, dw, dh, dr, hex_of(ACCENT)),
        "</svg>",
    ]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Android vector drawables
# ---------------------------------------------------------------------------
ADAPTIVE_SIZE = 108.0
# An adaptive icon's mask leaves a 72dp circle of the 108dp layer visible, which
# is radius 36 of this 108 unit layer, and launchers reserve the outer band for
# their parallax: `AdaptiveIconDrawable` calls everything inside 66/72 of that
# circle the safe zone (radius 33). The disc is fitted to the safe zone, so the
# rim survives the shift and no edge of the artwork is ever cropped.
MASK_RADIUS = 36.0
SAFE_ZONE = MASK_RADIUS * 66.0 / 72.0
MASK_INSET = 0.2

# A status-bar glyph fills its 24dp box with a little padding. It carries the key
# alone: the shield outline turns to mush at 24dp, where the key's blade is
# already thinner than one physical pixel.
STATUS_SIZE = 24.0
STATUS_GLYPH_RADIUS = 10.0


def fit_transform(polys, canvas, radius):
    """Scale `polys` to fit a circle of `radius` units inside a `canvas` square.

    The radius is measured from the polygons' own centre, so a glyph that is
    taller than it is wide keeps its proportions.
    """
    xs = [p[0] for poly in polys for p in poly]
    ys = [p[1] for poly in polys for p in poly]
    cx, cy = (min(xs) + max(xs)) / 2, (min(ys) + max(ys)) / 2
    reach = max(math.hypot(px - cx, py - cy) for poly in polys for px, py in poly)
    scale = radius / reach
    return scale, canvas / 2 - cx * scale, canvas / 2 - cy * scale


def android_group_transform():
    """The adaptive-icon layers: the whole disc, rim included, inside the mask."""
    reach = DISC_OUTER_R
    scale = (SAFE_ZONE - MASK_INSET) / reach
    return (
        scale,
        ADAPTIVE_SIZE / 2 - DISC_CENTRE * scale,
        ADAPTIVE_SIZE / 2 - DISC_CENTRE * scale,
    )


def path_data(poly):
    """A closed polygon as a vector-drawable path."""
    head = "M%.2f,%.2f" % poly[0]
    body = "".join(" L%.2f,%.2f" % p for p in poly[1:])
    return head + body + " Z"


def circle_path(cx, cy, r):
    """A full circle as two arcs, the only way a vector drawable can draw one."""
    return (
        "M%.2f,%.2f a%.2f,%.2f 0 1,0 %.2f,0 a%.2f,%.2f 0 1,0 %.2f,0 Z"
        % (cx - r, cy, r, r, 2 * r, r, r, -2 * r)
    )


def vector_drawable(width_dp, parts, viewport=ADAPTIVE_SIZE):
    head = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<!-- Generated by tools/gen-icons.py - edit the geometry there, not here. -->\n'
        '<vector xmlns:android="http://schemas.android.com/apk/res/android"\n'
        '    android:width="%gdp"\n'
        '    android:height="%gdp"\n'
        '    android:viewportWidth="%g"\n'
        '    android:viewportHeight="%g">\n' % (width_dp, width_dp, viewport, viewport)
    )
    body = "".join(part + "\n" for part in parts)
    return head + body + "</vector>\n"


def group_open(scale, tx, ty):
    return (
        '    <group android:scaleX="%.4f" android:scaleY="%.4f"'
        ' android:translateX="%.4f" android:translateY="%.4f">' % (scale, scale, tx, ty)
    )


def fill_path(data, colour, fill_type=None):
    fill = ' android:fillType="%s"' % fill_type if fill_type else ""
    return '        <path android:fillColor="%s"%s android:pathData="%s"/>' % (
        hex_of(colour),
        fill,
        data,
    )


def mark_paths():
    """Shield, plate and key, in painter's order, in design coordinates."""
    sx0, sy0, sw, sbot = SHAFT
    dx, dy, dw, dh = DOT[0:4]
    return [
        fill_path(path_data(SHIELD_OUTER), ACCENT),
        fill_path(path_data(offset_convex(SHIELD_OUTER, SHIELD_STROKE)), SHIELD),
        fill_path(path_data(rect(sx0, sy0, sx0 + sw, sbot)), KEY),
        fill_path(path_data(rect(64.0, TOOTH_1[0], TOOTH_RIGHT, TOOTH_1[1])), KEY),
        fill_path(path_data(rect(64.0, TOOTH_2[0], TOOTH_SHORT, TOOTH_2[1])), KEY),
        fill_path(circle_path(BOW[0], BOW[1], BOW[2]), KEY),
        # The bow hole shows the body colour, not the plate: it is a hole in the
        # key, and it reads that way against the plate in the logo too.
        fill_path(circle_path(BOW[0], BOW[1], BOW_HOLE_R), BODY),
        fill_path(path_data(rect(dx, dy, dx + dw, dy + dh)), ACCENT),
    ]


def android_launcher_foreground() -> str:
    """Adaptive-icon foreground: the disc logo - rim, shield and key.

    The launcher's mask supplies the outer shape, so the foreground carries the
    rim itself rather than a second, square one that the mask would then cut
    across. The background layer is the navy the disc's rim cut also uses.
    """
    scale, tx, ty = android_group_transform()
    parts = [
        group_open(scale, tx, ty),
        fill_path(circle_path(DISC_CENTRE, DISC_CENTRE, DISC_OUTER_R), ACCENT),
        fill_path(circle_path(DISC_CENTRE, DISC_CENTRE, DISC_INNER_R), BODY),
        *mark_paths(),
        "    </group>",
    ]
    return vector_drawable(108, parts)


def android_monochrome() -> str:
    """Themed-icon layer: the rim, the shield outline and the key as one evenOdd
    path, which is the logo's own line art. Android keeps the alpha and tints it.
    The subpaths are nested - the key sits inside the shield's outline, which
    sits inside the rim - which is exactly what evenOdd is for: an inner
    subpath is a hole in the one that contains it."""
    scale, tx, ty = android_group_transform()
    data = " ".join(
        [
            circle_path(DISC_CENTRE, DISC_CENTRE, DISC_OUTER_R),
            circle_path(DISC_CENTRE, DISC_CENTRE, DISC_INNER_R),
            path_data(SHIELD_OUTER),
            path_data(offset_convex(SHIELD_OUTER, SHIELD_STROKE)),
            circle_path(BOW[0], BOW[1], BOW[2]),
            circle_path(BOW[0], BOW[1], BOW_HOLE_R),
            path_data(key_silhouette()[2]),
        ]
    )
    parts = [group_open(scale, tx, ty), fill_path(data, KEY, "evenOdd"), "    </group>"]
    return vector_drawable(108, parts)


def android_notification() -> str:
    """Status-bar glyph: the key alone, scaled to fill the 24dp box, in one
    evenOdd path so the bow hole is a real hole Android can tint around."""
    scale, tx, ty = fit_transform(key_silhouette(), STATUS_SIZE, STATUS_GLYPH_RADIUS)
    data = " ".join(
        [
            circle_path(BOW[0], BOW[1], BOW[2]),
            circle_path(BOW[0], BOW[1], BOW_HOLE_R),
            path_data(key_silhouette()[2]),
        ]
    )
    parts = [group_open(scale, tx, ty), fill_path(data, KEY, "evenOdd"), "    </group>"]
    return vector_drawable(24, parts, viewport=STATUS_SIZE)


ANDROID_COLORS = """<?xml version="1.0" encoding="utf-8"?>
<!-- Generated by tools/gen-icons.py - the launcher background of the adaptive icon. -->
<resources>
    <color name="ic_launcher_background">#0F172A</color>
</resources>
"""


def android_adaptive() -> str:
    """The adaptive launcher icon: navy background, the mark as foreground, and
    a monochrome layer for the themed icons Android 13+ draws."""
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<!-- Generated by tools/gen-icons.py - edit the geometry there, not here. -->\n'
        '<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">\n'
        '    <background android:drawable="@color/ic_launcher_background"/>\n'
        '    <foreground android:drawable="@drawable/ic_launcher_foreground"/>\n'
        '    <monochrome android:drawable="@drawable/ic_launcher_monochrome"/>\n'
        "</adaptive-icon>\n"
    )


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXT_ICON_SIZES = (16, 32, 48, 128)
ANDROID_RES = os.path.join(ROOT, "android", "app", "src", "main", "res")
ANDROID_MIPMAPS = {
    "mdpi": 48,
    "hdpi": 72,
    "xhdpi": 96,
    "xxhdpi": 144,
    "xxxhdpi": 192,
}

written = []


def emit(path: str, data: bytes):
    with open(path, "wb") as fh:
        fh.write(data)
    written.append((os.path.relpath(path, ROOT), len(data)))


def emit_text(path: str, text: str):
    emit(path, text.encode("utf-8"))


def main():
    logo = paint_steps()
    round_logo = paint_steps(round_body=True)
    rasters = {}

    def logo_png(size, round_body=False):
        key = (size, round_body)
        if key not in rasters:
            rasters[key] = raster(size, round_logo if round_body else logo)
        return png(size, rasters[key])

    for size in EXT_ICON_SIZES:
        emit(os.path.join(ROOT, "extension", "icons", "icon-%d.png" % size), logo_png(size))

    emit_text(os.path.join(ROOT, "assets", "vrtfido.svg"), svg())
    emit(
        os.path.join(ROOT, "assets", "favicon.ico"),
        ico([(s, logo_png(s)) for s in (16, 32, 48)]),
    )
    emit(os.path.join(ROOT, "assets", "icon-192.png"), logo_png(192))

    for size in (24, 48):
        emit(
            os.path.join(ROOT, "assets", "tray-%d.argb" % size),
            argb(size, raster(size, logo)),
        )

    emit_text(
        os.path.join(ANDROID_RES, "drawable", "ic_launcher_foreground.xml"),
        android_launcher_foreground(),
    )
    emit_text(
        os.path.join(ANDROID_RES, "drawable", "ic_notification.xml"),
        android_notification(),
    )
    emit_text(
        os.path.join(ANDROID_RES, "drawable", "ic_launcher_monochrome.xml"),
        android_monochrome(),
    )
    emit_text(
        os.path.join(ANDROID_RES, "values", "ic_launcher_colors.xml"),
        ANDROID_COLORS,
    )
    for density, size in ANDROID_MIPMAPS.items():
        directory = os.path.join(ANDROID_RES, "mipmap-%s" % density)
        os.makedirs(directory, exist_ok=True)
        emit(os.path.join(directory, "ic_launcher.png"), logo_png(size))
        emit(os.path.join(directory, "ic_launcher_round.png"), logo_png(size, round_body=True))
    anydpi = os.path.join(ANDROID_RES, "mipmap-anydpi-v26")
    os.makedirs(anydpi, exist_ok=True)
    emit_text(os.path.join(anydpi, "ic_launcher.xml"), android_adaptive())
    emit_text(os.path.join(anydpi, "ic_launcher_round.xml"), android_adaptive())

    for path, size in written:
        print("  %-62s %7d B" % (path, size))


if __name__ == "__main__":
    main()
