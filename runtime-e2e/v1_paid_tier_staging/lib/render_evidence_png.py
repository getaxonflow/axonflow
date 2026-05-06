#!/usr/bin/env python3
# Copyright 2026 AxonFlow
# SPDX-License-Identifier: BUSL-1.1
"""Render an EVIDENCE.md to a EVIDENCE.png screenshot via PIL.

Used by the issue #1885 license-rework E2E harness so each per-plugin
evidence directory has both forms required by the runtime-test rule
(`feedback_user_facing_runtime_proof_required.md`):

    EVIDENCE.md  — full markdown narrative + raw bodies
    EVIDENCE.png — at-a-glance summary screenshot (this file's output)

The PNG renders the markdown lines verbatim with light syntax-color
treatment for ✅ / ❌ / ⏭️ status markers + section headers. No
external dependencies beyond Pillow (which is in the local devshell
already; CI runs use the system python3 + brew Pillow).

Usage:
    python3 render_evidence_png.py <input.md> <output.png>
"""

from __future__ import annotations

import sys

from PIL import Image, ImageDraw, ImageFont

# --- visual constants ---
WIDTH = 1280
PADDING = 32
LINE_HEIGHT = 22
FONT_SIZE = 15
HEADER_FONT_SIZE = 19
TITLE_FONT_SIZE = 26
BG = (24, 24, 27)            # slate-900
FG = (228, 228, 231)         # zinc-200
HEADER = (147, 197, 253)     # blue-300
TITLE = (252, 211, 77)       # amber-300
PASS_COLOR = (134, 239, 172) # green-300
FAIL_COLOR = (252, 165, 165) # red-300
SKIP_COLOR = (216, 180, 254) # purple-300
NOTE_COLOR = (148, 163, 184) # slate-400
def _load_font(size: int) -> ImageFont.ImageFont:
    """Try common monospace paths so the script works on macOS + Linux CI
    without a forced font install."""
    candidates = [
        "/System/Library/Fonts/Menlo.ttc",
        "/System/Library/Fonts/SFNSMono.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/dejavu/DejaVuSansMono.ttf",
    ]
    for path in candidates:
        try:
            return ImageFont.truetype(path, size)
        except OSError:
            continue
    return ImageFont.load_default()


def _classify(line: str) -> tuple[tuple[int, int, int], str, ImageFont.ImageFont, ImageFont.ImageFont]:
    body = _load_font(FONT_SIZE)
    header = _load_font(HEADER_FONT_SIZE)
    title = _load_font(TITLE_FONT_SIZE)

    stripped = line.strip()
    if stripped.startswith("# "):
        return TITLE, stripped[2:], title, title
    if stripped.startswith("## "):
        return HEADER, stripped[3:], header, header
    if stripped.startswith("- ✅") or "✅" in stripped:
        return PASS_COLOR, line.rstrip(), body, body
    if stripped.startswith("- ❌") or "❌" in stripped:
        return FAIL_COLOR, line.rstrip(), body, body
    if stripped.startswith("- ⏭") or "⏭" in stripped:
        return SKIP_COLOR, line.rstrip(), body, body
    if stripped.startswith("**Result:") or stripped.startswith("**PASS:") or stripped.startswith("**FAIL:"):
        return TITLE, line.rstrip(), body, body
    if stripped.startswith("- **") or stripped.startswith("**"):
        return FG, line.rstrip(), body, body
    if stripped.startswith("`") or "`" in stripped:
        return NOTE_COLOR, line.rstrip(), body, body
    return FG, line.rstrip(), body, body


def render(markdown: str, out_path: str) -> None:
    lines = markdown.splitlines()
    # Pre-compute classifications + heights so we know the canvas size.
    classified = [_classify(ln) for ln in lines]
    height = PADDING * 2 + sum(
        TITLE_FONT_SIZE + 8 if f.size == TITLE_FONT_SIZE else
        (HEADER_FONT_SIZE + 4 if f.size == HEADER_FONT_SIZE else LINE_HEIGHT)
        for _, _, f, _ in classified
    )
    height = max(height, 480)

    img = Image.new("RGB", (WIDTH, height), color=BG)
    draw = ImageDraw.Draw(img)

    y = PADDING
    for color, text, font, _ in classified:
        # Wrap long lines on display width
        max_chars = (WIDTH - 2 * PADDING) // max(1, font.getbbox("M")[2])
        if not text:
            y += LINE_HEIGHT
            continue
        if len(text) <= max_chars:
            draw.text((PADDING, y), text, font=font, fill=color)
        else:
            # Crude wrap — split on existing whitespace, fall back to
            # hard cut at max_chars when no space is found.
            current = ""
            for word in text.split(" "):
                attempt = (current + " " + word).strip() if current else word
                if len(attempt) <= max_chars:
                    current = attempt
                else:
                    if current:
                        draw.text((PADDING, y), current, font=font, fill=color)
                        y += LINE_HEIGHT
                    current = word
            if current:
                draw.text((PADDING, y), current, font=font, fill=color)
        # Advance y by per-line spacing; titles + headers get extra room.
        if font.size >= TITLE_FONT_SIZE:
            y += TITLE_FONT_SIZE + 8
        elif font.size >= HEADER_FONT_SIZE:
            y += HEADER_FONT_SIZE + 4
        else:
            y += LINE_HEIGHT

    img.save(out_path, "PNG", optimize=True)


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        md = f.read()
    render(md, sys.argv[2])
    print(f"wrote {sys.argv[2]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
