#!/usr/bin/env python3
"""Generate the README figures from the tool's own output.

    script/gen_figures.py [path-to-redos-proof-binary]

Writes docs/figures/growth.svg — the step-count growth of an exponential regex
(^(a+)+$) against a linear one (^a+$), measured by running the binary's `match`
command at n = 1..26. Nothing is hand-fitted: the numbers come from the model.

Zero dependencies (stdlib only), matching the rest of the project. The SVG is
drawn on a self-contained light card so it reads on both GitHub themes.
"""

import math
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = sys.argv[1] if len(sys.argv) > 1 else str(ROOT / "target/release/redos-proof")

# Palette (validated data-viz default): slot-1 blue = linear, slot-2 orange = exponential.
EXP = "#eb6834"
LIN = "#2a78d6"
SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK2 = "#52514e"
MUTED = "#898781"
GRID = "#e1e0d9"
AXIS = "#c3c2b7"
BORDER = "rgba(11,11,11,0.10)"
FONT = 'system-ui, -apple-system, "Segoe UI", sans-serif'

N_MAX = 26


def steps(pattern: str, n: int) -> int:
    """Exact backtracking steps the model takes on 'a'*n + '!' (a failing input)."""
    inp = "a" * n + "!"
    out = subprocess.run([BIN, "match", pattern, inp], capture_output=True, text=True, check=True)
    for tok in out.stdout.split():
        if tok.isdigit():
            last = tok
    return int(last)


def collect():
    ns = list(range(1, N_MAX + 1))
    exp = [steps("^(a+)+$", n) for n in ns]
    lin = [steps("^a+$", n) for n in ns]
    return ns, exp, lin


def svg(ns, exp, lin) -> str:
    W, H = 720, 430
    L, R, T, B = 68, 128, 58, 52
    pw, ph = W - L - R, H - T - B

    # x: linear 1..N_MAX. y: log10, decades 10^0 .. 10^9.
    y_lo, y_hi = 0, 9
    x_lo, x_hi = 1, N_MAX

    def px(n):
        return L + (n - x_lo) / (x_hi - x_lo) * pw

    def py(v):
        ly = math.log10(max(v, 1))
        return T + (y_hi - ly) / (y_hi - y_lo) * ph

    s = []
    s.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" '
        f'font-family=\'{FONT}\' width="{W}" height="{H}" role="img" '
        f'aria-label="Backtracking steps versus input length: exponential regex versus linear regex, log scale.">'
    )
    s.append(f'<rect x="0.5" y="0.5" width="{W-1}" height="{H-1}" rx="10" fill="{SURFACE}" stroke="{BORDER}"/>')
    # Title + subtitle.
    s.append(f'<text x="{L}" y="26" font-size="16" font-weight="600" fill="{INK}">One extra character can double the work</text>')
    s.append(f'<text x="{L}" y="44" font-size="12" fill="{INK2}">Backtracking steps to reject "aaa…a!", by input length — measured, log scale</text>')

    # Horizontal gridlines + y labels at each decade.
    for d in range(y_lo, y_hi + 1):
        y = py(10 ** d)
        s.append(f'<line x1="{L}" y1="{y:.1f}" x2="{L+pw}" y2="{y:.1f}" stroke="{GRID}" stroke-width="1"/>')
        label = "1" if d == 0 else (f"10^{d}" if d < 3 else _si(10 ** d))
        s.append(f'<text x="{L-8}" y="{y+4:.1f}" font-size="11" text-anchor="end" fill="{MUTED}" font-variant-numeric="tabular-nums">{label}</text>')
    # Baseline (x axis) + x labels.
    s.append(f'<line x1="{L}" y1="{T+ph}" x2="{L+pw}" y2="{T+ph}" stroke="{AXIS}" stroke-width="1"/>')
    for n in (1, 5, 10, 15, 20, 26):
        x = px(n)
        s.append(f'<text x="{x:.1f}" y="{T+ph+18}" font-size="11" text-anchor="middle" fill="{MUTED}" font-variant-numeric="tabular-nums">{n}</text>')
    s.append(f'<text x="{L+pw/2:.1f}" y="{H-8}" font-size="11" text-anchor="middle" fill="{INK2}">input length (characters)</text>')

    # Series polylines.
    def path(vals):
        return " ".join(f"{px(n):.1f},{py(v):.1f}" for n, v in zip(ns, vals))

    s.append(f'<polyline points="{path(lin)}" fill="none" stroke="{LIN}" stroke-width="2" stroke-linejoin="round"/>')
    s.append(f'<polyline points="{path(exp)}" fill="none" stroke="{EXP}" stroke-width="2" stroke-linejoin="round"/>')

    # End markers + direct labels.
    ex, ey = px(ns[-1]), py(exp[-1])
    lx, ly = px(ns[-1]), py(lin[-1])
    s.append(f'<circle cx="{ex:.1f}" cy="{ey:.1f}" r="3.5" fill="{EXP}" stroke="{SURFACE}" stroke-width="1.5"/>')
    s.append(f'<circle cx="{lx:.1f}" cy="{ly:.1f}" r="3.5" fill="{LIN}" stroke="{SURFACE}" stroke-width="1.5"/>')
    s.append(f'<text x="{ex+8:.1f}" y="{ey-6:.1f}" font-size="12" font-weight="600" fill="{EXP}">(a+)+$</text>')
    s.append(f'<text x="{ex+8:.1f}" y="{ey+9:.1f}" font-size="10.5" fill="{INK2}">exponential</text>')
    s.append(f'<text x="{lx+8:.1f}" y="{ly+4:.1f}" font-size="12" font-weight="600" fill="{LIN}">a+$</text>')
    s.append(f'<text x="{lx+8:.1f}" y="{ly+19:.1f}" font-size="10.5" fill="{INK2}">linear</text>')

    # Callout: the exponential hits a half-billion steps at 26 chars.
    s.append(
        f'<text x="{L+8}" y="{py(exp[-1])+2:.1f}" font-size="11" fill="{EXP}" font-weight="600">'
        f'{_si(exp[-1])} steps at 26 chars</text>'
    )
    s.append("</svg>")
    return "\n".join(s) + "\n"


def _si(v: int) -> str:
    for div, suf in ((1_000_000_000, "B"), (1_000_000, "M"), (1_000, "K")):
        if v >= div:
            return f"{v/div:.1f}".rstrip("0").rstrip(".") + suf
    return str(v)


def main():
    ns, exp, lin = collect()
    out = ROOT / "docs/figures/growth.svg"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(svg(ns, exp, lin))
    print(f"wrote {out} ({ns[-1]} points; exponential reaches {exp[-1]:,} steps, linear {lin[-1]:,})")


if __name__ == "__main__":
    main()
