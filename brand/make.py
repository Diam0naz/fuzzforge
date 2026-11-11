"""Generate the Fuzzforge mark. One geometry, several colourings; run `python3 make.py`.

The mark is the F of Fuzzforge built from bars of tempered steel (the site's
temper palette, straw to blue), stacked like fuzz inputs. The middle arm is
displaced and in oxide red: the mutated input that broke something.
"""

# Every bar clears 3:1 against #f1f3f4 / #ffffff (light) and #0e151d / #17202c (dark).
# Full mark, 48-unit grid: six bars 6 high with 2-unit gaps.
ROWS = [  # (y, x0, x1, role)
    (1, 6, 42, "t0"),    # top arm
    (9, 6, 16, "t1"),    # stem
    (17, 10, 38, "hit"), # middle arm, displaced 4 right
    (25, 6, 16, "t2"),
    (33, 6, 16, "t3"),
    (41, 6, 16, "t4"),
]
# Small mark (favicon), 16-unit grid: four bars 3 high, 1-unit gaps.
SMALL = [(1, 2, 14, "t0"), (5, 2, 6, "t1"), (9, 4, 12, "hit"), (13, 2, 6, "t4")]

LIGHT = {"t0": "#a8822f", "t1": "#8f6226", "t2": "#5b4f9b", "t3": "#3d57a8", "t4": "#2a4a9e", "hit": "#a3362e"}
DARK = {"t0": "#e4c57c", "t1": "#cf9a55", "t2": "#8f84d6", "t3": "#6f8fe2", "t4": "#9db6ea", "hit": "#e2675b"}
INK = "#17202c"


def bars(rows, h, fill):
    return "\n".join(f'  <rect x="{x0}" y="{y}" width="{x1 - x0}" height="{h}" fill="{fill(r)}"/>' for y, x0, x1, r in rows)


def svg(size, body, title="Fuzzforge"):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {size} {size}" width="{size}" height="{size}" role="img" aria-label="{title}">\n'
            f"  <title>{title}</title>\n{body}\n</svg>\n")


files = {
    "fuzzforge-mark.svg": svg(48, bars(ROWS, 6, lambda r: LIGHT[r])),
    "fuzzforge-mark-dark.svg": svg(48, bars(ROWS, 6, lambda r: DARK[r])),
    "fuzzforge-mark-mono.svg": svg(48, bars(ROWS, 6, lambda r: "currentColor")),
    "fuzzforge-mark-ink.svg": svg(48, bars(ROWS, 6, lambda r: "#a3362e" if r == "hit" else INK)),
}

# Favicon follows the browser's theme.
css = "".join(f".{k}{{fill:{v}}}" for k, v in LIGHT.items())
css_dark = "".join(f".{k}{{fill:{v}}}" for k, v in DARK.items())
small = "\n".join(f'  <rect class="{r}" x="{x0}" y="{y}" width="{x1 - x0}" height="3"/>' for y, x0, x1, r in SMALL)
files["fuzzforge-icon.svg"] = svg(16, f"  <style>{css}@media (prefers-color-scheme:dark){{{css_dark}}}</style>\n{small}")

# Lockup: mark plus wordmark in Archivo, expanded 125%, weight 760 (as on the site).
mark = bars(ROWS, 6, lambda r: LIGHT[r])
files["fuzzforge-lockup.svg"] = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 268 48" width="268" height="48" role="img" aria-label="Fuzzforge">\n'
    "  <title>Fuzzforge</title>\n"
    f"{mark}\n"
    f'  <text x="58" y="37" fill="{INK}" font-family="Archivo, \'Helvetica Neue\', Arial, sans-serif" '
    'font-size="33" font-weight="760" font-stretch="125%" letter-spacing="-0.6">Fuzzforge</text>\n'
    "</svg>\n"
)

for name, text in files.items():
    open(name, "w").write(text)
    print("wrote", name)

# The same geometry for the site's React component.
import json
print(json.dumps({"rows": ROWS, "light": LIGHT, "dark": DARK}))
