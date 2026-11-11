# Fuzzforge mark

The mark is the F of Fuzzforge, built from bars of tempered steel and
stacked like fuzz inputs. The middle arm is knocked out of line and coloured
oxide red: the one input that broke something. The bars follow the colours
steel takes on as it is tempered, straw to bronze to violet to blue, which is
the site's temper palette.

`make.py` generates every file here from one geometry. Edit it, not the SVGs.

| File | Use |
|---|---|
| `fuzzforge-mark.svg` | Default, on light backgrounds |
| `fuzzforge-mark-dark.svg` | On dark backgrounds |
| `fuzzforge-mark-ink.svg` | One ink colour plus the red arm (stamps, single-colour print with a spot red) |
| `fuzzforge-mark-mono.svg` | `currentColor` only, for embedding in UI or one-colour print |
| `fuzzforge-icon.svg` | 16-unit four-bar version for favicons and anything under 24 px; follows the browser's light or dark theme. Copied to `frontend/app/icon.svg`. |
| `fuzzforge-lockup.svg` | Mark plus wordmark |

## Rules

- **Wordmark:** Archivo, width 125%, weight 760, tracking -0.02em, as on the
  site. The lockup SVG sets the wordmark as live text, so it needs Archivo
  installed. Elsewhere it falls back to Arial: for print, set the wordmark in
  Archivo next to the mark.
- **Clear space:** at least one bar height (1/8 of the mark's height) on every
  side.
- **Minimum size:** the six-bar mark at 24 px or larger; below that, use
  `fuzzforge-icon.svg`.
- **Contrast:** every bar clears 3:1 against `#f1f3f4` and `#ffffff` (light
  set) and against `#0e151d` and `#17202c` (dark set).
- **Never:**
  - realign the displaced arm (it is the point of the mark);
  - recolour it anything but oxide red;
  - round the bars;
  - add a gradient across a bar.

## Colours

| Bar | Light | Dark |
|---|---|---|
| Top arm (straw) | `#a8822f` | `#e4c57c` |
| Stem (bronze) | `#8f6226` | `#cf9a55` |
| Displaced arm (oxide) | `#a3362e` | `#e2675b` |
| Stem (violet) | `#5b4f9b` | `#8f84d6` |
| Stem (blue) | `#3d57a8` | `#6f8fe2` |
| Stem (deep blue / pale blue) | `#2a4a9e` | `#9db6ea` |
| Ink | `#17202c` | — |
