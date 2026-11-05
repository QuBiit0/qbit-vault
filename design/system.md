# QBit Vault design system (qbitdev brand)

QBit Vault is a product of the user's personal brand **qbitdev**. Accepted on 2026-11-05: the user picked `design/qbitdev-vault-identity/01-atom-keyhole.html` ("Atom keyhole"). Colors were measured from the user's qbitdev logo image (banner sent in chat on 2026-11-05) and refined in that artboard; every token below names that artboard as its source. This replaces the earlier "Dial" system (design/qbit-vault-identity/02-dial.html), which is history only.

## Concept

The qbitdev Q (a rounded square with a tail, outlined with a blue-to-green gradient, inside two atom orbits) keeps its shape; its counter becomes a keyhole. On small sizes the orbits drop and the Q stands alone. Lowercase, light wordmark `qbit vault`, with the line `by qbitdev`.

## Colors

| Token | Value | Usage | Source |
| --- | --- | --- | --- |
| void | `#000204` | page and banner background | design/qbitdev-vault-identity/01-atom-keyhole.html (measured from the logo background) |
| deep | `#07121B` | panels, terminal background, icon plate | same |
| line | `#16303D` | borders and dividers on dark | same |
| qubit-blue | `#2E9BE0` | actions, focus, links | same (logo blue `#4891B4`, glow `#7FD0EC`) |
| qubit-green | `#2FBF78` | granted, healthy, success | same (logo green `#4BB480`, glow `#91ECC5`) |
| blue-glow | `#7FD0EC` | mark gradient start, info text on dark | same |
| green-glow | `#91ECC5` | mark gradient end, success text on dark | same |
| frost | `#C7D9DE` | primary text on dark, wordmark | same (measured wordmark color) |
| mist | `#8FA7B2` | secondary text on dark | same |
| flare | `#F07A6A` | refused, errors | same |
| gradient | `#2E9BE0 -> #2FBF78` (mark: `#7FD0EC -> #91ECC5`) | the mark and the selected row only; never for text blocks or backgrounds | same |
| on-light gradient | `#1C6E9E -> #1F8A57` | the mark on light backgrounds | same |

## Typography

- Wordmark and display: light (300) system grotesk (`Segoe UI Variable Display`, `SF Pro Display`, `Helvetica Neue`), lowercase `qbit vault`. Intended typeface at implementation: Sora Light (open), matching the qbitdev wordmark.
- Text: system UI sans, 16px/1.6 (intended: Inter).
- Mono (terminal, data): `ui-monospace`, `Cascadia Code`, `SF Mono`, `Consolas` (intended: JetBrains Mono).

## Shape and spacing

- Radius: 14px on panels and tiles, 84/380 on the app icon plate; the Q itself is a rounded square (rx 58/172).
- Glow: a soft blur (stdDeviation 5) behind the mark on dark backgrounds only.
- Spacing scale: 4, 8, 12, 18, 24, 28, 56, 80 px.

## Components

- Mark: `assets/brand/qbit-vault-mark.svg` (with orbits), `assets/brand/qbit-vault-icon.svg` (app icon, no orbits), `assets/brand/qbit-vault-banner.svg` (README, 1280 x 320).
- Terminal mark: rasterized from the mark's geometry with half blocks (`▀`, truecolor foreground = top pixel, background = bottom pixel), antialiased against `#02080D`, by `assets/brand/term-mark.py SIZE ansi [--no-orbits]`. Header: 16 columns x 8 rows, no orbits, next to the wordmark `qbit vault` (`vault` in green-glow), `0.1.0  by qbitdev` and the status line in mist. Splash (first run, no arguments): 40 columns with orbits. Pre-rendered: `assets/brand/qbit-vault-mark-16.ans`, `qbit-vault-mark-40.ans`. Sizes under 22 px of Q enlarge the keyhole optically. Without truecolor: 256-color fallback.
- Selection in the terminal: white text on the blue-to-green gradient (in a real terminal: a two-stop approximation, `#1C6E9E` background).
- Status colors: qubit-green for granted or healthy, flare for refused or errors, blue-glow for information, a warm `#E8B04A` only for warnings.
