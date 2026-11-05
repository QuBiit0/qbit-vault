# assets/brand/: brand assets

Files for QBit Vault (**qbitdev** brand). Colors, geometry rules and usage are defined in [../../design/system.md](../../design/system.md).

| File | Use |
| --- | --- |
| `qbit-vault-banner.svg` | README banner, 1280 x 320 |
| `qbit-vault-mark.svg` | The mark with the two atom orbits |
| `qbit-vault-icon.svg` | App icon: the mark without orbits, on a plate |
| `qbit-vault-mark-16.ans`, `qbit-vault-mark-40.ans` | Pre-rendered terminal marks (16 columns without orbits, 40 columns with), truecolor half blocks. Print them with `cat` in a truecolor terminal |
| `term-mark.py` | Renders the mark from its geometry (the generator of the `.ans` files; the TUI has its own Go port in `internal/tui`) |

## `term-mark.py`

Python 3, standard library only.

```bash
python term-mark.py SIZE [ansi|html] [--no-orbits] [--cell=N]
```

- `SIZE` is the width in pixels, which is also the width in terminal columns; the height is `SIZE/2` rows (each cell holds two square pixels).
- `ansi` (default) prints escape sequences for a truecolor terminal; `html` prints a `div` of cells, `--cell=N` sets the cell size in pixels (default 8).
- `--no-orbits` draws the Q alone.

```bash
python term-mark.py 40 ansi > qbit-vault-mark-40.ans
python term-mark.py 16 ansi --no-orbits > qbit-vault-mark-16.ans
```
