# design/: visual identity and artboards

Design work for QBit Vault under the **qbitdev** brand. Each artboard is one self-contained HTML file (inline CSS, system fonts, no network, no build step).

## Contents

| Path | What it is |
| --- | --- |
| [system.md](system.md) | The design system: concept, color tokens, typography, the mark and the terminal rules. The source of truth for the palette used by the README banner and the TUI |
| `system.html` | The same system rendered as a page |
| `qbitdev-vault-identity/` | Three identity directions (`01-atom-keyhole.html`, `02-hex-seal.html`, `03-orbit-lock.html`). `01-atom-keyhole.html` was chosen (see `system.md`) |
| `qbitdev-vault-tui/` | Three artboards for the interactive terminal app (`01-panes.html`, `02-launcher.html`, `03-command.html`) |
| `*/design.json`, `*/handoffs.json` | State written by the design tool (brief, chosen direction, hand-off status). Not meant to be edited by hand |

## How to view them

Open any `.html` file in a browser. From the repository root:

```bash
# macOS            open design/system.html
# Linux            xdg-open design/system.html
# Windows (cmd)    start design\system.html
```

Check them at 1440 px and 390 px wide.

## Related

- Brand files (banner, mark, icon, terminal marks): [../assets/brand/](../assets/brand/README.md).
- The TUI implements the TUI artboards; its record is [../odd/tasks/tui.md](../odd/tasks/tui.md).
