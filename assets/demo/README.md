# Demo assets

Recorded from the real binary with [VHS](https://github.com/charmbracelet/vhs) (in Docker), on a throwaway demo vault with obviously fake values. Nothing comes from a real vault.

| File | Shows |
| --- | --- |
| `../screenshots/tui-home.png` | The TUI home: sections, the list and the detail pane (names, descriptions and flags; the value is never shown). |
| `tui.gif` | A short tour: Secrets, Grants, Hosts, Audit, Doctor, quit. |
| `cli.gif` | `qbit-vault list` (names only), an `exec` whose child prints the value and gets it back as `[REDACTED:NAME]`, and `qbit-vault doctor` ending in `healthy`. |

## Regenerate

```bash
bash assets/demo/make.sh
```

Needs Go and Docker (Git Bash on Windows works). It builds a Linux binary into a temp directory, runs `setup-demo.sh` inside the `ghcr.io/charmbracelet/vhs` container to create the demo vault, then records `tui.tape` and `cli.tape` and copies the three outputs into place. Nothing else is written to the repository.

- The demo vault is a passphrase vault in the container. Its prompts (values, grant confirmations, the passphrase) are answered by the scripted prompt backend, which exists only in binaries built with `-tags e2eprompt`. `make.sh` builds that binary for the recording only; it is never a release binary.
- The grants are made with `qbit-vault grant`, as a user would. Nothing is weakened.
- The version in the TUI header is `DEMO_VERSION` (default `v1.0.0`), set with `-ldflags` at build time. Override it: `DEMO_VERSION=v1.1.0 bash assets/demo/make.sh`.
- Terminal: 1400 px wide, font size 17, the QBit Vault palette from `design/system.md` (background `#07121B`). Edit the `.tape` files to change size, theme or pacing.
