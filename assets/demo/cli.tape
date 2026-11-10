# CLI flow: names only, a redacted exec, a healthy doctor. Writes cli.gif.
Output "/work/out/cli.gif"

Set Shell "bash"
Set FontSize 17
Set Width 1400
Set Height 440
Set Padding 14
Set Framerate 20
Set TypingSpeed 45ms
Set WindowBar Colorful
Set BorderRadius 8
Set Theme { "name": "qbit-vault", "black": "#07121B", "red": "#F07A6A", "green": "#2FBF78", "yellow": "#E8B04A", "blue": "#2E9BE0", "magenta": "#7FD0EC", "cyan": "#91ECC5", "white": "#C7D9DE", "brightBlack": "#16303D", "brightRed": "#F07A6A", "brightGreen": "#91ECC5", "brightYellow": "#E8B04A", "brightBlue": "#7FD0EC", "brightMagenta": "#7FD0EC", "brightCyan": "#91ECC5", "brightWhite": "#FFFFFF", "background": "#07121B", "foreground": "#C7D9DE", "selection": "#16303D", "cursor": "#2E9BE0" }

Hide
Type "cd /root/demo/work/acme-api && export PS1='$ ' && clear" Enter
Show
Type "# the agent sees names, never values" Enter
Sleep 500ms
Type "qbit-vault list" Enter
Sleep 2500ms
Type "clear" Enter
Type "# a command that prints the token: the output comes back redacted" Enter
Type "qbit-vault exec --secret OPENAI_API_KEY -- sh show-token.sh" Enter
Sleep 3500ms
Type "qbit-vault doctor" Enter
Sleep 4s
