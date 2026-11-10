# TUI tour: the home, then each section. Writes tui.gif and tui-home.png.
Output "/work/out/tui.gif"

Set Shell "bash"
Set FontSize 17
Set Width 1400
Set Height 660
Set Padding 14
Set Framerate 20
Set TypingSpeed 60ms
Set WindowBar Colorful
Set BorderRadius 8
Set Theme { "name": "qbit-vault", "black": "#07121B", "red": "#F07A6A", "green": "#2FBF78", "yellow": "#E8B04A", "blue": "#2E9BE0", "magenta": "#7FD0EC", "cyan": "#91ECC5", "white": "#C7D9DE", "brightBlack": "#16303D", "brightRed": "#F07A6A", "brightGreen": "#91ECC5", "brightYellow": "#E8B04A", "brightBlue": "#7FD0EC", "brightMagenta": "#7FD0EC", "brightCyan": "#91ECC5", "brightWhite": "#FFFFFF", "background": "#07121B", "foreground": "#C7D9DE", "selection": "#16303D", "cursor": "#2E9BE0" }

Hide
Type "cd /root/demo/work/acme-api && clear" Enter
Show
Type "qbit-vault" Enter
Sleep 3s
Screenshot "/work/out/tui-home.png"
Tab
Sleep 500ms
Down 1
Sleep 700ms
Down 1
Sleep 700ms
Down 1
Sleep 700ms
Up 3
Sleep 400ms
Tab
Sleep 200ms
Type "2"
Sleep 1800ms
Type "3"
Sleep 1800ms
Type "4"
Sleep 1800ms
Type "6"
Sleep 2200ms
Type "1"
Sleep 1200ms
Type "q"
Sleep 800ms
