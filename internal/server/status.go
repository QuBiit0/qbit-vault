package server

import (
	"fmt"
	"html"
	"net/http"
)

// statusDocsURL is where the status page sends people who found the server.
const statusDocsURL = "https://github.com/QuBiit0/qbit-vault"

// statusPage is the page GET / answers: the brand, the versions and one
// sentence on what the server is. It is static apart from the version, shows
// nothing about accounts, devices or usage, and needs no script and no
// request to another host (colors from design/system.md, mark from
// assets/brand/qbit-vault-mark.svg).
func statusPage(version string) []byte {
	if version == "" {
		version = "dev"
	}
	return []byte(fmt.Sprintf(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>QBit Vault sync server</title>
<style>
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;background:#000204;color:#C7D9DE;font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{width:100%%;max-width:520px;background:#07121B;border:1px solid #16303D;border-radius:16px;padding:32px 28px}
svg{display:block;width:96px;height:96px;margin:0 auto 12px}
h1{margin:0 0 4px;font-size:1.5rem;font-weight:600;letter-spacing:.01em;text-align:center}
h1 span{color:#91ECC5}
.up{margin:0 0 24px;text-align:center;color:#91ECC5}
.up:before{content:"";display:inline-block;width:.6em;height:.6em;margin-right:.5em;border-radius:50%%;background:#2FBF78}
dl{margin:0 0 24px;display:grid;grid-template-columns:auto 1fr;gap:6px 16px;border-top:1px solid #16303D;border-bottom:1px solid #16303D;padding:14px 0}
dt{color:#8FA7B2}
dd{margin:0;font-family:ui-monospace,SFMono-Regular,Consolas,Menlo,monospace}
p{margin:0 0 12px;color:#C7D9DE}
a{color:#7FD0EC}
a:focus-visible{outline:2px solid #2E9BE0;outline-offset:3px}
</style>
</head>
<body>
<main>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 380 380" role="img" aria-label="QBit Vault">
<defs>
<linearGradient id="q" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#7FD0EC"/><stop offset="1" stop-color="#91ECC5"/></linearGradient>
<linearGradient id="qs" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="#2E9BE0"/><stop offset="1" stop-color="#2FBF78"/></linearGradient>
</defs>
<g fill="none" stroke="url(#qs)" stroke-width="2" opacity=".7"><ellipse cx="190" cy="190" rx="170" ry="58" transform="rotate(-28 190 190)"/></g>
<circle cx="334" cy="110" r="6" fill="#91ECC5"/>
<g fill="none" stroke="url(#qs)" stroke-width="2" opacity=".55"><ellipse cx="190" cy="190" rx="170" ry="58" transform="rotate(32 190 190)"/></g>
<circle cx="52" cy="104" r="5" fill="#7FD0EC"/>
<rect x="104" y="96" width="172" height="172" rx="58" fill="none" stroke="url(#q)" stroke-width="20"/>
<path d="M232 226 L282 282" stroke="url(#q)" stroke-width="20" stroke-linecap="round"/>
<circle cx="190" cy="168" r="18" fill="url(#q)"/>
<path d="M181 180 L174 214 L206 214 L199 180 Z" fill="url(#q)"/>
</svg>
<h1>QBit <span>Vault</span></h1>
<p class="up">This QBit Vault sync server is running</p>
<dl>
<dt>Server version</dt><dd>%s</dd>
<dt>API version</dt><dd>API v%d</dd>
</dl>
<p>This server only stores data sealed on your devices. It cannot read your secrets.</p>
<p><a href="%s">Documentation</a></p>
</main>
</body>
</html>
`, html.EscapeString(version), API, statusDocsURL))
}

// status answers GET / and HEAD /. The headers keep the page inert even if
// it were ever framed or given another body.
func (s *Server) status() http.HandlerFunc {
	page := statusPage(s.cfg.Version)
	return func(w http.ResponseWriter, _ *http.Request) {
		h := w.Header()
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		_, _ = w.Write(page)
	}
}
