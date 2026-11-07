# Tests scripts/install.ps1 against a fake local release (a directory, no
# network) whose binaries are tiny Go programs built here (Go is required).
# QBIT_VAULT_NO_PATH=1 keeps the real user PATH untouched.
#   pwsh -NoProfile -File scripts/install_test.ps1
$ErrorActionPreference = 'Stop'
$script = Join-Path $PSScriptRoot 'install.ps1'
$shell = (Get-Process -Id $PID).Path
$work = Join-Path ([IO.Path]::GetTempPath()) ("qbv-install-test-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
$fails = 0

function Check($what, [bool]$cond) {
    if ($cond) { Write-Host "ok   $what" } else { Write-Host "FAIL $what"; $script:fails++ }
}

# A fake qbit-vault.exe: `version` prints its version, `sync` appends to
# $env:QBV_TEST_SYNC_LOG, anything else prints fake-qbit-vault-<arch>.
$fakeSrc = Join-Path $work 'fake'
New-Item -ItemType Directory -Path $fakeSrc | Out-Null
Set-Content -LiteralPath (Join-Path $fakeSrc 'go.mod') -Value 'module fake'
Set-Content -LiteralPath (Join-Path $fakeSrc 'main.go') -Value @'
package main

import (
	"fmt"
	"os"
)

var version, arch string

func main() {
	switch {
	case len(os.Args) > 1 && os.Args[1] == "version":
		fmt.Println("qbit-vault " + version + " (abc1234, windows/" + arch + ")")
	case len(os.Args) > 1 && os.Args[1] == "sync":
		f, _ := os.OpenFile(os.Getenv("QBV_TEST_SYNC_LOG"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		fmt.Fprintln(f, "sync "+arch)
		f.Close()
	default:
		fmt.Println("fake-qbit-vault-" + arch)
	}
}
'@
function New-Fake($file, $ver, $arch) {
    Push-Location $fakeSrc
    try { go build -o $file -ldflags "-X main.version=$ver -X main.arch=$arch" . } finally { Pop-Location }
    if ($LASTEXITCODE -ne 0) { throw 'could not build the fake binary' }
}

function New-Release($dir) {
    $rel = Join-Path $dir 'v0.0.0-test'
    New-Item -ItemType Directory -Force -Path $rel | Out-Null
    $sums = @()
    foreach ($arch in 'amd64', 'arm64') {
        $src = Join-Path $work "src-$arch"
        New-Item -ItemType Directory -Force -Path $src | Out-Null
        New-Fake (Join-Path $src 'qbit-vault.exe') 'v0.0.0-test' $arch
        $zip = Join-Path $rel "qbit-vault_windows_$arch.zip"
        Compress-Archive -Path (Join-Path $src 'qbit-vault.exe') -DestinationPath $zip -Force
        $sums += "$((Get-FileHash -Algorithm SHA256 $zip).Hash.ToLowerInvariant())  qbit-vault_windows_$arch.zip"
    }
    Set-Content -LiteralPath (Join-Path $rel 'checksums.txt') -Value $sums
}

$env:QBIT_VAULT_HOME = Join-Path $work 'home'
$env:QBV_TEST_SYNC_LOG = Join-Path $work 'sync.log'
$realPath = $env:Path

function Invoke-Install($arch, $release, $dest, $prefixPath = $null, $noSync = $null, $version = 'v0.0.0-test') {
    Set-Content -LiteralPath $env:QBV_TEST_SYNC_LOG -Value $null
    $env:QBIT_VAULT_NO_SYNC = $noSync
    $env:Path = if ($prefixPath) { "$prefixPath;$realPath" } else { $realPath }
    $env:PROCESSOR_ARCHITECTURE = $arch
    $env:QBIT_VAULT_VERSION = $version
    $env:QBIT_VAULT_RELEASE_URL = $release
    $env:QBIT_VAULT_INSTALL_DIR = $dest
    $env:QBIT_VAULT_NO_PATH = '1'
    # Windows PowerShell turns a child's stderr into errors; keep them as output.
    $ErrorActionPreference = 'Continue'
    $out = & $shell -NoProfile -ExecutionPolicy Bypass -File $script 2>&1 | Out-String
    $code = $LASTEXITCODE
    $env:Path = $realPath
    return @{ Code = $code; Out = $out }
}

function Installed($dest) {
    $f = Join-Path $dest 'qbit-vault.exe'
    if (Test-Path -LiteralPath $f) { (& $f | Out-String).Trim() } else { '' }
}

function SyncLog { (Get-Content -Raw -LiteralPath $env:QBV_TEST_SYNC_LOG -ErrorAction SilentlyContinue | Out-String).Trim() }

$realArch = $env:PROCESSOR_ARCHITECTURE
try {
    New-Release (Join-Path $work 'good')

    # 1. A good release installs the binary of the host's architecture.
    $r = Invoke-Install 'AMD64' (Join-Path $work 'good') (Join-Path $work 'dest1')
    Check 'good release exits 0' ($r.Code -eq 0)
    Check 'amd64 archive was chosen' ((Installed (Join-Path $work 'dest1')) -eq 'fake-qbit-vault-amd64')
    Check 'output names the version' ($r.Out -match [regex]::Escape('installing qbit-vault v0.0.0-test (windows/amd64)'))
    Check 'output names the next step' ($r.Out -match 'qbit-vault init')
    Check 'only the binary is left in the target' (@(Get-ChildItem -Force (Join-Path $work 'dest1')).Name -join ',' -eq 'qbit-vault.exe')

    # 2. ARM64 maps to the arm64 archive.
    $r = Invoke-Install 'ARM64' (Join-Path $work 'good') (Join-Path $work 'dest2')
    Check 'ARM64 installs the arm64 binary' ((Installed (Join-Path $work 'dest2')) -eq 'fake-qbit-vault-arm64')

    # 3. A tampered archive is refused and nothing is installed.
    Copy-Item -Recurse (Join-Path $work 'good') (Join-Path $work 'bad')
    Add-Content -LiteralPath (Join-Path $work 'bad\v0.0.0-test\qbit-vault_windows_amd64.zip') -Value 'tampered'
    $r = Invoke-Install 'AMD64' (Join-Path $work 'bad') (Join-Path $work 'dest3')
    Check 'tampered archive exits non-zero' ($r.Code -ne 0)
    Check 'tampered archive reports the mismatch' ($r.Out -match [regex]::Escape('checksum mismatch for qbit-vault_windows_amd64.zip: nothing was installed'))
    Check 'tampered archive installs nothing' (-not (Test-Path (Join-Path $work 'dest3\qbit-vault.exe')))

    # 4. An archive missing from checksums.txt is refused.
    Copy-Item -Recurse (Join-Path $work 'good') (Join-Path $work 'unlisted')
    $sums = Join-Path $work 'unlisted\v0.0.0-test\checksums.txt'
    Set-Content -LiteralPath $sums -Value (Get-Content $sums | Where-Object { $_ -notmatch 'amd64' })
    $r = Invoke-Install 'AMD64' (Join-Path $work 'unlisted') (Join-Path $work 'dest4')
    Check 'unlisted archive exits non-zero' ($r.Code -ne 0)
    Check 'unlisted archive is reported' ($r.Out -match [regex]::Escape('qbit-vault_windows_amd64.zip is not listed in checksums.txt'))
    Check 'unlisted archive installs nothing' (-not (Test-Path (Join-Path $work 'dest4\qbit-vault.exe')))

    # 5. An unsupported architecture stops before any download.
    $r = Invoke-Install 'x86' (Join-Path $work 'good') (Join-Path $work 'dest5')
    Check 'unsupported arch exits non-zero' ($r.Code -ne 0)
    Check 'unsupported arch is reported' ($r.Out -match 'unsupported architecture x86')

    # 6. Re-running replaces the binary in place and leaves no .old file.
    $r = Invoke-Install 'ARM64' (Join-Path $work 'good') (Join-Path $work 'dest1')
    Check 're-install replaces the binary' ((Installed (Join-Path $work 'dest1')) -eq 'fake-qbit-vault-arm64')
    Check 're-install leaves no .old file' (@(Get-ChildItem -Force (Join-Path $work 'dest1') -Filter 'qbit-vault.exe.old*').Count -eq 0)

    # 6b. A leftover .old that cannot be removed (still locked by a running
    # qbit-vault, played here by a non-empty directory) does not block an upgrade.
    New-Item -ItemType Directory -Force -Path (Join-Path $work 'dest1\qbit-vault.exe.old') | Out-Null
    Set-Content -LiteralPath (Join-Path $work 'dest1\qbit-vault.exe.old\busy') -Value 'x'
    $r = Invoke-Install 'AMD64' (Join-Path $work 'good') (Join-Path $work 'dest1')
    Check 'a locked leftover .old does not block the upgrade' ($r.Code -eq 0 -and (Installed (Join-Path $work 'dest1')) -eq 'fake-qbit-vault-amd64')

    # 7. An existing install found on PATH is upgraded in place.
    $prev = Join-Path $work 'prev'
    New-Item -ItemType Directory -Path $prev | Out-Null
    New-Fake (Join-Path $prev 'qbit-vault.exe') 'v0.0.0-old' 'amd64'
    $r = Invoke-Install 'ARM64' (Join-Path $work 'good') '' $prev
    Check 'upgrade exits 0' ($r.Code -eq 0)
    Check 'upgrade replaces the binary where it was' ((Installed $prev) -eq 'fake-qbit-vault-arm64')
    Check 'upgrade names both versions' ($r.Out -match [regex]::Escape('upgrading qbit-vault v0.0.0-old -> v0.0.0-test'))

    # 8. The same version is reported as a reinstall.
    $r = Invoke-Install 'ARM64' (Join-Path $work 'good') '' $prev
    Check 'same version is a reinstall' ($r.Out -match [regex]::Escape('qbit-vault v0.0.0-test is already installed; reinstalling it'))

    # 9. No vault yet: no sync, the next step is init.
    $r = Invoke-Install 'AMD64' (Join-Path $work 'good') (Join-Path $work 'dest9')
    Check 'no vault: sync is not run' ((SyncLog) -eq '')
    Check 'no vault: next step is init' ($r.Out -match [regex]::Escape("next: run 'qbit-vault init'"))
    Check 'no vault: one next step only' ($r.Out -notmatch 'guided setup')

    # 10. A set-up vault: the new binary runs sync, unless QBIT_VAULT_NO_SYNC=1.
    New-Item -ItemType Directory -Force -Path $env:QBIT_VAULT_HOME | Out-Null
    Set-Content -LiteralPath (Join-Path $env:QBIT_VAULT_HOME 'state.json') -Value '{}'
    $r = Invoke-Install 'AMD64' (Join-Path $work 'good') (Join-Path $work 'dest10')
    Check 'set-up vault: the new binary runs sync' ((SyncLog) -eq 'sync amd64')
    Check 'set-up vault: restart hint' ($r.Out -match [regex]::Escape('agent registrations are up to date; restart your agents'))
    Check 'set-up vault: no init hint' ($r.Out -notmatch 'qbit-vault init')
    $r = Invoke-Install 'AMD64' (Join-Path $work 'good') (Join-Path $work 'dest10') $null '1'
    Check 'QBIT_VAULT_NO_SYNC=1 skips sync' ((SyncLog) -eq '')
    Check 'QBIT_VAULT_NO_SYNC=1 says so' ($r.Out -match [regex]::Escape("skipped 'qbit-vault sync' (QBIT_VAULT_NO_SYNC=1)"))
    Remove-Item -Recurse -Force $env:QBIT_VAULT_HOME

    # 11. An explicit directory leaves the old copy alone and warns that it shadows.
    New-Fake (Join-Path $prev 'qbit-vault.exe') 'v0.0.0-old' 'amd64'
    $r = Invoke-Install 'AMD64' (Join-Path $work 'good') (Join-Path $work 'dest11') $prev
    Check 'explicit dir installs there' ((Installed (Join-Path $work 'dest11')) -eq 'fake-qbit-vault-amd64')
    Check 'explicit dir leaves the old copy' ((& (Join-Path $prev 'qbit-vault.exe') version) -match 'v0.0.0-old')
    Check 'explicit dir warns about the shadowing copy' ($r.Out -match [regex]::Escape("another qbit-vault at $(Join-Path $prev 'qbit-vault.exe') comes first on your PATH"))

    # 12. Without QBIT_VAULT_VERSION the newest published release wins, wherever
    # the API lists it (GitHub orders by tag text, so beta.10 comes after beta.9).
    $api = Join-Path $work 'releases.json'
    Set-Content -LiteralPath $api -Value @'
[
  {
    "tag_name": "v0.0.9-old",
    "draft": false,
    "prerelease": true,
    "created_at": "2026-11-06T16:37:55Z",
    "published_at": "2026-11-06T16:41:42Z",
    "assets": [{"name": "checksums.txt", "created_at": "2026-11-06T18:00:00Z"}]
  },
  {
    "tag_name": "v0.0.0-draft",
    "draft": true,
    "created_at": "2026-11-06T19:00:00Z",
    "published_at": null
  },
  {
    "tag_name": "v0.0.0-test",
    "draft": false,
    "prerelease": true,
    "created_at": "2026-11-06T16:57:22Z",
    "published_at": "2026-11-06T17:00:26Z"
  }
]
'@
    $env:QBIT_VAULT_RELEASES_API = $api
    $r = Invoke-Install 'AMD64' (Join-Path $work 'good') (Join-Path $work 'dest12') $null $null ''
    Remove-Item Env:QBIT_VAULT_RELEASES_API
    Check 'newest published release is chosen' ($r.Out -match [regex]::Escape('installing qbit-vault v0.0.0-test (windows/amd64)'))
    Check 'newest published release installs' ((Installed (Join-Path $work 'dest12')) -eq 'fake-qbit-vault-amd64')

    # 13. The PATH comparison ignores a trailing backslash and case, so a re-run
    # does not add a duplicate entry.
    $dest13 = Join-Path $work 'dest13'
    $env:QBIT_VAULT_USER_PATH = "C:\somewhere;$($dest13.ToUpperInvariant())\"
    $r = Invoke-Install 'AMD64' (Join-Path $work 'good') $dest13
    Check 'PATH entry with a trailing backslash counts as present' ($r.Out -notmatch 'is not on your PATH')
    $env:QBIT_VAULT_USER_PATH = 'C:\somewhere'
    $r = Invoke-Install 'AMD64' (Join-Path $work 'good') $dest13
    Check 'a directory missing from PATH is reported' ($r.Out -match 'is not on your PATH')
    Remove-Item Env:QBIT_VAULT_USER_PATH

    # 14. A GitHub API failure says what to do.
    $env:QBIT_VAULT_RELEASES_API = 'https://127.0.0.1:9/releases'
    $r = Invoke-Install 'AMD64' (Join-Path $work 'good') (Join-Path $work 'dest14') $null $null ''
    Remove-Item Env:QBIT_VAULT_RELEASES_API
    Check 'API failure exits non-zero' ($r.Code -ne 0)
    Check 'API failure names the way out' (($r.Out -replace '[\s|]+', ' ') -match [regex]::Escape('could not reach the GitHub API (rate limit or network); set QBIT_VAULT_VERSION=vX.Y.Z and try again'))
    Check 'API failure installs nothing' (-not (Test-Path -LiteralPath (Join-Path $work 'dest14')))
} finally {
    $env:Path = $realPath
    $env:PROCESSOR_ARCHITECTURE = $realArch
    'QBIT_VAULT_USER_PATH', 'QBIT_VAULT_VERSION', 'QBIT_VAULT_RELEASES_API', 'QBIT_VAULT_RELEASE_URL', 'QBIT_VAULT_INSTALL_DIR', 'QBIT_VAULT_NO_PATH', 'QBIT_VAULT_NO_SYNC', 'QBIT_VAULT_HOME', 'QBV_TEST_SYNC_LOG' | ForEach-Object { Remove-Item "Env:$_" -ErrorAction SilentlyContinue }
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}

if ($fails -ne 0) { Write-Host "$fails check(s) failed"; exit 1 }
Write-Host 'all install.ps1 checks passed'
