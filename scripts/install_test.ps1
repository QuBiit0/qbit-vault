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

# .NET directly: Get-FileHash is missing when Windows PowerShell inherits pwsh's module path.
function Get-Sha256($file) {
    $stream = [IO.File]::OpenRead($file)
    try { -join ([Security.Cryptography.SHA256]::Create().ComputeHash($stream) | ForEach-Object { $_.ToString('x2') }) } finally { $stream.Dispose() }
}

function New-Release($dir, $ver = 'v0.0.0-test') {
    $rel = Join-Path $dir $ver
    New-Item -ItemType Directory -Force -Path $rel | Out-Null
    $sums = @()
    foreach ($arch in 'amd64', 'arm64') {
        $src = Join-Path $work "src-$arch"
        New-Item -ItemType Directory -Force -Path $src | Out-Null
        New-Fake (Join-Path $src 'qbit-vault.exe') $ver $arch
        $zip = Join-Path $rel "qbit-vault_windows_$arch.zip"
        Compress-Archive -Path (Join-Path $src 'qbit-vault.exe') -DestinationPath $zip -Force
        $sums += "$(Get-Sha256 $zip)  qbit-vault_windows_$arch.zip"
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

# A stub minisign.exe: logs its arguments to $env:QBV_TEST_MINISIGN_LOG and exits
# 0 only when -P is $env:QBV_TEST_KEY, -m exists and the -x file starts with
# STUB-VALID.
$msSrc = Join-Path $work 'ms'
New-Item -ItemType Directory -Path $msSrc | Out-Null
Set-Content -LiteralPath (Join-Path $msSrc 'go.mod') -Value 'module stub'
Set-Content -LiteralPath (Join-Path $msSrc 'main.go') -Value @'
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func main() {
	f, _ := os.OpenFile(os.Getenv("QBV_TEST_MINISIGN_LOG"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	fmt.Fprintln(f, strings.Join(os.Args[1:], " "))
	f.Close()
	var k, x, m string
	for i := 1; i+1 < len(os.Args); i++ {
		switch os.Args[i] {
		case "-P":
			k = os.Args[i+1]
		case "-x":
			x = os.Args[i+1]
		case "-m":
			m = os.Args[i+1]
		}
	}
	if _, err := os.Stat(m); err != nil || k != os.Getenv("QBV_TEST_KEY") {
		os.Exit(1)
	}
	sf, err := os.Open(x)
	if err != nil {
		os.Exit(1)
	}
	line, _ := bufio.NewReader(sf).ReadString('\n')
	if strings.TrimSpace(line) != "STUB-VALID" {
		os.Exit(1)
	}
}
'@
$msBin = Join-Path $work 'bin-ms'
New-Item -ItemType Directory -Path $msBin | Out-Null
Push-Location $msSrc
try { go build -o (Join-Path $msBin 'minisign.exe') . } finally { Pop-Location }
if ($LASTEXITCODE -ne 0) { throw 'could not build the minisign stub' }
$key = (Get-Content -LiteralPath (Join-Path $PSScriptRoot '../defaults/release-key.pub'))[1]
$env:QBV_TEST_KEY = $key
$env:QBV_TEST_MINISIGN_LOG = Join-Path $work 'minisign.log'
$warning = "minisign not found: checksums.txt was checked with SHA-256 only. Verify the signature with: minisign -V -P $key -m checksums.txt -x checksums.txt.minisig"
$hostHasMinisign = [bool](Get-Command minisign -CommandType Application -ErrorAction SilentlyContinue)

function New-SignedRelease($dir, $ver, $sig = $null) {
    New-Release $dir $ver
    if ($null -ne $sig) { Set-Content -LiteralPath (Join-Path $dir "$ver\checksums.txt.minisig") -Value $sig }
}
function Invoke-MsInstall($release, $dest, $ver, $withStub = $true) {
    Set-Content -LiteralPath $env:QBV_TEST_MINISIGN_LOG -Value $null
    Invoke-Install 'AMD64' $release $dest $(if ($withStub) { $msBin } else { $null }) $null $ver
}

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

    # 15. Minisign (S6): the stub stands in for the real tool.
    New-SignedRelease (Join-Path $work 's-valid') 'v1.4.0' 'STUB-VALID'
    $r = Invoke-MsInstall (Join-Path $work 's-valid') (Join-Path $work 'dest15a') 'v1.4.0'
    Check 'signed release with minisign exits 0' ($r.Code -eq 0)
    Check 'signed release is installed' ((Installed (Join-Path $work 'dest15a')) -eq 'fake-qbit-vault-amd64')
    Check 'signed release says it verified' ($r.Out -match [regex]::Escape('checksums.txt signature verified with minisign'))
    Check 'minisign gets the pinned key and files' ((Get-Content -Raw -LiteralPath $env:QBV_TEST_MINISIGN_LOG) -match ('(?m)^-V -q -P ' + [regex]::Escape($key) + ' -m .*checksums\.txt -x .*checksums\.txt\.minisig\s*$'))
    Check 'signed release prints no SHA-256-only warning' ($r.Out -notmatch 'minisign not found')

    New-SignedRelease (Join-Path $work 's-bad') 'v1.4.0' 'STUB-BAD'
    $r = Invoke-MsInstall (Join-Path $work 's-bad') (Join-Path $work 'dest15b') 'v1.4.0'
    Check 'bad signature exits non-zero' ($r.Code -ne 0)
    Check 'bad signature is reported' (($r.Out -replace '[\s|]+', ' ') -match [regex]::Escape('the signature of checksums.txt for v1.4.0 does not verify with the QBit Vault'))
    Check 'bad signature installs nothing' (-not (Test-Path -LiteralPath (Join-Path $work 'dest15b\qbit-vault.exe')))

    New-SignedRelease (Join-Path $work 's-missing') 'v1.4.0'
    $r = Invoke-MsInstall (Join-Path $work 's-missing') (Join-Path $work 'dest15c') 'v1.4.0'
    Check 'missing signature of a signed version exits non-zero' ($r.Code -ne 0)
    Check 'missing signature is reported' (($r.Out -replace '[\s|]+', ' ') -match [regex]::Escape('the release v1.4.0 has no checksums.txt.minisig'))
    Check 'missing signature installs nothing' (-not (Test-Path -LiteralPath (Join-Path $work 'dest15c\qbit-vault.exe')))

    # Without minisign: the exact warning, and the install goes on. A host that
    # has the real minisign cannot play this case.
    if ($hostHasMinisign) {
        Write-Host 'skip minisign absent (minisign is installed on this host)'
    } else {
        $r = Invoke-MsInstall (Join-Path $work 's-valid') (Join-Path $work 'dest15d') 'v1.4.0' $false
        Check 'no minisign: install goes on' ($r.Code -eq 0 -and (Installed (Join-Path $work 'dest15d')) -eq 'fake-qbit-vault-amd64')
        Check 'no minisign: the warning is printed exactly' (($r.Out -split '[\r\n]+') -contains $warning)
    }

    # Below the first signed version the release says it is unsigned; at or
    # above it a missing .minisig is refused (numeric compare).
    New-SignedRelease (Join-Path $work 's-old') 'v1.3.9'
    $r = Invoke-MsInstall (Join-Path $work 's-old') (Join-Path $work 'dest15f') 'v1.3.9'
    Check 'older release without .minisig installs' ($r.Code -eq 0 -and (Installed (Join-Path $work 'dest15f')) -eq 'fake-qbit-vault-amd64')
    Check 'older release says it is unsigned' (($r.Out -replace '[\s|]+', ' ') -match [regex]::Escape('v1.3.9 predates signed releases (first signed: v1.4.0)'))
    New-SignedRelease (Join-Path $work 's-old2') 'v0.0.0-test' 'STUB-BAD'
    $r = Invoke-MsInstall (Join-Path $work 's-old2') (Join-Path $work 'dest15g') 'v0.0.0-test'
    Check 'older release with a bad .minisig is still refused' ($r.Code -ne 0 -and -not (Test-Path -LiteralPath (Join-Path $work 'dest15g\qbit-vault.exe')))
    New-SignedRelease (Join-Path $work 's-ten') 'v1.10.0'
    $r = Invoke-MsInstall (Join-Path $work 's-ten') (Join-Path $work 'dest15h') 'v1.10.0'
    Check 'v1.10.0 counts as signed (numeric compare)' ($r.Code -ne 0 -and -not (Test-Path -LiteralPath (Join-Path $work 'dest15h\qbit-vault.exe')))
    New-SignedRelease (Join-Path $work 's-beta') 'v1.4.0-beta.1'
    $r = Invoke-MsInstall (Join-Path $work 's-beta') (Join-Path $work 'dest15i') 'v1.4.0-beta.1'
    Check 'a pre-release of the first signed version counts as signed' ($r.Code -ne 0 -and -not (Test-Path -LiteralPath (Join-Path $work 'dest15i\qbit-vault.exe')))
    # 16. A .minisig that cannot be downloaded is not "no .minisig" (S2): the
    # user is told the download failed, with a fixed short reason, and nothing
    # is installed. The file is held open exclusively, so reading it fails.
    foreach ($ver in 'v1.4.0', 'v1.3.9') {
        $rel = Join-Path $work "s-locked-$ver"
        New-SignedRelease $rel $ver 'STUB-VALID'
        $lock = [IO.File]::Open((Join-Path $rel "$ver\checksums.txt.minisig"), 'Open', 'Read', 'None')
        try {
            $r = Invoke-MsInstall $rel (Join-Path $work "dest16-$ver") $ver
        } finally { $lock.Dispose() }
        Check "unreadable signature of $ver exits non-zero" ($r.Code -ne 0)
        Check "unreadable signature of $ver is reported" (($r.Out -replace '[\s|]+', ' ') -match [regex]::Escape("could not download the signature of the release ${ver}: request failed; nothing was installed"))
        Check "unreadable signature of $ver installs nothing" (-not (Test-Path -LiteralPath (Join-Path $work "dest16-$ver\qbit-vault.exe")))
        Check "unreadable signature of $ver never runs minisign" ((Get-Item -LiteralPath $env:QBV_TEST_MINISIGN_LOG).Length -le 2)
    }
} finally {
    $env:Path = $realPath
    $env:PROCESSOR_ARCHITECTURE = $realArch
    'QBIT_VAULT_USER_PATH', 'QBIT_VAULT_VERSION', 'QBIT_VAULT_RELEASES_API', 'QBIT_VAULT_RELEASE_URL', 'QBIT_VAULT_INSTALL_DIR', 'QBIT_VAULT_NO_PATH', 'QBIT_VAULT_NO_SYNC', 'QBIT_VAULT_HOME', 'QBV_TEST_SYNC_LOG', 'QBV_TEST_KEY', 'QBV_TEST_MINISIGN_LOG' | ForEach-Object { Remove-Item "Env:$_" -ErrorAction SilentlyContinue }
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}

if ($fails -ne 0) { Write-Host "$fails check(s) failed"; exit 1 }
Write-Host 'all install.ps1 checks passed'
