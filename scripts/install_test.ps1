# Tests scripts/install.ps1 against a fake local release (a directory, no
# network). QBIT_VAULT_NO_PATH=1 keeps the real user PATH untouched.
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

function New-Release($dir) {
    $rel = Join-Path $dir 'v0.0.0-test'
    New-Item -ItemType Directory -Force -Path $rel | Out-Null
    $sums = @()
    foreach ($arch in 'amd64', 'arm64') {
        $src = Join-Path $work "src-$arch"
        New-Item -ItemType Directory -Force -Path $src | Out-Null
        Set-Content -NoNewline -LiteralPath (Join-Path $src 'qbit-vault.exe') -Value "fake-qbit-vault-$arch"
        $zip = Join-Path $rel "qbit-vault_windows_$arch.zip"
        Compress-Archive -Path (Join-Path $src 'qbit-vault.exe') -DestinationPath $zip -Force
        $sums += "$((Get-FileHash -Algorithm SHA256 $zip).Hash.ToLowerInvariant())  qbit-vault_windows_$arch.zip"
    }
    Set-Content -LiteralPath (Join-Path $rel 'checksums.txt') -Value $sums
}

function Invoke-Install($arch, $release, $dest) {
    $env:PROCESSOR_ARCHITECTURE = $arch
    $env:QBIT_VAULT_VERSION = 'v0.0.0-test'
    $env:QBIT_VAULT_RELEASE_URL = $release
    $env:QBIT_VAULT_INSTALL_DIR = $dest
    $env:QBIT_VAULT_NO_PATH = '1'
    # Windows PowerShell turns a child's stderr into errors; keep them as output.
    $ErrorActionPreference = 'Continue'
    $out = & $shell -NoProfile -ExecutionPolicy Bypass -File $script 2>&1 | Out-String
    return @{ Code = $LASTEXITCODE; Out = $out }
}

function Installed($dest) {
    $f = Join-Path $dest 'qbit-vault.exe'
    if (Test-Path -LiteralPath $f) { Get-Content -Raw -LiteralPath $f } else { '' }
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
    Check 're-install leaves no .old file' (-not (Test-Path (Join-Path $work 'dest1\qbit-vault.exe.old')))
} finally {
    $env:PROCESSOR_ARCHITECTURE = $realArch
    'QBIT_VAULT_VERSION', 'QBIT_VAULT_RELEASE_URL', 'QBIT_VAULT_INSTALL_DIR', 'QBIT_VAULT_NO_PATH' | ForEach-Object { Remove-Item "Env:$_" -ErrorAction SilentlyContinue }
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}

if ($fails -ne 0) { Write-Host "$fails check(s) failed"; exit 1 }
Write-Host 'all install.ps1 checks passed'
