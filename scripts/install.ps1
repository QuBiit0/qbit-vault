# Install qbit-vault from a GitHub release on Windows (docs/INSTALL.md § One-line install).
#
#   irm https://raw.githubusercontent.com/QuBiit0/qbit-vault/main/scripts/install.ps1 | iex
#
# Environment:
#   QBIT_VAULT_VERSION      tag to install (default: the newest release, pre-releases included)
#   QBIT_VAULT_INSTALL_DIR  target directory (default: %LOCALAPPDATA%\Programs\qbit-vault)
#   QBIT_VAULT_RELEASE_URL  base download URL or local directory (default: the GitHub releases)
#   QBIT_VAULT_NO_PATH      set to 1 to leave the user PATH unchanged
#
# It downloads one archive and checksums.txt, verifies the SHA-256, copies the
# binary and adds its directory to the user PATH. It never asks for, reads or
# stores a secret, and it does not run `qbit-vault init`: that stays your step.

function Install-QBitVault {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    $repo = 'QuBiit0/qbit-vault'
    $releaseUrl = if ($env:QBIT_VAULT_RELEASE_URL) { $env:QBIT_VAULT_RELEASE_URL } else { "https://github.com/$repo/releases/download" }
    $installDir = if ($env:QBIT_VAULT_INSTALL_DIR) { $env:QBIT_VAULT_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\qbit-vault' }
    $version = $env:QBIT_VAULT_VERSION

    function Say($msg) { Write-Host "qbit-vault install: $msg" }
    function Fetch($url, $file) {
        if ($url -match '^https://') {
            Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $file
        } else {
            Copy-Item -LiteralPath $url -Destination $file
        }
    }

    switch ($env:PROCESSOR_ARCHITECTURE) {
        'AMD64' { $arch = 'amd64' }
        'ARM64' { $arch = 'arm64' }
        default { throw "qbit-vault install: unsupported architecture $($env:PROCESSOR_ARCHITECTURE)" }
    }

    if (-not $version) {
        # releases/latest skips pre-releases, so ask for the newest release of any kind.
        $releases = Invoke-RestMethod -UseBasicParsing -Uri "https://api.github.com/repos/$repo/releases?per_page=1"
        $version = @($releases)[0].tag_name
        if (-not $version) { throw "qbit-vault install: no release of $repo found" }
    }

    $archive = "qbit-vault_windows_$arch.zip"
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("qbit-vault-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        Say "installing qbit-vault $version (windows/$arch)"
        Fetch "$releaseUrl/$version/$archive" (Join-Path $tmp $archive)
        Fetch "$releaseUrl/$version/checksums.txt" (Join-Path $tmp 'checksums.txt')

        $want = $null
        foreach ($line in Get-Content (Join-Path $tmp 'checksums.txt')) {
            $parts = $line -split '\s+'
            if ($parts.Count -ge 2 -and $parts[1] -eq $archive) { $want = $parts[0].ToLowerInvariant() }
        }
        if (-not $want) { throw "qbit-vault install: $archive is not listed in checksums.txt" }
        # .NET directly: Get-FileHash is missing when Windows PowerShell inherits pwsh's module path.
        $stream = [IO.File]::OpenRead((Join-Path $tmp $archive))
        try { $hash = [Security.Cryptography.SHA256]::Create().ComputeHash($stream) } finally { $stream.Dispose() }
        $got = -join ($hash | ForEach-Object { $_.ToString('x2') })
        if ($want -ne $got) { throw "qbit-vault install: checksum mismatch for ${archive}: nothing was installed" }

        Expand-Archive -LiteralPath (Join-Path $tmp $archive) -DestinationPath (Join-Path $tmp 'x')
        $exe = Join-Path $tmp 'x\qbit-vault.exe'
        if (-not (Test-Path -LiteralPath $exe)) { throw 'qbit-vault install: the archive has no qbit-vault.exe' }
        $previous = (Get-Command qbit-vault -ErrorAction SilentlyContinue | Select-Object -First 1).Source

        New-Item -ItemType Directory -Force -Path $installDir | Out-Null
        $target = Join-Path $installDir 'qbit-vault.exe'
        # A running .exe cannot be overwritten but can be renamed: move it aside first.
        if (Test-Path -LiteralPath $target) {
            $old = "$target.old"
            Remove-Item -LiteralPath $old -Force -ErrorAction SilentlyContinue
            Move-Item -LiteralPath $target -Destination $old -Force
        }
        Copy-Item -LiteralPath $exe -Destination $target
        Remove-Item -LiteralPath "$target.old" -Force -ErrorAction SilentlyContinue
        Say "installed $target"

        $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
        $onPath = @($userPath -split ';') -contains $installDir
        if (-not $onPath -and $env:QBIT_VAULT_NO_PATH -ne '1') {
            $newPath = if ($userPath) { "$userPath;$installDir" } else { $installDir }
            [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
            $env:Path = "$env:Path;$installDir"
            Say "added $installDir to your user PATH (open a new terminal to pick it up)"
        } elseif (-not $onPath) {
            Say "$installDir is not on your PATH"
        }
        if ($previous -and $previous -ne $target) {
            Say "another qbit-vault is at $previous; remove it, then run 'qbit-vault sync' so your agents use the new path"
        }
        Say "next: run 'qbit-vault' (guided setup) or 'qbit-vault init', then 'qbit-vault doctor'"
        Say "already set up? run 'qbit-vault sync' after an upgrade"
    } finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Install-QBitVault
