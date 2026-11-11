# Install qbit-vault from a GitHub release on Windows (docs/INSTALL.md § One-line install).
#
#   irm https://github.com/qbitdevz/qbit-vault/releases/latest/download/install.ps1 | iex
#
# Environment:
#   QBIT_VAULT_VERSION      tag to install (default: the newest release, pre-releases included)
#   QBIT_VAULT_RELEASES_API release list to pick the newest from (default: the GitHub releases API)
#   QBIT_VAULT_INSTALL_DIR  target directory (default: where qbit-vault already is, else %LOCALAPPDATA%\Programs\qbit-vault)
#   QBIT_VAULT_RELEASE_URL  base download URL or local directory (default: the GitHub releases)
#   QBIT_VAULT_NO_PATH      set to 1 to leave the user PATH unchanged
#   QBIT_VAULT_USER_PATH    user PATH to compare against (default: the real one; for tests)
#   QBIT_VAULT_NO_SYNC      set to 1 to skip `qbit-vault sync` after an upgrade
#
# It downloads one archive and checksums.txt, verifies the SHA-256 and, when
# minisign is installed, the Minisign signature of checksums.txt against the
# release key pinned below (docs/INSTALL.md § Verify a download), copies the
# binary and adds its directory to the user PATH. An existing install is
# upgraded in place, and when the vault is already set up it runs
# `qbit-vault sync` so your agents use the new binary. It never asks for, reads
# or stores a secret, and it never runs `qbit-vault init`: that stays your step.

function Install-QBitVault {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    $repo = 'qbitdevz/qbit-vault'
    $releaseUrl = if ($env:QBIT_VAULT_RELEASE_URL) { $env:QBIT_VAULT_RELEASE_URL } else { "https://github.com/$repo/releases/download" }
    $installDir = $env:QBIT_VAULT_INSTALL_DIR
    $version = $env:QBIT_VAULT_VERSION
    $vaultHome = if ($env:QBIT_VAULT_HOME) { $env:QBIT_VAULT_HOME } else { Join-Path ([Environment]::GetFolderPath('UserProfile')) '.qbit-vault' }

    # The release public key (key id BEEE762E58A69B2B; the second line of
    # defaults/release-key.pub, which a test keeps equal to this) and the first
    # release whose checksums.txt is signed.
    $minisignKey = 'RWQrm6ZYLnbuvsS0Px4nVFDMnfj6QG4sqbwDkmelqS9njb/q577zkLt8'
    $firstSigned = 'v1.4.0'

    function Say($msg) { Write-Host "qbit-vault install: $msg" }
    function Fetch($url, $file) {
        if ($url -match '^https://') {
            Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $file
        } else {
            Copy-Item -LiteralPath $url -Destination $file
        }
    }

    # True when $v is at or above $firstSigned (a pre-release suffix is
    # ignored). A version that does not parse counts as signed.
    function Test-SignedRelease($v) {
        $core = ($v -replace '^v', '') -replace '[-+].*$', ''
        if ($core -notmatch '^\d+\.\d+\.\d+$') { return $true }
        return ([version]$core) -ge ([version]($firstSigned -replace '^v', ''))
    }

    switch ($env:PROCESSOR_ARCHITECTURE) {
        'AMD64' { $arch = 'amd64' }
        'ARM64' { $arch = 'arm64' }
        default { throw "qbit-vault install: unsupported architecture $($env:PROCESSOR_ARCHITECTURE)" }
    }

    if (-not $version) {
        # releases/latest skips pre-releases, so list releases of any kind. The API
        # orders them by tag text (v0.1.0-beta.10 after v0.1.0-beta.9), so take the
        # newest publish date; a draft has none.
        $api = if ($env:QBIT_VAULT_RELEASES_API) { $env:QBIT_VAULT_RELEASES_API } else { "https://api.github.com/repos/$repo/releases?per_page=100" }
        try {
            $releases = if ($api -match '^https://') { Invoke-RestMethod -UseBasicParsing -Uri $api } else { Get-Content -Raw -LiteralPath $api | ConvertFrom-Json }
        } catch {
            throw 'qbit-vault install: could not reach the GitHub API (rate limit or network); set QBIT_VAULT_VERSION=vX.Y.Z and try again'
        }
        $newest = @($releases | ForEach-Object { $_ }) | Where-Object { -not $_.draft -and $_.published_at } | Sort-Object { [datetime]$_.published_at } -Descending | Select-Object -First 1
        $version = $newest.tag_name
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

        # The signature of checksums.txt, before anything is extracted or written.
        $signedRelease = Test-SignedRelease $version
        $unsignedNote = "$version predates signed releases (first signed: $firstSigned): checksums.txt was checked with SHA-256 only"
        $minisign = (Get-Command minisign -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source
        if ($minisign) {
            $sigFile = Join-Path $tmp 'checksums.txt.minisig'
            $haveSig = $true
            try { Fetch "$releaseUrl/$version/checksums.txt.minisig" $sigFile } catch { $haveSig = $false }
            if ($haveSig) {
                $verified = $false
                try {
                    & $minisign -V -q -P $minisignKey -m (Join-Path $tmp 'checksums.txt') -x $sigFile *> $null
                    $verified = ($LASTEXITCODE -eq 0)
                } catch { $verified = $false }
                if (-not $verified) { throw "qbit-vault install: the signature of checksums.txt for $version does not verify with the QBit Vault release key: nothing was installed" }
                Say 'checksums.txt signature verified with minisign'
            } elseif ($signedRelease) {
                throw "qbit-vault install: the release $version has no checksums.txt.minisig, so it is not signed with the QBit Vault release key: nothing was installed"
            } else {
                Say $unsignedNote
            }
        } elseif ($signedRelease) {
            Write-Host "minisign not found: checksums.txt was checked with SHA-256 only. Verify the signature with: minisign -V -P $minisignKey -m checksums.txt -x checksums.txt.minisig"
        } else {
            Say $unsignedNote
        }

        Expand-Archive -LiteralPath (Join-Path $tmp $archive) -DestinationPath (Join-Path $tmp 'x')
        $exe = Join-Path $tmp 'x\qbit-vault.exe'
        if (-not (Test-Path -LiteralPath $exe)) { throw 'qbit-vault install: the archive has no qbit-vault.exe' }
        # An existing install is upgraded where it is, so its path (and every
        # agent registration that holds it) stays the same.
        $previous = (Get-Command qbit-vault -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source
        $previousVersion = $null
        if ($previous) {
            try { $previousVersion = ((& $previous version 2>$null) -split ' ')[1] } catch { $previousVersion = $null }
        }
        if (-not $installDir) {
            $installDir = Join-Path $env:LOCALAPPDATA 'Programs\qbit-vault'
            if ($previous) {
                $prevDir = Split-Path -Parent $previous
                $probe = Join-Path $prevDir ('.qbit-vault-write-' + [Guid]::NewGuid().ToString('N'))
                try { New-Item -ItemType File -Path $probe | Out-Null; Remove-Item -LiteralPath $probe; $installDir = $prevDir } catch { }
            }
        }
        $target = Join-Path $installDir 'qbit-vault.exe'
        if ($previousVersion -and $previous -eq $target) {
            if ($previousVersion -eq $version) { Say "qbit-vault $version is already installed; reinstalling it" }
            else { Say "upgrading qbit-vault $previousVersion -> $version" }
        }

        New-Item -ItemType Directory -Force -Path $installDir | Out-Null
        # Leftovers of earlier upgrades go now if nothing runs them any more.
        Get-ChildItem -LiteralPath $installDir -Filter 'qbit-vault.exe.old*' -Force -ErrorAction SilentlyContinue |
            ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue }
        # A running .exe cannot be overwritten but can be renamed: move it aside
        # under a fresh name (an older aside file may still be locked), and put
        # it back if the copy fails, so a failed upgrade never leaves no binary.
        $old = $null
        if (Test-Path -LiteralPath $target) {
            $old = "$target.old-" + [Guid]::NewGuid().ToString('N').Substring(0, 8)
            Move-Item -LiteralPath $target -Destination $old
        }
        try {
            Copy-Item -LiteralPath $exe -Destination $target
        } catch {
            if ($old) { Move-Item -LiteralPath $old -Destination $target -Force -ErrorAction SilentlyContinue }
            throw "qbit-vault install: could not write ${target}: the previous binary was kept"
        }
        if ($old) { Remove-Item -LiteralPath $old -Force -ErrorAction SilentlyContinue }
        Say "installed $target"

        # QBIT_VAULT_USER_PATH stands in for the user PATH in the tests; it is
        # only read, never written back.
        $userPath = if ($env:QBIT_VAULT_USER_PATH) { $env:QBIT_VAULT_USER_PATH } else { [Environment]::GetEnvironmentVariable('Path', 'User') }
        # A trailing backslash (and case) must not make the same directory look new.
        $onPath = @($userPath -split ';' | ForEach-Object { $_.TrimEnd('\') }) -contains $installDir.TrimEnd('\')
        if (-not $onPath -and $env:QBIT_VAULT_NO_PATH -ne '1' -and -not $env:QBIT_VAULT_USER_PATH) {
            $newPath = if ($userPath) { "$userPath;$installDir" } else { $installDir }
            [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
            $env:Path = "$env:Path;$installDir"
            Say "added $installDir to your user PATH (open a new terminal to pick it up)"
        } elseif (-not $onPath) {
            Say "$installDir is not on your PATH"
        }
        $active = (Get-Command qbit-vault -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source
        if ($active -and $active -ne $target) {
            Say "another qbit-vault at $active comes first on your PATH; remove it so your shell runs the new one"
        }

        if (Test-Path -LiteralPath (Join-Path $vaultHome 'state.json')) {
            # Already set up: re-apply the recorded agent registrations, so they
            # point at this binary. sync reads no secret and asks nothing.
            if ($env:QBIT_VAULT_NO_SYNC -eq '1') {
                Say "skipped 'qbit-vault sync' (QBIT_VAULT_NO_SYNC=1); run it yourself so your agents use this binary"
            } else {
                & $target sync
                if ($LASTEXITCODE -eq 0) { Say 'agent registrations are up to date; restart your agents to load the new version' }
                else { Say "'qbit-vault sync' reported a problem (see above); run 'qbit-vault doctor', then restart your agents" }
            }
        } else {
            Say "next: run 'qbit-vault init'"
        }
    } finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Install-QBitVault
