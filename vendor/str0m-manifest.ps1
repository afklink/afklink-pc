# Writes vendor/str0m.sha256: the SHA-256 of every file of the vendored str0m (raw bytes), taken
# from the crates.io archive itself, except the files our patch changes, which are pinned to their
# vendored bytes. The workspace test `vendored_str0m` (crates/transport/tests) fails on any drift
# from it. Run it (pwsh 7) after a deliberate change to a patched file, or after re-vendoring with
# the new version, archive checksum and patched files set below. vendor/VENDORED.md says when.
#
#   pwsh -NoProfile -File vendor/str0m-manifest.ps1 [-Crate <path to str0m-<version>.crate>]
param([string]$Crate)
$ErrorActionPreference = 'Stop'

$Version = '0.24.1'
# crates.io's checksum of the archive (Cargo.lock before the patch).
$Checksum = '3e80c4a4ef148e4a9fd15b9525c7f376d97e86729f19880b591ad220f1288c0f'
# The files the AFKLink patch changes; every other file must be the archive's.
$Patched = @('src/bwe/delay/control.rs', 'src/bwe/delay/trendline.rs')

$vendor = Split-Path -Parent $PSCommandPath
$copy = Join-Path $vendor 'str0m'
if (-not $Crate) {
    $cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $HOME '.cargo' }
    $found = Get-ChildItem (Join-Path $cargoHome 'registry\cache') -Recurse -Filter "str0m-$Version.crate" |
        Select-Object -First 1
    if (-not $found) { throw "str0m-$Version.crate is not in $cargoHome\registry\cache: run cargo fetch on a checkout from before the patch, or pass -Crate" }
    $Crate = $found.FullName
}
$got = (Get-FileHash -LiteralPath $Crate -Algorithm SHA256).Hash.ToLowerInvariant()
if ($got -ne $Checksum) { throw "$Crate has SHA-256 $got, crates.io says $Checksum" }

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("str0m-manifest-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    tar -xzf $Crate -C $tmp
    if ($LASTEXITCODE -ne 0) { throw "tar failed on $Crate" }
    $pristine = Join-Path $tmp "str0m-$Version"
    $sha = [Security.Cryptography.SHA256]::Create()
    $hash = { param($p) ([BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($p))) -replace '-', '').ToLowerInvariant() }
    $rels = [string[]](Get-ChildItem -LiteralPath $pristine -Recurse -File -Force | ForEach-Object {
            [IO.Path]::GetRelativePath($pristine, $_.FullName).Replace('\', '/')
        })
    [Array]::Sort($rels, [StringComparer]::Ordinal)
    $sorted = foreach ($rel in $rels) {
        $from = if ($Patched -contains $rel) { Join-Path $copy $rel } else { Join-Path $pristine $rel }
        "$(& $hash $from)  $rel"
    }
    $out = Join-Path $vendor 'str0m.sha256'
    [IO.File]::WriteAllText($out, (($sorted -join "`n") + "`n"))
    "wrote ${out}: $($sorted.Count) files, $($Patched.Count) pinned to the patched copy"
} finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force
}
