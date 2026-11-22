[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $Binary,
    [string] $OutputDirectory = 'target/dist'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$binaryPath = (Get-Item -LiteralPath $Binary).FullName
$stream = [IO.File]::OpenRead($binaryPath)
try {
    $reader = [IO.BinaryReader]::new($stream)
    if ($stream.Length -lt 64 -or $reader.ReadUInt16() -ne 0x5A4D) { throw 'Expected a Windows PE executable.' }
    $stream.Position = 0x3c
    $offset = $reader.ReadInt32()
    if ($offset -lt 64 -or $offset -gt ($stream.Length - 6)) { throw 'Invalid Windows PE header.' }
    $stream.Position = $offset
    if ($reader.ReadUInt32() -ne 0x4550 -or $reader.ReadUInt16() -ne 0x8664) { throw 'Expected a Windows x64 executable.' }
} finally {
    $stream.Dispose()
}

Push-Location -LiteralPath $root
try {
    $metadata = cargo metadata --offline --locked --no-deps --format-version 1
    if ($LASTEXITCODE -ne 0) { throw 'Could not read VespDex package metadata.' }
    $project = ($metadata | ConvertFrom-Json).packages | Where-Object { $_.name -eq 'vespdex' }
} finally {
    Pop-Location
}
$version = $project.version
if ($version -notmatch '^\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?$') { throw 'Unsupported VespDex package version.' }

$directory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
[IO.Directory]::CreateDirectory($directory) | Out-Null
$name = "VespDex-$version-windows-x64"
$destination = Join-Path $directory $name
if (Test-Path -LiteralPath $destination) { throw "Package already exists: $destination" }

$stage = Join-Path $directory ".vespdex-package-$([guid]::NewGuid().ToString('N'))"
$payload = Join-Path $stage 'payload'
$outgoing = Join-Path $stage 'outgoing'
[IO.Directory]::CreateDirectory($payload) | Out-Null
[IO.Directory]::CreateDirectory($outgoing) | Out-Null
try {
    $files = [ordered]@{
        'vespdex.exe' = $binaryPath
        'Start-VespDex.cmd' = Join-Path $root 'packaging/windows/Start-VespDex.cmd'
        'examples/capture.json' = Join-Path $root 'examples/capture.json'
        'scripts/convert-sysmon.ps1' = Join-Path $root 'scripts/convert-sysmon.ps1'
        'KULLANIM.md' = Join-Path $root 'packaging/windows/KULLANIM.md'
        'USAGE.md' = Join-Path $root 'packaging/windows/USAGE.md'
        'NOTICE' = Join-Path $root 'NOTICE'
        'CHANGELOG.md' = Join-Path $root 'CHANGELOG.md'
    }
    $hashes = foreach ($relative in ($files.Keys | Sort-Object -CaseSensitive)) {
        $target = Join-Path $payload $relative
        [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target)) | Out-Null
        Copy-Item -LiteralPath $files[$relative] -Destination $target
        "$((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant())  $relative"
    }
    [IO.File]::WriteAllLines((Join-Path $payload 'PACKAGE-SHA256SUMS.txt'), [string[]] $hashes)

    $zipName = "$name.zip"
    $archive = Join-Path $outgoing $zipName
    [IO.Compression.ZipFile]::CreateFromDirectory($payload, $archive, [IO.Compression.CompressionLevel]::Optimal, $false)
    $zipHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllLines((Join-Path $outgoing 'SHA256SUMS.txt'), [string[]] @("$zipHash  $zipName"))
    [IO.Directory]::Move($outgoing, $destination)
    Get-Item -LiteralPath (Join-Path $destination $zipName), (Join-Path $destination 'SHA256SUMS.txt')
} finally {
    # The stage is a unique child of the caller's output directory.
    $resolved = (Resolve-Path -LiteralPath $stage -ErrorAction SilentlyContinue).Path
    if ($resolved -and $resolved -eq $stage -and [IO.Path]::GetDirectoryName($resolved) -eq $directory) {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
