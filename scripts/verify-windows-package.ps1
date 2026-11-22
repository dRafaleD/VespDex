[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $Archive,
    [switch] $CheckGui
)

$ErrorActionPreference = 'Stop'
$zip = Get-Item -LiteralPath $Archive
if ($zip.PSIsContainer -or $zip.Length -gt 40MB -or $zip.Name -cnotmatch '^VespDex-(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?)-windows-x64\.zip$') {
    throw 'Expected a VespDex Windows x64 package smaller than 40 MiB.'
}
$version = $Matches[1]
$expectedFiles = @(
    'vespdex.exe', 'Start-VespDex.cmd', 'examples/capture.json', 'scripts/convert-sysmon.ps1',
    'KULLANIM.md', 'USAGE.md', 'NOTICE', 'CHANGELOG.md', 'PACKAGE-SHA256SUMS.txt'
)
$summary = Get-Content -LiteralPath (Join-Path $zip.DirectoryName 'SHA256SUMS.txt')
$archiveDigest = (Get-FileHash -LiteralPath $zip.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
if (@($summary).Count -ne 1 -or $summary -cne "$archiveDigest  $($zip.Name)") { throw 'Archive checksum did not match.' }

$readable = [IO.Compression.ZipFile]::OpenRead($zip.FullName)
try {
    $files = $readable.Entries | ForEach-Object { $_.FullName }
    if (@($files).Count -ne $expectedFiles.Count -or (Compare-Object $expectedFiles $files -CaseSensitive)) {
        throw 'Archive contents do not match the expected file list.'
    }
    $total = ($readable.Entries | Measure-Object -Property Length -Sum).Sum
    if ($total -gt 80MB) { throw 'Expanded package exceeds 80 MiB.' }
} finally {
    $readable.Dispose()
}

$parent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar)
$install = Join-Path $parent "VespDex package check $([guid]::NewGuid().ToString('N'))"
$guiRenderer = $null
[IO.Directory]::CreateDirectory($install) | Out-Null
try {
    [IO.Compression.ZipFile]::ExtractToDirectory($zip.FullName, $install)
    $manifest = Get-Content -LiteralPath (Join-Path $install 'PACKAGE-SHA256SUMS.txt')
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $payload = @($expectedFiles | Where-Object { $_ -cne 'PACKAGE-SHA256SUMS.txt' })
    foreach ($line in $manifest) {
        if ($line -cnotmatch '^([a-f0-9]{64})  (.+)$') { throw 'Invalid packaged file checksum entry.' }
        $hash, $file = $Matches[1], $Matches[2]
        if ($file -cnotin $payload -or !$seen.Add($file)) { throw "Unexpected packaged filename: $file" }
        $actual = (Get-FileHash -LiteralPath (Join-Path $install $file) -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -cne $hash) { throw "Packaged file checksum mismatch: $file" }
    }
    if ($seen.Count -ne $payload.Count) { throw 'Some packaged files are missing checksums.' }

    $binary = Join-Path $install 'vespdex.exe'
    $demo = Join-Path $install 'examples/capture.json'
    Push-Location -LiteralPath $parent
    try {
        $actualVersion = & $binary --version
        if ($LASTEXITCODE -ne 0 -or $actualVersion -cne "vespdex $version") { throw 'Unexpected packaged executable version.' }
        $savedReport = Join-Path $install 'verified-report.json'
        & $binary $demo --output $savedReport
        if ($LASTEXITCODE -ne 0) { throw 'Packaged executable failed to analyze the sample.' }
        $json = [IO.File]::ReadAllText($savedReport)
    } finally {
        Pop-Location
    }
    $report = $json | ConvertFrom-Json -AsHashtable
    if ($report.kind -cne 'asphdex-behavior-report' -or $report.events.Count -ne 4 -or $report.processes.Count -ne 2) {
        throw 'Packaged demo did not produce its expected report.'
    }

    if ($CheckGui) {
        $start = [Diagnostics.ProcessStartInfo]::new($binary)
        $start.WorkingDirectory = $parent
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.RedirectStandardError = $true
        $start.ArgumentList.Add('--gui')
        $start.ArgumentList.Add($demo)
        $window = [Diagnostics.Process]::Start($start)
        $diagnostics = $window.StandardError.ReadToEndAsync()
        try {
            $deadline = [DateTime]::UtcNow.AddSeconds(15)
            do {
                $window.Refresh()
                if ($window.HasExited) {
                    $detail = $diagnostics.GetAwaiter().GetResult().Trim()
                    if ($detail.Length -gt 1600) { $detail = $detail.Substring(0, 1600) }
                    throw "Packaged GUI exited early ($($window.ExitCode)). $detail"
                }
                if ($window.MainWindowTitle -eq 'VespDex') { break }
                Start-Sleep -Milliseconds 200
            } while ([DateTime]::UtcNow -lt $deadline)
            if ($window.MainWindowTitle -ne 'VespDex') { throw 'Packaged desktop window did not appear.' }
        } finally {
            if (!$window.HasExited) {
                if (!$window.CloseMainWindow() -or !$window.WaitForExit(5000)) {
                    $window.Kill()
                    $window.WaitForExit()
                }
            }
            $window.Dispose()
        }
        $diagnosticText = $diagnostics.GetAwaiter().GetResult()
        $rendererLine = $diagnosticText -split '\r?\n' | Where-Object { $_ -match '^VespDex desktop renderer: Dx12 / ' } | Select-Object -First 1
        if (!$rendererLine) { throw 'Desktop renderer did not report a Direct3D 12 adapter.' }
        $guiRenderer = $rendererLine -replace '^VespDex desktop renderer: ', ''
    }
} finally {
    $resolved = (Resolve-Path -LiteralPath $install -ErrorAction SilentlyContinue).Path
    if ($resolved -and $resolved -eq $install -and [IO.Path]::GetDirectoryName($resolved) -eq $parent) {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
if (Test-Path -LiteralPath $install) { throw 'The package directory could not be removed.' }

[pscustomobject]@{
    version = $version
    archive_sha256 = $archiveDigest
    verified_files = $seen.Count
    demo_events = $report.events.Count
    demo_processes = $report.processes.Count
    gui_window_verified = [bool] $CheckGui
    gui_renderer = $guiRenderer
    removed = $true
} | ConvertTo-Json
