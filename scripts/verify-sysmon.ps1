[CmdletBinding()]
param([Parameter(Mandatory)][string] $VespDex)

$ErrorActionPreference = 'Stop'
$binary = (Get-Item -LiteralPath $VespDex).FullName
$channel = 'Microsoft-Windows-Sysmon/Operational'
$log = Get-WinEvent -ListLog $channel
if (!$log.IsEnabled) { throw 'This acceptance check requires an enabled Sysmon channel.' }

$work = Join-Path ([IO.Path]::GetTempPath()) "vespdex-smoke-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $work | Out-Null
$writtenFile = Join-Path $work 'marker.txt'
$captureFile = Join-Path $work 'capture.json'
$evtx = Join-Path $work 'capture.evtx'
try {
    $engine = Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
    $writeMarker = "[IO.File]::WriteAllText([Environment]::GetEnvironmentVariable('VESPDEX_SMOKE_FILE'), 'benign marker')"
    $encodedChild = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($writeMarker))
    $startChild = ('& ([Environment]::GetEnvironmentVariable(''VESPDEX_SMOKE_ENGINE'')) -NoProfile -NonInteractive -EncodedCommand {0}; exit $LASTEXITCODE' -f $encodedChild)
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $engine
    $encodedRoot = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($startChild))
    $start.Arguments = "-NoProfile -NonInteractive -EncodedCommand $encodedRoot"
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.EnvironmentVariables['VESPDEX_SMOKE_FILE'] = $writtenFile
    $start.EnvironmentVariables['VESPDEX_SMOKE_ENGINE'] = $engine

    $begin = [datetimeoffset]::UtcNow.AddSeconds(-1)
    $root = [Diagnostics.Process]::Start($start)
    try {
        if (!$root.WaitForExit(15000)) {
            $root.Kill()
            $root.WaitForExit()
            throw 'The benign fixture process exceeded its deadline.'
        }
        if ($root.ExitCode -ne 0 -or !(Test-Path -LiteralPath $writtenFile -PathType Leaf)) {
            throw 'The benign fixture did not write its marker.'
        }
        $rootPid = $root.Id
    } finally {
        $root.Dispose()
    }

    $filter = @{ LogName = $channel; Id = 1; StartTime = $begin.UtcDateTime }
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(12)
    $rootGuid = $null
    do {
        $records = Get-WinEvent -FilterHashtable $filter -MaxEvents 2000 -ErrorAction SilentlyContinue
        foreach ($record in $records) {
            [xml] $xml = $record.ToXml()
            $fields = @{}
            foreach ($node in $xml.Event.EventData.Data) {
                $fields[$node.GetAttribute('Name')] = $node.InnerText
            }
            if ($fields['ProcessId'] -eq [string] $rootPid -and ([string] $fields['CommandLine']).Contains($encodedRoot)) {
                $rootGuid = [guid] $fields['ProcessGuid']
                break
            }
        }
        if (!$rootGuid) { Start-Sleep -Milliseconds 400 }
    } while (!$rootGuid -and [DateTimeOffset]::UtcNow -lt $deadline)
    if (!$rootGuid) { throw 'Sysmon never recorded the benign process creation (event ID 1).' }

    $convert = Join-Path $PSScriptRoot 'convert-sysmon.ps1'
    $liveCapture = & $convert -Live -StartTime $begin -ObserveSeconds 3 -ProcessGuid $rootGuid -CaseId accept-live
    $query = '*[System[(EventID=1 or EventID=3 or EventID=11 or EventID=13 or EventID=22) and TimeCreated[timediff(@SystemTime) <= 120000]]]'
    & "$env:SystemRoot/System32/wevtutil.exe" epl $channel $evtx "/q:$query"
    if ($LASTEXITCODE -ne 0) { throw 'Could not export a bounded Sysmon EVTX.' }

    $candidates = @((& $convert -Evtx $evtx -ListProcesses | ConvertFrom-Json))
    if (!($candidates | Where-Object { $_.guid -eq $rootGuid.ToString('D') })) {
        throw 'The EVTX process picker did not return the fixture process.'
    }
    $offlineCapture = & $convert -Evtx $evtx -ProcessGuid $rootGuid -CaseId accept-evtx

    $hash = (Get-FileHash -LiteralPath $engine -Algorithm SHA256).Hash.ToLowerInvariant()
    $assertions = foreach ($capture in @($liveCapture, $offlineCapture)) {
        [IO.File]::WriteAllText($captureFile, $capture)
        $reportJson = & $binary $captureFile
        if ($LASTEXITCODE -ne 0) { throw 'VespDex rejected the Sysmon capture.' }
        $report = $reportJson | ConvertFrom-Json
        if ($report.sampleSha256 -ne $hash) { throw 'The root process SHA-256 did not match the fixture binary.' }
        $children = @($report.events | Where-Object {
            $_.kind -eq 'process-start' -and $_.parentProcessGuid -eq $rootGuid.ToString('D') -and $_.detail -eq $engine
        })
        $fixtureChildren = @($children | ForEach-Object { $_.processGuid })
        $marker = @($report.events | Where-Object {
            $_.kind -eq 'file-write' -and $_.detail -eq $writtenFile -and $_.processGuid -in $fixtureChildren
        })
        if ($marker.Count -lt 1) {
            throw "Sysmon did not attribute the marker file creation (event ID 11) to a direct fixture child in $($report.caseId). Matching child images: $($children.Count)."
        }
        if ($report.caseId -eq 'accept-live' -and !$report.captureWindow) {
            throw 'The live report omitted the observation window.'
        }
        [pscustomobject]@{
            case = $report.caseId
            root_sha256_matches = $true
            fixture_children = $children.Count
            attributed_marker_events = $marker.Count
            capture_window_recorded = [bool] $report.captureWindow
        }
    }
    $assertions | ConvertTo-Json -Depth 4
} finally {
    foreach ($file in @($writtenFile, $captureFile, $evtx)) {
        if (Test-Path -LiteralPath $file -PathType Leaf) { Remove-Item -LiteralPath $file }
    }
    Remove-Item -LiteralPath $work
}
