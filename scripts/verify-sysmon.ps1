[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $VespDex,
    [string] $FixtureEvtx
)

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
$fixture = Join-Path $work 'isolated-fixture.evtx'
$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
try {
    $listener.Start()
    $port = $listener.LocalEndpoint.Port
    $engine = Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
    $childScript = @'
$ErrorActionPreference = 'Stop'
[IO.File]::WriteAllText([Environment]::GetEnvironmentVariable('VESPDEX_SMOKE_FILE'), 'benign marker')
$client = [Net.Sockets.TcpClient]::new()
try {
    $client.Connect([Net.IPAddress]::Loopback, [int] $env:VESPDEX_SMOKE_PORT)
} finally {
    $client.Dispose()
}
'@
    $encodedChild = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($childScript))
    $startChild = ('& ([Environment]::GetEnvironmentVariable(''VESPDEX_SMOKE_ENGINE'')) -NoProfile -NonInteractive -EncodedCommand {0}; exit $LASTEXITCODE' -f $encodedChild)
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $engine
    $encodedRoot = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($startChild))
    $start.Arguments = "-NoProfile -NonInteractive -EncodedCommand $encodedRoot"
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.EnvironmentVariables['VESPDEX_SMOKE_FILE'] = $writtenFile
    $start.EnvironmentVariables['VESPDEX_SMOKE_ENGINE'] = $engine
    $start.EnvironmentVariables['VESPDEX_SMOKE_PORT'] = [string] $port

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
        if (!$listener.Pending()) { throw 'The benign fixture did not connect to the loopback listener.' }
        $listener.AcceptTcpClient().Dispose()
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
        $markerChildren = @($marker | ForEach-Object { $_.processGuid })
        $network = @($report.events | Where-Object {
            $_.kind -eq 'network-connection' -and $_.processGuid -in $markerChildren -and
                $_.detail -match '^127\.0\.0\.1(?:\s|$)' -and $_.detail.EndsWith(" port=$port")
        })
        if ($network.Count -lt 1) {
            throw "Sysmon did not attribute the loopback connection (event ID 3) to the marker writer in $($report.caseId)."
        }
        if ($report.caseId -eq 'accept-live' -and !$report.captureWindow) {
            throw 'The live report omitted the observation window.'
        }
        [pscustomobject]@{
            case = $report.caseId
            root_sha256_matches = $true
            fixture_children = $children.Count
            attributed_marker_events = $marker.Count
            attributed_loopback_events = $network.Count
            capture_window_recorded = [bool] $report.captureWindow
        }
    }
    $assertions | ConvertTo-Json -Depth 4

    if ($FixtureEvtx) {
        # Copy raw events only for the root and the verified child that wrote
        # the benign file. Keep the larger working export local to this run.
        $subjects = @($rootGuid.ToString('D')) + @($markerChildren | Select-Object -Unique)
        $startRows = @(Get-WinEvent -FilterHashtable @{LogName = $channel; Id = 1; StartTime = $begin.UtcDateTime} -MaxEvents 2000)
        $rawIds = @(foreach ($row in $startRows) {
            [xml] $xml = $row.ToXml()
            $node = $xml.Event.EventData.Data | Where-Object { $_.GetAttribute('Name') -eq 'ProcessGuid' } | Select-Object -First 1
            $value = [guid]::Empty
            if ($node -and [guid]::TryParse($node.InnerText, [ref] $value) -and $value.ToString('D') -in $subjects) {
                $node.InnerText
            }
        })
        if ($rawIds.Count -ne $subjects.Count) { throw 'Could not isolate the fixture process IDs.' }
        $conditions = @($rawIds | ForEach-Object { "Data[@Name='ProcessGuid']='$_'" }) -join ' or '
        $isolatedQuery = "*[System[(EventID=1 or EventID=3 or EventID=11)]] and *[EventData[$conditions]]"
        & "$env:SystemRoot/System32/wevtutil.exe" epl $channel $fixture "/q:$isolatedQuery"
        if ($LASTEXITCODE -ne 0) { throw 'Could not export the isolated EVTX fixture.' }
        foreach ($row in (Get-WinEvent -Path $fixture -MaxEvents 33)) {
            [xml] $xml = $row.ToXml()
            $node = $xml.Event.EventData.Data | Where-Object { $_.GetAttribute('Name') -eq 'ProcessGuid' } | Select-Object -First 1
            if ($row.ProviderName -ne 'Microsoft-Windows-Sysmon' -or !$node -or $node.InnerText -notin $rawIds) {
                throw 'Isolated EVTX contains unrelated events.'
            }
        }
        $isolatedCapture = & $convert -Evtx $fixture -ProcessGuid $rootGuid -CaseId accept-fixture | ConvertFrom-Json
        $kinds = @($isolatedCapture.events.kind)
        if ($isolatedCapture.events.Count -gt 32 -or 'file-write' -notin $kinds -or 'network-connection' -notin $kinds) {
            throw 'Isolated EVTX does not contain the expected small fixture.'
        }
        $destination = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FixtureEvtx)
        [IO.File]::Copy($fixture, $destination, $false)
    }
} finally {
    $listener.Stop()
    foreach ($file in @($writtenFile, $captureFile, $evtx, $fixture)) {
        if (Test-Path -LiteralPath $file -PathType Leaf) { Remove-Item -LiteralPath $file }
    }
    Remove-Item -LiteralPath $work
}
