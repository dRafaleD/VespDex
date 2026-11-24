[CmdletBinding(DefaultParameterSetName = 'Evtx')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Evtx')]
    [Parameter(Mandatory, ParameterSetName = 'List')]
    [string] $Evtx,
    [Parameter(Mandatory, ParameterSetName = 'List')]
    [switch] $ListProcesses,
    [Parameter(Mandatory, ParameterSetName = 'Live')]
    [switch] $Live,
    [Parameter(Mandatory, ParameterSetName = 'Live')]
    [datetimeoffset] $StartTime,
    [Parameter(ParameterSetName = 'Live')]
    [ValidateRange(0, 300)]
    [int] $ObserveSeconds = 0,
    [Parameter(Mandatory, ParameterSetName = 'Evtx')]
    [Parameter(Mandatory, ParameterSetName = 'Live')]
    [guid] $ProcessGuid,
    [Parameter(Mandatory, ParameterSetName = 'Evtx')]
    [Parameter(Mandatory, ParameterSetName = 'Live')]
    [ValidatePattern('^[A-Za-z0-9_-]{1,64}$')]
    [string] $CaseId
)

$ErrorActionPreference = 'Stop'
$root = $null
if (!$ListProcesses) {
    if (!$ProcessGuid -or $ProcessGuid -eq [guid]::Empty) { throw 'Select a nonzero process GUID.' }
    $root = $ProcessGuid.ToString('B')
}
$filter = @{
    ProviderName = 'Microsoft-Windows-Sysmon'
    Id = 1, 3, 11, 13, 22
}
$window = $null
if ($Live) {
    $now = [datetimeoffset]::UtcNow
    if ($StartTime -gt $now -or $StartTime -lt $now.AddHours(-1)) {
        throw 'Live StartTime must be within the past hour.'
    }
    $channel = 'Microsoft-Windows-Sysmon/Operational'
    try {
        $log = Get-WinEvent -ListLog $channel
    } catch {
        throw "Cannot access the Sysmon Operational log: $($_.Exception.Message)"
    }
    if (!$log.IsEnabled) { throw 'The Sysmon Operational log is disabled.' }
    if ($ObserveSeconds -gt 0) { Start-Sleep -Seconds $ObserveSeconds }
    $endTime = [datetimeoffset]::UtcNow
    $filter.LogName = $channel
    $filter.StartTime = $StartTime.UtcDateTime
    $filter.EndTime = $endTime.UtcDateTime
    $window = @{ start = $StartTime.ToUniversalTime().ToString('o'); end = $endTime.ToString('o') }
    $source = "sysmon-local:$root"
} else {
    $path = (Get-Item -LiteralPath $Evtx).FullName
    if ([IO.Path]::GetExtension($path) -ine '.evtx' -or ![IO.File]::Exists($path)) {
        throw 'Select an exported Sysmon .evtx file.'
    }
    if ((Get-Item -LiteralPath $path).Length -gt 128MB) { throw 'EVTX exceeds 128 MiB.' }
    $source = "sysmon-evtx:$root"
}

try {
    if ($Live) {
        $rows = @(Get-WinEvent -FilterHashtable $filter -Oldest -MaxEvents 20001)
    } else {
        # Match the provider in the file without looking for a locally registered provider.
        $eventIds = if ($ListProcesses) { @(1) } else { $filter.Id }
        $eventCondition = ($eventIds | ForEach-Object { "EventID=$_" }) -join ' or '
        $query = "*[System[Provider[@Name='Microsoft-Windows-Sysmon'] and ($eventCondition)]]"
        $rows = @(Get-WinEvent -Path ([WildcardPattern]::Escape($path)) -FilterXPath $query -Oldest -MaxEvents 20001)
    }
} catch {
    if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound,*') {
        throw 'There are no supported Sysmon events in the selected capture.'
    }
    throw
}
if ($rows.Count -gt 20000) { throw 'Export a narrower log: more than 20,000 supported events.' }

function Read-EventFields($row) {
    [xml] $xml = $row.ToXml()
    $fields = @{}
    foreach ($node in $xml.Event.EventData.Data) {
        $fields[$node.GetAttribute('Name')] = $node.InnerText
    }
    $fields
}

function Read-Sha256($fields) {
    $fields['Hashes'] -split ',' | ForEach-Object {
        if ($_ -match '^\s*SHA256=([0-9a-f]{64})\s*$') { $Matches[1].ToLowerInvariant() }
    }
}

if ($ListProcesses) {
    $candidates = @(foreach ($row in $rows) {
        $fields = Read-EventFields $row
        $guid = [guid]::Empty
        if (![guid]::TryParse($fields['ProcessGuid'], [ref] $guid) -or $guid -eq [guid]::Empty) { continue }
        $hash = @(Read-Sha256 $fields)
        $image = [string] $fields['Image']
        if ($hash.Count -ne 1 -or !$image -or [Text.Encoding]::UTF8.GetByteCount($image) -gt 1024 -or $image -match '\p{Cc}') { continue }
        @{
            guid = $guid.ToString('D')
            image = $image
            sha256 = $hash[0]
            timestamp = $row.TimeCreated.ToUniversalTime().ToString('o')
        }
    })
    $json = ConvertTo-Json -InputObject $candidates -Depth 3 -Compress
    if ([Text.Encoding]::UTF8.GetByteCount($json) -gt 4MB) { throw 'Process list exceeds 4 MiB. Export a narrower log.' }
    $json
    return
}

$starts = @{}
$children = @{}
$events = [Collections.Generic.List[object]]::new()
foreach ($row in $rows) {
    $fields = Read-EventFields $row
    $processId = [guid]::Empty
    if (![guid]::TryParse($fields['ProcessGuid'], [ref] $processId) -or $processId -eq [guid]::Empty) { continue }
    $guid = $processId.ToString('B')
    if ($row.Id -eq 1) {
        if ($starts.ContainsKey($guid)) { throw 'Duplicate process start GUID in capture.' }
        $starts[$guid] = $fields
        $parentId = [guid]::Empty
        if ([guid]::TryParse($fields['ParentProcessGuid'], [ref] $parentId) -and $parentId -ne [guid]::Empty) {
            $parent = $parentId.ToString('B')
            if (!$children.ContainsKey($parent)) { $children[$parent] = [Collections.Generic.List[string]]::new() }
            $children[$parent].Add($guid)
        }
    }
    $events.Add([pscustomobject]@{ Guid = $guid; Id = $row.Id; Time = $row.TimeCreated; Fields = $fields })
}

if (!$starts.ContainsKey($root)) { throw 'Process GUID was not found in a Sysmon process creation event.' }
$sha256 = @(Read-Sha256 $starts[$root])
if ($sha256.Count -ne 1) { throw 'Selected process creation event must contain one Sysmon SHA256 value.' }

$processes = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$queue = [Collections.Generic.Queue[string]]::new()
$queue.Enqueue($root)
while ($queue.Count -gt 0) {
    $guid = $queue.Dequeue()
    if (!$processes.Add($guid)) { continue }
    if ($children.ContainsKey($guid)) {
        foreach ($child in $children[$guid]) { $queue.Enqueue($child) }
    }
}

$timeline = @(foreach ($event in $events) {
    if (!$processes.Contains($event.Guid)) { continue }
    $fields = $event.Fields
    $kind, $detail = switch ($event.Id) {
        1 { 'process-start'; $fields['Image'] }
        3 {
            'network-connection'
            $destination = "$($fields['DestinationIp']) $($fields['DestinationHostname'])".Trim()
            $port = [uint16] 0
            if ([uint16]::TryParse($fields['DestinationPort'], [ref] $port)) {
                $destination = "$destination port=$port"
            }
            $destination
        }
        11 { 'file-write'; $fields['TargetFilename'] }
        13 { 'registry-write'; $fields['TargetObject'] }
        22 { 'dns-query'; $fields['QueryName'] }
    }
    $detail = ([string] $detail).Trim()
    if (!$detail -or [Text.Encoding]::UTF8.GetByteCount($detail) -gt 1024 -or $detail -match '\p{Cc}') {
        throw "Invalid or missing event detail for Sysmon event $($event.Id)."
    }
    $entry = @{
        timestamp = $event.Time.ToUniversalTime().ToString('o')
        kind = $kind
        detail = $detail
        processGuid = $event.Guid
    }
    $parent = [guid]::Empty
    if ($event.Id -eq 1 -and [guid]::TryParse($fields['ParentProcessGuid'], [ref] $parent) -and $parent -ne [guid]::Empty) {
        $entry.parentProcessGuid = $parent.ToString('D')
    }
    $entry
})
if ($timeline.Count -gt 2000) { throw 'The selected process tree has more than 2,000 events.' }

$capture = @{
    schemaVersion = 1
    caseId = $CaseId
    sampleSha256 = $sha256[0]
    source = $source
    events = $timeline
}
if ($window) { $capture.captureWindow = $window }
$json = $capture | ConvertTo-Json -Depth 5 -Compress
if ([Text.Encoding]::UTF8.GetByteCount($json) -gt 4MB) { throw 'Capture exceeds 4 MiB. Export a narrower log.' }
$json
