[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $Evtx,
    [Parameter(Mandatory)]
    [guid] $ProcessGuid,
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9_-]{1,64}$')]
    [string] $CaseId
)

$ErrorActionPreference = 'Stop'
$path = (Get-Item -LiteralPath $Evtx).FullName
if ([IO.Path]::GetExtension($path) -ine '.evtx' -or ![IO.File]::Exists($path)) {
    throw 'Select an exported Sysmon .evtx file.'
}
if ((Get-Item -LiteralPath $path).Length -gt 128MB) { throw 'EVTX exceeds 128 MiB.' }

$rows = @(Get-WinEvent -FilterHashtable @{
    Path = $path
    ProviderName = 'Microsoft-Windows-Sysmon'
    Id = 1, 3, 11, 13, 22
} -Oldest -MaxEvents 20001)
if ($rows.Count -gt 20000) { throw 'Export a narrower log: more than 20,000 supported events.' }

$root = $ProcessGuid.ToString('B')
$starts = @{}
$children = @{}
$events = [Collections.Generic.List[object]]::new()
foreach ($row in $rows) {
    [xml] $xml = $row.ToXml()
    $fields = @{}
    foreach ($node in $xml.Event.EventData.Data) {
        $fields[$node.GetAttribute('Name')] = $node.InnerText
    }
    $guid = $fields['ProcessGuid']
    if (!$guid) { continue }
    if ($row.Id -eq 1) {
        if ($starts.ContainsKey($guid)) { throw 'Duplicate process start GUID in capture.' }
        $starts[$guid] = $fields
        $parent = $fields['ParentProcessGuid']
        if ($parent) {
            if (!$children.ContainsKey($parent)) { $children[$parent] = [Collections.Generic.List[string]]::new() }
            $children[$parent].Add($guid)
        }
    }
    $events.Add([pscustomobject]@{ Guid = $guid; Id = $row.Id; Time = $row.TimeCreated; Fields = $fields })
}

if (!$starts.ContainsKey($root)) { throw 'Process GUID was not found in a Sysmon process creation event.' }
$sha256 = @($starts[$root]['Hashes'] -split ',' | ForEach-Object {
    if ($_ -match '^\s*SHA256=([0-9a-f]{64})\s*$') { $Matches[1].ToLowerInvariant() }
})
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
        3 { 'network-connection'; "$($fields['DestinationIp']) $($fields['DestinationHostname'])" }
        11 { 'file-write'; $fields['TargetFilename'] }
        13 { 'registry-write'; $fields['TargetObject'] }
        22 { 'dns-query'; $fields['QueryName'] }
    }
    $detail = ([string] $detail).Trim()
    if (!$detail -or [Text.Encoding]::UTF8.GetByteCount($detail) -gt 1024 -or $detail -match '\p{Cc}') {
        throw "Invalid or missing event detail for Sysmon event $($event.Id)."
    }
    @{
        timestamp = $event.Time.ToUniversalTime().ToString('o')
        kind = $kind
        detail = $detail
    }
})
if ($timeline.Count -gt 2000) { throw 'The selected process tree has more than 2,000 events.' }

@{
    schemaVersion = 1
    caseId = $CaseId
    sampleSha256 = $sha256[0]
    source = "sysmon-evtx:$root"
    events = $timeline
} | ConvertTo-Json -Depth 5 -Compress
