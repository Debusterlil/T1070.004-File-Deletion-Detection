$TargetPattern   = '*\T1070_004_Test.exe'
$LookbackMinutes = 15
$MaxDeltaMinutes = 10

$LogName = 'Microsoft-Windows-Sysmon/Operational'

function Convert-SysmonEvent {
    param($Event)

    [xml]$xml = $Event.ToXml()
    $fields = @{}

    foreach ($item in $xml.Event.EventData.Data) {
        $fields[$item.Name] = [string]$item.'#text'
    }

    [PSCustomObject]@{
        TimeCreated = $Event.TimeCreated
        Id          = $Event.Id
        RecordId    = $Event.RecordId
        Fields      = $fields
    }
}

$since = (Get-Date).AddMinutes(-$LookbackMinutes)

$creates = Get-WinEvent -FilterHashtable @{
    LogName   = $LogName
    Id        = 1
    StartTime = $since
} -ErrorAction SilentlyContinue |
ForEach-Object {
    Convert-SysmonEvent $_
} |
Where-Object {
    $_.Fields['Image'] -like $TargetPattern
}

$deletes = Get-WinEvent -FilterHashtable @{
    LogName   = $LogName
    Id        = 26
    StartTime = $since
} -ErrorAction SilentlyContinue |
ForEach-Object {
    Convert-SysmonEvent $_
} |
Where-Object {
    $_.Fields['TargetFilename'] -like $TargetPattern
}

$alerts = foreach ($create in $creates) {
    foreach ($delete in $deletes) {

        $delta = $delete.TimeCreated - $create.TimeCreated

        if (
            $delete.Fields['TargetFilename'] -ieq $create.Fields['Image'] -and
            $delta.TotalSeconds -ge 0 -and
            $delta.TotalMinutes -le $MaxDeltaMinutes
        ) {
            [PSCustomObject]@{
                Executable          = $create.Fields['Image']
                ExecutedAt          = $create.TimeCreated
                DeletedAt           = $delete.TimeCreated
                DeltaSeconds        = [math]::Round($delta.TotalSeconds, 3)
                LaunchParent        = $create.Fields['ParentImage']
                DeletedBy           = $delete.Fields['Image']
                ProcessCreateRecord = $create.RecordId
                FileDeleteRecord    = $delete.RecordId
            }
        }
    }
}

if ($alerts) {
    Write-Host "`n[ALERT] Executed file deleted shortly after launch`n"

    $alerts |
        Sort-Object ExecutedAt |
        Format-List
}
else {
    Write-Host "`n[OK] No matching execute -> delete sequence found."
}
