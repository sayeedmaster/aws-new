function Initialize-AndFormatDisks {
    [CmdletBinding()]
    param (
        [string]$FileSystem = "NTFS",
        [string]$Label = "Data",
        [switch]$QuickFormat,
        [int]$AllocationUnitSize = 4096,
        [ValidateSet("GPT", "MBR")]
        [string]$PartitionStyle = "GPT"
    )

    # Get all disks that are not yet initialized
    $rawDisks = Get-Disk | Where-Object PartitionStyle -eq 'RAW'
    foreach ($disk in $rawDisks) {
        Write-Host "Initializing disk number $($disk.Number) with $PartitionStyle partition style..."
        Initialize-Disk -Number $disk.Number -PartitionStyle $PartitionStyle

        Write-Host "Creating partition on disk number $($disk.Number)..."
        $partition = New-Partition -DiskNumber $disk.Number -UseMaximumSize -AssignDriveLetter

        Write-Host "Formatting partition $($partition.DriveLetter): as $FileSystem with allocation unit size $AllocationUnitSize..."
        Format-Volume -DriveLetter $partition.DriveLetter -FileSystem $FileSystem -NewFileSystemLabel $Label -AllocationUnitSize $AllocationUnitSize -Confirm:$false -Force
    }
    Write-Host "All raw disks have been initialized and formatted."
}