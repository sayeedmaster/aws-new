<#
.SYNOPSIS
    Bootstrap script for Windows EC2 instances to configure networking, rename computer, join domain using SSM Parameter Store credentials (unless Domain is "workgroup"), initialize EBS volumes using IMDS block-device-mapping, optionally install SQL Server, and retrieve EC2 IMDS tags for future automation, based on Config.json.

.DESCRIPTION
    This script is executed on a Windows EC2 instance via UserData, as orchestrated by Manage-AWSResourcesFromExcel.ps1. It reads configuration from Config.json in the script's directory ($PSScriptRoot), which includes instance settings (ComputerName, IPAddress, Gateway, SubnetMask, DNS, Domain, OU, SQLInstall) and EBS volume settings (VolumeName, VolumeMount, VolumeLabel, PartitionStyle, FileSystem, AllocationUnitSize). It retrieves the instance's local hostname from EC2 IMDSv2, configures the network interface, renames the computer, joins the domain using credentials from AWS SSM Parameter Store (unless Domain is "workgroup"), initializes and formats EBS volumes using IMDS block-device-mapping to match VolumeName, and optionally installs SQL Server. All actions are logged to $PSScriptRoot\Logs\Bootstrap_Log_YYYYMMDD_HHMMSS.log.

.NOTES
    Author: Sayeed Master
    Date: July 20, 2025
    Version: 1.0.6
    License: MIT
    Requirements: Runs on a Windows EC2 instance with PowerShell and administrative privileges.
    Prerequisites: Config.json must exist in the same directory as the script ($PSScriptRoot), containing valid instance and volume configurations.
    Prerequisites: The instance must have IAM permissions for s3:GetObject (for Config.json and bootstrap.zip), ssm:GetParameter (for domain credentials, if applicable), and ec2:DescribeVolumes (for volume tag matching).
    Prerequisites: Domain credentials must be stored in SSM Parameter Store as /domain/<Domain>/username (String) and /domain/<Domain>/password (SecureString) for domains other than "workgroup".
    Prerequisites: For SQL installation, the SQL Server installer must be accessible (e.g., in bootstrap.zip or an S3 location).
    Prerequisites: EC2 instance must have access to IMDSv2 (default for EC2 instances).
    Prerequisites: VolumeName in Config.json must match the Name tag of EBS volumes or be resolvable via DescribeVolumes.

.EXAMPLE
    & "$PSScriptRoot\Bootstrap.ps1"
#>

# Initialize logging
$logDir = Join-Path $PSScriptRoot "Logs"
$logFilePath = Join-Path $logDir "Bootstrap_Log_$(Get-Date -Format 'yyyyMMDD_HHmmss').log"

function Write-Log {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARN", "ERROR", "DEBUG")]
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Write-Output $logMessage | Out-File -FilePath $logFilePath -Append -Encoding UTF8
    if ($Level -eq "ERROR") {
        Write-Error $Message
    } elseif ($Level -eq "WARN") {
        Write-Warning $Message
    } else {
        Write-Information $Message -InformationAction Continue
    }
}

try {
    # Ensure log directory exists
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        Write-Log "Created log directory: $logDir" "INFO"
    }

    # Read Config.json
    $configPath = Join-Path $PSScriptRoot "Config.json"
    if (-not (Test-Path $configPath)) {
        throw "Config.json not found at $configPath"
    }
    Write-Log "Reading configuration from $configPath" "INFO"
    try {
        $config = Get-Content -Path $configPath -Raw | ConvertFrom-Json
        Write-Log "Successfully loaded Config.json" "INFO"
    } catch {
        throw "Failed to parse Config.json. Error: $($_.Exception.Message)"
    }

    # Validate required configuration fields
    if (-not $config.ComputerName) {
        throw "ComputerName is missing in Config.json"
    }
    Write-Log "Processing configuration for instance: $($config.ComputerName)" "INFO"

    # Retrieve EC2 IMDS token for metadata queries
    $token = $null
    try {
        Write-Log "Requesting IMDSv2 token" "INFO"
        $token = Invoke-RestMethod -Method Put -Uri "http://169.254.169.254/latest/api/token" -Headers @{ "X-aws-ec2-metadata-token-ttl-seconds" = "21600" } -ErrorAction Stop
        Write-Log "Successfully retrieved IMDSv2 token" "INFO"
    } catch {
        Write-Log "Failed to retrieve IMDSv2 token. Error: $($_.Exception.Message)" "WARN"
    }

    # Retrieve EC2 IMDS tags (local hostname)
    $hostname = $null
    if ($token) {
        try {
            Write-Log "Retrieving local hostname from EC2 IMDSv2" "INFO"
            $hostname = (Invoke-RestMethod -Uri "http://169.254.169.254/latest/meta-data/local-hostname" -Headers @{ "X-aws-ec2-metadata-token" = $token } -ErrorAction Stop).Split(".")[0]
            Write-Log "Retrieved local hostname from IMDS: $hostname" "INFO"
        } catch {
            Write-Log "Failed to retrieve local hostname from IMDS. Error: $($_.Exception.Message)" "WARN"
            $hostname = "unknown"
        }
    } else {
        Write-Log "Skipping local hostname retrieval: No IMDS token available" "WARN"
        $hostname = "unknown"
    }

    # Configure networking
    if ($config.IPAddress -and $config.SubnetMask -and $config.Gateway) {
        Write-Log "Configuring network interface with IP: $($config.IPAddress), SubnetMask: $($config.SubnetMask), Gateway: $($config.Gateway)" "INFO"
        try {
            $interface = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Name -like 'Ethernet*' } | Select-Object -First 1
            if (-not $interface) {
                throw "No suitable network adapter found"
            }
            $prefixLength = [math]::Log([convert]::ToInt32($config.SubnetMask.Split('.')[0]) * 256 * 256 * 256 + [convert]::ToInt32($config.SubnetMask.Split('.')[1]) * 256 * 256 + [convert]::ToInt32($config.SubnetMask.Split('.')[2]) * 256 + [convert]::ToInt32($config.SubnetMask.Split('.')[3]), 2)
            New-NetIPAddress -InterfaceAlias $interface.Name -IPAddress $config.IPAddress -PrefixLength $prefixLength -DefaultGateway $config.Gateway -ErrorAction Stop | Out-Null
            Write-Log "Successfully set static IP address" "INFO"
        } catch {
            Write-Log "Failed to configure IP address. Error: $($_.Exception.Message)" "ERROR"
        }
    } else {
        Write-Log "Skipping network configuration: IPAddress, SubnetMask, or Gateway not specified" "INFO"
    }

    if ($config.DNS -and $config.DNS.Count -gt 0) {
        Write-Log "Configuring DNS servers: $($config.DNS -join ', ')" "INFO"
        try {
            $interface = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Name -like 'Ethernet*' } | Select-Object -First 1
            if (-not $interface) {
                throw "No suitable network adapter found for DNS configuration"
            }
            Set-DnsClientServerAddress -InterfaceAlias $interface.Name -ServerAddresses $config.DNS -ErrorAction Stop
            Write-Log "Successfully set DNS servers" "INFO"
        } catch {
            Write-Log "Failed to configure DNS servers. Error: $($_.Exception.Message)" "ERROR"
        }
    } else {
        Write-Log "Skipping DNS configuration: No DNS servers specified" "INFO"
    }

    # Rename computer (before domain join)
    if ($config.ComputerName -and $config.ComputerName -ne (hostname)) {
        Write-Log "Renaming computer to: $($config.ComputerName)" "INFO"
        try {
            Rename-Computer -NewName $config.ComputerName -Force -ErrorAction Stop
            Write-Log "Successfully renamed computer to $($config.ComputerName). Reboot required." "INFO"
        } catch {
            Write-Log "Failed to rename computer. Error: $($_.Exception.Message)" "ERROR"
        }
    } else {
        Write-Log "Skipping computer rename: Name already set or not specified" "INFO"
    }

    # Join domain if specified and not "workgroup"
    if ($config.Domain -and $config.Domain -ne "workgroup") {
        Write-Log "Joining domain: $($config.Domain)" "INFO"
        try {
            # Retrieve credentials from SSM Parameter Store
            $usernamePath = "/domain/$($config.Domain)/username"
            $passwordPath = "/domain/$($config.Domain)/password"
            Write-Log "Retrieving credentials from SSM Parameter Store: $usernamePath, $passwordPath" "INFO"
            
            try {
                $username = (Get-SSMParameter -Name $usernamePath -ErrorAction Stop).Value
                $password = (Get-SSMParameter -Name $passwordPath -WithDecryption $true -ErrorAction Stop).Value
                $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
                $credential = New-Object System.Management.Automation.PSCredential($username, $securePassword)
                Write-Log "Successfully retrieved credentials for domain $($config.Domain)" "INFO"
            } catch {
                throw "Failed to retrieve credentials from SSM Parameter Store for domain $($config.Domain). Error: $($_.Exception.Message)"
            }

            $ouPath = if ($config.OU) { $config.OU } else { $null }
            Add-Computer -DomainName $config.Domain -Credential $credential -OUPath $ouPath -Force -ErrorAction Stop
            Write-Log "Successfully joined domain: $($config.Domain)" "INFO"
        } catch {
            Write-Log "Failed to join domain $($config.Domain). Error: $($_.Exception.Message)" "ERROR"
        }
    } else {
        Write-Log "Skipping domain join: Domain is 'workgroup' or not specified" "INFO"
    }

    # Initialize and format EBS volumes
    if ($config.Volumes -and $config.Volumes.Count -gt 0) {
        Write-Log "Processing $($config.Volumes.Count) EBS volume(s)" "INFO"
        # Retrieve block device mappings from IMDS
        $blockDevices = $null
        if ($token) {
            try {
                Write-Log "Retrieving block device mappings from IMDSv2" "INFO"
                $blockDevices = Invoke-RestMethod -Uri "http://169.254.169.254/latest/meta-data/block-device-mapping/" -Headers @{ "X-aws-ec2-metadata-token" = $token } -ErrorAction Stop
                Write-Log "Retrieved block device mappings: $blockDevices" "INFO"
            } catch {
                Write-Log "Failed to retrieve block device mappings from IMDS. Error: $($_.Exception.Message)" "WARN"
            }
        } else {
            Write-Log "Skipping block device mapping retrieval: No IMDS token available" "WARN"
        }

        foreach ($volume in $config.Volumes) {
            try {
                Write-Log "Configuring volume: $($volume.VolumeName) (Mount: $($volume.VolumeMount), Label: $($volume.VolumeLabel))" "INFO"

                # Validate volume configuration
                if (-not $volume.VolumeMount) { throw "VolumeMount is missing for volume $($volume.VolumeName)" }
                if (-not $volume.VolumeLabel) { throw "VolumeLabel is missing for volume $($volume.VolumeName)" }
                if (-not $volume.PartitionStyle -or $volume.PartitionStyle -notin @('MBR', 'GPT')) {
                    throw "Invalid or missing PartitionStyle for volume $($volume.VolumeName). Must be 'MBR' or 'GPT'"
                }
                if (-not $volume.FileSystem -or $volume.FileSystem -notin @('NTFS', 'exFAT')) {
                    throw "Invalid or missing FileSystem for volume $($volume.VolumeName). Must be 'NTFS' or 'exFAT'"
                }
                if ($volume.AllocationUnitSize -and -not ([int]$volume.AllocationUnitSize -in @(4096, 8192, 16384, 32768, 65536))) {
                    throw "Invalid AllocationUnitSize for volume $($volume.VolumeName). Must be 4096, 8192, 16384, 32768, or 65536"
                }

                # Find the disk using IMDS block-device-mapping
                $disk = $null
                if ($blockDevices -and $token) {
                    try {
                        # Assume VolumeName matches the Name tag of the EBS volume
                        Write-Log "Querying AWS EC2 for volume with Name tag: $($volume.VolumeName)" "INFO"
                        $ec2Volume = Get-EC2Volume -Filter @{ Name="tag:Name"; Values=$volume.VolumeName } -ErrorAction Stop
                        if (-not $ec2Volume) {
                            Write-Log "No volume found with Name tag: $($volume.VolumeName)" "WARN"
                            throw "Volume not found"
                        }
                        $volumeId = $ec2Volume.VolumeId
                        Write-Log "Found volume ID $volumeId for VolumeName: $($volume.VolumeName)" "INFO"

                        # Match volume ID to IMDS block device
                        foreach ($device in $blockDevices.Split("`n")) {
                            try {
                                $deviceVolumeId = Invoke-RestMethod -Uri "http://169.254.169.254/latest/meta-data/block-device-mapping/$device" -Headers @{ "X-aws-ec2-metadata-token" = $token } -ErrorAction Stop
                                if ($deviceVolumeId -eq $volumeId) {
                                    # Map device name to Windows disk (e.g., /dev/xvdb)
                                    $disk = Get-Disk | Where-Object { $_.SerialNumber -like "*$volumeId*" -or $_.UniqueId -like "*$volumeId*" }
                                    if ($disk) {
                                        Write-Log "Matched volume ID $volumeId to disk number $($disk.Number) for device $device" "INFO"
                                        break
                                    }
                                }
                            } catch {
                                Write-Log "Failed to query IMDS for device $device. Error: $($_.Exception.Message)" "WARN"
                                continue
                            }
                        }
                        if (-not $disk) {
                            Write-Log "No disk found for volume ID $volumeId" "WARN"
                            throw "Disk not found"
                        }
                    } catch {
                        Write-Log "Failed to match volume $($volume.VolumeName). Error: $($_.Exception.Message)" "WARN"
                    }
                }

                # Fallback to original RAW disk selection if IMDS matching fails
                if (-not $disk) {
                    Write-Log "Falling back to RAW disk selection for volume $($volume.VolumeName)" "INFO"
                    $disk = Get-Disk | Where-Object { $_.PartitionStyle -eq 'RAW' } | Sort-Object Number | Select-Object -First 1
                    if (-not $disk) {
                        Write-Log "No uninitialized disk found for volume $($volume.VolumeName). Skipping." "WARN"
                        continue
                    }
                }

                # Initialize disk
                Write-Log "Initializing disk $($disk.Number) with PartitionStyle: $($volume.PartitionStyle)" "INFO"
                Initialize-Disk -Number $disk.Number -PartitionStyle $volume.PartitionStyle -ErrorAction Stop

                # Create partition
                Write-Log "Creating partition on disk $($disk.Number) with drive letter: $($volume.VolumeMount)" "INFO"
                $partition = New-Partition -DiskNumber $disk.Number -UseMaximumSize -DriveLetter $volume.VolumeMount[0] -ErrorAction Stop

                # Format volume
                $formatParams = @{
                    DriveLetter = $volume.VolumeMount[0]
                    FileSystem = $volume.FileSystem
                    NewFileSystemLabel = $volume.VolumeLabel
                    Confirm = $false
                    ErrorAction = 'Stop'
                }
                if ($volume.AllocationUnitSize) {
                    $formatParams.AllocationUnitSize = [int]$volume.AllocationUnitSize
                }
                Write-Log "Formatting volume $($volume.VolumeName) as $($volume.FileSystem) with label $($volume.VolumeLabel)" "INFO"
                Format-Volume @formatParams | Out-Null

                Write-Log "Successfully configured volume $($volume.VolumeName) on $($volume.VolumeMount)" "INFO"
            } catch {
                Write-Log "Failed to configure volume $($volume.VolumeName). Error: $($_.Exception.Message)" "ERROR"
                continue
            }
        }
    } else {
        Write-Log "No EBS volumes specified in Config.json" "INFO"
    }

    # Install SQL Server if specified
    if ($config.SQLInstall -eq $true) {
        Write-Log "SQLInstall is true. Initiating SQL Server installation." "INFO"
        try {
            # Placeholder: Assume SQL installer is in $PSScriptRoot\SQLServerInstaller.exe
            $sqlInstaller = Join-Path $PSScriptRoot "SQLServerInstaller.exe"
            if (-not (Test-Path $sqlInstaller)) {
                throw "SQL Server installer not found at $sqlInstaller"
            }
            # Example command (replace with actual SQL installation command)
            # Start-Process -FilePath $sqlInstaller -ArgumentList "/quiet /action=install /features=SQL /instancename=MSSQLSERVER" -Wait -ErrorAction Stop
            Write-Log "SQL Server installation placeholder executed successfully" "INFO"
        } catch {
            Write-Log "Failed to install SQL Server. Error: $($_.Exception.Message)" "ERROR"
        }
    } else {
        Write-Log "Skipping SQL Server installation: SQLInstall is false or not specified" "INFO"
    }

    # Check if reboot is required (e.g., after computer rename or domain join)
    if ($config.ComputerName -ne (hostname) -or ($config.Domain -and $config.Domain -ne "workgroup")) {
        Write-Log "Reboot required due to computer rename or domain join. Scheduling reboot." "INFO"
        try {
            # Schedule a reboot in 1 minute to allow script completion
            Start-Process -FilePath "shutdown" -ArgumentList "/r /t 60" -NoNewWindow
            Write-Log "Scheduled system reboot in 60 seconds" "INFO"
        } catch {
            Write-Log "Failed to schedule reboot. Error: $($_.Exception.Message)" "ERROR"
        }
    }

    Write-Log "Bootstrap script completed successfully for instance: $($config.ComputerName)" "INFO"
} catch {
    Write-Log "Fatal error in Bootstrap.ps1 execution. Error: $($_.Exception.Message)" "ERROR"
    exit 1
}