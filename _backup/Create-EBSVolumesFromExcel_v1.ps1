# Create-EBSVolumesFromExcel.ps1
# PowerShell script to create and attach EBS volumes to EC2 instances from Excel configuration using AWSPowerShell.NetCore with multiple SSO profiles
# Supports dry run mode to simulate actions without modifying AWS resources

param (
    [Parameter(Mandatory=$true, HelpMessage="Path to the directory containing AWSPowerShell.NetCore and ImportExcel modules.")]
    [string]$PSModulesPath,
    [Parameter(Mandatory=$false)]
    [string]$ExcelFilePath = (Join-Path $PSScriptRoot "EC2_Config.xlsx"),
    [Parameter(Mandatory=$false)]
    [string]$LogFilePath = (Join-Path $PSScriptRoot "logs\EBS_Create_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"),
    [Parameter(Mandatory=$false, HelpMessage="Run in dry run mode to simulate actions without modifying AWS resources.")]
    [switch]$DryRun
)

# Function to write logs
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $prefix = if ($DryRun) { "[DRYRUN] " } else { "" }
    $logMessage = "[$timestamp] [$Level] $prefix$Message"
    Write-Host $logMessage
    Add-Content -Path $LogFilePath -Value $logMessage
}

# Helper function to convert a value to a normalized string for boolean checks
function Convert-ToNormalizedString {
    param (
        $Value
    )
    if ($Value -is [System.Boolean]) {
        return $Value.ToString().ToUpper()
    } elseif ($Value -is [string]) {
        return $Value.ToUpper()
    }
    return $null
}

# Function to validate SSO session and prompt for login if needed
function Test-SSOSession {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ProfileName,
        [Parameter(Mandatory=$true)]
        [string]$Region
    )
    try {
        if ($DryRun) {
            Write-Log "Dry run: Skipping SSO session validation for profile: $ProfileName in region: $Region" "INFO"
            return $true
        }
        Set-DefaultAWSRegion -Region $Region -ErrorAction Stop
        Write-Log "Region set to $Region for profile: $ProfileName"
        Get-STSCallerIdentity -ProfileName $ProfileName -Region $Region -ErrorAction Stop > $null
        Write-Log "SSO session is valid for profile: $ProfileName in region: $Region"
        return $true
    } catch {
        Write-Log "SSO session is invalid or expired for profile: $ProfileName. Error: $($_.Exception.Message)" "ERROR"
        Write-Log "Please run 'aws sso login --profile $ProfileName' to authenticate, then retry the script." "ERROR"
        try {
            Write-Log "Attempting to trigger SSO login for profile: $ProfileName"
            $process = Start-Process -FilePath "aws" -ArgumentList "sso login --profile $ProfileName" -NoNewWindow -Wait -PassThru
            if ($process.ExitCode -eq 0) {
                Write-Log "SSO login successful for profile: $ProfileName"
                Set-DefaultAWSRegion -Region $Region -ErrorAction Stop
                Get-STSCallerIdentity -ProfileName $ProfileName -Region $Region -ErrorAction Stop > $null
                Write-Log "SSO session validated after login for profile: $ProfileName"
                return $true
            } else {
                Write-Log "SSO login failed for profile: $ProfileName. Exit code: $($process.ExitCode)" "ERROR"
                return $false
            }
        } catch {
            Write-Log "Failed to trigger SSO login for profile: $ProfileName. Error: $($_.Exception.Message)" "ERROR"
            return $false
        }
    }
}

# Function for preflight checks before creating a volume
function Invoke-PreflightChecks {
    param(
        [Parameter(Mandatory=$true)]
        $Config,
        [Parameter(Mandatory=$true)]
        [string]$ProfileName,
        [Parameter(Mandatory=$true)]
        [string]$Region
    )

    Write-Log "Running preflight checks for volume $($Config.VolumeName)..."

    # --- Instance Check ---
    $instanceName = $Config.Instance
    if (-not $instanceName) {
        Write-Log "No Instance specified for volume $($Config.VolumeName). This is a required field." "ERROR"
        return @{ Success = $false }
    }
    if ($DryRun) {
        Write-Log "Dry run: Assuming instance '$instanceName' exists in region $Region and AZ $($Config.AvailabilityZone)." "INFO"
    } else {
        try {
            $instance = Get-EC2Instance -Filter @{Name="tag:Name";Values=$instanceName} -ProfileName $ProfileName -Region $Region -ErrorAction Stop
            if ($instance.Instances.Count -eq 0) {
                Write-Log "No EC2 instance found with Name tag '$instanceName' in region $Region." "ERROR"
                return @{ Success = $false }
            }
            $instanceId = $instance.Instances[0].InstanceId
            $instanceAz = $instance.Instances[0].Placement.AvailabilityZone
            if ($instanceAz -ne $Config.AvailabilityZone) {
                Write-Log "Instance '$instanceName' (ID: $instanceId) is in AZ '$instanceAz', but volume is specified for AZ '$($Config.AvailabilityZone)'. They must match." "ERROR"
                return @{ Success = $false }
            }
            Write-Log "Found instance '$instanceName' (ID: $instanceId) in AZ '$instanceAz'."
            # Check existing block device mappings for device name conflicts
            $existingDevices = $instance.Instances[0].BlockDeviceMappings | ForEach-Object { $_.DeviceName }
            $volumeMount = [string]$Config.VolumeMount
            if ($volumeMount) {
                $deviceLetter = $volumeMount -replace ':$', '' # Remove trailing colon
                $deviceName = "/dev/sd$($deviceLetter.ToLower())"
                if ($deviceName -in $existingDevices) {
                    Write-Log "Device name '$deviceName' is already in use for instance '$instanceName' (ID: $instanceId). Please specify a different VolumeMount." "ERROR"
                    return @{ Success = $false }
                }
            }
            return @{ Success = $true; InstanceId = $instanceId }
        } catch {
            Write-Log "Failed to validate instance '$instanceName'. Error: $($_.Exception.Message)" "ERROR"
            return @{ Success = $false }
        }
    }

    # --- Volume Size Check ---
    if ($Config.Size) {
        try {
            $size = [int]$Config.Size
            if ($size -le 0) {
                Write-Log "Size '$($Config.Size)' for volume $($Config.VolumeName) must be a positive integer." "ERROR"
                return @{ Success = $false }
            }
            Write-Log "Volume size '$size' GiB is valid for volume $($Config.VolumeName)."
        } catch {
            Write-Log "Invalid Size '$($Config.Size)' for volume $($Config.VolumeName). Must be a positive integer. Error: $($_.Exception.Message)" "ERROR"
            return @{ Success = $false }
        }
    } else {
        Write-Log "No Size specified for volume $($Config.VolumeName). This is a required field." "ERROR"
        return @{ Success = $false }
    }

    # --- Volume Type Check ---
    $validVolumeTypes = @('standard', 'gp2', 'gp3', 'io1', 'io2', 'sc1', 'st1')
    if ($Config.VolumeType) {
        if ($Config.VolumeType -notin $validVolumeTypes) {
            Write-Log "Invalid VolumeType '$($Config.VolumeType)' for volume $($Config.VolumeName). Must be one of: $($validVolumeTypes -join ', ')." "ERROR"
            return @{ Success = $false }
        }
        Write-Log "VolumeType '$($Config.VolumeType)' is valid for volume $($Config.VolumeName)."
    } else {
        Write-Log "No VolumeType specified for volume $($Config.VolumeName). Defaulting to 'gp2'." "WARN"
        $Config.VolumeType = 'gp2'
    }

    # --- IOPS Check ---
    if ($Config.Iops) {
        try {
            $iops = [int]$Config.Iops
            if ($iops -le 0) {
                Write-Log "Iops '$($Config.Iops)' for volume $($Config.VolumeName) must be a positive integer." "ERROR"
                return @{ Success = $false }
            }
            if ($Config.VolumeType -notin @('io1', 'io2', 'gp3')) {
                Write-Log "Iops specified for volume $($Config.VolumeName), but VolumeType '$($Config.VolumeType)' does not support IOPS configuration." "ERROR"
                return @{ Success = $false }
            }
            Write-Log "Iops '$iops' is valid for volume $($Config.VolumeName)."
        } catch {
            Write-Log "Invalid Iops '$($Config.Iops)' for volume $($Config.VolumeName). Must be a positive integer. Error: $($_.Exception.Message)" "ERROR"
            return @{ Success = $false }
        }
    }

    # --- Throughput Check ---
    if ($Config.Throughput) {
        try {
            $throughput = [int]$Config.Throughput
            if ($throughput -le 0) {
                Write-Log "Throughput '$($Config.Throughput)' for volume $($Config.VolumeName) must be a positive integer." "ERROR"
                return @{ Success = $false }
            }
            if ($Config.VolumeType -ne 'gp3') {
                Write-Log "Throughput specified for volume $($Config.VolumeName), but VolumeType '$($Config.VolumeType)' does not support throughput configuration." "ERROR"
                return @{ Success = $false }
            }
            Write-Log "Throughput '$throughput' MiB/s is valid for volume $($Config.VolumeName)."
        } catch {
            Write-Log "Invalid Throughput '$($Config.Throughput)' for volume $($Config.VolumeName). Must be a positive integer. Error: $($_.Exception.Message)" "ERROR"
            return @{ Success = $false }
        }
    }

    # --- Encryption Check ---
    if ($null -ne $Config.Encrypted) {
        $normalizedEncrypted = Convert-ToNormalizedString -Value $Config.Encrypted
        Write-Log "Encrypted raw value: '$($Config.Encrypted)' (Type: $($Config.Encrypted.GetType().Name)), normalized: '$normalizedEncrypted'" "DEBUG"
        if ($normalizedEncrypted -eq 'TRUE') {
            if ($Config.KmsKeyId) {
                if ($DryRun) {
                    Write-Log "Dry run: Assuming KMS key '$($Config.KmsKeyId)' is valid." "INFO"
                } else {
                    try {
                        Get-KMSKey -KeyId $Config.KmsKeyId -ProfileName $ProfileName -Region $Region -ErrorAction Stop > $null
                        Write-Log "KMS key '$($Config.KmsKeyId)' is valid for volume $($Config.VolumeName)."
                    } catch {
                        Write-Log "Invalid KmsKeyId '$($Config.KmsKeyId)' for volume $($Config.VolumeName). Error: $($_.Exception.Message)" "ERROR"
                        return @{ Success = $false }
                    }
                }
            } else {
                Write-Log "Encrypted is set to 'TRUE' for volume $($Config.VolumeName), but no KmsKeyId is specified. Using default KMS key for encryption." "WARN"
            }
        } elseif ($normalizedEncrypted -ne 'FALSE') {
            Write-Log "Invalid Encrypted value '$($Config.Encrypted)' for volume $($Config.VolumeName). Must be 'TRUE' or 'FALSE'. Defaulting to FALSE." "WARN"
            $Config.Encrypted = 'FALSE'
        }
    }

    # --- Snapshot ID Check ---
    if ($Config.SnapshotId) {
        if ($DryRun) {
            Write-Log "Dry run: Assuming SnapshotId '$($Config.SnapshotId)' is valid." "INFO"
        } else {
            try {
                Get-EC2Snapshot -SnapshotId $Config.SnapshotId -ProfileName $ProfileName -Region $Region -ErrorAction Stop > $null
                Write-Log "SnapshotId '$($Config.SnapshotId)' is valid for volume $($Config.VolumeName)."
            } catch {
                Write-Log "Invalid SnapshotId '$($Config.SnapshotId)' for volume $($Config.VolumeName). Error: $($_.Exception.Message)" "ERROR"
                return @{ Success = $false }
            }
        }
    }

    # --- Multi-Attach Check ---
    if ($null -ne $Config.MultiAttachEnabled) {
        $normalizedMultiAttach = Convert-ToNormalizedString -Value $Config.MultiAttachEnabled
        Write-Log "MultiAttachEnabled raw value: '$($Config.MultiAttachEnabled)' (Type: $($Config.MultiAttachEnabled.GetType().Name)), normalized: '$normalizedMultiAttach'" "DEBUG"
        if ($normalizedMultiAttach -eq 'TRUE') {
            if ($Config.VolumeType -notin @('io1', 'io2')) {
                Write-Log "MultiAttachEnabled is set to 'TRUE' for volume $($Config.VolumeName), but VolumeType '$($Config.VolumeType)' does not support multi-attach." "ERROR"
                return @{ Success = $false }
            }
            Write-Log "MultiAttachEnabled is valid for volume $($Config.VolumeName)."
        } elseif ($normalizedMultiAttach -ne 'FALSE') {
            Write-Log "Invalid MultiAttachEnabled value '$($Config.MultiAttachEnabled)' for volume $($Config.VolumeName). Must be 'TRUE' or 'FALSE'. Defaulting to FALSE." "WARN"
            $Config.MultiAttachEnabled = 'FALSE'
        }
    }

    # --- Volume Mount Check ---
    if ($Config.VolumeMount) {
        $volumeMount = [string]$Config.VolumeMount
        if ($volumeMount -notmatch '^[A-Z]:$') {
            Write-Log "Invalid VolumeMount '$volumeMount' for volume $($Config.VolumeName). Must be a valid Windows drive letter followed by a colon (e.g., 'D:')." "ERROR"
            return @{ Success = $false }
        }
        Write-Log "VolumeMount '$volumeMount' is valid for volume $($Config.VolumeName)."
    }

    return @{ Success = $true; InstanceId = $null }
}

try {
    # Ensure the log directory exists
    $logDir = Split-Path -Path $LogFilePath -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -ErrorAction Stop > $null
    }

    # Import required modules
    try {
        Import-Module -Name (Join-Path $PSModulesPath "AWSPowerShell.NetCore") -ErrorAction Stop
        Import-Module -Name (Join-Path $PSModulesPath "ImportExcel") -ErrorAction Stop
    } catch {
        Write-Log "Failed to import modules from $PSModulesPath. Error: $($_.Exception.Message)" "ERROR"
        exit 1
    }

    Write-Log "Starting EBS volume creation script (DryRun: $DryRun)"

    # Read Excel file
    Write-Log "Reading Excel file: $ExcelFilePath"
    if (-not (Test-Path $ExcelFilePath)) {
        throw "Excel file not found: $ExcelFilePath"
    }
    
    $ebsConfigs = Import-Excel -Path $ExcelFilePath -WorksheetName "EBS_Volumes" -ErrorAction Stop
    if ($ebsConfigs.Count -eq 0) {
        throw "No EBS volume configurations found in Excel file"
    }
    Write-Log "Found $($ebsConfigs.Count) EBS volume configurations in Excel"

    # Path to AWS config file
    $awsConfigPath = "$env:USERPROFILE\.aws\config"
    if (-not (Test-Path $awsConfigPath)) {
        throw "AWS config file not found: $awsConfigPath"
    }

    # Read config file into lines
    $configLines = Get-Content -Path $awsConfigPath

    # Process each EBS configuration
    foreach ($config in $ebsConfigs) {
        try {
            $accountId = $config.AccountId
            $accountName = $config.AccountName
            $ssoRole = $config.SSORole
            $volumeName = $config.VolumeName
            $instanceName = $config.Instance

            # Clean names to match the profile format
            $cleanAccountName = $accountName -replace '[^\w\-]', ''
            $cleanSsoRole = $ssoRole -replace '[^\w\-]', ''
            $profileName = "sso-$cleanAccountName-$cleanSsoRole"

            Write-Log "Processing EBS volume configuration for Account: $accountId ($accountName), Volume: $volumeName, Instance: $instanceName, Profile: $profileName"

            # Find profile section
            $profileHeaderPattern = "^\[profile\s+$([regex]::Escape($profileName))\s*\]$"
            $profileLine = $configLines | Select-String -Pattern $profileHeaderPattern

            if (-not $profileLine) {
                Write-Log "Profile section not found in AWS config for: $profileName. Please ensure it exists in '$awsConfigPath'." "ERROR"
                continue
            }

            $profileStart = $profileLine.LineNumber
            $nextHeader = $configLines[($profileStart)..($configLines.Count-1)] | Select-String -Pattern "^\[(profile|sso-session)\s+"
            $profileEnd = if ($nextHeader) { $profileStart + $nextHeader[0].LineNumber - 2 } else { $configLines.Count - 1 }
            $profileBlock = $configLines[($profileStart - 1)..$profileEnd]

            # Parse required fields from profile block
            $ssoStartUrl = ($profileBlock | Where-Object { $_ -match '^sso_start_url\s*=\s*(.+)$' }) -replace '^sso_start_url\s*=\s*', ''
            $region = ($profileBlock | Where-Object { $_ -match '^region\s*=\s*(.+)$' }) -replace '^region\s*=\s*', ''
            $ssoAccountId = ($profileBlock | Where-Object { $_ -match '^sso_account_id\s*=\s*(.+)$' }) -replace '^sso_account_id\s*=\s*', ''
            $ssoRoleName = ($profileBlock | Where-Object { $_ -match '^sso_role_name\s*=\s*(.+)$' }) -replace '^sso_role_name\s*=\s*', ''
            $ssoSession = ($profileBlock | Where-Object { $_ -match '^sso_session\s*=\s*(.+)$' }) -replace '^sso_session\s*=\s*', ''

            if (-not $ssoStartUrl -or -not $region -or -not $ssoAccountId -or -not $ssoRoleName -or -not $ssoSession) {
                Write-Log "Incomplete SSO profile configuration for: $profileName. Required fields: sso_start_url, region, sso_account_id, sso_role_name, sso_session." "ERROR"
                continue
            }

            # Validate AccountId and SSORole
            if ($ssoAccountId -ne $accountId) {
                Write-Log "AccountId ($accountId) in Excel does not match sso_account_id ($ssoAccountId) in profile: $profileName." "ERROR"
                continue
            }
            if ($ssoRoleName -ne $ssoRole) {
                Write-Log "SSORole ($ssoRole) in Excel does not match sso_role_name ($ssoRoleName) in profile: $profileName." "ERROR"
                continue
            }

            # Validate region
            $validRegions = if ($DryRun) { @($region) } else { Get-AWSRegion -ErrorAction Stop | Select-Object -ExpandProperty Region }
            if ($region -notin $validRegions) {
                Write-Log "Region '$region' is not a valid AWS region for profile: $profileName. Valid regions: $($validRegions -join ', ')" "ERROR"
                continue
            }

            # Set AWS credentials and region
            Write-Log "Setting AWS credentials for profile: $profileName"
            try {
                if (-not $DryRun) {
                    Set-AWSCredential -ProfileName $profileName -ErrorAction Stop
                    if (-not (Test-SSOSession -ProfileName $profileName -Region $region)) {
                        Write-Log "Skipping volume creation for $volumeName due to invalid SSO session." "ERROR"
                        continue
                    }
                    Set-DefaultAWSRegion -Region $region -ErrorAction Stop
                }
                Write-Log "Successfully set credentials and region ($region) for profile: $profileName"
            } catch {
                Write-Log "Failed to set credentials for profile: $profileName. Error: $($_.Exception.Message)" "ERROR"
                continue
            }

            # Run preflight checks
            $preflightResult = Invoke-PreflightChecks -Config $config -ProfileName $profileName -Region $region
            if (-not $preflightResult.Success) {
                Write-Log "Preflight checks failed for volume $($config.VolumeName). Skipping creation." "ERROR"
                continue
            }
            $instanceId = $preflightResult.InstanceId

            # Prepare EBS volume creation parameters
            $volumeParams = @{
                AvailabilityZone = $config.AvailabilityZone
                Size = [int]$config.Size
                VolumeType = $config.VolumeType
            }
            if ($config.Iops) { $volumeParams.Iops = [int]$config.Iops }
            if ($config.Throughput) { $volumeParams.Throughput = [int]$config.Throughput }
            $normalizedEncrypted = Convert-ToNormalizedString -Value $config.Encrypted
            if ($normalizedEncrypted -eq 'TRUE') { $volumeParams.Encrypted = $true }
            if ($config.KmsKeyId) { $volumeParams.KmsKeyId = $config.KmsKeyId }
            if ($config.SnapshotId) { $volumeParams.SnapshotId = $config.SnapshotId }
            $normalizedMultiAttach = Convert-ToNormalizedString -Value $config.MultiAttachEnabled
            if ($normalizedMultiAttach -eq 'TRUE') { $volumeParams.MultiAttachEnabled = $true }

            # Create tags
            $tags = @()
            if ($config.Tags) {
                Write-Log "Processing tags for volume $($config.VolumeName): $($config.Tags)" "DEBUG"
                $tagPairs = $config.Tags -split ',' | ForEach-Object { $_.Trim() }
                foreach ($tagPair in $tagPairs) {
                    $keyValue = $tagPair -split '='
                    if ($keyValue.Count -eq 2 -and $keyValue[0].Trim() -and $keyValue[1].Trim()) {
                        $tag = New-Object Amazon.EC2.Model.Tag
                        $tag.Key = $keyValue[0].Trim()
                        $tag.Value = $keyValue[1].Trim()
                        $tags += $tag
                        Write-Log "Adding tag: $($tag.Key)=$($tag.Value)" "DEBUG"
                    } else {
                        Write-Log "Invalid tag format: '$tagPair'. Expected 'key=value'. Skipping this tag." "WARN"
                    }
                }
            }
            if ($config.VolumeName -and -not ($tags | Where-Object { $_.Key -eq 'Name' })) {
                $nameTag = New-Object Amazon.EC2.Model.Tag
                $nameTag.Key = 'Name'
                $nameTag.Value = $config.VolumeName
                $tags += $nameTag
                Write-Log "Adding Name tag: Name=$($config.VolumeName)" "DEBUG"
            }

            # Create EBS volume
            Write-Log "Creating EBS volume for Account: $accountId ($accountName), Region: $region, Volume: $volumeName"
            if ($DryRun) {
                Write-Log "Dry run: Would create EBS volume with parameters: $(ConvertTo-Json -InputObject $volumeParams -Depth 5 -Compress)" "INFO"
                Write-Log "Dry run: Would apply tags: $(ConvertTo-Json -InputObject $tags -Depth 5 -Compress)" "INFO"
                $volumeId = "vol-dryrun-$(Get-Random -Minimum 1000000000 -Maximum 9999999999)"
                Write-Log "Dry run: Simulated EBS volume creation with VolumeId: $volumeId" "INFO"
            } else {
                $volume = New-EC2Volume @volumeParams -ProfileName $profileName -Region $region -ErrorAction Stop
                $volumeId = $volume.VolumeId
                Write-Log "Successfully created EBS volume: $volumeId"
                if ($tags.Count -gt 0) {
                    New-EC2Tag -Resource $volumeId -Tag $tags -ProfileName $profileName -Region $region -ErrorAction Stop
                    Write-Log "Applied $($tags.Count) tags to volume $volumeId"
                }
            }

            # Attach volume to instance
            if ($instanceId -or $DryRun) {
                $volumeMount = [string]$config.VolumeMount
                $deviceName = if ($volumeMount) { "/dev/sd$($($volumeMount -replace ':$', '').ToLower())" } else { "/dev/sdf" }
                Write-Log "Attaching volume $volumeId to instance ${instanceId} as device $deviceName"
                if ($DryRun) {
                    Write-Log "Dry run: Would attach volume $volumeId to instance ${instanceId} as device $deviceName" "INFO"
                } else {
                    # Wait for volume to be available
                    $timeout = 300 # 5 minutes
                    $startTime = Get-Date
                    do {
                        Start-Sleep -Seconds 5
                        $volumeState = (Get-EC2Volume -VolumeId $volumeId -ProfileName $profileName -Region $region).State
                        if ((New-TimeSpan -Start $startTime -End (Get-Date)).TotalSeconds -gt $timeout) {
                            throw "Timeout waiting for volume $volumeId to become available."
                        }
                    } until ($volumeState -eq 'available')
                    Write-Log "Volume $volumeId is available for attachment."
                    Add-EC2Volume -VolumeId $volumeId -InstanceId $instanceId -Device $deviceName -ProfileName $profileName -Region $region -ErrorAction Stop
                    Write-Log "Successfully attached volume $volumeId to instance $instanceId as device $deviceName"
                }
            }

            # Clear credentials
            if (-not $DryRun) {
                Clear-AWSCredential -ErrorAction SilentlyContinue
                Clear-DefaultAWSRegion -ErrorAction SilentlyContinue
            }

        } catch {
            Write-Log "Error processing configuration for Account: $accountId ($accountName), Region: $region, Volume: $volumeName, Instance: $instanceName. Error: $($_.Exception.Message)" "ERROR"
            if (-not $DryRun) {
                Clear-AWSCredential -ErrorAction SilentlyContinue
                Clear-DefaultAWSRegion -ErrorAction SilentlyContinue
            }
            continue
        }
    }

    Write-Log "EBS volume creation process completed"

} catch {
    Write-Log "Fatal error: $($_.Exception.Message)" "ERROR"
    exit 1
}