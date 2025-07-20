<#
.SYNOPSIS
    Creates EBS volumes and launches EC2 instances, attaching volumes after instance creation, based on an Excel configuration, with S3-based bootstrapping.

.DESCRIPTION
    This script reads EC2 instance and EBS volume configurations from an Excel file, creates EBS volumes, generates per-instance Config.json, uploads it to an S3 bucket, launches EC2 instances with optional UserData for bootstrapping, and attaches volumes. It applies tags from the EC2 configuration to both instances and volumes. Supports multiple SSO profiles, dry run mode, and optional permission validation skipping. Before launching each EC2 instance, it displays detailed parameters and prompts for user confirmation. Uses S3 for Windows EC2 bootstrapping with config-driven network, domain, and volume settings. The bootstrap.zip file must be manually uploaded to the specified S3 bucket and key prefix.

.NOTES
    Author: Sayeed Master
    Date: July 20, 2025
    Version: 1.4.2
    License: MIT
    Usage: .\Manage-AWSResourcesFromExcel.ps1 -PSModulesPath 'C:\Path\To\AWS.Tools' -S3BucketName 'userdata-terraform-packages' -S3BucketKeyPrefix 'artifacts' [-ExcelFilePath 'C:\Path\To\EC2_Config.xlsx'] [-LogFilePath 'C:\Path\To\Logs\AWS_Resources_Log.log'] [-DryRun] [-SkipPermissionValidation] [-EnableUserData]
    Requirements: AWS.Tools modules and ImportExcel module installed in the specified PSModulesPath.
    Prerequisites: AWS SSO must be set up in your AWS account.
    Prerequisites: AWS config file must exist at $env:USERPROFILE\.aws\config with required SSO profile configuration.
    Prerequisites: bootstrap.zip must be manually uploaded to s3://<S3BucketName>/<S3BucketKeyPrefix>/bootstrap.zip if EnableUserData is true.
    Excel File: Must contain 'EC2_Instances' and 'EBS_Volumes' worksheets. EC2_Instances must include columns: InstanceName, AccountId, AccountName, SSORole, ImageId, InstanceType, SubnetId, PrivateIpAddress, AssociatePublicIpAddress, SecurityGroupIds, IamInstanceProfile, KeyName, EbsOptimized, SriovNetSupport, RootVolumeSize, RootVolumeType, Encrypted, KmsKeyId, Tags, Domain, DefaultGateway, SubnetMask, PrimaryDNS, SecondaryDNS. EBS_Volumes must include columns: SSORole, AccountId, AccountName, AvailabilityZone, Instance, VolumeName, VolumeID, Size, VolumeType, Iops, Throughput, Encrypted, KmsKeyId, SnapshotId, MultiAttachEnabled, PartitionStyle, VolumeMount, VolumeLabel, FileSystem, AllocationUnitSize. EBS volumes are linked to EC2 instances via the 'Instance' column matching 'InstanceName'.

.PARAMETERS
    PSModulesPath
        Path to the directory containing AWS.Tools and ImportExcel modules.
        Mandatory: True.
        Example: 'C:\Path\To\AWS.Tools'

    S3BucketName
        Name of the S3 bucket for storing Config.json and accessing bootstrap.zip.
        Mandatory: True.
        Example: 'userdata-terraform-packages'

    S3BucketKeyPrefix
        S3 key prefix (folder) for storing Config.json and accessing bootstrap.zip (e.g., 'artifacts').
        Mandatory: True.
        Example: 'artifacts'

    ExcelFilePath
        Path to the Excel file containing EC2 and EBS configurations.
        Default: 'EC2_Config.xlsx' in the script's directory.
        Example: 'C:\Path\To\EC2_Config.xlsx'

    LogFilePath
        Path to the log file for actions and errors.
        Default: 'logs\AWS_Resources_Log_YYYYMMDD_HHMMSS.log' in the script's directory.
        Example: 'C:\Path\To\Logs\AWS_Resources_Log.log'

    DryRun
        Simulate actions without modifying AWS resources or the Excel file.
        Default: False.

    SkipPermissionValidation
        Skip permission validation for accounts with full administrator access.
        Default: False.

    EnableUserData
        Enable generation and inclusion of UserData for EC2 instances, including Config.json creation and upload.
        Default: True.

.EXAMPLE
    .\Manage-AWSResourcesFromExcel.ps1 -PSModulesPath 'C:\Path\To\AWS.Tools' -S3BucketName 'userdata-terraform-packages' -S3BucketKeyPrefix 'config' -ExcelFilePath 'C:\Path\To\EC2_Config.xlsx' -LogFilePath 'C:\Path\To\Logs\AWS_Resources_Log.log' -DryRun -EnableUserData:$false
#>

param (
    [Parameter(Mandatory=$true, HelpMessage="Path to the directory containing AWS.Tools and ImportExcel modules.")]
    [string]$PSModulesPath,
    [Parameter(Mandatory=$true, HelpMessage="Name of the S3 bucket for storing Config.json and accessing bootstrap.zip.")]
    [string]$S3BucketName,
    [Parameter(Mandatory=$true, HelpMessage="S3 key prefix (folder) for storing Config.json and accessing bootstrap.zip.")]
    [string]$S3BucketKeyPrefix,
    [Parameter(Mandatory=$false)]
    [string]$ExcelFilePath = (Join-Path $PSScriptRoot "EC2_Config.xlsx"),
    [Parameter(Mandatory=$false)]
    [string]$LogFilePath = (Join-Path $PSScriptRoot "logs\AWS_Resources_Log_$(Get-Date -Format 'yyyyMMDD_HHmmss').log"),
    [Parameter(Mandatory=$false, HelpMessage="Run in dry run mode to simulate actions without modifying AWS resources.")]
    [switch]$DryRun,
    [Parameter(Mandatory=$false, HelpMessage="Skip permission validation for accounts with full administrator access.")]
    [switch]$SkipPermissionValidation,
    [Parameter(Mandatory=$false, HelpMessage="Enable generation and inclusion of UserData for EC2 instances.")]
    [bool]$EnableUserData = $false
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
    switch ($Level.ToUpper()) {
        "INFO"    { $color = if ($Message -match "^Successfully") { "Green" } else { "Blue" } }
        "WARN"    { $color = "Yellow" }
        "WARNING" { $color = "Yellow" }
        "ERROR"   { $color = "Red" }
        "DEBUG"   { $color = "Gray" }
        default   { $color = $null }
    }
    if ($color) {
        Write-Host $logMessage -ForegroundColor $color
    } else {
        Write-Host $logMessage
    }
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

# Helper function to check if an IP address is within a CIDR block
function Test-IpInCidr {
    param(
        [Parameter(Mandatory=$true)]
        [string]$IpAddress,
        [Parameter(Mandatory=$true)]
        [string]$Cidr
    )
    try {
        $ip = [System.Net.IPAddress]::Parse($IpAddress)
        $ipBytes = $ip.GetAddressBytes()
        $cidrParts = $Cidr.Split('/')
        if ($cidrParts.Count -ne 2) {
            Write-Log "Invalid CIDR format: '$Cidr'. Expected format: 'x.x.x.x/y'." "ERROR"
            return $false
        }
        $cidrBaseIp = [System.Net.IPAddress]::Parse($cidrParts[0])
        $maskLength = [int]$cidrParts[1]
        $cidrBaseIpBytes = $cidrBaseIp.GetAddressBytes()
        if ($maskLength -lt 0 -or $maskLength -gt 32) {
            Write-Log "Invalid mask length '$maskLength' in CIDR '$Cidr'. Must be between 0 and 32." "ERROR"
            return $false
        }
        $maskBytes = [byte[]]::new(4)
        for ($i = 0; $i -lt $maskLength; $i++) {
            $byteIndex = [math]::Floor($i / 8)
            $bitPosition = $i % 8
            $maskBytes[$byteIndex] = $maskBytes[$byteIndex] -bor (128 -shr $bitPosition)
        }
        for ($i = 0; $i -lt 4; $i++) {
            $maskedIp = $ipBytes[$i] -band $maskBytes[$i]
            $maskedCidr = $cidrBaseIpBytes[$i]
            if ($maskedIp -ne $maskedCidr) {
                Write-Log "IP '$IpAddress' byte $i ($maskedIp) does not match CIDR '$Cidr' byte $i ($maskedCidr)." "DEBUG"
                return $false
            }
        }
        Write-Log "IP '$IpAddress' is within CIDR '$Cidr'." "DEBUG"
        return $true
    } catch {
        Write-Log "Failed to validate if IP '$IpAddress' is in CIDR '$Cidr'. Error: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Helper function to validate network settings
function Test-NetworkSettings {
    param(
        [Parameter(Mandatory=$true)]
        $Config,
        [Parameter(Mandatory=$true)]
        $SubnetInfo
    )
    if ($Config.DefaultGateway) {
        try {
            $null = [System.Net.IPAddress]::Parse($Config.DefaultGateway)
            if (-not (Test-IpInCidr -IpAddress $Config.DefaultGateway -Cidr $SubnetInfo.CidrBlock)) {
                Write-Log "DefaultGateway '$($Config.DefaultGateway)' is not within the subnet CIDR '$($SubnetInfo.CidrBlock)'." "ERROR"
                return $false
            }
        } catch {
            Write-Log "Invalid DefaultGateway '$($Config.DefaultGateway)'. Must be a valid IP address. Error: $($_.Exception.Message)" "ERROR"
            return $false
        }
    }
    if ($Config.SubnetMask) {
        try {
            $null = [System.Net.IPAddress]::Parse($Config.SubnetMask)
        } catch {
            Write-Log "Invalid SubnetMask '$($Config.SubnetMask)'. Must be a valid IP address format (e.g., '255.255.255.0'). Error: $($_.Exception.Message)" "ERROR"
            return $false
        }
    }
    if ($Config.PrimaryDNS) {
        try {
            $null = [System.Net.IPAddress]::Parse($Config.PrimaryDNS)
        } catch {
            Write-Log "Invalid PrimaryDNS '$($Config.PrimaryDNS)'. Must be a valid IP address. Error: $($_.Exception.Message)" "ERROR"
            return $false
        }
    }
    if ($Config.SecondaryDNS) {
        try {
            $null = [System.Net.IPAddress]::Parse($Config.SecondaryDNS)
        } catch {
            Write-Log "Invalid SecondaryDNS '$($Config.SecondaryDNS)'. Must be a valid IP address. Error: $($_.Exception.Message)" "ERROR"
            return $false
        }
    }
    if ($Config.Domain) {
        if ($Config.Domain -notmatch '^[a-zA-Z0-9][a-zA-Z0-9\-\.]*[a-zA-Z0-9]$') {
            Write-Log "Invalid Domain '$($Config.Domain)'. Must be a valid domain name (e.g., 'example.local')." "ERROR"
            return $false
        }
    }
    return $true
}

# Function to validate SSO session and prompt for login if needed
function Test-SSOSession {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ProfileName,
        [Parameter(Mandatory=$true)]
        [string]$Region
    )
    if ($SkipPermissionValidation) {
        Write-Log "Skipping SSO session validation for profile: $ProfileName due to SkipPermissionValidation flag." "INFO"
        return $true
    }
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

# Function to parse AWS SSO profile from config file
function Get-AWSProfile {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ProfileName,
        [Parameter(Mandatory=$true)]
        [string]$AccountId,
        [Parameter(Mandatory=$true)]
        [string]$AccountName,
        [Parameter(Mandatory=$true)]
        [string]$SSORole,
        [Parameter(Mandatory=$true)]
        [string]$ConfigPath
    )
    $configLines = Get-Content -Path $ConfigPath -ErrorAction Stop
    $profileHeaderPattern = "^\[profile\s+$([regex]::Escape($ProfileName))\s*\]$"
    $profileLine = $configLines | Select-String -Pattern $profileHeaderPattern
    if (-not $profileLine) {
        Write-Log "Profile section not found in AWS config for: $ProfileName. Please ensure it exists in '$ConfigPath'." "ERROR"
        return $null
    }
    $profileStart = $profileLine.LineNumber
    $nextHeader = $configLines[($profileStart)..($configLines.Count-1)] | Select-String -Pattern "^\[(profile|sso-session)\s+"
    $profileEnd = if ($nextHeader) { $profileStart + $nextHeader[0].LineNumber - 2 } else { $configLines.Count - 1 }
    $profileBlock = $configLines[($profileStart - 1)..$profileEnd]
    $ssoStartUrl = ($profileBlock | Where-Object { $_ -match '^sso_start_url\s*=\s*(.+)$' }) -replace '^sso_start_url\s*=\s*', ''
    $region = ($profileBlock | Where-Object { $_ -match '^region\s*=\s*(.+)$' }) -replace '^region\s*=\s*', ''
    $ssoAccountId = ($profileBlock | Where-Object { $_ -match '^sso_account_id\s*=\s*(.+)$' }) -replace '^sso_account_id\s*=\s*', ''
    $ssoRoleName = ($profileBlock | Where-Object { $_ -match '^sso_role_name\s*=\s*(.+)$' }) -replace '^sso_role_name\s*=\s*', ''
    $ssoSession = ($profileBlock | Where-Object { $_ -match '^sso_session\s*=\s*(.+)$' }) -replace '^sso_session\s*=\s*', ''
    if (-not $ssoStartUrl -or -not $region -or -not $ssoAccountId -or -not $ssoRoleName -or -not $ssoSession) {
        Write-Log "Incomplete SSO profile configuration for: $ProfileName. Required fields: sso_start_url, region, sso_account_id, sso_role_name, sso_session." "ERROR"
        return $null
    }
    if ($ssoAccountId -ne $AccountId) {
        Write-Log "AccountId ($AccountId) in Excel does not match sso_account_id ($ssoAccountId) in profile: $ProfileName." "ERROR"
        return $null
    }
    if ($ssoRoleName -ne $SSORole) {
        Write-Log "SSORole ($SSORole) in Excel does not match sso_role_name ($ssoRoleName) in profile: $ProfileName." "ERROR"
        return $null
    }
    $validRegions = if ($DryRun) { @($region) } else { Get-AWSRegion -ErrorAction Stop | Select-Object -ExpandProperty Region }
    if ($region -notin $validRegions) {
        Write-Log "Region '$region' is not a valid AWS region for profile: $ProfileName. Valid regions: $($validRegions -join ', ')" "ERROR"
        return $null
    }
    return @{
        Region = $region
        SSOStartUrl = $ssoStartUrl
        SSOAccountId = $ssoAccountId
        SSORoleName = $ssoRoleName
        SSOSession = $ssoSession
    }
}

# Function to process tags
function Get-Tags {
    param(
        [string]$TagsRaw,
        [string]$Name,
        [string]$ResourceType
    )
    $tags = @()
    if ($TagsRaw) {
        Write-Log "Processing tags for $ResourceType '$Name': $TagsRaw" "DEBUG"
        $tagPairs = $TagsRaw -split ',' | ForEach-Object { $_.Trim() }
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
    if ($Name -and -not ($tags | Where-Object { $_.Key -eq 'Name' })) {
        $nameTag = New-Object Amazon.EC2.Model.Tag
        $nameTag.Key = 'Name'
        $nameTag.Value = $Name
        $tags += $nameTag
        Write-Log "Adding Name tag: Name=$Name" "DEBUG"
    }
    return $tags
}

# Function for EC2 preflight checks
function Invoke-EC2PreflightChecks {
    param(
        [Parameter(Mandatory=$true)]
        $Config,
        [Parameter(Mandatory=$true)]
        [string]$ScriptRoot,
        [Parameter(Mandatory=$false)]
        [array]$ValidInstanceTypes,
        [Parameter(Mandatory=$false)]
        [array]$SRIOVCompatibleTypes,
        [Parameter(Mandatory=$true)]
        [string]$ProfileName,
        [Parameter(Mandatory=$true)]
        [string]$Region
    )
    Write-Log "Running preflight checks for instance $($Config.InstanceName)..."
    if (-not $Config.InstanceName) {
        Write-Log "No InstanceName specified in the Excel file. This is a required field." "ERROR"
        return @{ Success = $false }
    }
    if ($Config.SubnetId) {
        if ($DryRun) {
            Write-Log "Dry run: Assuming subnet '$($Config.SubnetId)' exists with VpcId 'vpc-dryrun'." "INFO"
            $vpcId = "vpc-dryrun"
            $subnetInfo = [PSCustomObject]@{
                AvailableIpAddressCount = 10
                CidrBlock = "172.31.0.0/16"
                VpcId = "vpc-1234567890abcdef0"
                AvailabilityZone = $Config.AvailabilityZone
            }
        } else {
            try {
                $subnetInfo = Get-EC2Subnet -ProfileName $ProfileName -Region $Region -SubnetId $Config.SubnetId -ErrorAction Stop
                $vpcId = $subnetInfo.VpcId
                Write-Log "Subnet '$($Config.SubnetId)' found with VpcId '$vpcId'."
            } catch {
                Write-Log "Failed to retrieve VpcId for subnet '$($Config.SubnetId)'. Error: $($_.Exception.Message)" "ERROR"
                return @{ Success = $false }
            }
        }
        Write-Log "Checking for existing running instances with name '$($Config.InstanceName)' in VPC '$vpcId'..."
        if ($DryRun) {
            Write-Log "Dry run: Assuming no running instances with name '$($Config.InstanceName)' exist." "INFO"
        } else {
            try {
                $existingInstances = Get-EC2Instance -ProfileName $ProfileName -Region $Region -Filter @(
                    @{Name="tag:Name"; Values=$Config.InstanceName},
                    @{Name="vpc-id"; Values=$vpcId},
                    @{Name="instance-state-name"; Values="running"}
                ) -ErrorAction Stop
                if ($existingInstances.Instances.Count -gt 0) {
                    $instanceIds = $existingInstances.Instances | ForEach-Object { $_.InstanceId }
                    Write-Log "Found $($existingInstances.Instances.Count) running instance(s) with name '$($Config.InstanceName)' in VPC '$vpcId': $($instanceIds -join ', '). Cannot launch a new instance." "ERROR"
                    return @{ Success = $false }
                }
            } catch {
                Write-Log "Failed to check for existing instances with name '$($Config.InstanceName)'. Error: $($_.Exception.Message)" "ERROR"
                return @{ Success = $false }
            }
        }
        # Validate network settings against subnet
        if (-not (Test-NetworkSettings -Config $Config -SubnetInfo $subnetInfo)) {
            Write-Log "Network settings validation failed for instance $($Config.InstanceName)." "ERROR"
            return @{ Success = $false }
        }
    }
    $keyName = $Config.KeyName
    if ($keyName) {
        Write-Log "Checking for key pair '$keyName'..."
        $keyDir = Join-Path $ScriptRoot 'keys'
        $keyFilePath = Join-Path $keyDir "$keyName.pem"
        if (Test-Path $keyFilePath) {
            Write-Log "Local key file found: $keyFilePath"
            if ($DryRun) {
                Write-Log "Dry run: Assuming key pair '$keyName' exists in AWS." "INFO"
            } else {
                try {
                    Get-EC2KeyPair -ProfileName $ProfileName -Region $Region -KeyName $keyName -ErrorAction Stop > $null
                    Write-Log "Key pair '$keyName' confirmed to exist in AWS."
                } catch {
                    Write-Log "Local key file '$keyFilePath' exists, but key pair '$keyName' not found in AWS. Please resolve the mismatch." "ERROR"
                    return @{ Success = $false }
                }
            }
        } else {
            Write-Log "Local key file not found. Checking if key pair '$keyName' exists in AWS..."
            if ($DryRun) {
                Write-Log "Dry run: Assuming key pair '$keyName' does not exist and would be created." "INFO"
            } else {
                try {
                    $existingKeyPair = Get-EC2KeyPair -ProfileName $ProfileName -Region $Region -KeyName $keyName -ErrorAction Stop
                } catch { $existingKeyPair = $null }
                if ($existingKeyPair) {
                    Write-Log "Key pair '$keyName' exists in AWS, but local private key file is missing." "ERROR"
                    return @{ Success = $false }
                }
                Write-Log "Creating new key pair '$keyName'..."
                try {
                    if (-not (Test-Path $keyDir)) {
                        Write-Log "Creating key directory: $keyDir"
                        if (-not $DryRun) {
                            New-Item -ItemType Directory -Path $keyDir -ErrorAction Stop > $null
                        }
                    }
                    if (-not $DryRun) {
                        $newKeyPair = New-EC2KeyPair -ProfileName $ProfileName -Region $Region -KeyName $keyName -ErrorAction Stop
                        $newKeyPair.KeyMaterial | Out-File -FilePath $keyFilePath -Encoding ascii
                        Write-Log "Successfully created key pair '$keyName' and saved private key to '$keyFilePath'."
                    } else {
                        Write-Log "Dry run: Would create key pair '$keyName' and save private key to '$keyFilePath'." "INFO"
                    }
                } catch {
                    Write-Log "Failed to create key pair '$keyName'. Error: $($_.Exception.Message)" "ERROR"
                    return @{ Success = $false }
                }
            }
        }
    }
    $subnetId = $Config.SubnetId
    $privateIp = $Config.PrivateIpAddress
    if ($subnetId) {
        if ($DryRun) {
            Write-Log "Dry run: Assuming subnet '$subnetId' exists with sufficient IPs." "INFO"
            $subnetInfo = [PSCustomObject]@{
                AvailableIpAddressCount = 10
                CidrBlock = "172.31.0.0/16"
                VpcId = "vpc-1234567890abcdef0"
                AvailabilityZone = $Config.AvailabilityZone
            }
        } else {
            try {
                $subnetInfo = Get-EC2Subnet -ProfileName $ProfileName -Region $Region -SubnetId $subnetId -ErrorAction Stop
                Write-Log "Subnet '$subnetId' found. Available IPs: $($subnetInfo.AvailableIpAddressCount). CIDR: $($subnetInfo.CidrBlock)."
            } catch {
                Write-Log "Failed to validate subnet '$subnetId'. Error: $($_.Exception.Message)" "ERROR"
                return @{ Success = $false }
            }
        }
        if ($subnetInfo.AvailableIpAddressCount -eq 0) {
            Write-Log "Subnet '$subnetId' has no available IP addresses." "ERROR"
            return @{ Success = $false }
        }
        if ($privateIp) {
            Write-Log "Validating private IP '$privateIp'..."
            if (-not (Test-IpInCidr -IpAddress $privateIp -Cidr $subnetInfo.CidrBlock)) {
                Write-Log "IP '$privateIp' is not within the CIDR block '$($subnetInfo.CidrBlock)' of subnet '$subnetId'." "ERROR"
                return @{ Success = $false }
            }
            if (-not $DryRun) {
                $ipInUse = Get-EC2NetworkInterface -ProfileName $ProfileName -Region $Region -Filter @{Name="addresses.private-ip-address"; Values=$privateIp} -ErrorAction Stop
                if ($ipInUse) {
                    Write-Log "IP '$privateIp' is already in use in this VPC." "ERROR"
                    return @{ Success = $false }
                }
            }
        }
    }
    $securityGroupIdsRaw = $Config.SecurityGroupIds
    if ($subnetInfo -and $securityGroupIdsRaw) {
        $securityGroupIds = $securityGroupIdsRaw -split ',' | ForEach-Object { $_.Trim() }
        if ($securityGroupIds.Count -gt 0) {
            Write-Log "Validating security groups: $($securityGroupIds -join ', ')"
            if ($DryRun) {
                Write-Log "Dry run: Assuming security groups exist and are in the correct VPC." "INFO"
            } else {
                try {
                    $vpcId = $subnetInfo.VpcId
                    $sgs = Get-EC2SecurityGroup -ProfileName $ProfileName -Region $Region -GroupId $securityGroupIds -ErrorAction Stop
                    foreach ($sg in $sgs) {
                        if ($sg.VpcId -ne $vpcId) {
                            Write-Log "Security group '$($sg.GroupId)' (VPC: $($sg.VpcId)) is not in the same VPC as subnet (VPC: $vpcId)." "ERROR"
                            return @{ Success = $false }
                        }
                    }
                    Write-Log "All security groups are valid and in the correct VPC."
                } catch {
                    Write-Log "Failed to validate security groups. Error: $($_.Exception.Message)" "ERROR"
                    return @{ Success = $false }
                }
            }
        }
    }
    $iamProfileName = $Config.IamInstanceProfile
    if ($iamProfileName) {
        Write-Log "Checking IAM Instance Profile '$iamProfileName'..."
        if ($DryRun) {
            Write-Log "Dry run: Assuming IAM Instance Profile '$iamProfileName' exists." "INFO"
        } else {
            try {
                Get-IAMInstanceProfile -ProfileName $ProfileName -Region $Region -InstanceProfileName $iamProfileName -ErrorAction Stop > $null
                Write-Log "IAM Instance Profile '$iamProfileName' found."
            } catch {
                Write-Log "IAM Instance Profile '$iamProfileName' not found. Error: $($_.Exception.Message)" "ERROR"
                return @{ Success = $false }
            }
        }
    }
    $imageId = $Config.ImageId
    $rootDeviceName = $null
    if ($imageId) {
        Write-Log "Checking Image ID (AMI) '$imageId'..."
        if ($DryRun) {
            Write-Log "Dry run: Assuming AMI '$imageId' exists with root device name '/dev/xvda'." "INFO"
            $rootDeviceName = "/dev/xvda"
        } else {
            try {
                $ami = Get-EC2Image -ProfileName $ProfileName -Region $Region -ImageId $imageId -ErrorAction Stop
                $rootDeviceName = if ($ami[0].RootDeviceName) { $ami[0].RootDeviceName } else { "/dev/xvda" }
                Write-Log "Image ID '$imageId' found. Root device name: $rootDeviceName"
            } catch {
                Write-Log "Failed to retrieve AMI '$imageId'. Error: $($_.Exception.Message)" "ERROR"
                return @{ Success = $false }
            }
        }
    } else {
        Write-Log "No ImageId specified for instance $($Config.InstanceName). This is a required field." "ERROR"
        return @{ Success = $false }
    }
    $instanceType = $Config.InstanceType
    if ($instanceType) {
        if ($ValidInstanceTypes.Count -gt 0) {
            if ($instanceType -notin $ValidInstanceTypes) {
                Write-Log "Instance type '$instanceType' is not in the list of valid instance types." "ERROR"
                return @{ Success = $false }
            }
            Write-Log "Instance type '$instanceType' is valid."
        }
    } else {
        Write-Log "No InstanceType specified for instance $($Config.InstanceName). This is a required field." "ERROR"
        return @{ Success = $false }
    }
    if ($Config.SriovNetSupport) {
        Write-Log "Checking SR-IOV compatibility for instance type '$instanceType'..."
        if ($SRIOVCompatibleTypes.Count -gt 0 -and $instanceType -notin $SRIOVCompatibleTypes) {
            Write-Log "Instance type '$instanceType' does not support SR-IOV. Ignoring SriovNetSupport setting." "WARN"
            $Config.SriovNetSupport = $null
        } else {
            Write-Log "Instance type '$instanceType' supports SR-IOV."
        }
    }
    if ($null -ne $Config.AssociatePublicIpAddress) {
        $validValues = @('TRUE', 'FALSE')
        $normalizedValue = Convert-ToNormalizedString -Value $Config.AssociatePublicIpAddress
        if ($normalizedValue -notin $validValues) {
            Write-Log "Invalid AssociatePublicIpAddress value '$($Config.AssociatePublicIpAddress)'. Must be 'TRUE' or 'FALSE'. Defaulting to FALSE." "WARN"
            $Config.AssociatePublicIpAddress = 'FALSE'
        }
    }
    if ($Config.RootVolumeSize -or $Config.RootVolumeType) {
        if ($Config.RootVolumeSize) {
            try {
                $volumeSize = [int]$Config.RootVolumeSize
                if ($volumeSize -le 0) {
                    Write-Log "RootVolumeSize '$($Config.RootVolumeSize)' must be a positive integer." "ERROR"
                    return @{ Success = $false }
                }
            } catch {
                Write-Log "Invalid RootVolumeSize '$($Config.RootVolumeSize)'. Must be a positive integer. Error: $($_.Exception.Message)" "ERROR"
                return @{ Success = $false }
            }
        }
        if ($Config.RootVolumeType) {
            $validVolumeTypes = @('standard', 'gp2', 'gp3', 'io1', 'io2', 'sc1', 'st1')
            if ($Config.RootVolumeType -notin $validVolumeTypes) {
                Write-Log "Invalid RootVolumeType '$($Config.RootVolumeType)'. Must be one of: $($validVolumeTypes -join ', '). Defaulting to AMI's default." "WARN"
                $Config.RootVolumeType = $null
            }
        }
    }
    if ($null -ne $Config.Encrypted) {
        $normalizedEncrypted = Convert-ToNormalizedString -Value $Config.Encrypted
        if ($normalizedEncrypted -eq 'TRUE') {
            if ($Config.KmsKeyId) {
                if ($DryRun) {
                    Write-Log "Dry run: Assuming KMS key '$($Config.KmsKeyId)' is valid." "INFO"
                } else {
                    try {
                        Get-KMSKey -KeyId $Config.KmsKeyId -ProfileName $ProfileName -Region $Region -ErrorAction Stop > $null
                        Write-Log "KMS key '$($Config.KmsKeyId)' is valid."
                    } catch {
                        Write-Log "Invalid KmsKeyId '$($Config.KmsKeyId)'. Error: $($_.Exception.Message)" "ERROR"
                        return @{ Success = $false }
                    }
                }
            } else {
                Write-Log "Encrypted is 'TRUE', but no KmsKeyId specified. Using default KMS key." "WARN"
            }
        } elseif ($normalizedEncrypted -ne 'FALSE') {
            Write-Log "Invalid Encrypted value '$($Config.Encrypted)'. Must be 'TRUE' or 'FALSE'. Defaulting to FALSE." "WARN"
            $Config.Encrypted = 'FALSE'
        }
    }
    return @{ Success = $true; RootDeviceName = $rootDeviceName; SubnetInfo = $subnetInfo }
}

# Function for EBS preflight checks
function Invoke-EBSPreflightChecks {
    param(
        [Parameter(Mandatory=$true)]
        $Config,
        [Parameter(Mandatory=$true)]
        [string]$ProfileName,
        [Parameter(Mandatory=$true)]
        [string]$Region,
        [Parameter(Mandatory=$true)]
        [string]$InstanceAz
    )
    Write-Log "Running preflight checks for volume $($Config.VolumeName)..."
    if (-not $Config.Instance) {
        Write-Log "No Instance specified for volume $($Config.VolumeName). This is a required field." "ERROR"
        return @{ Success = $false }
    }
    if ($Config.AvailabilityZone -ne $InstanceAz) {
        Write-Log "Volume '$($Config.VolumeName)' is specified for AZ '$($Config.AvailabilityZone)', but instance is in AZ '$InstanceAz'. They must match." "ERROR"
        return @{ Success = $false }
    }
    if ($Config.Size) {
        try {
            $size = [int]$Config.Size
            if ($size -le 0) {
                Write-Log "Size '$($Config.Size)' for volume $($Config.VolumeName) must be a positive integer." "ERROR"
                return @{ Success = $false }
            }
        } catch {
            Write-Log "Invalid Size '$($Config.Size)' for volume $($Config.VolumeName). Must be a positive integer. Error: $($_.Exception.Message)" "ERROR"
            return @{ Success = $false }
        }
    } else {
        Write-Log "No Size specified for volume $($Config.VolumeName). This is a required field." "ERROR"
        return @{ Success = $false }
    }
    $validVolumeTypes = @('standard', 'gp2', 'gp3', 'io1', 'io2', 'sc1', 'st1')
    if ($Config.VolumeType) {
        if ($Config.VolumeType -notin $validVolumeTypes) {
            Write-Log "Invalid VolumeType '$($Config.VolumeType)' for volume $($Config.VolumeName). Must be one of: $($validVolumeTypes -join ', ')." "ERROR"
            return @{ Success = $false }
        }
    } else {
        Write-Log "No VolumeType specified for volume $($Config.VolumeName). Defaulting to 'gp2'." "WARN"
        $Config.VolumeType = 'gp2'
    }
    if ($Config.Iops) {
        try {
            $iops = [int]$Config.Iops
            if ($iops -le 0) {
                Write-Log "Iops '$($Config.Iops)' for volume $($Config.VolumeName) must be a positive integer." "ERROR"
                return @{ Success = $false }
            }
            if ($Config.VolumeType -in @('sc1', 'st1')) {
                Write-Log "Iops specified for volume $($Config.VolumeName), but VolumeType '$($Config.VolumeType)' does not support IOPS. Unsetting Iops." "WARN"
                $Config.Iops = $null
            } elseif ($Config.VolumeType -notin @('io1', 'io2', 'gp3')) {
                Write-Log "Iops specified, but VolumeType '$($Config.VolumeType)' does not support IOPS." "ERROR"
                return @{ Success = $false }
            }
        } catch {
            Write-Log "Invalid Iops '$($Config.Iops)' for volume $($Config.VolumeName). Must be a positive integer. Error: $($_.Exception.Message)" "ERROR"
            return @{ Success = $false }
        }
    }
    if ($Config.Throughput) {
        try {
            $throughput = [int]$Config.Throughput
            if ($throughput -le 0) {
                Write-Log "Throughput '$($Config.Throughput)' for volume $($Config.VolumeName) must be a positive integer." "ERROR"
                return @{ Success = $false }
            }
            if ($Config.VolumeType -in @('sc1', 'st1')) {
                Write-Log "Throughput specified for volume $($Config.VolumeName), but VolumeType '$($Config.VolumeType)' does not support throughput. Unsetting Throughput." "WARN"
                $Config.Throughput = $null
            } elseif ($Config.VolumeType -ne 'gp3') {
                Write-Log "Throughput specified, but VolumeType '$($Config.VolumeType)' does not support throughput." "ERROR"
                return @{ Success = $false }
            }
        } catch {
            Write-Log "Invalid Throughput '$($Config.Throughput)' for volume $($Config.VolumeName). Must be a positive integer. Error: $($_.Exception.Message)" "ERROR"
            return $false
        }
    }
    if ($null -ne $Config.Encrypted) {
        $normalizedEncrypted = Convert-ToNormalizedString -Value $Config.Encrypted
        if ($normalizedEncrypted -eq 'TRUE') {
            if ($Config.KmsKeyId) {
                if ($DryRun) {
                    Write-Log "Dry run: Assuming KMS key '$($Config.KmsKeyId)' is valid." "INFO"
                } else {
                    try {
                        Get-KMSKey -KeyId $Config.KmsKeyId -ProfileName $ProfileName -Region $Region -ErrorAction Stop > $null
                        Write-Log "KMS key '$($Config.KmsKeyId)' is valid."
                    } catch {
                        Write-Log "Invalid KmsKeyId '$($Config.KmsKeyId)'. Error: $($_.Exception.Message)" "ERROR"
                        return @{ Success = $false }
                    }
                }
            } else {
                Write-Log "Encrypted is 'TRUE', but no KmsKeyId specified. Using default KMS key." "WARN"
            }
        } elseif ($normalizedEncrypted -ne 'FALSE') {
            Write-Log "Invalid Encrypted value '$($Config.Encrypted)'. Must be 'TRUE' or 'FALSE'. Defaulting to FALSE." "WARN"
            $Config.Encrypted = 'FALSE'
        }
    }
    if ($Config.SnapshotId) {
        if ($DryRun) {
            Write-Log "Dry run: Assuming SnapshotId '$($Config.SnapshotId)' is valid." "INFO"
        } else {
            try {
                Get-EC2Snapshot -SnapshotId $Config.SnapshotId -ProfileName $ProfileName -Region $Region -ErrorAction Stop > $null
                Write-Log "SnapshotId '$($Config.SnapshotId)' is valid."
            } catch {
                Write-Log "Invalid SnapshotId '$($Config.SnapshotId)'. Error: $($_.Exception.Message)" "ERROR"
                return @{ Success = $false }
            }
        }
    }
    if ($null -ne $Config.MultiAttachEnabled) {
        $normalizedMultiAttach = Convert-ToNormalizedString -Value $Config.MultiAttachEnabled
        if ($normalizedMultiAttach -eq 'TRUE') {
            if ($Config.VolumeType -notin @('io1', 'io2')) {
                Write-Log "MultiAttachEnabled is 'TRUE', but VolumeType '$($Config.VolumeType)' does not support multi-attach." "ERROR"
                return @{ Success = $false }
            }
        } elseif ($normalizedMultiAttach -ne 'FALSE') {
            Write-Log "Invalid MultiAttachEnabled value '$($Config.MultiAttachEnabled)'. Must be 'TRUE' or 'FALSE'. Defaulting to FALSE." "WARN"
            $Config.MultiAttachEnabled = 'FALSE'
        }
    }
    if ($Config.VolumeMount) {
        $volumeMount = [string]$Config.VolumeMount
        if ($volumeMount -notmatch '^[A-Z]:$') {
            Write-Log "Invalid VolumeMount '$volumeMount'. Must be a valid Windows drive letter followed by a colon (e.g., 'D:')." "ERROR"
            return @{ Success = $false }
        }
    } else {
        Write-Log "No VolumeMount specified for volume $($Config.VolumeName). Defaulting to 'F:'." "WARN"
        $Config.VolumeMount = 'F:'
    }
    return @{ Success = $true }
}

# Function to update Excel file
function Update-ExcelFile {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ExcelFilePath,
        [Parameter(Mandatory=$true)]
        [string]$WorksheetName,
        [Parameter(Mandatory=$true)]
        [string]$NameColumn,
        [Parameter(Mandatory=$true)]
        [string]$NameValue,
        [Parameter(Mandatory=$true)]
        [string]$IdColumn,
        [Parameter(Mandatory=$true)]
        [string]$IdValue
    )
    try {
        Write-Log "Updating $IdColumn '$IdValue' for $NameColumn '$NameValue' in Excel file '$ExcelFilePath' worksheet '$WorksheetName'"
        $excelPackage = Open-ExcelPackage -Path $ExcelFilePath -ErrorAction Stop
        $worksheet = $excelPackage.Workbook.Worksheets[$WorksheetName]
        if (-not $worksheet) {
            throw "Worksheet '$WorksheetName' not found in Excel file"
        }
        $headers = @{}
        for ($col = 1; $col -le $worksheet.Dimension.Columns; $col++) {
            $header = $worksheet.Cells[1, $col].Value
            if ($header) {
                $headers[$header] = $col
            }
        }
        if (-not $headers.ContainsKey($NameColumn)) {
            throw "$NameColumn column not found in worksheet '$WorksheetName'"
        }
        if (-not $headers.ContainsKey($IdColumn)) {
            Write-Log "$IdColumn column not found. Adding it." "WARN"
            $newCol = $worksheet.Dimension.Columns + 1
            $worksheet.Cells[1, $newCol].Value = $IdColumn
            $headers[$IdColumn] = $newCol
        }
        $rowFound = $false
        for ($row = 2; $row -le $worksheet.Dimension.Rows; $row++) {
            if ($worksheet.Cells[$row, $headers[$NameColumn]].Value -eq $NameValue) {
                if ($DryRun) {
                    Write-Log "Dry run: Would update row $row, column $IdColumn with value '$IdValue'" "INFO"
                } else {
                    $worksheet.Cells[$row, $headers[$IdColumn]].Value = $IdValue
                    Write-Log "Updated row $row, column $IdColumn with value '$IdValue'" "DEBUG"
                }
                $rowFound = $true
                break
            }
        }
        if (-not $rowFound) {
            Write-Log "No row found with $NameColumn '$NameValue' in worksheet '$WorksheetName'" "ERROR"
        }
        if (-not $DryRun) {
            Close-ExcelPackage -ExcelPackage $excelPackage -ErrorAction Stop
            $excelPackageVerify = Open-ExcelPackage -Path $ExcelFilePath -ErrorAction Stop
            $worksheetVerify = $excelPackageVerify.Workbook.Worksheets[$WorksheetName]
            $verified = $false
            for ($row = 2; $row -le $worksheetVerify.Dimension.Rows; $row++) {
                if ($worksheetVerify.Cells[$row, $headers[$NameColumn]].Value -eq $NameValue -and 
                    $worksheetVerify.Cells[$row, $headers[$IdColumn]].Value -eq $IdValue) {
                    $verified = $true
                    break
                }
            }
            Close-ExcelPackage -ExcelPackage $excelPackageVerify -ErrorAction Stop
            if ($verified) {
                Write-Log "Successfully updated and verified Excel file with $IdColumn '$IdValue' for $NameColumn '$NameValue'" "INFO"
            } else {
                Write-Log "Failed to verify $IdColumn '$IdValue' for $NameColumn '$NameValue' after save" "ERROR"
            }
        }
        return $rowFound
    } catch {
        Write-Log "Failed to update Excel file with $IdColumn '$IdValue' for $NameColumn '$NameValue'. Error: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Function to generate and upload Config.json
function New-InstanceConfig {
    param(
        [Parameter(Mandatory=$true)]
        $Config,
        [Parameter(Mandatory=$true)]
        [array]$EbsConfigs,
        [Parameter(Mandatory=$true)]
        [string]$S3BucketName,
        [Parameter(Mandatory=$true)]
        [string]$S3BucketKeyPrefix,
        [Parameter(Mandatory=$true)]
        [string]$ProfileName,
        [Parameter(Mandatory=$true)]
        [string]$Region
    )
    $instanceName = $Config.InstanceName
    $configJson = @{
        ComputerName = $instanceName
        IPAddress = $Config.PrivateIpAddress
        Gateway = $Config.DefaultGateway
        SubnetMask = $Config.SubnetMask
        DNS = @()
        Domain = $Config.Domain
        OU = $null
        SQLInstall = $false
        Volumes = @()
    }
    if ($Config.PrimaryDNS) { $configJson.DNS += $Config.PrimaryDNS }
    if ($Config.SecondaryDNS) { $configJson.DNS += $Config.SecondaryDNS }

    # Add EBS volume details
    $associatedEbsConfigs = $EbsConfigs | Where-Object { $_.Instance -eq $instanceName }
    foreach ($ebsConfig in $associatedEbsConfigs) {
        $volumeConfig = @{
            VolumeName = $ebsConfig.VolumeName
            VolumeMount = $ebsConfig.VolumeMount
            VolumeLabel = $ebsConfig.VolumeLabel
            PartitionStyle = $ebsConfig.PartitionStyle
            FileSystem = $ebsConfig.FileSystem
            AllocationUnitSize = $ebsConfig.AllocationUnitSize
        }
        $configJson.Volumes += $volumeConfig
        Write-Log "Added volume configuration for $($ebsConfig.VolumeName): $(ConvertTo-Json -InputObject $volumeConfig -Depth 5 -Compress)" "DEBUG"
    }

    $tempConfigPath = Join-Path $PSScriptRoot "Config-$instanceName.json"
    try {
        $configJson | ConvertTo-Json -Depth 5 | Set-Content -Path $tempConfigPath -Force
        Write-Log "Generated Config.json for instance $instanceName at $tempConfigPath"
        if (-not $DryRun) {
            $s3Key = "$S3BucketKeyPrefix/$instanceName/Config.json"
            Write-S3Object -BucketName $S3BucketName -Key $s3Key -File $tempConfigPath -ProfileName $ProfileName -Region $Region -ErrorAction Stop
            Write-Log "Uploaded Config.json to s3://$S3BucketName/$s3Key"
        } else {
            Write-Log "Dry run: Would upload Config.json to s3://$S3BucketName/$S3BucketKeyPrefix/$instanceName/Config.json" "INFO"
        }
        return $true
    } catch {
        Write-Log "Failed to generate or upload Config.json for instance $instanceName. Error: $($_.Exception.Message)" "ERROR"
        return $false
    } finally {
        if (Test-Path $tempConfigPath) {
            Remove-Item $tempConfigPath -Force
            Write-Log "Cleaned up temporary Config.json file: $tempConfigPath"
        }
    }
}
####################################
# Main script execution starts here
####################################

try {
    # Ensure log directory exists
    $logDir = Split-Path -Path $LogFilePath -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -ErrorAction Stop > $null
        Write-Log "Created log directory: $logDir"
    }

    # Import required modules
    try {
        Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.Common") -ErrorAction Stop
        Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.EC2") -ErrorAction Stop
        Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.IdentityManagement") -ErrorAction Stop
        Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.KeyManagementService") -ErrorAction Stop
        Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.SecurityToken") -ErrorAction Stop
        Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.S3") -ErrorAction Stop
        Import-Module -Name (Join-Path $PSModulesPath "ImportExcel") -ErrorAction Stop
        Write-Log "Successfully imported AWS.Tools modules and ImportExcel" "INFO"
    } catch {
        Write-Log "Failed to import modules from $PSModulesPath. Error: $($_.Exception.Message)" "ERROR"
        exit 1
    }

    Write-Log "Starting AWS resource management script (DryRun: $DryRun, SkipPermissionValidation: $SkipPermissionValidation, EnableUserData: $EnableUserData, S3BucketName: $S3BucketName, S3BucketKeyPrefix: $S3BucketKeyPrefix)"

    # Read Excel file
    Write-Log "Reading Excel file: $ExcelFilePath"
    if (-not (Test-Path $ExcelFilePath)) {
        throw "Excel file not found: $ExcelFilePath"
    }
    $ec2Configs = Import-Excel -Path $ExcelFilePath -WorksheetName "EC2_Instances" -ErrorAction Stop
    $ebsConfigs = Import-Excel -Path $ExcelFilePath -WorksheetName "EBS_Volumes" -ErrorAction Stop
    if ($ec2Configs.Count -eq 0) {
        throw "No EC2 configurations found in Excel file"
    }
    Write-Log "Found $($ec2Configs.Count) EC2 configurations and $($ebsConfigs.Count) EBS volume configurations in Excel"

    # Load valid instance types and SR-IOV compatible types
    $configJsonPath = Join-Path $PSScriptRoot "ec2-config-validation.json"
    $validInstanceTypes = @()
    $sriovCompatibleTypes = @()
    if (Test-Path $configJsonPath) {
        try {
            $configJson = Get-Content -Path $configJsonPath -Raw | ConvertFrom-Json
            $validInstanceTypes = $configJson.validInstanceTypes
            $sriovCompatibleTypes = $configJson.SRIOVCompatibleTypes
            Write-Log "Loaded $($validInstanceTypes.Count) valid instance types and $($sriovCompatibleTypes.Count) SR-IOV compatible types from $configJsonPath"
        } catch {
            Write-Log "Failed to read ec2-config-validation.json. Instance type and SR-IOV validation will be skipped. Error: $($_.Exception.Message)" "WARN"
        }
    }

    # Validate AWS config file
    $awsConfigPath = "$env:USERPROFILE\.aws\config"
    if (-not (Test-Path $awsConfigPath)) {
        throw "AWS config file not found: $awsConfigPath"
    }

    # Process each EC2 configuration
    foreach ($config in $ec2Configs) {
        try {
            $accountId = $config.AccountId
            $accountName = $config.AccountName
            $ssoRole = $config.SSORole
            $instanceName = $config.InstanceName
            $cleanAccountName = $accountName -replace '[^\w\-]', ''
            $cleanSsoRole = $ssoRole -replace '[^\w\-]', ''
            $profileName = "sso-$cleanAccountName-$cleanSsoRole"
            Write-Log "Processing EC2 configuration for Account: $accountId ($accountName), Instance: $instanceName, Profile: $profileName"

            # Get and validate AWS profile
            $awsprofile = Get-AWSProfile -ProfileName $profileName -AccountId $accountId -AccountName $accountName -SSORole $ssoRole -ConfigPath $awsConfigPath
            if (-not $awsprofile) {
                Write-Log "Skipping instance $instanceName due to invalid profile configuration." "ERROR"
                continue
            }
            $region = $awsprofile.Region

            # Set AWS credentials
            if (-not $DryRun) {
                Set-AWSCredential -ProfileName $profileName -ErrorAction Stop
                if (-not (Test-SSOSession -ProfileName $profileName -Region $region)) {
                    Write-Log "Skipping instance $instanceName due to invalid SSO session." "ERROR"
                    continue
                }
                Set-DefaultAWSRegion -Region $region -ErrorAction Stop
            }

            # Run EC2 preflight checks
            $ec2PreflightResult = Invoke-EC2PreflightChecks -Config $config -ScriptRoot $PSScriptRoot -ValidInstanceTypes $validInstanceTypes -SRIOVCompatibleTypes $sriovCompatibleTypes -ProfileName $profileName -Region $region
            if (-not $ec2PreflightResult.Success) {
                Write-Log "EC2 preflight checks failed for instance $instanceName. Skipping." "ERROR"
                continue
            }
            $rootDeviceName = $ec2PreflightResult.RootDeviceName
            $subnetInfo = $ec2PreflightResult.SubnetInfo

            # Generate and upload Config.json if EnableUserData is true
            if ($EnableUserData) {
                if (-not (New-InstanceConfig -Config $config -EbsConfigs $ebsConfigs -S3BucketName $S3BucketName -S3BucketKeyPrefix $S3BucketKeyPrefix -ProfileName $profileName -Region $region)) {
                    Write-Log "Failed to generate or upload Config.json for instance $instanceName. Skipping." "ERROR"
                    continue
                }
            } else {
                Write-Log "EnableUserData is false. Skipping Config.json generation and upload for instance $instanceName." "INFO"
            }

            # Process associated EBS volumes
            $associatedEbsConfigs = $ebsConfigs | Where-Object { $_.Instance -eq $instanceName }
            $volumeIds = @()
            if ($associatedEbsConfigs.Count -eq 0) {
                Write-Log "No EBS volumes associated with instance $instanceName." "INFO"
            } else {
                Write-Log "Found $($associatedEbsConfigs.Count) EBS volume(s) associated with instance $instanceName."
                foreach ($ebsConfig in $associatedEbsConfigs) {
                    try {
                        $volumeName = $ebsConfig.VolumeName
                        Write-Log "Processing EBS volume $volumeName for instance $instanceName"

                        # Run EBS preflight checks
                        $ebsPreflightResult = Invoke-EBSPreflightChecks -Config $ebsConfig -ProfileName $profileName -Region $region -InstanceAz $subnetInfo.AvailabilityZone
                        if (-not $ebsPreflightResult.Success) {
                            Write-Log "EBS preflight checks failed for volume $volumeName. Skipping." "ERROR"
                            continue
                        }

                        # Prepare EBS volume parameters
                        $volumeParams = @{
                            AvailabilityZone = $ebsConfig.AvailabilityZone
                            Size = [int]$ebsConfig.Size
                            VolumeType = $ebsConfig.VolumeType
                        }
                        if ($ebsConfig.Iops) { $volumeParams.Iops = [int]$ebsConfig.Iops }
                        if ($ebsConfig.Throughput) { $volumeParams.Throughput = [int]$ebsConfig.Throughput }
                        $normalizedEncrypted = Convert-ToNormalizedString -Value $ebsConfig.Encrypted
                        if ($normalizedEncrypted -eq 'TRUE') { $volumeParams.Encrypted = $true }
                        if ($ebsConfig.KmsKeyId) { $volumeParams.KmsKeyId = $ebsConfig.KmsKeyId }
                        if ($ebsConfig.SnapshotId) { $volumeParams.SnapshotId = $ebsConfig.SnapshotId }
                        $normalizedMultiAttach = Convert-ToNormalizedString -Value $ebsConfig.MultiAttachEnabled
                        if ($normalizedMultiAttach -eq 'TRUE') { $volumeParams.MultiAttachEnabled = $true }

                        # Use EC2 tags for EBS volume
                        $ebsTags = Get-Tags -TagsRaw $config.Tags -Name $volumeName -ResourceType "volume"

                        # Create EBS volume
                        Write-Log "Creating EBS volume $volumeName in Account: $accountId ($accountName), Region: $region"
                        if ($DryRun) {
                            Write-Log "Dry run: Would create EBS volume with parameters: $(ConvertTo-Json -InputObject $volumeParams -Depth 5 -Compress)" "INFO"
                            Write-Log "Dry run: Would apply tags: $(ConvertTo-Json -InputObject $ebsTags -Depth 5 -Compress)" "INFO"
                            $volumeId = "vol-dryrun-$(Get-Random -Minimum 1000000000 -Maximum 9999999999)"
                            Write-Log "Dry run: Simulated EBS volume creation with VolumeId: $volumeId" "INFO"
                        } else {
                            $volume = New-EC2Volume @volumeParams -ProfileName $profileName -Region $region -ErrorAction Stop
                            $volumeId = $volume.VolumeId
                            Write-Log "Successfully created EBS volume: $volumeId"
                            if ($ebsTags.Count -gt 0) {
                                New-EC2Tag -Resource $volumeId -Tag $ebsTags -ProfileName $profileName -Region $region -ErrorAction Stop
                                Write-Log "Applied $($ebsTags.Count) tags to volume $volumeId"
                            }
                            # Wait for volume to be available
                            $timeout = 300
                            $startTime = Get-Date
                            do {
                                Start-Sleep -Seconds 5
                                $volumeState = (Get-EC2Volume -VolumeId $volumeId -ProfileName $profileName -Region $region -ErrorAction Stop).State
                                if ((New-TimeSpan -Start $startTime -End (Get-Date)).TotalSeconds -gt $timeout) {
                                    throw "Timeout waiting for volume $volumeId to become available."
                                }
                            } until ($volumeState -eq 'available')
                            Write-Log "Volume $volumeId is now available."
                        }
                        # Store volume ID and config for later attachment
                        $volumeEntry = [Hashtable]@{ 'VolumeId' = $volumeId; 'Config' = $ebsConfig }
                        $volumeIds += $volumeEntry
                        Write-Log "Added volume entry to VolumeIds: $(ConvertTo-Json -InputObject $volumeEntry -Depth 5 -Compress)" "DEBUG"

                        # Update Excel with VolumeId
                        $excelUpdated = Update-ExcelFile -ExcelFilePath $ExcelFilePath -WorksheetName "EBS_Volumes" -NameColumn "VolumeName" -NameValue $volumeName -IdColumn "VolumeId" -IdValue $volumeId
                        if (-not $excelUpdated) {
                            Write-Log "Failed to update Excel file with VolumeId for volume $volumeName." "WARN"
                        }
                    } catch {
                        Write-Log "Error processing EBS volume $volumeName for instance $instanceName. Error: $($_.Exception.Message)" "ERROR"
                        continue
                    }
                }
            }

            # Prepare EC2 launch parameters
            $launchParams = @{
                ImageId = $config.ImageId
                InstanceType = $config.InstanceType
                MinCount = 1
                MaxCount = 1
            }
            if ($config.KeyName) { $launchParams.KeyName = $config.KeyName }
            if ($config.SubnetId) {
                $networkInterface = New-Object Amazon.EC2.Model.InstanceNetworkInterfaceSpecification
                $networkInterface.DeviceIndex = 0
                $networkInterface.SubnetId = $config.SubnetId
                if ($config.PrivateIpAddress) { $networkInterface.PrivateIpAddress = $config.PrivateIpAddress }
                $normalizedAssociatePublicIp = Convert-ToNormalizedString -Value $config.AssociatePublicIpAddress
                if ($normalizedAssociatePublicIp -eq 'TRUE') {
                    $networkInterface.AssociatePublicIpAddress = $true
                    Write-Log "Setting AssociatePublicIpAddress to true for instance $instanceName" "DEBUG"
                } elseif ($normalizedAssociatePublicIp -eq 'FALSE') {
                    $networkInterface.AssociatePublicIpAddress = $false
                    Write-Log "Setting AssociatePublicIpAddress to false for instance $instanceName" "DEBUG"
                } else {
                    Write-Log "No valid AssociatePublicIpAddress specified for instance $instanceName. Defaulting to subnet's MapPublicIpOnLaunch setting." "WARN"
                }
                if ($config.SecurityGroupIds) { $networkInterface.Groups = $config.SecurityGroupIds -split ',' | ForEach-Object { $_.Trim() } }
                $launchParams.NetworkInterface = @($networkInterface)
            }
            if ($config.IamInstanceProfile) { $launchParams.IamInstanceProfile_Name = $config.IamInstanceProfile }
            if ($config.EbsOptimized -eq 'true') { $launchParams.EbsOptimized = $true }
            if ($config.SriovNetSupport -eq 'true') {
                $sriovSpec = New-Object Amazon.EC2.Model.InstanceEnaSrdSpec
                $sriovSpec.EnaSupport = $true
                $sriovSpec.SrdSupport = $true
                $launchParams.EnaSrdSpecification = $sriovSpec
            }
            $blockDeviceMappings = @()
            if ($config.RootVolumeSize -or $config.RootVolumeType -or $config.Encrypted) {
                $blockDeviceMapping = New-Object Amazon.EC2.Model.BlockDeviceMapping
                $ebs = New-Object Amazon.EC2.Model.EbsBlockDevice
                if ($config.RootVolumeSize) { $ebs.VolumeSize = [int]$config.RootVolumeSize }
                if ($config.RootVolumeType) { $ebs.VolumeType = $config.RootVolumeType }
                $normalizedEncrypted = Convert-ToNormalizedString -Value $config.Encrypted
                if ($normalizedEncrypted -eq 'TRUE') {
                    $ebs.Encrypted = $true
                    if ($config.KmsKeyId) { $ebs.KmsKeyId = $config.KmsKeyId }
                }
                $ebs.DeleteOnTermination = $true
                $blockDeviceMapping.DeviceName = $rootDeviceName
                $blockDeviceMapping.Ebs = $ebs
                $blockDeviceMappings += $blockDeviceMapping
            }
            if ($blockDeviceMappings.Count -gt 0) {
                $launchParams.BlockDeviceMapping = $blockDeviceMappings
            }

            # Generate UserData script if EnableUserData is true
            if ($EnableUserData) {
                $userDataScript = @"
<powershell>
`$bucketName = "$S3BucketName"
`$keyPrefix = "$S3BucketKeyPrefix"
`$hostname = (Invoke-RestMethod -Uri http://169.254.169.254/latest/meta-data/local-hostname).Split(".")[0]
`$bootstrapRoot = "C:\\Fujitsu\\Bootstrap"
`$configKey = "`$keyPrefix/`$hostname/config.json"
`$bootstrapZipKey = "`$keyPrefix/bootstrap.zip"

New-Item -ItemType Directory -Path `$bootstrapRoot -Force | Out-Null

Read-S3Object -BucketName `$bucketName -Key `$configKey -File "`$bootstrapRoot\\`$hostname-config.json"
Read-S3Object -BucketName `$bucketName -Key `$bootstrapZipKey -File "`$bootstrapRoot\\bootstrap.zip"
Expand-Archive -Path "`$bootstrapRoot\\bootstrap.zip" -DestinationPath `$bootstrapRoot -Force

& "`$bootstrapRoot\\Bootstrap.ps1"
</powershell>
"@
                $userDataBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($userDataScript))
                $launchParams.UserData = $userDataBase64
                Write-Log "Generated and encoded UserData script for instance $instanceName" "INFO"
            } else {
                Write-Log "EnableUserData is false. Skipping UserData generation for instance $instanceName." "INFO"
            }

            # Process instance tags
            $instanceTags = Get-Tags -TagsRaw $config.Tags -Name $instanceName -ResourceType "instance"

            # Display instance and volume details for confirmation
            Write-Log "EC2 Instance Configuration for '$instanceName' in Account: $accountId ($accountName), Region: $region" "INFO"
            Write-Log "Instance Parameters:" "INFO"
            Write-Log "  InstanceName: $instanceName" "INFO"
            Write-Log "  ImageId: $($launchParams.ImageId)" "INFO"
            Write-Log "  InstanceType: $($launchParams.InstanceType)" "INFO"
            Write-Log "  SubnetId: $($config.SubnetId ? $config.SubnetId : 'Not specified')" "INFO"
            Write-Log "  PrivateIpAddress: $($config.PrivateIpAddress ? $config.PrivateIpAddress : 'Not specified')" "INFO"
            Write-Log "  AssociatePublicIpAddress: $($normalizedAssociatePublicIp ? $normalizedAssociatePublicIp : 'Not specified, using subnet default')" "INFO"
            Write-Log "  SecurityGroupIds: $($config.SecurityGroupIds ? ($config.SecurityGroupIds -split ',' | ForEach-Object { $_.Trim() } | Join-String -Separator ', ') : 'Not specified')" "INFO"
            Write-Log "  IamInstanceProfile: $($config.IamInstanceProfile ? $config.IamInstanceProfile : 'Not specified')" "INFO"
            Write-Log "  KeyName: $($config.KeyName ? $config.KeyName : 'Not specified')" "INFO"
            Write-Log "  EbsOptimized: $($config.EbsOptimized ? $config.EbsOptimized : 'Not specified')" "INFO"
            Write-Log "  SriovNetSupport: $($config.SriovNetSupport ? $config.SriovNetSupport : 'Not specified')" "INFO"
            Write-Log "  Root Volume Settings:" "INFO"
            Write-Log "    DeviceName: $rootDeviceName" "INFO"
            Write-Log "    VolumeSize: $($config.RootVolumeSize ? $config.RootVolumeSize : 'Default')" "INFO"
            Write-Log "    VolumeType: $($config.RootVolumeType ? $config.RootVolumeType : 'Default')" "INFO"
            Write-Log "    Encrypted: $($normalizedEncrypted ? $normalizedEncrypted : 'FALSE')" "INFO"
            if ($normalizedEncrypted -eq 'TRUE' -and $config.KmsKeyId) {
                Write-Log "    KmsKeyId: $($config.KmsKeyId)" "INFO"
            }
            Write-Log "  Bootstrap Settings:" "INFO"
            Write-Log "  UserData Enabled: $EnableUserData" "INFO"
            if ($EnableUserData) {
                Write-Log "  Domain: $($config.Domain ? $config.Domain : 'Not specified')" "INFO"
                Write-Log "  DefaultGateway: $($config.DefaultGateway ? $config.DefaultGateway : 'Not specified')" "INFO"
                Write-Log "  SubnetMask: $($config.SubnetMask ? $config.SubnetMask : 'Not specified')" "INFO"
                Write-Log "  PrimaryDNS: $($config.PrimaryDNS ? $config.PrimaryDNS : 'Not specified')" "INFO"
                Write-Log "  SecondaryDNS: $($config.SecondaryDNS ? $config.SecondaryDNS : 'Not specified')" "INFO"
            }
            Write-Log "  Tags: $($instanceTags.Count -gt 0 ? ($instanceTags | ForEach-Object { "$($_.Key)=$($_.Value)" } | Join-String -Separator ', ') : 'None')" "INFO"
            Write-Log "Associated EBS Volumes:" "INFO"
            if ($volumeIds.Count -eq 0) {
                Write-Log "  None" "INFO"
            } else {
                foreach ($volume in $volumeIds) {
                    $volConfig = $volume.Config
                    $volId = $volume.VolumeId
                    Write-Log "  Volume: $($volConfig.VolumeName)" "INFO"
                    Write-Log "    VolumeId: $volId" "INFO"
                    Write-Log "    AvailabilityZone: $($volConfig.AvailabilityZone)" "INFO"
                    Write-Log "    Size: $($volConfig.Size) GiB" "INFO"
                    Write-Log "    VolumeType: $($volConfig.VolumeType)" "INFO"
                    if ($volConfig.Iops) { Write-Log "    Iops: $($volConfig.Iops)" "INFO" }
                    if ($volConfig.Throughput) { Write-Log "    Throughput: $($volConfig.Throughput) MiB/s" "INFO" }
                    $volNormalizedEncrypted = Convert-ToNormalizedString -Value $volConfig.Encrypted
                    Write-Log "    Encrypted: $($volNormalizedEncrypted ? $volNormalizedEncrypted : 'FALSE')" "INFO"
                    if ($volNormalizedEncrypted -eq 'TRUE' -and $volConfig.KmsKeyId) { Write-Log "    KmsKeyId: $($volConfig.KmsKeyId)" "INFO" }
                    Write-Log "    SnapshotId: $($volConfig.SnapshotId ? $volConfig.SnapshotId : 'Not specified')" "INFO"
                    $volNormalizedMultiAttach = Convert-ToNormalizedString -Value $volConfig.MultiAttachEnabled
                    Write-Log "    MultiAttachEnabled: $($volNormalizedMultiAttach ? $volNormalizedMultiAttach : 'FALSE')" "INFO"
                    Write-Log "    VolumeMount: $($volConfig.VolumeMount ? $volConfig.VolumeMount : 'Not specified')" "INFO"
                    Write-Log "    VolumeLabel: $($volConfig.VolumeLabel ? $volConfig.VolumeLabel : 'Not specified')" "INFO"
                    Write-Log "    PartitionStyle: $($volConfig.PartitionStyle ? $volConfig.PartitionStyle : 'Not specified')" "INFO"
                    Write-Log "    FileSystem: $($volConfig.FileSystem ? $volConfig.FileSystem : 'Not specified')" "INFO"
                    Write-Log "    AllocationUnitSize: $($volConfig.AllocationUnitSize ? $volConfig.AllocationUnitSize : 'Not specified')" "INFO"
                }
            }

            # Prompt for confirmation
            Write-Log "Do you want to proceed with creating instance '$instanceName' and its associated volumes? [Y/N]" "INFO"
            if ($DryRun) {
                Write-Log "Dry run: Assuming user confirms with 'Y'." "INFO"
                $response = 'Y'
            } else {
                $response = Read-Host "Enter Y to proceed or N to skip"
            }
            if ($response -ne 'Y' -and $response -ne 'y') {
                Write-Log "User chose to skip instance $instanceName." "INFO"
                continue
            }

            # Launch EC2 instance
            Write-Log "Launching EC2 instance $instanceName in Account: $accountId ($accountName), Region: $region"
            if ($DryRun) {
                Write-Log "Dry run: Would launch EC2 instance with parameters: $(ConvertTo-Json -InputObject $launchParams -Depth 5 -Compress)" "INFO"
                Write-Log "Dry run: Would apply tags: $(ConvertTo-Json -InputObject $instanceTags -Depth 5 -Compress)" "INFO"
                $instanceId = "i-dryrun-$(Get-Random -Minimum 1000000000 -Maximum 9999999999)"
                Write-Log "Dry run: Simulated EC2 instance creation with InstanceId: $instanceId" "INFO"
            } else {
                try {
                    $reservation = New-EC2Instance @launchParams -ProfileName $profileName -Region $region -ErrorAction Stop
                    $instanceId = $reservation.Instances[0].InstanceId
                    Write-Log "Successfully launched EC2 instance: $instanceId"
                    if ($instanceTags.Count -gt 0) {
                        New-EC2Tag -Resource $instanceId -Tag $instanceTags -ProfileName $profileName -Region $region -ErrorAction Stop
                        Write-Log "Applied $($instanceTags.Count) tags to instance $instanceId"
                    }
                } catch {
                    Write-Log "Failed to launch EC2 instance $instanceName. Error: $($_.Exception.Message)" "ERROR"
                    continue
                }

                # Wait for instance to be running
                Write-Log "Waiting for instance $instanceId to reach 'running' state..."
                $timeout = 600
                $startTime = Get-Date
                do {
                    Start-Sleep -Seconds 5
                    $instanceState = (Get-EC2Instance -InstanceId $instanceId -ProfileName $profileName -Region $region -ErrorAction Stop).Instances[0].State.Name
                    if ((New-TimeSpan -Start $startTime -End (Get-Date)).TotalSeconds -gt $timeout) {
                        Write-Log "Timeout waiting for instance $instanceId to reach 'running' state." "ERROR"
                        continue
                    }
                } until ($instanceState -eq 'running')
                Write-Log "Instance $instanceId is now running."
            }

            # Update Excel with InstanceId
            $excelUpdated = Update-ExcelFile -ExcelFilePath $ExcelFilePath -WorksheetName "EC2_Instances" -NameColumn "InstanceName" -NameValue $instanceName -IdColumn "InstanceId" -IdValue $instanceId
            if (-not $excelUpdated) {
                Write-Log "Failed to update Excel file with InstanceId for instance $instanceName." "WARN"
            }

            # Attach EBS volumes
            if ($volumeIds.Count -gt 0) {
                Write-Log "Attaching $($volumeIds.Count) EBS volume(s) to instance $instanceId"
                foreach ($volume in $volumeIds) {
                    $volumeId = $volume.VolumeId
                    $volumeConfig = $volume.Config
                    $volumeName = $volumeConfig.VolumeName
                    $deviceName = $volumeConfig.DeviceName
                    if (-not $deviceName) {
                        $deviceName = "/dev/sd$([char](102 + $volumeIds.IndexOf($volume)))" # sdf, sdg, etc.
                        Write-Log "No DeviceName specified for volume $volumeName. Defaulting to $deviceName" "WARN"
                    }
                    Write-Log "Attaching volume $volumeId ($volumeName) to instance $instanceId as $deviceName"
                    if ($DryRun) {
                        Write-Log "Dry run: Would attach volume $volumeId to instance $instanceId as $deviceName" "INFO"
                    } else {
                        try {
                            Add-EC2Volume -VolumeId $volumeId -InstanceId $instanceId -Device $deviceName -ProfileName $profileName -Region $region -ErrorAction Stop
                            Write-Log "Successfully attached volume $volumeId to instance $instanceId as $deviceName"

                            # Wait for volume to be in-use
                            $timeout = 300
                            $startTime = Get-Date
                            do {
                                Start-Sleep -Seconds 5
                                $volumeState = (Get-EC2Volume -VolumeId $volumeId -ProfileName $profileName -Region $region -ErrorAction Stop).State
                                if ((New-TimeSpan -Start $startTime -End (Get-Date)).TotalSeconds -gt $timeout) {
                                    Write-Log "Timeout waiting for volume $volumeId to be attached to instance $instanceId." "ERROR"
                                    continue
                                }
                            } until ($volumeState -eq 'in-use')
                            Write-Log "Volume $volumeId is now attached to instance $instanceId."
                        } catch {
                            Write-Log "Failed to attach volume $volumeId to instance $instanceId. Error: $($_.Exception.Message)" "ERROR"
                            continue
                        }
                    }
                }
            }

            Write-Log "Successfully processed instance $instanceName (InstanceId: $instanceId) and its associated volumes." "INFO"
        } catch {
            Write-Log "Error processing instance $instanceName in account $accountId ($accountName). Error: $($_.Exception.Message)" "ERROR"
            continue
        }
    }

    Write-Log "AWS resource management script completed successfully." "INFO"
} catch {
    Write-Log "Fatal error in script execution. Error: $($_.Exception.Message)" "ERROR"
    exit 1
} finally {
    # Clear AWS credentials
    Clear-AWSCredential
    Write-Log "Cleared AWS credentials."
}
