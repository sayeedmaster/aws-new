# Launch-EC2FromExcel.ps1
# PowerShell script to launch EC2 instances from Excel configuration using AWS.Tools modules with multiple SSO profiles
# and write the InstanceId back to the InstanceId field in the Excel file
# Supports dry run mode to simulate actions without modifying AWS resources or the Excel file
# Added preflight check to ensure no EC2 instance with the same InstanceName exists in the same VPC in a running state

param (
    [Parameter(Mandatory=$true, HelpMessage="Path to the directory containing AWS.Tools and ImportExcel modules.")]
    [string]$PSModulesPath,
    [Parameter(Mandatory=$false)]
    [string]$ExcelFilePath = (Join-Path $PSScriptRoot "EC2_Config.xlsx"),
    [Parameter(Mandatory=$false)]
    [string]$LogFilePath = (Join-Path $PSScriptRoot "logs\EC2_Launch_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"),
    [Parameter(Mandatory=$false, HelpMessage="Run in dry run mode to simulate actions without modifying AWS resources or the Excel file.")]
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
    # Colorize output based on log level
    switch ($Level.ToUpper()) {
        "INFO" {
            if ($Message -match "^Successfully launched EC2 instance:") {
                $color = "Green"
            } else {
                $color = "Blue"
            }
        }
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

# Helper function to check if a given IP address is within a CIDR block
function Test-IpInCidr {
    param(
        [Parameter(Mandatory=$true)]
        [string]$IpAddress,
        [Parameter(Mandatory=$true)]
        [string]$Cidr
    )
    try {
        # Parse IP and CIDR
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

        # Validate mask length
        if ($maskLength -lt 0 -or $maskLength -gt 32) {
            Write-Log "Invalid mask length '$maskLength' in CIDR '$Cidr'. Must be between 0 and 32." "ERROR"
            return $false
        }

        # Create subnet mask
        $maskBytes = [byte[]]::new(4) # Explicitly 4 bytes for IPv4
        for ($i = 0; $i -lt $maskLength; $i++) {
            $byteIndex = [math]::Floor($i / 8)
            $bitPosition = $i % 8
            $maskBytes[$byteIndex] = $maskBytes[$byteIndex] -bor (128 -shr $bitPosition)
        }

        # Apply mask to both IP addresses
        for ($i = 0; $i -lt 4; $i++) {
            $maskedIp = $ipBytes[$i] -band $maskBytes[$i]
            $maskedCidr = $cidrBaseIpBytes[$i] -band $maskBytes[$i]
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

# Function to validate SSO session and prompt for login if needed
function Test-SSOSession {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ProfileName,
        [Parameter(Mandatory=$true)]
        [string]$Region
    )
    try {
        # In dry run mode, skip actual SSO validation
        if ($DryRun) {
            Write-Log "Dry run: Skipping SSO session validation for profile: $ProfileName in region: $Region" "INFO"
            return $true
        }

        # Ensure region is set before making any AWS API calls
        Set-DefaultAWSRegion -Region $Region -ErrorAction Stop
        Write-Log "Region set to $Region for profile: $ProfileName"

        # Attempt a simple AWS API call to verify credentials
        Get-STSCallerIdentity -ProfileName $ProfileName -Region $Region -ErrorAction Stop > $null
        Write-Log "SSO session is valid for profile: $ProfileName in region: $Region"
        return $true
    } catch {
        Write-Log "SSO session is invalid or expired for profile: $ProfileName. Error: $($_.Exception.Message)" "ERROR"
        Write-Log "Please run 'aws sso login --profile $ProfileName' to authenticate, then retry the script." "ERROR"
        # Attempt to trigger SSO login (requires AWS CLI)
        try {
            Write-Log "Attempting to trigger SSO login for profile: $ProfileName"
            $process = Start-Process -FilePath "aws" -ArgumentList "sso login --profile $ProfileName" -NoNewWindow -Wait -PassThru
            if ($process.ExitCode -eq 0) {
                Write-Log "SSO login successful for profile: $ProfileName"
                # Re-set region after login
                Set-DefaultAWSRegion -Region $Region -ErrorAction Stop
                # Re-test session
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

# Function for preflight checks before launching an instance
function Invoke-PreflightChecks {
    param(
        [Parameter(Mandatory=$true)]
        $Config,
        [Parameter(Mandatory=$true)]
        $ScriptRoot,
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

    # --- Instance Name Check ---
    if (-not $Config.InstanceName) {
        Write-Log "No InstanceName specified in the Excel file for instance. This is a required field." "ERROR"
        return @{ Success = $false }
    }

    # --- Duplicate Running Instance Check ---
    if ($Config.SubnetId) {
        # Retrieve VpcId from SubnetId
        if ($DryRun) {
            Write-Log "Dry run: Assuming subnet '$($Config.SubnetId)' exists with VpcId 'vpc-dryrun' for duplicate instance check." "INFO"
            $vpcId = "vpc-dryrun"
        } else {
            try {
                $subnetInfo = Get-EC2Subnet -ProfileName $ProfileName -Region $Region -SubnetId $Config.SubnetId -ErrorAction Stop
                $vpcId = $subnetInfo.VpcId
                Write-Log "Subnet '$($Config.SubnetId)' found with VpcId '$vpcId' for instance $($Config.InstanceName)."
            } catch {
                Write-Log "Failed to retrieve VpcId for subnet '$($Config.SubnetId)' for instance $($Config.InstanceName). Error: $($_.Exception.Message)" "ERROR"
                return @{ Success = $false }
            }
        }

        # Check for existing instances with the same InstanceName in the VPC
        Write-Log "Checking for existing running instances with name '$($Config.InstanceName)' in VPC '$vpcId'..."
        if ($DryRun) {
            Write-Log "Dry run: Assuming no running instances with name '$($Config.InstanceName)' exist in VPC '$vpcId'." "INFO"
        } else {
            try {
                $existingInstances = Get-EC2Instance -ProfileName $ProfileName -Region $Region -Filter @(
                    @{Name="tag:Name"; Values=$Config.InstanceName},
                    @{Name="vpc-id"; Values=$vpcId},
                    @{Name="instance-state-name"; Values="running"}
                ) -ErrorAction Stop
                if ($existingInstances.Instances.Count -gt 0) {
                    $instanceIds = $existingInstances.Instances | ForEach-Object { $_.InstanceId }
                    Write-Log "Found $($existingInstances.Instances.Count) running instance(s) with name '$($Config.InstanceName)' in VPC '$vpcId': $($instanceIds -join ', '). Cannot launch a new instance with the same name." "ERROR"
                    return @{ Success = $false }
                }
                Write-Log "No running instances with name '$($Config.InstanceName)' found in VPC '$vpcId'. Proceeding with launch."
            } catch {
                Write-Log "Failed to check for existing instances with name '$($Config.InstanceName)' in VPC '$vpcId'. Error: $($_.Exception.Message)" "ERROR"
                return @{ Success = $false }
            }
        }
    } else {
        Write-Log "No SubnetId specified for instance $($Config.InstanceName). Skipping duplicate instance name check." "WARN"
    }

    # --- Key Pair Check ---
    $keyName = $Config.KeyName
    if (-not $keyName) {
        Write-Log "No KeyName specified in Excel. Skipping key pair check." "WARN"
    } else {
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
                    Write-Log "Local key file '$keyFilePath' exists, but the key pair '$keyName' was NOT found in AWS for this region/account. Please resolve the mismatch." "ERROR"
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
                    Write-Log "Key pair '$keyName' exists in AWS, but the local private key file is missing." "ERROR"
                    Write-Log "Cannot recreate the private key. To resolve, place the correct .pem file at '$keyFilePath' or specify a new key name in the Excel file." "ERROR"
                    return @{ Success = $false }
                }

                Write-Log "Key pair '$keyName' not found locally or in AWS. Creating a new key pair..."
                try {
                    if (-not (Test-Path $keyDir)) {
                        Write-Log "Creating key directory: $keyDir"
                        if (-not $DryRun) {
                            New-Item -ItemType Directory -Path $keyDir -ErrorAction Stop > $null
                        } else {
                            Write-Log "Dry run: Would create key directory: $keyDir" "INFO"
                        }
                    }
                    if (-not $DryRun) {
                        $newKeyPair = New-EC2KeyPair -ProfileName $ProfileName -Region $Region -KeyName $keyName -ErrorAction Stop
                        $newKeyPair.KeyMaterial | Out-File -FilePath $keyFilePath -Encoding ascii
                        Write-Log "Successfully created new key pair '$keyName' and saved private key to '$keyFilePath'."
                    } else {
                        Write-Log "Dry run: Would create new key pair '$keyName' and save private key to '$keyFilePath'." "INFO"
                    }
                } catch {
                    Write-Log "Failed to create new key pair '$keyName'. Error: $($_.Exception.Message)" "ERROR"
                    return @{ Success = $false }
                }
            }
        }
    }

    # --- Subnet and IP Address Check ---
    $subnetId = $Config.SubnetId
    $privateIp = $Config.PrivateIpAddress
    $subnetInfo = $null # Ensure subnetInfo is scoped correctly

    if (-not $subnetId) {
        Write-Log "No SubnetId specified. Skipping IP checks." "WARN"
    } else {
        if ($DryRun) {
            Write-Log "Dry run: Assuming subnet '$subnetId' exists with sufficient IPs and CIDR block for validation." "INFO"
            $subnetInfo = [PSCustomObject]@{
                AvailableIpAddressCount = 10
                CidrBlock = "172.31.0.0/16"
                VpcId = "vpc-1234567890abcdef0"
            }
        } else {
            try {
                $subnetInfo = Get-EC2Subnet -ProfileName $ProfileName -Region $Region -SubnetId $subnetId -ErrorAction Stop
                Write-Log "Subnet '$subnetId' found. Available IPs: $($subnetInfo.AvailableIpAddressCount). CIDR: $($subnetInfo.CidrBlock)."
            } catch {
                Write-Log "Failed to validate subnet or IP address. Error: $($_.Exception.Message)" "ERROR"
                return @{ Success = $false }
            }
        }

        if ($subnetInfo.AvailableIpAddressCount -eq 0) {
            Write-Log "Subnet '$subnetId' has no available IP addresses." "ERROR"
            return @{ Success = $false }
        }

        if ($privateIp) {
            Write-Log "Validating specified private IP '$privateIp'..."
            if (-not (Test-IpInCidr -IpAddress $privateIp -Cidr $subnetInfo.CidrBlock)) {
                Write-Log "The specified IP address '$privateIp' is NOT within the CIDR block ('$($subnetInfo.CidrBlock)') of subnet '$subnetId'." "ERROR"
                return @{ Success = $false }
            }
            Write-Log "IP '$privateIp' is within the subnet's CIDR range."

            if (-not $DryRun) {
                $ipInUse = Get-EC2NetworkInterface -ProfileName $ProfileName -Region $Region -Filter @{Name="addresses.private-ip-address"; Values=$privateIp} -ErrorAction Stop
                if ($ipInUse) {
                    Write-Log "The specified IP address '$privateIp' is already in use in this VPC." "ERROR"
                    return @{ Success = $false }
                }
            }
            Write-Log "IP '$privateIp' appears to be available."
        }
    }

    # --- Security Group Check ---
    $securityGroupIdsRaw = $Config.SecurityGroupIds
    if ($subnetInfo -and $securityGroupIdsRaw) {
        $securityGroupIds = $securityGroupIdsRaw -split ',' | ForEach-Object { $_.Trim() }
        if ($securityGroupIds.Count -gt 0) {
            Write-Log "Validating security groups: $($securityGroupIds -join ', ')"
            if ($DryRun) {
                Write-Log "Dry run: Assuming security groups $($securityGroupIds -join ', ') exist and are in the correct VPC." "INFO"
            } else {
                try {
                    $vpcId = $subnetInfo.VpcId
                    $sgs = Get-EC2SecurityGroup -ProfileName $ProfileName -Region $Region -GroupId $securityGroupIds -ErrorAction Stop
                    foreach ($sg in $sgs) {
                        if ($sg.VpcId -ne $vpcId) {
                            Write-Log "Security group '$($sg.GroupId)' (VPC: $($sg.VpcId)) is not in the same VPC as the subnet (VPC: $vpcId)." "ERROR"
                            return @{ Success = $false }
                        }
                    }
                    Write-Log "All specified security groups are valid and in the correct VPC."
                } catch {
                    Write-Log "Failed to validate security groups. One or more may not exist. Error: $($_.Exception.Message)" "ERROR"
                    return @{ Success = $false }
                }
            }
        }
    } elseif (-not $securityGroupIdsRaw) {
        Write-Log "No SecurityGroupIds specified. Skipping check." "WARN"
    }

    # --- IAM Instance Profile Check ---
    $iamProfileName = $Config.IamInstanceProfile
    if ($iamProfileName) {
        Write-Log "Checking for IAM Instance Profile '$iamProfileName'..."
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
    } else {
        Write-Log "No IamInstanceProfile specified. Skipping check." "WARN"
    }

    # --- Image ID (AMI) Check ---
    $imageId = $Config.ImageId
    $rootDeviceName = $null
    if ($imageId) {
        Write-Log "Checking for Image ID (AMI) '$imageId'..."
        if ($DryRun) {
            Write-Log "Dry run: Assuming AMI '$imageId' exists with root device name '/dev/xvda'." "INFO"
            $rootDeviceName = "/dev/xvda"
        } else {
            try {
                $ami = Get-EC2Image -ProfileName $ProfileName -Region $Region -ImageId $imageId -ErrorAction Stop
                Write-Log "Image ID '$imageId' found."
                # Safely retrieve RootDeviceName
                if ($ami -and $ami.Count -gt 0) {
                    $rootDeviceName = $ami[0].RootDeviceName
                    if ($rootDeviceName) {
                        Write-Log "AMI '$imageId' root device name: $rootDeviceName"
                    } else {
                        Write-Log "RootDeviceName not found for AMI '$imageId'. Using default '/dev/xvda'." "WARN"
                        $rootDeviceName = "/dev/xvda"
                    }
                } else {
                    Write-Log "No AMI details returned for '$imageId'. Using default root device name '/dev/xvda'." "WARN"
                    $rootDeviceName = "/dev/xvda"
                }
            } catch {
                Write-Log "Failed to retrieve AMI '$imageId'. Error: $($_.Exception.Message)" "ERROR"
                return @{ Success = $false }
            }
        }
    } else {
        Write-Log "No ImageId specified in the Excel file for instance $($Config.InstanceName). This is a required field." "ERROR"
        return @{ Success = $false }
    }

    # --- Instance Type Check ---
    $instanceType = $Config.InstanceType
    if ($instanceType) {
        if ($ValidInstanceTypes.Count -gt 0) {
            Write-Log "Checking if instance type '$instanceType' is valid..."
            if ($instanceType -in $ValidInstanceTypes) {
                Write-Log "Instance type '$instanceType' is valid."
            } else {
                Write-Log "Instance type '$instanceType' is NOT in the list of valid instance types specified in config.json." "ERROR"
                return @{ Success = $false }
            }
        } else {
            Write-Log "Skipping instance type validation because the list of valid types could not be loaded." "WARN"
        }
    } else {
        Write-Log "No InstanceType specified in the Excel file for instance $($Config.InstanceName). This is a required field." "ERROR"
        return @{ Success = $false }
    }

    # --- SR-IOV Compatibility Check ---
    if ($Config.SriovNetSupport) {
        Write-Log "Checking SR-IOV compatibility for instance type '$instanceType'..."
        if ($SRIOVCompatibleTypes.Count -gt 0 -and $instanceType -notin $SRIOVCompatibleTypes) {
            Write-Log "Instance type '$instanceType' does not support SR-IOV. Ignoring SriovNetSupport setting ('$($Config.SriovNetSupport)')." "WARN"
            $Config.SriovNetSupport = $null # Clear to skip post-launch configuration
        } else {
            Write-Log "Instance type '$instanceType' supports SR-IOV. Will apply SriovNetSupport ('$($Config.SriovNetSupport)') post-launch."
        }
    }

    # --- Associate Public IP Address Check ---
    if ($null -ne $Config.AssociatePublicIpAddress) {
        $validValues = @('TRUE', 'FALSE')
        $normalizedValue = Convert-ToNormalizedString -Value $Config.AssociatePublicIpAddress
        Write-Log "AssociatePublicIpAddress raw value: '$($Config.AssociatePublicIpAddress)' (Type: $($Config.AssociatePublicIpAddress.GetType().Name)), normalized: '$normalizedValue'" "DEBUG"
        if ($normalizedValue -notin $validValues) {
            Write-Log "Invalid AssociatePublicIpAddress value '$($Config.AssociatePublicIpAddress)' for instance $($Config.InstanceName). Must be 'TRUE' or 'FALSE'. Defaulting to FALSE." "WARN"
            $Config.AssociatePublicIpAddress = 'FALSE'
        } else {
            Write-Log "AssociatePublicIpAddress set to '$normalizedValue' for instance $($Config.InstanceName)."
        }
    }

    # --- Root Volume Configuration Check ---
    if ($Config.RootVolumeSize -or $Config.RootVolumeType) {
        # Validate RootVolumeSize
        if ($Config.RootVolumeSize) {
            try {
                $volumeSize = [int]$Config.RootVolumeSize
                if ($volumeSize -le 0) {
                    Write-Log "RootVolumeSize '$($Config.RootVolumeSize)' for instance $($Config.InstanceName) must be a positive integer. Skipping volume configuration." "ERROR"
                    return @{ Success = $false }
                }
                Write-Log "RootVolumeSize '$volumeSize' GiB is valid for instance $($Config.InstanceName)."
            } catch {
                Write-Log "Invalid RootVolumeSize '$($Config.RootVolumeSize)' for instance $($Config.InstanceName). Must be a positive integer. Error: $($_.Exception.Message)" "ERROR"
                return @{ Success = $false }
            }
        }

        # Validate RootVolumeType
        if ($Config.RootVolumeType) {
            $validVolumeTypes = @('standard', 'gp2', 'gp3', 'io1', 'io2', 'sc1', 'st1')
            if ($Config.RootVolumeType -notin $validVolumeTypes) {
                Write-Log "Invalid RootVolumeType '$($Config.RootVolumeType)' for instance $($Config.InstanceName). Must be one of: $($validVolumeTypes -join ', '). Defaulting to AMI's default volume type." "WARN"
                $Config.RootVolumeType = $null
            } else {
                Write-Log "RootVolumeType '$($Config.RootVolumeType)' is valid for instance $($Config.InstanceName)."
            }
        }
    }

    # --- Encryption Check ---
    if ($null -ne $Config.Encrypted) {
        $normalizedEncrypted = Convert-ToNormalizedString -Value $Config.Encrypted
        Write-Log "Encrypted raw value: '$($Config.Encrypted)' (Type: $($Config.Encrypted.GetType().Name)), normalized: '$normalizedEncrypted'" "DEBUG"
        if ($normalizedEncrypted -eq 'TRUE') {
            if (-not $Config.KmsKeyId) {
                Write-Log "Encrypted is set to 'TRUE' for instance $($Config.InstanceName), but no KmsKeyId is specified. Using default KMS key for encryption." "WARN"
            } else {
                if ($DryRun) {
                    Write-Log "Dry run: Assuming KMS key '$($Config.KmsKeyId)' is valid." "INFO"
                } else {
                    try {
                        Get-KMSKey -KeyId $Config.KmsKeyId -ProfileName $ProfileName -Region $Region -ErrorAction Stop > $null
                        Write-Log "KMS key '$($Config.KmsKeyId)' is valid for instance $($Config.InstanceName)."
                    } catch {
                        Write-Log "Invalid KmsKeyId '$($Config.KmsKeyId)' for instance $($Config.InstanceName). Error: $($_.Exception.Message)" "ERROR"
                        return @{ Success = $false }
                    }
                }
            }
        } elseif ($normalizedEncrypted -ne 'FALSE') {
            Write-Log "Invalid Encrypted value '$($Config.Encrypted)' for instance $($Config.InstanceName). Must be 'TRUE' or 'FALSE'. Defaulting to FALSE." "WARN"
            $Config.Encrypted = 'FALSE'
        }
    }

    # Return rootDeviceName for use in block device mapping
    return @{ Success = $true; RootDeviceName = $rootDeviceName }
}

try {
    # Ensure the log directory exists
    $logDir = Split-Path -Path $LogFilePath -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -ErrorAction Stop > $null
    }

    # Import required AWS.Tools modules and ImportExcel from the specified path
    try {
        Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.Common") -ErrorAction Stop
        Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.EC2") -ErrorAction Stop
        Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.IdentityManagement") -ErrorAction Stop
        Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.KeyManagementService") -ErrorAction Stop
        Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.SecurityToken") -ErrorAction Stop
        Import-Module -Name (Join-Path $PSModulesPath "ImportExcel") -ErrorAction Stop
        Write-Log "Successfully imported AWS.Tools modules (Common, EC2, IdentityManagement, KeyManagementService, SecurityToken) and ImportExcel" "INFO"
    } catch {
        Write-Log "Failed to import modules from $PSModulesPath. Error: $($_.Exception.Message)" "ERROR"
        exit 1
    }

    Write-Log "Starting EC2 launch script (DryRun: $DryRun)"

    # Read Excel file
    Write-Log "Reading Excel file: $ExcelFilePath"
    if (-not (Test-Path $ExcelFilePath)) {
        throw "Excel file not found: $ExcelFilePath"
    }
    
    $ec2Configs = Import-Excel -Path $ExcelFilePath -WorksheetName "EC2_Instances" -ErrorAction Stop
    if ($ec2Configs.Count -eq 0) {
        throw "No EC2 configurations found in Excel file"
    }
    Write-Log "Found $($ec2Configs.Count) EC2 configurations in Excel"

    # Load valid instance types and SR-IOV compatible types from config.json
    $configJsonPath = Join-Path $PSScriptRoot "config.json"
    $validInstanceTypes = @()
    $sriovCompatibleTypes = @()
    if (Test-Path $configJsonPath) {
        try {
            $configJson = Get-Content -Path $configJsonPath -Raw | ConvertFrom-Json
            $validInstanceTypes = $configJson.validInstanceTypes
            $sriovCompatibleTypes = $configJson.SRIOVCompatibleTypes
            Write-Log "Successfully loaded $($validInstanceTypes.Count) valid instance types and $($sriovCompatibleTypes.Count) SR-IOV compatible types from $configJsonPath"
        } catch {
            Write-Log "Failed to read or parse config.json. Instance type and SR-IOV validation will be skipped. Error: $($_.Exception.Message)" "WARN"
        }
    } else {
        Write-Log "config.json not found at $configJsonPath. Instance type and SR-IOV validation will be skipped." "WARN"
    }

    # Path to AWS config file
    $awsConfigPath = "$env:USERPROFILE\.aws\config"
    if (-not (Test-Path $awsConfigPath)) {
        throw "AWS config file not found: $awsConfigPath"
    }

    # Read config file into lines
    $configLines = Get-Content -Path $awsConfigPath

    # Process each EC2 configuration
    foreach ($config in $ec2Configs) {
        try {
            $accountId = $config.AccountId
            $accountName = $config.AccountName
            $ssoRole = $config.SSORole
            $instanceName = $config.InstanceName

            # Clean names to match the profile format
            $cleanAccountName = $accountName -replace '[^\w\-]', ''
            $cleanSsoRole = $ssoRole -replace '[^\w\-]', ''
            $profileName = "sso-$cleanAccountName-$cleanSsoRole"

            Write-Log "Processing EC2 configuration for Account: $accountId ($accountName), Instance: $instanceName, Profile: $profileName"

            # Find profile section using a robust regex search
            $profileHeaderPattern = "^\[profile\s+$([regex]::Escape($profileName))\s*\]$"
            $profileLine = $configLines | Select-String -Pattern $profileHeaderPattern

            if (-not $profileLine) {
                Write-Log "Profile section not found in AWS config for: $profileName. Please ensure it exists in '$awsConfigPath'." "ERROR"
                continue
            }

            $profileStart = $profileLine.LineNumber
            # Find the start of the next profile or section to determine the end of the current one
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

            # Validate AccountId matches sso_account_id
            if ($ssoAccountId -ne $accountId) {
                Write-Log "AccountId ($accountId) in Excel does not match sso_account_id ($ssoAccountId) in profile: $profileName." "ERROR"
                continue
            }

            # Validate SSORole matches sso_role_name
            if ($ssoRoleName -ne $ssoRole) {
                Write-Log "SSORole ($ssoRole) in Excel does not match sso_role_name ($ssoRoleName) in profile: $profileName." "ERROR"
                continue
            }

            # Validate region is supported
            $validRegions = if ($DryRun) { @($region) } else { Get-AWSRegion -ErrorAction Stop | Select-Object -ExpandProperty Region }
            if ($region -notin $validRegions) {
                Write-Log "Region '$region' is not a valid AWS region for profile: $profileName. Valid regions: $($validRegions -join ', ')" "ERROR"
                continue
            }

            # Set AWS credentials and region
            Write-Log "Setting AWS credentials for profile: $profileName"
            try {
                if (-not $DryRun) {
                    # Set credentials for the session
                    Set-AWSCredential -ProfileName $profileName -ErrorAction Stop
                    # Validate SSO session with region explicitly set
                    if (-not (Test-SSOSession -ProfileName $profileName -Region $region)) {
                        Write-Log "Skipping instance launch for $instanceName due to invalid SSO session." "ERROR"
                        continue
                    }
                    # Ensure region is set for subsequent API calls
                    Set-DefaultAWSRegion -Region $region -ErrorAction Stop
                }
                Write-Log "Successfully set credentials and region ($region) for profile: $profileName"
            } catch {
                Write-Log "Failed to set credentials for profile: $profileName. Error: $($_.Exception.Message)" "ERROR"
                continue
            }

            # --- Run Preflight Checks ---
            $preflightResult = Invoke-PreflightChecks -Config $config -ScriptRoot $PSScriptRoot -ValidInstanceTypes $validInstanceTypes -SRIOVCompatibleTypes $sriovCompatibleTypes -ProfileName $profileName -Region $region
            if (-not $preflightResult.Success) {
                Write-Log "Preflight checks failed for instance $($config.InstanceName). Skipping launch." "ERROR"
                continue # Skip to the next configuration
            }
            $rootDeviceName = $preflightResult.RootDeviceName

            # Prepare EC2 launch parameters
            $launchParams = @{
                ImageId = $config.ImageId
                InstanceType = $config.InstanceType
                KeyName = $config.KeyName
                MinCount = 1
                MaxCount = 1
            }

            # Configure Network Interface
            if ($config.SubnetId) {
                $networkInterface = New-Object Amazon.EC2.Model.InstanceNetworkInterfaceSpecification
                $networkInterface.DeviceIndex = 0
                $networkInterface.SubnetId = $config.SubnetId
                if ($config.PrivateIpAddress) {
                    $networkInterface.PrivateIpAddress = $config.PrivateIpAddress
                }
                $normalizedAssociatePublicIp = Convert-ToNormalizedString -Value $config.AssociatePublicIpAddress
                if ($normalizedAssociatePublicIp -eq 'TRUE') {
                    $networkInterface.AssociatePublicIpAddress = $true
                } elseif ($normalizedAssociatePublicIp -eq 'FALSE') {
                    $networkInterface.AssociatePublicIpAddress = $false
                }
                if ($config.SecurityGroupIds) {
                    $networkInterface.Groups = $config.SecurityGroupIds -split ',' | ForEach-Object { $_.Trim() }
                }
                $launchParams.NetworkInterface = @($networkInterface)
                Write-Log "Network interface configured: SubnetId=$($config.SubnetId), PrivateIpAddress=$($config.PrivateIpAddress), AssociatePublicIpAddress=$($networkInterface.AssociatePublicIpAddress), Groups=$($config.SecurityGroupIds)" "DEBUG"
            }

            # Add IAM Instance Profile if specified
            if ($config.IamInstanceProfile) {
                $launchParams.IamInstanceProfile_Name = $config.IamInstanceProfile
            }

            # Add EBS Optimized
            if ($config.EbsOptimized -eq 'true') {
                $launchParams.EbsOptimized = $true
            }

            # Add Block Device Mapping for Root Volume
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
                $blockDeviceMapping.DeviceName = $rootDeviceName # Use AMI's root device name or fallback
                $blockDeviceMapping.Ebs = $ebs
                $launchParams.BlockDeviceMapping = @($blockDeviceMapping) # Ensure array to override AMI defaults
            }

            # Add Monitoring
            if ($config.Monitoring -eq 'true') {
                $launchParams.Monitoring_Enabled = $true
            }

            # Add Metadata Options
            if ($config.MetadataOptionsHttpTokens) {
                $launchParams.MetadataOptions_HttpTokens = $config.MetadataOptionsHttpTokens
            }
            if ($config.MetadataOptionsHttpEndpoint) {
                $launchParams.MetadataOptions_HttpEndpoint = $config.MetadataOptionsHttpEndpoint
            }
            if ($config.MetadataOptionsHttpPutResponseHopLimit) {
                $launchParams.MetadataOptions_HttpPutResponseHopLimit = [int]$config.MetadataOptionsHttpPutResponseHopLimit
            }
            if ($config.InstanceMetadataTags -eq 'true') {
                $launchParams.MetadataOptions_InstanceMetadataTags = 'enabled'
            }

            # Add CPU Options
            if ($config.CpuCoreCount -or $config.CpuThreadsPerCore) {
                $cpuOptions = New-Object Amazon.EC2.Model.CpuOptionsRequest
                if ($config.CpuCoreCount) { $cpuOptions.CoreCount = [int]$config.CpuCoreCount }
                if ($config.CpuThreadsPerCore) { $cpuOptions.ThreadsPerCore = [int]$config.CpuThreadsPerCore }
                $launchParams.CpuOptions = $cpuOptions
            }

            # Add Disable API Termination
            if ($config.DisableApiTermination -eq 'true') {
                $launchParams.DisableApiTermination = $true
            }

            # Add Instance Initiated Shutdown Behavior
            if ($config.InstanceInitiatedShutdownBehavior) {
                $launchParams.InstanceInitiatedShutdownBehavior = $config.InstanceInitiatedShutdownBehavior
            }

            # Add ENA Support
            if ($config.EnaSupport -eq 'true') {
                $launchParams.EnaSupport = $true
            }

            # Add User Data
            if ($config.UserData) {
                $launchParams.UserData = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($config.UserData))
            }

            # Add Tags (Name=Value format, comma-separated)
            if ($config.Tags -or $instanceName) {
                $tags = @()
                if ($config.Tags) {
                    Write-Log "Processing tags for instance $($config.InstanceName): $($config.Tags)" "DEBUG"
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
                # Add InstanceName as a Name tag if not already included
                if ($instanceName -and -not ($tags | Where-Object { $_.Key -eq 'Name' })) {
                    $nameTag = New-Object Amazon.EC2.Model.Tag
                    $nameTag.Key = 'Name'
                    $nameTag.Value = $instanceName
                    $tags += $nameTag
                    Write-Log "Adding Name tag: Name=$instanceName" "DEBUG"
                }
                if ($tags.Count -gt 0) {
                    $tagSpec = New-Object Amazon.EC2.Model.TagSpecification
                    $tagSpec.ResourceType = "instance"
                    $tagSpec.Tags = $tags
                    $launchParams.TagSpecification = $tagSpec
                    Write-Log "Applying $($tags.Count) tags to instance $($config.InstanceName)" "INFO"
                } else {
                    Write-Log "No valid tags to apply for instance $($config.InstanceName)" "WARN"
                }
            }

            # Launch EC2 instance
            Write-Log "Launching EC2 instance in Account: $accountId ($accountName), Region: $region, Instance: $instanceName"
            if ($DryRun) {
                Write-Log "Dry run: Would launch EC2 instance with parameters: $(ConvertTo-Json -InputObject $launchParams -Depth 5 -Compress)" "INFO"
                $instanceId = "i-dryrun-$(Get-Random -Minimum 1000000000 -Maximum 9999999999)"
                Write-Log "Dry run: Simulated EC2 instance launch with InstanceId: $instanceId" "INFO"
            } else {
                $reservation = New-EC2Instance @launchParams -ErrorAction Stop
                $instanceId = $reservation.Instances[0].InstanceId
                Write-Log "Successfully launched EC2 instance: $instanceId"
            }

            # Update Excel file with InstanceId
            try {
                Write-Log "Updating InstanceId '$instanceId' for instance '$instanceName' in Excel file '$ExcelFilePath'"
                # Open the Excel file
                $excelPackage = Open-ExcelPackage -Path $ExcelFilePath -ErrorAction Stop
                $worksheet = $excelPackage.Workbook.Worksheets["EC2_Instances"]
                if (-not $worksheet) {
                    throw "Worksheet 'EC2_Instances' not found in Excel file"
                }

                # Get headers and find InstanceId and InstanceName columns
                $headers = @{}
                for ($col = 1; $col -le $worksheet.Dimension.Columns; $col++) {
                    $header = $worksheet.Cells[1, $col].Value
                    if ($header) {
                        $headers[$header] = $col
                    }
                }

                # Verify required columns
                if (-not $headers.ContainsKey('InstanceName')) {
                    throw "InstanceName column not found in Excel worksheet"
                }
                if (-not $headers.ContainsKey('InstanceId')) {
                    Write-Log "InstanceId column not found in Excel worksheet. Adding it." "WARN"
                    # Add InstanceId column at the end
                    $newCol = $worksheet.Dimension.Columns + 1
                    $worksheet.Cells[1, $newCol].Value = 'InstanceId'
                    $headers['InstanceId'] = $newCol
                }

                # Find the row for the instance
                $rowFound = $false
                for ($row = 2; $row -le $worksheet.Dimension.Rows; $row++) {
                    if ($worksheet.Cells[$row, $headers['InstanceName']].Value -eq $instanceName) {
                        if ($DryRun) {
                            Write-Log "Dry run: Would update row $row, column InstanceId with value '$instanceId' for instance '$instanceName'" "INFO"
                        } else {
                            # Update the InstanceId cell
                            $worksheet.Cells[$row, $headers['InstanceId']].Value = $instanceId
                            Write-Log "Updated row $row, column InstanceId with value '$instanceId' for instance '$instanceName'" "DEBUG"
                        }
                        $rowFound = $true
                        break
                    }
                }

                if (-not $rowFound) {
                    Write-Log "No row found with InstanceName '$instanceName' in Excel worksheet" "ERROR"
                } else {
                    if (-not $DryRun) {
                        # Save and close the Excel file
                        Close-ExcelPackage -ExcelPackage $excelPackage -ErrorAction Stop
                        # Verify the update was saved
                        $excelPackageVerify = Open-ExcelPackage -Path $ExcelFilePath -ErrorAction Stop
                        $worksheetVerify = $excelPackageVerify.Workbook.Worksheets["EC2_Instances"]
                        $verified = $false
                        for ($row = 2; $row -le $worksheetVerify.Dimension.Rows; $row++) {
                            if ($worksheetVerify.Cells[$row, $headers['InstanceName']].Value -eq $instanceName -and 
                                $worksheetVerify.Cells[$row, $headers['InstanceId']].Value -eq $instanceId) {
                                $verified = $true
                                break
                            }
                        }
                        Close-ExcelPackage -ExcelPackage $excelPackageVerify -ErrorAction Stop
                        if ($verified) {
                            Write-Log "Successfully updated and verified Excel file with InstanceId '$instanceId' for instance '$instanceName'" "INFO"
                        } else {
                            Write-Log "Failed to verify InstanceId '$instanceId' for instance '$instanceName' in Excel file after save" "ERROR"
                        }
                    }
                }
            } catch {
                Write-Log "Failed to update Excel file with InstanceId '$instanceId' for instance '$instanceName'. Error: $($_.Exception.Message)" "ERROR"
            }

            # Apply SR-IOV post-launch if specified and instance type is compatible
            if ($config.SriovNetSupport) {
                try {
                    Write-Log "Applying SR-IOV setting ('$($config.SriovNetSupport)') for instance $instanceId..."
                    if ($DryRun) {
                        Write-Log "Dry run: Would apply SR-IOV setting ('$($config.SriovNetSupport)') to instance $instanceId." "INFO"
                    } else {
                        # Stop the instance if necessary (required for some instance types)
                        $instanceState = if ($DryRun) { "running" } else { (Get-EC2Instance -InstanceId $instanceId -ProfileName $profileName -Region $region).Instances[0].State.Name }
                        if ($instanceState -eq 'running') {
                            Write-Log "Stopping instance $instanceId to apply SR-IOV..."
                            if (-not $DryRun) {
                                Stop-EC2Instance -InstanceId $instanceId -ProfileName $profileName -Region $region -Force -ErrorAction Stop
                                # Wait for instance to stop
                                $timeout = 300 # 5 minutes
                                $startTime = Get-Date
                                do {
                                    Start-Sleep -Seconds 10
                                    $instanceState = (Get-EC2Instance -InstanceId $instanceId -ProfileName $profileName -Region $region).Instances[0].State.Name
                                    if ((New-TimeSpan -Start $startTime -End (Get-Date)).TotalSeconds -gt $timeout) {
                                        throw "Timeout waiting for instance $instanceId to stop."
                                    }
                                } until ($instanceState -eq 'stopped')
                                Write-Log "Instance $instanceId stopped."
                            } else {
                                Write-Log "Dry run: Would stop instance $instanceId." "INFO"
                            }
                        }
                        # Apply SR-IOV
                        if (-not $DryRun) {
                            Edit-EC2InstanceAttribute -InstanceId $instanceId -SriovNetSupport $config.SriovNetSupport -ProfileName $profileName -Region $region -ErrorAction Stop
                            Write-Log "Successfully applied SR-IOV setting ('$($config.SriovNetSupport)') to instance $instanceId."
                        }
                        # Restart the instance
                        if ($instanceState -eq 'running') {
                            Write-Log "Restarting instance $instanceId..."
                            if (-not $DryRun) {
                                Start-EC2Instance -InstanceId $instanceId -ProfileName $profileName -Region $region -ErrorAction Stop
                                Write-Log "Instance $instanceId restarted."
                            } else {
                                Write-Log "Dry run: Would restart instance $instanceId." "INFO"
                            }
                        }
                    }
                } catch {
                    Write-Log "Failed to apply SR-IOV setting to instance $instanceId. Error: $($_.Exception.Message)" "ERROR"
                    # Continue despite SR-IOV failure
                }
            }

            # Clear credentials after launch to prevent interference with subsequent profiles
            if (-not $DryRun) {
                Clear-AWSCredential -ErrorAction SilentlyContinue
                Clear-DefaultAWSRegion -ErrorAction SilentlyContinue
            }

        } catch {
            Write-Log "Error processing configuration for Account: $accountId ($accountName), Region: $region, Instance: $instanceName. Error: $($_.Exception.Message)" "ERROR"
            # Clear credentials on error to prevent interference
            if (-not $DryRun) {
                Clear-AWSCredential -ErrorAction SilentlyContinue
                Clear-DefaultAWSRegion -ErrorAction SilentlyContinue
            }
            continue
        }
    }

    Write-Log "EC2 launch process completed"

} catch {
    Write-Log "Fatal error: $($_.Exception.Message)" "ERROR"
    exit 1
}