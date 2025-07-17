# Attach-SecurityGroupsFromExcel.ps1
# PowerShell script to attach existing security groups to EC2 instances from Excel configuration
# using AWS.Tools modules with multiple SSO profiles and write the AttachedSecurityGroupIds and InstanceId back to the Excel file
# Supports dry run mode to simulate actions without modifying AWS resources or the Excel file
# Either InstanceName or InstanceId must be provided to identify the EC2 instance
# Updated to only attach security groups that are not already attached and ensure proper array handling for Edit-EC2InstanceAttribute

param (
    [Parameter(Mandatory=$true, HelpMessage="Path to the directory containing AWS.Tools and ImportExcel modules.")]
    [string]$PSModulesPath,
    [Parameter(Mandatory=$false)]
    [string]$ExcelFilePath = (Join-Path $PSScriptRoot "EC2_Config.xlsx"),
    [Parameter(Mandatory=$false)]
    [string]$LogFilePath = (Join-Path $PSScriptRoot "logs\SG_Attach_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"),
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
    switch ($Level.ToUpper()) {
        "INFO" {
            if ($Message -match "^Successfully") {
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

# Function to validate SSO session
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

# Function for preflight checks
function Invoke-PreflightChecks {
    param(
        [Parameter(Mandatory=$true)]
        $Config,
        [Parameter(Mandatory=$true)]
        [string]$ProfileName,
        [Parameter(Mandatory=$true)]
        [string]$Region
    )
    Write-Log "Running preflight checks for security group attachment to instance for configuration with InstanceName $($Config.InstanceName) and InstanceId $($Config.InstanceId)..."

    # --- VPC Check ---
    $vpcId = $Config.VpcID
    if (-not $vpcId) {
        Write-Log "No VpcID specified in the Excel file. This is a required field." "ERROR"
        return $false
    }
    if ($DryRun) {
        Write-Log "Dry run: Assuming VPC '$vpcId' exists." "INFO"
    } else {
        try {
            Get-EC2Vpc -ProfileName $ProfileName -Region $Region -VpcId $vpcId -ErrorAction Stop > $null
            Write-Log "VPC '$vpcId' found."
        } catch {
            Write-Log "VPC '$vpcId' not found. Error: $($_.Exception.Message)" "ERROR"
            return $false
        }
    }

    # --- Security Group Names Check ---
    $securityGroupNames = if ($Config.SecurityGroupNames) { $Config.SecurityGroupNames -split ',' | ForEach-Object { $_.Trim() } } else { @() }
    if ($securityGroupNames.Count -eq 0) {
        Write-Log "No SecurityGroupNames specified in the Excel file. This is a required field." "ERROR"
        return $false
    }
    $securityGroupIds = @()
    foreach ($sgName in $securityGroupNames) {
        Write-Log "Checking for existing security group '$sgName' in VPC '$vpcId'..."
        if ($DryRun) {
            Write-Log "Dry run: Assuming security group '$sgName' exists in VPC '$vpcId'." "INFO"
            $securityGroupIds += "sg-dryrun-$(Get-Random -Minimum 1000000000 -Maximum 9999999999)"
        } else {
            try {
                $sg = Get-EC2SecurityGroup -ProfileName $ProfileName -Region $Region -Filter @(
                    @{Name="group-name"; Values=$sgName},
                    @{Name="vpc-id"; Values=$vpcId}
                ) -ErrorAction Stop
                if ($sg.Count -eq 0) {
                    Write-Log "Security group '$sgName' not found in VPC '$vpcId'." "ERROR"
                    return $false
                }
                if ($sg.Count -gt 1) {
                    Write-Log "Multiple security groups with name '$sgName' found in VPC '$vpcId'. Expected exactly one." "ERROR"
                    return $false
                }
                $securityGroupIds += $sg.GroupId
                Write-Log "Security group '$sgName' found with ID '$($sg.GroupId)' in VPC '$vpcId'."
            } catch {
                Write-Log "Failed to retrieve security group '$sgName' in VPC '$vpcId'. Error: $($_.Exception.Message)" "ERROR"
                return $false
            }
        }
    }

    # --- Instance Identification Check ---
    $instanceId = $Config.InstanceId
    $instanceName = $Config.InstanceName
    $availabilityZone = $Config.AvailabilityZone
    if (-not $instanceId -and -not $instanceName) {
        Write-Log "Neither InstanceId nor InstanceName specified in the Excel file. At least one is required." "ERROR"
        return $false
    }
    if (-not $availabilityZone) {
        Write-Log "No AvailabilityZone specified in the Excel file. This is a required field." "ERROR"
        return $false
    }

    # Resolve InstanceId from InstanceName if not provided
    if (-not $instanceId -and $instanceName) {
        Write-Log "InstanceId not provided. Attempting to resolve InstanceId using InstanceName '$instanceName' in VPC '$vpcId' and AvailabilityZone '$availabilityZone'..."
        if ($DryRun) {
            Write-Log "Dry run: Assuming instance with name '$instanceName' exists in VPC '$vpcId' and AZ '$availabilityZone'." "INFO"
            $instanceId = "i-dryrun-$(Get-Random -Minimum 1000000000 -Maximum 9999999999)"
        } else {
            try {
                $instances = Get-EC2Instance -ProfileName $ProfileName -Region $Region -Filter @(
                    @{Name="tag:Name"; Values=$instanceName},
                    @{Name="vpc-id"; Values=$vpcId},
                    @{Name="availability-zone"; Values=$availabilityZone},
                    @{Name="instance-state-name"; Values="running"}
                ) -ErrorAction Stop
                if ($instances.Instances.Count -eq 0) {
                    Write-Log "No running instance found with name '$instanceName' in VPC '$vpcId' and AvailabilityZone '$availabilityZone'." "ERROR"
                    return $false
                }
                if ($instances.Instances.Count -gt 1) {
                    Write-Log "Multiple running instances found with name '$instanceName' in VPC '$vpcId' and AvailabilityZone '$availabilityZone'. Expected exactly one." "ERROR"
                    return $false
                }
                $instanceId = $instances.Instances[0].InstanceId
                Write-Log "Resolved InstanceId '$instanceId' for InstanceName '$instanceName'."
            } catch {
                Write-Log "Failed to resolve InstanceId for InstanceName '$instanceName' in VPC '$vpcId' and AvailabilityZone '$availabilityZone'. Error: $($_.Exception.Message)" "ERROR"
                return $false
            }
        }
    }

    # Validate instance
    if ($DryRun) {
        Write-Log "Dry run: Assuming instance '$instanceId' exists in VPC '$vpcId' and AZ '$availabilityZone' and is in running state." "INFO"
    } else {
        try {
            $instance = Get-EC2Instance -ProfileName $ProfileName -Region $Region -InstanceId $instanceId -ErrorAction Stop
            if ($instance.Instances.Count -eq 0) {
                Write-Log "Instance '$instanceId' not found." "ERROR"
                return $false
            }
            if ($instance.Instances[0].State.Name -ne 'running') {
                Write-Log "Instance '$instanceId' is not in running state (current state: $($instance.Instances[0].State.Name))." "ERROR"
                return $false
            }
            if ($instance.Instances[0].VpcId -ne $vpcId) {
                Write-Log "Instance '$instanceId' is in VPC '$($instance.Instances[0].VpcId)', which does not match specified VpcID '$vpcId'." "ERROR"
                return $false
            }
            if ($instance.Instances[0].Placement.AvailabilityZone -ne $availabilityZone) {
                Write-Log "Instance '$instanceId' is in AvailabilityZone '$($instance.Instances[0].Placement.AvailabilityZone)', which does not match specified AvailabilityZone '$availabilityZone'." "ERROR"
                return $false
            }
            if ($instanceName) {
                $instanceTags = $instance.Instances[0].Tags
                $nameTag = $instanceTags | Where-Object { $_.Key -eq 'Name' } | Select-Object -ExpandProperty Value
                if ($nameTag -ne $instanceName) {
                    Write-Log "Instance '$instanceId' has Name tag '$nameTag', which does not match specified InstanceName '$instanceName'." "ERROR"
                    return $false
                }
            }
            # Check if any of the security groups are already attached
            $currentSgIds = $instance.Instances[0].SecurityGroups | ForEach-Object { $_.GroupId }
            $alreadyAttached = $securityGroupIds | Where-Object { $_ -in $currentSgIds }
            if ($alreadyAttached) {
                Write-Log "Security group(s) $($alreadyAttached -join ', ') already attached to instance '$instanceId'. These will be skipped." "INFO"
            }
            Write-Log "Instance '$instanceId' is valid and running in VPC '$vpcId' and AvailabilityZone '$availabilityZone'."
        } catch {
            Write-Log "Failed to validate instance '$instanceId'. Error: $($_.Exception.Message)" "ERROR"
            return $false
        }
    }

    return @{ InstanceId = $instanceId; SecurityGroupIds = $securityGroupIds }
}

try {
    # Ensure the log directory exists
    $logDir = Split-Path -Path $LogFilePath -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -ErrorAction Stop > $null
    }

    # Import required AWS.Tools modules and ImportExcel
    try {
        Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.Common") -ErrorAction Stop
        Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.EC2") -ErrorAction Stop
        Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.SecurityToken") -ErrorAction Stop
        Import-Module -Name (Join-Path $PSModulesPath "ImportExcel") -ErrorAction Stop
        Write-Log "Successfully imported AWS.Tools modules (Common, EC2, SecurityToken) and ImportExcel" "INFO"
    } catch {
        Write-Log "Failed to import modules from $PSModulesPath. Error: $($_.Exception.Message)" "ERROR"
        exit 1
    }

    Write-Log "Starting security group attachment script (DryRun: $DryRun)"

    # Read Excel file
    Write-Log "Reading Excel file: $ExcelFilePath"
    if (-not (Test-Path $ExcelFilePath)) {
        throw "Excel file not found: $ExcelFilePath"
    }
    
    $sgConfigs = Import-Excel -Path $ExcelFilePath -WorksheetName "sg_attach" -ErrorAction Stop
    if ($sgConfigs.Count -eq 0) {
        throw "No security group configurations found in Excel file"
    }
    Write-Log "Found $($sgConfigs.Count) security group configurations in Excel"

    # Path to AWS config file
    $awsConfigPath = "$env:USERPROFILE\.aws\config"
    if (-not (Test-Path $awsConfigPath)) {
        throw "AWS config file not found: $awsConfigPath"
    }

    # Read config file into lines
    $configLines = Get-Content -Path $awsConfigPath

    # Process each security group configuration
    foreach ($config in $sgConfigs) {
        try {
            $accountId = $config.AccountId
            $accountName = $config.AccountName
            $ssoRole = $config.SSORole
            $instanceName = $config.InstanceName
            $instanceId = $config.InstanceId
            $vpcId = $config.VpcID

            # Clean names to match the profile format
            $cleanAccountName = $accountName -replace '[^\w\-]', ''
            $cleanSsoRole = $ssoRole -replace '[^\w\-]', ''
            $profileName = "sso-$cleanAccountName-$cleanSsoRole"

            Write-Log "Processing configuration for Account: $accountId ($accountName), VpcID: $vpcId, InstanceName: $instanceName, InstanceId: $instanceId, Profile: $profileName"

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
            $ssoAccountId = ($profileBlock | Where-Object { $_ -match '^sso_account_id\s*=\s*(.+)$' }) -replace '^sso_account_id\s*=\s*', ''
            $ssoRoleName = ($profileBlock | Where-Object { $_ -match '^sso_role_name\s*=\s*(.+)$' }) -replace '^sso_role_name\s*=\s*', ''
            $ssoSession = ($profileBlock | Where-Object { $_ -match '^sso_session\s*=\s*(.+)$' }) -replace '^sso_session\s*=\s*', ''
            $profileRegion = ($profileBlock | Where-Object { $_ -match '^region\s*=\s*(.+)$' }) -replace '^region\s*=\s*', ''

            if (-not $ssoStartUrl -or -not $profileRegion -or -not $ssoAccountId -or -not $ssoRoleName -or -not $ssoSession) {
                Write-Log "Incomplete SSO profile configuration for: $profileName. Required fields: sso_start_url, region, sso_account_id, sso_role_name, sso_session." "ERROR"
                continue
            }

            # Derive region from AvailabilityZone (e.g., eu-west-1a -> eu-west-1)
            $region = if ($config.AvailabilityZone) { $config.AvailabilityZone -replace '[a-z]$', '' } else { $profileRegion }
            if (-not $region) {
                Write-Log "No Region derived from AvailabilityZone or specified in AWS profile for: $profileName." "ERROR"
                continue
            }

            # Validate AccountId
            if ($ssoAccountId -ne $accountId) {
                Write-Log "AccountId ($accountId) in Excel does not match sso_account_id ($ssoAccountId) in profile: $profileName." "ERROR"
                continue
            }

            # Validate SSORole
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
                        Write-Log "Skipping security group attachment for InstanceName $instanceName, InstanceId $instanceId due to invalid SSO session." "ERROR"
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
            if (-not $preflightResult) {
                Write-Log "Preflight checks failed for configuration with InstanceName $instanceName, InstanceId $instanceId. Skipping attachment." "ERROR"
                continue
            }
            $resolvedInstanceId = $preflightResult.InstanceId
            $securityGroupIds = $preflightResult.SecurityGroupIds

            # Attach security groups to instance
            Write-Log "Processing security groups $($securityGroupIds -join ', ') for attachment to instance $resolvedInstanceId..."
            if ($DryRun) {
                Write-Log "Dry run: Would process security groups $($securityGroupIds -join ', ') for attachment to instance $resolvedInstanceId." "INFO"
            } else {
                try {
                    # Get current security groups
                    $instance = Get-EC2Instance -ProfileName $profileName -Region $region -InstanceId $resolvedInstanceId -ErrorAction Stop
                    $currentSgIds = $instance.Instances[0].SecurityGroups | ForEach-Object { $_.GroupId }
                    # Filter out already attached security groups
                    $sgsToAttach = [string[]]($securityGroupIds | Where-Object { $_ -notin $currentSgIds })
                    # Combine current and new security groups into a new array
                    $newSgIds = @()
                    foreach ($sgId in $currentSgIds) {
                        $newSgIds += $sgId
                    }
                    foreach ($sgId in $sgsToAttach) {
                        $newSgIds += $sgId
                    }
                    # Ensure uniqueness
                    $newSgIds = [string[]]($newSgIds | Sort-Object | Select-Object -Unique)
                    # Check security group limit (AWS allows up to 5 security groups per network interface)
                    if ($newSgIds.Count -gt 5) {
                        Write-Log "Cannot attach security groups to instance $resolvedInstanceId. Total security groups ($($newSgIds.Count)) exceeds AWS limit of 5." "ERROR"
                        continue
                    }
                    Write-Log "Current security groups: $($currentSgIds -join ', ')" "DEBUG"
                    if ($sgsToAttach.Count -eq 0) {
                        Write-Log "No new security groups to attach to instance $resolvedInstanceId. All specified groups are already attached." "INFO"
                    } else {
                        Write-Log "Security groups to attach:" "DEBUG"
                        foreach ($sgId in $sgsToAttach) {
                            Write-Log "  - $sgId" "DEBUG"
                        }
                        Write-Log "All security groups after attachment:" "DEBUG"
                        foreach ($sgId in $newSgIds) {
                            Write-Log "  - $sgId" "DEBUG"
                        }
                        # Attach security groups
                        Edit-EC2InstanceAttribute -InstanceId $resolvedInstanceId -Group $newSgIds -ProfileName $profileName -Region $region -ErrorAction Stop
                        Write-Log "Successfully attached security groups $($sgsToAttach -join ', ') to instance $resolvedInstanceId" "INFO"
                    }
                } catch {
                    Write-Log "Failed to attach security groups to instance $resolvedInstanceId. Error: $($_.Exception.Message)" "ERROR"
                    continue
                }
            }

            # Update Excel file with AttachedSecurityGroupIds and InstanceId (if resolved)
            try {
                Write-Log "Updating Excel file '$ExcelFilePath' with AttachedSecurityGroupIds '$($securityGroupIds -join ',')' and InstanceId '$resolvedInstanceId' for InstanceName '$instanceName', InstanceId '$instanceId'"
                $excelPackage = Open-ExcelPackage -Path $ExcelFilePath -ErrorAction Stop
                $worksheet = $excelPackage.Workbook.Worksheets["sg_attach"]
                if (-not $worksheet) {
                    throw "Worksheet 'sg_attach' not found in Excel file"
                }

                # Get headers
                $headers = @{}
                for ($col = 1; $col -le $worksheet.Dimension.Columns; $col++) {
                    $header = $worksheet.Cells[1, $col].Value
                    if ($header) {
                        $headers[$header] = $col
                    }
                }

                # Verify required columns
                if (-not $headers.ContainsKey('InstanceName') -and -not $headers.ContainsKey('InstanceId')) {
                    throw "Neither InstanceName nor InstanceId column found in Excel worksheet"
                }
                if (-not $headers.ContainsKey('AttachedSecurityGroupIds')) {
                    Write-Log "AttachedSecurityGroupIds column not found in Excel worksheet. Adding it." "WARN"
                    $newCol = $worksheet.Dimension.Columns + 1
                    $worksheet.Cells[1, $newCol].Value = 'AttachedSecurityGroupIds'
                    $headers['AttachedSecurityGroupIds'] = $newCol
                }
                if (-not $headers.ContainsKey('InstanceId')) {
                    Write-Log "InstanceId column not found in Excel worksheet. Adding it." "WARN"
                    $newCol = $worksheet.Dimension.Columns + 1
                    $worksheet.Cells[1, $newCol].Value = 'InstanceId'
                    $headers['InstanceId'] = $newCol
                }

                # Find the row for the configuration
                $rowFound = $false
                for ($row = 2; $row -le $worksheet.Dimension.Rows; $row++) {
                    $rowInstanceName = $worksheet.Cells[$row, $headers['InstanceName']].Value
                    $rowInstanceId = if ($headers.ContainsKey('InstanceId')) { $worksheet.Cells[$row, $headers['InstanceId']].Value } else { $null }
                    if (($instanceName -and $rowInstanceName -eq $instanceName) -or ($instanceId -and $rowInstanceId -eq $instanceId)) {
                        if ($DryRun) {
                            Write-Log "Dry run: Would update row $row, column AttachedSecurityGroupIds with value '$($securityGroupIds -join ',')' and InstanceId with '$resolvedInstanceId' for InstanceName '$instanceName', InstanceId '$instanceId'" "INFO"
                        } else {
                            $worksheet.Cells[$row, $headers['AttachedSecurityGroupIds']].Value = $securityGroupIds -join ','
                            $worksheet.Cells[$row, $headers['InstanceId']].Value = $resolvedInstanceId
                            Write-Log "Updated row $row, column AttachedSecurityGroupIds with value '$($securityGroupIds -join ',')' and InstanceId with '$resolvedInstanceId' for InstanceName '$instanceName', InstanceId '$instanceId'" "DEBUG"
                        }
                        $rowFound = $true
                        break
                    }
                }

                if (-not $rowFound) {
                    Write-Log "No row found with InstanceName '$instanceName' or InstanceId '$instanceId' in Excel worksheet" "ERROR"
                } else {
                    if (-not $DryRun) {
                        Close-ExcelPackage -ExcelPackage $excelPackage -ErrorAction Stop
                        # Verify the update
                        $excelPackageVerify = Open-ExcelPackage -Path $ExcelFilePath -ErrorAction Stop
                        $worksheetVerify = $excelPackageVerify.Workbook.Worksheets["sg_attach"]
                        $verified = $false
                        for ($row = 2; $row -le $worksheetVerify.Dimension.Rows; $row++) {
                            $rowInstanceName = $worksheetVerify.Cells[$row, $headers['InstanceName']].Value
                            $rowInstanceId = if ($headers.ContainsKey('InstanceId')) { $worksheetVerify.Cells[$row, $headers['InstanceId']].Value } else { $null }
                            if (($instanceName -and $rowInstanceName -eq $instanceName) -or ($instanceId -and $rowInstanceId -eq $instanceId)) {
                                if ($worksheetVerify.Cells[$row, $headers['AttachedSecurityGroupIds']].Value -eq ($securityGroupIds -join ',') -and 
                                    $worksheetVerify.Cells[$row, $headers['InstanceId']].Value -eq $resolvedInstanceId) {
                                    $verified = $true
                                    break
                                }
                            }
                        }
                        Close-ExcelPackage -ExcelPackage $excelPackageVerify -ErrorAction Stop
                        if ($verified) {
                            Write-Log "Successfully updated and verified Excel file with AttachedSecurityGroupIds '$($securityGroupIds -join ',')' and InstanceId '$resolvedInstanceId' for InstanceName '$instanceName', InstanceId '$instanceId'" "INFO"
                        } else {
                            Write-Log "Failed to verify AttachedSecurityGroupIds '$($securityGroupIds -join ',')' and InstanceId '$resolvedInstanceId' for InstanceName '$instanceName', InstanceId '$instanceId' in Excel file after save" "ERROR"
                        }
                    }
                }
            } catch {
                Write-Log "Failed to update Excel file with AttachedSecurityGroupIds '$($securityGroupIds -join ',')' and InstanceId '$resolvedInstanceId' for InstanceName '$instanceName', InstanceId '$instanceId'. Error: $($_.Exception.Message)" "ERROR"
            }

            # Clear credentials after processing
            if (-not $DryRun) {
                Clear-AWSCredential -ErrorAction SilentlyContinue
                Clear-DefaultAWSRegion -ErrorAction SilentlyContinue
            }

        } catch {
            Write-Log "Error processing configuration for Account: $accountId ($accountName), VpcID: $vpcId, InstanceName: $instanceName, InstanceId: $instanceId. Error: $($_.Exception.Message)" "ERROR"
            if (-not $DryRun) {
                Clear-AWSCredential -ErrorAction SilentlyContinue
                Clear-DefaultAWSRegion -ErrorAction SilentlyContinue
            }
            continue
        }
    }

    Write-Log "Security group attachment process completed"

} catch {
    Write-Log "Fatal error: $($_.Exception.Message)" "ERROR"
    exit 1
}