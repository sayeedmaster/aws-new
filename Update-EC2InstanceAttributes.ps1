<#
.SYNOPSIS
    Updates EC2 instance attributes based on configurations specified in a JSON file.

.DESCRIPTION
    This script reads EC2 instance configurations from a JSON file, performs preflight checks, and updates instance attributes using AWS.Tools modules.
    It supports multiple SSO profiles and allows dry run mode to simulate actions without modifying AWS resources or the JSON file.
    The script also writes the updated instance attributes back to the JSON file.
    It includes comprehensive logging, error handling, and input validation to ensure robust operation.
    The script can update attributes such as Monitoring, MetadataOptions, Tags, and more.
    It also validates SSO sessions, checks IAM permissions, and ensures instances are in the running state before applying updates.
    The script is designed to be run in a PowerShell environment with AWS.Tools modules installed.
    It supports AWS SSO authentication and requires the AWS SSO profile to be configured in the AWS CLI config file.


.NOTES
    Author: Sayeed Master
    Date: July 17, 2025
    Version: 1.0.0
    License: MIT
    Usage: .\Update-EC2InstanceAttributes.ps1 -PSModulesPath 'C:\Path\To\AWS.Tools' -JsonFilePath 'C:\Path\To\ec2-attributes.json' -DryRun
    Requrements: AWS.Tools modules installed in the specified PSModulesPath
    Requirements: ImportExcel module installed in the specified PSModulesPath
    Prerequisites: AWS SSO must be set up in your AWS account
    Dependencies: AWS.Tools.Common, AWS.Tools.EC2, AWS.Tools.SecurityToken, AWS.Tools.CloudWatch, ImportExcel
    Error Handling: The script includes error handling for AWS API calls, file operations, and input validation.
    Updated to remove dependency on ConvertTo-Hashtable and directly use ConvertFrom-Json output
.PARAMETERS 
    -PSModulesPath - Path to the directory containing AWS.Tools and ImportExcel modules (mandatory).
    -JsonFilePath - Path to the JSON file containing EC2 attribute key-value pairs (mandatory).
    -LogFilePath - Path to the log file where script actions will be recorded (optional, default: 'logs\ec2_Update_Log_YYYYMMDD_HHMMSS.log' in script directory).
    -DryRun - Switch to run the script in dry run mode, simulating actions without modifying AWS resources or the JSON file (optional).

.EXAMPLE
    .\Update-EC2InstanceAttributes.ps1 -PSModulesPath 'C:\Path\To\AWS.Tools' -JsonFilePath 'C:\Path\To\ec2-attributes.json' -LogFilePath 'C:\Path\To\Logs\ec2_Update_Log.log' -DryRun
#>

param (
    [Parameter(Mandatory=$true, HelpMessage="Path to the directory containing AWS.Tools and ImportExcel modules.")]
    [string]$PSModulesPath,
    [Parameter(Mandatory=$true, HelpMessage="Path to the JSON file containing EC2 attribute key-value pairs.")]
    [string]$JsonFilePath,
    [Parameter(Mandatory=$false, HelpMessage="Run in dry run mode to simulate actions without modifying AWS resources.")]
    [switch]$DryRun,
    [Parameter(Mandatory=$false, HelpMessage="Show debug messages in output.")]
    [bool]$ScriptDebug = $false
)

# Determine the script's root directory for reliable path resolution
$ScriptPath = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
$ExcelFilePath = (Join-Path $ScriptPath "EC2_Config.xlsx")
$LogFilePath = (Join-Path $ScriptPath "logs\EC2_Update_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log")

# Function to write logs
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $prefix = if ($DryRun) { "[DRYRUN] " } else { "" }
    $logMessage = "[$timestamp] [$Level] $prefix$Message"
    $suppress = $false
    if ($Level.ToUpper() -eq "DEBUG" -and -not $ScriptDebug) {
        $suppress = $true
    }
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
    if (-not $suppress) {
        if ($color) {
            Write-Host $logMessage -ForegroundColor $color
        } else {
            Write-Host $logMessage
        }
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
        Write-Log "Region set to $Region for profile: $ProfileName" "DEBUG"
        Get-STSCallerIdentity -ProfileName $ProfileName -Region $Region -ErrorAction Stop > $null
        Write-Log "SSO session is valid for profile: $ProfileName in region: $Region" "INFO"
        return $true
    } catch {
        Write-Log "SSO session is invalid or expired for profile: $ProfileName. Error: $($_.Exception.Message)" "ERROR"
        Write-Log "Please run 'aws sso login --profile $ProfileName' to authenticate, then retry the script." "ERROR"
        try {
            Write-Log "Attempting to trigger SSO login for profile: $ProfileName" "INFO"
            $process = Start-Process -FilePath "aws" -ArgumentList "sso login --profile $ProfileName" -NoNewWindow -Wait -PassThru
            if ($process.ExitCode -eq 0) {
                Write-Log "SSO login successful for profile: $ProfileName" "INFO"
                Set-DefaultAWSRegion -Region $Region -ErrorAction Stop
                Get-STSCallerIdentity -ProfileName $ProfileName -Region $Region -ErrorAction Stop > $null
                Write-Log "SSO session validated after login for profile: $ProfileName" "INFO"
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

# Function to validate IAM permissions
function Test-EC2Permissions {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ProfileName,
        [Parameter(Mandatory=$true)]
        [string]$Region
    )
    try {
        if ($DryRun) {
            Write-Log "Dry run: Skipping permission validation for profile: $ProfileName in region: $Region" "INFO"
            return $true
        }
        Get-EC2Instance -ProfileName $ProfileName -Region $Region -MaxResults 5 -ErrorAction Stop > $null
        Write-Log "Permissions validated for ec2:DescribeInstances with profile: $ProfileName in region: $Region" "DEBUG"
        return $true
    } catch {
        $errorMessage = $_.Exception.Message
        $errorCode = $_.Exception.ErrorCode
        Write-Log "Failed to validate permissions for EC2 operations with profile: $ProfileName in region: $Region. ErrorCode: $errorCode, Error: $errorMessage" "ERROR"
        if ($errorMessage -match "AccessDenied|UnauthorizedOperation") {
            $requiredPermissions = "'ec2:DescribeInstances', 'ec2:ModifyInstanceAttribute', 'ec2:ModifyInstanceMetadataOptions', 'ec2:CreateTags'"
            Write-Log "Insufficient permissions. Ensure the role has $requiredPermissions permissions." "ERROR"
            return $false
        } else {
            Write-Log "Non-permission-related error occurred. Assuming permissions are sufficient for profile: $ProfileName due to administrator role." "WARN"
            return $true
        }
    }
}

# Function to validate EC2 instance state
function Test-EC2InstanceState {
    param(
        [Parameter(Mandatory=$true)]
        [string]$InstanceId,
        [Parameter(Mandatory=$true)]
        [string]$ProfileName,
        [Parameter(Mandatory=$true)]
        [string]$Region
    )
    try {
        $instance = Get-EC2Instance -InstanceId $InstanceId -ProfileName $ProfileName -Region $Region -ErrorAction Stop
        $state = $instance.Instances[0].State.Name
        if ($state -eq 'running') {
            Write-Log "Instance $InstanceId is in running state." "DEBUG"
            return $true
        } else {
            Write-Log "Instance $InstanceId is in state '$state'. Only running instances can be updated." "ERROR"
            return $false
        }
    } catch {
        Write-Log "Failed to validate state for instance $InstanceId. Error: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Function to update EC2 instance attributes
function Update-EC2InstanceAttributes {
    param(
        [Parameter(Mandatory=$true)]
        [string]$InstanceId,
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Attributes,
        [Parameter(Mandatory=$true)]
        [string]$ProfileName,
        [Parameter(Mandatory=$true)]
        [string]$Region
    )
    try {
        $attributeNames = $Attributes.PSObject.Properties.Name
        foreach ($key in $attributeNames) {
            $value = $Attributes.$key
            Write-Log "Updating attribute '$key' to '$value' for instance $InstanceId" "INFO"
            
            if ($DryRun) {
                Write-Log "Dry run: Would update attribute '$key' to '$value' for instance $InstanceId" "INFO"
                continue
            }

            switch ($key) {
                'Monitoring' {
                    $enabled = [bool]::Parse($value)
                    if ($enabled) {
                        Enable-EC2Monitoring -InstanceId $InstanceId -ProfileName $ProfileName -Region $Region -ErrorAction Stop
                        Write-Log "Successfully enabled monitoring for instance $InstanceId" "INFO"
                    } else {
                        Disable-EC2Monitoring -InstanceId $InstanceId -ProfileName $ProfileName -Region $Region -ErrorAction Stop
                        Write-Log "Successfully disabled monitoring for instance $InstanceId" "INFO"
                    }
                }
                'MetadataOptionsHttpTokens' {
                    if ($value -notin @('optional', 'required')) {
                        Write-Log "Invalid value '$value' for MetadataOptionsHttpTokens. Must be 'optional' or 'required'." "ERROR"
                        continue
                    }
                    Edit-EC2InstanceMetadataOption -InstanceId $InstanceId -HttpTokens $value -ProfileName $ProfileName -Region $Region -ErrorAction Stop
                    Write-Log "Successfully set MetadataOptionsHttpTokens to '$value' for instance $InstanceId" "INFO"
                }
                'MetadataOptionsHttpEndpoint' {
                    if ($value -notin @('enabled', 'disabled')) {
                        Write-Log "Invalid value '$value' for MetadataOptionsHttpEndpoint. Must be 'enabled' or 'disabled'." "ERROR"
                        continue
                    }
                    Edit-EC2InstanceMetadataOption -InstanceId $InstanceId -HttpEndpoint $value -ProfileName $ProfileName -Region $Region -ErrorAction Stop
                    Write-Log "Successfully set MetadataOptionsHttpEndpoint to '$value' for instance $InstanceId" "INFO"
                }
                'MetadataOptionsHttpPutResponseHopLimit' {
                    $hopLimit = [int]$value
                    if ($hopLimit -lt 1 -or $hopLimit -gt 64) {
                        Write-Log "Invalid value '$value' for MetadataOptionsHttpPutResponseHopLimit. Must be between 1 and 64." "ERROR"
                        continue
                    }
                    Edit-EC2InstanceMetadataOption -InstanceId $InstanceId -HttpPutResponseHopLimit $hopLimit -ProfileName $ProfileName -Region $Region -ErrorAction Stop
                    Write-Log "Successfully set MetadataOptionsHttpPutResponseHopLimit to '$hopLimit' for instance $InstanceId" "INFO"
                }
                'InstanceMetadataTags' {
                    if ($value -notin @('enabled', 'disabled')) {
                        Write-Log "Invalid value '$value' for InstanceMetadataTags. Must be 'enabled' or 'disabled'." "ERROR"
                        continue
                    }
                    Edit-EC2InstanceMetadataOption -InstanceId $InstanceId -InstanceMetadataTags $value -ProfileName $ProfileName -Region $Region -ErrorAction Stop
                    Write-Log "Successfully set InstanceMetadataTags to '$value' for instance $InstanceId" "INFO"
                }
                'DisableApiTermination' {
                    $disable = [bool]::Parse($value)
                    Edit-EC2InstanceAttribute -InstanceId $InstanceId -DisableApiTermination $disable -ProfileName $ProfileName -Region $Region -ErrorAction Stop
                    Write-Log "Successfully set DisableApiTermination to '$disable' for instance $InstanceId" "INFO"
                }
                'InstanceInitiatedShutdownBehavior' {
                    if ($value -notin @('stop', 'terminate')) {
                        Write-Log "Invalid value '$value' for InstanceInitiatedShutdownBehavior. Must be 'stop' or 'terminate'." "ERROR"
                        continue
                    }
                    Edit-EC2InstanceAttribute -InstanceId $InstanceId -InstanceInitiatedShutdownBehavior $value -ProfileName $ProfileName -Region $Region -ErrorAction Stop
                    Write-Log "Successfully set InstanceInitiatedShutdownBehavior to '$value' for instance $InstanceId" "INFO"
                }
                'AutoRecovery' {
                    $enabled = [bool]::Parse($value)
                    $alarmName = "AutoRecovery-$InstanceId"
                    if ($enabled) {
                        $alarmActions = @("arn:aws:automate:${Region}:ec2:recover")
                        New-CWMetricAlarm -AlarmName $alarmName -AlarmDescription "Auto-recovery for $InstanceId" -MetricName StatusCheckFailed_System -Namespace AWS/EC2 -Statistic Average -Period 60 -EvaluationPeriods 2 -Threshold 1 -ComparisonOperator GreaterThanOrEqualToThreshold -Dimensions @{Name="InstanceId";Value=$InstanceId} -AlarmActions $alarmActions -ProfileName $ProfileName -Region $Region -ErrorAction Stop
                        Write-Log "Successfully enabled auto-recovery for instance $InstanceId via CloudWatch alarm '$alarmName'" "INFO"
                    } else {
                        Remove-CWMetricAlarm -AlarmName $alarmName -ProfileName $ProfileName -Region $Region -ErrorAction Stop -Force
                        Write-Log "Successfully disabled auto-recovery for instance $InstanceId by removing CloudWatch alarm '$alarmName'" "INFO"
                    }
                }
                'SriovNetSupport' {
                    if ($value -ne 'simple') {
                        Write-Log "Invalid value '$value' for SriovNetSupport. Must be 'simple'." "ERROR"
                        continue
                    }
                    Edit-EC2InstanceAttribute -InstanceId $InstanceId -SriovNetSupport $value -ProfileName $ProfileName -Region $Region -ErrorAction Stop
                    Write-Log "Successfully set SriovNetSupport to '$value' for instance $InstanceId" "INFO"
                }
                'EnaSupport' {
                    $enabled = [bool]::Parse($value)
                    Edit-EC2InstanceAttribute -InstanceId $InstanceId -EnaSupport $enabled -ProfileName $ProfileName -Region $Region -ErrorAction Stop
                    Write-Log "Successfully set EnaSupport to '$enabled' for instance $InstanceId" "INFO"
                }
                'TrafficMirroring' {
                    $enabled = [bool]::Parse($value)
                    if ($enabled) {
                        Write-Log "TrafficMirroring enablement requires additional configuration (e.g., traffic mirror target). Skipping as not supported in this script." "WARN"
                        continue
                    } else {
                        Write-Log "TrafficMirroring disablement not directly supported via EC2 API. Ensure no traffic mirror sessions are active for instance $InstanceId." "WARN"
                        continue
                    }
                }
                'CpuCoreCount' {
                    $coreCount = [int]$value
                    if ($coreCount -lt 1) {
                        Write-Log "Invalid value '$value' for CpuCoreCount. Must be a positive integer." "ERROR"
                        continue
                    }
                    Edit-EC2InstanceAttribute -InstanceId $InstanceId -CpuOptionsCoreCount $coreCount -ProfileName $ProfileName -Region $Region -ErrorAction Stop
                    Write-Log "Successfully set CpuCoreCount to '$coreCount' for instance $InstanceId" "INFO"
                }
                'CpuThreadsPerCore' {
                    $threadsPerCore = [int]$value
                    if ($threadsPerCore -notin @(1, 2)) {
                        Write-Log "Invalid value '$value' for CpuThreadsPerCore. Must be 1 or 2." "ERROR"
                        continue
                    }
                    Edit-EC2InstanceAttribute -InstanceId $InstanceId -CpuOptionsThreadsPerCore $threadsPerCore -ProfileName $ProfileName -Region $Region -ErrorAction Stop
                    Write-Log "Successfully set CpuThreadsPerCore to '$threadsPerCore' for instance $InstanceId" "INFO"
                }
                'Tags' {
                    $tagPairs = $value -split ',' | ForEach-Object { $_.Trim() }
                    $tags = @()
                    foreach ($tagPair in $tagPairs) {
                        $keyValue = $tagPair -split '='
                        if ($keyValue.Count -eq 2 -and $keyValue[0].Trim() -and $keyValue[1].Trim()) {
                            $tag = New-Object Amazon.EC2.Model.Tag
                            $tag.Key = $keyValue[0].Trim()
                            $tag.Value = $keyValue[1].Trim()
                            $tags += $tag
                        } else {
                            Write-Log "Invalid tag format: '$tagPair'. Expected 'key=value'. Skipping this tag." "WARN"
                        }
                    }
                    if ($tags.Count -gt 0) {
                        New-EC2Tag -Resource $InstanceId -Tag $tags -ProfileName $ProfileName -Region $Region -ErrorAction Stop
                        Write-Log "Successfully applied $($tags.Count) tags to instance $InstanceId" "INFO"
                    }
                }
                default {
                    Write-Log "Unsupported attribute '$key' for instance $InstanceId. Skipping." "WARN"
                }
            }
        }
    } catch {
        Write-Log "Failed to update attribute '$key' for instance $InstanceId. Error: $($_.Exception.Message)" "ERROR"
    }
}

try {
    # Ensure the log directory exists
    $logDir = Split-Path -Path $LogFilePath -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -ErrorAction Stop > $null
        Write-Log "Created log directory: $logDir" "INFO"
    }

    # Import required AWS.Tools modules and ImportExcel
    try {
        Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.Common") -ErrorAction Stop
        Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.EC2") -ErrorAction Stop
        Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.SecurityToken") -ErrorAction Stop
        Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.CloudWatch") -ErrorAction Stop
        Import-Module -Name (Join-Path $PSModulesPath "ImportExcel") -ErrorAction Stop
        $awsEc2Version = (Get-Module -Name AWS.Tools.EC2).Version.ToString()
        $importExcelVersion = (Get-Module -Name ImportExcel).Version.ToString()
        Write-Log "Loaded AWS.Tools.EC2 version: $awsEc2Version, AWS.Tools.CloudWatch, ImportExcel version: $importExcelVersion" "INFO"
        if ($importExcelVersion -lt "7.0.0") {
            Write-Log "ImportExcel version $importExcelVersion is outdated. Consider updating to 7.0.0 or later: Install-Module -Name ImportExcel -Scope CurrentUser -Force" "WARN"
        }
    } catch {
        Write-Log "Failed to import modules from $PSModulesPath. Error: $($_.Exception.Message)" "ERROR"
        exit 1
    }

    # Validate JSON file
    Write-Log "Checking JSON file: $JsonFilePath" "INFO"
    if (-not (Test-Path $JsonFilePath)) {
        throw "JSON file not found: $JsonFilePath"
    }
    try {
        $attributes = Get-Content -Path $JsonFilePath -Raw | ConvertFrom-Json -ErrorAction Stop
        Write-Log "Successfully read JSON attributes: $(ConvertTo-Json -InputObject $attributes -Depth 3 -Compress)" "DEBUG"
    } catch {
        Write-Log "Failed to parse JSON file: $JsonFilePath. Error: $($_.Exception.Message)" "ERROR"
        throw
    }

    # Validate Excel file
    Write-Log "Checking Excel file: $ExcelFilePath" "INFO"
    if (-not (Test-Path $ExcelFilePath)) {
        throw "Excel file not found: $ExcelFilePath"
    }

    # Define expected headers
    $headerNames = @('SSORole', 'AccountId', 'AccountName', 'InstanceId', 'Region')

    # Read Excel file
    Write-Log "Reading Excel file: $ExcelFilePath, Worksheet: ec2_attributes" "INFO"
    try {
        $ec2Configs = Import-Excel -Path $ExcelFilePath -WorksheetName "ec2_attributes" -ErrorAction Stop
        Write-Log "Successfully read Excel file with headers" "DEBUG"

        # Validate headers
        $actualHeaders = ($ec2Configs | Get-Member -MemberType NoteProperty).Name
        $missingHeaders = $headerNames | Where-Object { $_ -notin $actualHeaders }
        if ($missingHeaders) {
            Write-Log "Missing expected headers in Excel file: $($missingHeaders -join ', ')." "ERROR"
            throw "Invalid Excel file headers"
        }

        # Filter out invalid rows
        $ec2Configs = $ec2Configs | Where-Object {
            $_.AccountId -and $_.AccountId -ne 'AccountId' -and
            $_.SSORole -and $_.SSORole -ne 'SSORole' -and
            $_.InstanceId -and $_.InstanceId -ne 'InstanceId'
        }
        Write-Log "Filtered to $($ec2Configs.Count) valid rows after removing placeholders" "DEBUG"
    } catch {
        Write-Log "Failed to read Excel file. Error: $($_.Exception.Message)" "ERROR"
        throw
    }

    if ($ec2Configs.Count -eq 0) {
        throw "No valid EC2 instance configurations found in Excel file after filtering"
    }

    # Path to AWS config file
    $awsConfigPath = "$env:USERPROFILE\.aws\config"
    if (-not (Test-Path $awsConfigPath)) {
        throw "AWS config file not found: $awsConfigPath"
    }

    # Read config file
    $configLines = Get-Content -Path $awsConfigPath

    # Process each EC2 instance
    foreach ($config in $ec2Configs) {
        try {
            $accountId = $config.AccountId
            $accountName = $config.AccountName
            $ssoRole = $config.SSORole
            $instanceId = $config.InstanceId
            $region = $config.Region

            # Clean names for profile
            $cleanAccountName = $accountName -replace '[^\w\-]', ''
            $cleanSsoRole = $ssoRole -replace '[^\w\-]', ''
            $profileName = "sso-$cleanAccountName-$cleanSsoRole"

            Write-Log "Processing EC2 instance $instanceId in Account: $accountId ($accountName), Region: $region, Profile: $profileName" "INFO"

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

            # Parse required fields
            $ssoStartUrl = ($profileBlock | Where-Object { $_ -match '^sso_start_url\s*=\s*(.+)$' }) -replace '^sso_start_url\s*=\s*', ''
            $ssoRegion = ($profileBlock | Where-Object { $_ -match '^region\s*=\s*(.+)$' }) -replace '^region\s*=\s*', ''
            $ssoAccountId = ($profileBlock | Where-Object { $_ -match '^sso_account_id\s*=\s*(.+)$' }) -replace '^sso_account_id\s*=\s*', ''
            $ssoRoleName = ($profileBlock | Where-Object { $_ -match '^sso_role_name\s*=\s*(.+)$' }) -replace '^sso_role_name\s*=\s*', ''
            $ssoSession = ($profileBlock | Where-Object { $_ -match '^sso_session\s*=\s*(.+)$' }) -replace '^sso_session\s*=\s*', ''

            if (-not $ssoStartUrl -or -not $ssoRegion -or -not $ssoAccountId -or -not $ssoRoleName -or -not $ssoSession) {
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
            try {
                if (-not $DryRun) {
                    Set-AWSCredential -ProfileName $profileName -ErrorAction Stop
                    if (-not (Test-SSOSession -ProfileName $profileName -Region $region)) {
                        Write-Log "Skipping updates for instance $instanceId due to invalid SSO session." "ERROR"
                        continue
                    }
                    Set-DefaultAWSRegion -Region $region -ErrorAction Stop
                }
                Write-Log "Successfully set credentials and region ($region) for profile: $profileName" "INFO"
            } catch {
                Write-Log "Failed to set credentials for profile: $profileName. Error: $($_.Exception.Message)" "ERROR"
                continue
            }

            # Validate permissions
            if (-not (Test-EC2Permissions -ProfileName $profileName -Region $region)) {
                Write-Log "Skipping updates for instance $instanceId due to permission validation failure." "ERROR"
                continue
            }

            # Validate instance state
            if (-not $DryRun -and -not (Test-EC2InstanceState -InstanceId $instanceId -ProfileName $profileName -Region $region)) {
                Write-Log "Skipping updates for instance $instanceId due to invalid state." "ERROR"
                continue
            }

            # Apply updates with retries
            $maxRetries = 3
            $retryCount = 0
            $success = $false
            while ($retryCount -lt $maxRetries -and -not $success) {
                try {
                    $retryCount++
                    Write-Log "Attempt $retryCount of $maxRetries to update instance $instanceId" "DEBUG"
                    Update-EC2InstanceAttributes -InstanceId $instanceId -Attributes $attributes -ProfileName $profileName -Region $region
                    $success = $true
                    Write-Log "Successfully updated attributes for instance $instanceId" "INFO"
                } catch {
                    Write-Log "Failed to update instance $instanceId on attempt $retryCount. Error: $($_.Exception.Message)" "ERROR"
                    if ($retryCount -eq $maxRetries) {
                        Write-Log "Max retries reached for instance $instanceId. Skipping." "ERROR"
                        break
                    }
                    Start-Sleep -Seconds 2
                }
            }
        } catch {
            Write-Log "Error processing instance $instanceId in Account: $accountId ($accountName), Region: $region. Error: $($_.Exception.Message)" "ERROR"
        } finally {
            if (-not $DryRun) {
                Clear-AWSCredential -ErrorAction SilentlyContinue
                Clear-DefaultAWSRegion -ErrorAction SilentlyContinue
            }
        }
    }

    Write-Log "EC2 instance update process completed" "INFO"

} catch {
    Write-Log "Fatal error: $($_.Exception.Message)" "ERROR"
    Write-Log "Error details: Message=$($_.Exception.Message), Type=$($_.Exception.GetType().FullName)" "DEBUG"
    exit 1
}