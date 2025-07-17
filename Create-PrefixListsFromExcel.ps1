<#
.SYNOPSIS
    Creates and manages AWS prefix lists from Excel configuration.

.DESCRIPTION
    This script reads prefix list configurations from an Excel file, performs preflight checks, and creates prefix lists using AWS.Tools modules.
    It supports multiple SSO profiles and allows dry run mode to simulate actions without modifying AWS resources or the Excel file.
    The script also writes the created prefix list's ID back to the Excel file.
    It performs various preflight checks including:
    - Validating prefix list name uniqueness in the specified VPC
    - Checking for existing prefix lists and creating new ones if necessary
    - Logging actions and errors to a specified log file
    - It also supports skipping permission validation for accounts with full administrator access using the -SkipPermissionValidation switch.
    - The script can be run in dry run mode using the -DryRun switch, which simulates actions without modifying AWS resources or the Excel file.
    
.NOTES
    Author: Sayeed Master
    Date: July 17, 2025
    Version: 2.0.0
    License: MIT
    Usage: .\Create-PrefixListsFromExcel.ps1 -PSModulesPath 'C:\Path\To\AWS.Tools' -DryRun -LogFilePath 'C:\Path\To\Logs\PrefixList_Create_Log.log'
    Requrements: AWS.Tools modules installed in the specified PSModulesPath
    Requirements: ImportExcel module installed in the specified PSModulesPath
    Prerequisites: AWS SSO must be set up in your AWS account
    Prerequisites: AWS CLI must be installed and configured in your environment for prefix list rules.
    Prerequisites: Ensure the AWS.Tools and ImportExcel modules are available in the specified PSModulesPath.
    Prerequisites: Ensure the AWS CLI is installed and available in your PATH for prefix list rules.
    Prerequisites: Ensure the AWS config file exists at $env:USERPROFILE\.aws\config with the required SSO profile configuration.

.PARAMETERS 
    PSModulesPath
        Path to the directory containing AWS.Tools and ImportExcel modules.
        Default: Current script directory.

    ExcelFilePath
        Path to the Excel file containing prefix list configurations.
        Default: "EC2_Config.xlsx" in the current script directory.

    LogFilePath
        Path to the log file where script actions and errors will be recorded.
        Default: "logs\PrefixList_Create_Log_YYYYMMDD_HHMMSS.log" in the current script directory.

    DryRun
        Run in dry run mode to simulate actions without modifying AWS resources or the Excel file.
        Default: False.

    ScriptDebug
        Show debug messages in output.
        Default: False.
        Use -ScriptDebug to enable debug messages for detailed logging.
.EXAMPLE
    .\Create-PrefixListsFromExcel.ps1 -PSModulesPath 'C:\Path\To\AWS.Tools' -ExcelFilePath 'C:\Path\To\EC2_Config.xlsx' -LogFilePath 'C:\Path\To\Logs\EC2_Launch_Log.log' -DryRun
#>

param (
    [Parameter(Mandatory=$true, HelpMessage="Path to the directory containing AWS.Tools and ImportExcel modules.")]
    [string]$PSModulesPath,
    [Parameter(Mandatory=$false)]
    [string]$ExcelFilePath = (Join-Path $PSScriptRoot "EC2_Config.xlsx"),
    [Parameter(Mandatory=$false)]
    [string]$LogFilePath = (Join-Path $PSScriptRoot "logs\PrefixList_Create_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"),
    [Parameter(Mandatory=$false, HelpMessage="Run in dry run mode to simulate actions without modifying AWS resources or the Excel file.")]
    [switch]$DryRun,
    [Parameter(Mandatory=$false, HelpMessage="Show debug messages in output.")]
    [bool]$ScriptDebug = $false
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

# Function for preflight checks
function Invoke-PreflightChecks {
    param(
        [Parameter(Mandatory=$true)]
        $ConfigGroup,
        [Parameter(Mandatory=$true)]
        [string]$ProfileName,
        [Parameter(Mandatory=$true)]
        [string]$Region
    )
    $prefixListName = $ConfigGroup[0].PrefixListName
    Write-Log "Running preflight checks for prefix list creation for configuration with PrefixListName '$prefixListName'..." "INFO"

    # --- Required Fields Check ---
    $requiredFields = @('SSORole', 'AccountId', 'AccountName', 'VpcID', 'PrefixListName', 'MaxEntries', 'CIDR')
    foreach ($config in $ConfigGroup) {
        foreach ($field in $requiredFields) {
            if (-not $config.$field -or $config.$field -eq $field) {
                Write-Log "Invalid or missing value for $field ('$($config.$field)') in row for PrefixListName '$prefixListName'. Skipping group." "ERROR"
                return $false
            }
        }
    }

    # --- VPC Check ---
    $vpcId = $ConfigGroup[0].VpcID
    if ($DryRun) {
        Write-Log "Dry run: Assuming VPC '$vpcId' exists." "INFO"
    } else {
        try {
            Get-EC2Vpc -ProfileName $ProfileName -Region $Region -VpcId $vpcId -ErrorAction Stop > $null
            Write-Log "VPC '$vpcId' found." "DEBUG"
        } catch {
            Write-Log "VPC '$vpcId' not found. Error: $($_.Exception.Message)" "ERROR"
            return $false
        }
    }

    # --- Prefix List Existence Check ---
    $prefixListId = $ConfigGroup[0].PrefixListId
    if ($prefixListId -and $prefixListId -match '^pl-[0-9a-f]{17}$') {
        if ($DryRun) {
            Write-Log "Dry run: Assuming prefix list ID '$prefixListId' exists for PrefixListName '$prefixListName'." "INFO"
        } else {
            try {
                $existingPrefixList = Get-EC2ManagedPrefixList -ProfileName $ProfileName -Region $Region -PrefixListId $prefixListId -ErrorAction Stop
                if ($existingPrefixList) {
                    Write-Log "Prefix list with ID '$prefixListId' already exists for PrefixListName '$prefixListName'. Skipping creation." "WARN"
                    return @{ 
                        PrefixListName = $prefixListName
                        PrefixListId = $prefixListId
                        SkipCreation = $true
                    }
                }
            } catch {
                Write-Log "PrefixListId '$prefixListId' is invalid or does not exist. Proceeding with creation checks. Error: $($_.Exception.Message)" "WARN"
            }
        }
    }

    # --- Prefix List Name Check ---
    if ($DryRun) {
        Write-Log "Dry run: Assuming prefix list name '$prefixListName' is valid and unique." "INFO"
    } else {
        try {
            $existingPrefixList = Get-EC2ManagedPrefixList -ProfileName $ProfileName -Region $Region -Filter @{Name="prefix-list-name"; Values=$prefixListName} -ErrorAction Stop
            if ($existingPrefixList) {
                Write-Log "Prefix list with name '$prefixListName' already exists in region '$Region' with ID '$($existingPrefixList.PrefixListId)'. Skipping creation." "WARN"
                return @{ 
                    PrefixListName = $prefixListName
                    PrefixListId = $existingPrefixList.PrefixListId
                    SkipCreation = $true
                }
            }
            Write-Log "Prefix list name '$prefixListName' is available." "DEBUG"
        } catch {
            Write-Log "Failed to check prefix list name '$prefixListName'. Error: $($_.Exception.Message)" "ERROR"
            return $false
        }
    }

    # --- MaxEntries Check ---
    $maxEntries = $ConfigGroup[0].MaxEntries
    if (-not $maxEntries -or $maxEntries -lt 1) {
        Write-Log "MaxEntries must be a positive integer for PrefixListName '$prefixListName'. Found: '$maxEntries'." "ERROR"
        return $false
    }

    # --- Entries Check ---
    $entries = @($ConfigGroup | ForEach-Object { @{ Cidr = $_.CIDR; Description = $_.CIDRDescription } })
    if ($entries.Count -eq 0) {
        Write-Log "No CIDR entries specified for PrefixListName '$prefixListName'. At least one CIDR block is required." "ERROR"
        return $false
    }
    if ($entries.Count -gt $maxEntries) {
        Write-Log "Number of entries ($($entries.Count)) exceeds MaxEntries ($maxEntries) for PrefixListName '$prefixListName'." "ERROR"
        return $false
    }
    foreach ($entry in $entries) {
        $cidr = $entry.Cidr
        if (-not $cidr) {
            Write-Log "Missing CIDR for an entry in PrefixListName '$prefixListName'." "ERROR"
            return $false
        }
        if ($cidr -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$') {
            Write-Log "Invalid CIDR format: '$cidr' for PrefixListName '$prefixListName'. Expected format: x.x.x.x/y." "ERROR"
            return $false
        }
    }
    Write-Log "Validated $($entries.Count) CIDR entries for PrefixListName '$prefixListName': $(($entries | ForEach-Object { "$($_.Cidr) ($($_.Description))" }) -join ', ')" "DEBUG"

    # --- Tag Check ---
    $tag = $ConfigGroup[0].Tags
    $tagKey = $null
    $tagValue = $null
    if ($tag) {
        if ($tag -match '^([^=]+)=([^=]+)$') {
            $tagKey = $matches[1].Trim()
            $tagValue = $matches[2].Trim()
            Write-Log "Validated tag for PrefixListName '$prefixListName': $tagKey=$tagValue" "DEBUG"
        } else {
            Write-Log "Invalid tag format for PrefixListName '$prefixListName': '$tag'. Expected format: key=value. Tag will not be applied." "WARN"
            $tag = $null
        }
    }

    return @{ 
        PrefixListName = $prefixListName
        MaxEntries = $maxEntries
        Entries = $entries
        VpcId = $vpcId
        TagKey = $tagKey
        TagValue = $tagValue
        SkipCreation = $false
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
        Import-Module -Name (Join-Path $PSModulesPath "ImportExcel") -ErrorAction Stop
        $importExcelVersion = (Get-Module -Name ImportExcel).Version.ToString()
        Write-Log "Successfully imported AWS.Tools modules (Common, EC2, SecurityToken) and ImportExcel version: $importExcelVersion" "INFO"
        if ($importExcelVersion -lt "7.0.0") {
            Write-Log "ImportExcel version $importExcelVersion is outdated. Consider updating to 7.0.0 or later for better compatibility: Install-Module -Name ImportExcel -Scope CurrentUser -Force" "WARN"
        }
    } catch {
        Write-Log "Failed to import modules from $PSModulesPath. Error: $($_.Exception.Message)" "ERROR"
        exit 1
    }

    Write-Log "Starting prefix list creation script (DryRun: $DryRun, ScriptDebug: $ScriptDebug)" "INFO"

    # Validate Excel file existence
    Write-Log "Checking Excel file: $ExcelFilePath" "INFO"
    if (-not (Test-Path $ExcelFilePath)) {
        throw "Excel file not found: $ExcelFilePath"
    }

    # Define expected headers
    $headerNames = @(
        'SSORole',
        'AccountId',
        'AccountName',
        'AvailabilityZone',
        'VpcID',
        'PrefixListName',
        'PLDescription',
        'MaxEntries',
        'CIDR',
        'CIDRDescription',
        'Tags',
        'PrefixListId'
    )

    # Read Excel file with dual-strategy approach
    Write-Log "Reading Excel file: $ExcelFilePath, Worksheet: prefix_list" "INFO"
    $plConfigs = $null
    try {
        # First attempt: read with headers
        $plConfigs = Import-Excel -Path $ExcelFilePath -WorksheetName "prefix_list" -ErrorAction Stop
        Write-Log "Successfully read Excel file with headers" "DEBUG"

        # Validate headers
        $actualHeaders = ($plConfigs | Get-Member -MemberType NoteProperty).Name
        $missingHeaders = $headerNames | Where-Object { $_ -notin $actualHeaders }
        if ($missingHeaders) {
            Write-Log "Missing expected headers in Excel file: $($missingHeaders -join ', '). Falling back to -NoHeader mode." "WARN"
            throw "Missing headers"
        }

        # Filter out invalid rows (e.g., header row or placeholders)
        $plConfigs = $plConfigs | Where-Object {
            $_.AccountId -and $_.AccountId -ne 'AccountId' -and
            $_.SSORole -and $_.SSORole -ne 'SSORole' -and
            $_.PrefixListName -and $_.PrefixListName -ne 'PrefixListName'
        }
        Write-Log "Filtered to $($plConfigs.Count) valid rows after removing placeholders" "DEBUG"
    } catch {
        Write-Log "Failed to read Excel file with headers. Error: $($_.Exception.Message). Attempting to read with -NoHeader and explicit headers." "WARN"
        try {
            $plConfigs = Import-Excel -Path $ExcelFilePath -WorksheetName "prefix_list" -NoHeader -HeaderName $headerNames -ErrorAction Stop
            # Skip the header row (P1, P2, etc. are default column names without headers)
            $plConfigs = $plConfigs | Where-Object {
                $_.P1 -and $_.P1 -ne 'SSORole' -and
                $_.P2 -and $_.P2 -ne 'AccountId' -and
                $_.P6 -and $_.P6 -ne 'PrefixListName'
            }
            Write-Log "Successfully read Excel file with -NoHeader and explicit headers" "DEBUG"
        } catch {
            Write-Log "Failed to read Excel file with -NoHeader. Error: $($_.Exception.Message)" "ERROR"
            throw "Unable to read Excel file after attempting both header and no-header modes"
        }
    }

    if ($plConfigs.Count -eq 0) {
        throw "No valid prefix list configurations found in Excel file after filtering"
    }
    Write-Log "Found $($plConfigs.Count) valid prefix list configuration rows in Excel" "INFO"

    # Group configurations by PrefixListName
    $groupedConfigs = $plConfigs | Group-Object -Property PrefixListName
    Write-Log "Grouped into $($groupedConfigs.Count) unique prefix lists" "INFO"

    # Path to AWS config file
    $awsConfigPath = "$env:USERPROFILE\.aws\config"
    if (-not (Test-Path $awsConfigPath)) {
        throw "AWS config file not found: $awsConfigPath"
    }

    # Read config file into lines
    $configLines = Get-Content -Path $awsConfigPath

    # Process each prefix list group
    foreach ($group in $groupedConfigs) {
        try {
            $prefixListName = $group.Name
            $configGroup = $group.Group
            $accountId = $configGroup[0].AccountId
            $accountName = $configGroup[0].AccountName
            $ssoRole = $configGroup[0].SSORole
            $vpcId = $configGroup[0].VpcID

            # Clean names to match the profile format
            $cleanAccountName = $accountName -replace '[^\w\-]', ''
            $cleanSsoRole = $ssoRole -replace '[^\w\-]', ''
            $profileName = "sso-$cleanAccountName-$cleanSsoRole"

            Write-Log "Processing configuration for Account: $accountId ($accountName), VpcID: $vpcId, PrefixListName: $prefixListName, Profile: $profileName" "INFO"

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

            # Use profile region (prefix lists are region-wide, not AZ-specific)
            $region = $profileRegion
            if (-not $region) {
                Write-Log "No Region specified in AWS profile for: $profileName." "ERROR"
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
            Write-Log "Setting AWS credentials for profile: $profileName" "INFO"
            try {
                if (-not $DryRun) {
                    Set-AWSCredential -ProfileName $profileName -ErrorAction Stop
                    if (-not (Test-SSOSession -ProfileName $profileName -Region $region)) {
                        Write-Log "Skipping prefix list creation for PrefixListName $prefixListName due to invalid SSO session." "ERROR"
                        continue
                    }
                    Set-DefaultAWSRegion -Region $region -ErrorAction Stop
                }
                Write-Log "Successfully set credentials and region ($region) for profile: $profileName" "INFO"
            } catch {
                Write-Log "Failed to set credentials for profile: $profileName. Error: $($_.Exception.Message)" "ERROR"
                continue
            }

            # Run preflight checks
            $preflightResult = Invoke-PreflightChecks -ConfigGroup $configGroup -ProfileName $profileName -Region $region
            if (-not $preflightResult) {
                Write-Log "Preflight checks failed for configuration with PrefixListName $prefixListName. Skipping creation." "ERROR"
                continue
            }
            $prefixListName = $preflightResult.PrefixListName
            $maxEntries = $preflightResult.MaxEntries
            $entries = $preflightResult.Entries
            $vpcId = $preflightResult.VpcId
            $tagKey = $preflightResult.TagKey
            $tagValue = $preflightResult.TagValue
            $skipCreation = $preflightResult.SkipCreation
            $existingPrefixListId = $preflightResult.PrefixListId

            if ($skipCreation) {
                $prefixListId = $existingPrefixListId
                Write-Log "Skipping creation of prefix list '$prefixListName' as it already exists with ID '$prefixListId'." "INFO"
            } else {
                # Create managed prefix list
                Write-Log "Creating managed prefix list '$prefixListName' in VPC '$vpcId' with MaxEntries $maxEntries and entries: $(($entries | ForEach-Object { "$($_.Cidr) ($($_.Description))" }) -join ', ')..." "INFO"
                if ($DryRun) {
                    Write-Log "Dry run: Would create managed prefix list '$prefixListName' in VPC '$vpcId' with MaxEntries $maxEntries and entries: $(($entries | ForEach-Object { "$($_.Cidr) ($($_.Description))" }) -join ', ')." "INFO"
                    if ($tagKey -and $tagValue) {
                        Write-Log "Dry run: Would apply tag $tagKey=$tagValue to prefix list '$prefixListName'." "INFO"
                    }
                    $prefixListId = "pl-dryrun-$(Get-Random -Minimum 1000000000 -Maximum 9999999999)"
                } else {
                    try {
                        $prefixListEntries = @()
                        foreach ($entry in $entries) {
                            $prefixListEntries += @{ Cidr = $entry.Cidr; Description = $entry.Description }
                        }
                        $tagSpecifications = $null
                        if ($tagKey -and $tagValue) {
                            $tagSpecifications = @(@{ ResourceType = "prefix-list"; Tags = @(@{ Key = $tagKey; Value = $tagValue }) })
                        }
                        $prefixList = New-EC2ManagedPrefixList -PrefixListName $prefixListName -MaxEntries $maxEntries -AddressFamily "IPv4" -Entry $prefixListEntries -TagSpecification $tagSpecifications -ProfileName $profileName -Region $region -ErrorAction Stop
                        $prefixListId = $prefixList.PrefixListId
                        Write-Log "Successfully created managed prefix list '$prefixListName' with ID '$prefixListId'" "INFO"
                        if ($tagKey -and $tagValue) {
                            Write-Log "Applied tag $tagKey=$tagValue to prefix list '$prefixListName'" "INFO"
                        }
                    } catch {
                        Write-Log "Failed to create managed prefix list '$prefixListName'. Error: $($_.Exception.Message)" "ERROR"
                        continue
                    }
                }
            }

            # Update Excel file with PrefixListId for all rows with this PrefixListName (only if empty or invalid)
            try {
                Write-Log "Updating Excel file '$ExcelFilePath' with PrefixListId '$prefixListId' for PrefixListName '$prefixListName'" "INFO"
                $excelPackage = Open-ExcelPackage -Path $ExcelFilePath -ErrorAction Stop
                $worksheet = $excelPackage.Workbook.Worksheets["prefix_list"]
                if (-not $worksheet) {
                    throw "Worksheet 'prefix_list' not found in Excel file"
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
                if (-not $headers.ContainsKey('PrefixListName')) {
                    throw "PrefixListName column not found in Excel worksheet"
                }
                if (-not $headers.ContainsKey('PrefixListId')) {
                    Write-Log "PrefixListId column not found in Excel worksheet. Adding it." "WARN"
                    $newCol = $worksheet.Dimension.Columns + 1
                    $worksheet.Cells[1, $newCol].Value = 'PrefixListId'
                    $headers['PrefixListId'] = $newCol
                }

                # Update rows for this PrefixListName where PrefixListId is empty or invalid
                $rowsUpdated = 0
                for ($row = 2; $row -le $worksheet.Dimension.Rows; $row++) {
                    $rowPrefixListName = $worksheet.Cells[$row, $headers['PrefixListName']].Value
                    if ($rowPrefixListName -eq $prefixListName) {
                        $currentPrefixListId = $worksheet.Cells[$row, $headers['PrefixListId']].Value
                        if (-not $currentPrefixListId -or $currentPrefixListId -notmatch '^pl-[0-9a-f]{17}$') {
                            if ($DryRun) {
                                Write-Log "Dry run: Would update row $row, column PrefixListId with value '$prefixListId' for PrefixListName '$prefixListName'" "INFO"
                            } else {
                                $worksheet.Cells[$row, $headers['PrefixListId']].Value = $prefixListId
                                Write-Log "Updated row $row, column PrefixListId with value '$prefixListId' for PrefixListName '$prefixListName'" "DEBUG"
                            }
                            $rowsUpdated++
                        } else {
                            Write-Log "Row $row for PrefixListName '$prefixListName' already has valid PrefixListId '$currentPrefixListId'. Skipping update." "DEBUG"
                        }
                    }
                }

                if ($rowsUpdated -eq 0 -and -not $skipCreation) {
                    Write-Log "No rows updated for PrefixListName '$prefixListName' (all rows may already have valid PrefixListId)" "WARN"
                } else {
                    if (-not $DryRun) {
                        Close-ExcelPackage -ExcelPackage $excelPackage -ErrorAction Stop
                        # Verify the update
                        $excelPackageVerify = Open-ExcelPackage -Path $ExcelFilePath -ErrorAction Stop
                        $worksheetVerify = $excelPackageVerify.Workbook.Worksheets["prefix_list"]
                        $verified = $true
                        $verifiedRows = 0
                        for ($row = 2; $row -le $worksheetVerify.Dimension.Rows; $row++) {
                            $rowPrefixListName = $worksheetVerify.Cells[$row, $headers['PrefixListName']].Value
                            if ($rowPrefixListName -eq $prefixListName) {
                                $currentPrefixListId = $worksheetVerify.Cells[$row, $headers['PrefixListId']].Value
                                if ($currentPrefixListId -eq $prefixListId -or ($currentPrefixListId -match '^pl-[0-9a-f]{17}$' -and $skipCreation)) {
                                    $verifiedRows++
                                } else {
                                    $verified = $false
                                }
                            }
                        }
                        Close-ExcelPackage -ExcelPackage $excelPackageVerify -ErrorAction Stop
                        if ($verified -and $verifiedRows -gt 0) {
                            Write-Log "Successfully updated and verified $verifiedRows rows in Excel file with PrefixListId '$prefixListId' for PrefixListName '$prefixListName'" "INFO"
                        } else {
                            Write-Log "Failed to verify PrefixListId '$prefixListId' for $verifiedRows rows with PrefixListName '$prefixListName' in Excel file after save" "ERROR"
                        }
                    }
                }
            } catch {
                Write-Log "Failed to update Excel file with PrefixListId '$prefixListId' for PrefixListName '$prefixListName'. Error: $($_.Exception.Message)" "ERROR"
            }

            # Clear credentials after processing
            if (-not $DryRun) {
                Clear-AWSCredential -ErrorAction SilentlyContinue
                Clear-DefaultAWSRegion -ErrorAction SilentlyContinue
            }

        } catch {
            Write-Log "Error processing configuration for Account: $accountId ($accountName), VpcID: $vpcId, PrefixListName: $prefixListName. Error: $($_.Exception.Message)" "ERROR"
            if (-not $DryRun) {
                Clear-AWSCredential -ErrorAction SilentlyContinue
                Clear-DefaultAWSRegion -ErrorAction SilentlyContinue
            }
            continue
        }
    }

    Write-Log "Prefix list creation process completed" "INFO"

} catch {
    Write-Log "Fatal error: $($_.Exception.Message)" "ERROR"
    Write-Log "Error details: $(ConvertTo-Json -InputObject $_.Exception -Depth 3)" "DEBUG"
    exit 1
}