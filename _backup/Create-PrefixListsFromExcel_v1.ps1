# Create-PrefixListsFromExcel.ps1
# PowerShell script to create managed prefix lists in specified VPCs from Excel configuration
# using AWS.Tools modules with multiple SSO profiles and write the PrefixListId back to the Excel file
# Supports dry run mode to simulate actions without modifying AWS resources or the Excel file
# Groups rows by PrefixListName, with each row specifying a single CIDR and its description
# Handles updated column headers (CIDRDescription, Tags) and applies tags to prefix lists
# Skips creation if prefix list already exists (based on PrefixListId or PrefixListName)

param (
    [Parameter(Mandatory=$true, HelpMessage="Path to the directory containing AWS.Tools and ImportExcel modules.")]
    [string]$PSModulesPath,
    [Parameter(Mandatory=$false)]
    [string]$ExcelFilePath = (Join-Path $PSScriptRoot "EC2_Config.xlsx"),
    [Parameter(Mandatory=$false)]
    [string]$LogFilePath = (Join-Path $PSScriptRoot "logs\PrefixList_Create_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"),
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
        $ConfigGroup,
        [Parameter(Mandatory=$true)]
        [string]$ProfileName,
        [Parameter(Mandatory=$true)]
        [string]$Region
    )
    $prefixListName = $ConfigGroup[0].PrefixListName
    Write-Log "Running preflight checks for prefix list creation for configuration with PrefixListName '$prefixListName'..."

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
            Write-Log "VPC '$vpcId' found."
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
            Write-Log "Prefix list name '$prefixListName' is available."
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
    Write-Log "Validated $($entries.Count) CIDR entries for PrefixListName '$prefixListName': $(($entries | ForEach-Object { "$($_.Cidr) ($($_.Description))" }) -join ', ')"

    # --- Tag Check ---
    $tag = $ConfigGroup[0].Tags
    $tagKey = $null
    $tagValue = $null
    if ($tag) {
        if ($tag -match '^([^=]+)=([^=]+)$') {
            $tagKey = $matches[1].Trim()
            $tagValue = $matches[2].Trim()
            Write-Log "Validated tag for PrefixListName '$prefixListName': $tagKey=$tagValue"
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

    Write-Log "Starting prefix list creation script (DryRun: $DryRun)"

    # Read Excel file with custom header names
    Write-Log "Reading Excel file: $ExcelFilePath"
    if (-not (Test-Path $ExcelFilePath)) {
        throw "Excel file not found: $ExcelFilePath"
    }
    
    $headerNames = @(
        'SSORole',
        'AccountId',
        'AccountName',
        'AvailabilityZone',
        'VpcID',
        'PrefixListName',
        'Description', # Prefix list description
        'MaxEntries',
        'CIDR',
        'CIDRDescription', # Per-CIDR description
        'Tags',
        'PrefixListId'
    )
    $plConfigs = Import-Excel -Path $ExcelFilePath -WorksheetName "prefix_list" -HeaderName $headerNames -ErrorAction Stop
    if ($plConfigs.Count -eq 0) {
        throw "No prefix list configurations found in Excel file"
    }
    Write-Log "Found $($plConfigs.Count) prefix list configuration rows in Excel"

    # Group configurations by PrefixListName
    $groupedConfigs = $plConfigs | Group-Object -Property PrefixListName
    Write-Log "Grouped into $($groupedConfigs.Count) unique prefix lists"

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

            Write-Log "Processing configuration for Account: $accountId ($accountName), VpcID: $vpcId, PrefixListName: $prefixListName, Profile: $profileName"

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
            Write-Log "Setting AWS credentials for profile: $profileName"
            try {
                if (-not $DryRun) {
                    Set-AWSCredential -ProfileName $profileName -ErrorAction Stop
                    if (-not (Test-SSOSession -ProfileName $profileName -Region $region)) {
                        Write-Log "Skipping prefix list creation for PrefixListName $prefixListName due to invalid SSO session." "ERROR"
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
                Write-Log "Creating managed prefix list '$prefixListName' in VPC '$vpcId' with MaxEntries $maxEntries and entries: $(($entries | ForEach-Object { "$($_.Cidr) ($($_.Description))" }) -join ', ')..."
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
                Write-Log "Updating Excel file '$ExcelFilePath' with PrefixListId '$prefixListId' for PrefixListName '$prefixListName'"
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

    Write-Log "Prefix list creation process completed"

} catch {
    Write-Log "Fatal error: $($_.Exception.Message)" "ERROR"
    exit 1
}