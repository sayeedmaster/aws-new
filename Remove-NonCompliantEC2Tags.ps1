# Remove-NonCompliantEC2Tags.ps1
# PowerShell script to identify and remove non-compliant EC2 tags with user confirmation
# Supports multiple AWS profiles with interactive selection, limited to profiles ending with -privFujitsuCSA
# Validates tags per AWS EC2 restrictions (https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/work-with-tags-in-IMDS.html)
# Outputs CSV with AccountName, AccountId, SSORole, InstanceId, and RemovedTags
# Logs all actions to a log file
# Version 1.2: Restricted to profiles ending with -privFujitsuCSA

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, HelpMessage="Path to the directory containing AWS.Tools modules.")]
    [string]$PSModulesPath,
    [Parameter()]
    [string]$Region,
    [Parameter()]
    [string[]]$AwsProfiles,
    [Parameter()]
    [string]$OutputFile,
    [Parameter()]
    [bool]$InteractiveSelection = $true,
    [Parameter()]
    [bool]$TestProfilesFirst = $true
)

# Get script directory and set relative paths
$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
$OutputDir = Join-Path $ScriptDir "output"
$LogFilePath = Join-Path $OutputDir "EC2_Tag_Removal_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Function to write logs
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    switch ($Level.ToUpper()) {
        "INFO"  { Write-Host $logMessage -ForegroundColor Blue }
        "WARN"  { Write-Host $logMessage -ForegroundColor Yellow }
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
        default { Write-Host $logMessage }
    }
    Add-Content -Path $LogFilePath -Value $logMessage
}

# Function to validate EC2 tag keys per AWS restrictions
function Test-EC2TagKey {
    param(
        [string]$TagKey
    )
    try {
        # AWS EC2 Tag Restrictions
        # - Max length: 128 characters
        # - Allowed characters: Unicode letters (a-z, A-Z), digits (0-9), and specific symbols (_ . : / = + - @)
        # - Case sensitive
        # - Cannot start with 'aws:'
        # - Cannot be empty or null
        # - Spaces are not allowed
        if ([string]::IsNullOrEmpty($TagKey)) {
            return "Empty or null tag key"
        }
        if ($TagKey.Length -gt 128) {
            return "Tag key length exceeds 128 characters"
        }
        #if ($TagKey -match '^aws:') {
        #    return "Tag key starts with reserved prefix 'aws:'"
        #}
        if ($TagKey -match '\s') {
            return "Tag key contains spaces"
        }
        if ($TagKey -notmatch '^[a-zA-Z0-9_\.:/=+@-]+$') {
            return "Tag key contains invalid characters (allowed: letters, digits, _ . : / = + - @)"
        }
        return $null
    } catch {
        Write-Log "Error validating tag key '${TagKey}': $($_.Exception.Message)" "WARN"
        return "Validation error"
    }
}

# Function to validate AWS region
function Get-ValidAWSRegion {
    param(
        [string]$Region,
        [string]$ProfileName
    )
    $validRegions = @(
        "us-east-1", "us-east-2", "us-west-1", "us-west-2",
        "ap-south-1", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
        "ap-southeast-1", "ap-southeast-2", "ca-central-1",
        "eu-central-1", "eu-west-1", "eu-west-2", "eu-west-3",
        "eu-north-1", "sa-east-1"
    )
    if ($Region -and $validRegions -contains $Region) {
        Write-Log "Using provided region: ${Region}" "INFO"
        return $Region
    }
    try {
        $configPath = Join-Path $env:USERPROFILE ".aws\config"
        if (Test-Path $configPath) {
            $configContent = Get-Content -Path $configPath -Raw
            $profileSection = if ($ProfileName) { "\[(profile\s+)?${ProfileName}\]" } else { "\[default\]" }
            if ($configContent -match "(?s)$profileSection.*?\nregion\s*=\s*([^\s#]+)") {
                $configRegion = $matches[2]
                if ($validRegions -contains $configRegion) {
                    Write-Log "Using region from profile ${ProfileName} in config: ${configRegion}" "INFO"
                    return $configRegion
                }
            }
        }
    } catch {
        Write-Log "Failed to parse region from config for profile ${ProfileName}: $($_.Exception.Message)" "WARN"
    }
    if ($env:AWS_DEFAULT_REGION -and $validRegions -contains $env:AWS_DEFAULT_REGION) {
        Write-Log "Using region from AWS_DEFAULT_REGION: $env:AWS_DEFAULT_REGION" "INFO"
        return $env:AWS_DEFAULT_REGION
    }
    $defaultRegion = "eu-west-1"
    Write-Log "No valid region found for profile ${ProfileName}. Using default region: ${defaultRegion}" "WARN"
    return $defaultRegion
}

# Function to sanitize strings for filenames
function Sanitize-String {
    param([string]$InputString)
    try {
        $fileName = [System.IO.Path]::GetFileName($InputString)
        $directory = [System.IO.Path]::GetDirectoryName($InputString)
        $sanitizedFileName = $fileName -replace '[^a-zA-Z0-9.]', '_'
        $sanitized = if ($directory) { Join-Path $directory $sanitizedFileName } else { $sanitizedFileName }
        Write-Log "Sanitized string '${InputString}' to '${sanitized}' using -replace" "INFO"
        return $sanitized
    } catch {
        Write-Log "Error with -replace on '${InputString}': $($_.Exception.Message). Using regex fallback." "ERROR"
        $sanitizedFileName = [regex]::Replace([System.IO.Path]::GetFileName($InputString), '[^a-zA-Z0-9.]', '_')
        $sanitized = if ($directory) { Join-Path $directory $sanitizedFileName } else { $sanitizedFileName }
        Write-Log "Sanitized string '${InputString}' to '${sanitized}' using regex" "INFO"
        return $sanitized
    }
}

# Function to get resource name from tags
function Get-ResourceName {
    param([object]$Resource)
    try {
        $nameTag = $Resource.Tags | Where-Object { $_.Key -eq "Name" }
        if ($nameTag) {
            return $nameTag.Value
        } else {
            $resourceId = $Resource.InstanceId
            Write-Log "No Name tag found for instance ${resourceId}" "DEBUG"
            return "(No Name Tag)"
        }
    } catch {
        $resourceId = $Resource.InstanceId
        Write-Log "Error accessing tags for instance ${resourceId}: $($_.Exception.Message)" "WARN"
        return "(No Name Tag)"
    }
}

# Function to get SSO role name
function Get-SSORoleName {
    param(
        [string]$ProfileName,
        [string]$Region
    )
    try {
        $configPath = Join-Path $env:USERPROFILE ".aws\config"
        if (Test-Path $configPath) {
            $configContent = Get-Content -Path $configPath -Raw
            $profileSection = if ($ProfileName) { "\[(profile\s+)?${ProfileName}\]" } else { "\[default\]" }
            if ($configContent -match "(?s)$profileSection.*?\nsso_role_name\s*=\s*([^\s#]+)") {
                $ssoRoleName = $matches[2]
                Write-Log "Retrieved SSO role name '${ssoRoleName}' from config for profile ${ProfileName}" "INFO"
                return $ssoRoleName
            }
        }
        if ($ProfileName -or $Region) {
            $identity = Get-STSCallerIdentity -ProfileName $ProfileName -Region $Region -ErrorAction Stop
            if ($identity.Arn -match 'assumed-role/([^/]+)/') {
                $ssoRoleName = $matches[1]
                Write-Log "Retrieved SSO role name '${ssoRoleName}' from ARN for profile ${ProfileName}" "INFO"
                return $ssoRoleName
            }
        }
        Write-Log "Could not determine SSO role for profile ${ProfileName}. Using 'Unknown'." "WARN"
        return "Unknown"
    } catch {
        Write-Log "Error retrieving SSO role for profile ${ProfileName}: $($_.Exception.Message). Using 'Unknown'." "WARN"
        return "Unknown"
    }
}

# Function to prompt for tag removal confirmation
function Confirm-TagRemoval {
    param(
        [string]$InstanceId,
        [string]$InstanceName,
        [array]$NonCompliantTags
    )
    Write-Host "`nNon-compliant tags found for instance ${InstanceId} (${InstanceName}):" -ForegroundColor Yellow
    foreach ($tag in $NonCompliantTags) {
        Write-Host "  - Tag Key: '$($tag.Key)', Reason: $($tag.Reason)" -ForegroundColor Red
    }
    Write-Host "Do you want to remove these tags? (y/n)" -ForegroundColor Cyan
    $response = Read-Host
    return ($response -match '^[Yy]$')
}

# Function to remove non-compliant tags
function Remove-NonCompliantTags {
    param(
        [object]$Instance,
        [string]$Region,
        [string]$ProfileName
    )
    $nonCompliantTags = @()
    foreach ($tag in $Instance.Tags) {
        $validationResult = Test-EC2TagKey -TagKey $tag.Key
        if ($validationResult) {
            $nonCompliantTags += [PSCustomObject]@{
                Key = $tag.Key
                Value = $tag.Value
                Reason = $validationResult
            }
        }
    }
    if ($nonCompliantTags.Count -eq 0) {
        Write-Log "No non-compliant tags found for instance $($Instance.InstanceId)" "INFO"
        return $null
    }
    $instanceName = Get-ResourceName -Resource $Instance
    if (Confirm-TagRemoval -InstanceId $Instance.InstanceId -InstanceName $instanceName -NonCompliantTags $nonCompliantTags) {
        try {
            $tagKeysToRemove = $nonCompliantTags | ForEach-Object { $_.Key }
            Remove-EC2Tag -ResourceId $Instance.InstanceId -Tag $tagKeysToRemove -ProfileName $ProfileName -Region $Region -ErrorAction Stop
            Write-Log "Successfully removed non-compliant tags from instance $($Instance.InstanceId): $($tagKeysToRemove -join ', ')" "INFO"
            return ($nonCompliantTags | ForEach-Object { "$($_.Key)=$($_.Value) ($($_.Reason))" }) -join '; '
        } catch {
            Write-Log "Failed to remove tags from instance $($Instance.InstanceId): $($_.Exception.Message)" "ERROR"
            return "Failed to remove: $($nonCompliantTags | ForEach-Object { "$($_.Key)=$($_.Value) ($($_.Reason))" } | Join-String -Separator '; ')"
        }
    } else {
        Write-Log "User declined to remove non-compliant tags for instance $($Instance.InstanceId)" "INFO"
        return "Declined: $($nonCompliantTags | ForEach-Object { "$($_.Key)=$($_.Value) ($($_.Reason))" } | Join-String -Separator '; ')"
    }
}

# Function to process instances for a single profile
function Get-EC2InstancesForProfile {
    param(
        [string]$ProfileName,
        [string]$Region
    )
    $DisplayProfileName = if ($ProfileName) { $ProfileName } else { 'Default' }
    Write-Log "Processing profile: ${DisplayProfileName}" "INFO"
    try {
        $identity = Get-STSCallerIdentity -ProfileName $ProfileName -Region $Region -ErrorAction Stop
        $accountId = $identity.Account
        try {
            $accountName = (Get-IAMAccountAlias -ProfileName $ProfileName -Region $Region -ErrorAction Stop) | Select-Object -First 1
            if (-not $accountName) {
                if ($ProfileName) {
                    $accountName = $ProfileName -replace '^sso-' -replace '-privFujitsuCSA$', ''
                    Write-Log "No account alias found for profile ${DisplayProfileName}. Derived AccountName '${accountName}' from ProfileName." "INFO"
                } else {
                    $accountName = 'Default'
                    Write-Log "No account alias found for default profile. Using 'Default' as AccountName." "INFO"
                }
            }
        } catch {
            Write-Log "Failed to get account alias for profile ${DisplayProfileName}: $($_.Exception.Message)." "WARN"
            if ($ProfileName) {
                $accountName = $ProfileName -replace '^sso-' -replace '-privFujitsuCSA$', ''
                Write-Log "Derived AccountName '${accountName}' from ProfileName." "INFO"
            } else {
                $accountName = 'Default'
                Write-Log "Using 'Default' as AccountName for default profile." "INFO"
            }
            if (-not $accountName) {
                $accountName = $accountId
                Write-Log "Derived AccountName is empty. Using AccountId '${accountId}' as AccountName." "WARN"
            }
        }
        Write-Log "Account: ${accountName} (${accountId}), ARN: $($identity.Arn)" "INFO"
    } catch {
        Write-Log "Failed to configure credentials for profile ${DisplayProfileName}: $($_.Exception.Message). Skipping." "ERROR"
        return @(), $accountName, $accountId
    }
    try {
        $reservations = Get-EC2Instance -ProfileName $ProfileName -Region $Region -ErrorAction Stop
        $instances = $reservations.Instances
        if (-not $instances) {
            Write-Log "No instances found for profile ${DisplayProfileName} in region ${Region}" "WARN"
            return @(), $accountName, $accountId
        }
        Write-Log "Retrieved $($instances.Count) instances for profile ${DisplayProfileName}" "INFO"
        return $instances, $accountName, $accountId
    } catch {
        Write-Log "Error retrieving instances for profile ${DisplayProfileName}: $($_.Exception.Message)" "ERROR"
        return @(), $accountName, $accountId
    }
}

# Function for interactive profile selection, limited to profiles ending with -privFujitsuCSA
function Select-AwsProfilesInteractive {
    param([array]$ProfileList)
    $selectedProfiles = @()
    $currentSelection = 0
    $marked = @{}
    for ($i = 0; $i -lt $ProfileList.Count; $i++) { $marked[$i] = $false }
    function Show-ProfileList {
        param([int]$current, [hashtable]$marked, [array]$profiles)
        Clear-Host
        Write-Host "`nInteractive AWS Profile Selection (Profiles ending with -privFujitsuCSA)" -ForegroundColor Cyan
        Write-Host "=================================" -ForegroundColor Cyan
        Write-Host "Use UP/DOWN arrows to navigate, SPACEBAR to select/deselect, ENTER to confirm" -ForegroundColor Yellow
        Write-Host "ESC to cancel, A to select all, C to clear all" -ForegroundColor Yellow
        Write-Host ""
        for ($i = 0; $i -lt $profiles.Count; $i++) {
            $marker = if ($marked[$i]) { "[X]" } else { "[ ]" }
            $arrow = if ($i -eq $current) { ">>>" } else { "   " }
            $color = if ($i -eq $current) { "Yellow" } else { "Gray" }
            Write-Host "$arrow $marker $($i + 1). $($profiles[$i])" -ForegroundColor $color
        }
        $selectedCount = ($marked.Values | Where-Object { $_ }).Count
        Write-Host "`nSelected: $selectedCount profile(s)" -ForegroundColor Green
    }
    do {
        Show-ProfileList -current $currentSelection -marked $marked -profiles $ProfileList
        $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        switch ($key.VirtualKeyCode) {
            38 { $currentSelection = if ($currentSelection -gt 0) { $currentSelection - 1 } else { $ProfileList.Count - 1 } }
            40 { $currentSelection = if ($currentSelection -lt $ProfileList.Count - 1) { $currentSelection + 1 } else { 0 } }
            32 { $marked[$currentSelection] = -not $marked[$currentSelection] }
            65 { for ($i = 0; $i -lt $ProfileList.Count; $i++) { $marked[$i] = $true } }
            67 { for ($i = 0; $i -lt $ProfileList.Count; $i++) { $marked[$i] = $false } }
            13 {
                $selectedIndices = 0..($ProfileList.Count - 1) | Where-Object { $marked[$_] }
                $selectedProfiles = $selectedIndices | ForEach-Object { $ProfileList[$_] }
                if ($selectedProfiles.Count -eq 0) {
                    Write-Host "`nNo profiles selected. Please select at least one profile." -ForegroundColor Red
                    Start-Sleep -Seconds 2
                } else {
                    Clear-Host
                    Write-Host "`nSelected profiles:" -ForegroundColor Green
                    $selectedProfiles | ForEach-Object { Write-Host "  - $_" -ForegroundColor Gray }
                    return $selectedProfiles
                }
            }
            27 { Write-Host "Profile selection cancelled." -ForegroundColor Yellow; exit 0 }
        }
    } while ($true)
}

# Function to test AWS profile connectivity
function Test-AwsProfileConnectivity {
    param([string]$ProfileName, [string]$Region)
    $displayProfileName = if ($ProfileName) { $ProfileName } else { 'Default' }
    Write-Log "Testing profile: ${displayProfileName}" "INFO"
    try {
        if (-not $Region) {
            Write-Log "No region provided for profile ${displayProfileName} during connectivity test" "WARN"
            return $false
        }
        Get-STSCallerIdentity -ProfileName $ProfileName -Region $Region -ErrorAction Stop | Out-Null
        Write-Log "Profile authentication successful for ${displayProfileName}" "INFO"
        return $true
    } catch {
        Write-Log "Profile ${displayProfileName} authentication failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

try {
    # Create output directory
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
        Write-Log "Created output directory: ${OutputDir}" "INFO"
    }

    # Import AWS Tools modules
    try {
        Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.Common") -ErrorAction Stop
        Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.EC2") -ErrorAction Stop
        Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.SecurityToken") -ErrorAction Stop
        Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.IdentityManagement") -ErrorAction Stop
        Write-Log "Loaded AWS Tools modules" "INFO"
    } catch {
        Write-Log "Failed to import AWS Tools modules from ${PSModulesPath}: $($_.Exception.Message)" "ERROR"
        exit 1
    }

    # Get AWS profiles, limited to those ending with -privFujitsuCSA
    if (-not $AwsProfiles -or $AwsProfiles.Count -eq 0) {
        $profileList = Get-AWSCredential -ListProfile | Select-Object -ExpandProperty ProfileName | Where-Object { $_ -like '*-privFujitsuCSA' }
        if ($profileList.Count -eq 0) {
            Write-Log "No AWS profiles ending with -privFujitsuCSA found. Exiting." "ERROR"
            exit 1
        }
        if ($InteractiveSelection) {
            $AwsProfiles = Select-AwsProfilesInteractive -ProfileList $profileList
        } else {
            Write-Host "`nAvailable AWS Profiles (ending with -privFujitsuCSA):" -ForegroundColor Cyan
            for ($i = 0; $i -lt $profileList.Count; $i++) {
                $CurrentIndicator = if ($env:AWS_PROFILE -eq $profileList[$i]) { " (current)" } else { "" }
                Write-Host "  $($i + 1). $($profileList[$i])$CurrentIndicator" -ForegroundColor Gray
            }
            Write-Host "  0. Use default profile (if ending with -privFujitsuCSA)" -ForegroundColor Gray
            do {
                $Selection = Read-Host "`nSelect AWS profile (0-$($profileList.Count))"
                if ($Selection -eq "0") {
                    if ($env:AWS_PROFILE -like '*-privFujitsuCSA') {
                        $AwsProfiles = @($env:AWS_PROFILE)
                        Write-Log "Using default AWS profile: $($env:AWS_PROFILE)" "INFO"
                        break
                    } else {
                        Write-Host "Default profile does not end with -privFujitsuCSA. Please select a valid profile." -ForegroundColor Red
                    }
                } elseif ($Selection -match '^\d+$' -and [int]$Selection -ge 1 -and [int]$Selection -le $profileList.Count) {
                    $AwsProfiles = @($profileList[[int]$Selection - 1])
                    Write-Log "Selected profile: $($AwsProfiles[0])" "INFO"
                    break
                } else {
                    Write-Host "Invalid selection. Please enter a number between 0 and $($profileList.Count)." -ForegroundColor Yellow
                }
            } while ($true)
        }
        Write-Log "Found $($profileList.Count) profiles ending with -privFujitsuCSA" "INFO"
    } else {
        # Filter provided AwsProfiles to only those ending with -privFujitsuCSA
        $AwsProfiles = $AwsProfiles | Where-Object { $_ -like '*-privFujitsuCSA' }
        if ($AwsProfiles.Count -eq 0) {
            Write-Log "No provided AWS profiles end with -privFujitsuCSA. Exiting." "ERROR"
            exit 1
        }
        Write-Log "Filtered provided profiles to $($AwsProfiles.Count) ending with -privFujitsuCSA" "INFO"
    }

    # Test profile connectivity
    if ($TestProfilesFirst -and $AwsProfiles) {
        Write-Log "Testing AWS profile connectivity" "INFO"
        $validProfiles = @()
        foreach ($profile in $AwsProfiles) {
            $currentRegion = Get-ValidAWSRegion -Region $Region -ProfileName $profile
            if (-not $currentRegion) {
                Write-Log "Skipping profile ${profile} due to invalid region" "ERROR"
                continue
            }
            if (Test-AwsProfileConnectivity -ProfileName $profile -Region $currentRegion) {
                $validProfiles += $profile
            }
        }
        if ($validProfiles.Count -eq 0) {
            Write-Log "No valid profiles ending with -privFujitsuCSA found after connectivity tests. Please check your AWS configuration." "ERROR"
            exit 1
        }
        $AwsProfiles = $validProfiles
        Write-Log "Proceeding with $($validProfiles.Count) valid profiles" "INFO"
    }

    # Initialize output array and counters
    $allOutput = @()
    $processedAccounts = @()
    $instanceIdsProcessed = @{} # Track processed instances to avoid duplicates
    $regionsUsed = @() # Track regions used across profiles
    $tagsRemovedCount = 0 # Track number of tags removed

    # Process each profile
    foreach ($profileName in $AwsProfiles) {
        $currentRegion = Get-ValidAWSRegion -Region $Region -ProfileName $profileName
        if (-not $currentRegion) {
            Write-Log "No valid region for profile ${profileName}. Skipping." "ERROR"
            continue
        }
        if ($currentRegion -notin $regionsUsed) {
            $regionsUsed += $currentRegion
            Write-Log "Added region ${currentRegion} to regions used" "INFO"
        }
        $ssoRole = Get-SSORoleName -ProfileName $profileName -Region $currentRegion
        $instances, $accountName, $accountId = Get-EC2InstancesForProfile -ProfileName $profileName -Region $currentRegion
        if (-not $instances) {
            Write-Log "No instances or unable to retrieve data for profile ${profileName}" "WARN"
            continue
        }
        $processedAccounts += [PSCustomObject]@{
            SSORole = $ssoRole
            AccountName = $accountName
            AccountId = $accountId
        }
        foreach ($instance in $instances) {
            if ($instanceIdsProcessed.ContainsKey($instance.InstanceId)) {
                Write-Log "Instance $($instance.InstanceId) already processed. Skipping to avoid duplication." "DEBUG"
                continue
            }
            $instanceIdsProcessed[$instance.InstanceId] = $true
            try {
                # Check and remove non-compliant tags
                $removedTags = Remove-NonCompliantTags -Instance $instance -Region $currentRegion -ProfileName $profileName
                if ($removedTags -and $removedTags -notlike "Declined:*" -and $removedTags -notlike "Failed:*") {
                    $tagsRemovedCount += ($removedTags -split '; ').Count
                }
                if ($removedTags) {
                    $allOutput += [PSCustomObject]@{
                        AccountName = $accountName
                        AccountId = $accountId
                        SSORole = $ssoRole
                        InstanceId = $instance.InstanceId
                        RemovedTags = $removedTags
                    }
                }
            } catch {
                Write-Log "Error processing instance $($instance.InstanceId): $($_.Exception.Message)" "ERROR"
            }
        }
    }

    # Set output file
    if (-not $OutputFile) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        try {
            $regionSafe = if ($regionsUsed.Count -eq 1) { Sanitize-String -InputString $regionsUsed[0] } else { "multiregion" }
            $profileCount = $AwsProfiles.Count
            $OutputFile = Join-Path $OutputDir "ec2_tag_removal_${profileCount}accounts_${regionSafe}_${timestamp}.csv"
            Write-Log "Generated output filename: ${OutputFile}" "INFO"
        } catch {
            Write-Log "Error generating output filename: $($_.Exception.Message). Using default." "ERROR"
            $OutputFile = Join-Path $OutputDir "ec2_tag_removal_${timestamp}.csv"
        }
    }

    # Display summary
    Write-Host "`nEC2 Tag Removal Summary" -ForegroundColor Cyan
    Write-Host "=======================" -ForegroundColor Cyan
    Write-Host "Script version: 1.2 (EC2 Non-Compliant Tag Removal, Limited to -privFujitsuCSA Profiles)" -ForegroundColor Green
    Write-Host "Profiles processed: $($AwsProfiles.Count)" -ForegroundColor Green
    Write-Host "Regions used: $($regionsUsed -join ', ')" -ForegroundColor Green
    Write-Host "Total instances processed: $($instanceIdsProcessed.Count)" -ForegroundColor Green
    Write-Host "Unique accounts: $(($processedAccounts | Select-Object -Unique AccountId).Count)" -ForegroundColor Green
    Write-Host "Non-compliant tags removed: $tagsRemovedCount" -ForegroundColor Green
    Write-Host "Log file: ${LogFilePath}" -ForegroundColor Gray
    Write-Host ""

    # Display results
    if ($allOutput.Count -eq 0) {
        Write-Log "No non-compliant tags were found or removed across all profiles" "WARN"
        exit 0
    }
    if ($allOutput.Count -le 20) {
        Write-Host "Removed Tags Details (All Results):" -ForegroundColor Cyan
        $allOutput | Format-Table -AutoSize
    } else {
        Write-Host "Removed Tags Details (First 20 of $($allOutput.Count) results):" -ForegroundColor Cyan
        $allOutput | Select-Object -First 20 | Format-Table -AutoSize
        Write-Host "... and $($allOutput.Count - 20) more instances with removed tags. See CSV file for complete results." -ForegroundColor Yellow
    }

    # Export results
    try {
        $allOutput | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Log "Successfully exported tag removal data to ${OutputFile}" "INFO"
    } catch {
        Write-Log "Failed to export tag removal data to CSV: $($_.Exception.Message)" "ERROR"
    }

    # Final summary
    Write-Log "FINAL SUMMARY" "INFO"
    Write-Log "Total accounts processed: $($processedAccounts.Count)" "INFO"
    Write-Log "Total instances processed: $($instanceIdsProcessed.Count)" "INFO"
    Write-Log "Non-compliant tags removed: $tagsRemovedCount" "INFO"
    Write-Log "Regions used: $($regionsUsed -join ', ')" "INFO"
    Write-Log "Output file: ${OutputFile}" "INFO"
    Write-Log "Script completed successfully!" "INFO"

} catch {
    Write-Log "Fatal error: $($_.Exception.Message)" "ERROR"
    exit 1
}