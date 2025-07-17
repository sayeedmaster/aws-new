# Get-EC2SecurityGroupRules.ps1
# PowerShell script to retrieve detailed security group rules across multiple AWS accounts
# Supports interactive selection of all configured AWS profiles
# Outputs rules to a consolidated CSV or individual CSV files per security group
# Uses AWS.Tools.EC2, AWS.Tools.SecurityToken, and AWS.Tools.IdentityManagement cmdlets
# Includes robust logging, region validation, and error handling

[CmdletBinding()]
param(
    [Parameter()]
    [string]$PSModulesPath = "D:\SidM\psmodules",
    [Parameter()]
    [string]$Region,
    [Parameter()]
    [string[]]$AwsProfiles,
    [Parameter()]
    [string]$OutputFile,
    [Parameter()]
    [bool]$InteractiveSelection = $true,
    [Parameter()]
    [bool]$TestProfilesFirst = $true,
    [Parameter()]
    [string]$FilterByVpcId,
    [Parameter()]
    [bool]$IndividualFiles = $false
)

# Determine the script's root directory
$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
$OutputDir = Join-Path $ScriptDir "output"
$LogFilePath = Join-Path $OutputDir "SG_Analysis_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

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
        Write-Log "Using provided region: $Region" "INFO"
        return $Region
    }
    try {
        $configPath = Join-Path $env:USERPROFILE ".aws\config"
        if (Test-Path $configPath) {
            $configContent = Get-Content -Path $configPath -Raw
            $profileSection = if ($ProfileName) { "\[(profile\s+)?$ProfileName\]" } else { "\[default\]" }
            if ($configContent -match "(?s)$profileSection.*?\nregion\s*=\s*([^\s#]+)") {
                $configRegion = $matches[2]
                if ($validRegions -contains $configRegion) {
                    Write-Log "Using region from profile $ProfileName in config: $configRegion" "INFO"
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
    Write-Log "No valid region found for profile $ProfileName. Using default region: $defaultRegion" "WARN"
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
        Write-Log "Sanitized string '$InputString' to '$sanitized' using -replace" "INFO"
        return $sanitized
    } catch {
        Write-Log "Error with -replace on '$InputString': $($_.Exception.Message). Using regex fallback." "ERROR"
        $sanitizedFileName = [regex]::Replace([System.IO.Path]::GetFileName($InputString), '[^a-zA-Z0-9.]', '_')
        $sanitized = if ($directory) { Join-Path $directory $sanitizedFileName } else { $sanitizedFileName }
        Write-Log "Sanitized string '$InputString' to '$sanitized' using regex" "INFO"
        return $sanitized
    }
}

# Function to get resource name from tags
function Get-ResourceName {
    param([object]$Resource)
    $nameTag = $Resource.Tags | Where-Object { $_.Key -eq "Name" }
    return $nameTag ? $nameTag.Value : $Resource.GroupName
}

# Function to test AWS profile connectivity
function Test-AwsProfileConnectivity {
    param(
        [string]$ProfileName,
        [string]$Region
    )
    $displayProfileName = if ([string]::IsNullOrEmpty($ProfileName)) { 'Default' } else { $ProfileName }
    Write-Host "Testing profile: $displayProfileName" -ForegroundColor Cyan
    try {
        if (-not $Region) {
            Write-Log "No region provided for profile $displayProfileName during connectivity test" "WARN"
            return $false
        }
        Get-STSCallerIdentity -ProfileName $ProfileName -Region $Region -ErrorAction Stop > $null
        Write-Host "  [PASS] Profile authentication successful" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "  [FAIL] Profile authentication failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Log "Profile $displayProfileName authentication failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Function to process security group rules
function Get-SecurityGroupRulesDetails {
    param(
        [object]$SecurityGroup,
        [string]$Direction,
        [string]$AccountId,
        [string]$AccountName,
        [string]$ProfileUsed,
        [string]$Region
    )
    $rules = @()
    $ruleSet = if ($Direction -eq "Inbound") { $SecurityGroup.IpPermissions } else { $SecurityGroup.IpPermissionsEgress }
    
    foreach ($rule in $ruleSet) {
        $protocol = if ($rule.IpProtocol -eq "-1") { "All" } else { $rule.IpProtocol }
        $portRange = if ($rule.IpProtocol -eq "-1") { 
            "All" 
        } elseif ($rule.FromPort -eq $rule.ToPort) { 
            $rule.FromPort 
        } else { 
            "$($rule.FromPort)-$($rule.ToPort)" 
        }
        
        foreach ($ipRange in $rule.IpRanges) {
            $rules += [PSCustomObject]@{
                AccountId = $AccountId
                AccountName = $AccountName
                ProfileUsed = $ProfileUsed
                Region = $Region
                SecurityGroupId = $SecurityGroup.GroupId
                SecurityGroupName = Get-ResourceName -Resource $SecurityGroup
                VpcId = $SecurityGroup.VpcId
                Direction = $Direction
                Protocol = $protocol
                PortRange = $portRange
                Source = $ipRange.CidrIp
                Description = if ($ipRange.Description) { $ipRange.Description } else { "" }
                Type = "IPv4"
            }
        }
        
        foreach ($ipv6Range in $rule.Ipv6Ranges) {
            $rules += [PSCustomObject]@{
                AccountId = $AccountId
                AccountName = $AccountName
                ProfileUsed = $ProfileUsed
                Region = $Region
                SecurityGroupId = $SecurityGroup.GroupId
                SecurityGroupName = Get-ResourceName -Resource $SecurityGroup
                VpcId = $SecurityGroup.VpcId
                Direction = $Direction
                Protocol = $protocol
                PortRange = $portRange
                Source = $ipv6Range.CidrIpv6
                Description = if ($ipv6Range.Description) { $ipv6Range.Description } else { "" }
                Type = "IPv6"
            }
        }
        
        foreach ($sgRef in $rule.UserIdGroupPairs) {
            $sourceDescription = $sgRef.GroupId
            if ($sgRef.GroupName) {
                $sourceDescription += " ($($sgRef.GroupName))"
            }
            if ($sgRef.UserId) {
                $sourceDescription += " [Account: $($sgRef.UserId)]"
            }
            
            $rules += [PSCustomObject]@{
                AccountId = $AccountId
                AccountName = $AccountName
                ProfileUsed = $ProfileUsed
                Region = $Region
                SecurityGroupId = $SecurityGroup.GroupId
                SecurityGroupName = Get-ResourceName -Resource $SecurityGroup
                VpcId = $SecurityGroup.VpcId
                Direction = $Direction
                Protocol = $protocol
                PortRange = $portRange
                Source = $sourceDescription
                Description = if ($sgRef.Description) { $sgRef.Description } else { "" }
                Type = "SecurityGroup"
            }
        }
        
        foreach ($prefixList in $rule.PrefixListIds) {
            $rules += [PSCustomObject]@{
                AccountId = $AccountId
                AccountName = $AccountName
                ProfileUsed = $ProfileUsed
                Region = $Region
                SecurityGroupId = $SecurityGroup.GroupId
                SecurityGroupName = Get-ResourceName -Resource $SecurityGroup
                VpcId = $SecurityGroup.VpcId
                Direction = $Direction
                Protocol = $protocol
                PortRange = $portRange
                Source = $prefixList.PrefixListId
                Description = if ($prefixList.Description) { $prefixList.Description } else { "" }
                Type = "PrefixList"
            }
        }
    }
    
    return $rules
}

# Function for interactive profile selection
function Select-AwsProfilesInteractive {
    param([array]$ProfileList)
    $selectedProfiles = @()
    $currentSelection = 0
    $marked = @{}
    for ($i = 0; $i -lt $ProfileList.Count; $i++) { $marked[$i] = $false }

    function Show-ProfileList {
        param([int]$current, [hashtable]$marked, [array]$profiles)
        Clear-Host
        Write-Host "`nInteractive AWS Profile Selection (All Profiles)" -ForegroundColor Cyan
        Write-Host "===========================================================" -ForegroundColor Cyan
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
            32 { $marked[$currentSelection] = !$marked[$currentSelection] }
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

# Function to display results
function Show-Results {
    param([object[]]$SecurityGroups, [object[]]$Rules)
    if ($SecurityGroups.Count -eq 0) {
        Write-Host "No security groups found with the specified criteria" -ForegroundColor Yellow
        return
    }

    $sgStats = $SecurityGroups | Group-Object SecurityGroupId | ForEach-Object {
        [PSCustomObject]@{
            AccountName = ($_.Group | Select-Object -First 1).AccountName
            SecurityGroupId = $_.Name
            SecurityGroupName = ($_.Group | Select-Object -First 1).SecurityGroupName
            VpcId = ($_.Group | Select-Object -First 1).VpcId
            TotalRules = ($_.Group | Measure-Object -Property TotalRules -Sum).Sum
            InboundRules = ($_.Group | Measure-Object -Property InboundRules -Sum).Sum
            OutboundRules = ($_.Group | Measure-Object -Property OutboundRules -Sum).Sum
        }
    }

    Write-Host "`nDetailed Summary:" -ForegroundColor Cyan
    Write-Host "- Total accounts processed: $(($SecurityGroups | Select-Object -Unique AccountId).Count)"
    Write-Host "- Total security groups found: $($SecurityGroups.Count)"
    Write-Host "- Total rules extracted: $($Rules.Count)"
    Write-Host "- Security groups with rules: $(($SecurityGroups | Where-Object { $_.TotalRules -gt 0 }).Count)"
    Write-Host "- Security groups without rules: $(($SecurityGroups | Where-Object { $_.TotalRules -eq 0 }).Count)"

    Write-Host "`nSecurity Group Breakdown:" -ForegroundColor Cyan
    $sgStats | Format-Table -Property AccountName, SecurityGroupId, SecurityGroupName, VpcId, TotalRules, InboundRules, OutboundRules -AutoSize

    if ($Rules.Count -gt 0) {
        Write-Host "`nSample Rules (First 10):" -ForegroundColor Cyan
        $Rules | Select-Object -First 10 | 
            Select-Object AccountName, SecurityGroupId, SecurityGroupName, Direction, Protocol, PortRange, Source, Type | 
            Format-Table -AutoSize
        if ($Rules.Count -gt 10) {
            Write-Host "... and $($Rules.Count - 10) more rules. See CSV file for full details." -ForegroundColor Gray
        }
    }
}

try {
    # Create output directory
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
        Write-Log "Created output directory: $OutputDir" "INFO"
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

    # Get AWS profiles
    if (-not $AwsProfiles -or $AwsProfiles.Count -eq 0) {
        $profileList = Get-AWSCredential -ListProfile | Select-Object -ExpandProperty ProfileName
        if ($profileList.Count -eq 0) {
            Write-Log "No AWS profiles found. Using default configuration." "WARN"
            $AwsProfiles = @("")
        } elseif ($InteractiveSelection) {
            $AwsProfiles = Select-AwsProfilesInteractive -ProfileList $profileList
        } else {
            $AwsProfiles = $profileList
        }
        Write-Log "Found $($profileList.Count) AWS profiles" "INFO"
    }

    # Test profile connectivity
    if ($TestProfilesFirst -and $AwsProfiles) {
        Write-Host "`nTesting AWS profile connectivity..." -ForegroundColor Cyan
        $validProfiles = @()
        foreach ($profile in $AwsProfiles) {
            $currentRegion = Get-ValidAWSRegion -Region $Region -ProfileName $profile
            if (-not $currentRegion) {
                Write-Log "Skipping profile $profile due to invalid region" "ERROR"
                continue
            }
            if (Test-AwsProfileConnectivity -ProfileName $profile -Region $currentRegion) {
                $validProfiles += $profile
            }
        }
        if ($validProfiles.Count -eq 0) {
            Write-Log "No valid profiles found after connectivity tests. Please check your AWS configuration." "ERROR"
            exit 1
        }
        $AwsProfiles = $validProfiles
        Write-Log "Proceeding with $($validProfiles.Count) valid profiles" "INFO"
    }

    # Initialize output arrays
    $allRules = @()
    $allSecurityGroups = @()
    $processedAccounts = @()

    # Process each profile
    foreach ($profileName in $AwsProfiles) {
        $profileDisplayName = if ($profileName) { $profileName } else { "Default Profile" }
        Write-Log "Processing Account: $profileDisplayName" "INFO"

        # Get account information
        try {
            $currentRegion = Get-ValidAWSRegion -Region $Region -ProfileName $profileName
            if (-not $currentRegion) {
                Write-Log "No valid region for profile $profileName. Skipping." "ERROR"
                continue
            }
            $identity = Get-STSCallerIdentity -ProfileName $profileName -Region $currentRegion -ErrorAction Stop
            $accountId = $identity.Account
            try {
                $accountName = (Get-IAMAccountAlias -ProfileName $profileName -Region $currentRegion -ErrorAction Stop) | Select-Object -First 1
                if (-not $accountName) { $accountName = $accountId }
            } catch {
                Write-Log "Failed to get account alias: $($_.Exception.Message). Using AccountId as name." "WARN"
                $accountName = $accountId
            }
            Write-Log "Account: $accountName ($accountId), ARN: $($identity.Arn)" "INFO"
            $processedAccounts += [PSCustomObject]@{
                ProfileName = $profileName
                AccountName = $accountName
                AccountId = $accountId
            }
        } catch {
            Write-Log "Failed to configure credentials for profile ${profileName}: $($_.Exception.Message). Skipping." "ERROR"
            continue
        }

        # Retrieve security groups
        $securityGroups = @()
        try {
            $filters = if ($FilterByVpcId) { @(@{ Name = "vpc-id"; Values = $FilterByVpcId }) } else { @() }
            $securityGroups = Get-EC2SecurityGroup -Filter $filters -ProfileName $profileName -Region $currentRegion -ErrorAction Stop
            Write-Log "Found $($securityGroups.Count) security groups in $accountName ($currentRegion)" "INFO"
            foreach ($sg in $securityGroups) {
                Write-Host "  - $($sg.GroupId): $(Get-ResourceName -Resource $sg)" -ForegroundColor Gray
            }
        } catch {
            Write-Log "Failed to retrieve security groups for profile $profileName in region ${currentRegion}: $($_.Exception.Message)" "ERROR"
            continue
        }

        if ($securityGroups.Count -eq 0) {
            Write-Log "No security groups found in $accountName ($currentRegion)" "WARN"
            continue
        }

        # Process each security group
        $currentSG = 0
        foreach ($sg in $securityGroups) {
            $currentSG++
            $sgName = Get-ResourceName -Resource $sg
            Write-Progress -Activity "Processing Security Groups" -Status "Analyzing $($sg.GroupId) ($sgName) ($currentSG of $($securityGroups.Count))" -PercentComplete (($currentSG / $securityGroups.Count) * 100)
            Write-Log "Processing: $($sg.GroupId) ($sgName)" "DEBUG"

            $inboundRules = @(Get-SecurityGroupRulesDetails -SecurityGroup $sg -Direction "Inbound" -AccountId $accountId -AccountName $accountName -ProfileUsed $profileName -Region $currentRegion)
            $outboundRules = @(Get-SecurityGroupRulesDetails -SecurityGroup $sg -Direction "Outbound" -AccountId $accountId -AccountName $accountName -ProfileUsed $profileName -Region $currentRegion)

            $sgRules = @()
            if ($inboundRules) { $sgRules += $inboundRules }
            if ($outboundRules) { $sgRules += $outboundRules }
            if ($sgRules) { $allRules += $sgRules }

            if ($IndividualFiles) {
                $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                $sgFileName = "security_group_${accountName}_$($sg.GroupId)_$timestamp.csv"
                $sgOutputPath = Join-Path $OutputDir $sgFileName
                try {
                    if ($sgRules.Count -gt 0) {
                        $sgRules | Export-Csv -Path $sgOutputPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
                        Write-Log "Exported $($sgRules.Count) rules to: $sgOutputPath" "DEBUG"
                    } else {
                        $headers = '"AccountId","AccountName","ProfileUsed","Region","SecurityGroupId","SecurityGroupName","VpcId","Direction","Protocol","PortRange","Source","Description","Type"'
                        Set-Content -Path $sgOutputPath -Value $headers -Encoding UTF8
                        Write-Log "Created empty CSV with headers: $sgOutputPath" "DEBUG"
                    }
                } catch {
                    Write-Log "Failed to export individual CSV for $($sg.GroupId): $($_.Exception.Message)" "ERROR"
                }
            }

            $allSecurityGroups += [PSCustomObject]@{
                AccountId = $accountId
                AccountName = $accountName
                ProfileUsed = $profileName
                Region = $currentRegion
                SecurityGroupId = $sg.GroupId
                SecurityGroupName = $sgName
                VpcId = $sg.VpcId
                Description = $sg.Description
                TotalRules = $sgRules.Count
                InboundRules = $inboundRules.Count
                OutboundRules = $outboundRules.Count
            }

            $statusMessage = "  Security Group: $($sg.GroupId) ($sgName) - $($sgRules.Count) rules ($($inboundRules.Count) inbound, $($outboundRules.Count) outbound)"
            $statusColor = if ($sgRules.Count -gt 0) { "Green" } else { "Gray" }
            Write-Host $statusMessage -ForegroundColor $statusColor
        }
        Write-Progress -Activity "Processing Security Groups" -Completed
    }

    # Set default output file
    if (-not $IndividualFiles -and -not $OutputFile) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        try {
            $regionSafe = Sanitize-String -InputString $currentRegion
            $profileSafe = Sanitize-String -InputString $(if ($AwsProfiles.Count -eq 1 -and $AwsProfiles[0]) { $AwsProfiles[0] } else { "multi-profile" })
            $vpcSuffix = if ($FilterByVpcId) { "_vpc_$(Sanitize-String -InputString $FilterByVpcId)" } else { "" }
            $OutputFile = Join-Path $OutputDir "security_groups_${profileSafe}_${regionSafe}${vpcSuffix}_${timestamp}.csv"
        } catch {
            Write-Log "Error in generating safe output filename: $($_.Exception.Message). Using default values." "ERROR"
            $regionSafe = "unknown-region"
            $profileSafe = "unknown-profile"
            $OutputFile = Join-Path $OutputDir "security_groups_${profileSafe}_${regionSafe}_${timestamp}.csv"
        }
    }

    # Display execution summary
    Write-Host "`nMulti-Account AWS Security Group Rules Analysis" -ForegroundColor Cyan
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "Profiles: $($AwsProfiles.Count) account(s)" -ForegroundColor Gray
    Write-Host "Region: $(if ($Region) { $Region } else { 'Account-configured regions' })" -ForegroundColor Gray
    Write-Host "Filter by VPC: $(if ($FilterByVpcId) { $FilterByVpcId } else { 'None' })" -ForegroundColor Gray
    Write-Host "Individual Files: $IndividualFiles" -ForegroundColor Gray
    Write-Host ""

    # Display results
    if ($allSecurityGroups.Count -eq 0) {
        Write-Log "No security groups found matching the criteria across all accounts" "WARN"
        exit 0
    }
    Show-Results -SecurityGroups $allSecurityGroups -Rules $allRules

    # Export consolidated CSV
    if (-not $IndividualFiles -and $allRules.Count -gt 0) {
        try {
            $allRules | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
        } catch {
            Write-Log "Failed to export consolidated CSV: $($_.Exception.Message)" "ERROR"
        }
    }

    # Output summary CSV
    $summaryCsvFile = try {
        Sanitize-String -InputString ($OutputFile -replace '\.csv$', '_summary.csv')
    } catch {
        Write-Log "Error generating summary CSV filename: $($_.Exception.Message). Using default." "ERROR"
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        Join-Path $OutputDir "security_groups_summary_${timestamp}.csv"
    }
    try {
        $allSecurityGroups | Select-Object AccountName, SecurityGroupId, SecurityGroupName, VpcId, TotalRules, InboundRules, OutboundRules |
            Export-Csv -Path $summaryCsvFile -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Host "Security group summary exported to: $summaryCsvFile" -ForegroundColor Green
    } catch {
        Write-Log "Failed to export summary CSV: $($_.Exception.Message)" "ERROR"
    }

    # Final summary
    Write-Log "FINAL SUMMARY" "INFO"
    Write-Log "Total accounts processed: $($processedAccounts.Count)" "INFO"
    Write-Log "Total security groups found: $($allSecurityGroups.Count)" "INFO"
    Write-Log "Total rules extracted: $($allRules.Count)" "INFO"
    if ($IndividualFiles) {
        Write-Log "Individual files created: $($allSecurityGroups.Count)" "INFO"
    } else {
        Write-Log "Consolidated file: $OutputFile" "INFO"
        Write-Log "Summary file: $summaryCsvFile" "INFO"
    }
    Write-Log "Script completed successfully!" "INFO"

} catch {
    Write-Log "Fatal error: $($_.Exception.Message)" "ERROR"
    exit 1
}