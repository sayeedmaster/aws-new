# Get-EC2SubnetsWithInstances.ps1
# PowerShell script to list subnets with running EC2 instances across multiple AWS accounts using AWS Tools for PowerShell
# Supports interactive selection of all configured AWS profiles
# Outputs subnet details and optionally instance details to CSV
# Uses AWS.Tools.EC2 and AWS.Tools.IdentityManagement cmdlets
# Includes robust logging, region validation, and error handling

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, HelpMessage="Path to the directory containing AWS.Tools modules.")]
    [string]$PSModulesPath,
    [Parameter()]
    [string]$Region,
    [Parameter()]
    [string[]]$AwsProfiles,
    [Parameter()]
    [bool]$IncludeInstanceDetails = $true,
    [Parameter()]
    [ValidateSet("pending", "running", "shutting-down", "terminated", "stopping", "stopped")]
    [string[]]$InstanceStates = @("running"),
    [Parameter()]
    [ValidateSet("CSV")]
    [string]$OutputFormat = "CSV",
    [Parameter()]
    [string]$OutputFile,
    [Parameter()]
    [switch]$IncludeEmptySubnets,
    [Parameter()]
    [bool]$IncludeDefaultVPC = $true,
    [Parameter()]
    [int]$MinInstanceCount = 0,
    [Parameter()]
    [bool]$InteractiveSelection = $true,
    [Parameter()]
    [bool]$TestProfilesFirst = $true
)

# Determine the script's root directory
$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
$OutputDir = Join-Path $ScriptDir "output"
$LogFilePath = Join-Path $OutputDir "Subnet_Analysis_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

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
    # Try to parse region from ~/.aws/config
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
    # Fall back to environment variable
    if ($env:AWS_DEFAULT_REGION -and $validRegions -contains $env:AWS_DEFAULT_REGION) {
        Write-Log "Using region from AWS_DEFAULT_REGION: $env:AWS_DEFAULT_REGION" "INFO"
        return $env:AWS_DEFAULT_REGION
    }
    # Fall back to default region
    $defaultRegion = "eu-west-1"
    Write-Log "No valid region found for profile $ProfileName. Using default region: $defaultRegion" "WARN"
    return $defaultRegion
}

# Function to sanitize strings for filenames
function Sanitize-String {
    param([string]$InputString)
    try {
        # Extract the filename without path
        $fileName = [System.IO.Path]::GetFileName($InputString)
        $directory = [System.IO.Path]::GetDirectoryName($InputString)
        # Sanitize only the filename
        $sanitizedFileName = $fileName -replace '[^a-zA-Z0-9.]', '_'
        # Reconstruct the full path
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
    return $nameTag ? $nameTag.Value : "N/A"
}

# Function to get a specific tag value
function Get-ResourceTagValue {
    param(
        [object]$Resource,
        [string]$TagName
    )
    $tag = $Resource.Tags | Where-Object { $_.Key -eq $TagName }
    return $tag ? $tag.Value : "N/A"
}

# Function to check if VPC is default
function Test-DefaultVPC {
    param([object]$VPC)
    return $VPC.IsDefault
}

# Function to determine instance platform
function Get-InstancePlatform {
    param([object]$Instance)
    try {
        Write-Log "Determining platform for instance $($Instance.InstanceId): Platform=$($Instance.Platform), PlatformDetails=$($Instance.PlatformDetails)" "INFO"
        if ($null -ne $Instance.Platform -and $Instance.Platform -ne "") {
            $platformString = $Instance.Platform.ToString()
            Write-Log "Converted Platform to string: $platformString" "INFO"
            return $platformString.ToLower()
        }
        if ($Instance.PlatformDetails) {
            if ($Instance.PlatformDetails -like "*Windows*") { 
                Write-Log "Identified platform from PlatformDetails: windows" "INFO"
                return "windows" 
            }
            if ($Instance.PlatformDetails -like "*Linux*" -or $Instance.PlatformDetails -like "*Ubuntu*" -or
                $Instance.PlatformDetails -like "*Red Hat*" -or $Instance.PlatformDetails -like "*SUSE*" -or
                $Instance.PlatformDetails -like "*Amazon Linux*") { 
                Write-Log "Identified platform from PlatformDetails: linux" "INFO"
                return "linux" 
            }
        }
        if ($Instance.ImageId) {
            if ($Instance.ImageId -like "*windows*" -or $Instance.ImageId -like "*win*") { 
                Write-Log "Identified platform from ImageId: windows" "INFO"
                return "windows" 
            }
            if ($Instance.ImageId -like "*amzn*" -or $Instance.ImageId -like "*ubuntu*" -or
                $Instance.ImageId -like "*rhel*" -or $Instance.ImageId -like "*suse*") { 
                Write-Log "Identified platform from ImageId: linux" "INFO"
                return "linux" 
            }
        }
        Write-Log "No platform identified for instance $($Instance.InstanceId). Defaulting to 'linux'." "INFO"
        return "linux"
    } catch {
        Write-Log "Error determining platform for instance $($Instance.InstanceId): $($_.Exception.Message)" "ERROR"
        return "unknown"
    }
}

# Function to get all VPCs in the region
function Get-AllVPCs {
    param(
        [string]$Region,
        [string]$ProfileName
    )
    try {
        Write-Log "Discovering all VPCs in region: $Region for profile: $ProfileName" "INFO"
        $vpcs = Get-EC2Vpc -ProfileName $ProfileName -Region $Region -ErrorAction Stop
        if (-not $IncludeDefaultVPC) {
            $vpcs = $vpcs | Where-Object { -not $_.IsDefault }
            Write-Log "Excluded default VPC from analysis" "INFO"
        }
        if ($vpcs.Count -eq 0) {
            Write-Log "No VPCs found matching the criteria" "WARN"
            return @()
        }
        Write-Log "Found $($vpcs.Count) VPC(s) to analyze" "INFO"
        foreach ($vpc in $vpcs) {
            $vpcName = Get-ResourceName -Resource $vpc
            $isDefault = if ($vpc.IsDefault) { " (Default)" } else { "" }
            Write-Host "  - $($vpc.VpcId): $vpcName$isDefault" -ForegroundColor Gray
        }
        return $vpcs
    } catch {
        Write-Log "Error retrieving VPCs: $($_.Exception.Message)" "ERROR"
        return @()
    }
}

# Function to analyze subnet utilization across all VPCs
function Get-AllSubnetUtilization {
    param(
        [object[]]$VPCs,
        [string]$Region,
        [string]$ProfileName,
        [string]$AccountName,
        [string]$AccountId
    )
    $results = @()
    $totalVPCs = $VPCs.Count
    $currentVPC = 0
    $totalSubnetsAnalyzed = 0
    $totalInstancesFound = 0

    foreach ($vpc in $VPCs) {
        $currentVPC++
        $vpcName = Get-ResourceName -Resource $vpc
        $vpcIpfEnvironment = Get-ResourceTagValue -Resource $vpc -TagName "ipf:environment"
        $isDefault = if ($vpc.IsDefault) { " (Default)" } else { "" }
        # Determine if VPC is shared (ownerId != current accountId)
        $vpcIsShared = $false
        if ($vpc.PSObject.Properties['OwnerId'] -and $vpc.OwnerId -ne $AccountId) {
            $vpcIsShared = $true
        }
        Write-Progress -Activity "Analyzing VPCs" -Status "Processing VPC $($vpc.VpcId)$isDefault ($currentVPC of $totalVPCs)" -PercentComplete (($currentVPC / $totalVPCs) * 100)
        Write-Log "Analyzing VPC: $($vpc.VpcId) ($vpcName)$isDefault" "INFO"

        try {
            $subnets = Get-EC2Subnet -Filter @{ Name = "vpc-id"; Values = $vpc.VpcId } -ProfileName $ProfileName -Region $Region -ErrorAction Stop
            Write-Log "  Found $($subnets.Count) subnets" "INFO"
            $totalSubnetsAnalyzed += $subnets.Count

            foreach ($subnet in $subnets) {
                $subnetName = Get-ResourceName -Resource $subnet
                $filters = @(
                    @{ Name = "subnet-id"; Values = $subnet.SubnetId }
                    @{ Name = "instance-state-name"; Values = $InstanceStates }
                )
                $instances = @()
                try {
                    $reservations = Get-EC2Instance -Filter $filters -ProfileName $ProfileName -Region $Region -ErrorAction Stop
                    $instances = $reservations.Instances | Where-Object { $_.Tags -and $_.Tags.Key -notin $ProblematicTags }
                    Write-Host "      DEBUG: Subnet $($subnet.SubnetId) has $($instances.Count) instances" -ForegroundColor Gray
                } catch {
                    Write-Log "Error retrieving instances for subnet $($subnet.SubnetId): $($_.Exception.Message)" "WARN"
                }

                $instanceCount = $instances.Count
                $totalInstancesFound += $instanceCount
                $includeSubnet = if ($IncludeEmptySubnets) { $instanceCount -ge $MinInstanceCount } else { $instanceCount -gt 0 -and $instanceCount -ge $MinInstanceCount }

                if ($includeSubnet) {
                    $subnetResult = [PSCustomObject]@{
                        AccountName = $AccountName
                        AccountId = $AccountId
                        VPCId = $vpc.VpcId
                        VPCName = $vpcName
                        VPCIpfEnvironment = $vpcIpfEnvironment
                        VPCIsDefault = $vpc.IsDefault
                        VPCIsShared = $vpcIsShared
                        SubnetId = $subnet.SubnetId
                        SubnetName = $subnetName
                        AvailabilityZone = $subnet.AvailabilityZone
                        CidrBlock = $subnet.CidrBlock
                        InstanceCount = $instanceCount
                        AvailableIpAddresses = $subnet.AvailableIpAddressCount
                        State = $subnet.State
                        MapPublicIpOnLaunch = $subnet.MapPublicIpOnLaunch
                        SubnetType = if ($subnet.MapPublicIpOnLaunch) { "Public" } else { "Private" }
                        Instances = @()
                    }

                    if ($IncludeInstanceDetails -and $instanceCount -gt 0) {
                        foreach ($instance in $instances) {
                            try {
                                $instanceName = Get-ResourceName -Resource $instance
                                $instancePlatform = Get-InstancePlatform -Instance $instance
                                $subnetResult.Instances += [PSCustomObject]@{
                                    InstanceId = $instance.InstanceId
                                    InstanceName = $instanceName
                                    InstanceType = $instance.InstanceType
                                    State = $instance.State.Name
                                    PrivateIpAddress = $instance.PrivateIpAddress
                                    PublicIpAddress = $instance.PublicIpAddress
                                    LaunchTime = $instance.LaunchTime
                                    Platform = $instancePlatform
                                    VpcId = $instance.VpcId
                                    SubnetId = $instance.SubnetId
                                }
                            } catch {
                                Write-Log "Error processing instance $($instance.InstanceId) for subnet $($subnet.SubnetId): $($_.Exception.Message)" "ERROR"
                                $subnetResult.Instances += [PSCustomObject]@{
                                    InstanceId = $instance.InstanceId
                                    InstanceName = Get-ResourceName -Resource $instance
                                    InstanceType = $instance.InstanceType
                                    State = $instance.State.Name
                                    PrivateIpAddress = $instance.PrivateIpAddress
                                    PublicIpAddress = $instance.PublicIpAddress
                                    LaunchTime = $instance.LaunchTime
                                    Platform = "unknown"
                                    VpcId = $instance.VpcId
                                    SubnetId = $instance.SubnetId
                                }
                            }
                        }
                    }

                    $results += $subnetResult
                    $statusMessage = if ($instanceCount -gt 0) { "    Subnet: $($subnet.SubnetId) ($subnetName) - $instanceCount instances" } else { "    Subnet: $($subnet.SubnetId) ($subnetName) - Empty" }
                    $statusColor = if ($instanceCount -gt 0) { "Green" } else { "Gray" }
                    Write-Host $statusMessage -ForegroundColor $statusColor
                }
            }
        } catch {
            Write-Log "Error analyzing subnets in VPC $($vpc.VpcId): $($_.Exception.Message)" "ERROR"
        }
    }

    Write-Progress -Activity "Analyzing VPCs" -Completed
    Write-Log "Discovery Summary: Total VPCs: $($VPCs.Count), Subnets: $totalSubnetsAnalyzed, Instances: $totalInstancesFound, Matching Subnets: $($results.Count)" "INFO"
    return $results
}

# Function to display results
function Show-Results {
    param([object[]]$Results)
    if ($Results.Count -eq 0) {
        Write-Host "No subnets found with the specified criteria" -ForegroundColor Yellow
        return
    }

    $vpcStats = $Results | Group-Object VPCId | ForEach-Object {
        [PSCustomObject]@{
            VPCId = $_.Name
            VPCName = ($_.Group | Select-Object -First 1).VPCName
            IsDefault = ($_.Group | Select-Object -First 1).VPCIsDefault
            IsShared = ($_.Group | Select-Object -First 1).VPCIsShared
            SubnetCount = $_.Count
            TotalInstances = ($_.Group | Measure-Object -Property InstanceCount -Sum).Sum
        }
    }

    Write-Host "`nDetailed Summary:" -ForegroundColor Cyan
    Write-Host "- Total VPCs with matching subnets: $(($Results | Select-Object -Unique VPCId).Count)"
    Write-Host "- Total subnets with instances: $(($Results | Where-Object { $_.InstanceCount -gt 0 }).Count)"
    Write-Host "- Total subnets found: $($Results.Count)"
    Write-Host "- Total instances: $(($Results | Measure-Object -Property InstanceCount -Sum).Sum)"
    Write-Host "- Public subnets: $(($Results | Where-Object { $_.SubnetType -eq 'Public' }).Count)"
    Write-Host "- Private subnets: $(($Results | Where-Object { $_.SubnetType -eq 'Private' }).Count)"
    if ($vpcStats | Where-Object { $_.IsDefault }) { Write-Host "- Default VPC included: Yes" -ForegroundColor Gray }

    Write-Host "`nVPC Breakdown:" -ForegroundColor Cyan
    $vpcStats | Format-Table -Property VPCId, VPCName, IsDefault, IsShared, SubnetCount, TotalInstances -AutoSize


    if ($OutputFormat -eq "CSV") {
        $flatResults = @()
        foreach ($result in $Results) {
            if ($IncludeInstanceDetails -and $result.Instances.Count -gt 0) {
                foreach ($instance in $result.Instances) {
                    $flatResults += [PSCustomObject]@{
                        AccountName = $result.AccountName
                        AccountId = $result.AccountId
                        VPCId = $result.VPCId
                        VPCName = $result.VPCName
                        VPCIpfEnvironment = $result.VPCIpfEnvironment
                        VPCIsDefault = $result.VPCIsDefault
                        VPCIsShared = $result.VPCIsShared
                        SubnetId = $result.SubnetId
                        SubnetName = $result.SubnetName
                        SubnetType = $result.SubnetType
                        AvailabilityZone = $result.AvailabilityZone
                        CidrBlock = $result.CidrBlock
                        AvailableIpAddresses = $result.AvailableIpAddresses
                        InstanceCount = $result.InstanceCount
                        InstanceId = $instance.InstanceId
                        InstanceName = $instance.InstanceName
                        InstanceType = $instance.InstanceType
                        InstanceState = $instance.State
                        PrivateIpAddress = $instance.PrivateIpAddress
                        PublicIpAddress = $instance.PublicIpAddress
                        LaunchTime = $instance.LaunchTime
                        Platform = $instance.Platform
                    }
                }
            } else {
                $flatResults += [PSCustomObject]@{
                    AccountName = $result.AccountName
                    AccountId = $result.AccountId
                    VPCId = $result.VPCId
                    VPCName = $result.VPCName
                    VPCIpfEnvironment = $result.VPCIpfEnvironment
                    VPCIsDefault = $result.VPCIsDefault
                    VPCIsShared = $result.VPCIsShared
                    SubnetId = $result.SubnetId
                    SubnetName = $result.SubnetName
                    SubnetType = $result.SubnetType
                    AvailabilityZone = $result.AvailabilityZone
                    CidrBlock = $result.CidrBlock
                    AvailableIpAddresses = $result.AvailableIpAddresses
                    InstanceCount = $result.InstanceCount
                    InstanceId = ""
                    InstanceName = ""
                    InstanceType = ""
                    InstanceState = ""
                    PrivateIpAddress = ""
                    PublicIpAddress = ""
                    LaunchTime = ""
                    Platform = ""
                }
            }
        }

        try {
            $flatResults | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
            # Display deduplicated subnet summary in console
            $columnsToShow = @('AccountName', 'VPCId', 'VPCName', 'VPCIpfEnvironment', 'SubnetId', 'SubnetName', 'InstanceCount', 'VPCIsShared')
            $dedupedResults = $flatResults | Group-Object SubnetId | ForEach-Object {
                $_.Group | Select-Object -First 1 | Select-Object $columnsToShow
            }
            $dedupedResults | Format-Table -Property $columnsToShow -AutoSize
            if ($flatResults.Count -gt $dedupedResults.Count) {
                Write-Host "Displayed deduplicated subnet summary. See CSV file for instance details." -ForegroundColor Gray
            }
        } catch {
            Write-Log "Failed to export CSV: $($_.Exception.Message)" "ERROR"
        }
    }
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
        Write-Host "`nInteractive AWS Profile Selection (All AWS Profiles)" -ForegroundColor Cyan
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

# Function to test AWS profile connectivity
function Test-AwsProfileConnectivity {
    param([string]$ProfileName, [string]$Region)
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

    # Define problematic tags
    $ProblematicTags = @('ipf:sd:serviceowner', 'ipf:sd:businessowner', 'Owner')

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
        foreach ($profile in $AwsProfiles) {
            $currentRegion = Get-ValidAWSRegion -Region $Region -ProfileName $profile
            if (-not $currentRegion) {
                Write-Log "Skipping profile $profile due to invalid region" "ERROR"
                continue
            }
            Test-AwsProfileConnectivity -ProfileName $profile -Region $currentRegion
        }
    }

    # Main execution
    $allResults = @()
    $allVPCs = @()
    $processedAccounts = @()

    foreach ($profileName in $AwsProfiles) {
        $profileDisplayName = if ($profileName) { $profileName } else { "Default Profile" }
        Write-Log "`nProcessing Account: $profileDisplayName" "INFO"

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

        # Get VPCs
        $vpcs = Get-AllVPCs -Region $currentRegion -ProfileName $profileName
        if ($vpcs.Count -eq 0) {
            Write-Log "No VPCs found in account $accountName. Skipping." "WARN"
            continue
        }

        # Analyze subnets
        $subnetResults = Get-AllSubnetUtilization -VPCs $vpcs -Region $currentRegion -ProfileName $profileName -AccountName $accountName -AccountId $accountId
        $allResults += $subnetResults
        $allVPCs += $vpcs
    }

    # Set default output file
    if (-not $OutputFile) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        try {
            $regionSafe = Sanitize-String -InputString $currentRegion
            $profileSafe = Sanitize-String -InputString $(if ($AwsProfiles.Count -eq 1 -and $AwsProfiles[0]) { $AwsProfiles[0] } else { "multi-account" })
            $OutputFile = Join-Path $OutputDir "subnet_utilization_${profileSafe}_${regionSafe}_${timestamp}.csv"
        } catch {
            Write-Log "Error in generating safe output filename: $($_.Exception.Message). Using default values." "ERROR"
            $regionSafe = "unknown-region"
            $profileSafe = "unknown-profile"
            $OutputFile = Join-Path $OutputDir "subnet_utilization_${profileSafe}_${regionSafe}_${timestamp}.csv"
        }
    }

    # Display execution summary
    Write-Host "`nMulti-Account AWS Subnet Utilization Analysis" -ForegroundColor Cyan
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "Profiles: $($AwsProfiles.Count) account(s)" -ForegroundColor Gray
    Write-Host "Region: $(if ($Region) { $Region } else { 'Account-configured regions' })" -ForegroundColor Gray
    Write-Host "Instance States: $($InstanceStates -join ', ')" -ForegroundColor Gray
    Write-Host "Include Instance Details: $IncludeInstanceDetails" -ForegroundColor Gray
    Write-Host "Include Empty Subnets: $IncludeEmptySubnets" -ForegroundColor Gray
    Write-Host "Include Default VPC: $IncludeDefaultVPC" -ForegroundColor Gray
    Write-Host "Minimum Instance Count: $MinInstanceCount" -ForegroundColor Gray
    Write-Host ""

    # Display results
    if ($allResults.Count -eq 0) {
        Write-Log "No subnets found matching the criteria across all accounts" "WARN"
        exit 0
    }
    Show-Results -Results $allResults

    # Output summary CSV
    $summaryCsvFile = try {
        Sanitize-String -InputString ($OutputFile -replace '\.csv$', '_subnet_summary.csv')
    } catch {
        Write-Log "Error generating summary CSV filename: $($_.Exception.Message). Using default." "ERROR"
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        Join-Path $OutputDir "subnet_utilization_summary_${timestamp}.csv"
    }
    try {
        $allResults | Select-Object VPCId, VPCName, SubnetName, SubnetId, InstanceCount | Export-Csv -Path $summaryCsvFile -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Host "Subnet summary exported to: $summaryCsvFile" -ForegroundColor Green
    } catch {
        Write-Log "Failed to export subnet summary CSV: $($_.Exception.Message)" "ERROR"
    }

    # Final summary
    Write-Log "FINAL SUMMARY" "INFO"
    Write-Log "Total accounts processed: $($processedAccounts.Count)" "INFO"
    Write-Log "Total VPCs discovered: $($allVPCs.Count)" "INFO"
    Write-Log "Total subnets found: $($allResults.Count)" "INFO"
    Write-Log "Total instances: $(($allResults | Measure-Object -Property InstanceCount -Sum).Sum)" "INFO"
    Write-Log "Output file: $OutputFile" "INFO"
    Write-Log "Script completed successfully!" "INFO"

} catch {
    Write-Log "Fatal error: $($_.Exception.Message)" "ERROR"
    exit 1
}