# Get-EC2Instances.ps1
# PowerShell script to retrieve EC2 instance details across multiple AWS profiles with interactive selection
# Uses AWS Tools for PowerShell instead of AWS CLI
# Supports tag filtering, AMI usage reporting, shared VPC handling, SSORole, Subnet CIDRBlock, and additional instance attributes
# Outputs instance details and AMI report to CSV files with region-specific filenames
# Fixed DisableApiTermination and InstanceInitiatedShutdownBehavior retrieval
# Removed RootVolumeSize and RootVolumeType
# Fixed VpcOwnerId and VpcIsShared calculation
# Updated AccountName to use profile name (without sso- prefix and -nonprivFujitsuCSA suffix) if no alias is found
# Added validation of EC2 tag keys per AWS restrictions with ProblematicTags column
# Fixed tag key validation to correctly handle spaces and invalid characters

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, HelpMessage="Path to the directory containing AWS.Tools modules.")]
    [string]$PSModulesPath,
    [Parameter()]
    [string]$Region,
    [Parameter()]
    [string[]]$AwsProfiles,
    [Parameter()]
    [bool]$DebugPlatform = $false,
    [Parameter()]
    [string]$OutputFile,
    [Parameter()]
    [bool]$InteractiveSelection = $true,
    [Parameter()]
    [bool]$FilterProblematicTags = $true,
    [Parameter()]
    [bool]$TestProfilesFirst = $true
)

# Get script directory and set relative paths
$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
$OutputDir = Join-Path $ScriptDir "output"
$LogFilePath = Join-Path $OutputDir "EC2_Instance_Analysis_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Define problematic tags that cause Unicode encoding errors
$ProblematicTags = @('ipf:sd:serviceowner', 'ipf:sd:businessowner', 'Owner')

# Function to validate EC2 tag keys per AWS restrictions
function Test-EC2TagKey {
    param(
        [string]$TagKey
    )
    try {
        # AWS EC2 Tag Restrictions (https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/work-with-tags-in-IMDS.html)
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
        if ($TagKey -match '^aws:') {
            return "Tag key starts with reserved prefix 'aws:'"
        }
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
            $resourceId = if ($Resource.PSObject.Properties['InstanceId']) { $Resource.InstanceId } else { $Resource.ImageId }
            Write-Log "No Name tag found for resource ${resourceId}" "DEBUG"
            return "(No Name Tag)"
        }
    } catch {
        $resourceId = if ($Resource.PSObject.Properties['InstanceId']) { $Resource.InstanceId } else { $Resource.ImageId }
        Write-Log "Error accessing tags for resource ${resourceId}: $($_.Exception.Message)" "WARN"
        return "(No Name Tag)"
    }
}

# Function to get a specific tag value
function Get-ResourceTagValue {
    param(
        [object]$Resource,
        [string]$TagName
    )
    try {
        $tag = $Resource.Tags | Where-Object { $_.Key -eq $TagName }
        if ($tag) {
            return $tag.Value
        } else {
            $resourceId = if ($Resource.PSObject.Properties['InstanceId']) { $Resource.InstanceId } else { $Resource.ImageId }
            Write-Log "No ${TagName} tag found for resource ${resourceId}" "DEBUG"
            return "N/A"
        }
    } catch {
        $resourceId = if ($Resource.PSObject.Properties['InstanceId']) { $Resource.InstanceId } else { $Resource.ImageId }
        Write-Log "Error accessing ${TagName} tag for resource ${resourceId}: $($_.Exception.Message)" "WARN"
        return "N/A"
    }
}

# Function to determine instance platform
function Get-InstancePlatform {
    param([object]$Instance)
    try {
        Write-Log "Determining platform for instance $($Instance.InstanceId): Platform=$($Instance.Platform), PlatformDetails=$($Instance.PlatformDetails)" "INFO"
        if ($null -ne $Instance.Platform -and $Instance.Platform -ne "") {
            $platformString = $Instance.Platform.ToString()
            Write-Log "Converted Platform to string: ${platformString}" "INFO"
            return $platformString.ToLower()
        }
        if ($Instance.PlatformDetails) {
            if ($Instance.PlatformDetails -like "*Windows*") { 
                Write-Log "Identified platform from PlatformDetails: windows" "INFO"
                return "Windows" 
            }
            if ($Instance.PlatformDetails -like "*Linux*" -or $Instance.PlatformDetails -like "*Ubuntu*" -or
                $Instance.PlatformDetails -like "*Red Hat*" -or $Instance.PlatformDetails -like "*SUSE*" -or
                $Instance.PlatformDetails -like "*Amazon Linux*") { 
                Write-Log "Identified platform from PlatformDetails: linux" "INFO"
                return "Linux/UNIX" 
            }
        }
        if ($Instance.ImageId) {
            if ($Instance.ImageId -like "*windows*" -or $Instance.ImageId -like "*win*") { 
                Write-Log "Identified platform from ImageId: windows" "INFO"
                return "Windows" 
            }
            if ($Instance.ImageId -like "*amzn*" -or $Instance.ImageId -like "*ubuntu*" -or
                $Instance.ImageId -like "*rhel*" -or $Instance.ImageId -like "*suse*") { 
                Write-Log "Identified platform from ImageId: linux" "INFO"
                return "Linux/UNIX" 
            }
        }
        Write-Log "No platform identified for instance $($Instance.InstanceId). Defaulting to 'Linux/UNIX'." "INFO"
        return "Linux/UNIX (Inferred)"
    } catch {
        Write-Log "Error determining platform for instance $($Instance.InstanceId): $($_.Exception.Message)" "ERROR"
        return "Unknown"
    }
}

# Function to get AMI name from AMI ID
function Get-AMIName {
    param(
        [string]$AmiId,
        [string]$Region,
        [string]$ProfileName
    )
    if ($AmiId -eq 'N/A' -or [string]::IsNullOrEmpty($AmiId)) {
        return 'N/A'
    }
    try {
        $ami = Get-EC2Image -ImageId $AmiId -ProfileName $ProfileName -Region $Region -ErrorAction Stop
        if ($ami -and $ami.Count -gt 0) {
            $amiName = $ami[0].Name
            if ($amiName -and $amiName.Trim() -ne "" -and $amiName.Trim() -ne "null") {
                return $amiName.Trim()
            } else {
                Write-Log "AMI ${AmiId} has no name" "DEBUG"
                return "AMI No Name (${AmiId})"
            }
        } else {
            Write-Log "AMI ${AmiId} not found or not accessible" "WARN"
            return "AMI Deleted/Private (${AmiId})"
        }
    } catch {
        Write-Log "Error retrieving AMI info for ${AmiId}: $($_.Exception.Message)" "WARN"
        return "AMI Query Error (${AmiId})"
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

# Function to get subnet CIDR block
function Get-SubnetCidrBlock {
    param(
        [string]$SubnetId,
        [string]$Region,
        [string]$ProfileName,
        [hashtable]$SubnetCache
    )
    if (-not $SubnetId -or $SubnetId -eq 'N/A') {
        return 'N/A'
    }
    $cacheKey = "${ProfileName}:${Region}:${SubnetId}"
    if ($SubnetCache.ContainsKey($cacheKey)) {
        Write-Log "Retrieved CIDR block for subnet ${SubnetId} from cache" "DEBUG"
        return $SubnetCache[$cacheKey]
    }
    try {
        $subnet = Get-EC2Subnet -SubnetId $SubnetId -ProfileName $ProfileName -Region $Region -ErrorAction Stop
        if ($subnet -and $subnet.CidrBlock) {
            $SubnetCache[$cacheKey] = $subnet.CidrBlock
            Write-Log "Retrieved CIDR block '$($subnet.CidrBlock)' for subnet ${SubnetId}" "INFO"
            return $subnet.CidrBlock
        } else {
            Write-Log "No CIDR block found for subnet ${SubnetId}" "WARN"
            return "N/A"
        }
    } catch {
        Write-Log "Error retrieving CIDR block for subnet ${SubnetId}: $($_.Exception.Message)" "WARN"
        return "Subnet Query Error (${SubnetId})"
    }
}

# Function to get VPC OwnerId
function Get-VpcOwnerId {
    param(
        [string]$VpcId,
        [string]$Region,
        [string]$ProfileName,
        [hashtable]$VpcCache
    )
    if (-not $VpcId -or $VpcId -eq 'N/A') {
        return 'N/A'
    }
    $cacheKey = "${ProfileName}:${Region}:${VpcId}"
    if ($VpcCache.ContainsKey($cacheKey)) {
        Write-Log "Retrieved VPC OwnerId for VPC ${VpcId} from cache" "DEBUG"
        return $VpcCache[$cacheKey]
    }
    try {
        $vpc = Get-EC2VPC -VpcId $VpcId -ProfileName $ProfileName -Region $Region -ErrorAction Stop
        if ($vpc -and $vpc.OwnerId) {
            $VpcCache[$cacheKey] = $vpc.OwnerId
            Write-Log "Retrieved OwnerId '$($vpc.OwnerId)' for VPC ${VpcId}" "INFO"
            return $vpc.OwnerId
        } else {
            Write-Log "No OwnerId found for VPC ${VpcId}" "WARN"
            return "N/A"
        }
    } catch {
        Write-Log "Error retrieving OwnerId for VPC ${VpcId}: $($_.Exception.Message)" "WARN"
        return "VPC Query Error (${VpcId})"
    }
}

# Function to get instance attributes (DisableApiTermination, InstanceInitiatedShutdownBehavior)
function Get-InstanceAttributes {
    param(
        [string]$InstanceId,
        [string]$Region,
        [string]$ProfileName,
        [hashtable]$AttributeCache
    )
    $cacheKey = "${ProfileName}:${Region}:${InstanceId}"
    if ($AttributeCache.ContainsKey($cacheKey)) {
        Write-Log "Retrieved attributes for instance ${InstanceId} from cache" "DEBUG"
        return $AttributeCache[$cacheKey]
    }
    try {
        $disableApiTermination = (Get-EC2InstanceAttribute -InstanceId $InstanceId -Attribute disableApiTermination -ProfileName $ProfileName -Region $Region -ErrorAction Stop).DisableApiTermination
        $shutdownBehavior = (Get-EC2InstanceAttribute -InstanceId $InstanceId -Attribute instanceInitiatedShutdownBehavior -ProfileName $ProfileName -Region $Region -ErrorAction Stop).InstanceInitiatedShutdownBehavior
        $attributes = @{
            DisableApiTermination = $disableApiTermination
            InstanceInitiatedShutdownBehavior = $shutdownBehavior
        }
        $AttributeCache[$cacheKey] = $attributes
        Write-Log "Retrieved attributes for instance ${InstanceId}: DisableApiTermination=$disableApiTermination, InstanceInitiatedShutdownBehavior=$shutdownBehavior" "INFO"
        return $attributes
    } catch {
        Write-Log "Error retrieving attributes for instance ${InstanceId}: $($_.Exception.Message)" "WARN"
        return @{
            DisableApiTermination = "N/A"
            InstanceInitiatedShutdownBehavior = "N/A"
        }
    }
}

# Function to generate AMI usage report
function Get-AmiUsageReport {
    param(
        [array]$InstanceData,
        [string]$Region,
        [string]$ProfileName
    )
    Write-Log "Generating AMI usage report for profile ${ProfileName}" "INFO"
    $uniqueAmis = $InstanceData | ForEach-Object { $_.AMIId } | Sort-Object -Unique | Where-Object { $_ -ne 'N/A' -and -not [string]::IsNullOrEmpty($_) }
    if ($uniqueAmis.Count -eq 0) {
        Write-Log "No valid AMI IDs found for analysis in profile ${ProfileName}" "WARN"
        return @()
    }
    $amiReport = @()
    foreach ($amiId in $uniqueAmis) {
        $instancesUsingAmi = $InstanceData | Where-Object { $_.AMIId -eq $amiId }
        $instanceCount = $instancesUsingAmi.Count
        $amiName = Get-AMIName -AmiId $amiId -Region $Region -ProfileName $ProfileName
        try {
            $amiDetails = Get-EC2Image -ImageId $amiId -ProfileName $ProfileName -Region $Region -ErrorAction Stop
            if ($amiDetails -and $amiDetails.Count -gt 0) {
                $ami = $amiDetails[0]
                $amiDescription = if ($ami.Description) { $ami.Description } else { 'N/A' }
                $amiArchitecture = if ($ami.Architecture) { $ami.Architecture } else { 'N/A' }
                $amiPlatform = if ($ami.PlatformDetails) { $ami.PlatformDetails } else { 'Linux/UNIX' }
                $amiCreationDate = if ($ami.CreationDate) { $ami.CreationDate } else { 'N/A' }
                $amiOwnerId = if ($ami.OwnerId) { $ami.OwnerId } else { 'N/A' }
                $amiState = if ($ami.State) { $ami.State } else { 'N/A' }
                $amiPublic = if ($ami.Public) { $ami.Public } else { $false }
            } else {
                $amiDescription = 'AMI not found or no access'
                $amiArchitecture = 'N/A'
                $amiPlatform = 'N/A'
                $amiCreationDate = 'N/A'
                $amiOwnerId = 'N/A'
                $amiState = 'N/A'
                $amiPublic = $false
            }
        } catch {
            Write-Log "Error retrieving AMI details for ${amiId}: $($_.Exception.Message)" "WARN"
            $amiDescription = 'Error retrieving details'
            $amiArchitecture = 'N/A'
            $amiPlatform = 'N/A'
            $amiCreationDate = 'N/A'
            $amiOwnerId = 'N/A'
            $amiState = 'N/A'
            $amiPublic = $false
        }
        $accountBreakdown = $instancesUsingAmi | Group-Object AccountName | ForEach-Object { "$($_.Name):$($_.Count)" }
        $instanceTypeBreakdown = $instancesUsingAmi | Group-Object InstanceType | ForEach-Object { "$($_.Name):$($_.Count)" }
        $stateBreakdown = $instancesUsingAmi | Group-Object InstanceState | ForEach-Object { "$($_.Name):$($_.Count)" }
        $amiReport += [PSCustomObject]@{
            AMIId = $amiId
            AMIName = $amiName
            Description = $amiDescription
            Architecture = $amiArchitecture
            Platform = $amiPlatform
            CreationDate = $amiCreationDate
            OwnerId = $amiOwnerId
            State = $amiState
            Public = $amiPublic
            InstanceCount = $instanceCount
            Region = $Region
            SSORole = Get-SSORoleName -ProfileName $ProfileName -Region $Region
            AccountBreakdown = ($accountBreakdown -join '; ')
            InstanceTypeBreakdown = ($instanceTypeBreakdown -join '; ')
            StateBreakdown = ($stateBreakdown -join '; ')
        }
    }
    Write-Log "Found $($amiReport.Count) unique AMIs in use for profile ${ProfileName}" "INFO"
    return $amiReport
}

# Function to process instances for a single profile
function Get-EC2InstancesForProfile {
    param(
        [string]$ProfileName,
        [string]$Region,
        [bool]$FilterTags,
        [hashtable]$SubnetCache,
        [hashtable]$VpcCache
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
                    $accountName = $ProfileName -replace '^sso-' -replace '-nonprivFujitsuCSA$', ''
                    Write-Log "No account alias found for profile ${DisplayProfileName}. Derived AccountName '${accountName}' from ProfileName." "INFO"
                } else {
                    $accountName = 'Default'
                    Write-Log "No account alias found for default profile. Using 'Default' as AccountName." "INFO"
                }
            }
        } catch {
            Write-Log "Failed to get account alias for profile ${DisplayProfileName}: $($_.Exception.Message)." "WARN"
            if ($ProfileName) {
                $accountName = $ProfileName -replace '^sso-' -replace '-nonprivFujitsuCSA$', ''
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
        Write-Host "`nInteractive AWS Profile Selection" -ForegroundColor Cyan
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

    # Display tag filtering status
    if ($FilterProblematicTags) {
        Write-Log "Tag filtering: ENABLED. Excluding tags: $($ProblematicTags -join ', ')" "INFO"
    } else {
        Write-Log "Tag filtering: DISABLED. Including all tags." "INFO"
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
            Write-Host "`nAvailable AWS Profiles:" -ForegroundColor Cyan
            for ($i = 0; $i -lt $profileList.Count; $i++) {
                $CurrentIndicator = if ($env:AWS_PROFILE -eq $profileList[$i]) { " (current)" } else { "" }
                Write-Host "  $($i + 1). $($profileList[$i])$CurrentIndicator" -ForegroundColor Gray
            }
            Write-Host "  0. Use default profile" -ForegroundColor Gray
            do {
                $Selection = Read-Host "`nSelect AWS profile (0-$($profileList.Count))"
                if ($Selection -eq "0") {
                    $AwsProfiles = @("")
                    Write-Log "Using default AWS profile" "INFO"
                    break
                } elseif ($Selection -match '^\d+$' -and [int]$Selection -ge 1 -and [int]$Selection -le $profileList.Count) {
                    $AwsProfiles = @($profileList[[int]$Selection - 1])
                    Write-Log "Selected profile: $($AwsProfiles[0])" "INFO"
                    break
                } else {
                    Write-Host "Invalid selection. Please enter a number between 0 and $($profileList.Count)." -ForegroundColor Yellow
                }
            } while ($true)
        }
        Write-Log "Found $($profileList.Count) profiles" "INFO"
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
            Write-Log "No valid profiles found after connectivity tests. Please check your AWS configuration." "ERROR"
            exit 1
        }
        $AwsProfiles = $validProfiles
        Write-Log "Proceeding with $($validProfiles.Count) valid profiles" "INFO"
    }

    # Initialize combined output arrays and caches
    $allOutput = @()
    $allAmiReports = @()
    $processedAccounts = @()
    $instanceIdsProcessed = @{} # Track processed instances to avoid duplicates
    $subnetCache = @{} # Cache subnet CIDR blocks
    $attributeCache = @{} # Cache instance attributes
    $vpcCache = @{} # Cache VPC OwnerIds
    $regionsUsed = @() # Track regions used across profiles

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
        $instances, $accountName, $accountId = Get-EC2InstancesForProfile -ProfileName $profileName -Region $currentRegion -FilterTags $FilterProblematicTags -SubnetCache $subnetCache -VpcCache $vpcCache
        if (-not $instances) {
            Write-Log "No instances or unable to retrieve data for profile ${profileName}" "WARN"
            continue
        }
        $processedAccounts += [PSCustomObject]@{
            SSORole = $ssoRole
            AccountName = $accountName
            AccountId = $accountId
        }
        $profileInstances = @()
        foreach ($instance in $instances) {
            if ($instanceIdsProcessed.ContainsKey($instance.InstanceId)) {
                Write-Log "Instance $($instance.InstanceId) already processed. Skipping to avoid duplication." "DEBUG"
                continue
            }
            $instanceIdsProcessed[$instance.InstanceId] = $true
            try {
                $tags = if ($FilterProblematicTags) { $instance.Tags | Where-Object { $_.Key -notin $ProblematicTags } } else { $instance.Tags }
                $problematicTagList = @()
                foreach ($tag in $instance.Tags) {
                    $validationResult = Test-EC2TagKey -TagKey $tag.Key
                    if ($validationResult) {
                        $problematicTagList += "$($tag.Key): $validationResult"
                    }
                }
                $problematicTagsFormatted = if ($problematicTagList.Count -gt 0) { $problematicTagList -join '; ' } else { "None" }
                $instanceName = Get-ResourceName -Resource $instance
                $monitoredValue = Get-ResourceTagValue -Resource $instance -TagName "Monitored"
                $ipfEnvironmentValue = Get-ResourceTagValue -Resource $instance -TagName "ipf:environment"
                $sqlServerMonitoredValue = Get-ResourceTagValue -Resource $instance -TagName "SqlServerMonitored"
                $ipfServiceNameValue = Get-ResourceTagValue -Resource $instance -TagName "ipf:sd:servicename"
                $fcmsMonitoringValue = Get-ResourceTagValue -Resource $instance -TagName "fcms:CustomMonitoring"
                $roleValue = Get-ResourceTagValue -Resource $instance -TagName "role"
                $applicationValue = Get-ResourceTagValue -Resource $instance -TagName "application"
                $vCPU = if ($instance.CpuOptions.CoreCount -and $instance.CpuOptions.ThreadsPerCore) {
                    $instance.CpuOptions.CoreCount * $instance.CpuOptions.ThreadsPerCore
                } else { "N/A (Lookup needed for $($instance.InstanceType))" }
                $platformDisplay = Get-InstancePlatform -Instance $instance
                $cwMonitoringDisplay = switch ($instance.Monitoring.State) {
                    "enabled" { "Detailed" }
                    "disabled" { "Basic" }
                    "pending" { "Pending" }
                    default { if ($null -ne $instance.Monitoring.State) { $instance.Monitoring.State } else { "N/A" } }
                }
                $amiName = Get-AMIName -AmiId $instance.ImageId -Region $currentRegion -ProfileName $profileName
                $iamInstanceProfile = if ($instance.IamInstanceProfile -and $instance.IamInstanceProfile.Arn) {
                    $instance.IamInstanceProfile.Arn
                } else { "N/A" }
                $securityGroupIds = if ($instance.SecurityGroups -and $instance.SecurityGroups.Count -gt 0) {
                    ($instance.SecurityGroups | ForEach-Object { $_.GroupId }) -join ';'
                } else { "N/A" }
                $secondaryPrivateIps = if ($instance.NetworkInterfaces) {
                    $allSecondaryIps = @()
                    foreach ($eni in $instance.NetworkInterfaces) {
                        if ($eni.PrivateIpAddresses) {
                            $allSecondaryIps += $eni.PrivateIpAddresses | Where-Object { $_.Primary -eq $false } | ForEach-Object { $_.PrivateIpAddress }
                        }
                    }
                    if ($allSecondaryIps.Count -gt 0) { $allSecondaryIps -join ';' } else { "N/A" }
                } else { "N/A" }
                $tagsFormatted = if ($tags -and $tags.Count -gt 0) {
                    ($tags | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ';'
                } else { "N/A" }
                $vpcOwnerId = Get-VpcOwnerId -VpcId $instance.VpcId -Region $currentRegion -ProfileName $profileName -VpcCache $vpcCache
                $isSharedVPC = if ($instance.VpcId -and $vpcOwnerId -ne 'N/A' -and $vpcOwnerId -ne $accountId) { $true } else { $false }
                $cidrBlock = Get-SubnetCidrBlock -SubnetId $instance.SubnetId -Region $currentRegion -ProfileName $profileName -SubnetCache $subnetCache
                $attributes = Get-InstanceAttributes -InstanceId $instance.InstanceId -Region $currentRegion -ProfileName $profileName -AttributeCache $attributeCache
                $disableApiTermination = $attributes.DisableApiTermination
                $shutdownBehavior = $attributes.InstanceInitiatedShutdownBehavior
                $metadataHttpTokens = if ($instance.MetadataOptions -and $instance.MetadataOptions.HttpTokens) {
                    $instance.MetadataOptions.HttpTokens
                } else { "N/A" }
                $metadataHttpEndpoint = if ($instance.MetadataOptions -and $instance.MetadataOptions.HttpEndpoint) {
                    $instance.MetadataOptions.HttpEndpoint
                } else { "N/A" }
                $metadataHttpHopLimit = if ($instance.MetadataOptions -and $instance.MetadataOptions.HttpPutResponseHopLimit) {
                    $instance.MetadataOptions.HttpPutResponseHopLimit
                } else { "N/A" }
                $instanceMetadataTags = if ($instance.MetadataOptions -and $instance.MetadataOptions.InstanceMetadataTags) {
                    $instance.MetadataOptions.InstanceMetadataTags
                } else { "N/A" }
                $props = [ordered]@{
                    AccountName = $accountName
                    AccountId = $accountId
                    SSORole = $ssoRole
                    InstanceId = $instance.InstanceId
                    InstanceName = $instanceName
                    Tenancy = if ($instance.Placement.Tenancy) { $instance.Placement.Tenancy } else { "N/A" }
                    Monitored = $monitoredValue
                    IpfEnvironment = $ipfEnvironmentValue
                    SqlServerMonitored = $sqlServerMonitoredValue
                    IpfServiceName = $ipfServiceNameValue
                    FcmsCustomMonitoring = $fcmsMonitoringValue
                    Role = $roleValue
                    Application = $applicationValue
                    InstanceState = $instance.State.Name
                    AvailabilityZone = $instance.Placement.AvailabilityZone
                    VpcId = $instance.VpcId
                    VpcOwnerId = $vpcOwnerId
                    VpcIsShared = $isSharedVPC
                    SubnetId = $instance.SubnetId
                    CidrBlock = $cidrBlock
                    PrivateIpAddress = $instance.PrivateIpAddress
                    SecondaryPrivateIPs = $secondaryPrivateIps
                    Platform = $platformDisplay
                    InstanceType = $instance.InstanceType
                    CWMonitoring = $cwMonitoringDisplay
                    vCPU = $vCPU
                    AMIId = $instance.ImageId
                    AMIName = $amiName
                    IamInstanceProfile = $iamInstanceProfile
                    EbsOptimized = $instance.EbsOptimized
                    MetadataOptionsHttpTokens = $metadataHttpTokens
                    MetadataOptionsHttpEndpoint = $metadataHttpEndpoint
                    MetadataOptionsHttpPutResponseHopLimit = $metadataHttpHopLimit
                    InstanceMetadataTags = $instanceMetadataTags
                    DisableApiTermination = $disableApiTermination
                    InstanceInitiatedShutdownBehavior = $shutdownBehavior
                    KeyPair = $instance.KeyName
                    SecurityGroupIds = $securityGroupIds
                    Tags = $tagsFormatted
                    TagsFiltered = $FilterProblematicTags
                    ProblematicTags = $problematicTagsFormatted
                }
                if ($DebugPlatform) {
                    $props.Add("RawPlatform", $instance.Platform)
                    $props.Add("RawPlatformDetails", $instance.PlatformDetails)
                }
                $allOutput += [PSCustomObject]$props
                $profileInstances += [PSCustomObject]$props
            } catch {
                Write-Log "Error processing instance $($instance.InstanceId): $($_.Exception.Message)" "ERROR"
            }
        }
        if ($profileInstances.Count -gt 0) {
            $profileAmiReport = Get-AmiUsageReport -InstanceData $profileInstances -Region $currentRegion -ProfileName $profileName
            if ($profileAmiReport.Count -gt 0) {
                $allAmiReports += $profileAmiReport
            }
        }
    }

    # Set output files
    if (-not $OutputFile) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        try {
            $regionSafe = if ($regionsUsed.Count -eq 1) { Sanitize-String -InputString $regionsUsed[0] } else { "multiregion" }
            $profileCount = $AwsProfiles.Count
            $filterSuffix = if ($FilterProblematicTags) { "_filtered" } else { "_unfiltered" }
            $OutputFile = Join-Path $OutputDir "ec2_instances_${profileCount}accounts_${regionSafe}${filterSuffix}_${timestamp}.csv"
            Write-Log "Generated output filename: ${OutputFile}" "INFO"
        } catch {
            Write-Log "Error generating output filename: $($_.Exception.Message). Using default." "ERROR"
            $OutputFile = Join-Path $OutputDir "ec2_instances_${timestamp}.csv"
        }
    }
    $AmiOutputFile = $OutputFile -replace "\.csv$", "_ami_usage_report.csv"

    # Display summary
    Write-Host "`nEC2 Instance Analysis Summary" -ForegroundColor Cyan
    Write-Host "============================" -ForegroundColor Cyan
    Write-Host "Script version: 12.10 (EC2 Inventory + AMI Usage Reporting with PowerShell modules, SSORole, CIDRBlock, additional attributes, region-specific filenames, fixed termination/shutdown attributes, fixed VpcOwnerId/VpcIsShared, updated AccountName derivation, added EC2 tag key validation, fixed space detection in tag keys)" -ForegroundColor Green
    Write-Host "Tag filtering enabled: $FilterProblematicTags" -ForegroundColor Green
    if ($FilterProblematicTags) {
        Write-Host "Filtered tags: $($ProblematicTags -join ', ')" -ForegroundColor Gray
    }
    Write-Host "Profiles processed: $($AwsProfiles.Count)" -ForegroundColor Green
    Write-Host "Regions used: $($regionsUsed -join ', ')" -ForegroundColor Green
    Write-Host "Total instances found: $($allOutput.Count)" -ForegroundColor Green
    Write-Host "Unique accounts: $(($allOutput | Select-Object -Unique AccountId).Count)" -ForegroundColor Green
    Write-Host "Log file: ${LogFilePath}" -ForegroundColor Gray
    Write-Host ""

    # Display account summary
    $accountSummary = $allOutput | Group-Object AccountName | Sort-Object Name
    Write-Log "Instances by Account:" "INFO"
    foreach ($account in $accountSummary) {
        Write-Log "  $($account.Name): $($account.Count) instances" "INFO"
    }

    # Display results
    if ($allOutput.Count -eq 0) {
        Write-Log "No instances were processed successfully across all profiles" "WARN"
        exit 0
    }
    if ($allOutput.Count -le 20) {
        Write-Host "EC2 Instances Details (All Results):" -ForegroundColor Cyan
        $allOutput | Format-Table -AutoSize
    } else {
        Write-Host "EC2 Instances Details (First 20 of $($allOutput.Count) results):" -ForegroundColor Cyan
        $allOutput | Select-Object -First 20 | Format-Table -AutoSize
        Write-Host "... and $($allOutput.Count - 20) more instances. See CSV file for complete results." -ForegroundColor Yellow
    }

    # Export instance results
    try {
        $allOutput | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Log "Successfully exported instance data to ${OutputFile}" "INFO"
    } catch {
        Write-Log "Failed to export instance data to CSV: $($_.Exception.Message)" "ERROR"
    }

    # Export AMI usage report
    if ($allAmiReports.Count -gt 0) {
        try {
            $consolidatedAmiReport = $allAmiReports | Group-Object AMIId | ForEach-Object {
                $amiGroup = $_.Group
                $firstAmi = $amiGroup[0]
                $totalInstances = ($amiGroup | Measure-Object InstanceCount -Sum).Sum
                $rolesUsing = ($amiGroup | Select-Object -ExpandProperty SSORole -Unique) -join '; '
                $accountsUsing = ($amiGroup | ForEach-Object { $_.AccountBreakdown } | Where-Object { $_ }) -join '; '
                [PSCustomObject]@{
                    AMIId = $firstAmi.AMIId
                    AMIName = $firstAmi.AMIName
                    Description = $firstAmi.Description
                    Architecture = $firstAmi.Architecture
                    Platform = $firstAmi.Platform
                    CreationDate = $firstAmi.CreationDate
                    OwnerId = $firstAmi.OwnerId
                    State = $firstAmi.State
                    Public = $firstAmi.Public
                    TotalInstanceCount = $totalInstances
                    SSORolesUsing = $rolesUsing
                    AccountBreakdown = $accountsUsing
                    InstanceTypeBreakdown = ($amiGroup | ForEach-Object { $_.InstanceTypeBreakdown } | Where-Object { $_ }) -join '; '
                    StateBreakdown = ($amiGroup | ForEach-Object { $_.StateBreakdown } | Where-Object { $_ }) -join '; '
                }
            } | Sort-Object TotalInstanceCount -Descending
            $consolidatedAmiReport | Export-Csv -Path $AmiOutputFile -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            Write-Log "Successfully exported AMI usage report to ${AmiOutputFile}" "INFO"
            Write-Host "`nAMI Usage Summary:" -ForegroundColor Yellow
            Write-Host "Total unique AMIs in use: $($consolidatedAmiReport.Count)" -ForegroundColor Green
            Write-Host "Top 10 most used AMIs:" -ForegroundColor Cyan
            $consolidatedAmiReport | Select-Object -First 10 | Format-Table AMIId, AMIName, Platform, TotalInstanceCount -AutoSize
        } catch {
            Write-Log "Failed to export AMI usage report: $($_.Exception.Message)" "ERROR"
        }
    } else {
        Write-Log "No AMI data collected for reporting" "WARN"
    }

    # Final summary
    Write-Log "FINAL SUMMARY" "INFO"
    Write-Log "Total accounts processed: $($processedAccounts.Count)" "INFO"
    Write-Log "Total instances found: $($allOutput.Count)" "INFO"
    Write-Log "Total unique AMIs: $($allAmiReports.Count)" "INFO"
    Write-Log "Regions used: $($regionsUsed -join ', ')" "INFO"
    Write-Log "Output file: ${OutputFile}" "INFO"
    Write-Log "AMI report file: ${AmiOutputFile}" "INFO"
    Write-Log "Script completed successfully!" "INFO"

} catch {
    Write-Log "Fatal error: $($_.Exception.Message)" "ERROR"
    exit 1
}