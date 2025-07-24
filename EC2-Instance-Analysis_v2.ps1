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

# Global function definitions
function Write-Log {
    param ([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    switch ($Level.ToUpper()) {
        "INFO"  { Write-Host $logMessage -ForegroundColor Blue }
        "WARN"  { Write-Host $logMessage -ForegroundColor Yellow }
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
        default { Write-Host $logMessage }
    }
    [System.Threading.Monitor]::Enter($script:logBuffer)
    try {
        $script:logBuffer.Add($logMessage)
        if ($script:logBuffer.Count -ge 100) {
            Add-Content -Path $script:LogFilePath -Value $script:logBuffer -ErrorAction SilentlyContinue
            $script:logBuffer.Clear()
        }
    } finally {
        [System.Threading.Monitor]::Exit($script:logBuffer)
    }
}

function Sanitize-String {
    param([string]$InputString)
    try {
        $fileName = [System.IO.Path]::GetFileName($InputString)
        $directory = [System.IO.Path]::GetDirectoryName($InputString)
        $sanitizedFileName = $fileName -replace '[^a-zA-Z0-9.]', '_'
        $sanitized = if ($directory) { Join-Path $directory $sanitizedFileName } else { $sanitizedFileName }
        Write-Log -Message "Sanitized string '${InputString}' to '${sanitized}'" -Level "INFO"
        return $sanitized
    } catch {
        Write-Log -Message "Error sanitizing string '${InputString}': $($_.Exception.Message)" -Level "ERROR"
        return $InputString
    }
}

function Test-AwsProfileConnectivity {
    param([string]$ProfileName, [string]$Region)
    try {
        $identity = Get-STSCallerIdentity -ProfileName $ProfileName -Region $Region -ErrorAction Stop
        Write-Log -Message "Successfully validated connectivity for profile ${ProfileName}" -Level "INFO"
        return $true
    } catch {
        Write-Log -Message "Failed to validate connectivity for profile ${ProfileName}: $($_.Exception.Message)" -Level "WARN"
        return $false
    }
}

function Flush-LogBuffer {
    param([System.Collections.Concurrent.ConcurrentBag[string]]$LogBuffer, [string]$LogFilePath)
    [System.Threading.Monitor]::Enter($LogBuffer)
    try {
        if ($LogBuffer.Count -gt 0) {
            Add-Content -Path $LogFilePath -Value $LogBuffer -ErrorAction SilentlyContinue
            $LogBuffer.Clear()
        }
    } finally {
        [System.Threading.Monitor]::Exit($LogBuffer)
    }
}

# Initialize script variables
$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
$OutputDir = Join-Path $ScriptDir "output"
$LogFilePath = Join-Path $OutputDir "EC2_Instance_Analysis_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$logBuffer = [System.Collections.Concurrent.ConcurrentBag[string]]::new()
$ProblematicTags = @('ipf:sd:serviceowner', 'ipf:sd:businessowner', 'Owner')
$amiCache = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new()
$maxParallelJobs = 5  # Configurable throttle limit
$scriptVersion = "13.7 (Refactored for parallel function availability)"

# Create output directory if it doesn't exist
if (-not (Test-Path $OutputDir)) {
    try {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    } catch {
        Write-Error "Failed to create output directory ${OutputDir}: $($_.Exception.Message)"
        exit 1
    }
}

# Import AWS Tools modules with detailed error handling
try {
    $modulePaths = @(
        (Join-Path $PSModulesPath "AWS.Tools.Common"),
        (Join-Path $PSModulesPath "AWS.Tools.EC2"),
        (Join-Path $PSModulesPath "AWS.Tools.SecurityToken"),
        (Join-Path $PSModulesPath "AWS.Tools.IdentityManagement")
    )
    foreach ($path in $modulePaths) {
        if (-not (Test-Path $path)) {
            throw "Module path ${path} does not exist"
        }
        Import-Module -Name $path -ErrorAction Stop
    }
} catch {
    $errorMsg = "[$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))] [ERROR] Failed to import AWS Tools modules from ${PSModulesPath}: $($_.Exception.Message)"
    Add-Content -Path $LogFilePath -Value $errorMsg
    Write-Error $errorMsg
    exit 1
}

# Set output files with sanitization
if (-not $OutputFile) {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $regionSafe = if ($Region) { $Region -replace '[^a-zA-Z0-9]', '_' } else { "multiregion" }
    $filterSuffix = if ($FilterProblematicTags) { "_filtered" } else { "_unfiltered" }
    $baseName = "ec2_instances_$($AwsProfiles.Count)accounts_${regionSafe}${filterSuffix}_${timestamp}.csv"
    $OutputFile = Join-Path $OutputDir $baseName
    $OutputFile = Sanitize-String -InputString $OutputFile
}
$AmiOutputFile = $OutputFile -replace "\.csv$", "_ami_usage_report.csv"
$AmiOutputFile = Sanitize-String -InputString $AmiOutputFile

# Get AWS profiles with interactive or manual selection
if (-not $AwsProfiles) {
    $profileList = Get-AWSCredential -ListProfile | Select-Object -ExpandProperty ProfileName
    if ($profileList.Count -eq 0) {
        $AwsProfiles = @("")
    } elseif ($InteractiveSelection) {
        $selected = $profileList | Out-GridView -Title "Select AWS Profiles" -OutputMode Multiple
        $AwsProfiles = if ($selected) { $selected } else { @() }
        if ($AwsProfiles.Count -eq 0) { exit 0 }
    } else {
        Write-Host "`nAvailable AWS Profiles:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $profileList.Count; $i++) {
            Write-Host "  $($i + 1). $($profileList[$i])$(if ($env:AWS_PROFILE -eq $profileList[$i]) { ' (current)' })" -ForegroundColor Gray
        }
        Write-Host "  0. Use default profile" -ForegroundColor Gray
        do {
            $Selection = Read-Host "`nSelect AWS profile (0-$($profileList.Count))"
            if ($Selection -eq "0") { $AwsProfiles = @(""); break }
            elseif ($Selection -match '^\d+$' -and [int]$Selection -ge 1 -and [int]$Selection -le $profileList.Count) {
                $AwsProfiles = @($profileList[[int]$Selection - 1]); break
            } else {
                Write-Host "Invalid selection. Please enter a number between 0 and $($profileList.Count)." -ForegroundColor Yellow
            }
        } while ($true)
    }
}

# Test profile connectivity and build account-to-profile mapping
$accountProfileCache = [System.Collections.Concurrent.ConcurrentDictionary[string, string]]::new()
$subnetCache = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new()
$vpcCache = [System.Collections.Concurrent.ConcurrentDictionary[string, string]]::new()
$attributeCache = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new()
$instanceIdsProcessed = [System.Collections.Concurrent.ConcurrentDictionary[string, bool]]::new()
$regionsUsed = [System.Collections.Concurrent.ConcurrentBag[string]]::new()
$allAmiReports = [System.Collections.Concurrent.ConcurrentBag[PSObject]]::new()
$processedAccounts = [System.Collections.Concurrent.ConcurrentBag[PSObject]]::new()
$outputBag = [System.Collections.Concurrent.ConcurrentBag[PSObject]]::new()
if ($TestProfilesFirst -and $AwsProfiles) {
    $validProfiles = @()
    foreach ($profile in $AwsProfiles) {
        $currentRegion = $Region ? $Region : "eu-west-1"
        if (Test-AwsProfileConnectivity -ProfileName $profile -Region $currentRegion) {
            $validProfiles += $profile
            try {
                $identity = Get-STSCallerIdentity -ProfileName $profile -Region $currentRegion -ErrorAction Stop
                if ($identity) { $accountProfileCache.TryAdd("$($identity.Account):$currentRegion", $profile) }
            } catch {
                Add-Content -Path $LogFilePath -Value "[$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))] [WARN] Failed to get identity for profile ${profile}: $($_.Exception.Message)"
            }
        }
    }
    if ($validProfiles.Count -eq 0) { exit 1 }
    $AwsProfiles = $validProfiles
}

# Process profiles in parallel
$results = $AwsProfiles | ForEach-Object -Parallel {
    # Define local variables from the calling scope
    $local_PSModulesPath = $using:PSModulesPath
    $local_logBuffer = $using:logBuffer
    $local_Region = $using:Region
    $local_FilterProblematicTags = $using:FilterProblematicTags
    $local_subnetCache = $using:subnetCache
    $local_vpcCache = $using:vpcCache
    $local_accountProfileCache = $using:accountProfileCache
    $local_AwsProfiles = $using:AwsProfiles
    $local_instanceIdsProcessed = $using:instanceIdsProcessed
    $local_attributeCache = $using:attributeCache
    $local_OutputFile = $using:OutputFile
    $local_outputBag = $using:outputBag
    $local_amiCache = $using:amiCache
    $local_LogFilePath = $using:LogFilePath
    $local_ProblematicTags = $using:ProblematicTags
    $local_DebugPlatform = $using:DebugPlatform
    $local_maxParallelJobs = $using:maxParallelJobs

    # Define Write-Log function (local for parallel scope)
    function Write-Log {
        param ([string]$Message, [string]$Level = "INFO")
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logMessage = "[$timestamp] [$Level] $Message"
        switch ($Level.ToUpper()) {
            "INFO"  { Write-Host $logMessage -ForegroundColor Blue }
            "WARN"  { Write-Host $logMessage -ForegroundColor Yellow }
            "ERROR" { Write-Host $logMessage -ForegroundColor Red }
            default { Write-Host $logMessage }
        }
        [System.Threading.Monitor]::Enter($local_logBuffer)
        try {
            $local_logBuffer.Add($logMessage)
            if ($local_logBuffer.Count -ge 100) {
                Add-Content -Path $local_LogFilePath -Value $local_logBuffer -ErrorAction SilentlyContinue
                $local_logBuffer.Clear()
            }
        } finally {
            [System.Threading.Monitor]::Exit($local_logBuffer)
        }
    }

    # Define Flush-LogBuffer function (local for parallel scope)
    function Flush-LogBuffer {
        param([System.Collections.Concurrent.ConcurrentBag[string]]$LogBuffer, [string]$LogFilePath)
        [System.Threading.Monitor]::Enter($LogBuffer)
        try {
            if ($LogBuffer.Count -gt 0) {
                Add-Content -Path $LogFilePath -Value $LogBuffer -ErrorAction SilentlyContinue
                $LogBuffer.Clear()
            }
        } finally {
            [System.Threading.Monitor]::Exit($LogBuffer)
        }
    }

    # Define Get-ValidAWSRegion function
    function Get-ValidAWSRegion {
        param([string]$Region, [string]$ProfileName)
        $validRegions = @("us-east-1", "us-east-2", "us-west-1", "us-west-2", "ap-south-1", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3", "ap-southeast-1", "ap-southeast-2", "ca-central-1", "eu-central-1", "eu-west-1", "eu-west-2", "eu-west-3", "eu-north-1", "sa-east-1")
        if ($Region -and $validRegions -contains $Region) { Write-Log "Using provided region: ${Region}"; return $Region }
        try {
            $configPath = Join-Path $env:USERPROFILE ".aws\config"
            if (Test-Path $configPath) {
                $configContent = Get-Content -Path $configPath -Raw
                $profileSection = if ($ProfileName) { "\[(profile\s+)?${ProfileName}\]" } else { "\[default\]" }
                if ($configContent -match "(?s)$profileSection.*?\nregion\s*=\s*([^\s#]+)") {
                    $configRegion = $matches[1]
                    if ($validRegions -contains $configRegion) { Write-Log "Using region from profile ${ProfileName} in config: ${configRegion}"; return $configRegion }
                }
            }
        } catch { Write-Log "Failed to parse region from config for profile ${ProfileName}: $($_.Exception.Message)" "WARN" }
        if ($env:AWS_DEFAULT_REGION -and $validRegions -contains $env:AWS_DEFAULT_REGION) { Write-Log "Using region from AWS_DEFAULT_REGION: $env:AWS_DEFAULT_REGION"; return $env:AWS_DEFAULT_REGION }
        $defaultRegion = "eu-west-1"
        Write-Log "No valid region found for profile ${ProfileName}. Using default region: ${defaultRegion}" "WARN"
        return $defaultRegion
    }

    # Define Invoke-AwsApiCall function
    function Invoke-AwsApiCall {
        param([scriptblock]$ApiCall, [string]$ProfileName, [string]$Region, [string]$OperationDescription, [int]$MaxRetries = 3)
        $retryCount = 0
        while ($retryCount -lt $MaxRetries) {
            try {
                $result = & $ApiCall
                Write-Log "Successfully executed ${OperationDescription}"
                return $result
            } catch {
                $retryCount++
                Write-Log "Retry $retryCount/$MaxRetries for ${OperationDescription}: $($_.Exception.Message)" "WARN"
                if ($retryCount -eq $MaxRetries) { Write-Log "Failed ${OperationDescription} after $MaxRetries retries: $($_.Exception.Message)" "ERROR"; return $null }
                Start-Sleep -Seconds (2 * $retryCount)
            }
        }
    }

    # Define Get-EC2InstancesForProfile function
    function Get-EC2InstancesForProfile {
        param([string]$ProfileName, [string]$Region, [bool]$FilterTags, [hashtable]$SubnetCache, [hashtable]$VpcCache, [hashtable]$AccountProfileCache, [string[]]$AvailableProfiles, [hashtable]$InstanceIdsProcessed, [hashtable]$AttributeCache, [System.Collections.Concurrent.ConcurrentBag[PSObject]]$OutputBag)
        $DisplayProfileName = if ($ProfileName) { $ProfileName } else { 'Default' }
        Write-Log "Processing profile: ${DisplayProfileName}"
        try {
            $identity = Invoke-AwsApiCall -ApiCall { Get-STSCallerIdentity -ProfileName $ProfileName -Region $Region -ErrorAction Stop } -ProfileName $ProfileName -Region $Region -OperationDescription "Get caller identity for $ProfileName"
            $accountId = $identity.Account
            $accountName = (Invoke-AwsApiCall -ApiCall { Get-IAMAccountAlias -ProfileName $ProfileName -Region $Region -ErrorAction Stop } -ProfileName $ProfileName -Region $Region -OperationDescription "Get account alias for $ProfileName") | Select-Object -First 1
            if (-not $accountName) { $accountName = if ($ProfileName) { $ProfileName -replace '^sso-' -replace '-nonprivFujitsuCSA$', '' } else { 'Default' }; Write-Log "No account alias found. Using '${accountName}' as AccountName." }
            Write-Log "Account: ${accountName} (${accountId})"
        } catch { Write-Log "Failed to configure credentials for profile ${DisplayProfileName}: $($_.Exception.Message)" "ERROR"; return @(), $accountName, $accountId, @(), @(), @() }
        Initialize-AwsResourceCache -ProfileName $ProfileName -Region $Region -SubnetCache $SubnetCache -VpcCache $VpcCache
        $instances = @()
        $nextToken = $null
        do {
            $result = Invoke-AwsApiCall -ApiCall { Get-EC2Instance -ProfileName $ProfileName -Region $Region -NextToken $nextToken -ErrorAction Stop } -ProfileName $ProfileName -Region $Region -OperationDescription "Get instances for $ProfileName"
            if ($result) { $instances += $result.Instances }
            $nextToken = $result.NextToken
        } while ($nextToken)
        if (-not $instances) { Write-Log "No instances found for profile ${DisplayProfileName} in region ${Region}" "WARN"; return @(), $accountName, $accountId, @(), @(), @() }
        Write-Log "Retrieved $($instances.Count) instances for profile ${DisplayProfileName}"
        $profileInstances = @()
        $progress = 0
        foreach ($instance in $instances) {
            $progress++
            Write-Progress -Activity "Processing instances for profile $DisplayProfileName" -Status "Instance $progress of $($instances.Count)" -PercentComplete (($progress / $instances.Count) * 100)
            [System.Threading.Monitor]::Enter($InstanceIdsProcessed)
            try {
                if ($InstanceIdsProcessed.ContainsKey($instance.InstanceId)) { Write-Log "Instance $($instance.InstanceId) already processed. Skipping." "DEBUG"; continue }
                $InstanceIdsProcessed[$instance.InstanceId] = $true
            } finally { [System.Threading.Monitor]::Exit($InstanceIdsProcessed) }
            $tags = if ($FilterTags) { $instance.Tags | Where-Object { $_.Key -notin $local_ProblematicTags } } else { $instance.Tags }
            $problematicTagList = $instance.Tags | ForEach-Object { $key = $_.Key; $res = Test-EC2TagKey -TagKey $key; if ($res) { "${key}: $res" } } | Where-Object { $_ }
            $VpcOwnerId = Get-VpcOwnerId -VpcId $instance.VpcId -Region $Region -ProfileName $ProfileName -AvailableProfiles $AvailableProfiles -VpcCache $VpcCache -AccountProfileCache $AccountProfileCache
            $VpcIsShared = $instance.VpcId -and $VpcOwnerId -ne 'N/A' -and $VpcOwnerId -ne "VPC Query Error ($($instance.VpcId))" -and $VpcOwnerId -ne $accountId
            $tempProps = [ordered]@{
                AccountName = $accountName
                AccountId = $accountId
                SSORole = Get-SSORoleName -ProfileName $ProfileName -Region $Region
                InstanceId = $instance.InstanceId
                InstanceName = Get-ResourceName -Resource $instance
                Tenancy = $instance.Placement.Tenancy ?? "N/A"
                Monitored = Get-ResourceTagValue -Resource $instance -TagName "Monitored"
                IpfEnvironment = Get-ResourceTagValue -Resource $instance -TagName "ipf:environment"
                SqlServerMonitored = Get-ResourceTagValue -Resource $instance -TagName "SqlServerMonitored"
                IpfServiceName = Get-ResourceTagValue -Resource $instance -TagName "ipf:sd:servicename"
                FcmsCustomMonitoring = Get-ResourceTagValue -Resource $instance -TagName "fcms:CustomMonitoring"
                Role = Get-ResourceTagValue -Resource $instance -TagName "role"
                Application = Get-ResourceTagValue -Resource $instance -TagName "application"
                PatchGroup = Get-ResourceTagValue -Resource $instance -TagName "PatchGroup"
                AutoPatch = Get-ResourceTagValue -Resource $instance -TagName "AutoPatch"
                InstanceState = $instance.State.Name
                AvailabilityZone = $instance.Placement.AvailabilityZone
                VpcId = $instance.VpcId
                VpcOwnerId = $VpcOwnerId
                VpcIsShared = $VpcIsShared
                SubnetId = $instance.SubnetId
                SubnetName = (Get-SubnetCidrBlock -SubnetId $instance.SubnetId -Region $Region -ProfileName $ProfileName -VpcOwnerId $VpcOwnerId -AvailableProfiles $AvailableProfiles -SubnetCache $SubnetCache -AccountProfileCache $AccountProfileCache -IsSharedVPC $VpcIsShared).SubnetName
                CidrBlock = (Get-SubnetCidrBlock -SubnetId $instance.SubnetId -Region $Region -ProfileName $ProfileName -VpcOwnerId $VpcOwnerId -AvailableProfiles $AvailableProfiles -SubnetCache $SubnetCache -AccountProfileCache $AccountProfileCache -IsSharedVPC $VpcIsShared).CidrBlock
                PrivateIpAddress = $instance.PrivateIpAddress
                SecondaryPrivateIPs = if ($instance.NetworkInterfaces) { ($instance.NetworkInterfaces | ForEach-Object { $_.PrivateIpAddresses | Where-Object { $_.Primary -eq $false } | ForEach-Object { $_.PrivateIpAddress } } | Join-String -Separator ';') ?? "N/A" } else { "N/A" }
                Platform = Get-InstancePlatform -Instance $instance
                InstanceType = $instance.InstanceType
                CWMonitoring = switch ($instance.Monitoring.State) { "enabled" { "Detailed" } "disabled" { "Basic" } "pending" { "Pending" } default { $instance.Monitoring.State ?? "N/A" } }
                vCPU = if ($instance.CpuOptions.CoreCount -and $instance.CpuOptions.ThreadsPerCore) { $instance.CpuOptions.CoreCount * $instance.CpuOptions.ThreadsPerCore } else { "N/A" }
                AMIId = $instance.ImageId
                AMIName = Get-AMIName -AmiId $instance.ImageId -Region $Region -ProfileName $ProfileName
                IamInstanceProfile = if ($instance.IamInstanceProfile -and $instance.IamInstanceProfile.Arn) { $instance.IamInstanceProfile.Arn } else { "N/A" }
                EbsOptimized = $instance.EbsOptimized
                MetadataOptionsHttpTokens = $instance.MetadataOptions.HttpTokens ?? "N/A"
                MetadataOptionsHttpEndpoint = $instance.MetadataOptions.HttpEndpoint ?? "N/A"
                MetadataOptionsHttpPutResponseHopLimit = $instance.MetadataOptions.HttpPutResponseHopLimit ?? "N/A"
                InstanceMetadataTags = $instance.MetadataOptions.InstanceMetadataTags ?? "N/A"
                DisableApiTermination = (Get-InstanceAttributes -InstanceId $instance.InstanceId -Region $Region -ProfileName $ProfileName -AttributeCache $AttributeCache).DisableApiTermination
                InstanceInitiatedShutdownBehavior = (Get-InstanceAttributes -InstanceId $instance.InstanceId -Region $Region -ProfileName $ProfileName -AttributeCache $AttributeCache).InstanceInitiatedShutdownBehavior
                KeyPair = $instance.KeyName
                SecurityGroupIds = if ($instance.SecurityGroups) { ($instance.SecurityGroups | ForEach-Object { $_.GroupId } | Join-String -Separator ';') } else { "N/A" }
                Tags = if ($tags) { ($tags | ForEach-Object { "$($_.Key)=$($_.Value)" } | Join-String -Separator ';') } else { "N/A" }
                TagsFiltered = $FilterTags
                ProblematicTags = if ($problematicTagList) { $problematicTagList -join '; ' } else { "None" }
            }
            if ($local_DebugPlatform) {
                $tempProps.Add("RawPlatform", $instance.Platform)
                $tempProps.Add("RawPlatformDetails", $instance.PlatformDetails)
            }
            $instanceObj = [PSCustomObject]$tempProps
            Write-Log "Created instance object for InstanceId $($instance.InstanceId) with properties: $($tempProps.Keys -join ', ')" -Level "DEBUG"
            $profileInstances += $instanceObj
            $OutputBag.Add($instanceObj)
        }
        Write-Progress -Activity "Processing instances for profile $DisplayProfileName" -Completed
        $amiReport = if ($profileInstances) { Get-AmiUsageReport -InstanceData $profileInstances -Region $Region -ProfileName $ProfileName } else { @() }
        $accountInfo = if ($accountName -and $accountId) { [PSCustomObject]@{ SSORole = Get-SSORoleName -ProfileName $ProfileName -Region $Region; AccountName = $accountName; AccountId = $accountId } } else { $null }
        return $profileInstances, $accountName, $accountId, $amiReport, $accountInfo, @($Region)
    }

    # Define Get-SSORoleName function
    function Get-SSORoleName {
        param([string]$ProfileName, [string]$Region)
        try {
            $configPath = Join-Path $env:USERPROFILE ".aws\config"
            if (Test-Path $configPath) {
                $configContent = Get-Content -Path $configPath -Raw
                $profileSection = if ($ProfileName) { "\[(profile\s+)?${ProfileName}\]" } else { "\[default\]" }
                if ($configContent -match "(?s)$profileSection.*?\nsso_role_name\s*=\s*([^\s#]+)") { return $matches[1] }
            }
            $identity = Invoke-AwsApiCall -ApiCall { Get-STSCallerIdentity -ProfileName $ProfileName -Region $Region -ErrorAction Stop } -ProfileName $ProfileName -Region $Region -OperationDescription "Get caller identity for $ProfileName"
            if ($identity.Arn -match 'assumed-role/([^/]+)/') { return $matches[1] }
            Write-Log "Could not determine SSO role for profile ${ProfileName}. Using 'Unknown'." "WARN"
            return "Unknown"
        } catch { Write-Log "Error retrieving SSO role for profile ${ProfileName}: $($_.Exception.Message)" "WARN"; return "Unknown" }
    }

    # Define Get-AMIName function
    function Get-AMIName {
        param([string]$AmiId, [string]$Region, [string]$ProfileName)
        if (-not $AmiId) { return 'N/A' }
        $cacheKey = "${ProfileName}:${Region}:${AmiId}"
        if ($local_amiCache.ContainsKey($cacheKey)) { return $local_amiCache[$cacheKey].Name }
        try {
            $ami = Invoke-AwsApiCall -ApiCall { Get-EC2Image -ImageId $AmiId -ProfileName $ProfileName -Region $Region -ErrorAction Stop } -ProfileName $ProfileName -Region $Region -OperationDescription "Get AMI $AmiId"
            $amiInfo = @{ Name = $ami[0].Name ?? "AMI No Name (${AmiId})"; Description = $ami[0].Description ?? 'N/A'; Architecture = $ami[0].Architecture ?? 'N/A'; Platform = $ami[0].PlatformDetails ?? 'N/A'; CreationDate = $ami[0].CreationDate ?? 'N/A'; OwnerId = $ami[0].OwnerId ?? 'N/A'; State = $ami[0].State ?? 'N/A'; Public = $ami[0].Public ?? $false }
            $local_amiCache.TryAdd($cacheKey, $amiInfo)
            return $amiInfo.Name
        } catch {
            $amiInfo = @{ Name = "AMI Query Error (${AmiId})"; Description = 'Error'; Architecture = 'N/A'; Platform = 'N/A'; CreationDate = 'N/A'; OwnerId = 'N/A'; State = 'N/A'; Public = $false }
            $local_amiCache.TryAdd($cacheKey, $amiInfo)
            return $amiInfo.Name
        }
    }

    # Define Get-SubnetCidrBlock function
    function Get-SubnetCidrBlock {
        param([string]$SubnetId, [string]$Region, [string]$ProfileName, [string]$VpcOwnerId, [string[]]$AvailableProfiles, [hashtable]$SubnetCache, [hashtable]$AccountProfileCache, [bool]$IsSharedVPC = $false)
        if (-not $SubnetId) { return @{ CidrBlock = 'N/A'; SubnetName = 'N/A' } }
        $cacheKey = "${ProfileName}:${Region}:${SubnetId}"
        [System.Threading.Monitor]::Enter($SubnetCache)
        try { if (-not $IsSharedVPC -and $SubnetCache.ContainsKey($cacheKey)) { return $SubnetCache[$cacheKey] } } finally { [System.Threading.Monitor]::Exit($SubnetCache) }
        $profilesToTry = @($ProfileName) + ($AvailableProfiles | Where-Object { $_ -ne $ProfileName })
        if ($IsSharedVPC -and $VpcOwnerId -and $VpcOwnerId -ne 'N/A') {
            $ownerProfile = $AccountProfileCache["${VpcOwnerId}:${Region}"]
            if ($ownerProfile) { $profilesToTry = @($ownerProfile) + $profilesToTry }
        }
        foreach ($profile in $profilesToTry) {
            $subnet = Invoke-AwsApiCall -ApiCall { Get-EC2Subnet -SubnetId $SubnetId -ProfileName $profile -Region $Region -ErrorAction Stop } -ProfileName $profile -Region $Region -OperationDescription "Get subnet $SubnetId"
            if ($subnet) {
                $subnetInfo = @{ CidrBlock = $subnet.CidrBlock ?? 'N/A'; SubnetName = ($subnet.Tags | Where-Object { $_.Key -eq 'Name' } | Select-Object -ExpandProperty Value) ?? 'N/A' }
                [System.Threading.Monitor]::Enter($SubnetCache)
                try { $SubnetCache[$cacheKey] = $subnetInfo } finally { [System.Threading.Monitor]::Exit($SubnetCache) }
                return $subnetInfo
            }
        }
        $subnetInfo = @{ CidrBlock = "Subnet Query Error (${SubnetId})"; SubnetName = "Subnet Query Error (${SubnetId})" }
        [System.Threading.Monitor]::Enter($SubnetCache)
        try { $SubnetCache[$cacheKey] = $subnetInfo } finally { [System.Threading.Monitor]::Exit($SubnetCache) }
        return $subnetInfo
    }

    # Define Get-VpcOwnerId function
    function Get-VpcOwnerId {
        param([string]$VpcId, [string]$Region, [string]$ProfileName, [string[]]$AvailableProfiles, [hashtable]$VpcCache, [hashtable]$AccountProfileCache)
        if (-not $VpcId) { return 'N/A' }
        $cacheKey = "${ProfileName}:${Region}:${VpcId}"
        [System.Threading.Monitor]::Enter($VpcCache)
        try { if ($VpcCache.ContainsKey($cacheKey)) { return $VpcCache[$cacheKey] } } finally { [System.Threading.Monitor]::Exit($VpcCache) }
        $profilesToTry = @($ProfileName) + ($AvailableProfiles | Where-Object { $_ -ne $ProfileName })
        foreach ($profile in $profilesToTry) {
            $vpc = Invoke-AwsApiCall -ApiCall { Get-EC2VPC -VpcId $VpcId -ProfileName $profile -Region $Region -ErrorAction Stop } -ProfileName $profile -Region $Region -OperationDescription "Get VPC $VpcId"
            if ($vpc -and $vpc.OwnerId) {
                [System.Threading.Monitor]::Enter($VpcCache)
                try { $VpcCache[$cacheKey] = $vpc.OwnerId } finally { [System.Threading.Monitor]::Exit($VpcCache) }
                return $vpc.OwnerId
            }
        }
        [System.Threading.Monitor]::Enter($VpcCache)
        try { $VpcCache[$cacheKey] = "VPC Query Error (${VpcId})" } finally { [System.Threading.Monitor]::Exit($VpcCache) }
        return $VpcCache[$cacheKey]
    }

    # Define Get-InstanceAttributes function
    function Get-InstanceAttributes {
        param([string]$InstanceId, [string]$Region, [string]$ProfileName, [hashtable]$AttributeCache)
        $cacheKey = "${ProfileName}:${Region}:${InstanceId}"
        [System.Threading.Monitor]::Enter($AttributeCache)
        try { if ($AttributeCache.ContainsKey($cacheKey)) { return $AttributeCache[$cacheKey] } } finally { [System.Threading.Monitor]::Exit($AttributeCache) }
        try {
            $disableApiTermination = Invoke-AwsApiCall -ApiCall { (Get-EC2InstanceAttribute -InstanceId $InstanceId -Attribute disableApiTermination -ProfileName $ProfileName -Region $Region -ErrorAction Stop).DisableApiTermination } -ProfileName $ProfileName -Region $Region -OperationDescription "Get disableApiTermination for $InstanceId"
            $shutdownBehavior = Invoke-AwsApiCall -ApiCall { (Get-EC2InstanceAttribute -InstanceId $InstanceId -Attribute instanceInitiatedShutdownBehavior -ProfileName $ProfileName -Region $Region -ErrorAction Stop).InstanceInitiatedShutdownBehavior } -ProfileName $ProfileName -Region $Region -OperationDescription "Get shutdownBehavior for $InstanceId"
            $attributes = @{ DisableApiTermination = $disableApiTermination ?? "N/A"; InstanceInitiatedShutdownBehavior = $shutdownBehavior ?? "N/A" }
            [System.Threading.Monitor]::Enter($AttributeCache)
            try { $AttributeCache[$cacheKey] = $attributes } finally { [System.Threading.Monitor]::Exit($AttributeCache) }
            return $attributes
        } catch { return @{ DisableApiTermination = "N/A"; InstanceInitiatedShutdownBehavior = "N/A" } }
    }

    # Define Get-InstancePlatform function
    function Get-InstancePlatform {
        param([object]$Instance)
        if ($Instance.Platform -and $Instance.Platform -ne "") { return $Instance.Platform.ToString().ToLower() }
        if ($Instance.PlatformDetails -like "*Windows*") { return "Windows" }
        if ($Instance.PlatformDetails -match "Linux|Ubuntu|Red Hat|SUSE|Amazon Linux") { return "Linux/UNIX" }
        if ($Instance.ImageId -match "windows|win") { return "Windows" }
        if ($Instance.ImageId -match "amzn|ubuntu|rhel|suse") { return "Linux/UNIX" }
        Write-Log "No platform identified for instance $($Instance.InstanceId). Defaulting to 'Linux/UNIX'."
        return "Linux/UNIX (Inferred)"
    }

    # Define Get-ResourceName function
    function Get-ResourceName {
        param([object]$Resource)
        $nameTag = $Resource.Tags | Where-Object { $_.Key -eq "Name" }
        return $nameTag ? $nameTag.Value : "(No Name Tag)"
    }

    # Define Get-ResourceTagValue function
    function Get-ResourceTagValue {
        param([object]$Resource, [string]$TagName)
        $tag = $Resource.Tags | Where-Object { $_.Key -eq $TagName }
        return $tag ? $tag.Value : "N/A"
    }

    # Define Test-EC2TagKey function
    function Test-EC2TagKey {
        param([string]$TagKey)
        if ([string]::IsNullOrEmpty($TagKey)) { return "Empty or null tag key" }
        if ($TagKey.Length -gt 128) { return "Tag key length exceeds 128 characters" }
        if ($TagKey -match '^aws:') { return "Tag key starts with reserved prefix 'aws:'" }
        if ($TagKey -notmatch '^[a-zA-Z0-9_\.:/=+@-]+$') { return "Tag key contains invalid characters" }
        return $null
    }

    # Define Initialize-AwsResourceCache function
    function Initialize-AwsResourceCache {
        param([string]$ProfileName, [string]$Region, [hashtable]$SubnetCache, [hashtable]$VpcCache)
        Write-Log "Preloading subnet and VPC data for profile ${ProfileName} in region ${Region}"
        try {
            $subnets = Invoke-AwsApiCall -ApiCall { Get-EC2Subnet -ProfileName $ProfileName -Region $Region -ErrorAction Stop } -ProfileName $ProfileName -Region $Region -OperationDescription "Get all subnets"
            foreach ($subnet in $subnets) {
                $cacheKey = "${ProfileName}:${Region}:$($subnet.SubnetId)"
                [System.Threading.Monitor]::Enter($SubnetCache)
                try { $SubnetCache[$cacheKey] = @{ CidrBlock = $subnet.CidrBlock ?? 'N/A'; SubnetName = ($subnet.Tags | Where-Object { $_.Key -eq 'Name' } | Select-Object -ExpandProperty Value) ?? 'N/A' } } finally { [System.Threading.Monitor]::Exit($SubnetCache) }
            }
            $vpcs = Invoke-AwsApiCall -ApiCall { Get-EC2VPC -ProfileName $ProfileName -Region $Region -ErrorAction Stop } -ProfileName $ProfileName -Region $Region -OperationDescription "Get all VPCs"
            foreach ($vpc in $vpcs) {
                $cacheKey = "${ProfileName}:${Region}:$($vpc.VpcId)"
                [System.Threading.Monitor]::Enter($VpcCache)
                try { $VpcCache[$cacheKey] = $vpc.OwnerId ?? 'N/A' } finally { [System.Threading.Monitor]::Exit($VpcCache) }
            }
            Write-Log "Cached $($subnets.Count) subnets and $($vpcs.Count) VPCs for profile ${ProfileName}"
        } catch { Write-Log "Failed to preload resources for profile ${ProfileName}: $($_.Exception.Message)" "ERROR" }
    }

    # Define Get-AmiUsageReport function
    function Get-AmiUsageReport {
        param([array]$InstanceData, [string]$Region, [string]$ProfileName)
        $uniqueAmis = $InstanceData | ForEach-Object { $_.AMIId } | Sort-Object -Unique | Where-Object { $_ -and $_ -ne 'N/A' }
        $amiReport = @()
        foreach ($amiId in $uniqueAmis) {
            $instancesUsingAmi = $InstanceData | Where-Object { $_.AMIId -eq $amiId }
            $instanceCount = $instancesUsingAmi.Count
            $cacheKey = "${ProfileName}:${Region}:${amiId}"
            $amiInfo = $local_amiCache[$cacheKey] ?? @{ Name = "AMI Query Error (${amiId})"; Description = 'Error'; Architecture = 'N/A'; Platform = 'N/A'; CreationDate = 'N/A'; OwnerId = 'N/A'; State = 'N/A'; Public = $false }
            $accountBreakdown = $instancesUsingAmi | Group-Object AccountName | ForEach-Object { "$($_.Name):$($_.Count)" } | Join-String -Separator '; '
            $instanceTypeBreakdown = $instancesUsingAmi | Group-Object InstanceType | ForEach-Object { "$($_.Name):$($_.Count)" } | Join-String -Separator '; '
            $stateBreakdown = $instancesUsingAmi | Group-Object InstanceState | ForEach-Object { "$($_.Name):$($_.Count)" } | Join-String -Separator '; '
            $amiReport += [PSCustomObject]@{ AMIId = $amiId; AMIName = $amiInfo.Name; Description = $amiInfo.Description; Architecture = $amiInfo.Architecture; Platform = $amiInfo.Platform; CreationDate = $amiInfo.CreationDate; OwnerId = $amiInfo.OwnerId; State = $amiInfo.State; Public = $amiInfo.Public; InstanceCount = $instanceCount; Region = $Region; SSORole = Get-SSORoleName -ProfileName $ProfileName -Region $Region; AccountBreakdown = $accountBreakdown; InstanceTypeBreakdown = $instanceTypeBreakdown; StateBreakdown = $stateBreakdown }
        }
        Write-Log "Generated AMI report with $($amiReport.Count) unique AMIs for profile ${ProfileName}"
        return $amiReport
    }

    # Import modules and execute
    $moduleImportSuccess = $true
    try {
        Import-Module -Name (Join-Path $local_PSModulesPath "AWS.Tools.Common") -ErrorAction Stop
        Import-Module -Name (Join-Path $local_PSModulesPath "AWS.Tools.EC2") -ErrorAction Stop
        Import-Module -Name (Join-Path $local_PSModulesPath "AWS.Tools.SecurityToken") -ErrorAction Stop
        Import-Module -Name (Join-Path $local_PSModulesPath "AWS.Tools.IdentityManagement") -ErrorAction Stop
    } catch {
        Write-Log "Failed to import AWS Tools modules in parallel runspace for profile ${profileName}: $($_.Exception.Message)" "ERROR"
        $moduleImportSuccess = $false
    }

    if (-not $moduleImportSuccess) { return $null }

    $profileName = $_
    $localRegions = @()
    $currentRegion = Get-ValidAWSRegion -Region $local_Region -ProfileName $profileName
    if (-not $currentRegion) {
        Write-Log "No valid region for profile $profileName. Skipping." "ERROR"
        return $null
    }
    $localRegions += $currentRegion
    Write-Log "Processing region $currentRegion for profile $profileName"

    try {
        $profileInstances, $accountName, $accountId, $amiReport, $accountInfo, $regions = Get-EC2InstancesForProfile -ProfileName $profileName -Region $currentRegion -FilterTags $local_FilterProblematicTags -SubnetCache $local_subnetCache -VpcCache $local_vpcCache -AccountProfileCache $local_accountProfileCache -AvailableProfiles $local_AwsProfiles -InstanceIdsProcessed $local_instanceIdsProcessed -AttributeCache $local_attributeCache -OutputBag $local_outputBag
        return [PSCustomObject]@{ ProfileInstances = $profileInstances; AccountName = $accountName; AccountId = $accountId; AmiReport = $amiReport; AccountInfo = $accountInfo; Regions = $regions }
    } catch {
        Write-Log "Unexpected error processing profile ${profileName}: $($_.Exception.Message)" "ERROR"
        return $null
    } finally {
        Flush-LogBuffer -LogBuffer $local_logBuffer -LogFilePath $local_LogFilePath
    }
} -ThrottleLimit $maxParallelJobs

# Process results in the main thread
$failedProfiles = 0
foreach ($result in $results) {
    if ($null -eq $result) { $failedProfiles++; continue }
    $profileInstances = $result.ProfileInstances
    $amiReport = $result.AmiReport
    $accountInfo = $result.AccountInfo
    $regions = $result.Regions
    if ($profileInstances) { foreach ($instance in $profileInstances) { $outputBag.Add($instance) } }
    if ($amiReport) { foreach ($report in $amiReport) { $allAmiReports.Add($report) } }
    if ($accountInfo) { $processedAccounts.Add($accountInfo) }
    foreach ($region in $regions) { if (-not ($regionsUsed | Where-Object { $_ -eq $region })) { $regionsUsed.Add($region) } }
}
if ($failedProfiles -gt 0) {
    Add-Content -Path $LogFilePath -Value "[$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))] [WARN] $failedProfiles profile(s) failed to process in parallel block"
}

# Export instance data to CSV in the main thread
if ($outputBag.Count -gt 0) {
    $props = [ordered]@{ AccountName = $null; AccountId = $null; SSORole = $null; InstanceId = $null; InstanceName = $null; Tenancy = $null; Monitored = $null; IpfEnvironment = $null; SqlServerMonitored = $null; IpfServiceName = $null; FcmsCustomMonitoring = $null; Role = $null; Application = $null; PatchGroup = $null; AutoPatch = $null; InstanceState = $null; AvailabilityZone = $null; VpcId = $null; VpcOwnerId = $null; VpcIsShared = $null; SubnetId = $null; SubnetName = $null; CidrBlock = $null; PrivateIpAddress = $null; SecondaryPrivateIPs = $null; Platform = $null; InstanceType = $null; CWMonitoring = $null; vCPU = $null; AMIId = $null; AMIName = $null; IamInstanceProfile = $null; EbsOptimized = $null; MetadataOptionsHttpTokens = $null; MetadataOptionsHttpEndpoint = $null; MetadataOptionsHttpPutResponseHopLimit = $null; InstanceMetadataTags = $null; DisableApiTermination = $null; InstanceInitiatedShutdownBehavior = $null; KeyPair = $null; SecurityGroupIds = $null; Tags = $null; TagsFiltered = $null; ProblematicTags = $null }
    if ($DebugPlatform) { $props.Add("RawPlatform", $null); $props.Add("RawPlatformDetails", $null) }
    [System.Threading.Monitor]::Enter($OutputFile)
    try {
        $outputBag | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8 -Force
        Write-Log "Exported $($outputBag.Count) instances to ${OutputFile}" -Level "INFO"
    } catch {
        Write-Log "Failed to export instances to ${OutputFile}: $($_.Exception.Message)" -Level "ERROR"
    } finally {
        [System.Threading.Monitor]::Exit($OutputFile)
    }
}

# Export AMI usage report
if ($allAmiReports.Count -gt 0) {
    $consolidatedAmiReport = $allAmiReports | Group-Object AMIId | ForEach-Object {
        $amiGroup = $_.Group
        $firstAmi = $amiGroup[0]
        $totalInstances = ($amiGroup | Measure-Object InstanceCount -Sum).Sum
        $rolesUsing = ($amiGroup | Select-Object -ExpandProperty SSORole -Unique) -join '; '
        $accountsUsing = ($amiGroup | ForEach-Object { $_.AccountBreakdown } | Where-Object { $_ }) -join '; '
        [PSCustomObject]@{ AMIId = $firstAmi.AMIId; AMIName = $firstAmi.AMIName; Description = $firstAmi.Description; Architecture = $firstAmi.Architecture; Platform = $firstAmi.Platform; CreationDate = $firstAmi.CreationDate; OwnerId = $firstAmi.OwnerId; State = $firstAmi.State; Public = $firstAmi.Public; TotalInstanceCount = $totalInstances; SSORolesUsing = $rolesUsing; AccountBreakdown = $accountsUsing; InstanceTypeBreakdown = ($amiGroup | ForEach-Object { $_.InstanceTypeBreakdown } | Where-Object { $_ }) -join '; '; StateBreakdown = ($amiGroup | ForEach-Object { $_.StateBreakdown } | Where-Object { $_ }) -join '; ' }
    } | Sort-Object TotalInstanceCount -Descending
    try {
        $consolidatedAmiReport | Export-Csv -Path $AmiOutputFile -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Add-Content -Path $LogFilePath -Value "[$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))] [INFO] Exported AMI usage report to ${AmiOutputFile}"
    } catch {
        Add-Content -Path $LogFilePath -Value "[$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))] [ERROR] Failed to export AMI usage report to ${AmiOutputFile}: $($_.Exception.Message)"
    }
} else {
    Add-Content -Path $LogFilePath -Value "[$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))] [WARN] No AMI data collected for reporting"
}

# Display summary
Write-Host "`nEC2 Instance Analysis Summary" -ForegroundColor Cyan
Write-Host "============================" -ForegroundColor Cyan
Write-Host "Script version: $scriptVersion" -ForegroundColor Green
Write-Host "Tag filtering enabled: $FilterProblematicTags" -ForegroundColor Green
if ($FilterProblematicTags) { Write-Host "Filtered tags: $($ProblematicTags -join ', ')" -ForegroundColor Gray }
Write-Host "Profiles processed: $($AwsProfiles.Count)" -ForegroundColor Green
Write-Host "Regions used: $($regionsUsed -join ', ')" -ForegroundColor Green
Write-Host "Total accounts: $($processedAccounts.Count)" -ForegroundColor Green
Write-Host "Total instances: $($outputBag.Count)" -ForegroundColor Green
Write-Host "Log file: ${LogFilePath}" -ForegroundColor Gray
Write-Host "Output file: ${OutputFile}" -ForegroundColor Gray
Write-Host "AMI report file: ${AmiOutputFile}" -ForegroundColor Gray
if ($outputBag.Count -le 20) {
    Write-Host "EC2 Instances Details (All Results):" -ForegroundColor Cyan
    $outputBag | Format-Table -AutoSize
} else {
    Write-Host "EC2 Instances Details (First 20 of $($outputBag.Count) results):" -ForegroundColor Cyan
    $outputBag | Select-Object -First 20 | Format-Table -AutoSize
    Write-Host "... and $($outputBag.Count - 20) more instances. See CSV file for complete results." -ForegroundColor Yellow
}
foreach ($account in $processedAccounts | Sort-Object AccountName) {
    Add-Content -Path $LogFilePath -Value "[$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))] [INFO] Account: $($account.AccountName) ($($account.AccountId)): $($account.SSORole)"
}
if ($allAmiReports.Count -gt 0) {
    Write-Host "`nAMI Usage Summary:" -ForegroundColor Yellow
    Write-Host "Total unique AMIs: $($consolidatedAmiReport.Count)" -ForegroundColor Green
    Write-Host "Top 10 AMIs:" -ForegroundColor Cyan
    $consolidatedAmiReport | Select-Object -First 10 | Format-Table AMIId, AMIName, Platform, TotalInstanceCount -AutoSize
}

# Flush log buffer and cleanup
if ($logBuffer.Count -gt 0) {
    Add-Content -Path $LogFilePath -Value $logBuffer -ErrorAction SilentlyContinue
    $logBuffer.Clear()
}
Add-Content -Path $LogFilePath -Value "[$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))] [INFO] Script completed successfully at $(Get-Date -Format 'HH:mm:ss')"