# Launch-EC2FromExcel.ps1
# PowerShell script to launch EC2 instances from Excel configuration using AWSPowerShell.NetCore with multiple SSO profiles

# Requires AWSPowerShell.NetCore and ImportExcel module
# Prerequisites:
# 1. AWSPowerShell.NetCore module located at D:\psmodules
# 2. Install-Module -Name ImportExcel
# 3. AWS CLI installed and configured with SSO profiles for each AccountName in the Excel file
# 4. Excel file with EC2 configuration (see sample layout below)

param (
    [Parameter(Mandatory=$true)]
    [string]$ExcelFilePath,
    [Parameter(Mandatory=$true)]
    [string]$SSORoleName,
    [Parameter(Mandatory=$true)]
    [string]$SSOStartUrl,
    [Parameter(Mandatory=$false)]
    [string]$LogFilePath = ".\EC2_Launch_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
)

# Function to write logs
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Write-Host $logMessage
    Add-Content -Path $LogFilePath -Value $logMessage
}

try {
    # Import required modules from specified path
    Import-Module -Name "$env:D:\psmodules\AWSPowerShell.NetCore" -ErrorAction Stop
    Import-Module -Name ImportExcel -ErrorAction Stop

    Write-Log "Starting EC2 launch script"

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

    # Process each EC2 configuration
    foreach ($config in $ec2Configs) {
        try {
            $accountId = $config.AccountId
            $accountName = $config.AccountName
            $region = ($config.AvailabilityZone -split '-')[0..2] -join '-'  # Extract region from AZ
            $instanceName = $config.InstanceName
            
            Write-Log "Processing EC2 configuration for Account: $accountId ($accountName), Region: $region, Instance: $instanceName"

            # Authenticate using AWS SSO for the specific account
            Write-Log "Initiating AWS SSO authentication for profile: $accountName"
            try {
                $ssoCredentials = Get-SSOToken -ProfileName $accountName -StartUrl $SSOStartUrl -ErrorAction Stop
                Write-Log "SSO authentication successful for profile: $accountName"
            } catch {
                Write-Log "Failed to authenticate with SSO profile: $accountName. Error: $($_.Exception.Message)" "ERROR"
                continue
            }

            # Assume role for the target account
            $roleArn = "arn:aws:iam::$($accountId):role/$SSORoleName"
            $assumeRoleParams = @{
                RoleArn = $roleArn
                RoleSessionName = "EC2LaunchSession_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
                AccessToken = $ssoCredentials.AccessToken
            }
            $roleCredentials = (Get-STSAssumeRoleWithSAML -RoleArn $roleArn -AccessToken $ssoCredentials.AccessToken).Credentials
            Write-Log "Successfully assumed role: $roleArn"

            # Set AWS credentials for the session
            Set-AWSCredential -AccessKey $roleCredentials.AccessKeyId `
                            -SecretKey $roleCredentials.SecretAccessKey `
                            -SessionToken $roleCredentials.SessionToken `
                            -Region $region

            # Prepare EC2 launch parameters
            $launchParams = @{
                ImageId = $config.ImageId
                InstanceType = $config.InstanceType
                KeyName = $config.KeyName
                SubnetId = $config.SubnetId
                MinCount = 1
                MaxCount = 1
            }

            # Add Private IP Address if specified
            if ($config.PrivateIpAddress) {
                $launchParams.PrivateIpAddress = $config.PrivateIpAddress
            }

            # Add Associate Public IP Address
            if ($config.AssociatePublicIpAddress -eq 'true') {
                $launchParams.AssociatePublicIpAddress = $true
            }

            # Add Security Group IDs (comma-separated in Excel)
            if ($config.SecurityGroupIds) {
                $launchParams.SecurityGroupId = $config.SecurityGroupIds -split ',' | ForEach-Object { $_.Trim() }
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
            if ($config.RootVolumeSize -or $config.RootVolumeType) {
                $blockDeviceMapping = New-Object Amazon.EC2.Model.BlockDeviceMapping
                $ebs = New-Object Amazon.EC2.Model.EbsBlockDevice
                if ($config.RootVolumeSize) { $ebs.VolumeSize = [int]$config.RootVolumeSize }
                if ($config.RootVolumeType) { $ebs.VolumeType = $config.RootVolumeType }
                $ebs.DeleteOnTermination = $true
                $blockDeviceMapping.DeviceName = "/dev/xvda"
                $blockDeviceMapping.Ebs = $ebs
                $launchParams.BlockDeviceMapping = $blockDeviceMapping
            }

            # Add Monitoring
            if ($config.Monitoring -eq 'true') {
                $launchParams.Monitoring_Enabled = $true
            }

            # Add Metadata Options
            $metadataOptions = New-Object Amazon.EC2.Model.InstanceMetadataOptionsRequest
            if ($config.MetadataOptionsHttpTokens) { $metadataOptions.HttpTokens = $config.MetadataOptionsHttpTokens }
            if ($config.MetadataOptionsHttpEndpoint) { $metadataOptions.HttpEndpoint = $config.MetadataOptionsHttpEndpoint }
            if ($config.MetadataOptionsHttpPutResponseHopLimit) { $metadataOptions.HttpPutResponseHopLimit = [int]$config.MetadataOptionsHttpPutResponseHopLimit }
            if ($config.InstanceMetadataTags -eq 'true') { $metadataOptions.InstanceMetadataTags = 'enabled' }
            $launchParams.MetadataOptions = $metadataOptions

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

            # Add SR-IOV and ENA Support
            if ($config.SriovNetSupport) { $launchParams.SriovNetSupport = $config.SriovNetSupport }
            if ($config.EnaSupport -eq 'true') { $launchParams.EnaSupport = $true }

            # Add User Data
            if ($config.UserData) {
                $launchParams.UserData = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($config.UserData))
            }

            # Add Tags (Name=Value format, comma-separated)
            if ($config.Tags -or $instanceName) {
                $tags = @()
                if ($config.Tags) {
                    $tagPairs = $config.Tags -split ',' | ForEach-Object { $_.Trim() }
                    foreach ($tagPair in $tagPairs) {
                        $keyValue = $tagPair -split '='
                        if ($keyValue.Count -eq 2) {
                            $tag = New-Object Amazon.EC2.Model.Tag
                            $tag.Key = $keyValue[0].Trim()
                            $tag.Value = $keyValue[1].Trim()
                            $tags += $tag
                        }
                    }
                }
                # Add InstanceName as a tag if not already included
                if ($instanceName -and -not ($tags | Where-Object { $_.Key -eq 'Name' })) {
                    $nameTag = New-Object Amazon.EC2.Model.Tag
                    $nameTag.Key = 'Name'
                    $nameTag.Value = $instanceName
                    $tags += $nameTag
                }
                if ($tags.Count -gt 0) {
                    $tagSpec = New-Object Amazon.EC2.Model.TagSpecification
                    $tagSpec.ResourceType = "instance"
                    $tagSpec.Tags = $tags
                    $launchParams.TagSpecification = $tagSpec
                }
            }

            # Launch EC2 instance
            Write-Log "Launching EC2 instance in Account: $accountId ($accountName), Region: $region, Instance: $instanceName"
            $reservation = New-EC2Instance @launchParams -ErrorAction Stop
            $instanceId = $reservation.Instances[0].InstanceId
            Write-Log "Successfully launched EC2 instance: $instanceId"

            # Note: Some attributes like Domain, DefaultGateway, PrimaryDNS, SecondaryDNS, AutoRecovery, and TrafficMirroring
            # require additional API calls (e.g., ModifyInstanceAttribute) and are not supported directly in New-EC2Instance.

        } catch {
            Write-Log "Error processing configuration for Account: $accountId ($accountName), Region: $region, Instance: $instanceName. Error: $($_.Exception.Message)" "ERROR"
            continue
        }
    }

    Write-Log "EC2 launch process completed"

} catch {
    Write-Log "Fatal error: $($_.Exception.Message)" "ERROR"
    exit 1
}