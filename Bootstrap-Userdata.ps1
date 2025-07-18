<powershell>
#==============================================================================
#
#                 TAG-DRIVEN ADVANCED USERDATA SCRIPT (v2.0)
#
# This script performs advanced configuration for a Windows EC2 instance by
# reading its configuration from its own EC2 tags.
#
#   1. Sets up detailed logging to C:\Temp\userdata-log.txt.
#   2. Gathers instance metadata (ID, region) from IMDS.
#   3. Fetches its own EC2 tags to get configuration values.
#   4. Initializes and formats any attached secondary EBS volumes.
#   5. Renames the computer based on a tag.
#   6. Joins the instance to an Active Directory domain using credentials
#      whose names are specified in tags.
#   7. Restarts the computer to apply the domain join and name change.
#
# PREREQUISITES:
#   - An IAM Instance Profile with a role that has permissions for:
#     - ec2:DescribeInstances (to read its own tags)
#     - ssm:GetParameter (to get domain join credentials)
#   - The AWS.Tools.EC2 and AWS.Tools.SimpleSystemsManagement modules must be
#     available on the AMI (pre-installed on recent AWS Windows Server AMIs).
#
# REQUIRED EC2 TAGS:
#   - Domain: The FQDN of the Active Directory domain (e.g., prod01.local).
#   - PrimaryDNS: The IP address of the primary DNS server/domain controller.
#
# OPTIONAL EC2 TAGS:
#   - SecondaryDNS: The IP address of the secondary DNS server.
#   - ComputerNamePrefix: A prefix for the new computer name (e.g., WEB-SRV).
#
# SSM PARAMETER NAMING CONVENTION:
#   This script derives the Parameter Store names from the 'Domain' tag.
#   For a domain 'prod01.local', it will look for:
#   - ad/prod01.local/username (String)
#   - ad/prod01.local/password (SecureString)
#
#==============================================================================

# --- Script-level Configuration ---
$LogFile = "C:\Temp\userdata-log.txt"

#==============================================================================
# SCRIPT START
#==============================================================================

# --- 1. Setup Logging ---
Function Write-Log {
    Param ([string]$LogString)
    $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Add-Content $LogFile -Value "$Timestamp - $LogString" -Force
}

If (-not (Test-Path -Path "C:\Temp")) {
    New-Item -ItemType Directory -Path "C:\Temp" -Force
}
Write-Log "------------------ Tag-Driven Userdata Script Started ------------------"

# --- 2. Gather Instance Metadata & Tags ---
Try {
    Write-Log "Querying Instance Metadata Service (IMDS)..."
    $imds_base_uri = "http://169.254.169.254/latest/meta-data"
    $InstanceId = Invoke-RestMethod -Uri "$imds_base_uri/instance-id"
    $Region = (Invoke-RestMethod -Uri "http://169.254.169.254/latest/dynamic/instance-identity/document").region
    $PrivateIp = Invoke-RestMethod -Uri "$imds_base_uri/local-ipv4"

    Write-Log "Successfully retrieved metadata:"
    Write-Log "  - Instance ID: $InstanceId"
    Write-Log "  - Region: $Region"
    Write-Log "  - Private IP: $PrivateIp"

    Write-Log "Fetching EC2 tags for instance $InstanceId..."
    # Import required module and fetch instance details, which include tags
    Import-Module AWS.Tools.EC2 -ErrorAction SilentlyContinue
    $instance = Get-EC2Instance -InstanceId $InstanceId -Region $Region -ErrorAction Stop
    
    # Convert the tags list to a more accessible hashtable
    $tags = @{}
    $instance.Instances.Tags | ForEach-Object { $tags[$_.Key] = $_.Value }

    Write-Log "Successfully fetched $($tags.Count) tags."
}
Catch {
    Write-Log "[FATAL] Failed to query IMDS or fetch EC2 tags. The IAM role may be missing ec2:DescribeInstances permission. Error: $_"
    Exit 1
}

# --- 3. Populate Variables from Tags and Validate ---
Write-Log "Populating configuration from tags..."

$DomainName = $tags['Domain']
$PrimaryDNS = $tags['PrimaryDNS']
$SecondaryDNS = $tags['SecondaryDNS'] # This can be null
$DomainUserParameter = $tags['DomainUserParameter']
$DomainPasswordParameter = $tags['DomainPasswordParameter']
$ComputerNamePrefix = $tags['ComputerNamePrefix'] # Optional, will use a default if not set

# Validate required tags
$missingTags = @()
if (-not $DomainName) { $missingTags += "'Domain'" }
if (-not $PrimaryDNS) { $missingTags += "'PrimaryDNS'" }
if (-not $DomainUserParameter) { $missingTags += "'DomainUserParameter'" }
if (-not $DomainPasswordParameter) { $missingTags += "'DomainPasswordParameter'" }

if ($missingTags.Count -gt 0) {
    Write-Log "[FATAL] The instance is missing required tags: $($missingTags -join ', '). Halting script."
    Exit 1
}

# Set default for optional tag
if (-not $ComputerNamePrefix) {
    $ComputerNamePrefix = "WIN-SRV"
    Write-Log "'ComputerNamePrefix' tag not found. Using default value: $ComputerNamePrefix" "WARN"
}

Write-Log "Configuration loaded successfully from tags."

# --- 4. Initialize and Format Attached Disks ---
Try {
    Write-Log "Scanning for uninitialized disks..."
    $disks = Get-Disk | Where-Object { $_.PartitionStyle -eq 'RAW' -and $_.IsReadOnly -eq $false }

    If ($disks) {
        Write-Log "Found $($disks.Count) raw disk(s) to prepare."
        foreach ($disk in $disks) {
            $diskNumber = $disk.Number
            Write-Log "Processing Disk #$diskNumber..."
            $disk | Initialize-Disk -PartitionStyle GPT -PassThru | `
                New-Partition -AssignDriveLetter -UseMaximumSize | `
                Format-Volume -FileSystem NTFS -NewFileSystemLabel "Data" -Confirm:$false
            Write-Log "Disk #$diskNumber has been initialized, partitioned, and formatted."
        }
    }
    Else {
        Write-Log "No uninitialized disks found."
    }
}
Catch {
    Write-Log "[ERROR] Failed during disk preparation. Error: $_"
}

# --- 5. Set Computer Name ---
$NewComputerName = "$ComputerNamePrefix-$InstanceId"
Write-Log "Preparing to rename computer to '$NewComputerName'."

# --- 6. Join to Active Directory Domain ---
Write-Log "Preparing to join domain '$DomainName'."

# Construct DNS IP list
$DnsIpAddresses = @($PrimaryDNS)
if ($SecondaryDNS) {
    $DnsIpAddresses += $SecondaryDNS
}

# Set Primary DNS to the Domain Controller for domain resolution
Try {
    Get-NetAdapter | Set-DnsClientServerAddress -ServerAddresses $DnsIpAddresses
    Write-Log "Successfully set DNS servers to ($($DnsIpAddresses -join ', '))."
}
Catch {
    Write-Log "[ERROR] Failed to set DNS server addresses. Domain join may fail. Error: $_"
}

# Retrieve credentials securely from AWS Parameter Store using names from tags
Try {
    Write-Log "Retrieving domain credentials from Parameter Store..."
    Import-Module AWS.Tools.SimpleSystemsManagement -ErrorAction SilentlyContinue
    $username = (Get-SSMParameter -Name $DomainUserParameter -Region $Region -ErrorAction Stop).Value
    $password = (Get-SSMParameter -Name $DomainPasswordParameter -WithDecryption $true -Region $Region -ErrorAction Stop).Value | ConvertTo-SecureString -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential($username, $password)
    Write-Log "Successfully retrieved credentials for user '$username'."
}
Catch {
    Write-Log "[FATAL] Could not retrieve credentials from Parameter Store. Halting domain join. Error: $_"
    Write-Log "------------------ Userdata Script Finished with Errors ------------------"
    Exit 1
}

# Perform the domain join and rename, then restart
Try {
    Write-Log "Executing domain join and rename. The instance will restart upon completion."
    Add-Computer -DomainName $DomainName -Credential $credential -NewName $NewComputerName -Force -Restart
}
Catch {
    Write-Log "[FATAL] The Add-Computer command failed. This instance may not be properly configured. Error: $_"
    Write-Log "------------------ Userdata Script Finished with Errors ------------------"
    Exit 1
}

Write-Log "------------------ Userdata Script Finished ------------------"

</powershell>