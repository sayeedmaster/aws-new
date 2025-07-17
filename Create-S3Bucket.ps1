param(
    [Parameter(Mandatory = $true)]
    [string]$BucketName,

    [Parameter(Mandatory = $false)]
    [string]$ProfileName,

    [Parameter(Mandatory = $false)]
    [string]$PSModulesPath = "C:\Development\binaries\psmodules",

    [Parameter(Mandatory = $false)]
    [switch]$EnableVersioning = $false,

    [Parameter(Mandatory = $false)]
    [switch]$BlockPublicAccess = $true
)

# Import AWS.Tools modules
try {
    Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.Common") -ErrorAction Stop
    Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.S3") -ErrorAction Stop
    Write-Host "✅ Successfully imported AWS.Tools modules (Common, S3)" -ForegroundColor Green
} catch {
    Write-Host "❌ Failed to import modules from $PSModulesPath. Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Function to derive region
function Get-ValidAWSRegion {
    param([string]$ProfileName)
    $validRegions = @(
        "us-east-1", "us-east-2", "us-west-1", "us-west-2",
        "ap-south-1", "ap-northeast-1", "ap-northeast-2",
        "ap-southeast-1", "ap-southeast-2",
        "eu-central-1", "eu-west-1", "eu-west-2", "eu-west-3"
    )
    try {
        $configPath = Join-Path $env:USERPROFILE ".aws\config"
        if (Test-Path $configPath) {
            $lines = Get-Content $configPath
            $inSection = $false
            foreach ($line in $lines) {
                if ($line -match "^\[profile $ProfileName\]" -or $line -match "^\[$ProfileName\]") {
                    $inSection = $true
                    continue
                }
                if ($inSection) {
                    if ($line -match "^\[") { $inSection = $false; continue }
                    if ($line -match "^region\s*=\s*(.+)") {
                        $region = $Matches[1].Trim()
                        if ($validRegions -contains $region) { return $region }
                    }
                }
            }
        }
    } catch {}
    if ($env:AWS_DEFAULT_REGION -and $validRegions -contains $env:AWS_DEFAULT_REGION) {
        return $env:AWS_DEFAULT_REGION
    }
    return "eu-west-1"
}

$Region = Get-ValidAWSRegion -ProfileName $ProfileName
Write-Host "Using AWS profile: $ProfileName" -ForegroundColor Cyan
Write-Host "Using AWS region: $Region" -ForegroundColor Cyan

# Step 1: Check if the bucket exists
try {
    $bucketExists = Get-S3Bucket -BucketName $BucketName -ProfileName $ProfileName -Region $Region -ErrorAction Stop
    Write-Host "⚠️ Bucket '$BucketName' already exists in region $Region." -ForegroundColor Yellow
    return
} catch {
    Write-Host "Bucket does not exist. Proceeding to create..." -ForegroundColor Green
}

# Step 2: Create the S3 bucket
New-S3Bucket -BucketName $BucketName -Region $Region -ProfileName $ProfileName
Write-Host "✅ Created S3 bucket: $BucketName" -ForegroundColor Green

# Step 3: Enable versioning (optional)
if ($EnableVersioning) {
    Write-S3BucketVersioning -BucketName $BucketName -VersioningConfig_Status Enabled -ProfileName $ProfileName -Region $Region
    Write-Host "🗂️ Versioning enabled for bucket: $BucketName" -ForegroundColor Gray
}

# Step 4: Block public access (recommended)
if ($BlockPublicAccess) {
    Write-S3PublicAccessBlock -BucketName $BucketName `
        -BlockPublicAcls $true `
        -IgnorePublicAcls $true `
        -BlockPublicPolicy $true `
        -RestrictPublicBuckets $true `
        -ProfileName $ProfileName `
        -Region $Region
    Write-Host "🔐 Public access blocked for bucket: $BucketName" -ForegroundColor Gray
}

# Step 5: Add optional tags (optional)
$tags = @(
    @{ Key = "Environment"; Value = "Lab" },
    @{ Key = "Purpose"; Value = "UserDataPackages" },
    @{ Key = "Owner"; Value = "$env:USERNAME" }
)
Write-S3BucketTagging -BucketName $BucketName -TagSet $tags -ProfileName $ProfileName -Region $Region
Write-Host "🏷️ Tags applied to bucket." -ForegroundColor Gray

Write-Host "`n🎉 Done! Bucket '$BucketName' is ready for storing software packages and related scripts."
