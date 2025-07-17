param(
    [Parameter(Mandatory = $true)]
    [string]$SourceDirectory,

    [Parameter(Mandatory = $true)]
    [string]$BucketName,

    [Parameter(Mandatory = $false)]
    [string]$ProfileName,

    [Parameter(Mandatory = $false)]
    [string]$Prefix = "",  # optional S3 key prefix (e.g., "userdata-packages/")

    [Parameter(Mandatory = $false)]
    [string]$PSModulesPath = "C:\Development\binaries\psmodules"
)

# Import AWS.Tools modules
try {
    Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.Common") -ErrorAction Stop
    Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.S3") -ErrorAction Stop
    Write-Host "✅ Successfully imported AWS.Tools modules (Common, S3)" -ForegroundColor Green
} catch {
    Write-Host "❌ Failed to import AWS modules from $PSModulesPath. Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Region helper function
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

# Validate local directory
if (-not (Test-Path $SourceDirectory)) {
    Write-Host "❌ Source directory '$SourceDirectory' does not exist." -ForegroundColor Red
    exit 1
}

# Upload files
$files = Get-ChildItem -Path $SourceDirectory -Recurse -File
if ($files.Count -eq 0) {
    Write-Host "⚠️ No files found in $SourceDirectory to upload." -ForegroundColor Yellow
    exit 0
}

foreach ($file in $files) {
    $relativePath = $file.FullName.Substring($SourceDirectory.Length).TrimStart('\').Replace('\', '/')
    $s3Key = if ($Prefix) { "$Prefix$relativePath" } else { $relativePath }

    try {
        Write-S3Object -BucketName $BucketName `
                       -File $file.FullName `
                       -Key $s3Key `
                       -Region $Region `
                       -ProfileName $ProfileName `
                       -CannedACL "bucket-owner-full-control" | Out-Null

        Write-Host "📦 Uploaded: $relativePath -> s3://$BucketName/$s3Key" -ForegroundColor Green
    } catch {
        Write-Host "❌ Failed to upload $relativePath. Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "`n🎉 Upload complete. Files available in S3 bucket: $BucketName" -ForegroundColor Cyan
