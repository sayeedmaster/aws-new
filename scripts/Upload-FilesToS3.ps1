param(
    [Parameter(Mandatory = $true)]
    [string]$SourceFile,

    [Parameter(Mandatory = $true)]
    [string]$BucketName,

    [Parameter(Mandatory = $false)]
    [string]$ProfileName,

    [Parameter(Mandatory = $false)]
    [string]$Prefix = "artifacts/",  # S3 key prefix (folder)

    [Parameter(Mandatory = $false)]
    [string]$PSModulesPath = "C:\github\psmodules"
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

# Validate local file
if (-not (Test-Path $SourceFile -PathType Leaf)) {
    Write-Host "❌ Source file '$SourceFile' does not exist or is a directory." -ForegroundColor Red
    exit 1
}

# Upload file
$fileInfo = Get-Item $SourceFile
$s3Key = if ($Prefix) { "$Prefix$($fileInfo.Name)" } else { $fileInfo.Name }

try {
    Write-S3Object -BucketName $BucketName `
                   -File $fileInfo.FullName `
                   -Key $s3Key `
                   -Region $Region `
                   -ProfileName $ProfileName `
                   -CannedACL "bucket-owner-full-control" | Out-Null

    Write-Host "📦 Uploaded: $($fileInfo.Name) -> s3://$BucketName/$s3Key" -ForegroundColor Green
} catch {
    Write-Host "❌ Failed to upload $($fileInfo.Name). Error: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "Upload complete." -ForegroundColor Cyan
