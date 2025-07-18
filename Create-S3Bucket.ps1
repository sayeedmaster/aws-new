param(
    [Parameter(Mandatory = $false)]
    [string]$BucketName = "userdata-terraform-packages",

    [Parameter(Mandatory = $false)]
    [string]$ProfileName = "sso-production-AdministratorAccess",

    [Parameter(Mandatory = $false)]
    [string]$PSModulesPath = "C:\github\psmodules",

    [Parameter(Mandatory = $false)]
    [switch]$EnableVersioning = $true,

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
$bucketExists = Get-S3Bucket -BucketName $BucketName -ProfileName $ProfileName -Region $Region -ErrorAction SilentlyContinue
if ($null -ne $bucketExists) {
    Write-Host "⚠️ Bucket '$BucketName' already exists in region $Region." -ForegroundColor Yellow
    return
}
else {
    Write-Host "Bucket '$BucketName' does not exist. Proceeding to create..." -ForegroundColor Green
}

# Step 2: Create the S3 bucket
New-S3Bucket -BucketName $BucketName -Region $Region -ProfileName $ProfileName
Write-Host "✅ Created S3 bucket: $BucketName" -ForegroundColor Green

# Step 3: Enable versioning (optional)
if ($EnableVersioning) {
    Write-S3BucketVersioning -BucketName $BucketName -VersioningConfig_Status Enabled -ProfileName $ProfileName -Region $Region
    Write-Host "🗂️ Versioning enabled for bucket: $BucketName" -ForegroundColor Gray
}

# Step 4: Apply server-side encryption
try {
    $encryptionRule = New-Object Amazon.S3.Model.ServerSideEncryptionRule
    $encryptionRule.ServerSideEncryptionByDefault = New-Object Amazon.S3.Model.ServerSideEncryptionByDefault
    $encryptionRule.ServerSideEncryptionByDefault.ServerSideEncryptionAlgorithm = "AES256"
    Set-S3BucketEncryption -BucketName $BucketName -ServerSideEncryptionConfiguration_ServerSideEncryptionRule $encryptionRule -ProfileName $ProfileName -Region $Region
    Write-Host "🔑 Server-side encryption (AES256) enabled for bucket: $BucketName" -ForegroundColor Gray
} catch {
    Write-Host "❌ Failed to apply server-side encryption. Error: $($_.Exception.Message)" -ForegroundColor Red
}

# Step 5: Block public access (recommended)
if ($BlockPublicAccess) {
    Add-S3PublicAccessBlock -BucketName $BucketName `
        -PublicAccessBlockConfiguration_BlockPublicAcl $true `
        -PublicAccessBlockConfiguration_IgnorePublicAcl $true `
        -PublicAccessBlockConfiguration_BlockPublicPolicy $true `
        -PublicAccessBlockConfiguration_RestrictPublicBucket $true `
        -ProfileName $ProfileName `
        -Region $Region
    Write-Host "🔐 Public access blocked for bucket: $BucketName" -ForegroundColor Gray
}

# Step 6: Add optional tags (optional)
$tags = @(
    @{ Key = "Environment"; Value = "Lab" },
    @{ Key = "Purpose"; Value = "Terraform State and Artifacts" },
    @{ Key = "Owner"; Value = "$env:USERNAME" }
)
Write-S3BucketTagging -BucketName $BucketName -TagSet $tags -ProfileName $ProfileName -Region $Region
Write-Host "🏷️ Tags applied to bucket." -ForegroundColor Gray

# Step 7: Apply lifecycle rules
try {
    $rule1 = New-Object Amazon.S3.Model.LifecycleRule
    $rule1.ID = "TerraformStateRetention"
    $rule1.Filter = New-Object Amazon.S3.Model.LifecycleFilter
    $rule1.Filter.LifecycleFilterPredicate = New-Object Amazon.S3.Model.LifecyclePrefixPredicate
    $rule1.Filter.LifecycleFilterPredicate.Prefix = "terraform/"
    $rule1.Status = "Enabled"
    $rule1.NoncurrentVersionExpiration = New-Object Amazon.S3.Model.LifecycleRuleNoncurrentVersionExpiration
    $rule1.NoncurrentVersionExpiration.NoncurrentDays = 3

    $rule2 = New-Object Amazon.S3.Model.LifecycleRule
    $rule2.ID = "ArtifactsLifecycle"
    $rule2.Filter = New-Object Amazon.S3.Model.LifecycleFilter
    $rule2.Filter.LifecycleFilterPredicate = New-Object Amazon.S3.Model.LifecyclePrefixPredicate
    $rule2.Filter.LifecycleFilterPredicate.Prefix = "artifacts/"
    $rule2.Status = "Enabled"
    $rule2.Transitions = New-Object 'System.Collections.Generic.List[Amazon.S3.Model.LifecycleTransition]'
    $transition = New-Object Amazon.S3.Model.LifecycleTransition
    $transition.Days = 30
    $transition.StorageClass = "STANDARD_IA"
    $rule2.Transitions.Add($transition)
    $rule2.Expiration = New-Object Amazon.S3.Model.LifecycleRuleExpiration
    $rule2.Expiration.Days = 31
    $rule2.AbortIncompleteMultipartUpload = New-Object Amazon.S3.Model.LifecycleRuleAbortIncompleteMultipartUpload
    $rule2.AbortIncompleteMultipartUpload.DaysAfterInitiation = 7

    Write-Host "--- DEBUG: Rule 1 ---"
    Write-Host ($rule1 | Out-String)
    Write-Host "--- DEBUG: Rule 2 ---"
    Write-Host ($rule2 | Out-String)

    Write-S3LifecycleConfiguration -BucketName $BucketName -Configuration_Rule $rule1, $rule2 -ProfileName $ProfileName -Region $Region
    Write-Host "🔄 Lifecycle rules applied to bucket." -ForegroundColor Gray
} catch {
    Write-Host "❌ Failed to apply lifecycle rules. Error: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n🎉 Done! Bucket '$BucketName' is ready for storing Terraform state and artifacts."
