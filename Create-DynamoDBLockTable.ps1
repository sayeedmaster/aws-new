param(
    [Parameter(Mandatory = $false)]
    [string]$TableName = "terraform-state-lock",

    [Parameter(Mandatory = $false)]
    [string]$ProfileName = "sso-production-AdministratorAccess",

    [Parameter(Mandatory = $false)]
    [string]$PSModulesPath = "C:\github\psmodules"
)

# Import AWS.Tools modules
try {
    Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.Common") -ErrorAction Stop
    Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.DynamoDBv2") -ErrorAction Stop
    Write-Host "✅ Successfully imported AWS.Tools modules (Common, DynamoDBv2)" -ForegroundColor Green
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

# Step 1: Check if the table exists
try {
    Get-DDBTable -TableName $TableName -ProfileName $ProfileName -Region $Region -ErrorAction Stop
    Write-Host "⚠️ DynamoDB table '$TableName' already exists in region $Region." -ForegroundColor Yellow
    return
} catch {
    Write-Host "DynamoDB table does not exist. Proceeding to create..." -ForegroundColor Green
}

# Step 2: Create the DynamoDB table for Terraform state locking
try {
    $schema = New-DDBTableSchema
    $schema | Add-DDBKeySchema -KeyName "LockID" -KeyDataType "S" | New-DDBTable -TableName $TableName -BillingMode PAY_PER_REQUEST -ProfileName $ProfileName -Region $Region

    Write-Host "✅ Successfully created DynamoDB table '$TableName' for Terraform state locking." -ForegroundColor Green
} catch {
    Write-Host "❌ Failed to create DynamoDB table. Error: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n🎉 Done! DynamoDB table '$TableName' is ready for use with Terraform."
