# Test script to verify region detection logic
# This tests various methods of detecting the AWS region from SSO profiles

Write-Host "=== Testing AWS Region Detection ===" -ForegroundColor Cyan

# Mock Write-Log function for testing
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "INFO" { "White" }
        "WARN" { "Yellow" }
        "ERROR" { "Red" }
        "DEBUG" { "Gray" }
        default { "Gray" }
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

Write-Host "`nTesting region detection methods..." -ForegroundColor Yellow

# Test Method 1: Get-DefaultAWSRegion
Write-Host "`n1. Testing Get-DefaultAWSRegion:" -ForegroundColor Cyan
try {
    $defaultRegion = Get-DefaultAWSRegion -ErrorAction Stop
    if ($defaultRegion -is [string]) {
        Write-Log -Message "Get-DefaultAWSRegion returned string: $defaultRegion" -Level "INFO"
    } elseif ($defaultRegion -and $defaultRegion.Region) {
        Write-Log -Message "Get-DefaultAWSRegion returned object with Region: $($defaultRegion.Region)" -Level "INFO"
    } else {
        Write-Log -Message "Get-DefaultAWSRegion returned: $defaultRegion" -Level "WARN"
    }
} catch {
    Write-Log -Message "Get-DefaultAWSRegion failed: $($_.Exception.Message)" -Level "WARN"
}

# Test Method 2: AWS Profile Details
Write-Host "`n2. Testing AWS Profile Details:" -ForegroundColor Cyan
try {
    $profiles = Get-AWSCredential -ListProfileDetail -ErrorAction Stop
    Write-Log -Message "Found $($profiles.Count) AWS profiles" -Level "INFO"
    
    foreach ($profile in $profiles | Select-Object -First 3) {
        $regionInfo = if ($profile.Region) { $profile.Region } else { "No region configured" }
        Write-Log -Message "Profile '$($profile.ProfileName)': Region = $regionInfo" -Level "INFO"
    }
} catch {
    Write-Log -Message "AWS Profile listing failed: $($_.Exception.Message)" -Level "WARN"
}

# Test Method 3: Environment Variables
Write-Host "`n3. Testing Environment Variables:" -ForegroundColor Cyan
$awsDefaultRegion = $env:AWS_DEFAULT_REGION
$awsRegion = $env:AWS_REGION

if ($awsDefaultRegion) {
    Write-Log -Message "AWS_DEFAULT_REGION = $awsDefaultRegion" -Level "INFO"
} else {
    Write-Log -Message "AWS_DEFAULT_REGION is not set" -Level "WARN"
}

if ($awsRegion) {
    Write-Log -Message "AWS_REGION = $awsRegion" -Level "INFO"
} else {
    Write-Log -Message "AWS_REGION is not set" -Level "WARN"
}

# Test Method 4: EC2 Region Detection
Write-Host "`n4. Testing EC2 Region Detection:" -ForegroundColor Cyan
try {
    $ec2Regions = Get-EC2Region -ErrorAction Stop
    if ($ec2Regions) {
        Write-Log -Message "EC2 region command succeeded - AWS session is active" -Level "INFO"
        Write-Log -Message "Available regions: $($ec2Regions.Count)" -Level "INFO"
    }
} catch {
    Write-Log -Message "EC2 region detection failed: $($_.Exception.Message)" -Level "WARN"
    Write-Log -Message "This indicates no active AWS session or credentials not set" -Level "INFO"
}

Write-Host "`n=== Region Detection Test Complete ===" -ForegroundColor Cyan
Write-Host "The script will now use multiple fallback methods to detect the region." -ForegroundColor Green
