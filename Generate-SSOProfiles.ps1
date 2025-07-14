<#
.SYNOPSIS
    Wipes ~/.aws/config and rebuilds it:
      • Creates a base SSO profile interactively
      • Logs in (opens browser once)
      • Creates one profile per Account + Role you can access

.DESCRIPTION
    This script uses 'aws configure sso' to set up SSO authentication interactively.
    You will be prompted to enter your SSO start URL, region, and other configuration.
    After successful authentication, it automatically creates profiles for all accounts and roles.

.DESIGNED FOR
    Windows PowerShell 5.1  (no extra modules needed)

.PARAMETERS
    -Prefix         Text to prepend to every generated profile name (default: 'sso')
    
.NOTES
    The script will prompt you interactively for:
    - SSO start URL (e.g., https://ipfeu.awsapps.com/start)
    - SSO region (e.g., eu-west-1)
    - Default region for all profiles (e.g., eu-west-1)
    
    Version: 2.0
    Changes from v1:
    - Fixed SSO authentication issue by using 'aws configure sso' instead of manual profile setup
    - Interactive configuration prompts for all SSO settings
    - Dynamic configuration reading from the base profile
    - Improved error handling and validation
    - Better user experience with clearer feedback
#>

param(
    [string]$Prefix = 'sso'          # profile names look like sso-Prod-Admin
)

# ----------------------------  0. Paths  ------------------------------------
$AwsDir      = Join-Path $env:USERPROFILE '.aws'
$configPath  = Join-Path $AwsDir 'config'
$cacheDir    = Join-Path $AwsDir 'sso\cache'

Write-Host "AWS SSO Profile Generator v2.0" -ForegroundColor Cyan
Write-Host "==============================" -ForegroundColor Cyan
Write-Host ""

# ----------------------------  1. Backup & wipe  ----------------------------
if (Test-Path $configPath) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    Copy-Item $configPath "$configPath.bak-$stamp"
    Remove-Item $configPath
    Write-Host "Existing config backed-up to $($configPath).bak-$stamp" -ForegroundColor Green
}

# ----------------------------  2. Base profile  -----------------------------
$base = "$Prefix-base"
Write-Host "Setting up base SSO profile [$base]..." -ForegroundColor Yellow

# ----------------------------  3. SSO Configuration & Authentication  ------
Write-Host "`nStarting interactive SSO configuration..." -ForegroundColor Cyan
Write-Host "You will be prompted for the following:" -ForegroundColor White
Write-Host "  1. SSO start URL (e.g., https://ipfeu.awsapps.com/start)" -ForegroundColor Gray
Write-Host "  2. SSO region (e.g., eu-west-1)" -ForegroundColor Gray
Write-Host "  3. Account selection" -ForegroundColor Gray
Write-Host "  4. Role selection" -ForegroundColor Gray
Write-Host "  5. Default CLI region" -ForegroundColor Gray
Write-Host ""

# Use aws configure sso to set up the base profile interactively
# This handles the browser authentication and creates a proper SSO profile
Write-Host "Running 'aws configure sso --profile $base'..." -ForegroundColor Yellow
aws configure sso --profile $base

# Verify the SSO login was successful by checking if cache exists
if (!(Test-Path $cacheDir)) { 
    Write-Error "SSO authentication failed - cache directory not found."
    Write-Host "Please try running manually: aws configure sso --profile $base" -ForegroundColor Yellow
    exit 1
}

Write-Host "SSO authentication successful!" -ForegroundColor Green

# ----------------------------  4. Read SSO Configuration  ------------------
Write-Host "`nReading SSO configuration from base profile..." -ForegroundColor Cyan

# Get the SSO configuration that was set up interactively
$baseStartUrl = aws configure get sso_start_url --profile $base
$baseSsoRegion = aws configure get sso_region --profile $base
$baseRegion = aws configure get region --profile $base

if (-not $baseStartUrl -or -not $baseSsoRegion) {
    Write-Error "SSO configuration incomplete. Please run 'aws configure sso --profile $base' manually."
    exit 1
}

Write-Host "Using SSO configuration:" -ForegroundColor Green
Write-Host "  Start URL: $baseStartUrl" -ForegroundColor Gray
Write-Host "  SSO Region: $baseSsoRegion" -ForegroundColor Gray
Write-Host "  Default Region: $baseRegion" -ForegroundColor Gray

# ----------------------------  5. Grab Token  ------------------------------
Write-Host "`nRetrieving SSO access token..." -ForegroundColor Cyan

if (!(Test-Path $cacheDir)) { 
    Write-Error "SSO cache not found - login must have failed."
    exit 1
}

$tokenFile = Get-ChildItem $cacheDir -Filter '*.json' |
             Sort-Object LastWriteTime -Descending |
             Select-Object -First 1

if (-not $tokenFile) {
    Write-Error "No SSO token files found in cache directory."
    exit 1
}

try {
    $tokenData = Get-Content $tokenFile.FullName -Raw | ConvertFrom-Json
    $accessToken = $tokenData.accessToken
    
    if (-not $accessToken) { 
        throw "Access token not found in token file"
    }
    
    Write-Host "Using cached token from $($tokenFile.Name)" -ForegroundColor Green
} catch {
    Write-Error "Failed to read access token: $($_.Exception.Message)"
    Write-Host "Please try running: aws sso login --profile $base" -ForegroundColor Yellow
    exit 1
}

# ----------------------------  6. Enumerate Accounts & Roles  --------------
Write-Host "`nEnumerating available accounts and roles..." -ForegroundColor Cyan

try {
    $accountsResult = aws sso list-accounts `
                     --access-token $accessToken `
                     --region       $baseSsoRegion `
                     --output       json
    
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to list accounts"
    }
    
    $accounts = $accountsResult | ConvertFrom-Json | Select-Object -Expand accountList
    
    if (-not $accounts -or $accounts.Count -eq 0) {
        Write-Warning "No accounts found. You may not have access to any accounts."
        exit 0
    }
    
    Write-Host "Found $($accounts.Count) account(s)" -ForegroundColor Green
} catch {
    Write-Error "Failed to enumerate accounts: $($_.Exception.Message)"
    Write-Host "Please ensure your SSO session is valid: aws sso login --profile $base" -ForegroundColor Yellow
    exit 1
}

$totalProfiles = 0

foreach ($acct in $accounts) {
    Write-Host "`nAccount: $($acct.accountName) [$($acct.accountId)]" -ForegroundColor Yellow

    try {
        $rolesResult = aws sso list-account-roles `
                      --access-token $accessToken `
                      --account-id   $acct.accountId `
                      --region       $baseSsoRegion `
                      --output       json
        
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Failed to list roles for account $($acct.accountId)"
            continue
        }
        
        $roles = $rolesResult | ConvertFrom-Json | Select-Object -Expand roleList
        
        if (-not $roles -or $roles.Count -eq 0) {
            Write-Warning "No roles found for account $($acct.accountName)"
            continue
        }

        foreach ($role in $roles) {
            # Clean up profile name by removing spaces and special characters
            $cleanAccountName = $acct.accountName -replace '[^\w\-]', ''
            $cleanRoleName = $role.roleName -replace '[^\w\-]', ''
            $profileName = "$Prefix-$cleanAccountName-$cleanRoleName"
            
            try {
                aws configure set sso_start_url  $baseStartUrl      --profile $profileName
                aws configure set sso_region     $baseSsoRegion     --profile $profileName
                aws configure set sso_account_id $acct.accountId    --profile $profileName
                aws configure set sso_role_name  $role.roleName     --profile $profileName
                aws configure set region         $baseRegion        --profile $profileName
                
                Write-Host "   >> created profile [$profileName]" -ForegroundColor Green
                $totalProfiles++
                
                # Add a blank line after each profile (with a small delay to ensure AWS CLI has finished writing)
                Start-Sleep -Milliseconds 50
                Add-Content -Path $configPath -Value ""
            } catch {
                Write-Warning "Failed to create profile [$profileName]: $($_.Exception.Message)"
            }
        }
    } catch {
        Write-Warning "Failed to process account $($acct.accountName): $($_.Exception.Message)"
    }
}

# ----------------------------  7. Summary & Validation  --------------------
Write-Host "`n" -NoNewline
Write-Host "===============================================================================" -ForegroundColor Green
Write-Host "                                  SUMMARY                                     " -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Green

$allProfiles = aws configure list-profiles
$profileCount = ($allProfiles | Measure-Object).Count

Write-Host ">> SSO Configuration completed successfully!" -ForegroundColor Green
Write-Host ">> Total profiles created: $totalProfiles" -ForegroundColor Green
Write-Host ">> Total profiles available: $profileCount" -ForegroundColor Green
Write-Host ">> Config file: $configPath" -ForegroundColor Green

# Validate a few profiles
Write-Host "`nValidating profile configuration..." -ForegroundColor Cyan
$sampleProfiles = $allProfiles | Where-Object { $_ -like "$Prefix-*" -and $_ -ne $base } | Select-Object -First 3

foreach ($testProfile in $sampleProfiles) {
    try {
        $testResult = aws configure get sso_start_url --profile $testProfile
        if ($testResult -eq $baseStartUrl) {
            Write-Host ">> Profile [$testProfile] configured correctly" -ForegroundColor Green
        } else {
            Write-Warning "Profile [$testProfile] may have configuration issues"
        }
    } catch {
        Write-Warning "Failed to validate profile [$testProfile]"
    }
}

# ----------------------------  8. Usage Instructions  ----------------------
Write-Host "`n" -NoNewline
Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "                            AWS PROFILE USAGE GUIDE                           " -ForegroundColor Cyan
Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "LIST ALL PROFILES:" -ForegroundColor Yellow
Write-Host "   aws configure list-profiles" -ForegroundColor Green
Write-Host ""

Write-Host "CHECK CURRENT PROFILE:" -ForegroundColor Yellow
Write-Host "   aws configure list" -ForegroundColor Green
Write-Host "   # Shows current profile and configuration" -ForegroundColor Gray
Write-Host ""

Write-Host "SWITCH TO A SPECIFIC PROFILE:" -ForegroundColor Yellow
Write-Host "   Method 1 - Set environment variable (PowerShell):" -ForegroundColor Cyan
Write-Host "   `$env:AWS_PROFILE = '<profile-name>'" -ForegroundColor Green
Write-Host "   # Example: `$env:AWS_PROFILE = '$Prefix-Production-Admin'" -ForegroundColor Gray
Write-Host ""
Write-Host "   Method 2 - Set environment variable (Command Prompt):" -ForegroundColor Cyan
Write-Host "   set AWS_PROFILE=<profile-name>" -ForegroundColor Green
Write-Host "   # Example: set AWS_PROFILE=$Prefix-Production-Admin" -ForegroundColor Gray
Write-Host ""
Write-Host "   Method 3 - Use with individual commands:" -ForegroundColor Cyan
Write-Host "   aws <command> --profile <profile-name>" -ForegroundColor Green
Write-Host "   # Example: aws s3 ls --profile $Prefix-Production-Admin" -ForegroundColor Gray
Write-Host ""

Write-Host "SSO LOGIN (when your session expires):" -ForegroundColor Yellow
Write-Host "   aws sso login --profile <profile-name>" -ForegroundColor Green
Write-Host "   # Or if you set AWS_PROFILE: aws sso login" -ForegroundColor Gray
Write-Host "   # Login is shared across all profiles with the same SSO configuration" -ForegroundColor Gray
Write-Host ""

Write-Host "TEST YOUR PROFILE:" -ForegroundColor Yellow
Write-Host "   aws sts get-caller-identity --profile <profile-name>" -ForegroundColor Green
Write-Host "   # Shows Account ID, User ID, and ARN for the profile" -ForegroundColor Gray
Write-Host ""

Write-Host "COMMON COMMANDS:" -ForegroundColor Yellow
Write-Host "   aws ec2 describe-instances --profile <profile-name>" -ForegroundColor Green
Write-Host "   aws s3 ls --profile <profile-name>" -ForegroundColor Green
Write-Host "   aws iam list-users --profile <profile-name>" -ForegroundColor Green
Write-Host ""

Write-Host "CONFIG FILE LOCATION:" -ForegroundColor Yellow
Write-Host "   $configPath" -ForegroundColor Green
Write-Host "   # You can edit this file manually if needed" -ForegroundColor Gray
Write-Host ""

if ($allProfiles.Count -gt 0) {
    Write-Host "AVAILABLE PROFILES:" -ForegroundColor Yellow
    $allProfiles | ForEach-Object { 
        $indicator = if ($_ -eq $base) { " (base profile)" } else { "" }
        Write-Host "   $_$indicator" -ForegroundColor Green 
    }
    Write-Host ""
}

Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "Setup complete! You can now use AWS CLI with multiple accounts and roles." -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Cyan
