# Windows EC2 Bootstrapping Framework (Modular, S3-based, Config-Driven)

## Overview

This document outlines a modular, scalable approach to bootstrap **Windows EC2 instances** using a combination of:

* PowerShell scripts
* Config-driven logic (via `Config.json`)
* Amazon S3 for storing assets and scripts
* Excel as the source of truth

Designed for environments with:

* No internet access on EC2s
* Dynamic instance configuration
* Conditional application install (e.g., SQL Server)

---

## ✅ High-Level Workflow

1. Parse Excel (source of truth)
2. Generate EC2 config and `Config.json`
3. Upload `Config.json` + scripts to S3
4. Launch EC2 instance with base64-encoded user data
5. User data downloads & executes bootstrap pipeline
6. Modular scripts execute based on config
7. Post-reboot actions (e.g., SQL install)

---

## ✅ Prerequisites

### Local Machine

* PowerShell 7+ or Windows PowerShell 5.1
* Modules:

  * `ImportExcel`
  * `AWS.Tools.S3`

### EC2 IAM Role

* `s3:GetObject` for your bootstrap bucket

### S3 Bucket Layout

```
s3://my-bucket/
├── bootstrap/
│   ├── bootstrap.zip            # Contains all .ps1 files and modules
│   ├── AZ1-SQL01/               # Per-instance config
│   │   └── Config.json
│   ├── aws-modules/            # AWS.Tools prepackaged
│   │   └── AWS.Tools.S3.zip
│   ├── sql2019/
│   │   ├── SQLServer2019.iso
│   │   └── ConfigurationFile.ini
```

---

## ✅ Excel to Config Generator (Local)

```powershell
$instanceName = "AZ1-SQL01"
$config = @{
    ComputerName = "AZ1-SQL01"
    IPAddress = "10.0.1.10"
    Gateway = "10.0.1.1"
    DNS = @("10.0.1.5", "10.0.1.6")
    Domain = "corp.local"
    OU = "OU=SQL,DC=corp,DC=local"
    SQLInstall = $true
    SQLMediaUrl = "s3://my-bucket/sql2019/SQLServer2019.iso"
    SQLConfigUrl = "s3://my-bucket/sql2019/ConfigurationFile.ini"
}

$config | ConvertTo-Json -Depth 5 | Set-Content "Config.json"
Write-S3Object -BucketName "my-bucket" -Key "bootstrap/$instanceName/Config.json" -File "Config.json"
```

---

## ✅ User Data Script (Embedded in EC2 Launch)

```powershell
<powershell>
$bucketName = "my-bucket"
$hostname   = (Invoke-RestMethod -Uri http://169.254.169.254/latest/meta-data/local-hostname).Split(".")[0]
$bootstrapRoot = "C:\\Bootstrap"
$configKey  = "bootstrap/$hostname/Config.json"
$bootstrapZipKey = "bootstrap/bootstrap.zip"
$modulesKey = "bootstrap/aws-modules/AWS.Tools.S3.zip"

New-Item -ItemType Directory -Path $bootstrapRoot -Force | Out-Null

Expand-Archive -Path "$bootstrapRoot\\AWS.Tools.S3.zip" -DestinationPath "$bootstrapRoot\\Modules" -Force
Import-Module "$bootstrapRoot\\Modules\\AWS.Tools.S3\\AWS.Tools.S3.psd1"

Read-S3Object -BucketName $bucketName -Key $configKey -File "$bootstrapRoot\\Config.json"
Read-S3Object -BucketName $bucketName -Key $bootstrapZipKey -File "$bootstrapRoot\\bootstrap.zip"
Expand-Archive -Path "$bootstrapRoot\\bootstrap.zip" -DestinationPath $bootstrapRoot -Force

& "$bootstrapRoot\\Bootstrap.ps1"
</powershell>
```

Encode before launching EC2:

```powershell
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($UserDataScript))
```

---

## ✅ Bootstrap.ps1 (S3 Script Entry Point)

```powershell
$config = Get-Content "$PSScriptRoot\\Config.json" | ConvertFrom-Json

. "$PSScriptRoot\\Modules\\Rename-Computer.ps1"
Rename-ComputerSafely -NewName $config.ComputerName

. "$PSScriptRoot\\Modules\\Set-Network.ps1"
Set-StaticIP -IPAddress $config.IPAddress -DNS $config.DNS -Gateway $config.Gateway

. "$PSScriptRoot\\Modules\\Join-Domain.ps1"
Join-DomainSafely -Domain $config.Domain -OU $config.OU

New-Item "C:\\Bootstrap\\RunSQL.flag" -Force | Out-Null
Restart-Computer -Force
```

---

## ✅ Startup.ps1 (Post-reboot)

```powershell
if (Test-Path "C:\\Bootstrap\\RunSQL.flag") {
    Remove-Item "C:\\Bootstrap\\RunSQL.flag"
    $config = Get-Content "C:\\Bootstrap\\Config.json" | ConvertFrom-Json

    if ($config.SQLInstall) {
        . "C:\\Bootstrap\\Modules\\Install-SQL.ps1"
        Install-SQLFromConfig -Config $config
    }
}
```

---

## ✅ Install-SQL.ps1 (Module)

```powershell
function Install-SQLFromConfig {
    param ($Config)

    $bucketName = "my-bucket"
    $sqlMediaLocal = "C:\\Bootstrap\\Assets\\SQL.iso"
    $sqlConfigLocal = "C:\\Bootstrap\\Assets\\ConfigurationFile.ini"

    $mediaKey = $Config.SQLMediaUrl -replace "^s3://$bucketName/", ""
    $iniKey   = $Config.SQLConfigUrl -replace "^s3://$bucketName/", ""

    Read-S3Object -BucketName $bucketName -Key $mediaKey -File $sqlMediaLocal
    Read-S3Object -BucketName $bucketName -Key $iniKey -File $sqlConfigLocal

    Mount-DiskImage -ImagePath $sqlMediaLocal
    $drive = (Get-Volume -FileSystemLabel "SQL2019").DriveLetter
    Start-Process "$drive`:\\setup.exe" -ArgumentList "/ConfigurationFile=$sqlConfigLocal /IAcceptSQLServerLicenseTerms /Q" -Wait
}
```

---

## ✅ Optional Bootstrap Enhancements

* Configure Windows Updates
* Configure RDP access or jumpbox routing
* Enable WinRM for Ansible/Chef/Puppet
* Configure file shares / DFS
* Pull certs or secrets via AWS SSM Parameter Store
* Set timezone and region settings
* Enable Windows features (IIS, .NET, etc)

---

## ✅ Summary

| Component          | Approach                                        |
| ------------------ | ----------------------------------------------- |
| User Data          | Lightweight, calls downloaded scripts           |
| Config             | JSON per instance, Excel-driven                 |
| Modules            | In `bootstrap.zip`, hosted in S3                |
| SQL Install        | Post-reboot, config-driven                      |
| AWS Tools          | Pre-zipped, loaded from S3                      |
| No Internet Needed | Yes (as long as EC2 has S3 VPC endpoint access) |

This approach gives you a scalable, modular, declarative system to deploy Windows EC2s cleanly with full lifecycle control.

---

Let me know if you'd like me to auto-generate the base `bootstrap.zip` layout and script boilerplate next.
