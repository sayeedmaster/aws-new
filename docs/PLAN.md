# Plan: Excel Template and Script Changes for EC2 Launch (Dedicated Host & Robust Inputs)

## 1) Scope & Goals
- Enable placement on Dedicated Hosts and Dedicated Tenancy from Excel.
- Normalize/clarify Excel inputs (tags, booleans, SR-IOV) for reliable launches.
- Keep backwards compatibility: if new columns are blank, behavior remains unchanged.

## 2) Excel Template Changes (EC2_Instances sheet)
- Add columns (optional unless stated):
  - Tenancy: `default|dedicated|host`
  - HostId: Required when `Tenancy=host` (e.g., `h-0abcd1234ef567890`)
  - Affinity: Optional `default|host` (only relevant for host tenancy)
- Tags format:
  - Preferred delimiter is comma: `Env=Prod,Owner=TeamX`
  - We will update the script to accept both comma and semicolon (`[,;]`). No data change strictly required, but recommend migrating to commas for consistency.
- Booleans normalization:
  - Columns affected: `AssociatePublicIpAddress`, `Encrypted`, `EbsOptimized`, `Monitoring`, `InstanceMetadataTags`, `DisableApiTermination`, `EnaSupport`.
  - Accept values: true/false, yes/no, y/n, 1/0 (case-insensitive). Excel may display TRUE/FALSE; both are accepted after changes.
- SR-IOV value:
  - Use `simple` to enable (leave blank to skip). Any other value will be ignored with a warning.
- AvailabilityZone:
  - Keep the column; it will be validated against the chosen `SubnetId` AZ. Note: AZ does not override subnet placement; the subnet dictates AZ.

## 3) Script Changes (Launch-EC2FromExcel.ps1)

### 3.1 Placement / Dedicated Host Support
- Preflight validation (inside `Invoke-PreflightChecks` after subnet is retrieved):
  - If `Tenancy=host`:
    - Require `HostId` or error.
    - Describe host and validate it exists and is available in the region.
    - Validate Host AZ matches Subnet AZ; error if mismatch.
  - If `Tenancy=dedicated`: no `HostId` required.
  - If `AvailabilityZone` provided in Excel: validate it equals the Subnet AZ; error on mismatch.
- Launch parameters (when building `@launchParams`):
  - Set `Placement_Tenancy = $config.Tenancy` when provided.
  - If `Tenancy=host`: set `Placement_HostId = $config.HostId`.
  - If `Affinity` provided: set `Placement_Affinity = $config.Affinity`.
  - If `AvailabilityZone` provided (and matches subnet): set `Placement_AvailabilityZone = $config.AvailabilityZone`.

Touchpoints:
- Preflight placement checks around existing subnet validation block.
- Launch params assembly block where `@launchParams` is built.

### 3.2 Tag Parsing (comma or semicolon)
- Change tag split from `-split ','` to `-split '[,;]'` and trim. Invalid pairs still logged and skipped.

### 3.3 Boolean Normalization
- Add helper `Convert-ToBoolean` near `Convert-ToNormalizedString` to accept diverse truthy/falsey inputs.
- Use it for: `Monitoring`, `InstanceMetadataTags`, `DisableApiTermination`, `EnaSupport`, `EbsOptimized`.
- Optionally use boolean for `AssociatePublicIpAddress` on network interface after normalizing.

### 3.4 SR-IOV Value Normalization
- Normalize `SriovNetSupport`:
  - Accept `simple` (enable); treat `none`/empty as not set (skip applying).
  - Warn and skip for any other value.
- Keep existing compatibility checks against the SR-IOV capable instance types list.

## 4) Implementation Steps (sequenced)
1. Add `Convert-ToBoolean` helper near the existing helpers at the top of the script.
2. Update `Invoke-PreflightChecks`:
   - After subnet info is available, add host/tenancy validations.
   - Validate `AvailabilityZone` (if provided) == subnet AZ.
   - Normalize/validate `SriovNetSupport` value (map to `simple` or clear).
3. Update tag parsing to split on `[ , ; ]` when building tags.
4. Replace string comparisons like `-eq 'true'` with `Convert-ToBoolean(...)` for all applicable flags.
5. In the launch params section, add `Placement_*` assignments based on Excel inputs.
6. Ensure logging covers new validation and placement decisions.

Approximate insertion points (for reference only):
- Helpers: near top of `Launch-EC2FromExcel.ps1` (after `Convert-ToNormalizedString`).
- Preflight checks: within `Invoke-PreflightChecks` after subnet retrieval and before security-group checks.
- Launch params: where `@{ ImageId ... }` is built and just after NIC configuration.
- Tag parsing: within the existing tags block where `$config.Tags` is processed.

File references to guide editing:
- Launch-EC2FromExcel.ps1:711 (launch params creation starts)
- Launch-EC2FromExcel.ps1:736 (NIC assembly ends; good spot for Placement_*)
- Launch-EC2FromExcel.ps1:820 (tags parsing loop)
- Launch-EC2FromExcel.ps1:450–560 (preflight instance/AMI/type checks; subnet context is available)

## 5) Backwards Compatibility
- New columns are optional; leaving them blank keeps current behavior.
- Tag parsing will accept both commas and semicolons (existing data continues to work).
- Boolean normalization expands accepted inputs; existing exact `true` values still work.
- SR-IOV left blank continues to skip; `none` will be treated as blank with a warning.

## 6) Testing & Validation
- Dry Run tests (no AWS changes):
  - Valid `Tenancy=host` with `HostId` and matching subnet AZ → simulates Placement_* set.
  - `Tenancy=host` without `HostId` → fails preflight.
  - Mismatched `AvailabilityZone` vs subnet AZ → fails preflight.
  - Tag parsing with semicolons and commas → both parsed into multiple tags.
  - Booleans provided as YES/No/1/0/True/FALSE across affected fields → normalized correctly.
- Live tests (single small instance):
  - `Tenancy=dedicated` launch in test account.
  - `Tenancy=host` launch to a known host with capacity; verify instance placement and tags.
- Excel update: verify `InstanceId` is written post-launch (non-dry run), or simulated log in dry run.

## 7) Permissions & Dependencies
- IAM permissions likely needed in the SSO role:
  - `ec2:RunInstances`, `ec2:DescribeHosts`, `ec2:DescribeSubnets`, `ec2:DescribeSecurityGroups`, `ec2:DescribeNetworkInterfaces`,
  - `ec2:StopInstances`, `ec2:StartInstances`, `ec2:ModifyInstanceAttribute` (for SR-IOV),
  - `iam:GetInstanceProfile`, `ec2:DescribeImages`, `ec2:CreateKeyPair`, `kms:DescribeKey` (if KMS keys used).
- Module requirements unchanged: `AWS.Tools.*` and `ImportExcel` via `-PSModulesPath`.

## 8) Rollout & Docs
- Update README or add a short usage section describing new columns and accepted values.
- Provide a revised example row in `_backup/EC2_Config.xlsx` once ready (optional follow-up).

## 9) Example Snippets (to be applied during implementation)

Boolean helper:
```powershell
function Convert-ToBoolean {
    param($Value)
    if ($Value -is [bool]) { return $Value }
    $s = ($Value | Out-String).Trim().ToLower()
    switch ($s) {
        'true' { return $true }
        'yes' { return $true }
        'y' { return $true }
        '1' { return $true }
        'false' { return $false }
        'no' { return $false }
        'n' { return $false }
        '0' { return $false }
        default { return [bool]$Value }
    }
}
```

Placement in launch params:
```powershell
if ($config.Tenancy) { $launchParams.Placement_Tenancy = $config.Tenancy }
if ($config.Tenancy -and $config.Tenancy.ToLower() -eq 'host' -and $config.HostId) {
    $launchParams.Placement_HostId = $config.HostId
}
if ($config.Affinity) { $launchParams.Placement_Affinity = $config.Affinity }
if ($config.AvailabilityZone) { $launchParams.Placement_AvailabilityZone = $config.AvailabilityZone }
```

Tags parsing:
```powershell
$tagPairs = $config.Tags -split '[,;]' | ForEach-Object { $_.Trim() }
```

SR-IOV normalization (preflight):
```powershell
if ($Config.SriovNetSupport) {
    $val = ($Config.SriovNetSupport | Out-String).Trim().ToLower()
    if ($val -eq 'simple') { $Config.SriovNetSupport = 'simple' }
    elseif ([string]::IsNullOrWhiteSpace($val) -or $val -eq 'none') { $Config.SriovNetSupport = $null }
    else { Write-Log "Unsupported SriovNetSupport value '$($Config.SriovNetSupport)'. Skipping." 'WARN'; $Config.SriovNetSupport = $null }
}
```

Host/tenancy checks (preflight, after subnet):
```powershell
if ($Config.Tenancy) {
    $ten = $Config.Tenancy.ToLower()
    if ($ten -eq 'host') {
        if (-not $Config.HostId) { Write-Log "Tenancy=host requires HostId." 'ERROR'; return @{ Success = $false } }
        if (-not $DryRun) {
            $host = Get-EC2Host -ProfileName $ProfileName -Region $Region -HostId $Config.HostId -ErrorAction Stop
            if (-not $host) { Write-Log "HostId '$($Config.HostId)' not found." 'ERROR'; return @{ Success = $false } }
            $hostAz = $host.AvailabilityZone
            $subnetAz = $subnetInfo.AvailabilityZone
            if ($hostAz -and $subnetAz -and ($hostAz -ne $subnetAz)) {
                Write-Log "Host AZ ($hostAz) != Subnet AZ ($subnetAz)." 'ERROR'; return @{ Success = $false }
            }
        } else { Write-Log "Dry run: assume host $($Config.HostId) exists & AZ matches subnet." 'INFO' }
    }
}
if ($Config.AvailabilityZone) {
    $subnetAz = $subnetInfo.AvailabilityZone
    if ($subnetAz -and ($Config.AvailabilityZone -ne $subnetAz)) {
        Write-Log "AvailabilityZone '$($Config.AvailabilityZone)' does not match subnet AZ '$subnetAz'." 'ERROR'; return @{ Success = $false }
    }
}
```

---
Owner: Sayeed Master
Proposed version after changes: 5.1.0
Notes: No changes required to `config.json`; optional future enhancement to include allowed Tenancy/Affinity values.

