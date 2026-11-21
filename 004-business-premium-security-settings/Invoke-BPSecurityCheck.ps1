<#
.SYNOPSIS
    Checks the Microsoft 365 Business Premium security settings from the video and
    optionally fixes the four tenant-wide quick wins.

.DESCRIPTION
    Report mode is the default: the script reads your tenant and prints a pass or
    fix list. It changes nothing.

    With -Apply it fixes only these four settings, and only where they are not
    already correct (safe to re-run):
      1. Unified audit log ingestion turned on
      2. Automatic external email forwarding turned off in the default outbound policy
      3. DKIM signing enabled for custom domains that already have a DKIM config
      4. User consent to apps limited to verified publishers, low-risk permissions
    -Apply honors -WhatIf and -Confirm, so preview first.

    Conditional Access, preset security policies, Intune and Defender settings are
    reported only, because they need a human decision and a report-only rollout.

    Demo tenant: harborlane.example (fictional company used on the channel).
    Requires Microsoft 365 Business Premium (Entra ID P1, Intune, Defender for
    Business, Defender for Office 365 Plan 1).
    Roles: Global Reader for report mode. Exchange Administrator plus Privileged
    Role Administrator (or Global Administrator) for -Apply.

.PARAMETER Apply
    Fix the four quick wins listed above. Without this switch the script only reports.

.PARAMETER CsvPath
    Optional path to save the results as CSV.

.EXAMPLE
    .\Invoke-BPSecurityCheck.ps1
    .\Invoke-BPSecurityCheck.ps1 -CsvPath .\bp-check.csv
    .\Invoke-BPSecurityCheck.ps1 -Apply -WhatIf
    .\Invoke-BPSecurityCheck.ps1 -Apply
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Apply,
    [string]$CsvPath
)

$ErrorActionPreference = 'Stop'

foreach ($m in @('Microsoft.Graph.Authentication', 'ExchangeOnlineManagement')) {
    if (-not (Get-Module -ListAvailable -Name $m)) {
        Write-Host "Installing $m..."
        Install-Module -Name $m -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module -Name $m
}

$scopes = @(
    'Policy.Read.All',
    'DeviceManagementConfiguration.Read.All',
    'DeviceManagementManagedDevices.Read.All',
    'SecurityEvents.Read.All'
)
if ($Apply) { $scopes += 'Policy.ReadWrite.Authorization' }
Connect-MgGraph -Scopes $scopes -NoWelcome
Connect-ExchangeOnline -ShowBanner:$false

$results = [System.Collections.Generic.List[object]]::new()
function Add-Result {
    param([string]$Area, [string]$Check, [bool]$Pass, [string]$Detail, [string]$Fix)
    $results.Add([pscustomobject]@{
        Area   = $Area
        Check  = $Check
        Status = if ($Pass) { 'PASS' } else { 'FIX' }
        Detail = $Detail
        HowToFix = if ($Pass) { '' } else { $Fix }
    })
}

function Get-AllPages {
    param([string]$Uri)
    $items = [System.Collections.Generic.List[object]]::new()
    while ($Uri) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType HashTable
        foreach ($i in $page['value']) { $items.Add($i) }
        $Uri = $page['@odata.nextLink']
    }
    return $items
}

# ---------- Identity (Entra ID P1) ----------
$secDefaults = Invoke-MgGraphRequest -Method GET -OutputType HashTable `
    -Uri 'v1.0/policies/identitySecurityDefaultsEnforcementPolicy'
$caPolicies = Get-AllPages -Uri 'v1.0/identity/conditionalAccess/policies'
$enabledCa = @($caPolicies | Where-Object { $_['state'] -eq 'enabled' })

if ($secDefaults['isEnabled']) {
    Add-Result 'Identity' 'Security defaults or Conditional Access' $true `
        'Security defaults are on. Move to Conditional Access when you are ready for exclusions and named locations.' ''
} else {
    Add-Result 'Identity' 'Security defaults or Conditional Access' ($enabledCa.Count -gt 0) `
        "Security defaults off. Enabled Conditional Access policies: $($enabledCa.Count)." `
        'Turn security defaults back on, or deploy Conditional Access baseline policies.'
}

$mfaAll = $enabledCa | Where-Object {
    (@($_['conditions']['users']['includeUsers']) -contains 'All') -and
    ((@($_['grantControls']['builtInControls']) -contains 'mfa') -or $_['grantControls']['authenticationStrength'])
}
Add-Result 'Identity' 'MFA required for all users' ($secDefaults['isEnabled'] -or @($mfaAll).Count -gt 0) `
    "Enabled policies requiring MFA for All users: $(@($mfaAll).Count)" `
    'Create a Conditional Access policy: All users, All resources, require MFA. Start in report-only.'

$legacyBlock = $enabledCa | Where-Object {
    $types = @($_['conditions']['clientAppTypes'])
    ($types -contains 'exchangeActiveSync' -or $types -contains 'other') -and
    (@($_['grantControls']['builtInControls']) -contains 'block')
}
Add-Result 'Identity' 'Legacy authentication blocked' ($secDefaults['isEnabled'] -or @($legacyBlock).Count -gt 0) `
    "Enabled policies blocking legacy auth: $(@($legacyBlock).Count)" `
    'Create a Conditional Access policy that blocks Exchange ActiveSync and other clients. Report-only first.'

$authz = Invoke-MgGraphRequest -Method GET -OutputType HashTable -Uri 'v1.0/policies/authorizationPolicy'
$grants = @($authz['defaultUserRolePermissions']['permissionGrantPoliciesAssigned'])
$consentOk = -not ($grants | Where-Object { $_ -like '*microsoft-user-default-legacy*' })
Add-Result 'Identity' 'User consent to apps limited' $consentOk `
    "Assigned consent policies: $(if ($grants) { $grants -join ', ' } else { 'none (consent disabled)' })" `
    'Run with -Apply, or set Enterprise apps > Consent and permissions to verified publishers only.'

# ---------- Email (Defender for Office 365 Plan 1) ----------
$audit = Get-AdminAuditLogConfig
Add-Result 'Email' 'Unified audit log on' ([bool]$audit.UnifiedAuditLogIngestionEnabled) `
    "UnifiedAuditLogIngestionEnabled: $($audit.UnifiedAuditLogIngestionEnabled)" 'Run with -Apply.'

$outbound = Get-HostedOutboundSpamFilterPolicy -Identity Default
$forwardOk = $outbound.AutoForwardingMode -ne 'On'
Add-Result 'Email' 'External auto-forwarding off' $forwardOk `
    "Default outbound policy AutoForwardingMode: $($outbound.AutoForwardingMode)" 'Run with -Apply.'

$dkim = @(Get-DkimSigningConfig | Where-Object { $_.Domain -notmatch 'onmicrosoft\.com$' })
$dkimOff = @($dkim | Where-Object { -not $_.Enabled })
Add-Result 'Email' 'DKIM signing on for custom domains' ($dkim.Count -gt 0 -and $dkimOff.Count -eq 0) `
    "Custom domains with DKIM config: $($dkim.Count). Disabled: $($dkimOff.Count)" `
    'Publish the two DKIM CNAME records at your DNS host, then run with -Apply.'

foreach ($preset in @('Standard Preset Security Policy', 'Strict Preset Security Policy')) {
    $eop = Get-EOPProtectionPolicyRule -Identity $preset -ErrorAction SilentlyContinue
    $atp = Get-ATPProtectionPolicyRule -Identity $preset -ErrorAction SilentlyContinue
    $on = ($eop -and $eop.State -eq 'Enabled') -and ($atp -and $atp.State -eq 'Enabled')
    if ($preset -like 'Standard*') {
        Add-Result 'Email' 'Standard preset security policy on' $on `
            "EOP rule: $(if ($eop) { $eop.State } else { 'not created' }). Defender rule: $(if ($atp) { $atp.State } else { 'not created' })" `
            'Defender portal > Email and collaboration > Policies > Preset security policies > Standard: turn on for all recipients.'
    } else {
        Write-Verbose "Strict preset: EOP $($eop.State), Defender $($atp.State)"
    }
}

# ---------- Devices (Intune and Defender for Business) ----------
$compliance = Get-AllPages -Uri 'v1.0/deviceManagement/deviceCompliancePolicies?$select=id,displayName'
Add-Result 'Devices' 'Device compliance policies exist' ($compliance.Count -gt 0) `
    "Compliance policies: $($compliance.Count)" 'Intune > Devices > Compliance: create a Windows policy that requires BitLocker and Defender.'

$windows = Get-AllPages -Uri "v1.0/deviceManagement/managedDevices?`$filter=operatingSystem eq 'Windows'&`$select=deviceName,isEncrypted,complianceState"
$unencrypted = @($windows | Where-Object { -not $_['isEncrypted'] })
Add-Result 'Devices' 'Windows devices encrypted' ($windows.Count -gt 0 -and $unencrypted.Count -eq 0) `
    "Managed Windows devices: $($windows.Count). Not encrypted: $($unencrypted.Count)" `
    'Intune > Endpoint security > Disk encryption: BitLocker policy for all Windows devices.'

$nonCompliant = @($windows | Where-Object { $_['complianceState'] -ne 'compliant' })
Add-Result 'Devices' 'Windows devices compliant' ($windows.Count -gt 0 -and $nonCompliant.Count -eq 0) `
    "Not compliant: $($nonCompliant.Count)" 'Check Intune > Devices > Monitor > Noncompliant devices.'

# ---------- Score ----------
$score = Invoke-MgGraphRequest -Method GET -OutputType HashTable -Uri 'v1.0/security/secureScores?$top=1'
$latest = @($score['value'])[0]
if ($latest) {
    $pct = [math]::Round(100 * $latest['currentScore'] / [math]::Max(1, $latest['maxScore']), 0)
    Write-Host "Microsoft Secure Score: $pct% ($($latest['currentScore']) of $($latest['maxScore']))" -ForegroundColor Cyan
}

$results | Format-Table Area, Check, Status, Detail -AutoSize -Wrap
if ($CsvPath) {
    $results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "Saved: $CsvPath"
}
$toFix = @($results | Where-Object Status -eq 'FIX')
Write-Host "Checks: $($results.Count). Need attention: $($toFix.Count)."

if (-not $Apply) {
    Write-Host 'Report mode: nothing changed. Re-run with -Apply -WhatIf to preview the quick wins.' -ForegroundColor Yellow
    Disconnect-ExchangeOnline -Confirm:$false
    Disconnect-MgGraph | Out-Null
    return
}

# ---------- Apply: four quick wins, idempotent ----------
if (-not $audit.UnifiedAuditLogIngestionEnabled) {
    if ($PSCmdlet.ShouldProcess('Tenant', 'Turn on unified audit log ingestion')) {
        Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
        Write-Host 'Unified audit log: on (can take up to an hour to start recording).' -ForegroundColor Green
    }
}

if (-not $forwardOk) {
    if ($PSCmdlet.ShouldProcess('Default outbound spam policy', 'Set AutoForwardingMode to Off')) {
        Set-HostedOutboundSpamFilterPolicy -Identity Default -AutoForwardingMode Off
        Write-Host 'External auto-forwarding: off.' -ForegroundColor Green
    }
}

foreach ($d in $dkimOff) {
    if ($PSCmdlet.ShouldProcess($d.Domain, 'Enable DKIM signing')) {
        try {
            Set-DkimSigningConfig -Identity $d.Identity -Enabled $true
            Write-Host "DKIM enabled: $($d.Domain)" -ForegroundColor Green
        } catch {
            Write-Warning "DKIM not enabled for $($d.Domain). Publish the CNAME records first. $($_.Exception.Message)"
        }
    }
}

if (-not $consentOk) {
    $body = @{
        defaultUserRolePermissions = @{
            permissionGrantPoliciesAssigned = @('ManagePermissionGrantsForSelf.microsoft-user-default-low')
        }
    } | ConvertTo-Json -Depth 5
    if ($PSCmdlet.ShouldProcess('Authorization policy', 'Limit user consent to verified publishers, low-risk permissions')) {
        Invoke-MgGraphRequest -Method PATCH -Uri 'v1.0/policies/authorizationPolicy' `
            -Body $body -ContentType 'application/json' | Out-Null
        Write-Host 'User consent: verified publishers, low-risk permissions only.' -ForegroundColor Green
    }
}

Write-Host "`nDone. Re-run without -Apply to confirm every quick win shows PASS."
Disconnect-ExchangeOnline -Confirm:$false
Disconnect-MgGraph | Out-Null
