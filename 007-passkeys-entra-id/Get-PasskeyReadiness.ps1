<#
.SYNOPSIS
    Read-only passkey readiness report for Microsoft Entra ID.

.DESCRIPTION
    Shows how the Passkey (FIDO2) authentication method is configured, then sorts users into:
      Passkey          at least one passkey registered
      AuthenticatorApp Microsoft Authenticator, but no passkey yet (easiest to move)
      PhoneOnly        only SMS or voice (most urgent)
      NoStrongMethod   password only, or nothing this report recognises

    It only reads. Nothing in the tenant changes. Works on every Entra ID edition, because it reads
    each user's methods directly instead of using the registration report (which needs Entra ID P1).

    From the One Admin Army video "Passkeys in Entra ID: Full Setup".
    Test in a lab tenant first. Run with -WhatIf before making changes.

.PARAMETER GroupName
    Only report on members of this group (for example your pilot group). Default: all enabled member users.

.PARAMETER ReportPath
    Where to save the per-user CSV. With -WhatIf the file is not written.

.EXAMPLE
    .\Get-PasskeyReadiness.ps1

.EXAMPLE
    .\Get-PasskeyReadiness.ps1 -GroupName 'SG-MFA-Migration'
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$GroupName,

    [string]$ReportPath = (Join-Path (Get-Location) ("PasskeyReadiness-{0}.csv" -f (Get-Date -Format 'yyyy-MM-dd')))
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    Write-Verbose 'Installing Microsoft.Graph.Authentication for the current user'
    Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -WhatIf:$false
}
Import-Module Microsoft.Graph.Authentication

# Read-only scopes
Connect-MgGraph -Scopes 'Policy.Read.All', 'UserAuthenticationMethod.Read.All', 'User.Read.All', 'GroupMember.Read.All' -NoWelcome

function Get-GraphPage {
    param([Parameter(Mandatory)][string]$Uri)
    $WhatIfPreference = $false
    $next = $Uri
    while ($next) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject
        foreach ($item in $page.value) { $item }
        $next = $page.'@odata.nextLink'
    }
}

function Invoke-GraphGet {
    param([Parameter(Mandatory)][string]$Uri)
    $WhatIfPreference = $false   # reads always run, even in a -WhatIf preview
    Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject
}

# 1. How is the passkey method configured?
$cfg = Invoke-GraphGet -Uri 'v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/fido2'

Write-Output '=== Passkey (FIDO2) method ==='
Write-Output ("State:                  {0}" -f $cfg.state)
Write-Output ("Self-service setup:     {0}" -f $cfg.isSelfServiceRegistrationAllowed)
Write-Output ("Attestation (global):   {0}" -f $cfg.isAttestationEnforced)
if ($cfg.keyRestrictions) {
    Write-Output ("Key restrictions:       enforced={0}, {1}, {2} AAGUID(s)" -f $cfg.keyRestrictions.isEnforced,
        $cfg.keyRestrictions.enforcementType, @($cfg.keyRestrictions.aaGuids).Count)
}
$profiles = @($cfg.passkeyProfiles | Where-Object { $_ })
if ($profiles.Count -gt 0) {
    Write-Output ("Passkey profiles:       {0}" -f $profiles.Count)
    foreach ($p in $profiles) {
        Write-Output ("  - {0}: types={1}, attestation={2}" -f $p.name, $p.passkeyTypes, $p.attestationEnforcement)
    }
}
foreach ($t in @($cfg.includeTargets)) {
    $label = $t.id
    if ($t.targetType -eq 'group' -and $t.id -ne 'all_users') {
        try { $label = (Invoke-GraphGet -Uri "v1.0/groups/$($t.id)?`$select=displayName").displayName }
        catch { $label = "$($t.id) (group not found)" }
    }
    Write-Output ("Targeted:               {0}" -f $label)
}
if ($cfg.state -ne 'enabled') { Write-Warning 'The passkey method is disabled. Nobody can register a passkey yet.' }

# 2. Which users?
$select = 'id,displayName,userPrincipalName,accountEnabled,userType'
if ($GroupName) {
    $filter = [uri]::EscapeDataString("displayName eq '$($GroupName.Replace("'", "''"))'")
    $group = @(Get-GraphPage -Uri "v1.0/groups?`$filter=$filter&`$select=id,displayName") | Select-Object -First 1
    if (-not $group) { throw "Group not found: $GroupName" }
    $users = Get-GraphPage -Uri "v1.0/groups/$($group.id)/members/microsoft.graph.user?`$select=$select"
}
else {
    $users = Get-GraphPage -Uri "v1.0/users?`$select=$select&`$top=999"
}
$users = @($users | Where-Object { $_.accountEnabled -eq $true -and $_.userType -eq 'Member' })

# 3. What has each user registered?
$rows = foreach ($u in $users) {
    $methods = @(Get-GraphPage -Uri "v1.0/users/$($u.id)/authentication/methods")
    $types = @($methods | ForEach-Object { ($_.'@odata.type' -replace '#microsoft.graph.', '') -replace 'AuthenticationMethod$', '' })
    $passkeys = @($methods | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.fido2AuthenticationMethod' })

    $bucket = if ($passkeys.Count -gt 0) { 'Passkey' }
    elseif ($types -contains 'microsoftAuthenticator') { 'AuthenticatorApp' }
    elseif ($types -contains 'phone') { 'PhoneOnly' }
    else { 'NoStrongMethod' }

    [pscustomobject]@{
        User              = $u.displayName
        UserPrincipalName = $u.userPrincipalName
        Bucket            = $bucket
        PasskeyModels     = ($passkeys | ForEach-Object { $_.model } | Where-Object { $_ }) -join '; '
        Methods           = ($types | Where-Object { $_ -ne 'password' } | Sort-Object -Unique) -join ', '
    }
}
$rows = @($rows)

Write-Output ''
Write-Output ("=== Users checked: {0} ===" -f $rows.Count)
foreach ($b in 'Passkey', 'AuthenticatorApp', 'PhoneOnly', 'NoStrongMethod') {
    Write-Output ("{0,-17} {1}" -f $b, @($rows | Where-Object Bucket -eq $b).Count)
}

if ($PSCmdlet.ShouldProcess($ReportPath, 'Write readiness CSV')) {
    $rows | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding utf8
    Write-Output "Full report: $ReportPath"
}
