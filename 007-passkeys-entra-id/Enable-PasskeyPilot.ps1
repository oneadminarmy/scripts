<#
.SYNOPSIS
    Turns on the Passkey (FIDO2) method in Microsoft Entra ID for one pilot group.

.DESCRIPTION
    Preview by default: shows the current settings and exactly what would change, and changes nothing.
    Add -Apply to make the change, and -Apply -WhatIf to see the final confirmation step without saving.

    What it changes (only if needed, so it is safe to run again):
      - Passkey (FIDO2) method state: enabled
      - "Allow self-service set up": Yes (users need this to register)
      - Adds the pilot group to the method's targets, keeping every existing target

    What it never changes: attestation, key restrictions, passkey profile settings, excluded groups.
    Configure passkey profiles in the Entra admin center as shown in the video.

    If your tenant has passkey profiles, the group is assigned the profile named in -ProfileName,
    or, if you leave it out, the profile already used by the "All users" target, else the first profile.

    Needs the Authentication Policy Administrator role (or higher). Works on every Entra ID edition.

    From the One Admin Army video "Passkeys in Entra ID: Full Setup".
    Test in a lab tenant first. Run with -WhatIf before making changes.

.PARAMETER GroupName
    Display name of the pilot group, for example 'SG-MFA-Migration'.

.PARAMETER ProfileName
    Optional passkey profile to assign to the pilot group.

.PARAMETER Apply
    Save the change. Without it the script only previews.

.EXAMPLE
    .\Enable-PasskeyPilot.ps1 -GroupName 'SG-MFA-Migration'
    Preview only.

.EXAMPLE
    .\Enable-PasskeyPilot.ps1 -GroupName 'SG-MFA-Migration' -ProfileName 'Staff passkeys' -Apply -WhatIf

.EXAMPLE
    .\Enable-PasskeyPilot.ps1 -GroupName 'SG-MFA-Migration' -ProfileName 'Staff passkeys' -Apply
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [string]$GroupName,

    [string]$ProfileName,

    [switch]$Apply
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    Write-Verbose 'Installing Microsoft.Graph.Authentication for the current user'
    Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -WhatIf:$false
}
Import-Module Microsoft.Graph.Authentication

$scopes = if ($Apply) { @('Policy.ReadWrite.AuthenticationMethod', 'Group.Read.All') } else { @('Policy.Read.All', 'Group.Read.All') }
Connect-MgGraph -Scopes $scopes -NoWelcome

function Invoke-GraphGet {
    param([Parameter(Mandatory)][string]$Uri)
    $WhatIfPreference = $false   # reads always run, even in a -WhatIf preview
    Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject
}

$configUri = 'v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/fido2'

# Find the pilot group
$filter = [uri]::EscapeDataString("displayName eq '$($GroupName.Replace("'", "''"))'")
$groups = @((Invoke-GraphGet -Uri "v1.0/groups?`$filter=$filter&`$select=id,displayName,securityEnabled").value)
if ($groups.Count -eq 0) { throw "Group not found: $GroupName. Create it first and add your pilot users." }
if ($groups.Count -gt 1) { throw "More than one group is called $GroupName. Rename one so the name is unique." }
$group = $groups[0]

# Current configuration
$cfg = Invoke-GraphGet -Uri $configUri
$targets = @($cfg.includeTargets | Where-Object { $_ })
$profiles = @($cfg.passkeyProfiles | Where-Object { $_ })

Write-Output '=== Current Passkey (FIDO2) settings ==='
Write-Output ("State:              {0}" -f $cfg.state)
Write-Output ("Self-service setup: {0}" -f $cfg.isSelfServiceRegistrationAllowed)
Write-Output ("Targets:            {0}" -f (($targets | ForEach-Object { $_.id }) -join ', '))
if ($profiles.Count -gt 0) { Write-Output ("Passkey profiles:   {0}" -f (($profiles | ForEach-Object { $_.name }) -join ', ')) }

# Work out the plan
$plan = [System.Collections.Generic.List[string]]::new()
if ($cfg.state -ne 'enabled') { $plan.Add('Turn the Passkey (FIDO2) method on') }
if (-not $cfg.isSelfServiceRegistrationAllowed) { $plan.Add('Allow self-service set up') }

$allUsers = $targets | Where-Object { $_.id -eq 'all_users' } | Select-Object -First 1
$existing = $targets | Where-Object { $_.id -eq $group.id } | Select-Object -First 1
$addTarget = -not $existing -and -not $allUsers
if ($allUsers) { Write-Output 'Note: the method already targets All users, so the pilot group is already covered.' }
if ($existing) { Write-Output "Note: $($group.displayName) is already targeted." }

$profileId = $null
if ($addTarget -and $profiles.Count -gt 0) {
    $chosen = if ($ProfileName) {
        $profiles | Where-Object { $_.name -eq $ProfileName } | Select-Object -First 1
    }
    elseif ($allUsers -and $allUsers.allowedPasskeyProfiles) {
        $profiles | Where-Object { $_.id -in @($allUsers.allowedPasskeyProfiles) } | Select-Object -First 1
    }
    else { $profiles | Select-Object -First 1 }
    if (-not $chosen) { throw "Passkey profile not found: $ProfileName. Profiles: $(($profiles | ForEach-Object { $_.name }) -join ', ')" }
    $profileId = $chosen.id
    $plan.Add("Target group $($group.displayName) with passkey profile '$($chosen.name)'")
}
elseif ($addTarget) {
    $plan.Add("Target group $($group.displayName)")
}

Write-Output ''
if ($plan.Count -eq 0) {
    Write-Output 'Nothing to change. Passkeys are already on for this group.'
    return
}
Write-Output '=== Planned changes ==='
$plan | ForEach-Object { Write-Output "  - $_" }

if (-not $Apply) {
    Write-Output ''
    Write-Output 'Preview only. Nothing was changed. Add -Apply -WhatIf, then -Apply, to make these changes.'
    return
}

# Build the new target list: every existing target, plus the pilot group
$newTargets = foreach ($t in $targets) {
    $entry = @{ targetType = $t.targetType; id = $t.id; isRegistrationRequired = [bool]$t.isRegistrationRequired }
    if ($t.allowedPasskeyProfiles) { $entry.allowedPasskeyProfiles = @($t.allowedPasskeyProfiles) }
    $entry
}
$newTargets = @($newTargets)
if ($addTarget) {
    $entry = @{ targetType = 'group'; id = $group.id; isRegistrationRequired = $false }
    if ($profileId) { $entry.allowedPasskeyProfiles = @($profileId) }
    $newTargets += $entry
}

$body = @{
    '@odata.type'                    = '#microsoft.graph.fido2AuthenticationMethodConfiguration'
    state                            = 'enabled'
    isSelfServiceRegistrationAllowed = $true
    includeTargets                   = $newTargets
}

if ($PSCmdlet.ShouldProcess("Passkey (FIDO2) method, group $($group.displayName)", ($plan -join '; '))) {
    Invoke-MgGraphRequest -Method PATCH -Uri $configUri -Body ($body | ConvertTo-Json -Depth 6) -ContentType 'application/json'
    $after = Invoke-GraphGet -Uri $configUri
    Write-Output ''
    Write-Output ("Saved. State: {0}, self-service: {1}, targets: {2}" -f $after.state,
        $after.isSelfServiceRegistrationAllowed, @($after.includeTargets).Count)
}
