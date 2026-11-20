<#
.SYNOPSIS
    Finds Conditional Access policies that do not exclude your break-glass group, and fixes them.

.DESCRIPTION
    Report mode is the default: the script lists every policy that is missing the
    break-glass exclusion and changes nothing. Add -Apply to add the exclusion.
    -Apply also honors -WhatIf and -Confirm, so you can preview each change first.

    Only conditions.users.excludeGroups is changed. The policy state (On, Off or
    report-only), its assignments and its controls stay exactly as they are.
    Policies that already exclude the group are skipped, so it is safe to re-run.
    Microsoft-managed policies are skipped unless you pass -IncludeMicrosoftManaged.

    Demo tenant: harborlane.example (fictional company used on the channel).
    Requires Microsoft Entra ID P1 (included in Microsoft 365 Business Premium and E3).
    Graph permissions (delegated): Policy.Read.All, Group.Read.All, and with -Apply
    also Policy.ReadWrite.ConditionalAccess.

.PARAMETER BreakGlassGroupName
    Display name of the security group holding your emergency access accounts.

.PARAMETER Apply
    Add the exclusion to every policy that is missing it. Without this switch the
    script only reports.

.PARAMETER IncludeMicrosoftManaged
    Also check policies whose name starts with "Microsoft-managed".

.EXAMPLE
    .\Add-CABreakGlassExclusion.ps1 -BreakGlassGroupName 'SG-BreakGlass'
    .\Add-CABreakGlassExclusion.ps1 -BreakGlassGroupName 'SG-BreakGlass' -Apply -WhatIf
    .\Add-CABreakGlassExclusion.ps1 -BreakGlassGroupName 'SG-BreakGlass' -Apply
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$BreakGlassGroupName,

    [switch]$Apply,

    [switch]$IncludeMicrosoftManaged
)

$ErrorActionPreference = 'Stop'

foreach ($m in @('Microsoft.Graph.Authentication')) {
    if (-not (Get-Module -ListAvailable -Name $m)) {
        Write-Host "Installing $m..."
        Install-Module -Name $m -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module -Name $m
}

$scopes = @('Policy.Read.All', 'Group.Read.All')
if ($Apply) { $scopes += 'Policy.ReadWrite.ConditionalAccess' }
Connect-MgGraph -Scopes $scopes -NoWelcome

# Break-glass group (must exist and be unique)
$safeName = $BreakGlassGroupName.Replace("'", "''")
$groupPage = Invoke-MgGraphRequest -Method GET -OutputType HashTable `
    -Uri "v1.0/groups?`$filter=displayName eq '$safeName'&`$select=id,displayName"
$group = @($groupPage['value'])
if ($group.Count -ne 1) {
    throw "Break-glass group '$BreakGlassGroupName' not found or not unique (found $($group.Count))."
}
$breakGlassId = $group[0]['id']

# All policies, following paging
$policies = [System.Collections.Generic.List[object]]::new()
$uri = 'v1.0/identity/conditionalAccess/policies'
while ($uri) {
    $page = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType HashTable
    foreach ($p in $page['value']) { $policies.Add($p) }
    $uri = $page['@odata.nextLink']
}

$missing = foreach ($p in $policies) {
    if (-not $IncludeMicrosoftManaged -and $p['displayName'] -like 'Microsoft-managed*') { continue }
    $users = $p['conditions']['users']
    $excluded = @($users['excludeGroups'])
    if ($excluded -notcontains $breakGlassId) { $p }
}
$missing = @($missing)

Write-Host "Checked $($policies.Count) policies. Missing the break-glass exclusion: $($missing.Count)"
$missing | ForEach-Object {
    [pscustomobject]@{ Policy = $_['displayName']; State = $_['state'] }
} | Format-Table -AutoSize

if ($missing.Count -eq 0) {
    Write-Host 'Nothing to fix.' -ForegroundColor Green
    Disconnect-MgGraph | Out-Null
    return
}

if (-not $Apply) {
    Write-Host 'Report mode: nothing changed. Re-run with -Apply -WhatIf to preview the fix.' -ForegroundColor Yellow
    Disconnect-MgGraph | Out-Null
    return
}

foreach ($p in $missing) {
    # Send the complete users condition back with one group added, so nothing else changes
    $users = [ordered]@{}
    foreach ($k in $p['conditions']['users'].Keys) {
        if ($null -ne $p['conditions']['users'][$k]) { $users[$k] = $p['conditions']['users'][$k] }
    }
    $users['excludeGroups'] = @(@($p['conditions']['users']['excludeGroups']) + $breakGlassId | Where-Object { $_ })
    $body = @{ conditions = @{ users = $users } } | ConvertTo-Json -Depth 10

    if ($PSCmdlet.ShouldProcess($p['displayName'], "Exclude break-glass group '$BreakGlassGroupName'")) {
        Invoke-MgGraphRequest -Method PATCH -Uri "v1.0/identity/conditionalAccess/policies/$($p['id'])" `
            -Body $body -ContentType 'application/json' | Out-Null
        Write-Host "Updated: $($p['displayName'])" -ForegroundColor Green
    }
}

Write-Host "`nDone. Confirm in Entra admin center > Conditional Access > What If, using a break-glass account."
Disconnect-MgGraph | Out-Null
