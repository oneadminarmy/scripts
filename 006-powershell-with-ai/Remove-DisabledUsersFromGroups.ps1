<#
.SYNOPSIS
    Finds disabled user accounts that are still members of security groups, and removes them.

.DESCRIPTION
    Report-only by default: nothing changes unless you add -Apply.
    Use -Apply -WhatIf to preview exactly which memberships would be removed.

    Reads every page of results from Microsoft Graph, so tenants of any size are fully checked,
    and asks Graph for accountEnabled explicitly, because it is not returned by default.

    Groups it skips (and says why):
      - dynamic groups (membership comes from a rule)
      - groups synced from on-premises Active Directory
      - mail-enabled security groups (managed in Exchange Online)
      - role-assignable groups (need extra admin permissions; review these by hand)

    Running it again is safe: memberships already removed are simply not found.

    From the One Admin Army video "Write PowerShell With AI Without Breaking Production".
    Test in a lab tenant first. Run with -WhatIf before making changes.

.PARAMETER GroupName
    One or more group display names to check. If omitted, every security group is checked.

.PARAMETER Apply
    Remove the disabled members. Without it the script only reports.

.PARAMETER ReportPath
    Where to save the CSV report.

.EXAMPLE
    .\Remove-DisabledUsersFromGroups.ps1
    Report every disabled account that is still in a security group. Changes nothing.

.EXAMPLE
    .\Remove-DisabledUsersFromGroups.ps1 -GroupName 'SG-Warehouse' -Apply -WhatIf
    Preview the removals for one group.

.EXAMPLE
    .\Remove-DisabledUsersFromGroups.ps1 -GroupName 'SG-Warehouse' -Apply
    Remove disabled accounts from one group.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [string[]]$GroupName,

    [switch]$Apply,

    [string]$ReportPath = (Join-Path (Get-Location) ("DisabledGroupMembers-{0}.csv" -f (Get-Date -Format 'yyyy-MM-dd')))
)

$ErrorActionPreference = 'Stop'

# Module check: only the Graph authentication module is needed.
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    Write-Verbose 'Installing Microsoft.Graph.Authentication for the current user'
    Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -WhatIf:$false
}
Import-Module Microsoft.Graph.Authentication

# Least privilege: read-only unless -Apply is used.
$scopes = if ($Apply) { @('GroupMember.ReadWrite.All', 'User.Read.All') } else { @('GroupMember.Read.All', 'User.Read.All') }
Connect-MgGraph -Scopes $scopes -NoWelcome

function Get-GraphPage {
    # Follows @odata.nextLink until every page has been read.
    param([Parameter(Mandatory)][string]$Uri)
    $WhatIfPreference = $false   # reads always run, even in a -WhatIf preview
    $next = $Uri
    while ($next) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject
        foreach ($item in $page.value) { $item }
        $next = $page.'@odata.nextLink'
    }
}

$select = 'id,displayName,groupTypes,securityEnabled,mailEnabled,onPremisesSyncEnabled,isAssignableToRole'

if ($GroupName) {
    $groups = foreach ($name in $GroupName) {
        $filter = [uri]::EscapeDataString("displayName eq '$($name.Replace("'", "''"))'")
        $found = @(Get-GraphPage -Uri "v1.0/groups?`$filter=$filter&`$select=$select")
        if ($found.Count -eq 0) { Write-Warning "Group not found: $name" }
        $found
    }
}
else {
    $filter = [uri]::EscapeDataString('securityEnabled eq true')
    $groups = Get-GraphPage -Uri "v1.0/groups?`$filter=$filter&`$select=$select&`$top=999"
}
$groups = @($groups)

$rows = foreach ($g in $groups) {
    $skip = $null
    if ($g.groupTypes -contains 'DynamicMembership') { $skip = 'dynamic group, fix the membership rule instead' }
    elseif ($g.onPremisesSyncEnabled) { $skip = 'synced from on-premises AD, change it there' }
    elseif ($g.mailEnabled -and -not ($g.groupTypes -contains 'Unified')) { $skip = 'mail-enabled, change it in Exchange Online' }
    elseif ($g.isAssignableToRole) { $skip = 'role-assignable, review by hand' }

    $members = Get-GraphPage -Uri "v1.0/groups/$($g.id)/members/microsoft.graph.user?`$select=id,displayName,userPrincipalName,accountEnabled"

    # Compare with -eq $false on purpose: a missing value ($null) must never count as disabled.
    foreach ($m in @($members | Where-Object { $_.accountEnabled -eq $false })) {
        [pscustomobject]@{
            Group             = $g.displayName
            User              = $m.displayName
            UserPrincipalName = $m.userPrincipalName
            Action            = if ($skip) { "Skipped: $skip" } else { 'Remove' }
            GroupId           = $g.id
            UserId            = $m.id
        }
    }
}
$rows = @($rows)

if ($Apply) {
    foreach ($r in $rows | Where-Object Action -eq 'Remove') {
        if ($PSCmdlet.ShouldProcess("$($r.UserPrincipalName) in group $($r.Group)", 'Remove group member')) {
            try {
                Invoke-MgGraphRequest -Method DELETE -Uri "v1.0/groups/$($r.GroupId)/members/$($r.UserId)/`$ref"
                $r.Action = 'Removed'
            }
            catch {
                $r.Action = "Failed: $($_.Exception.Message)"
                Write-Warning "Could not remove $($r.UserPrincipalName) from $($r.Group): $($_.Exception.Message)"
            }
        }
    }
}

$rows | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding utf8 -WhatIf:$false

Write-Output ("Groups checked: {0}" -f $groups.Count)
Write-Output ("Disabled memberships found: {0}" -f $rows.Count)
if ($rows.Count -gt 0) {
    foreach ($bucket in @($rows | Group-Object Action)) {
        Write-Output ("  {0}: {1}" -f $bucket.Name, $bucket.Count)
    }
}
if (-not $Apply) {
    Write-Output 'Report only. Nothing was changed. Add -Apply -WhatIf to preview removals.'
}
Write-Output "Full report: $ReportPath"
