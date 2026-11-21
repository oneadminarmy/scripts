<#
.SYNOPSIS
    Finds every user who still depends on SMS or voice MFA before Microsoft-provided
    SMS and voice MFA retires, and optionally adds them to a migration group.

.DESCRIPTION
    Report mode is the default: the script reads authentication method registration
    details from Microsoft Graph and sorts every user into one of three buckets:

      PhoneOnly     Only phone methods registered (SMS, voice, office phone).
                    These users get a blocking passkey registration prompt at
                    sign-in once the retirement reaches the tenant.
      PhoneDefault  Has a stronger method, but SMS or voice is the default.
                    Not blocked, but should be moved before the deadline.
      Ready         No phone dependency.

    It also flags Global Administrators with an active assignment, because the
    later retirement date only applies while that role is active.

    With -Apply and -AddToGroupName, it adds PhoneOnly and PhoneDefault member
    users to an existing security group (for a registration campaign or a
    staged rollout). Existing members are skipped, so it is safe to re-run.
    -Apply honors -WhatIf and -Confirm.

    Registration data can be up to 36 hours old. Disabled users are not listed.
    Cross-check the result with Microsoft's own SMS and voice usage analyzer.

    Demo tenant: harborlane.example (fictional company used on the channel).
    Requires Microsoft Entra ID P1 (Business Premium, E3) for registration reports.
    Graph permissions (delegated): AuditLog.Read.All, UserAuthenticationMethod.Read.All,
    RoleManagement.Read.Directory, and with -Apply also GroupMember.ReadWrite.All.

.PARAMETER CsvPath
    Where to save the full report. Default: .\SmsMfaUsers-<date>.csv

.PARAMETER AddToGroupName
    Display name of an existing security group to add PhoneOnly and PhoneDefault users to.

.PARAMETER Apply
    Actually add users to the group. Without this switch the script only reports.

.EXAMPLE
    .\Get-SmsMfaUsers.ps1
    .\Get-SmsMfaUsers.ps1 -AddToGroupName 'SG-MFA-Migration' -Apply -WhatIf
    .\Get-SmsMfaUsers.ps1 -AddToGroupName 'SG-MFA-Migration' -Apply
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$CsvPath = (Join-Path -Path (Get-Location) -ChildPath ("SmsMfaUsers-{0:yyyy-MM-dd}.csv" -f (Get-Date))),
    [string]$AddToGroupName,
    [switch]$Apply
)

$ErrorActionPreference = 'Stop'

if ($Apply -and -not $AddToGroupName) {
    throw '-Apply needs -AddToGroupName. Without a group there is nothing to change.'
}

foreach ($m in @('Microsoft.Graph.Authentication')) {
    if (-not (Get-Module -ListAvailable -Name $m)) {
        Write-Host "Installing $m..."
        Install-Module -Name $m -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module -Name $m
}

$scopes = @('AuditLog.Read.All', 'UserAuthenticationMethod.Read.All', 'RoleManagement.Read.Directory')
if ($Apply) { $scopes += 'GroupMember.ReadWrite.All' }
Connect-MgGraph -Scopes $scopes -NoWelcome

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

# Method names as returned in methodsRegistered and defaultMfaMethod
$phoneMethods  = @('mobilePhone', 'alternateMobilePhone', 'officePhone')
$strongPattern = 'authenticator|softwareOneTimePasscode|hardwareOneTimePasscode|windowsHelloForBusiness|fido2|passKey|macOsSecureEnclaveKey'
$phoneDefault  = 'phone|sms|voice'

# Active Global Administrators (eligible-only PIM users are not members until they activate)
$gaIds = @{}
$roles = Get-AllPages -Uri 'v1.0/directoryRoles?$select=id,displayName'
$ga = $roles | Where-Object { $_['displayName'] -eq 'Global Administrator' }
if ($ga) {
    foreach ($member in (Get-AllPages -Uri "v1.0/directoryRoles/$($ga['id'])/members?`$select=id")) {
        $gaIds[$member['id']] = $true
    }
}

Write-Host 'Reading registration details (this can take a minute in larger tenants)...'
$details = Get-AllPages -Uri 'v1.0/reports/authenticationMethods/userRegistrationDetails'

$report = foreach ($u in $details) {
    $methods = @($u['methodsRegistered'])
    $hasPhone  = [bool]($methods | Where-Object { $phoneMethods -contains $_ })
    $hasStrong = [bool]($methods | Where-Object { $_ -match $strongPattern })
    $default   = [string]$u['defaultMfaMethod']

    $bucket = if ($hasPhone -and -not $hasStrong) { 'PhoneOnly' }
              elseif ($hasPhone -and $default -match $phoneDefault) { 'PhoneDefault' }
              else { 'Ready' }

    $isGa = $gaIds.ContainsKey($u['id'])
    $deadline = if ($bucket -eq 'Ready') { '' }
                elseif ($isGa) { '2027-07-01 (active Global Admin)' }
                elseif ($u['userType'] -eq 'guest') { 'Check: 2027-02-01 internal guest, 2027-07-01 external' }
                else { '2027-02-01' }

    [pscustomobject]@{
        UserPrincipalName = $u['userPrincipalName']
        DisplayName       = $u['userDisplayName']
        UserType          = $u['userType']
        ActiveGlobalAdmin = $isGa
        Bucket            = $bucket
        DefaultMethod     = $default
        MethodsRegistered = ($methods -join ';')
        Deadline          = $deadline
        Id                = $u['id']
    }
}
$report = @($report)

$report | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

$summary = $report | Group-Object Bucket | Select-Object Name, Count
Write-Host "`nUsers checked: $($report.Count)"
$summary | Format-Table -AutoSize
$atRisk = @($report | Where-Object { $_.Bucket -ne 'Ready' })
$atRisk | Sort-Object Bucket, UserPrincipalName |
    Format-Table UserPrincipalName, Bucket, DefaultMethod, Deadline -AutoSize
Write-Host "Full report: $CsvPath"

$gaPhoneOnly = @($atRisk | Where-Object { $_.ActiveGlobalAdmin -and $_.Bucket -eq 'PhoneOnly' })
if ($gaPhoneOnly.Count -gt 0) {
    Write-Warning "$($gaPhoneOnly.Count) active Global Admin(s) rely on phone methods only. Fix these first."
}

if (-not $AddToGroupName) {
    Write-Host 'Report mode: nothing changed.' -ForegroundColor Yellow
    Disconnect-MgGraph | Out-Null
    return
}

# Group (must exist and be unique)
$safeName = $AddToGroupName.Replace("'", "''")
$groupPage = Invoke-MgGraphRequest -Method GET -OutputType HashTable `
    -Uri "v1.0/groups?`$filter=displayName eq '$safeName'&`$select=id,displayName"
$group = @($groupPage['value'])
if ($group.Count -ne 1) {
    throw "Group '$AddToGroupName' not found or not unique (found $($group.Count))."
}
$groupId = $group[0]['id']

$existing = @{}
foreach ($m in (Get-AllPages -Uri "v1.0/groups/$groupId/members?`$select=id")) { $existing[$m['id']] = $true }

$memberUsers = @($atRisk | Where-Object { $_.UserType -eq 'member' })
$toAdd = @($memberUsers | Where-Object { -not $existing.ContainsKey($_.Id) })
$alreadyIn = $memberUsers.Count - $toAdd.Count
Write-Host "To add to '$AddToGroupName': $($toAdd.Count). Already in the group: $alreadyIn. Guests skipped: $($atRisk.Count - $memberUsers.Count)."

if (-not $Apply) {
    Write-Host 'Preview only: re-run with -Apply -WhatIf, then -Apply, to add them.' -ForegroundColor Yellow
    Disconnect-MgGraph | Out-Null
    return
}

foreach ($u in $toAdd) {
    if ($PSCmdlet.ShouldProcess($u.UserPrincipalName, "Add to group '$AddToGroupName'")) {
        $body = @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($u.Id)" } | ConvertTo-Json
        Invoke-MgGraphRequest -Method POST -Uri "v1.0/groups/$groupId/members/`$ref" `
            -Body $body -ContentType 'application/json' | Out-Null
        Write-Host "Added: $($u.UserPrincipalName)" -ForegroundColor Green
    }
}

Write-Host "`nDone. Target '$AddToGroupName' with a passkey registration campaign, then re-run this report weekly."
Disconnect-MgGraph | Out-Null
