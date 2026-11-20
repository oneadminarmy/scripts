<#
.SYNOPSIS
    Creates a three-policy Conditional Access baseline in report-only mode.

.DESCRIPTION
    CA01  Require MFA for all users (break-glass group excluded)
    CA02  Block legacy authentication (break-glass group excluded)
    CA03  Require phishing-resistant MFA for admin roles (break-glass group excluded)

    All policies are created in report-only mode. Review sign-in logs for 7 to 14 days,
    then switch each policy to On in the Entra admin center.
    Skips any policy whose display name already exists, so it is safe to re-run.

    Demo tenant: harborlane.example (fictional company used on the channel).
    Requires Microsoft Entra ID P1 (included in Microsoft 365 Business Premium and E3).

.PARAMETER BreakGlassGroupName
    Display name of the security group holding your emergency access accounts.

.PARAMETER Prefix
    Prefix for policy names. Default: CA

.EXAMPLE
    .\New-CABaseline.ps1 -BreakGlassGroupName 'SG-BreakGlass' -WhatIf
    .\New-CABaseline.ps1 -BreakGlassGroupName 'SG-BreakGlass'
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$BreakGlassGroupName,

    [string]$Prefix = 'CA'
)

$ErrorActionPreference = 'Stop'

$modules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Identity.SignIns',
    'Microsoft.Graph.Groups',
    'Microsoft.Graph.Identity.DirectoryManagement'
)
foreach ($m in $modules) {
    if (-not (Get-Module -ListAvailable -Name $m)) {
        Write-Host "Installing $m..."
        Install-Module -Name $m -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module -Name $m
}

Connect-MgGraph -Scopes 'Policy.ReadWrite.ConditionalAccess', 'Policy.Read.All', 'Group.Read.All', 'RoleManagement.Read.Directory' -NoWelcome

# Break-glass group (must exist and be unique)
$group = @(Get-MgGroup -Filter "displayName eq '$BreakGlassGroupName'")
if ($group.Count -ne 1) {
    throw "Break-glass group '$BreakGlassGroupName' not found or not unique (found $($group.Count))."
}
$breakGlassId = $group[0].Id

# Admin roles resolved by name, so no tenant-specific IDs are hard-coded
$adminRoleNames = @(
    'Global Administrator',
    'Privileged Role Administrator',
    'Security Administrator',
    'Conditional Access Administrator',
    'Exchange Administrator',
    'SharePoint Administrator',
    'User Administrator',
    'Intune Administrator',
    'Application Administrator',
    'Cloud Application Administrator'
)
$roleIds = @(Get-MgDirectoryRoleTemplate | Where-Object { $adminRoleNames -contains $_.DisplayName } | Select-Object -ExpandProperty Id)
if ($roleIds.Count -eq 0) {
    throw 'No admin role templates resolved. Check RoleManagement.Read.Directory consent.'
}
Write-Host "Resolved $($roleIds.Count) admin role templates."

# Built-in authentication strength: phishing-resistant MFA
$phishingResistantStrengthId = '00000000-0000-0000-0000-000000000004'

$policies = @(
    @{
        displayName   = "$($Prefix)01 - Require MFA for all users"
        state         = 'enabledForReportingButNotEnforced'
        conditions    = @{
            users          = @{ includeUsers = @('All'); excludeGroups = @($breakGlassId) }
            applications   = @{ includeApplications = @('All') }
            clientAppTypes = @('all')
        }
        grantControls = @{ operator = 'OR'; builtInControls = @('mfa') }
    },
    @{
        displayName   = "$($Prefix)02 - Block legacy authentication"
        state         = 'enabledForReportingButNotEnforced'
        conditions    = @{
            users          = @{ includeUsers = @('All'); excludeGroups = @($breakGlassId) }
            applications   = @{ includeApplications = @('All') }
            clientAppTypes = @('exchangeActiveSync', 'other')
        }
        grantControls = @{ operator = 'OR'; builtInControls = @('block') }
    },
    @{
        displayName   = "$($Prefix)03 - Require phishing-resistant MFA for admins"
        state         = 'enabledForReportingButNotEnforced'
        conditions    = @{
            users          = @{ includeRoles = $roleIds; excludeGroups = @($breakGlassId) }
            applications   = @{ includeApplications = @('All') }
            clientAppTypes = @('all')
        }
        grantControls = @{
            operator               = 'OR'
            authenticationStrength = @{ id = $phishingResistantStrengthId }
        }
    }
)

$existing = @(Get-MgIdentityConditionalAccessPolicy -All | Select-Object -ExpandProperty DisplayName)

foreach ($p in $policies) {
    if ($existing -contains $p.displayName) {
        Write-Host "Skip (already exists): $($p.displayName)" -ForegroundColor Yellow
        continue
    }
    if ($PSCmdlet.ShouldProcess($p.displayName, 'Create Conditional Access policy in report-only mode')) {
        $created = New-MgIdentityConditionalAccessPolicy -BodyParameter $p
        Write-Host "Created: $($created.DisplayName) [$($created.State)]" -ForegroundColor Green
    }
}

Write-Host "`nDone. Review: Entra admin center > Protection > Conditional Access > Insights and reporting."
Disconnect-MgGraph | Out-Null
