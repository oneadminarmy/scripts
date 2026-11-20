<#
.SYNOPSIS
    Exports every Conditional Access policy as redacted, human-readable JSON for an AI audit.

.DESCRIPTION
    Read-only against the tenant. Nothing in Entra ID is created, changed or deleted.

    The script pulls all Conditional Access policies, named locations and authentication
    strengths through Microsoft Graph, then replaces every object ID with a readable label:
        Role: Global Administrator
        Group: SG-BreakGlass [BREAK-GLASS]
        App: Office 365 Exchange Online
        Location: HQ office (trusted)
        User-03                      (users are tokenized by default)

    Two files are written to the output folder:
        CA-Audit-<date>.json       Redacted export. This is the file you give the AI.
        CA-Audit-Map-<date>.csv    Token to real name map. Keep this local. Never upload it.

    No tenant ID, policy IDs or object IDs are written to the audit file.
    IP ranges of named locations are left out unless you pass -IncludeIpRanges.
    Re-running on the same day overwrites the same two files, so it is safe to repeat.

    Demo tenant: harborlane.example (fictional company used on the channel).
    Requires Microsoft Entra ID P1 (included in Microsoft 365 Business Premium and E3).
    Graph permissions (delegated): Policy.Read.All, Directory.Read.All.

.PARAMETER OutputFolder
    Folder for the two output files. Created if missing. Default: .\CA-Audit

.PARAMETER BreakGlassGroupName
    Optional. Display name of your emergency access group. It is labeled [BREAK-GLASS]
    so the audit can check that every policy excludes it.

.PARAMETER IncludeUserNames
    Write user display names instead of User-01 style tokens. Off by default.

.PARAMETER RedactGroupNames
    Replace group names with Group-01 style tokens too. Off by default, because group
    names usually explain intent (for example SG-CA-Exclude-Scanners).

.PARAMETER IncludeIpRanges
    Include the IP ranges of named locations. Off by default.

.EXAMPLE
    .\Export-CAPolicyForAudit.ps1 -BreakGlassGroupName 'SG-BreakGlass' -WhatIf
    .\Export-CAPolicyForAudit.ps1 -BreakGlassGroupName 'SG-BreakGlass'
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$OutputFolder = '.\CA-Audit',

    [string]$BreakGlassGroupName,

    [switch]$IncludeUserNames,

    [switch]$RedactGroupNames,

    [switch]$IncludeIpRanges
)

$ErrorActionPreference = 'Stop'

foreach ($m in @('Microsoft.Graph.Authentication')) {
    if (-not (Get-Module -ListAvailable -Name $m)) {
        Write-Host "Installing $m..."
        Install-Module -Name $m -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module -Name $m
}

Connect-MgGraph -Scopes 'Policy.Read.All', 'Directory.Read.All' -NoWelcome

$guidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

function Get-GraphAll {
    param([string]$Uri)
    $items = [System.Collections.Generic.List[object]]::new()
    while ($Uri) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType HashTable
        if ($page.ContainsKey('value')) {
            foreach ($v in $page['value']) { $items.Add($v) }
        }
        $Uri = $page['@odata.nextLink']
    }
    return , $items.ToArray()
}

# Collect every GUID-shaped string in an object tree
function Get-Guids {
    param($Node, [System.Collections.Generic.HashSet[string]]$Set)
    if ($null -eq $Node) { return }
    if ($Node -is [string]) {
        if ($Node -match $guidPattern) { [void]$Set.Add($Node.ToLowerInvariant()) }
        return
    }
    if ($Node -is [System.Collections.IDictionary]) {
        foreach ($k in @($Node.Keys)) {
            if ($k -in @('id', 'templateId') -or $k -like '@odata*') { continue }
            Get-Guids -Node $Node[$k] -Set $Set
        }
        return
    }
    if ($Node -is [System.Collections.IEnumerable]) {
        foreach ($item in $Node) { Get-Guids -Node $item -Set $Set }
    }
}

Write-Host 'Reading Conditional Access policies...'
$policies = Get-GraphAll -Uri 'v1.0/identity/conditionalAccess/policies'
$locations = Get-GraphAll -Uri 'v1.0/identity/conditionalAccess/namedLocations'
$strengths = Get-GraphAll -Uri 'v1.0/policies/authenticationStrengthPolicies'
$roleTemplates = Get-GraphAll -Uri 'v1.0/directoryRoleTemplates'
Write-Host "Found $($policies.Count) policies and $($locations.Count) named locations."

# Name cache: lowercase GUID -> label
$names = @{}
$map = [System.Collections.Generic.List[object]]::new()
$userCount = 0
$groupCount = 0

function Add-Label {
    param([string]$Id, [string]$Kind, [string]$RealName, [string]$Label)
    $script:names[$Id.ToLowerInvariant()] = $Label
    $script:map.Add([pscustomobject]@{ Label = $Label; Kind = $Kind; RealName = $RealName })
}

foreach ($r in $roleTemplates) { Add-Label -Id $r['id'] -Kind 'Role' -RealName $r['displayName'] -Label "Role: $($r['displayName'])" }
foreach ($s in $strengths) { Add-Label -Id $s['id'] -Kind 'AuthStrength' -RealName $s['displayName'] -Label "AuthStrength: $($s['displayName'])" }
foreach ($l in $locations) {
    $trust = if ($l['isTrusted']) { ' (trusted)' } else { '' }
    Add-Label -Id $l['id'] -Kind 'Location' -RealName $l['displayName'] -Label "Location: $($l['displayName'])$trust"
}

$allGuids = [System.Collections.Generic.HashSet[string]]::new()
foreach ($p in $policies) { Get-Guids -Node $p -Set $allGuids }
$unknown = @($allGuids | Where-Object { -not $names.ContainsKey($_) })

# Resolve users, groups and service principals by object ID, 1000 at a time
for ($i = 0; $i -lt $unknown.Count; $i += 1000) {
    $chunk = $unknown[$i..([Math]::Min($i + 999, $unknown.Count - 1))]
    $body = @{ ids = @($chunk); types = @('user', 'group', 'servicePrincipal') } | ConvertTo-Json
    $res = Invoke-MgGraphRequest -Method POST -Uri 'v1.0/directoryObjects/getByIds' -Body $body -ContentType 'application/json' -OutputType HashTable
    foreach ($o in $res['value']) {
        $id = $o['id'].ToLowerInvariant()
        switch ($o['@odata.type']) {
            '#microsoft.graph.user' {
                $userCount++
                $label = if ($IncludeUserNames) { "User: $($o['displayName'])" } else { 'User-{0:D2}' -f $userCount }
                Add-Label -Id $id -Kind 'User' -RealName $o['userPrincipalName'] -Label $label
            }
            '#microsoft.graph.group' {
                $groupCount++
                $label = if ($RedactGroupNames) { 'Group-{0:D2}' -f $groupCount } else { "Group: $($o['displayName'])" }
                if ($BreakGlassGroupName -and $o['displayName'] -eq $BreakGlassGroupName) { $label += ' [BREAK-GLASS]' }
                Add-Label -Id $id -Kind 'Group' -RealName $o['displayName'] -Label $label
            }
            '#microsoft.graph.servicePrincipal' {
                Add-Label -Id $id -Kind 'App' -RealName $o['displayName'] -Label "App: $($o['displayName'])"
            }
        }
    }
}

# Applications in policies are referenced by appId, not object ID
foreach ($g in @($unknown | Where-Object { -not $names.ContainsKey($_) })) {
    $sp = Get-GraphAll -Uri "v1.0/servicePrincipals?`$filter=appId eq '$g'&`$select=displayName,appId"
    if ($sp.Count -gt 0) {
        Add-Label -Id $g -Kind 'App' -RealName $sp[0]['displayName'] -Label "App: $($sp[0]['displayName'])"
    }
}

# Anything still unknown (deleted users, deleted groups) gets a token the AI can flag
$unresolved = 0
foreach ($g in @($unknown | Where-Object { -not $names.ContainsKey($_) })) {
    $unresolved++
    Add-Label -Id $g -Kind 'Unresolved' -RealName $g -Label ('Unresolved-{0:D2} (deleted or no access)' -f $unresolved)
}

function ConvertTo-Readable {
    param($Node)
    if ($null -eq $Node) { return $null }
    if ($Node -is [string]) {
        if ($Node -match $guidPattern) { return $script:names[$Node.ToLowerInvariant()] }
        return $Node
    }
    if ($Node -is [System.Collections.IDictionary]) {
        $out = [ordered]@{}
        foreach ($k in @($Node.Keys | Sort-Object)) {
            if ($k -in @('id', 'templateId', 'partialEnablementStrategy') -or $k -like '@odata*') { continue }
            $out[$k] = ConvertTo-Readable -Node $Node[$k]
        }
        return $out
    }
    if ($Node -is [System.Collections.IEnumerable]) {
        $list = @(foreach ($item in $Node) { ConvertTo-Readable -Node $item })
        return , $list
    }
    return $Node
}

$readablePolicies = foreach ($p in ($policies | Sort-Object { $_['displayName'] })) {
    ConvertTo-Readable -Node $p
}

$locationSummary = foreach ($l in $locations) {
    $entry = [ordered]@{
        name      = $l['displayName']
        type      = ($l['@odata.type'] -replace '#microsoft.graph.', '')
        isTrusted = [bool]$l['isTrusted']
    }
    if ($l.ContainsKey('ipRanges')) {
        $entry.ipRangeCount = @($l['ipRanges']).Count
        if ($IncludeIpRanges) { $entry.ipRanges = @($l['ipRanges'] | ForEach-Object { $_['cidrAddress'] }) }
    }
    if ($l.ContainsKey('countriesAndRegions')) { $entry.countriesAndRegions = @($l['countriesAndRegions']) }
    $entry
}

$stateCounts = [ordered]@{}
foreach ($p in $policies) { $stateCounts[$p['state']] = 1 + [int]$stateCounts[$p['state']] }

$audit = [ordered]@{
    exportedOn      = (Get-Date).ToString('yyyy-MM-dd')
    breakGlassGroup = if ($BreakGlassGroupName) { 'labeled [BREAK-GLASS]' } else { 'not provided' }
    policyCount     = $policies.Count
    stateCounts     = $stateCounts
    namedLocations  = @($locationSummary)
    policies        = @($readablePolicies)
}

$stamp = Get-Date -Format 'yyyy-MM-dd'
$auditPath = Join-Path $OutputFolder "CA-Audit-$stamp.json"
$mapPath = Join-Path $OutputFolder "CA-Audit-Map-$stamp.csv"

if ($PSCmdlet.ShouldProcess($OutputFolder, "Write $($policies.Count) redacted policies and the local name map")) {
    if (-not (Test-Path $OutputFolder)) { New-Item -ItemType Directory -Path $OutputFolder | Out-Null }
    $audit | ConvertTo-Json -Depth 20 | Set-Content -Path $auditPath -Encoding utf8
    $map | Sort-Object Kind, Label | Export-Csv -Path $mapPath -NoTypeInformation -Encoding utf8
    Write-Host "Audit file (give this to the AI): $auditPath" -ForegroundColor Green
    Write-Host "Name map (keep local, never upload): $mapPath" -ForegroundColor Yellow
}
else {
    Write-Host "Preview: $($policies.Count) policies, $($map.Count) labeled objects, $unresolved unresolved."
}

if ($unresolved -gt 0) {
    Write-Warning "$unresolved object(s) could not be resolved. They are often deleted users or groups still named in a policy."
}

Disconnect-MgGraph | Out-Null
