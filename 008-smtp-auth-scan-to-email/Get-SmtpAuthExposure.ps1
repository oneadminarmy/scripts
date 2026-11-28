<#
.SYNOPSIS
    Read-only report: who can still use SMTP AUTH in Exchange Online, and who actually does.

.DESCRIPTION
    Exchange Online turns off Basic authentication for SMTP AUTH (client submission to
    smtp.office365.com) by default for existing tenants at the end of December 2026. Printers,
    scanners, apps and scripts that send mail with a stored username and password stop sending.

    This script only reads. It shows:
      1. The organization-wide SMTP AUTH setting (Set-TransportConfig).
      2. Authentication policies and whether they allow Basic auth for SMTP.
      3. Every mailbox where SMTP AUTH is effectively on, and why (mailbox setting or org default).
      4. Optional (-IncludeSignIns): Entra sign-ins that used "Authenticated SMTP" in the last
         -Days days, grouped by account and IP address. This part reads sign-in logs through
         Microsoft Graph, which needs Entra ID P1 (included in Business Premium and E3).

    Then cross-check the SMTP AUTH clients report in the Exchange admin center
    (Reports > Mail flow), which shows whether each sender uses Basic auth or OAuth.

    From the One Admin Army video "Scan to Email Breaks in December: Fix SMTP AUTH Now".
    Test in a lab tenant first. Run with -WhatIf before making changes.

.PARAMETER IncludeSignIns
    Also read Entra sign-in logs for "Authenticated SMTP" sign-ins (needs Entra ID P1).

.PARAMETER Days
    How many days of sign-ins to read with -IncludeSignIns. 1 to 30. Default 7.

.PARAMETER ReportPath
    Where to save the per-mailbox CSV. With -WhatIf the file is not written.

.EXAMPLE
    .\Get-SmtpAuthExposure.ps1

.EXAMPLE
    .\Get-SmtpAuthExposure.ps1 -IncludeSignIns -Days 30
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$IncludeSignIns,

    [ValidateRange(1, 30)]
    [int]$Days = 7,

    [string]$ReportPath = (Join-Path (Get-Location) ("SmtpAuthExposure-{0}.csv" -f (Get-Date -Format 'yyyy-MM-dd')))
)

$ErrorActionPreference = 'Stop'

function Confirm-Module {
    param([Parameter(Mandatory)][string]$Name)
    if (-not (Get-Module -ListAvailable -Name $Name)) {
        Write-Verbose "Installing $Name for the current user"
        Install-Module $Name -Scope CurrentUser -Force -WhatIf:$false
    }
    Import-Module $Name
}

Confirm-Module -Name ExchangeOnlineManagement
if (-not (Get-ConnectionInformation -ErrorAction SilentlyContinue)) {
    Connect-ExchangeOnline -ShowBanner:$false
}

# 1. Organization-wide setting. True means SMTP AUTH is off for every mailbox that does not override it.
$transport = Get-TransportConfig
$orgDisabled = [bool]$transport.SmtpClientAuthenticationDisabled

Write-Output '=== Organization ==='
Write-Output ("SMTP AUTH org-wide:     {0}" -f $(if ($orgDisabled) { 'OFF' } else { 'ON' }))

# 2. Authentication policies. AllowBasicAuthSmtp = False blocks Basic auth SMTP for the users they apply to.
$orgConfig = Get-OrganizationConfig
$policies = @(Get-AuthenticationPolicy -ErrorAction SilentlyContinue)
Write-Output ("Default auth policy:    {0}" -f $(if ($orgConfig.DefaultAuthenticationPolicy) { $orgConfig.DefaultAuthenticationPolicy } else { '(none)' }))
foreach ($p in $policies) {
    Write-Output ("  - {0}: AllowBasicAuthSmtp={1}" -f $p.Name, $p.AllowBasicAuthSmtp)
}

# 3. Per-mailbox setting. $null follows the org setting; $false turns SMTP AUTH on; $true turns it off.
$rows = foreach ($m in Get-CASMailbox -ResultSize Unlimited) {
    $value = $m.SmtpClientAuthenticationDisabled
    $effectiveOn = if ($null -eq $value) { -not $orgDisabled } else { -not [bool]$value }
    [pscustomobject]@{
        Mailbox          = $m.PrimarySmtpAddress
        MailboxSetting   = if ($null -eq $value) { 'Org default' } elseif ($value) { 'Off' } else { 'On' }
        SmtpAuthEnabled  = $effectiveOn
    }
}
$rows = @($rows)
$enabled = @($rows | Where-Object SmtpAuthEnabled)
$explicit = @($rows | Where-Object MailboxSetting -eq 'On')

Write-Output ''
Write-Output ("=== Mailboxes checked: {0} ===" -f $rows.Count)
Write-Output ("SMTP AUTH on:           {0}" -f $enabled.Count)
Write-Output ("  turned on per mailbox {0}" -f $explicit.Count)
foreach ($e in $explicit) { Write-Output ("    {0}" -f $e.Mailbox) }

# 4. Who actually signs in with SMTP AUTH (optional, needs Entra ID P1).
if ($IncludeSignIns) {
    Confirm-Module -Name Microsoft.Graph.Authentication
    Connect-MgGraph -Scopes 'AuditLog.Read.All', 'Directory.Read.All' -NoWelcome

    $since = (Get-Date).ToUniversalTime().AddDays(-$Days).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $filter = [uri]::EscapeDataString("clientAppUsed eq 'Authenticated SMTP' and createdDateTime ge $since")
    $next = "v1.0/auditLogs/signIns?`$filter=$filter&`$top=500"
    $signIns = while ($next) {
        $WhatIfPreference = $false
        $page = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject
        foreach ($s in $page.value) { $s }
        $next = $page.'@odata.nextLink'
    }
    $signIns = @($signIns)

    Write-Output ''
    Write-Output ("=== Authenticated SMTP sign-ins, last {0} days: {1} ===" -f $Days, $signIns.Count)
    $signIns | Group-Object userPrincipalName, ipAddress | Sort-Object Count -Descending | ForEach-Object {
        $last = ($_.Group | Sort-Object createdDateTime -Descending | Select-Object -First 1)
        $failed = @($_.Group | Where-Object { $_.status.errorCode -ne 0 }).Count
        Write-Output ("{0,-34} {1,-15} {2,5} sign-ins, {3} failed, last {4}" -f $last.userPrincipalName,
            $last.ipAddress, $_.Count, $failed, ([datetime]$last.createdDateTime).ToString('yyyy-MM-dd'))
    }
}

Write-Output ''
Write-Output 'Next: open Exchange admin center > Reports > Mail flow > SMTP AUTH clients'
Write-Output 'and check which senders still use Basic auth.'

if ($PSCmdlet.ShouldProcess($ReportPath, 'Save per-mailbox CSV')) {
    $rows | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding utf8
    Write-Output ("Saved: {0}" -f $ReportPath)
}
