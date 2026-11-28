<#
.SYNOPSIS
    Turn SMTP AUTH off for everyone except the device mailboxes that still need it.

.DESCRIPTION
    Once your scanners and apps use OAuth, an SMTP relay connector or Microsoft Graph, almost no
    mailbox needs SMTP AUTH. Leaving it on everywhere gives attackers one more way to try stolen
    passwords. This script:
      1. Turns SMTP AUTH on for each mailbox in -AllowMailbox (devices that now use OAuth).
      2. With -DisableOrgWide, turns SMTP AUTH off for the whole organization.
      3. With -ResetOthers, sets every other mailbox that has SMTP AUTH turned on by hand back to the
         org default, so it follows the org-wide setting.

    Without -Apply the script only shows what it would change. Running it again changes nothing.

    From the One Admin Army video "Scan to Email Breaks in December: Fix SMTP AUTH Now".
    Test in a lab tenant first. Run with -WhatIf before making changes.

.PARAMETER AllowMailbox
    Mailboxes that keep SMTP AUTH, for example scanner@harborlane.example.

.PARAMETER DisableOrgWide
    Turn SMTP AUTH off for the organization (Set-TransportConfig -SmtpClientAuthenticationDisabled $true).

.PARAMETER ResetOthers
    Return other mailboxes with SMTP AUTH turned on by hand to the org default.

.PARAMETER Apply
    Make the changes. Without it the script is a preview.

.EXAMPLE
    .\Set-SmtpAuthAllowList.ps1 -AllowMailbox scanner@harborlane.example -DisableOrgWide -ResetOthers

.EXAMPLE
    .\Set-SmtpAuthAllowList.ps1 -AllowMailbox scanner@harborlane.example -DisableOrgWide -ResetOthers -Apply
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string[]]$AllowMailbox,

    [switch]$DisableOrgWide,

    [switch]$ResetOthers,

    [switch]$Apply
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    Write-Verbose 'Installing ExchangeOnlineManagement for the current user'
    Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force -WhatIf:$false
}
Import-Module ExchangeOnlineManagement
if (-not (Get-ConnectionInformation -ErrorAction SilentlyContinue)) {
    Connect-ExchangeOnline -ShowBanner:$false
}

$changes = 0
function Invoke-Change {
    param([string]$Target, [string]$Action, [scriptblock]$Do)
    $script:changes++
    if (-not $Apply) {
        Write-Output ("Preview: {0}: {1}" -f $Target, $Action)
    }
    elseif ($PSCmdlet.ShouldProcess($Target, $Action)) {
        & $Do
        Write-Output ("Done:    {0}: {1}" -f $Target, $Action)
    }
}

# 1. Allowed device mailboxes keep SMTP AUTH (set per mailbox, so they survive the org-wide switch).
$allowed = @{}
foreach ($id in $AllowMailbox) {
    $m = Get-CASMailbox -Identity $id
    $allowed["$($m.PrimarySmtpAddress)".ToLower()] = $true
    if ($m.SmtpClientAuthenticationDisabled -ne $false) {
        Invoke-Change -Target $m.PrimarySmtpAddress -Action 'turn SMTP AUTH on for this mailbox' -Do {
            Set-CASMailbox -Identity $m.Identity -SmtpClientAuthenticationDisabled $false
        }.GetNewClosure()
    }
    else {
        Write-Output ("OK:      {0}: SMTP AUTH already on" -f $m.PrimarySmtpAddress)
    }
}

# 2. Organization-wide switch.
if ($DisableOrgWide) {
    if ((Get-TransportConfig).SmtpClientAuthenticationDisabled) {
        Write-Output 'OK:      organization: SMTP AUTH already off'
    }
    else {
        Invoke-Change -Target 'organization' -Action 'turn SMTP AUTH off org-wide' -Do {
            Set-TransportConfig -SmtpClientAuthenticationDisabled $true
        }
    }
}

# 3. Everyone else who has SMTP AUTH turned on by hand goes back to the org default.
if ($ResetOthers) {
    $others = @(Get-CASMailbox -ResultSize Unlimited | Where-Object {
        $_.SmtpClientAuthenticationDisabled -eq $false -and -not $allowed.ContainsKey("$($_.PrimarySmtpAddress)".ToLower())
    })
    foreach ($o in $others) {
        Invoke-Change -Target $o.PrimarySmtpAddress -Action 'set SMTP AUTH back to the org default' -Do {
            Set-CASMailbox -Identity $o.Identity -SmtpClientAuthenticationDisabled $null
        }.GetNewClosure()
    }
}

if ($changes -eq 0) {
    Write-Output 'Nothing to change.'
}
elseif (-not $Apply) {
    Write-Output ("{0} change(s) previewed. Run again with -Apply to make them." -f $changes)
}
