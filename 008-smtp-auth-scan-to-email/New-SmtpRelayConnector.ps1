<#
.SYNOPSIS
    Create (or update) an Exchange Online inbound connector so devices at a static public IP can
    relay mail through Microsoft 365 without a username or password.

.DESCRIPTION
    SMTP relay is one of Microsoft's three supported ways for printers, scanners and apps to send
    mail. The device sends to your tenant's MX endpoint on port 25, and Exchange Online accepts it
    because it comes from your office's static public IP address. It can send to people inside and
    outside the organization, and it does not depend on SMTP AUTH or Basic authentication.

    Without -Apply the script only shows what it would do. With -Apply it creates the connector, or
    updates the IP list on an existing connector with the same name. Running it again changes nothing.
    It also prints the device settings and the SPF change you need.

    Requirements: a static public IP address for the office, and an accepted domain in the tenant.

    From the One Admin Army video "Scan to Email Breaks in December: Fix SMTP AUTH Now".
    Test in a lab tenant first. Run with -WhatIf before making changes.

.PARAMETER PublicIPAddress
    The office's static public IPv4 address or addresses that devices send from.

.PARAMETER Name
    Connector name. Default: "Device relay (static IP)".

.PARAMETER Apply
    Make the change. Without it the script is a preview.

.EXAMPLE
    .\New-SmtpRelayConnector.ps1 -PublicIPAddress 192.0.2.25

.EXAMPLE
    .\New-SmtpRelayConnector.ps1 -PublicIPAddress 192.0.2.25 -Apply
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string[]]$PublicIPAddress,

    [string]$Name = 'Device relay (static IP)',

    [switch]$Apply
)

$ErrorActionPreference = 'Stop'

# Validate the addresses: they must be IPv4 and public, because Exchange Online sees your public IP.
function Test-PrivateIPv4 {
    param([ipaddress]$Ip)
    $b = $Ip.GetAddressBytes()
    ($b[0] -eq 10) -or ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or ($b[0] -eq 192 -and $b[1] -eq 168)
}
foreach ($ip in $PublicIPAddress) {
    $parsed = $null
    if (-not [ipaddress]::TryParse($ip, [ref]$parsed) -or $parsed.AddressFamily -ne 'InterNetwork') {
        throw "Not an IPv4 address: $ip"
    }
    if (Test-PrivateIPv4 -Ip $parsed) {
        throw "$ip is a private address. Use the office's public IP (what the internet sees)."
    }
}
$wanted = @($PublicIPAddress | Sort-Object -Unique)

if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    Write-Verbose 'Installing ExchangeOnlineManagement for the current user'
    Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force -WhatIf:$false
}
Import-Module ExchangeOnlineManagement
if (-not (Get-ConnectionInformation -ErrorAction SilentlyContinue)) {
    Connect-ExchangeOnline -ShowBanner:$false
}

$existing = @(Get-InboundConnector | Where-Object Name -eq $Name)[0]

if ($existing) {
    $current = @($existing.SenderIPAddresses | ForEach-Object { "$_" } | Sort-Object -Unique)
    if (-not (Compare-Object $current $wanted)) {
        Write-Output "Connector '$Name' already allows $($wanted -join ', '). Nothing to change."
    }
    elseif (-not $Apply) {
        Write-Output "Preview: would update '$Name' from $($current -join ', ') to $($wanted -join ', ')."
        Write-Output 'Run again with -Apply to make the change.'
    }
    elseif ($PSCmdlet.ShouldProcess($Name, "Set sender IPs to $($wanted -join ', ')")) {
        Set-InboundConnector -Identity $existing.Identity -SenderIPAddresses $wanted -RestrictDomainsToIPAddresses $true
        Write-Output "Updated '$Name': $($wanted -join ', ')"
    }
}
elseif (-not $Apply) {
    Write-Output "Preview: would create inbound connector '$Name'"
    Write-Output "  From: your organization's devices at $($wanted -join ', ')"
    Write-Output '  To:   Microsoft 365, identified by sender IP address'
    Write-Output 'Run again with -Apply to make the change.'
}
elseif ($PSCmdlet.ShouldProcess($Name, "Create inbound connector for $($wanted -join ', ')")) {
    New-InboundConnector -Name $Name -ConnectorType OnPremises -SenderDomains '*' `
        -SenderIPAddresses $wanted -RestrictDomainsToIPAddresses $true `
        -Comment 'Relay for printers, scanners and apps at a static public IP' | Out-Null
    Write-Output "Created inbound connector '$Name' for $($wanted -join ', ')"
}

# Device settings and SPF, so the change is complete.
$domain = (Get-AcceptedDomain | Where-Object Default).DomainName
$mx = $null
if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) {
    $mx = (Resolve-DnsName -Name $domain -Type MX -ErrorAction SilentlyContinue |
        Where-Object QueryType -eq 'MX' | Sort-Object Preference | Select-Object -First 1).NameExchange
}

Write-Output ''
Write-Output '=== Device settings ==='
Write-Output ("Server: {0}" -f $(if ($mx) { $mx } else { "your MX record for $domain (Exchange admin center > Domains)" }))
Write-Output 'Port:   25, TLS on if the device supports it'
Write-Output "From:   any address in $domain, for example scanner@$domain"
Write-Output 'Auth:   none'
Write-Output ''
Write-Output '=== SPF ==='
Write-Output ("Add to the SPF record for {0}: {1}" -f $domain, (($wanted | ForEach-Object { "ip4:$_" }) -join ' '))
