<#
.SYNOPSIS
    Pre-flight review of an AI-written PowerShell script, without running it.

.DESCRIPTION
    Parses the script with the PowerShell parser. Nothing in the reviewed script is executed.
    It flags the mistakes AI assistants make most often in Microsoft 365 scripts:

      High    Syntax errors
      High    Retired modules (MSOnline, AzureAD)
      High    Commands that change things, in a script with no -WhatIf support
      High    Get-MgUser properties used but never requested with -Property (they come back empty)
      High    Hard-coded passwords or secrets
      Medium  Commands that do not exist on this machine (often invented by the AI)
      Medium  Graph list commands without -All (only the first page comes back)
      Medium  -Confirm:$false, Invoke-Expression, hard-coded GUIDs, Directory.ReadWrite.All
      Low     Parameters that the installed command does not have

    If PSScriptAnalyzer is installed, its errors and warnings are added too.
    Install the modules the reviewed script uses first, so the command checks are accurate.

    From the One Admin Army video "Write PowerShell With AI Without Breaking Production".
    Test in a lab tenant first. Run with -WhatIf before making changes.

.PARAMETER Path
    The script to review. A relative path is looked up in the current folder, then next to this script.

.PARAMETER ReportPath
    Optional CSV file for the findings. With -WhatIf the file is not written.

.EXAMPLE
    .\Test-AIScript.ps1 -Path .\Draft-FromAI.ps1

.EXAMPLE
    .\Test-AIScript.ps1 -Path .\Draft-FromAI.ps1 -ReportPath .\review.csv
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$Path,

    [string]$ReportPath
)

$ErrorActionPreference = 'Stop'

$full = $null
foreach ($candidate in @($Path, (Join-Path $PSScriptRoot $Path))) {
    if (Test-Path -LiteralPath $candidate -PathType Leaf) { $full = (Resolve-Path -LiteralPath $candidate).Path; break }
}
if (-not $full) { throw "Script not found: $Path" }

$findings = [System.Collections.Generic.List[object]]::new()
function Add-Finding {
    param([string]$Severity, [int]$Line, [string]$Rule, [string]$Detail)
    $findings.Add([pscustomobject]@{ Severity = $Severity; Line = $Line; Rule = $Rule; Detail = $Detail })
}

$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($full, [ref]$tokens, [ref]$parseErrors)
$text = Get-Content -LiteralPath $full -Raw

foreach ($e in $parseErrors) {
    Add-Finding 'High' $e.Extent.StartLineNumber 'Syntax error' $e.Message
}

# Functions the script defines itself are not "missing" commands.
$defined = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
    ForEach-Object { $_.Name })

# Does the script support -WhatIf, and does it actually call ShouldProcess?
$cmdletBinding = $null
if ($ast.ParamBlock) {
    $cmdletBinding = $ast.ParamBlock.Attributes | Where-Object { $_.TypeName.Name -eq 'CmdletBinding' } | Select-Object -First 1
}
$supportsShouldProcess = $false
if ($cmdletBinding) {
    $arg = $cmdletBinding.NamedArguments | Where-Object { $_.ArgumentName -eq 'SupportsShouldProcess' } | Select-Object -First 1
    if ($arg -and ($arg.ExpressionOmitted -or $arg.Argument.Extent.Text -notmatch '\$false')) { $supportsShouldProcess = $true }
}
$callsShouldProcess = $text -match '\.ShouldProcess\('

$changeVerbs = 'Set|New|Remove|Add|Update|Disable|Enable|Revoke|Clear|Reset|Grant|Move|Rename|Stop|Restart|Uninstall|Publish|Register|Unregister|Send|Restore|Confirm|Approve|Deny|Lock|Unlock|Block|Unblock'
$harmless = @('New-Object', 'New-TimeSpan', 'New-Guid', 'New-Variable', 'Set-Variable', 'Remove-Variable', 'Set-StrictMode',
    'Set-Location', 'Add-Member', 'Add-Type', 'Remove-Module', 'Clear-Host', 'Set-Alias', 'New-Alias', 'Update-TypeData',
    'Update-FormatData', 'Register-ArgumentCompleter', 'Clear-Variable')
$retired = '^(Connect-MsolService|\w+-Msol\w+|Connect-AzureAD|Disconnect-AzureAD|\w+-AzureAD\w+)$'
$singleIdParam = '^(UserId|GroupId|ApplicationId|ServicePrincipalId|DeviceId|DirectoryObjectId|ConditionalAccessPolicyId|Id)$'
$listNoun = '(Member|Owner|MemberOf|TransitiveMember|TransitiveMemberOf|Method|AppRoleAssignment|RegisteredDevice|OwnedDevice)$'

$changeLines = [System.Collections.Generic.List[int]]::new()
$userPropertiesRequested = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$usesGetMgUser = $false
$missingReported = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

$commands = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)
foreach ($cmd in $commands) {
    $name = $cmd.GetCommandName()
    if (-not $name) { continue }
    $line = $cmd.Extent.StartLineNumber
    $params = @($cmd.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] })
    $paramNames = @($params | ForEach-Object { $_.ParameterName })

    if ($name -match $retired) {
        Add-Finding 'High' $line 'Retired module' "$name comes from the retired MSOnline or AzureAD module. Use Microsoft Graph PowerShell."
        continue
    }

    if ($name -in @('Invoke-Expression', 'iex')) {
        Add-Finding 'Medium' $line 'Invoke-Expression' 'Runs text as code. Call the command directly instead.'
    }

    foreach ($p in $params) {
        if ($p.ParameterName -eq 'Confirm' -and $p.Argument -and $p.Argument.Extent.Text -match '\$false') {
            Add-Finding 'Medium' $line 'Confirm disabled' "$name -Confirm:`$false skips the safety prompt."
        }
    }

    # Commands that change things
    $isChange = ($name -match "^($changeVerbs)-" -and $name -notin $harmless)
    if ($name -eq 'Invoke-MgGraphRequest' -or $name -eq 'Invoke-RestMethod') {
        $methodIndex = [array]::IndexOf($paramNames, 'Method')
        if ($methodIndex -ge 0) {
            $methodAst = $params[$methodIndex]
            $value = if ($methodAst.Argument) { $methodAst.Argument.Extent.Text } else {
                $pos = [array]::IndexOf($cmd.CommandElements, $methodAst)
                if ($pos -ge 0 -and $pos + 1 -lt $cmd.CommandElements.Count) { $cmd.CommandElements[$pos + 1].Extent.Text } else { '' }
            }
            if ($value -match 'POST|PATCH|PUT|DELETE') { $isChange = $true }
        }
    }
    if ($isChange) { $changeLines.Add($line) }

    # Graph paging
    if ($name -match '^Get-Mg' -and -not ($paramNames | Where-Object { $_ -in @('All', 'Top', 'PageSize') })) {
        $hasSingleId = [bool]($paramNames | Where-Object { $_ -match $singleIdParam })
        if (($name -match $listNoun) -or -not $hasSingleId) {
            Add-Finding 'Medium' $line 'First page only' "$name without -All returns only the first page of results (often 100 items)."
        }
    }

    # Which user properties were asked for
    if ($name -match '^Get-Mg(Beta)?User$') {
        $usesGetMgUser = $true
        for ($i = 0; $i -lt $cmd.CommandElements.Count; $i++) {
            $el = $cmd.CommandElements[$i]
            if ($el -is [System.Management.Automation.Language.CommandParameterAst] -and $el.ParameterName -in @('Property', 'Select')) {
                $valueText = if ($el.Argument) { $el.Argument.Extent.Text } elseif ($i + 1 -lt $cmd.CommandElements.Count) { $cmd.CommandElements[$i + 1].Extent.Text } else { '' }
                foreach ($prop in ($valueText -replace "[`"'@()\s]", '' -split ',')) { if ($prop) { [void]$userPropertiesRequested.Add($prop) } }
            }
        }
    }

    # Does the command exist here, and does it have these parameters?
    if ($name -in $defined) { continue }
    $info = Get-Command -Name $name -ErrorAction Ignore | Select-Object -First 1
    if (-not $info) {
        if (-not $missingReported.Add($name)) { continue }
        Add-Finding 'Medium' $line 'Command not found' "$name was not found. The AI may have invented it, or its module is not installed here."
        continue
    }
    if ($info.CommandType -in @('Cmdlet', 'Function') -and $info.Parameters.Count -gt 0) {
        $known = @($info.Parameters.Values | ForEach-Object { $_.Name; $_.Aliases })
        foreach ($pn in $paramNames) {
            if (-not ($known | Where-Object { $_ -like "$pn*" })) {
                Add-Finding 'Low' $line 'Unknown parameter' "$name has no parameter -$pn in the installed version. Check the docs."
            }
        }
    }
}

if ($changeLines.Count -gt 0 -and -not $supportsShouldProcess) {
    Add-Finding 'High' $changeLines[0] 'No WhatIf support' "The script changes things ($($changeLines.Count) command(s)) but has no [CmdletBinding(SupportsShouldProcess)], so -WhatIf cannot preview it."
}
elseif ($changeLines.Count -gt 0 -and -not $callsShouldProcess) {
    Add-Finding 'Medium' $changeLines[0] 'ShouldProcess never called' 'SupportsShouldProcess is declared but $PSCmdlet.ShouldProcess() is never called, so some changes may ignore -WhatIf.'
}

# Get-MgUser returns a small default set of properties. Anything else is empty unless requested.
if ($usesGetMgUser) {
    $notDefault = @('AccountEnabled', 'SignInActivity', 'OnPremisesSyncEnabled', 'LastPasswordChangeDateTime', 'CreatedDateTime',
        'Department', 'UsageLocation', 'AssignedLicenses', 'EmployeeId', 'CompanyName', 'UserType', 'Manager', 'ExternalUserState')
    $members = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.MemberExpressionAst] }, $true)
    $reported = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($m in $members) {
        $prop = $m.Member.Extent.Text
        if ($prop -in $notDefault -and -not $userPropertiesRequested.Contains($prop) -and $reported.Add($prop)) {
            Add-Finding 'High' $m.Extent.StartLineNumber 'Property never requested' "$prop is used but not requested with Get-MgUser -Property, so it is empty for every user."
        }
    }
}

# Secrets, IDs and scopes, line by line
$lines = $text -split "`r?`n"
for ($n = 0; $n -lt $lines.Count; $n++) {
    $l = $lines[$n]
    if ($l.TrimStart().StartsWith('#')) { continue }
    if ($l -match '(?i)(password|secret|apikey|clientsecret|token)\w*\s*=\s*["''][^"'']{6,}["'']' -or
        $l -match '(?i)ConvertTo-SecureString\s+["''][^"'']+["'']\s+-AsPlainText') {
        Add-Finding 'High' ($n + 1) 'Hard-coded secret' 'A password or secret is written in the script. Use a certificate, managed identity or a secret store.'
    }
    if ($l -match '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b' -and $l -notmatch '00000000-0000-0000-0000-') {
        Add-Finding 'Medium' ($n + 1) 'Hard-coded ID' 'A tenant, app or object ID is hard-coded. Make it a parameter or look it up by name.'
    }
    if ($l -match 'Directory\.ReadWrite\.All') {
        Add-Finding 'Medium' ($n + 1) 'Broad permission' 'Directory.ReadWrite.All can change almost anything. Ask for the narrowest scope that works.'
    }
}

# PSScriptAnalyzer, when available
if (Get-Module -ListAvailable -Name PSScriptAnalyzer) {
    Import-Module PSScriptAnalyzer
    foreach ($r in @(Invoke-ScriptAnalyzer -Path $full -Severity Error, Warning -WhatIf:$false)) {
        $sev = if ("$($r.Severity)" -eq 'Error') { 'High' } else { 'Low' }
        Add-Finding $sev $r.Line "Analyzer: $($r.RuleName)" $r.Message
    }
}
else {
    Write-Verbose 'PSScriptAnalyzer is not installed; skipping its rules. Install-Module PSScriptAnalyzer -Scope CurrentUser'
}

$order = @{ High = 0; Medium = 1; Low = 2 }
$sorted = @($findings | Sort-Object { $order[$_.Severity] }, Line)

Write-Output ("Reviewed: {0}" -f (Split-Path $full -Leaf))
Write-Output ("High: {0}  Medium: {1}  Low: {2}" -f @($sorted | Where-Object Severity -eq 'High').Count,
    @($sorted | Where-Object Severity -eq 'Medium').Count, @($sorted | Where-Object Severity -eq 'Low').Count)
if ($sorted.Count -gt 0) {
    $sorted | Format-Table Severity, Line, Rule, Detail -AutoSize -Wrap | Out-String -Width 160 | Write-Output
}
else {
    Write-Output 'No findings. Still read every line before you run it.'
}

if ($ReportPath -and $PSCmdlet.ShouldProcess($ReportPath, 'Write findings report')) {
    $sorted | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding utf8
    Write-Output "Report saved: $ReportPath"
}
