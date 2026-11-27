<#
Test for Find-NonPlainData, the plain-data check of spike.ps1.

Runs on any machine with PowerShell (pwsh on macOS or Linux, powershell.exe on Windows).
It parses spike.ps1, takes out only that one function, and tests it. It runs none of the
Windows-only parts of the spike.

    pwsh -NoProfile -File ./test-plain-data.ps1
#>
$ErrorActionPreference = 'Stop'
$spike = Join-Path $PSScriptRoot 'spike.ps1'
$ast = [Management.Automation.Language.Parser]::ParseFile($spike, [ref]$null, [ref]$null)
$fn = $ast.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Find-NonPlainData' }, $true)
if ($null -eq $fn) { Write-Host 'FAIL: Find-NonPlainData is not defined in spike.ps1'; exit 1 }
. ([scriptblock]::Create($fn.Extent.Text))

$script:failed = 0
function Expect([string]$name, $value, [string]$wantPath, [string]$wantType) {
    $got = Find-NonPlainData $value 'evidence' 8
    if ($wantPath -eq '') {
        if ($null -eq $got) { Write-Host "ok   $name" } else { Write-Host "FAIL ${name}: expected plain, got: $got"; $script:failed++ }
        return
    }
    if ($null -ne $got -and $got.Contains($wantPath) -and $got.Contains($wantType)) { Write-Host "ok   $name ($got)" }
    else { Write-Host "FAIL ${name}: expected path '$wantPath' and type '$wantType', got: $got"; $script:failed++ }
}

$plain = [ordered]@{
    s = 'text'; n = 3; d = 1.5; b = $true; z = $null
    list = @(1, 'two', @{ k = 'v' })
    nested = [ordered]@{ deeper = [ordered]@{ bytes = [byte[]](1, 2, 3); empty = @() } }
}
Expect 'nested ordered dictionary of plain values is accepted' $plain '' ''

Expect 'PSCustomObject is rejected with its path' ([ordered]@{ child = [pscustomobject]@{ a = 1 } }) 'evidence.child' 'PSCustomObject'

$proc = [Diagnostics.Process]::GetCurrentProcess()
Expect 'Process-like object is rejected with its path' ([ordered]@{ list = @('ok', $proc) }) 'evidence.list[1]' 'System.Diagnostics.Process'

$self = @{ name = 'loop' }
$self['me'] = $self
Expect 'self-referencing hashtable is rejected with its path' $self 'evidence.me' 'cycle'

Expect 'enum value is rejected' ([ordered]@{ e = [DayOfWeek]::Monday }) 'evidence.e' 'DayOfWeek'
Expect 'non-string dictionary key is rejected' @{ 1 = 'x' } 'evidence' 'key'

if ($script:failed -gt 0) { Write-Host "$($script:failed) FAILED"; exit 1 }
Write-Host 'ALL OK'
