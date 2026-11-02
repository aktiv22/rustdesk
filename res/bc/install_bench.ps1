<#
 BancControl: instalare pe un banc (rulează ca Administrator).
 Exemplu:  .\install_bench.ps1 -Installer .\BancControl-setup.exe -Config .\custom.txt -Password 'parola-lunga-aici'
 -Role este doar informativ: rolul vine din profilul semnat din custom.txt (bench / master / reception).
#>
param(
    [Parameter(Mandatory)][string]$Installer,
    [Parameter(Mandatory)][string]$Config,
    [Parameter(Mandatory)][string]$Password,
    [string]$InstallDir = "$env:ProgramFiles\BancControl",
    [string]$ServiceName = "BancControl"
)
$ErrorActionPreference = 'Stop'

function Fail($m) { Write-Error "EROARE: $m"; exit 1 }

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) { Fail "Rulează scriptul ca Administrator." }
if ([string]::IsNullOrWhiteSpace($Password) -or $Password.Length -lt 8) { Fail "Parola e goală sau prea scurtă (minim 8 caractere)." }
if (-not (Test-Path $Installer)) { Fail "Nu găsesc installerul: $Installer" }
if (-not (Test-Path $Config)) { Fail "Nu găsesc custom.txt: $Config" }

# Citare corectă pentru linia de comandă Windows (parole cu ", ', $, spații, \)
function ConvertTo-WinArg([string]$a) {
    $a = $a -replace '(\\*)"', '$1$1\"'
    $a = $a -replace '(\\+)$', '$1$1'
    return '"' + $a + '"'
}
function Run([string]$exe, [string[]]$argv) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $exe
    $psi.Arguments = ($argv | ForEach-Object { ConvertTo-WinArg $_ }) -join ' '
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $out = $p.StandardOutput.ReadToEnd(); $p.WaitForExit()
    return @{ Code = $p.ExitCode; Out = $out }
}

# 1) instalare silențioasă (instalează și serviciul)
$r = Run (Resolve-Path $Installer) @('--silent-install')
if ($r.Code -ne 0) { Fail "Instalarea a eșuat (cod $($r.Code))." }

$exe = Get-ChildItem $InstallDir -Filter '*.exe' -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'BancControl*' } | Select-Object -First 1
if (-not $exe) { Fail "Nu găsesc programul instalat în $InstallDir." }

# 2) profilul semnat lângă executabil; operatorii obișnuiți doar citesc
Copy-Item $Config (Join-Path $InstallDir 'custom.txt') -Force
& icacls $InstallDir /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' 'Users:(OI)(CI)RX' | Out-Null

# 3) serviciu cu pornire automată, repornit ca să citească profilul
$svc = Get-Service | Where-Object { $_.Name -like "$ServiceName*" } | Select-Object -First 1
if (-not $svc) { Fail "Nu găsesc serviciul $ServiceName." }
Set-Service -Name $svc.Name -StartupType Automatic
Restart-Service -Name $svc.Name

# 4) parola permanentă (după repornire, fără a fi afișată)
$r = Run $exe.FullName @('--password', $Password)
if ($r.Code -ne 0 -or $r.Out -notmatch 'Done') { Fail "Setarea parolei a eșuat: $($r.Out.Trim())" }
Write-Host "Gata. Serviciul $($svc.Name) pornește automat cu Windows."
