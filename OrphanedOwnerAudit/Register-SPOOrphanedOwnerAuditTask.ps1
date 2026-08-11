#Requires -Version 5.1
<#
.SYNOPSIS
    Registers (or updates) a Windows Task Scheduler task that runs
    Get-SPOOrphanedOwnerAudit.ps1 unattended, using app-only authentication.

.DESCRIPTION
    Companion script for Get-SPOOrphanedOwnerAudit.ps1. This does NOT run the
    audit itself — it only creates/updates the scheduled task definition.
    The audit script must already be configured for app-only auth
    ($AuthenticationMode = "AppOnly" and the AppOnly* variables populated in
    its CONFIGURATION section) before the scheduled run will succeed.

    This script must be run elevated (Administrator) since registering a
    scheduled task under a specific run-as account requires admin rights.

.PARAMETER ScriptPath
    Full path to Get-SPOOrphanedOwnerAudit.ps1.

.PARAMETER TaskName
    Name to give the scheduled task. Defaults to "SPO Orphaned Owner Audit".

.PARAMETER TriggerTime
    Daily run time, 24-hour "HH:mm" format. Defaults to "02:00".

.PARAMETER RunAsUser
    The account the task runs as, e.g. "DOMAIN\svc-spo-audit" or a managed
    service account. This account must:
        - Have the certificate's private key accessible (LocalMachine store,
          or its own CurrentUser store if the cert was installed there).
        - Be granted "Log on as a batch job" rights (the Task Scheduler UI/
          New-ScheduledTaskPrincipal handles this automatically in most cases).
        - Have the required PowerShell modules installed/available.
    If omitted, defaults to the SYSTEM account (only recommended if the
    certificate is installed in the LocalMachine store).

.PARAMETER OutputFolder
    Optional -OutputFolder value to pass through to the audit script.

.EXAMPLE
    .\Register-SPOOrphanedOwnerAuditTask.ps1 `
        -ScriptPath "C:\Source Control\FedAIRs\GCC High\Get-SPOOrphanedOwnerAudit.ps1" `
        -TaskName "SPO Orphaned Owner Audit" `
        -TriggerTime "02:00" `
        -RunAsUser "CONTOSO\svc-spo-audit"

.EXAMPLE
    # Remove a previously registered task.
    Unregister-ScheduledTask -TaskName "SPO Orphaned Owner Audit" -Confirm:$false
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path $_ })]
    [string]$ScriptPath,

    [string]$TaskName = "SPO Orphaned Owner Audit",

    [ValidatePattern('^([01]\d|2[0-3]):[0-5]\d$')]
    [string]$TriggerTime = "02:00",

    [string]$RunAsUser,

    [string]$OutputFolder,

    # Optional: pass through -IdentityProvider to the audit script (e.g.,
    # "ExchangeOnline" for Graph-blocked environments). Defaults to whatever
    # the audit script's own CONFIGURATION section specifies if omitted.
    [ValidateSet("MicrosoftGraph", "ExchangeOnline")]
    [string]$IdentityProvider
)

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This script must be run in an elevated (Administrator) PowerShell session to register a scheduled task."
}

# Build the argument list passed to pwsh.exe. -AuthenticationMode AppOnly is
# always forced here, since scheduled/unattended runs cannot respond to the
# interactive sign-in prompt used by "Interactive" mode.
$scriptArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$ScriptPath`"", '-AuthenticationMode', 'AppOnly')
if (-not [string]::IsNullOrWhiteSpace($OutputFolder)) {
    $scriptArgs += @('-OutputFolder', "`"$OutputFolder`"")
}
if (-not [string]::IsNullOrWhiteSpace($IdentityProvider)) {
    $scriptArgs += @('-IdentityProvider', $IdentityProvider)
}

# Prefer PowerShell 7+ (pwsh.exe) if present, since app-only cert auth for
# Connect-SPOService/Connect-MgGraph is documented and tested there; fall back
# to Windows PowerShell (powershell.exe) otherwise.
$pwshPath = (Get-Command pwsh.exe -ErrorAction SilentlyContinue).Source
if (-not $pwshPath) {
    $pwshPath = (Get-Command powershell.exe -ErrorAction SilentlyContinue).Source
}
if (-not $pwshPath) {
    throw "Could not locate pwsh.exe or powershell.exe on this machine."
}

$action  = New-ScheduledTaskAction -Execute $pwshPath -Argument ($scriptArgs -join ' ')
$trigger = New-ScheduledTaskTrigger -Daily -At $TriggerTime
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 15) -ExecutionTimeLimit (New-TimeSpan -Hours 6)

if ($RunAsUser) {
    $credential = Get-Credential -UserName $RunAsUser -Message "Enter the password for $RunAsUser (used to register the scheduled task's run-as account)"
    $principal = New-ScheduledTaskPrincipal -UserId $RunAsUser -LogonType Password -RunLevel Limited
}
else {
    Write-Warning "No -RunAsUser specified; registering task to run as SYSTEM. Ensure the certificate is installed in the LocalMachine certificate store."
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
}

$task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Unattended run of Get-SPOOrphanedOwnerAudit.ps1 (app-only auth)."

try {
    if ($RunAsUser) {
        Register-ScheduledTask -TaskName $TaskName -InputObject $task -User $RunAsUser -Password $credential.GetNetworkCredential().Password -Force | Out-Null
    }
    else {
        Register-ScheduledTask -TaskName $TaskName -InputObject $task -Force | Out-Null
    }
    Write-Host "Scheduled task '$TaskName' registered successfully." -ForegroundColor Green
    Write-Host "  Runs daily at $TriggerTime as: $(if ($RunAsUser) { $RunAsUser } else { 'SYSTEM' })" -ForegroundColor Green
    Write-Host "  Command: $pwshPath $($scriptArgs -join ' ')" -ForegroundColor Green
}
catch {
    throw "Failed to register scheduled task '$TaskName': $($_.Exception.Message)"
}
