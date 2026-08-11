#Requires -Version 5.1
<#
.SYNOPSIS
    Audits SharePoint Online site ownership across a Microsoft 365 tenant and
    identifies orphaned, deleted, unresolved, or otherwise risky owners.

.DESCRIPTION
    This script enumerates all SharePoint Online sites in a tenant, collects
    ownership information from three sources:
        - The Owner property returned by Get-PnPTenantSite
        - Site Collection Administrators returned by Get-PnPSiteCollectionAdmin
        - Microsoft 365 Group owners (for group-connected sites)

    Each owner/admin identity is validated against Microsoft Entra ID to determine
    whether the account still exists, is a guest/external account, is a group
    principal, or cannot be resolved. Per-site governance risk is then evaluated
    (e.g., no active owners, only a single active owner, group-connected sites
    with no valid group owners).

    Identity validation for individual owners can run through either Microsoft
    Graph (most accurate) or Exchange Online (fallback for environments where
    Microsoft Graph identity/user-lookup permissions are unavailable) — see
    $DefaultIdentityProvider in config.ps1 (see config.sample.ps1). NOTE:
    Microsoft 365 Group owner enumeration always uses Microsoft Graph
    (Get-MgGroupOwner) — Get-UnifiedGroupLinks (the Exchange Online equivalent)
    only works in Windows PowerShell 5.1, not PowerShell 7. In ExchangeOnline
    mode, no
    second Graph connection is opened for this (ExchangeOnlineManagement and
    Microsoft.Graph.Authentication cannot reliably coexist in one PowerShell
    process — a known, unresolved conflict in Microsoft's own SDKs), so
    group-connected sites are reported with zero group owners in that mode.
    Use MicrosoftGraph mode (the default) for complete, accurate results.

    This script is READ-ONLY / AUDIT-ONLY. It does not remove, modify, or
    remediate any owner, admin, or group membership.

.NOTES
    Author:            Copilot CLI (assisted)
    Audit-only script: No write/remediation operations are performed.

    REQUIRED MODULES
        - PnP.PowerShell (always required — used for all SharePoint Online
          connectivity; Connect-SPOService/Microsoft.Online.SharePoint.PowerShell
          is NOT used, since it is unreliable under PowerShell 7+)
        - ImportExcel (used to write the combined multi-tab .xlsx report)
        - If $IdentityProvider = "MicrosoftGraph" (default): Microsoft.Graph
          (specifically Microsoft.Graph.Authentication, Microsoft.Graph.Users,
          Microsoft.Graph.Groups)
        - If $IdentityProvider = "ExchangeOnline": ExchangeOnlineManagement
          only. Microsoft.Graph is intentionally NOT loaded in this mode (see
          DESCRIPTION) — group-owned sites will show zero group owners.

    REQUIRED PERMISSIONS / SCOPES (delegated, least privilege)
        SharePoint (PnP.PowerShell) — requires your own Entra ID App Registration
        (Microsoft retired the shared PnP Management Shell app in Sept 2024):
        - Interactive mode: delegated SharePoint permission "AllSites.Read" is
          sufficient for this read-only audit (usually does not require admin
          consent). See $PnPClientId in config.ps1/config.sample.ps1 for
          registration steps.
        - AppOnly mode: application SharePoint permission "Sites.FullControl.All"
          (or narrower, tenant-documented), admin consented, using the same
          certificate as $AppOnlyCertificateThumbprint.

        MicrosoftGraph provider:
        - User.Read.All        (resolve users in Entra ID; Test-EntraUserExists)
        - Group.Read.All       (enumerate Microsoft 365 group owners, and verify
                                 whether group-principal owners/site collection
                                 admins have any active members)
        - Directory.Read.All   (optional; improves resolution of guests/orphans
                                 and group-principal detection in some tenants)
        ExchangeOnline provider:
        - An Exchange Online RBAC role such as "View-Only Recipients" or
          "View-Only Configuration" is sufficient to run Get-EXORecipient for
          individual owner identity resolution.
        - LIMITATION: group owner data will be incomplete (see DESCRIPTION) —
          prefer MicrosoftGraph mode unless you specifically cannot use it.

    REQUIRED SHAREPOINT ONLINE ROLE
        - SharePoint Administrator (or Global Administrator) to run
          Get-PnPTenantSite / Get-PnPSiteCollectionAdmin tenant-wide.

.EXAMPLE
    # Basic run against the tenant configured in config.ps1 (see config.sample.ps1
    # for first-time setup instructions).
    .\Get-SPOOrphanedOwnerAudit.ps1 -Verbose

.EXAMPLE
    # Limit the audit to a handful of sites first, to validate behavior safely.
    .\Get-SPOOrphanedOwnerAudit.ps1 -MaxSites 5 -Verbose

.EXAMPLE
    # Run against a single, specific site only (useful for testing/troubleshooting).
    .\Get-SPOOrphanedOwnerAudit.ps1 -SiteUrl "https://contoso.sharepoint.com/sites/Test" -Verbose

.EXAMPLE
    # Run and place reports in a specific folder.
    .\Get-SPOOrphanedOwnerAudit.ps1 -OutputFolder "C:\Audits\SPOOwnership" -Verbose

.EXAMPLE
    # Unattended / scheduled task run using app-only certificate authentication.
    # (Set $DefaultAuthenticationMode = "AppOnly" and the AppOnly variables in
    # config.ps1 first, or pass -AuthenticationMode AppOnly here.)
    .\Get-SPOOrphanedOwnerAudit.ps1 -AuthenticationMode AppOnly -InstallMissingModules -Verbose

.EXAMPLE
    # Graph-blocked environment: validate owners via Exchange Online instead
    # of Microsoft Graph. See the $DefaultIdentityProvider comment in
    # config.sample.ps1 for the accuracy limitation this introduces.
    .\Get-SPOOrphanedOwnerAudit.ps1 -IdentityProvider ExchangeOnline -Verbose

.NOTES
    SCHEDULING THIS SCRIPT (Windows Task Scheduler)

    Use the companion script Register-SPOOrphanedOwnerAuditTask.ps1 (in the
    same folder) to register a scheduled task that runs this script
    unattended via app-only certificate authentication:

        .\Register-SPOOrphanedOwnerAuditTask.ps1 `
            -ScriptPath "C:\Source Control\FedAIRs\GCC High\Get-SPOOrphanedOwnerAudit.ps1" `
            -TaskName "SPO Orphaned Owner Audit" `
            -TriggerTime "02:00" `
            -RunAsUser "DOMAIN\svc-spo-audit"

    This registers a task that runs:
        pwsh.exe -NoProfile -ExecutionPolicy Bypass -File "<ScriptPath>" -AuthenticationMode AppOnly

    Prerequisites for unattended/scheduled execution:
        - $DefaultAuthenticationMode = "AppOnly" and the AppOnly* variables
          populated in config.ps1 (or baked into the task's arguments).
        - The certificate's private key installed in the LocalMachine (or the
          run-as service account's CurrentUser) certificate store on the
          machine that will run the scheduled task.
        - The service/run-as account must have "Log on as a batch job" rights.
        - Required modules already installed for that account/machine, or run
          once interactively first with -InstallMissingModules.
#>

[CmdletBinding()]
param(
    # Optional cap on number of sites processed. Useful for a safe first test run.
    # Leave $null (default) to process all sites.
    [int]$MaxSites,

    # Optional: restrict the run to a single site (exact URL match), e.g. for
    # testing a specific known scenario without waiting on a full-tenant run.
    # Leave blank (default) to process all sites.
    [string]$SiteUrl,

    # Folder where CSV reports will be written. Defaults to a subfolder next to the script.
    [string]$OutputFolder = (Join-Path -Path $PSScriptRoot -ChildPath 'AuditReports'),

    # Overrides $DefaultAuthenticationMode from config.ps1, if supplied.
    # "Interactive" = admin sign-in (default). "AppOnly" = unattended, cert-based.
    [ValidateSet("Interactive", "AppOnly")]
    [string]$AuthenticationMode,

    # Overrides $DefaultIdentityProvider from config.ps1, if supplied.
    # "MicrosoftGraph" (default) or "ExchangeOnline" (Graph-free fallback).
    [ValidateSet("MicrosoftGraph", "ExchangeOnline")]
    [string]$IdentityProvider,

    # If set, missing required modules are installed automatically (CurrentUser scope)
    # after a one-time confirmation prompt. Suitable for unattended/scheduled runs
    # where the modules are already known-good, since -Confirm:$false-style
    # unattended installs still require this switch to be explicitly passed.
    [switch]$InstallMissingModules
)

# ---------------------------------------------------------------------------
# Self-healing PSModulePath: guarantees this process can see modules saved to
# the non-OneDrive local module folder, even if the User-level PSModulePath
# environment variable hasn't propagated to this session yet (Windows only
# broadcasts that change to NEW processes started after a full sign-out/sign-in
# or reboot — a merely-new terminal window is not always enough). Safe/no-op
# if the path is already present or doesn't exist yet.
$localModulePath = Join-Path -Path $env:LOCALAPPDATA -ChildPath 'PSModules'
if ((Test-Path -Path $localModulePath) -and ($env:PSModulePath -notlike "*$localModulePath*")) {
    $env:PSModulePath = "$localModulePath;$env:PSModulePath"
    Write-Verbose "Added '$localModulePath' to PSModulePath for this session."
}

#region ============================ CONFIGURATION ============================
# ---------------------------------------------------------------------------
# All tenant-specific settings (cloud environment, tenant name, identity
# provider, authentication mode, AppOnly/app-registration values) live in a
# separate config.ps1 file in this same folder -- NOT in this script. This
# keeps the script itself identical for every tenant, so pulling future
# updates never conflicts with or overwrites your tenant's settings.
#
# FIRST-TIME SETUP: copy config.sample.ps1 to config.ps1 in this folder, then
# edit config.ps1 with your tenant's values. See config.sample.ps1 for full
# documentation of each setting (cloud environment, tenant name, identity
# provider, authentication mode, AppOnly certificate settings, PnP client ID).
# config.ps1 is intentionally excluded from git (see .gitignore) since it will
# contain values specific to your tenant/app registration.
# ---------------------------------------------------------------------------

$configPath = Join-Path -Path $PSScriptRoot -ChildPath 'config.ps1'
if (-not (Test-Path -Path $configPath)) {
    throw "Configuration file not found: '$configPath'. Copy 'config.sample.ps1' to 'config.ps1' in this folder, then edit config.ps1 with your tenant's values before running this script."
}
. $configPath

# Defensive check: confirm config.ps1 actually defines every setting this
# script expects. Catches a stale/incomplete config.ps1 left over from an
# older version of config.sample.ps1, before it causes a more confusing
# failure deeper in the script.
$requiredConfigVars = @(
    'CloudEnvironment', 'TenantName', 'GraphUserPrincipalName',
    'DefaultIdentityProvider', 'DefaultAuthenticationMode',
    'AppOnlyClientId', 'AppOnlyTenantId', 'AppOnlyCertificateThumbprint',
    'PnPClientId'
)
$missingConfigVars = $requiredConfigVars | Where-Object { -not (Get-Variable -Name $_ -Scope Script -ErrorAction SilentlyContinue) }
if ($missingConfigVars) {
    throw "config.ps1 is missing required setting(s): $($missingConfigVars -join ', '). Compare your config.ps1 against the current config.sample.ps1 and add the missing value(s)."
}

#endregion =========================== CONFIGURATION ===========================

#region ============================ CLOUD MAPPING =============================
<#
    Get-CloudConfiguration
    WHY: Centralizes all cloud-specific endpoint/URL logic in one place so the
    rest of the script never has to branch on $CloudEnvironment directly. This
    is what makes the script portable between Commercial, GCC, and GCC High —
    an admin only ever needs to change config.ps1, never this script.
#>
function Get-CloudConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet("Commercial", "GCC", "GCCHigh")]
        [string]$CloudEnvironment,

        [Parameter(Mandatory)]
        [string]$TenantName
    )

    switch ($CloudEnvironment) {
        "GCCHigh" {
            return [pscustomobject]@{
                CloudEnvironment       = $CloudEnvironment
                GraphEnvironment       = "USGov"                      # Connect-MgGraph -Environment
                SPOAdminUrl            = "https://$TenantName-admin.sharepoint.us"
                SharePointSuffix       = ".sharepoint.us"
                ExchangeEnvironmentName = "O365USGovGCCHigh"          # Connect-ExchangeOnline -ExchangeEnvironmentName
                OnMicrosoftDomain      = "$TenantName.onmicrosoft.us" # Connect-ExchangeOnline -Organization (app-only)
                PnPAzureEnvironment    = "USGovernmentHigh"           # Connect-PnPOnline -AzureEnvironment
            }
        }
        "GCC" {
            # GCC uses the standard commercial multi-tenant Graph cloud and the
            # standard .sharepoint.com SPO domain, but the tenant itself is a
            # GCC-authorized tenant. Adjust here if your tenant documentation
            # specifies otherwise.
            return [pscustomobject]@{
                CloudEnvironment       = $CloudEnvironment
                GraphEnvironment       = "Global"
                SPOAdminUrl            = "https://$TenantName-admin.sharepoint.com"
                SharePointSuffix       = ".sharepoint.com"
                ExchangeEnvironmentName = "O365Default"
                OnMicrosoftDomain      = "$TenantName.onmicrosoft.com"
                PnPAzureEnvironment    = "USGovernment"
            }
        }
        "Commercial" {
            return [pscustomobject]@{
                CloudEnvironment       = $CloudEnvironment
                GraphEnvironment       = "Global"
                SPOAdminUrl            = "https://$TenantName-admin.sharepoint.com"
                SharePointSuffix       = ".sharepoint.com"
                ExchangeEnvironmentName = "O365Default"
                OnMicrosoftDomain      = "$TenantName.onmicrosoft.com"
                PnPAzureEnvironment    = "Production"
            }
        }
    }
}
#endregion =========================== CLOUD MAPPING ============================

#region ============================ CONNECTION ================================
<#
    Connect-M365Services
    WHY: Wraps Microsoft Graph + SharePoint Online connection logic together so
    the main script body only needs one call. Keeps cloud-specific connection
    parameters (e.g., -Environment for Graph, -Region for SPO) isolated here.
#>
function Connect-M365Services {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$CloudConfig,

        [Parameter(Mandatory)]
        [ValidateSet("Interactive", "AppOnly")]
        [string]$AuthenticationMode,

        [Parameter(Mandatory)]
        [ValidateSet("MicrosoftGraph", "ExchangeOnline")]
        [string]$IdentityProvider,

        [string]$GraphUserPrincipalName,

        # AppOnly-only parameters. Validated by the caller before this is invoked.
        [string]$AppOnlyClientId,
        [string]$AppOnlyTenantId,
        [string]$AppOnlyCertificateThumbprint,

        # Client ID of the Entra ID App Registration used for the PnP.PowerShell
        # SharePoint connection (both Interactive and AppOnly modes).
        [string]$PnPClientId
    )

    # ---- Identity provider connection (Microsoft Graph OR Exchange Online) ----
    if ($IdentityProvider -eq "MicrosoftGraph") {
        try {
            Write-Verbose "Connecting to Microsoft Graph (Environment: $($CloudConfig.GraphEnvironment), Mode: $AuthenticationMode)..."

            # Explicit import — see comment near the SharePoint Import-Module call
            # below for why this isn't left to command auto-load.
            Import-Module Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Groups -ErrorAction Stop

            if ($AuthenticationMode -eq "AppOnly") {
                # Certificate-based, non-interactive auth. Requires the Graph app
                # permissions (application, admin-consented): User.Read.All,
                # Group.Read.All, Directory.Read.All.
                $connectParams = @{
                    Environment           = $CloudConfig.GraphEnvironment
                    ClientId              = $AppOnlyClientId
                    TenantId              = $AppOnlyTenantId
                    CertificateThumbprint = $AppOnlyCertificateThumbprint
                    NoWelcome             = $true
                }
                Connect-MgGraph @connectParams -ErrorAction Stop | Out-Null
            }
            else {
                # Interactive delegated sign-in. Requires the Graph delegated scopes:
                # User.Read.All, Group.Read.All, Directory.Read.All (admin consent
                # may be required depending on tenant policy).
                $graphScopes = @("User.Read.All", "Group.Read.All", "Directory.Read.All")
                $connectParams = @{
                    Environment = $CloudConfig.GraphEnvironment
                    Scopes      = $graphScopes
                    NoWelcome   = $true
                }
                if (-not [string]::IsNullOrWhiteSpace($GraphUserPrincipalName)) {
                    # Hints the sign-in account for the interactive browser prompt.
                    Write-Verbose "Using account hint: $GraphUserPrincipalName"
                }
                Connect-MgGraph @connectParams -ErrorAction Stop | Out-Null
            }

            $context = Get-MgContext
            Write-Verbose "Connected to Microsoft Graph as $($context.Account) [Env: $($context.Environment)]"
        }
        catch {
            throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
        }
    }
    else {
        # Exchange Online handles individual owner/admin identity lookups
        # without Graph — useful when Graph identity/user-lookup permissions
        # are unavailable for that purpose.
        # LIMITATION: M365 Group owner enumeration requires Microsoft Graph
        # (Get-MgGroupOwner) no matter which provider is selected here —
        # Get-UnifiedGroupLinks (the Exchange Online equivalent) only works in
        # Windows PowerShell 5.1, not PowerShell 7. Deliberately NOT opening a
        # second Graph connection alongside Exchange Online in this process:
        # ExchangeOnlineManagement and Microsoft.Graph.Authentication cannot
        # reliably coexist in the same PowerShell process regardless of
        # connect order — this is a known, unresolved conflict in Microsoft's
        # own SDKs (MSAL assembly version clash), not something fixable here.
        # Net effect: in ExchangeOnline mode, group-owned sites will show zero
        # group owners (same as if the group had none) rather than crashing.
        # Use MicrosoftGraph mode (the default) for accurate group-owned site
        # results.
        Write-Warning "ExchangeOnline identity provider selected: Microsoft 365 Group owners cannot be enumerated in this mode (Exchange Online and Microsoft Graph cannot coexist in one PowerShell process). Group-connected sites will be reported with zero group owners. Use -IdentityProvider MicrosoftGraph for complete, accurate results."
        try {
            Write-Verbose "Connecting to Exchange Online (Environment: $($CloudConfig.ExchangeEnvironmentName), Mode: $AuthenticationMode)..."

            Import-Module ExchangeOnlineManagement -ErrorAction Stop

            if ($AuthenticationMode -eq "AppOnly") {
                # Certificate-based app-only auth. Requires the Exchange.ManageAsApp
                # application permission (admin consented) and an Exchange Online
                # RBAC role assigned to the app (e.g., "View-Only Recipients").
                Connect-ExchangeOnline -AppId $AppOnlyClientId `
                    -CertificateThumbprint $AppOnlyCertificateThumbprint `
                    -Organization $CloudConfig.OnMicrosoftDomain `
                    -ExchangeEnvironmentName $CloudConfig.ExchangeEnvironmentName `
                    -ShowBanner:$false -ErrorAction Stop
            }
            else {
                $connectParams = @{
                    ExchangeEnvironmentName = $CloudConfig.ExchangeEnvironmentName
                    ShowBanner              = $false
                }
                if (-not [string]::IsNullOrWhiteSpace($GraphUserPrincipalName)) {
                    $connectParams['UserPrincipalName'] = $GraphUserPrincipalName
                }
                Connect-ExchangeOnline @connectParams -ErrorAction Stop
            }

            Write-Verbose "Connected to Exchange Online."
        }
        catch {
            throw "Failed to connect to Exchange Online: $($_.Exception.Message)"
        }
    }

    # ---- SharePoint Online (PnP.PowerShell) ----
    # Uses Connect-PnPOnline instead of Connect-SPOService: the latter (from
    # Microsoft.Online.SharePoint.PowerShell) is only reliably supported in
    # Windows PowerShell 5.1, not PowerShell 7+, and throws "No valid OAuth 2.0
    # authentication session exists" under pwsh. PnP.PowerShell is fully
    # cross-platform and GCC High-aware via -AzureEnvironment.
    try {
        Write-Verbose "Connecting to SharePoint Online admin center: $($CloudConfig.SPOAdminUrl)"

        Import-Module PnP.PowerShell -ErrorAction Stop

        if ($AuthenticationMode -eq "AppOnly") {
            # Certificate-based app-only auth. The app registration must be
            # granted the SharePoint application permission Sites.FullControl.All
            # (or narrower, tenant-documented) and use the same certificate.
            $script:PnPAdminConnection = Connect-PnPOnline -Url $CloudConfig.SPOAdminUrl `
                -ClientId $PnPClientId `
                -Tenant $CloudConfig.OnMicrosoftDomain `
                -Thumbprint $AppOnlyCertificateThumbprint `
                -AzureEnvironment $CloudConfig.PnPAzureEnvironment `
                -ReturnConnection -ErrorAction Stop
        }
        else {
            # Interactive delegated sign-in via your own Entra ID App Registration
            # (see the $PnPClientId comment in config.sample.ps1 for setup steps).
            # Requires the delegated SharePoint permission AllSites.Read.
            $script:PnPAdminConnection = Connect-PnPOnline -Url $CloudConfig.SPOAdminUrl `
                -ClientId $PnPClientId `
                -Tenant $CloudConfig.OnMicrosoftDomain `
                -AzureEnvironment $CloudConfig.PnPAzureEnvironment `
                -Interactive -ReturnConnection -ErrorAction Stop
        }

        Write-Verbose "Connected to SharePoint Online."
    }
    catch {
        throw "Failed to connect to SharePoint Online ($($CloudConfig.SPOAdminUrl)): $($_.Exception.Message)"
    }
}
#endregion =========================== CONNECTION ================================

#region ============================ MODULE CHECKS ================================
<#
    Test-RequiredModules
    WHY: Fails fast with a clear, actionable message instead of cryptic
    "command not found" errors deep inside the audit loop. Does NOT auto-install
    modules, since silently installing modules tenant-wide can be unexpected
    or blocked by policy in locked-down admin workstations.
#>
function Test-RequiredModules {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet("MicrosoftGraph", "ExchangeOnline")]
        [string]$IdentityProvider,

        # When set, offers (or performs, if -Force) to install missing modules
        # via Save-Module to a local, non-OneDrive-synced folder instead of
        # only reporting them.
        [switch]$InstallMissingModules,

        # Skips the interactive confirmation prompt when installing. Intended
        # for unattended/scheduled runs where the admin has already validated
        # the modules should be auto-installed. Ignored unless
        # -InstallMissingModules is also set.
        [switch]$Force
    )

    # Modules needed always, plus modules specific to the selected identity
    # provider — only one of Microsoft.Graph.* or ExchangeOnlineManagement is
    # required at a time, so a Graph-blocked environment never needs Graph.
    $required = @(
        @{ Name = "PnP.PowerShell" },
        @{ Name = "ImportExcel" }
    )
    if ($IdentityProvider -eq "MicrosoftGraph") {
        $required += @{ Name = "Microsoft.Graph.Authentication" }
        $required += @{ Name = "Microsoft.Graph.Users" }
        $required += @{ Name = "Microsoft.Graph.Groups" }
    }
    else {
        $required += @{ Name = "ExchangeOnlineManagement" }
    }

    $missing = @()
    foreach ($mod in $required) {
        if (-not (Get-Module -ListAvailable -Name $mod.Name)) {
            $missing += $mod.Name
        }
    }

    if ($missing.Count -eq 0) {
        Write-Verbose "All required modules are present."
        return
    }

    Write-Host ""
    Write-Host "The following required PowerShell modules are not installed:" -ForegroundColor Yellow
    foreach ($m in $missing) { Write-Host "  - $m" -ForegroundColor Yellow }
    Write-Host ""

    # Modules are installed to a local, non-OneDrive-synced folder rather than
    # the default Documents-based CurrentUser scope, to avoid triggering
    # Purview/DLP false-positive alerts on synced module help files.
    $localModulePath = Join-Path $env:LOCALAPPDATA "PSModules"

    if (-not $InstallMissingModules) {
        Write-Host "Install them, for example:" -ForegroundColor Yellow
        foreach ($m in $missing) {
            Write-Host "  Save-Module -Name $m -Path `"$localModulePath`"" -ForegroundColor Cyan
        }
        Write-Host ""
        Write-Host "Tip: re-run this script with -InstallMissingModules to install them automatically." -ForegroundColor Yellow
        Write-Host ""
        throw "Required module(s) missing. Install the modules listed above, then re-run this script."
    }

    if (-not (Test-Path $localModulePath)) {
        New-Item -Path $localModulePath -ItemType Directory -Force | Out-Null
    }
    $userModulePath = [Environment]::GetEnvironmentVariable('PSModulePath', 'User')
    if (-not $userModulePath -or $userModulePath -notlike "*$localModulePath*") {
        $newUserPath = if ($userModulePath) { "$localModulePath;$userModulePath" } else { $localModulePath }
        [Environment]::SetEnvironmentVariable('PSModulePath', $newUserPath, 'User')
    }
    if ($env:PSModulePath -notlike "*$localModulePath*") {
        $env:PSModulePath = "$localModulePath;$env:PSModulePath"
    }

    # -InstallMissingModules was specified: install after confirmation (or
    # immediately if -Force, e.g. for scheduled/unattended runs).
    foreach ($m in $missing) {
        $doInstall = $Force
        if (-not $doInstall) {
            $response = Read-Host "Install missing module '$m' now to '$localModulePath'? (Y/N)"
            $doInstall = ($response -match '^(y|yes)$')
        }

        if ($doInstall) {
            try {
                Write-Host "Installing module '$m' to '$localModulePath'..." -ForegroundColor Cyan
                Save-Module -Name $m -Path $localModulePath -Force -ErrorAction Stop
                Write-Host "Installed '$m'." -ForegroundColor Green
            }
            catch {
                throw "Failed to install required module '$m': $($_.Exception.Message)"
            }
        }
        else {
            throw "Required module '$m' was not installed. Re-run and confirm installation, or install it manually."
        }
    }

    Write-Verbose "All required modules are now present."
}
#endregion =========================== MODULE CHECKS ================================

#region ============================ HELPERS ================================
<#
    Normalize-SPOLoginName
    WHY: Get-SPOUser returns claims-based login names (e.g.
    "i:0#.f|membership|user@domain.com") for member users, and different
    prefixes for groups/apps/external users. This function extracts a usable
    UPN when possible and classifies the principal type so downstream logic
    knows whether it's even meaningful to look the account up in Entra ID.
#>
function Normalize-SPOLoginName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$LoginName
    )

    $result = [pscustomobject]@{
        RawLoginName  = $LoginName
        UPN           = $null
        PrincipalType = "Unknown"
        # Entra ID object GUID of the group, when the claim format actually
        # encodes one (only true for the two GroupPrincipal branches below
        # that set it). Populated so the caller can look up whether the
        # group has any active members/owners.
        GroupObjectId = $null
        # For the c:0o.c|federateddirectoryclaimprovider|<guid>_o / _m claim
        # format specifically: this GUID is an M365 Group's ID, and the
        # suffix says whether the claim represents that group's OWNERS
        # ("Owner") or MEMBERS ("Member") sub-role -- NOT the group itself.
        # $null for the c:0t.c|tenant|<guid> format, which (confirmed via
        # live testing against a real tenant) represents a plain, directly
        # queryable Entra ID security group's own membership.
        GroupRole     = $null
    }

    if ([string]::IsNullOrWhiteSpace($LoginName)) {
        return $result
    }

    # Standard member user claim: i:0#.f|membership|user@domain.com
    if ($LoginName -match '^i:0#\.f\|membership\|(?<upn>.+)$') {
        $result.UPN = $Matches['upn']
        $result.PrincipalType = "Member"
        return $result
    }

    # Guest/external user claim (B2B): i:0#.f|membership|guestUser_domain.com#ext#@tenant...
    if ($LoginName -match '^i:0#\.f\|membership\|.*#ext#') {
        $result.UPN = $LoginName -replace '^i:0#\.f\|membership\|', ''
        $result.PrincipalType = "ExternalOrGuest"
        return $result
    }

    # c:0o.c|federateddirectoryclaimprovider|<guid>[_o|_m] -- confirmed via
    # live testing to represent a Microsoft 365 Group's OWNERS ("_o") or
    # MEMBERS ("_m") sub-role, where <guid> is the M365 Group's own object
    # ID (frequently the SAME group already backing a group-connected site,
    # i.e. the same ID as $site.GroupId). This is NOT an independent,
    # directly-queryable group -- the correct Graph check depends on the
    # suffix (Get-MgGroupOwner for "_o", Get-MgGroupMember for "_m"). No
    # suffix at all is unresolved territory (not observed in testing); left
    # unverified/Valid rather than guessing.
    if ($LoginName -match '^c:0o\.c\|federateddirectoryclaimprovider\|(?<groupid>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?<suffix>_[a-z])?$') {
        $result.PrincipalType = "GroupPrincipal"
        switch ($Matches['suffix']) {
            "_o" { $result.GroupObjectId = $Matches['groupid']; $result.GroupRole = "Owner" }
            "_m" { $result.GroupObjectId = $Matches['groupid']; $result.GroupRole = "Member" }
            default { } # unrecognized/no suffix: leave unverified
        }
        return $result
    }

    # c:0t.c|tenant|<guid> -- confirmed via live testing to represent a
    # plain, directly-queryable Entra ID security group's own object ID (not
    # a generic tenant-wide "Everyone" claim, despite some older/generic
    # documentation suggesting otherwise -- always verify claim formats
    # against your own tenant if this script behaves unexpectedly). Its own
    # membership can be checked directly via Get-MgGroupMember.
    if ($LoginName -match '^c:0t\.c\|tenant\|(?<groupid>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$') {
        $result.PrincipalType = "GroupPrincipal"
        $result.GroupObjectId = $Matches['groupid']
        $result.GroupRole = "Member"
        return $result
    }

    # SharePoint's built-in tenant-wide "Everyone except external users"
    # claim (spo-grid-all-users/<tenantId>) is not a real, queryable Entra ID
    # group object -- there is no GroupObjectId here, so membership can't be
    # verified and this remains treated as unverified/Valid, same as before.
    if ($LoginName -match '^c:0-\.f\|rolemanager\|') {
        $result.PrincipalType = "GroupPrincipal"
        return $result
    }

    # SharePoint app / system account principal.
    if ($LoginName -match '^i:0i\.t\|' -or $LoginName -match 'app@sharepoint') {
        $result.PrincipalType = "AppOrSystem"
        return $result
    }

    # Plain UPN/email with no claims prefix at all. Get-SPOSite's .Owner
    # property (unlike Get-SPOUser's LoginName) returns a bare UPN string
    # rather than a claims-encoded login, so this must be treated as a
    # normal member account or it silently never gets an identity lookup.
    if ($LoginName -notmatch '\|' -and $LoginName -match '^[^@\s]+@[^@\s]+\.[^@\s]+$') {
        $result.UPN = $LoginName
        $result.PrincipalType = "Member"
        return $result
    }

    # Fallback: unrecognized claim format.
    $result.PrincipalType = "Unknown"
    return $result
}

<#
    Invoke-WithRetry
    WHY: Get-MgUser/Get-EXORecipient calls run in a tight loop across a large
    tenant; transient errors (Graph throttling/429, brief service blips) are
    expected at that volume and should NOT be treated the same as a
    confirmed "account not found". Retries with exponential backoff only for
    errors that look transient; anything else (including a genuine "not
    found") is rethrown immediately on the first attempt.
#>
function Invoke-WithRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [int]$MaxAttempts = 4,

        [int]$InitialDelayMs = 500
    )

    $attempt = 0
    $delay = $InitialDelayMs
    while ($true) {
        $attempt++
        try {
            return & $ScriptBlock
        }
        catch {
            $errMsg = $_.Exception.Message
            $isTransient = $errMsg -match "429|TooManyRequests|throttl|timed? ?out|temporarily unavailable|ServiceUnavailable|gateway|connection.*reset|error occurred while sending"
            if (-not $isTransient -or $attempt -ge $MaxAttempts) {
                throw
            }
            Write-Verbose "Invoke-WithRetry: transient error on attempt $attempt/$MaxAttempts - '$errMsg' - retrying in ${delay}ms"
            Start-Sleep -Milliseconds $delay
            $delay = $delay * 2
        }
    }
}

<#
    Test-EXORecipientExists
    WHY: Graph-free alternative to Test-EntraUserExists for environments where
    Microsoft Graph is blocked/unreachable. Exchange Online recipients are
    synced from Entra ID, so a missing recipient is a reasonable proxy for a
    deleted/orphaned account — with the important limitation documented below.

    LIMITATION: only mail-enabled objects are visible via Get-EXORecipient. A
    valid Entra ID account with no mailbox/license (e.g., an unlicensed guest)
    will NOT be found here and will be misclassified as "DeletedFromEntra".
    Prefer Test-EntraUserExists (MicrosoftGraph mode) when this matters.
#>
function Test-EXORecipientExists {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName
    )

    $outcome = [pscustomobject]@{
        Exists            = $false
        Status            = "Unresolved"
        EntraObjectId     = $null
        UserPrincipalName = $UserPrincipalName
        DisplayName       = $null
        ErrorDetail       = $null
    }

    try {
        $recipient = Invoke-WithRetry -ScriptBlock { Get-EXORecipient -Identity $UserPrincipalName -ErrorAction Stop }
        if ($recipient) {
            $outcome.Exists = $true
            $outcome.Status = "Valid"
            # ExternalDirectoryObjectId is the recipient's Entra ID object GUID.
            $outcome.EntraObjectId = $recipient.ExternalDirectoryObjectId
            $outcome.DisplayName = $recipient.DisplayName
        }
    }
    catch {
        $errMsg = $_.Exception.Message
        $outcome.ErrorDetail = $errMsg
        if ($errMsg -match "wasn't found|couldn't be found|doesn't exist|not found|NotFound") {
            # NOTE: this also fires for valid-but-mailbox-less accounts (see
            # function-level LIMITATION comment above).
            $outcome.Status = "DeletedFromEntra"
        }
        else {
            $outcome.Status = "Unresolved"
            Write-Verbose "Test-EXORecipientExists: could not resolve '$UserPrincipalName' - $errMsg"
        }
    }

    return $outcome
}

<#
    Test-EntraUserExists
    WHY: MicrosoftGraph-mode counterpart to Test-EXORecipientExists. Looks up
    the account directly in Entra ID via Get-MgUser, so (unlike the Exchange
    path) unlicensed/mailbox-less guest accounts are still correctly resolved
    as Valid rather than being misclassified as deleted.
#>
function Test-EntraUserExists {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName
    )

    $outcome = [pscustomobject]@{
        Exists            = $false
        Status            = "Unresolved"
        EntraObjectId     = $null
        UserPrincipalName = $UserPrincipalName
        DisplayName       = $null
        ErrorDetail       = $null
    }

    try {
        $user = Invoke-WithRetry -ScriptBlock { Get-MgUser -UserId $UserPrincipalName -Property "id,displayName,userPrincipalName" -ErrorAction Stop }
        if ($user) {
            $outcome.Exists = $true
            $outcome.Status = "Valid"
            $outcome.EntraObjectId = $user.Id
            $outcome.DisplayName = $user.DisplayName
        }
    }
    catch {
        $errMsg = $_.Exception.Message
        $outcome.ErrorDetail = $errMsg
        if ($errMsg -match "Request_ResourceNotFound|does not exist|NotFound|couldn't be found|wasn't found") {
            $outcome.Status = "DeletedFromEntra"
        }
        else {
            $outcome.Status = "Unresolved"
            Write-Verbose "Test-EntraUserExists: could not resolve '$UserPrincipalName' - $errMsg"
        }
    }

    return $outcome
}

<#
    Test-EntraGroupStatus
    WHY: Closes a real gap found while reviewing this script -- a SharePoint
    site whose Owner property or Site Collection Admin is a *group* (rather
    than a user) was previously always marked "Valid" with no further check.
    A group with zero active members/owners provides no real ownership at
    all, which is exactly the kind of orphaned-ownership risk this audit
    exists to catch. This function checks whether the group itself still
    exists in Entra ID, and if so, whether it currently has any members (or
    owners, for claims that specifically represent an M365 Group's owner
    sub-role -- see the -Role parameter).

    LIMITATION: only meaningful for group claims that resolve to a real Entra
    ID GroupObjectId (see Normalize-SPOLoginName); requires MicrosoftGraph as
    the identity provider (Get-MgGroup/Get-MgGroupOwner/Get-MgGroupMember use
    the same Group.Read.All permission already required for M365-Group-
    connected site checks -- no new consent is needed).
#>
function Test-EntraGroupStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$GroupObjectId,

        # "Member" (default) checks Get-MgGroupMember; "Owner" checks
        # Get-MgGroupOwner instead -- used for the c:0o.c|...|<guid>_o claim
        # format, which represents an M365 Group's OWNERS specifically, not
        # its general membership.
        [ValidateSet("Member", "Owner")]
        [string]$Role = "Member"
    )

    $outcome = [pscustomobject]@{
        Status        = "Unresolved"
        MemberCount   = $null
        ErrorDetail   = $null
        # Only populated when $Role -eq "Member" (a plain, directly-assigned
        # security group). Tracks a distinct, lower-severity governance gap:
        # the group still has active members (so SharePoint access via this
        # assignment works fine), but has zero owners, so nobody can manage
        # its membership going forward. Not applicable when $Role -eq
        # "Owner", since that claim format already IS an owner-list check.
        GroupOwnerCount    = $null
        HasNoGroupOwners   = $false
    }

    try {
        $group = Invoke-WithRetry -ScriptBlock { Get-MgGroup -GroupId $GroupObjectId -ErrorAction Stop }
        if (-not $group) {
            $outcome.Status = "DeletedFromEntra"
            return $outcome
        }
    }
    catch {
        $errMsg = $_.Exception.Message
        $outcome.ErrorDetail = $errMsg
        if ($errMsg -match "Request_ResourceNotFound|does not exist|NotFound|couldn't be found|wasn't found") {
            $outcome.Status = "DeletedFromEntra"
        }
        else {
            $outcome.Status = "Unresolved"
            Write-Verbose "Test-EntraGroupStatus: could not resolve group '$GroupObjectId' - $errMsg"
        }
        return $outcome
    }

    try {
        # -All ensures the true count is seen rather than just the first
        # page. This audit only needs to know whether the group/role is
        # empty, not its exact size, so a plain count is sufficient.
        $members = if ($Role -eq "Owner") {
            Invoke-WithRetry -ScriptBlock { Get-MgGroupOwner -GroupId $GroupObjectId -All -ErrorAction Stop }
        }
        else {
            Invoke-WithRetry -ScriptBlock { Get-MgGroupMember -GroupId $GroupObjectId -All -ErrorAction Stop }
        }
        $memberCount = ($members | Measure-Object).Count
        $outcome.MemberCount = $memberCount
        $outcome.Status = if ($memberCount -eq 0) { "EmptyGroup" } else { "Valid" }
    }
    catch {
        $errMsg = $_.Exception.Message
        $outcome.ErrorDetail = $errMsg
        $outcome.Status = "Unresolved"
        Write-Verbose "Test-EntraGroupStatus: could not enumerate ${Role}s for group '$GroupObjectId' - $errMsg"
    }

    # Secondary, lower-severity governance check: does this group (checked
    # as a plain security group, i.e. Role -eq "Member") have any owners of
    # its own? Only meaningful if the member check above actually succeeded
    # (Valid or EmptyGroup) -- if the group lookup itself failed/was
    # unresolved, skip this to avoid a confusing partial result.
    if ($Role -eq "Member" -and $outcome.Status -in @("Valid", "EmptyGroup")) {
        try {
            $owners = Invoke-WithRetry -ScriptBlock { Get-MgGroupOwner -GroupId $GroupObjectId -All -ErrorAction Stop }
            $ownerCount = ($owners | Measure-Object).Count
            $outcome.GroupOwnerCount = $ownerCount
            $outcome.HasNoGroupOwners = ($ownerCount -eq 0)
        }
        catch {
            Write-Verbose "Test-EntraGroupStatus: could not enumerate owners for group '$GroupObjectId' - $($_.Exception.Message)"
        }
    }

    return $outcome
}

<#
    Resolve-IdentityStatus
    WHY: Single dispatch point used everywhere in the main loop, so the rest
    of the script never needs to know or care whether MicrosoftGraph or
    ExchangeOnline is doing the actual identity validation. Also the single
    place that times each lookup, so MicrosoftGraph vs ExchangeOnline
    throughput can be compared using the same instrumentation regardless of
    which of the three call sites in the main loop triggered it.
#>
function Resolve-IdentityStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory)]
        [ValidateSet("MicrosoftGraph", "ExchangeOnline")]
        [string]$IdentityProvider
    )

    if ($script:IdentityLookupStopwatch) { $script:IdentityLookupStopwatch.Start() }
    try {
        if ($IdentityProvider -eq "ExchangeOnline") {
            return Test-EXORecipientExists -UserPrincipalName $UserPrincipalName
        }
        else {
            return Test-EntraUserExists -UserPrincipalName $UserPrincipalName
        }
    }
    finally {
        if ($script:IdentityLookupStopwatch) {
            $script:IdentityLookupStopwatch.Stop()
            $script:IdentityLookupCount++
        }
    }
}

<#
    Get-AccountStatusNote
    WHY: DisplayName/EntraObjectId are only populated when the identity lookup
    succeeds — for a genuinely departed account, that lookup fails, so those
    fields end up blank by design, not because data was missed. Surfacing a
    consistent explanation here (rather than only for some rows) avoids the
    reviewer confusion of "why does this row have a name and this one doesn't?"
    For "Unresolved" rows specifically, appends the actual underlying error
    message (when available) so it's possible to tell a genuine lookup
    problem apart from a false positive (e.g., transient throttling) without
    needing to re-run with -Verbose.
#>
function Get-AccountStatusNote {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccountStatus,

        [string]$ErrorDetail,

        # Set when this row's owner/admin is a GroupPrincipal, so the wording
        # correctly says "group" instead of "account" for the shared status
        # values (DeletedFromEntra/Unresolved) reused by both users and groups.
        [switch]$IsGroupPrincipal,

        # Set when this row's group has active members (access still works)
        # but zero owners of its own (nobody can manage its membership going
        # forward). A separate, lower-severity governance note appended
        # regardless of AccountStatus (Valid or EmptyGroup).
        [switch]$GroupHasNoOwners
    )

    $note = ""
    switch ($AccountStatus) {
        "DeletedFromEntra" {
            if ($IsGroupPrincipal) {
                $note = "This owner is a security/Microsoft 365 group that no longer exists in Entra ID. Display name/Entra object ID are unavailable because the directory lookup found no matching group; only the login captured at audit time identifies this owner."
            }
            else {
                $note = "Account no longer exists in Entra ID (or no longer has a mailbox, if using ExchangeOnline identity provider). Display name/Entra object ID are unavailable because the directory lookup found no matching record; only the login/UPN captured at audit time identifies this owner."
            }
        }
        "EmptyGroup" {
            $note = "This owner is a security/Microsoft 365 group that currently has zero members, so no one can actually act as owner through this assignment. Add at least one active member to the group, or assign a different owner directly."
            if (-not [string]::IsNullOrWhiteSpace($ErrorDetail)) {
                $note = "$note Underlying error: $ErrorDetail"
            }
        }
        "Unresolved" {
            if ($IsGroupPrincipal) {
                $note = "This owner is a group whose membership could not be verified (e.g., Microsoft Graph is unavailable in ExchangeOnline identity-provider mode, a lookup error occurred, or this is an 'Everyone'/tenant-wide or SharePoint permission-level claim that has no queryable Entra ID group behind it). This does NOT necessarily mean the group is empty -- re-verify manually before taking action."
            }
            else {
                $note = "Identity could not be resolved (e.g., malformed login, unsupported principal type, or a lookup error). Display name/Entra object ID are unavailable; only the login/UPN captured at audit time identifies this owner. This does NOT necessarily mean the account is deleted -- re-verify before taking action."
            }
            if (-not [string]::IsNullOrWhiteSpace($ErrorDetail)) {
                $note = "$note Underlying error: $ErrorDetail"
            }
        }
    }

    if ($GroupHasNoOwners) {
        $governanceNote = "This group currently has zero owners of its own -- SharePoint access via its members still works today, but nobody can add/remove members going forward. Nominate at least one group owner to keep it maintainable."
        $note = if ([string]::IsNullOrWhiteSpace($note)) { $governanceNote } else { "$note $governanceNote" }
    }

    return $note
}

<#
    Get-SiteCollectionAdmins
    WHY: Wraps Get-SPOUser with -Limit All and filters to site collection
    admins only, isolating SPO-specific cmdlet quirks from the main loop.
#>
function Get-SiteCollectionAdmins {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SiteUrl
    )

    # Reuses the cached admin-center connection's token against this specific
    # site (no re-prompting) via -Connection/-ReturnConnection, since PnP.PowerShell
    # requires a connection whose context matches the target site collection.
    $siteConnection = Connect-PnPOnline -Url $SiteUrl -Connection $script:PnPAdminConnection -ReturnConnection -ErrorAction Stop
    $admins = Get-PnPSiteCollectionAdmin -Connection $siteConnection -ErrorAction Stop

    # Normalize to the shape the caller expects (LoginName, DisplayName), matching
    # the previous Get-SPOUser-based output so downstream code needs no changes.
    return $admins | ForEach-Object {
        [pscustomobject]@{
            LoginName   = $_.LoginName
            DisplayName = $_.Title
        }
    }
}

<#
    Get-M365GroupOwners
    WHY: Isolates the Graph call + pagination handling for group owners so
    callers don't need to know about Graph's owner object shape (which
    returns a directoryObject that must be resolved to a user).
#>
function Get-M365GroupOwners {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$GroupId
    )

    try {
        $owners = Get-MgGroupOwner -GroupId $GroupId -All -ErrorAction Stop
        return $owners
    }
    catch {
        Write-Verbose "Get-M365GroupOwners: failed for GroupId '$GroupId' - $($_.Exception.Message)"
        return @()
    }
}

<#
    Get-GroupOwners
    WHY: Always uses Microsoft Graph (Get-MgGroupOwner) to enumerate M365
    Group owners, regardless of $IdentityProvider. Get-UnifiedGroupLinks (the
    Exchange Online equivalent) only works in Windows PowerShell 5.1 -- it is
    never imported into a PowerShell 7 (pwsh) Exchange Online V3 session.
    NOTE: In ExchangeOnline mode, no Graph connection is established (see
    Connect-M365Services) because ExchangeOnlineManagement and
    Microsoft.Graph.Authentication cannot reliably coexist in one PowerShell
    process (known, unresolved MSAL assembly conflict in Microsoft's SDKs).
    Get-M365GroupOwners's own try/catch handles the resulting "not connected"
    failure gracefully, returning an empty list rather than crashing -- so
    group-owned sites simply show zero group owners in that mode. Individual
    owner/admin identity resolution (Resolve-IdentityStatus) is unaffected
    and still honors $IdentityProvider.
#>
function Get-GroupOwners {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$GroupId,

        [Parameter(Mandatory)]
        [ValidateSet("MicrosoftGraph", "ExchangeOnline")]
        [string]$IdentityProvider
    )

    $normalized = [System.Collections.Generic.List[object]]::new()

    foreach ($owner in (Get-M365GroupOwners -GroupId $GroupId)) {
        # Group owners come back as directoryObjects; the additional
        # properties bag typically includes userPrincipalName/displayName
        # for user-type owners.
        $normalized.Add([pscustomobject]@{
            DisplayName       = $owner.AdditionalProperties['displayName']
            UserPrincipalName = $owner.AdditionalProperties['userPrincipalName']
            EntraObjectId     = $owner.Id
        })
    }

    return $normalized
}
#endregion =========================== HELPERS ================================

#region ============================ RESULT COLLECTION ================================
# Using generic Lists instead of array += for performance in large tenants.
$script:OwnerResults  = [System.Collections.Generic.List[object]]::new()
$script:SiteSummaries = [System.Collections.Generic.List[object]]::new()
$script:ErrorLog      = [System.Collections.Generic.List[object]]::new()
# Sites where Get-PnPSiteCollectionAdmin was denied because the signed-in
# account isn't a site collection admin on that specific site (tenant-level
# SharePoint Administrator does not grant this). Tracked separately from
# $script:ErrorLog because it's an expected, known access gap rather than a
# processing failure, and Add-SiteSummary needs to know about it so it
# doesn't misclassify "no SCA data" as "confirmed zero owners".
$script:SiteCollectionAdminAccessDeniedSites = [System.Collections.Generic.List[string]]::new()

<#
    Add-OwnerResult
    WHY: Single, consistent place to shape each owner-check row before it's
    added to the in-memory results collection (and eventually exported).
#>
function Add-OwnerResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SiteUrl,
        [string]$SiteTitle,
        [string]$SiteTemplate,
        [string]$GroupId,
        [Parameter(Mandatory)][string]$OwnerSource,
        [string]$DisplayName,
        [string]$LoginName,
        [string]$UserPrincipalName,
        [Parameter(Mandatory)][string]$PrincipalType,
        [string]$EntraObjectId,
        [Parameter(Mandatory)][string]$AccountStatus,
        [string]$RiskFlag = "",
        [string]$Notes = "",
        # True when this row is a group-principal owner/admin whose
        # underlying security group has active members (so SharePoint access
        # via this assignment still works) but zero group owners (so nobody
        # can manage/update that group's membership going forward). This is
        # a lower-severity governance concern, distinct from AccountStatus
        # (which tracks whether the assignment currently grants real access).
        [bool]$GroupOwnerGovernanceRisk = $false
    )

    $script:OwnerResults.Add([pscustomobject]@{
        SiteUrl           = $SiteUrl
        SiteTitle         = $SiteTitle
        SiteTemplate      = $SiteTemplate
        GroupId           = $GroupId
        OwnerSource       = $OwnerSource
        DisplayName       = $DisplayName
        LoginName         = $LoginName
        UserPrincipalName = $UserPrincipalName
        PrincipalType     = $PrincipalType
        EntraObjectId     = $EntraObjectId
        AccountStatus     = $AccountStatus
        RiskFlag          = $RiskFlag
        Notes             = $Notes
        GroupOwnerGovernanceRisk = $GroupOwnerGovernanceRisk
    })
}

<#
    Add-SiteSummary
    WHY: Aggregates the per-owner rows for a single site into one governance
    summary row, applying the risk rules described in the project requirements.
#>
function Add-SiteSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SiteUrl,
        [string]$GroupId,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$SiteOwnerRows,
        # True when Get-SiteCollectionAdmins was denied access for this site (the
        # signed-in account isn't a site collection admin here). When set, a
        # zero-active-owner result is NOT a confirmed "no owners" finding - it may
        # simply mean this data source couldn't be checked, so risk is downgraded
        # from Critical rather than reported as a false-positive emergency.
        [switch]$SiteCollectionAdminDataUnavailable
    )

    $activeOwners     = $SiteOwnerRows | Where-Object { $_.AccountStatus -eq "Valid" }
    $deletedOwners     = $SiteOwnerRows | Where-Object { $_.AccountStatus -eq "DeletedFromEntra" }
    $unresolvedOwners = $SiteOwnerRows | Where-Object { $_.AccountStatus -eq "Unresolved" }
    # Group-principal owners/admins confirmed (via Test-EntraGroupStatus) to
    # currently have zero active members -- these do NOT count as "Valid"
    # above, so a site whose only owner is an empty group correctly falls
    # into HasNoActiveOwnersRisk below rather than being silently trusted.
    $emptyGroupOwners = $SiteOwnerRows | Where-Object { $_.AccountStatus -eq "EmptyGroup" }
    $groupPrincipals  = $SiteOwnerRows | Where-Object { $_.PrincipalType -eq "GroupPrincipal" -and $_.AccountStatus -eq "Valid" }
    $groupOwnerRows   = $SiteOwnerRows | Where-Object { $_.OwnerSource -eq "M365GroupOwner" }
    $activeGroupOwners = $groupOwnerRows | Where-Object { $_.AccountStatus -eq "Valid" }

    $activeOwnerCount     = ($activeOwners | Measure-Object).Count
    $deletedOwnerCount    = ($deletedOwners | Measure-Object).Count
    $unresolvedOwnerCount = ($unresolvedOwners | Measure-Object).Count
    $emptyGroupOwnerCount = ($emptyGroupOwners | Measure-Object).Count

    # Rows where the group has active members (access works) but zero
    # owners of its own (nobody can manage its membership going forward) --
    # a separate, lower-severity governance concern from the above.
    $groupOwnerGovernanceRiskRows = $SiteOwnerRows | Where-Object { $_.GroupOwnerGovernanceRisk -eq $true }
    $groupOwnerGovernanceRiskCount = ($groupOwnerGovernanceRiskRows | Measure-Object).Count

    $hasSingleOwnerRisk    = ($activeOwnerCount -eq 1)
    $hasNoActiveOwnersRisk = ($activeOwnerCount -eq 0)
    $hasEmptyGroupRisk     = ($emptyGroupOwnerCount -gt 0)
    $hasGroupOwnerRisk     = (-not [string]::IsNullOrWhiteSpace($GroupId)) -and (($activeGroupOwners | Measure-Object).Count -eq 0)
    $hasGroupPrincipalAdminRisk = (($groupPrincipals | Measure-Object).Count -gt 0)
    $hasGroupOwnerGovernanceRisk = ($groupOwnerGovernanceRiskCount -gt 0)

    # Overall risk level: simple tiered classification an admin can triage by.
    $overallRisk = "Low"
    $recommendedAction = "No action needed."

    if ($hasNoActiveOwnersRisk -and $SiteCollectionAdminDataUnavailable) {
        $overallRisk = "Unknown"
        $recommendedAction = "Site collection admin data could not be checked (insufficient permissions on this site) and no other active owner was found. Verify ownership manually or re-run with an account that has site collection admin rights here."
    }
    elseif ($hasNoActiveOwnersRisk -and $hasEmptyGroupRisk) {
        $overallRisk = "Critical"
        $recommendedAction = "Assign at least one active owner immediately; the current owner(s) is/are a security or Microsoft 365 group with zero active members, so no one can currently manage this site through that assignment."
    }
    elseif ($hasNoActiveOwnersRisk) {
        $overallRisk = "Critical"
        $recommendedAction = "Assign at least one active owner immediately; site currently has no valid, resolvable owners."
    }
    elseif ($hasEmptyGroupRisk) {
        $overallRisk = "High"
        $recommendedAction = "One or more owners/admins is a security or Microsoft 365 group with zero active members. Another active owner exists, but add members to the group (or assign a different owner) to close this gap."
    }
    elseif ($hasGroupOwnerRisk -and $hasSingleOwnerRisk) {
        $overallRisk = "High"
        $recommendedAction = "Add additional group owners and review site collection admin coverage."
    }
    elseif ($hasGroupOwnerRisk) {
        $overallRisk = "High"
        $recommendedAction = "Assign at least one valid owner to the connected Microsoft 365 Group."
    }
    elseif ($hasSingleOwnerRisk) {
        $overallRisk = "Medium"
        $recommendedAction = "Consider adding a second site collection admin to avoid a single point of failure."
    }
    elseif ($hasGroupPrincipalAdminRisk) {
        $overallRisk = "Medium"
        $recommendedAction = "Review group-based site collection admin assignment; confirm the group has valid owners/members."
    }
    elseif ($deletedOwnerCount -gt 0 -or $unresolvedOwnerCount -gt 0) {
        $overallRisk = "Medium"
        $recommendedAction = "Remove or replace deleted/unresolved owners at your convenience."
    }
    elseif ($hasGroupOwnerGovernanceRisk) {
        $overallRisk = "Medium"
        $recommendedAction = "A security group used as an owner/admin here has active members (site access still works) but zero owners of its own. Nominate at least one owner for that group so its membership can still be maintained going forward."
    }

    $script:SiteSummaries.Add([pscustomobject]@{
        SiteUrl                = $SiteUrl
        GroupId                = $GroupId
        ActiveOwnerCount       = $activeOwnerCount
        DeletedOwnerCount      = $deletedOwnerCount
        UnresolvedOwnerCount   = $unresolvedOwnerCount
        EmptyGroupOwnerCount   = $emptyGroupOwnerCount
        GroupOwnerGovernanceRiskCount = $groupOwnerGovernanceRiskCount
        HasSingleOwnerRisk     = $hasSingleOwnerRisk
        HasNoActiveOwnersRisk  = $hasNoActiveOwnersRisk
        HasEmptyGroupRisk      = $hasEmptyGroupRisk
        HasGroupOwnerRisk      = $hasGroupOwnerRisk
        HasGroupOwnerGovernanceRisk = $hasGroupOwnerGovernanceRisk
        SiteCollectionAdminDataUnavailable = [bool]$SiteCollectionAdminDataUnavailable
        OverallRiskLevel       = $overallRisk
        RecommendedAction      = $recommendedAction
    })
}

<#
    Add-ErrorRecord
    WHY: Central place to capture non-fatal, per-site errors so the audit can
    continue processing remaining sites instead of terminating entirely.
#>
function Add-ErrorRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SiteUrl,
        [Parameter(Mandatory)][string]$Operation,
        [Parameter(Mandatory)][string]$ErrorMessage
    )

    $script:ErrorLog.Add([pscustomobject]@{
        SiteUrl      = $SiteUrl
        Operation    = $Operation
        ErrorMessage = $ErrorMessage
        Timestamp    = (Get-Date).ToString("o")
    })
}

<#
    Export-AuditReports
    WHY: Single place responsible for writing the audit workbook. Combines the
    Site Summary, Detail, Orphaned Owners, and Errors reports into one
    timestamped .xlsx file (via the ImportExcel module) as separate worksheet
    tabs, so reviewers only need to open one file.
#>
function Export-AuditReports {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$OutputFolder
    )

    if (-not (Test-Path -Path $OutputFolder)) {
        New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
    }

    Import-Module ImportExcel -ErrorAction Stop

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $workbookPath = Join-Path $OutputFolder "SPOOwnerAudit_$timestamp.xlsx"

    # Remove any stale file of the same name (shouldn't normally exist, given
    # the timestamp, but Export-Excel appends worksheets to an existing file
    # rather than overwriting it by default).
    if (Test-Path $workbookPath) { Remove-Item $workbookPath -Force }

    # Sheet order matters here: Export-Excel appends sheets to the workbook in
    # the order each is written, and that's also the left-to-right tab order
    # Excel opens with. SiteSummary is written first (governance overview),
    # followed by Detail (full raw owner listing), OrphanedOwners (owners
    # needing attention only), and finally Errors (processing issues).
    $script:SiteSummaries | Export-Excel -Path $workbookPath -WorksheetName "SiteSummary" `
        -AutoSize -FreezeTopRow -BoldTopRow -TableName "SiteSummary"

    $script:OwnerResults | Export-Excel -Path $workbookPath -WorksheetName "Detail" `
        -AutoSize -FreezeTopRow -BoldTopRow -TableName "OwnerDetail"

    # Orphaned/problem owners only: anything not a confirmed-valid account.
    # This is the "did anyone leave the org and still own a site?" view.
    # Sorted by LoginName then SiteUrl so all sites owned by the same orphaned
    # identity group together, alphabetically.
    $orphanedOwners = $script:OwnerResults | Where-Object { $_.AccountStatus -ne "Valid" } |
        Sort-Object LoginName, SiteUrl
    if (($orphanedOwners | Measure-Object).Count -gt 0) {
        $orphanedOwners | Export-Excel -Path $workbookPath -WorksheetName "OrphanedOwners" `
            -AutoSize -FreezeTopRow -BoldTopRow -TableName "OrphanedOwners"
    }

    $script:ErrorLog | Export-Excel -Path $workbookPath -WorksheetName "Errors" `
        -AutoSize -FreezeTopRow -BoldTopRow -TableName "ProcessingErrors"

    return [pscustomobject]@{
        WorkbookPath = $workbookPath
    }
}
#endregion =========================== RESULT COLLECTION ================================

#region ============================ MAIN ================================
# The -AuthenticationMode script parameter overrides the config.ps1 value
# when supplied, so the same script file supports both interactive,
# human-run audits and unattended/scheduled-task runs without editing the file.
if ($PSBoundParameters.ContainsKey('AuthenticationMode')) {
    $effectiveAuthMode = $AuthenticationMode
}
else {
    $effectiveAuthMode = $DefaultAuthenticationMode
}

if ($PSBoundParameters.ContainsKey('IdentityProvider')) {
    $effectiveIdentityProvider = $IdentityProvider
}
else {
    $effectiveIdentityProvider = $DefaultIdentityProvider
}

Write-Host "==============================================================" -ForegroundColor Cyan
Write-Host " SharePoint Online Orphaned/Risky Owner Audit" -ForegroundColor Cyan
Write-Host " Cloud Environment : $CloudEnvironment" -ForegroundColor Cyan
Write-Host " Tenant            : $TenantName" -ForegroundColor Cyan
Write-Host " Auth Mode         : $effectiveAuthMode" -ForegroundColor Cyan
Write-Host " Identity Provider : $effectiveIdentityProvider" -ForegroundColor Cyan
Write-Host "==============================================================" -ForegroundColor Cyan

try {
    if ($effectiveAuthMode -eq "AppOnly") {
        # Fail fast with a clear message if AppOnly config is incomplete,
        # rather than letting Connect-MgGraph/Connect-SPOService error out
        # cryptically mid-run — important for unattended/scheduled execution
        # where nobody is watching the console in real time.
        $missingAppOnlySettings = @()
        if ([string]::IsNullOrWhiteSpace($AppOnlyClientId)) { $missingAppOnlySettings += "AppOnlyClientId" }
        if ([string]::IsNullOrWhiteSpace($AppOnlyTenantId)) { $missingAppOnlySettings += "AppOnlyTenantId" }
        if ([string]::IsNullOrWhiteSpace($AppOnlyCertificateThumbprint)) { $missingAppOnlySettings += "AppOnlyCertificateThumbprint" }

        if ($missingAppOnlySettings.Count -gt 0) {
            throw "AuthenticationMode is 'AppOnly' but the following settings are not set: $($missingAppOnlySettings -join ', '). Populate these in config.ps1 for unattended runs."
        }
    }

    Test-RequiredModules -IdentityProvider $effectiveIdentityProvider -InstallMissingModules:$InstallMissingModules -Force:($effectiveAuthMode -eq "AppOnly")

    $cloudConfig = Get-CloudConfiguration -CloudEnvironment $CloudEnvironment -TenantName $TenantName
    Write-Verbose "Resolved cloud configuration: $($cloudConfig | Out-String)"

    Connect-M365Services -CloudConfig $cloudConfig -AuthenticationMode $effectiveAuthMode -IdentityProvider $effectiveIdentityProvider `
        -GraphUserPrincipalName $GraphUserPrincipalName `
        -AppOnlyClientId $AppOnlyClientId -AppOnlyTenantId $AppOnlyTenantId `
        -AppOnlyCertificateThumbprint $AppOnlyCertificateThumbprint `
        -PnPClientId $PnPClientId

    Write-Host "Enumerating SharePoint Online sites (this may take a while for large tenants)..." -ForegroundColor Cyan
    $allSites = Get-PnPTenantSite -Detailed -Connection $script:PnPAdminConnection -ErrorAction Stop

    if (-not [string]::IsNullOrWhiteSpace($SiteUrl)) {
        Write-Verbose "SiteUrl specified: limiting to '$SiteUrl' only."
        $allSites = $allSites | Where-Object { $_.Url -eq $SiteUrl }
        if (($allSites | Measure-Object).Count -eq 0) {
            throw "No site matching -SiteUrl '$SiteUrl' was found among the enumerated tenant sites. Check the URL is exact (including https:// and no trailing slash)."
        }
    }
    elseif ($MaxSites -and $MaxSites -gt 0) {
        Write-Verbose "MaxSites specified: limiting to first $MaxSites site(s)."
        $allSites = $allSites | Select-Object -First $MaxSites
    }

    $siteCount = ($allSites | Measure-Object).Count
    Write-Host "Found $siteCount site(s) to process." -ForegroundColor Cyan

    # Cache Entra lookups within a run to avoid redundant Graph calls for
    # owners/admins who appear on many sites (common for tenant admins).
    $entraUserCache = @{}

    # Same idea, but for group-principal owners/admins (a group frequently
    # owns many sites, e.g. an IT security group used as SCA tenant-wide) --
    # avoids re-querying Get-MgGroup/Get-MgGroupMember for the same group.
    $groupStatusCache = @{}

    # Timing instrumentation: measures only the identity-resolution calls
    # (Resolve-IdentityStatus), isolated from SharePoint enumeration/connection
    # time, so MicrosoftGraph vs ExchangeOnline throughput can be compared
    # apples-to-apples on the same tenant.
    $script:IdentityLookupStopwatch = [System.Diagnostics.Stopwatch]::new()
    $script:IdentityLookupCount = 0

    $siteIndex = 0
    foreach ($site in $allSites) {
        $siteIndex++
        $siteUrl = $site.Url
        Write-Verbose "[$siteIndex/$siteCount] Processing site: $siteUrl"
        Write-Progress -Activity "Auditing SharePoint Online site ownership" `
            -Status "Site $siteIndex of $siteCount : $siteUrl" `
            -PercentComplete (($siteIndex / [math]::Max($siteCount,1)) * 100)

        $siteOwnerRows = [System.Collections.Generic.List[object]]::new()
        $groupId = $null
        if ($site.GroupId -and $site.GroupId -ne [guid]::Empty) {
            $groupId = $site.GroupId.ToString()
        }

        # ---- 1. Owner property from Get-SPOSite ----
        try {
            if (-not [string]::IsNullOrWhiteSpace($site.Owner)) {
                $normalized = Normalize-SPOLoginName -LoginName $site.Owner
                $status = "Unknown"
                $entraId = $null
                $displayName = $null
                $errorDetail = $null
                $groupOwnerGovernanceRisk = $false

                if ($normalized.PrincipalType -in @("Member", "ExternalOrGuest") -and $normalized.UPN) {
                    if (-not $entraUserCache.ContainsKey($normalized.UPN)) {
                        $entraUserCache[$normalized.UPN] = Resolve-IdentityStatus -UserPrincipalName $normalized.UPN -IdentityProvider $effectiveIdentityProvider
                    }
                    $lookup = $entraUserCache[$normalized.UPN]
                    $status = $lookup.Status
                    $entraId = $lookup.EntraObjectId
                    $displayName = $lookup.DisplayName
                    $errorDetail = $lookup.ErrorDetail
                }
                elseif ($normalized.PrincipalType -eq "GroupPrincipal") {
                    if ($normalized.GroupObjectId -and $effectiveIdentityProvider -eq "MicrosoftGraph") {
                        $groupRole = if ($normalized.GroupRole) { $normalized.GroupRole } else { "Member" }
                        $groupCacheKey = "$($normalized.GroupObjectId)|$groupRole"
                        if (-not $groupStatusCache.ContainsKey($groupCacheKey)) {
                            $groupStatusCache[$groupCacheKey] = Test-EntraGroupStatus -GroupObjectId $normalized.GroupObjectId -Role $groupRole
                        }
                        $groupLookup = $groupStatusCache[$groupCacheKey]
                        $status = $groupLookup.Status
                        $errorDetail = $groupLookup.ErrorDetail
                        $groupOwnerGovernanceRisk = [bool]$groupLookup.HasNoGroupOwners
                    }
                    else {
                        # Not a real, queryable Entra group (e.g. a tenant-wide
                        # "Everyone" claim), or Graph isn't available in
                        # ExchangeOnline identity-provider mode -- membership
                        # can't be verified, so this remains unverified/Valid.
                        $status = "Valid"
                    }
                }
                else {
                    $status = "Unresolved"
                }

                $riskFlag = ""
                if ($status -eq "EmptyGroup") { $riskFlag = "EmptyGroupOwner" }
                elseif ($status -in @("DeletedFromEntra", "Unresolved")) { $riskFlag = "OrphanedOwnerProperty" }
                if ($groupOwnerGovernanceRisk) { $riskFlag = if ($riskFlag) { "$riskFlag,GroupHasNoOwners" } else { "GroupHasNoOwners" } }

                $ownerRow = [pscustomobject]@{
                    OwnerSource       = "SiteOwnerProperty"
                    DisplayName       = $displayName
                    LoginName         = $site.Owner
                    UserPrincipalName = $normalized.UPN
                    PrincipalType     = $normalized.PrincipalType
                    EntraObjectId     = $entraId
                    AccountStatus     = $status
                    GroupOwnerGovernanceRisk = $groupOwnerGovernanceRisk
                }

                Add-OwnerResult -SiteUrl $siteUrl -SiteTitle $site.Title -SiteTemplate $site.Template `
                    -GroupId $groupId -OwnerSource $ownerRow.OwnerSource -DisplayName $ownerRow.DisplayName `
                    -LoginName $ownerRow.LoginName -UserPrincipalName $ownerRow.UserPrincipalName `
                    -PrincipalType $ownerRow.PrincipalType -EntraObjectId $ownerRow.EntraObjectId `
                    -AccountStatus $ownerRow.AccountStatus -RiskFlag $riskFlag `
                    -Notes (Get-AccountStatusNote -AccountStatus $ownerRow.AccountStatus -ErrorDetail $errorDetail -IsGroupPrincipal:($ownerRow.PrincipalType -eq "GroupPrincipal") -GroupHasNoOwners:$groupOwnerGovernanceRisk) `
                    -GroupOwnerGovernanceRisk $groupOwnerGovernanceRisk

                $siteOwnerRows.Add($ownerRow)
            }
        }
        catch {
            Add-ErrorRecord -SiteUrl $siteUrl -Operation "SiteOwnerProperty" -ErrorMessage $_.Exception.Message
        }

        # ---- 2. Site Collection Administrators via Get-SPOUser ----
        $scaAccessDenied = $false
        try {
            $admins = Get-SiteCollectionAdmins -SiteUrl $siteUrl
            foreach ($admin in $admins) {
                $normalized = Normalize-SPOLoginName -LoginName $admin.LoginName
                $status = "Unknown"
                $entraId = $null
                $displayName = $admin.DisplayName
                $errorDetail = $null
                $groupOwnerGovernanceRisk = $false

                switch ($normalized.PrincipalType) {
                    { $_ -in @("Member", "ExternalOrGuest") } {
                        if ($normalized.UPN) {
                            if (-not $entraUserCache.ContainsKey($normalized.UPN)) {
                                $entraUserCache[$normalized.UPN] = Resolve-IdentityStatus -UserPrincipalName $normalized.UPN -IdentityProvider $effectiveIdentityProvider
                            }
                            $lookup = $entraUserCache[$normalized.UPN]
                            $status = $lookup.Status
                            $entraId = $lookup.EntraObjectId
                            if ($lookup.DisplayName) { $displayName = $lookup.DisplayName }
                            $errorDetail = $lookup.ErrorDetail
                        }
                        else {
                            $status = "Unresolved"
                        }
                    }
                    "GroupPrincipal" {
                        if ($normalized.GroupObjectId -and $effectiveIdentityProvider -eq "MicrosoftGraph") {
                            $groupRole = if ($normalized.GroupRole) { $normalized.GroupRole } else { "Member" }
                            $groupCacheKey = "$($normalized.GroupObjectId)|$groupRole"
                            if (-not $groupStatusCache.ContainsKey($groupCacheKey)) {
                                $groupStatusCache[$groupCacheKey] = Test-EntraGroupStatus -GroupObjectId $normalized.GroupObjectId -Role $groupRole
                            }
                            $groupLookup = $groupStatusCache[$groupCacheKey]
                            $status = $groupLookup.Status
                            $errorDetail = $groupLookup.ErrorDetail
                            $groupOwnerGovernanceRisk = [bool]$groupLookup.HasNoGroupOwners
                        }
                        else {
                            $status = "Valid"
                        }
                    }
                    "AppOrSystem"    { $status = "Valid" }
                    default          { $status = "Unresolved" }
                }

                $riskFlag = ""
                if ($normalized.PrincipalType -eq "GroupPrincipal") {
                    switch ($status) {
                        "EmptyGroup"       { $riskFlag = "EmptyGroupAdmin" }
                        "DeletedFromEntra" { $riskFlag = "OrphanedSiteAdmin" }
                        default            { $riskFlag = "GroupPrincipalAdmin" }
                    }
                }
                elseif ($status -in @("DeletedFromEntra", "Unresolved")) { $riskFlag = "OrphanedSiteAdmin" }
                if ($groupOwnerGovernanceRisk) { $riskFlag = if ($riskFlag) { "$riskFlag,GroupHasNoOwners" } else { "GroupHasNoOwners" } }

                $ownerRow = [pscustomobject]@{
                    OwnerSource       = "SiteCollectionAdmin"
                    DisplayName       = $displayName
                    LoginName         = $admin.LoginName
                    UserPrincipalName = $normalized.UPN
                    PrincipalType     = $normalized.PrincipalType
                    EntraObjectId     = $entraId
                    AccountStatus     = $status
                    GroupOwnerGovernanceRisk = $groupOwnerGovernanceRisk
                }

                Add-OwnerResult -SiteUrl $siteUrl -SiteTitle $site.Title -SiteTemplate $site.Template `
                    -GroupId $groupId -OwnerSource $ownerRow.OwnerSource -DisplayName $ownerRow.DisplayName `
                    -LoginName $ownerRow.LoginName -UserPrincipalName $ownerRow.UserPrincipalName `
                    -PrincipalType $ownerRow.PrincipalType -EntraObjectId $ownerRow.EntraObjectId `
                    -AccountStatus $ownerRow.AccountStatus -RiskFlag $riskFlag `
                    -Notes (Get-AccountStatusNote -AccountStatus $ownerRow.AccountStatus -ErrorDetail $errorDetail -IsGroupPrincipal:($ownerRow.PrincipalType -eq "GroupPrincipal") -GroupHasNoOwners:$groupOwnerGovernanceRisk) `
                    -GroupOwnerGovernanceRisk $groupOwnerGovernanceRisk

                $siteOwnerRows.Add($ownerRow)
            }
        }
        catch {
            if ($_.Exception.Message -match "Attempted to perform an unauthorized operation") {
                # Expected access gap: tenant-level SharePoint Administrator does not
                # grant per-site Get-PnPSiteCollectionAdmin rights. Soft-skip rather
                # than logging as a processing error.
                $scaAccessDenied = $true
                $script:SiteCollectionAdminAccessDeniedSites.Add($siteUrl)
                Write-Verbose "Get-SiteCollectionAdmins: access denied for '$siteUrl' (not a site collection admin on this site) - skipping"
            }
            else {
                Add-ErrorRecord -SiteUrl $siteUrl -Operation "Get-SiteCollectionAdmins" -ErrorMessage $_.Exception.Message
            }
        }

        # ---- 3. Microsoft 365 Group owners (group-connected sites only) ----
        if ($groupId) {
            try {
                $groupOwners = Get-GroupOwners -GroupId $groupId -IdentityProvider $effectiveIdentityProvider
                foreach ($owner in $groupOwners) {
                    $ownerUpn = $owner.UserPrincipalName
                    $ownerDisplayName = $owner.DisplayName

                    $status = "Unknown"
                    $entraId = $owner.EntraObjectId
                    $errorDetail = $null

                    if ($ownerUpn) {
                        if (-not $entraUserCache.ContainsKey($ownerUpn)) {
                            $entraUserCache[$ownerUpn] = Resolve-IdentityStatus -UserPrincipalName $ownerUpn -IdentityProvider $effectiveIdentityProvider
                        }
                        $lookup = $entraUserCache[$ownerUpn]
                        $status = $lookup.Status
                        $entraId = $lookup.EntraObjectId
                        if ($lookup.DisplayName) { $ownerDisplayName = $lookup.DisplayName }
                        $errorDetail = $lookup.ErrorDetail
                    }
                    else {
                        # Non-user owner (e.g., service principal) — treat as Valid
                        # since it exists as a directory object, but note it.
                        $status = "Valid"
                    }

                    $riskFlag = if ($status -in @("DeletedFromEntra", "Unresolved")) { "OrphanedGroupOwner" } else { "" }

                    $ownerRow = [pscustomobject]@{
                        OwnerSource       = "M365GroupOwner"
                        DisplayName       = $ownerDisplayName
                        LoginName         = $null
                        UserPrincipalName = $ownerUpn
                        PrincipalType     = if ($ownerUpn) { "Member" } else { "ServicePrincipal" }
                        EntraObjectId     = $entraId
                        AccountStatus     = $status
                    }

                    Add-OwnerResult -SiteUrl $siteUrl -SiteTitle $site.Title -SiteTemplate $site.Template `
                        -GroupId $groupId -OwnerSource $ownerRow.OwnerSource -DisplayName $ownerRow.DisplayName `
                        -LoginName $ownerRow.LoginName -UserPrincipalName $ownerRow.UserPrincipalName `
                        -PrincipalType $ownerRow.PrincipalType -EntraObjectId $ownerRow.EntraObjectId `
                        -AccountStatus $ownerRow.AccountStatus -RiskFlag $riskFlag `
                        -Notes (Get-AccountStatusNote -AccountStatus $ownerRow.AccountStatus -ErrorDetail $errorDetail)

                    $siteOwnerRows.Add($ownerRow)
                }
            }
            catch {
                Add-ErrorRecord -SiteUrl $siteUrl -Operation "Get-GroupOwners" -ErrorMessage $_.Exception.Message
            }
        }

        # ---- Site-level governance summary ----
        try {
            Add-SiteSummary -SiteUrl $siteUrl -GroupId $groupId -SiteOwnerRows $siteOwnerRows -SiteCollectionAdminDataUnavailable:$scaAccessDenied
        }
        catch {
            Add-ErrorRecord -SiteUrl $siteUrl -Operation "Add-SiteSummary" -ErrorMessage $_.Exception.Message
        }
    }

    Write-Progress -Activity "Auditing SharePoint Online site ownership" -Completed

    # ---- Export reports ----
    $paths = Export-AuditReports -OutputFolder $OutputFolder

    # ---- Console summary ----
    $criticalCount = ($script:SiteSummaries | Where-Object { $_.OverallRiskLevel -eq "Critical" } | Measure-Object).Count
    $highCount     = ($script:SiteSummaries | Where-Object { $_.OverallRiskLevel -eq "High" } | Measure-Object).Count
    $mediumCount   = ($script:SiteSummaries | Where-Object { $_.OverallRiskLevel -eq "Medium" } | Measure-Object).Count
    $lowCount      = ($script:SiteSummaries | Where-Object { $_.OverallRiskLevel -eq "Low" } | Measure-Object).Count
    $unknownCount  = ($script:SiteSummaries | Where-Object { $_.OverallRiskLevel -eq "Unknown" } | Measure-Object).Count

    Write-Host ""
    Write-Host "==============================================================" -ForegroundColor Green
    Write-Host " Audit Complete" -ForegroundColor Green
    Write-Host "==============================================================" -ForegroundColor Green
    Write-Host " Sites processed        : $siteCount"
    Write-Host " Owner/admin rows       : $($script:OwnerResults.Count)"
    Write-Host " Processing errors      : $($script:ErrorLog.Count)"
    Write-Host " Risk - Critical        : $criticalCount"
    Write-Host " Risk - High            : $highCount"
    Write-Host " Risk - Medium          : $mediumCount"
    Write-Host " Risk - Low             : $lowCount"
    if ($unknownCount -gt 0) {
        Write-Host " Risk - Unknown         : $unknownCount (owner status could not be fully verified - see below)"
    }
    if ($script:SiteCollectionAdminAccessDeniedSites.Count -gt 0) {
        Write-Host ""
        Write-Host " Site collection admin data unavailable on $($script:SiteCollectionAdminAccessDeniedSites.Count) site(s):" -ForegroundColor Yellow
        Write-Host " your account is tenant-level SharePoint Administrator but not a site" -ForegroundColor Yellow
        Write-Host " collection admin on these specific sites, so secondary admins (beyond" -ForegroundColor Yellow
        Write-Host " the primary Owner) could not be enumerated there. Not counted as errors." -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host " Identity provider      : $effectiveIdentityProvider"
    Write-Host " Identity lookups       : $($script:IdentityLookupCount) (unique identities resolved, cache-deduplicated)"
    if ($script:IdentityLookupCount -gt 0) {
        $totalLookupMs = $script:IdentityLookupStopwatch.Elapsed.TotalMilliseconds
        $avgLookupMs   = $totalLookupMs / $script:IdentityLookupCount
        Write-Host (" Identity lookup time   : {0:N2}s total, {1:N0}ms average per lookup" -f ($totalLookupMs / 1000), $avgLookupMs)
    }
    Write-Host ""
    Write-Host " Report workbook        : $($paths.WorkbookPath)"
    Write-Host "==============================================================" -ForegroundColor Green
}
catch {
    Write-Error "Audit failed: $($_.Exception.Message)"
    throw
}
finally {
    # Best-effort disconnects; do not mask the original error/result if these fail.
    try { Disconnect-PnPOnline -ErrorAction SilentlyContinue } catch { }
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue } catch { }
    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue } catch { }
}
#endregion =========================== MAIN ================================
