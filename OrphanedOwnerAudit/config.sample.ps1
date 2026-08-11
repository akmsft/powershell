<#
    config.sample.ps1
    ------------------
    Template configuration for Get-SPOOrphanedOwnerAudit.ps1.

    FIRST-TIME SETUP:
        1. Copy this file to "config.ps1" in this same folder.
        2. Edit config.ps1 (NOT this sample file) with your tenant's real values.
        3. Never commit/share config.ps1 -- it is excluded via .gitignore because
           it will contain values specific to your tenant/app registration.

    This file only contains placeholder values and documentation. The main
    script (Get-SPOOrphanedOwnerAudit.ps1) is never edited for a new tenant --
    only config.ps1 changes. This keeps the script itself identical across
    every tenant/customer that uses it, which makes picking up upstream fixes
    (via `git pull`) safe and conflict-free.
#>

# ---------------------------------------------------------------------------
# CLOUD ENVIRONMENT
# ---------------------------------------------------------------------------
# Valid values: "Commercial", "GCC", "GCCHigh"
# NOTE: This script is built and validated first against GCC High.
$CloudEnvironment = "GCC"

# ---------------------------------------------------------------------------
# TENANT NAME
# ---------------------------------------------------------------------------
# Tenant short name only (the part before .onmicrosoft.us / .onmicrosoft.com,
# and before .sharepoint.us / .sharepoint.com). Do NOT include a domain suffix.
# Example: for "contoso.sharepoint.us", set $TenantName = "contoso"
$TenantName = "contoso"

# ---------------------------------------------------------------------------
# OPTIONAL SIGN-IN HINT
# ---------------------------------------------------------------------------
# Optional: explicit UPN hint for interactive sign-in (Graph or Exchange Online,
# whichever $DefaultIdentityProvider below selects). Leave blank to let the
# connect cmdlet prompt normally. Only used when $DefaultAuthenticationMode =
# "Interactive" (or -AuthenticationMode Interactive is passed at runtime).
$GraphUserPrincipalName = ""

# ---------------------------------------------------------------------------
# IDENTITY PROVIDER (how owners/admins are validated against Entra ID)
# ---------------------------------------------------------------------------
# "MicrosoftGraph" (default): uses Get-MgUser / Get-MgGroupOwner. Most accurate
#   (checks the directory directly), but requires the Microsoft Graph
#   PowerShell SDK and outbound access to graph.microsoft.us (GCC High) or
#   graph.microsoft.com to be permitted on the machine running this script.
# "ExchangeOnline": fallback for individual owner/admin identity resolution
#   when Microsoft Graph user-lookup permissions are unavailable. Uses
#   Get-EXORecipient (via the ExchangeOnlineManagement module) for that piece
#   only.
#   LIMITATION #1 (group owners): M365 Group owner enumeration always uses
#   Microsoft Graph (Get-MgGroupOwner) — Get-UnifiedGroupLinks (the Exchange
#   equivalent) only works in Windows PowerShell 5.1, not PowerShell 7. No
#   Graph connection is opened in this mode, because ExchangeOnlineManagement
#   and Microsoft.Graph.Authentication cannot reliably coexist in the same
#   PowerShell process (a known, unresolved MSAL assembly conflict in
#   Microsoft's own SDKs, confirmed across both connection orders). As a
#   result, group-connected sites will show zero group owners in this mode.
#   LIMITATION #2 (mailbox-less accounts): Exchange Online only "sees"
#   mail-enabled recipients. A valid Entra ID account with no mailbox/license
#   (e.g., an unlicensed guest) will NOT be found and will be misclassified
#   as "DeletedFromEntra" even though it still exists.
#   Given both limitations, prefer MicrosoftGraph mode (the default) unless
#   you specifically cannot use Microsoft Graph at all.
$DefaultIdentityProvider = "MicrosoftGraph"   # "MicrosoftGraph" | "ExchangeOnline"

# ---------------------------------------------------------------------------
# AUTHENTICATION MODE
# ---------------------------------------------------------------------------
# "Interactive" (default): an admin signs in via browser prompt for both
#   Microsoft Graph and SharePoint Online. Best for ad-hoc, human-run audits.
# "AppOnly": certificate-based, non-interactive authentication for both
#   Microsoft Graph and SharePoint Online. Required for scheduled
#   tasks/unattended runs. Can be overridden at runtime with
#   -AuthenticationMode, so the same script file works both ways without edits.
#   NOTE: the AppOnly path has not yet been validated in a live unattended run
#   by the script's author -- review it carefully and test in a non-production
#   tenant first if you plan to rely on it for scheduled/unattended execution.
$DefaultAuthenticationMode = "Interactive"   # "Interactive" | "AppOnly"

# ---- AppOnly settings (only required when $AuthenticationMode = "AppOnly") ----
# Azure AD / Entra ID App Registration (client) ID, shared by whichever
# $DefaultIdentityProvider is selected above. Grant it only the permissions
# needed for your chosen provider:
#   - MicrosoftGraph mode: Graph application permissions User.Read.All,
#     Group.Read.All, Directory.Read.All (admin consented), plus the SharePoint
#     app permission Sites.FullControl.All (or narrower, tenant-documented).
#   - ExchangeOnline mode: the Exchange.ManageAsApp application permission
#     (admin consented) and the app must be assigned an Exchange Online RBAC
#     role (e.g., "View-Only Recipients"), plus the same SharePoint permission.
$AppOnlyClientId = ""

# Entra ID (Azure AD) tenant ID (GUID) or verified domain, e.g. "contoso.onmicrosoft.us"
$AppOnlyTenantId = ""

# Thumbprint of the certificate associated with the App Registration. The
# certificate's private key must be installed in the CurrentUser (or
# LocalMachine, if running as a service account) certificate store on the
# machine executing this script.
$AppOnlyCertificateThumbprint = ""

# ---------------------------------------------------------------------------
# SHAREPOINT CONNECTION (PnP.PowerShell) -- Interactive mode client ID
# ---------------------------------------------------------------------------
# SharePoint Online connectivity uses the PnP.PowerShell module (Connect-PnPOnline),
# not Microsoft.Online.SharePoint.PowerShell / Connect-SPOService — the latter
# is only reliably supported in Windows PowerShell 5.1, not PowerShell 7+.
#
# Interactive mode requires your OWN Entra ID App Registration (Microsoft
# retired the shared PnP Management Shell app in Sept 2024). See the main
# script's header .NOTES section for step-by-step registration instructions.
# Grant it the delegated SharePoint permission "AllSites.Read" (least privilege
# for this read-only audit script; admin consent is usually not required for
# this scope).
#
# Populate this with the "Application (client) ID" from YOUR OWN app
# registration -- this value is tenant-specific and will NOT work for any
# tenant other than the one it was registered in.
$PnPClientId = "<your-app-registration-client-id>"
