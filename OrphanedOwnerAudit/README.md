# SharePoint Online Orphaned Owner Audit

A read-only PowerShell auditing tool that scans every SharePoint Online site in
a Microsoft 365 tenant, checks each site's owner(s) and site collection
administrators against Entra ID (Azure AD), and flags sites that are
ownerless, have a deleted/orphaned owner, or otherwise carry ownership-related
governance risk.

Built and validated first against **GCC High**, and also supports **GCC** and
**Commercial** tenants.

> **This script is audit-only.** It never modifies, removes, or remediates any
> owner, admin, or group membership — it only reads and reports.

## Why this exists

Over time, SharePoint sites accumulate owners who leave the organization, get
their accounts disabled, or were never replaced when the original site creator
moved on. Left unnoticed, this creates real risk: sites with no active owner
can't be governed, recertified, or have access reviewed by anyone with
legitimate authority over them. This tool surfaces that risk across an entire
tenant in a single run, with enough detail (real error messages, per-site risk
tiers, and a dedicated "orphaned owners" tab) to act on immediately.

## What it checks

For every SharePoint Online site in the tenant, this script collects
ownership data from three sources and validates each identity found:

1. **The site's `Owner` property** (from `Get-PnPTenantSite`)
2. **Site Collection Administrators** (from `Get-PnPSiteCollectionAdmin`)
3. **Microsoft 365 Group owners**, for group-connected sites (via Microsoft Graph)

Each identity found is checked against Entra ID and classified as:

| Status | Meaning |
|---|---|
| `Valid` | Account exists and is active (or, for a group-principal owner/admin, the group exists and has at least one active member) |
| `DeletedFromEntra` | Account no longer exists (or has no mailbox, in ExchangeOnline mode); or, for a group principal, the group itself no longer exists in Entra ID |
| `EmptyGroup` | Owner/admin is a security or Microsoft 365 group that still exists, but currently has **zero active members** — so no one can actually act as owner through this assignment |
| `Unresolved` | Lookup could not be completed (e.g., malformed login, unsupported principal type, group membership couldn't be verified) — see the row's Notes column for the real underlying error |
| `Unknown` | Site collection admin data unavailable for this specific site (see [Known limitations](#known-limitations)) |

Each site is then assigned an overall risk tier:

| Risk | Meaning |
|---|---|
| **Critical** | Site has zero valid/active owners (including when the only owner is an empty group) |
| **High** | Group-connected site has no valid group owners; or another owner exists, but a group-principal owner/admin has zero active members |
| **Medium** | Site has only a single active owner (single point of failure), an unverifiable group-principal admin, a deleted/unresolved owner, or a group-principal owner/admin has active members but zero owners of its own |
| **Low** | No issues found |
| **Unknown** | Site has zero *confirmed* active owners, but site collection admin data couldn't be checked for this site (may have unseen admins) — see limitation below |

## Output

Each run produces a single timestamped `.xlsx` workbook in `AuditReports/`
(e.g., `SPOOwnerAudit_20260810_080308.xlsx`) with four tabs:

- **SiteSummary** — one row per site: risk tier, owner counts, recommended action
- **Detail** — one row per owner/admin found, with identity status and notes
- **OrphanedOwners** — every owner that is `DeletedFromEntra` or `Unresolved`, for quick triage
- **Errors** — any per-site processing errors encountered (the audit continues past individual site failures)

Every run also writes a full **transcript log** (`.xlsx` alongside a matching
`.log` file, same timestamp — e.g. `SPOOwnerAudit_20260810_080308.log`) to
the same output folder. This captures the entire console output of the run,
including any errors or warnings, and exists so an unattended/scheduled run
that fails overnight can still be diagnosed after the fact (see
[Authentication modes](#authentication-modes)). If the log file itself can't
be created (e.g., read-only folder), the audit still runs — you'll get a
`Could not start a transcript log` warning instead of a hard failure.

A summary is also printed to the console at the end of each run, e.g.:

```
==============================================================
 Audit Complete
==============================================================
 Sites processed        : 350
 Owner/admin rows       : 342
 Processing errors      : 0
 Risk - Critical        : 26
 Risk - High            : 0
 Risk - Medium          : 248
 Risk - Low             : 19
 Risk - Unknown         : 57 (owner status could not be fully verified - see below)
 ...
==============================================================
```

## Prerequisites

### PowerShell version
PowerShell 7+ is recommended. (`Connect-SPOService` /
`Microsoft.Online.SharePoint.PowerShell` is intentionally **not** used, since
it isn't reliable under PowerShell 7 — this script uses `PnP.PowerShell`
instead.)

### Required modules
- **PnP.PowerShell** — always required (SharePoint Online connectivity)
- **ImportExcel** — always required (writes the `.xlsx` report)
- **Microsoft.Graph** (`Microsoft.Graph.Authentication`, `Microsoft.Graph.Users`,
  `Microsoft.Graph.Groups`) — required if using the default `MicrosoftGraph`
  identity provider
- **ExchangeOnlineManagement** — required only if using the `ExchangeOnline`
  identity provider (see [Identity providers](#identity-providers) below)

Pass `-InstallMissingModules` on first run to have the script install any
missing modules automatically (CurrentUser scope, after a confirmation prompt).

### Required permissions
- **SharePoint Administrator** (or Global Administrator) role — needed to
  enumerate all sites tenant-wide.
- Your own **Entra ID App Registration** for `PnP.PowerShell` sign-in
  (Microsoft retired the shared PnP Management Shell app in September 2024).
  See [Setting up your App Registration](#setting-up-your-app-registration-required)
  below.
- Delegated Graph scopes (if using `MicrosoftGraph` mode): `User.Read.All`,
  `Group.Read.All`, and optionally `Directory.Read.All`.

## First-time setup

1. **Clone or download this folder.**
2. **Copy `config.sample.ps1` to `config.ps1`** in this same folder:
   ```powershell
   Copy-Item config.sample.ps1 config.ps1
   ```
3. **Edit `config.ps1`** (never `config.sample.ps1`, and never the main
   script) with your tenant's values:
   - `$CloudEnvironment` — `"Commercial"`, `"GCC"`, or `"GCCHigh"`
   - `$TenantName` — your tenant's short name (e.g., `contoso` for
     `contoso.sharepoint.com`)
   - `$PnPClientId` — your own App Registration's client ID (see below)
4. **Run a small test first**, capped to a handful of sites:
   ```powershell
   .\Get-SPOOrphanedOwnerAudit.ps1 -MaxSites 5 -Verbose
   ```
5. Once you've confirmed it works, run the full audit:
   ```powershell
   .\Get-SPOOrphanedOwnerAudit.ps1 -Verbose
   ```

`config.ps1` is excluded from git via `.gitignore` — it will contain values
specific to your tenant and should never be committed or shared.

### Setting up your App Registration (required)

Interactive sign-in for `PnP.PowerShell` requires your own Entra ID App
Registration (Microsoft retired the shared PnP Management Shell app in
September 2024):

1. In the Entra admin center, go to **App registrations** → **New registration**.
2. Give it a name (e.g., "SPO Orphaned Owner Audit"), single-tenant, no redirect URI needed for device-code/interactive PnP sign-in (or add `http://localhost` if prompted).
3. Under **API permissions**, add the delegated SharePoint permission
   **`AllSites.Read`** (least privilege needed for this read-only audit —
   admin consent is usually not required for this scope).
4. Copy the **Application (client) ID** from the Overview page into
   `$PnPClientId` in your `config.ps1`.

If you plan to also use Microsoft Graph identity validation (the default),
no separate app registration is needed for that — `Connect-MgGraph` uses its
own interactive sign-in flow and delegated consent prompt at runtime.

## Identity providers

This script supports two ways of validating owner/admin identities against
Entra ID — set via `$DefaultIdentityProvider` in `config.ps1`, or override
per-run with `-IdentityProvider`:

- **`MicrosoftGraph`** (default, recommended) — uses `Get-MgUser` /
  `Get-MgGroupOwner`. Most accurate: checks the directory directly, and
  correctly resolves unlicensed/mailbox-less guest accounts.
- **`ExchangeOnline`** — fallback for environments where Microsoft Graph
  user-lookup permissions are unavailable. Uses `Get-EXORecipient`.
  **Two limitations apply in this mode** (see [Known limitations](#known-limitations)):
  group owner data will always be incomplete, and mailbox-less accounts will
  be misclassified as deleted.

## Excluding groups from membership/ownership checks

Some organizations have one or more "everyone" style security or Microsoft
365 groups (e.g., "All Employees", "All Staff") assigned as a site owner or
Site Collection Administrator. These groups are typically huge, always have
active members, and checking them wastes time/API calls on every run for a
result that's already known in advance.

To skip a group entirely, list its Entra ID **Object ID** (GUID) in
`$DefaultExcludedGroupObjectIds` in `config.ps1`:

```powershell
$DefaultExcludedGroupObjectIds = @(
    "11111111-1111-1111-1111-111111111111"   # e.g., "All Employees"
)
```

You can also override this at runtime without editing `config.ps1`, using
the `-ExcludedGroupObjectIds` parameter:

```powershell
.\Get-SPOOrphanedOwnerAudit.ps1 -ExcludedGroupObjectIds "11111111-1111-1111-1111-111111111111" -Verbose
```

A group matched by this list is treated as `Valid` (an active owner) without
calling Microsoft Graph to check its membership or ownership — but it still
appears in the **Detail** report tab, with a note explaining it was excluded
via configuration and a `GroupExcluded` column set to `True`, so the
exclusion stays visible/auditable rather than silently hidden. Find a
group's Object ID in the Entra admin center (**Groups** → select the group →
**Object ID**), or via `Get-MgGroup -Filter "DisplayName eq 'All Employees'"`.

## Authentication modes

- **`Interactive`** (default) — an admin signs in via browser prompt. Best
  for ad-hoc, human-run audits.
- **`AppOnly`** — certificate-based, non-interactive authentication, for
  scheduled/unattended runs. Set `$DefaultAuthenticationMode = "AppOnly"` and
  populate the `AppOnlyClientId`/`AppOnlyTenantId`/`AppOnlyCertificateThumbprint`
  values in `config.ps1`, or pass `-AuthenticationMode AppOnly` at runtime.

  > ⚠️ **This path has not yet been validated in a live unattended run by this
  > project's author.** Every piece of it has been carefully reviewed and the
  > individual building blocks (certificate auth, Graph/PnP connections) use
  > well-documented Microsoft cmdlets, but the full end-to-end AppOnly +
  > Task Scheduler flow — run unattended, start to finish, on a real schedule
  > — has not been personally observed to succeed. **Before pointing this at
  > production:**
  > 1. Register the scheduled task (see below), then **right-click it in Task
  >    Scheduler and choose "Run" manually** at least once. Confirm it
  >    completes, produces a `.xlsx` report *and* a `.log` transcript in
  >    `AuditReports/`, and that the row/risk counts look sane compared to an
  >    interactive run against the same tenant.
  > 2. Only after that manual run succeeds, let it run on its actual nightly
  >    schedule for a few cycles before relying on it unattended long-term.
  > 3. If the manual run fails, **read the `.log` transcript first** — it
  >    captures the exact error, not just Task Scheduler's generic exit code.
  >    Common first-run failures: the run-as account can't read the
  >    certificate's private key, the app registration is missing
  >    admin-consented permissions, or required PowerShell modules aren't
  >    installed/visible to that account.
  >
  > Contributions/confirmations from real-world testing are welcome — see
  > [Contributing](#contributing).

  **`Register-SPOOrphanedOwnerAuditTask.ps1` is a separate, optional helper
  script included in this folder.** It does **not** run the audit itself —
  its only job is to register a Windows Task Scheduler task that runs
  `Get-SPOOrphanedOwnerAudit.ps1` automatically on a recurring schedule (e.g.,
  nightly at 2 AM) using `AppOnly` authentication, so no one has to sign in
  interactively. It only matters if you intend to use `AppOnly`/unattended
  mode — if you're always running the audit interactively yourself, you can
  ignore this file entirely. Must be run elevated (as Administrator):
  ```powershell
  .\Register-SPOOrphanedOwnerAuditTask.ps1 `
      -ScriptPath "C:\Path\To\Get-SPOOrphanedOwnerAudit.ps1" `
      -TaskName "SPO Orphaned Owner Audit" `
      -TriggerTime "02:00" `
      -RunAsUser "DOMAIN\svc-spo-audit"
  ```

## Known limitations

- **"Unknown" risk tier (site collection admin data gap):** `Get-PnPSiteCollectionAdmin`
  requires the signed-in account to be a site collection admin on that
  *specific* site — tenant-level SharePoint Administrator alone is not
  sufficient, and there is no tenant-wide equivalent cmdlet. When this happens
  on a site with no other confirmed active owner, the site is marked
  **Unknown** rather than falsely flagged Critical. This is a permissions gap,
  not a bug — granting the auditing account site collection admin rights
  tenant-wide (or on the specific sites in question) will resolve it.
- **ExchangeOnline mode + group owners:** Microsoft 365 Group owner
  enumeration always uses Microsoft Graph (`Get-MgGroupOwner`) — the Exchange
  Online equivalent, `Get-UnifiedGroupLinks`, only works in Windows PowerShell
  5.1, not PowerShell 7. Because `ExchangeOnlineManagement` and
  `Microsoft.Graph.Authentication` cannot reliably coexist in the same
  PowerShell process (a known, unresolved MSAL assembly conflict in
  Microsoft's own SDKs — confirmed regardless of connection order), no second
  Graph connection is opened in `ExchangeOnline` mode. Group-connected sites
  will show zero group owners in that mode. **Use `MicrosoftGraph` mode (the
  default) for complete, accurate results.**
- **ExchangeOnline mode + mailbox-less accounts:** `Get-EXORecipient` only
  "sees" mail-enabled recipients. A valid Entra ID account with no
  mailbox/license (e.g., an unlicensed guest) will not be found and will be
  misclassified as `DeletedFromEntra`, even though it still exists.
- **Group-principal membership check only covers real, queryable Entra ID
  groups.** When a site's `Owner` property or a Site Collection Admin is a
  group, the script resolves the group's Entra Object ID from the claim and
  checks (via Microsoft Graph) whether it has any active members — flagging
  a genuinely empty group as `EmptyGroup` instead of blindly trusting it as
  `Valid`. This only works for the group-claim format that actually encodes
  a queryable group GUID. Two rarer claim types cannot be resolved this way
  and remain unverified (treated as `Valid`, same as before this check
  existed): the tenant-wide "Everyone"/"Everyone except external users"
  claim, and SharePoint's own built-in permission-level groups (e.g. Limited
  Access System Group). This check also requires `MicrosoftGraph` identity
  provider mode; in `ExchangeOnline` mode, group-principal owners/admins are
  not verified at all and remain unverified/`Valid`.
- **Group-owner-governance check:** for a real security group used directly
  as a Site Collection Administrator (not the M365 Group owners sub-role),
  the script also checks whether that group itself has any owners. A group
  can have active members (so SharePoint access still works) but zero
  owners — meaning nobody can manage its membership going forward. This is
  reported separately as a lower-severity `Medium` risk (`GroupHasNoOwners`
  risk flag) and does not affect the primary `AccountStatus`/`EmptyGroup`
  determination above.
- **AppOnly/unattended mode is untested by the author** in a live scheduled
  run — see the warning under [Authentication modes](#authentication-modes)
  for the recommended manual "Run" verification step before trusting the
  nightly schedule.
- **`-OutputFolder` must be writable by the scheduled task's run-as account**
  (SYSTEM or a service account), not just by you interactively. The default
  (`AuditReports` next to the script) is usually fine, but if you point
  `-OutputFolder` at a network share or a path under another user's profile,
  confirm that account actually has write access — a permissions error here
  will prevent both the `.xlsx` report *and* the `.log` transcript from being
  written, so you may only see it via Task Scheduler's exit code.

## Repository layout

```
OrphanedOwnerAudit/
  Get-SPOOrphanedOwnerAudit.ps1          # Main audit script
  Register-SPOOrphanedOwnerAuditTask.ps1 # Optional: registers a scheduled task for unattended runs
  config.sample.ps1                      # Public template -- copy to config.ps1 and edit
  config.ps1                             # Your real tenant settings (gitignored, not in this repo)
  AuditReports/                          # Generated .xlsx reports land here (gitignored)
```

## Disclaimer

This tool is provided as-is, with no warranty of any kind. It performs
read-only operations against your tenant, but you are responsible for
reviewing the code and testing it in a non-production environment before
relying on it, especially the unattended/AppOnly execution path. Always
verify any "orphaned" or "deleted" finding manually (e.g., via `Get-MgUser`)
before taking remediation action — see the Notes column in the report for the
specific underlying error behind any `Unresolved` finding.

## Contributing

Issues and pull requests are welcome — especially real-world validation
reports for the `AppOnly`/unattended execution path, or testing against
Commercial/GCC tenants beyond GCC High.

## License

Licensed under the [MIT License](LICENSE).
