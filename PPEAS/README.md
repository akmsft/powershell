# Power Platform Environment Audited Table & Field Summary (PowerShell)

## Overview

This PowerShell script (`EnvironmentAuditingSummary.ps1`) enumerates Microsoft Dataverse tables that have auditing enabled and exports the audited attributes for each table to a CSV file. The script is designed for Power Platform administrators and security teams to inventory and review audit coverage across Dataverse environments.

### Key Features

- **Read-Only**: The script performs no modifications to your environment; it only queries and exports audit metadata.
- **Multi-Cloud Support**: Automatically detects and handles commercial Azure, GCCH (US Government Cloud), and GCC (US Government) clouds.
- **Enterprise Robustness**: Implements automatic retry logic with exponential backoff for throttled requests (HTTP 429/503), follows OData paging for large result sets, and validates token credentials before executing.
- **Flexible Authentication**: Supports three authentication methods for different automation scenarios (user delegation, service principal with certificate, or service principal with client secret).
- **Token Diagnostics**: Provides token inspection and audience validation to troubleshoot authentication issues.
- **Error Handling**: Includes graceful fallback logic for token acquisition when initial authentication targets fail.

## Prerequisites

### Local Machine Requirements

- **PowerShell Core 7.0+** (recommended) or **Windows PowerShell 5.1+** (minimum)
  - PowerShell Core 7+ is recommended for better cross-platform support and modern capabilities.
  - To check your version: Open PowerShell and run `$PSVersionTable.PSVersion`
  - If you need PowerShell Core 7+: Download from https://github.com/PowerShell/PowerShell/releases
  
- **Az.Accounts PowerShell Module**
  - The script automatically detects and installs this module if it is not already available.
  - This module is required for Azure authentication flows (device code and certificate-based auth).
  - Manual install (if needed): `Install-Module -Name Az.Accounts -Scope CurrentUser -Force`

- **Internet Connectivity**
  - Connectivity to Azure AD endpoints (`login.microsoftonline.com` or `login.microsoftonline.us` for government)
  - Connectivity to your target Dataverse organization URL
  - Outbound HTTPS (port 443) access to these endpoints

## Azure AD & Power Platform Setup (Required Steps)

Before running the script, you must prepare your Azure AD tenant and Power Platform environment. Follow these steps in order.

### Step 1: Identify Your Dataverse Organization URL

Locate your Dataverse organization URL; you will need this throughout the setup process:

- **Commercial Cloud**: Format is `https://<org>.crm.dynamics.com`
  - Example: `https://contoso.crm.dynamics.com`
- **GCCH (US Government Cloud)**: Format is `https://<org>.microsoftdynamics.us` or `https://<org>.crm.microsoftdynamics.us`
  - Example: `https://contoso.microsoftdynamics.us`
- **GCC (US Government)**: Instance-style format `https://crm<number>.dynamics.com`
  - Example: `https://crm9.dynamics.com`

To find your organization URL:
1. Open the **Power Platform Admin Center** (https://admin.powerplatform.microsoft.com)
2. Select your **Environment**
3. The URL is displayed in the environment details (or click **Settings** > **Session Details** to see the org URL)

**Record this URL now — you will need it for script configuration and app registration setup.**

### Step 2: Create an Azure AD App Registration

The script authenticates using an Azure AD application. Create one as follows:

1. Sign in to the **Azure Portal** (https://portal.azure.com)
2. Open **Azure Active Directory** (use the search bar if needed)
3. Select **App registrations** > **+ New registration**
4. **Name**: Provide a meaningful name for the app, e.g., `Dataverse Auditing Reader`
5. **Supported account types**: Choose based on your organization's requirements:
   - **Accounts in this organizational directory only** (single-tenant) — most secure if managing a single organization
   - **Accounts in any organizational directory** (multi-tenant) — only if you need to manage multiple tenants
6. **Redirect URI** (optional): Leave blank for non-interactive service principal authentication
7. Click **Register**
8. On the app registration page, **record the following values immediately**; you will need them for script configuration:
   - **Application (client) ID** (under "Display name" in the top section)
   - **Directory (tenant) ID** (under "Display name" in the top section)

### Step 3: Assign API Permissions

The app must have permission to read Dataverse metadata:

1. In the app registration, select **API permissions** (left sidebar)
2. Click **+ Add a permission**
3. Click **APIs my organization uses** (tab at the top)
4. Search for `Dynamics CRM` and select it from the results
5. On the "Request API permissions" screen, choose your permission type based on your authentication method:
   - **For app-only authentication (client secret or certificate)**: 
     - Select **Application permissions**
     - Find and check `user_impersonation` (or the equivalent Dataverse metadata scope)
   - **For user delegation (device code)**:
     - Select **Delegated permissions**
     - Find and check `user_impersonation`
6. Click **Add permissions**
7. Return to the **API permissions** page
8. Click **Grant admin consent for [Your Organization]** (requires Azure AD administrator role)
   - **Important**: Admin consent is **required** for the application to function correctly in service principal flows
   - If you do not have admin consent ability, ask your Azure AD administrator to grant consent

**Verify the permission is shown as "Granted"** in the API permissions list before proceeding.

### Step 4: Choose an Authentication Method and Create Credentials

The script supports three authentication methods. Choose one based on your scenario:

#### Option A: Device Code (Interactive, Delegated) — **Recommended for Ad Hoc Runs**

- **Best for**: One-time audits, local development, manual testing, interactive scenarios
- **Requires**: Client ID only (no secret or certificate needed)
- **Security**: User must interactively authenticate; no stored credentials
- **Flow**: You are prompted to visit a URL and enter an alphanumeric code

**Setup**: No additional credentials needed. Proceed to script configuration with your Client ID.

#### Option B: Client Credentials (Non-Interactive, Service Principal with Client Secret) — **Recommended for Automated Scheduling**

- **Best for**: Scheduled automation, CI/CD pipelines, Azure Automation runbooks, service accounts
- **Requires**: Application ID, Tenant ID, and a client secret
- **Security**: Client secret must be stored securely; if compromised, rotate immediately

**Steps to create a client secret:**

1. In the app registration, select **Certificates & secrets** (left sidebar)
2. Click the **Client secrets** tab
3. Click **+ New client secret**
4. **Description**: Provide a meaningful description, e.g., `Dataverse Auditing Script`
5. **Expires**: Select an expiration period:
   - Shorter expiration (6 months or less) is more secure; plan for secret rotation before expiration
   - "Never" (no expiration) simplifies automation but is less secure
6. Click **Add**
7. **IMMEDIATELY copy and record the secret value** — it will not be displayed again after you leave this page

**Critical Security Notes**:
- **Never store the secret in the script file or source control**
- Store the secret securely using one of:
  - **Azure Key Vault** (recommended for cloud automation)
  - **Local DPAPI-protected store** (for local scripts)
  - **CI/CD secure environment variables** (GitHub Secrets, Azure DevOps Secure Variables)
  - **Password manager** or **secure vault** for manual runs

#### Option C: Client Certificate (Non-Interactive, Service Principal with Certificate) — **Recommended for High-Security Environments**

- **Best for**: High-security environments, certificate-pinned automation, certificate management infrastructure
- **Requires**: A valid X.509 certificate with a private key
- **Security**: Certificate private key must be protected and access-restricted

**Steps to create or use a certificate:**

1. **Obtain or create a certificate**:
   - **If using an existing organizational certificate**: Skip to step 3
   - **If creating a self-signed certificate for testing**, run this PowerShell command:
     ```powershell
     $cert = New-SelfSignedCertificate -CertStoreLocation "Cert:\CurrentUser\My" `
       -Subject "CN=DataverseAuditingReader" -KeyExportPolicy Exportable
     $thumbprint = $cert.Thumbprint
     Write-Host "Certificate created. Thumbprint: $thumbprint"
     ```
     Record the thumbprint (40-character hex string)

2. **Export the certificate for secure storage** (if needed):
   ```powershell
   $cert = Get-Item -Path "Cert:\CurrentUser\My\$thumbprint"
   Export-PfxCertificate -Cert $cert -FilePath "cert.pfx" `
     -Password (ConvertTo-SecureString "secure_password" -AsPlainText -Force)
   ```
   Store `cert.pfx` in a secure location (Azure Key Vault, secure file storage, etc.)

3. **Upload the public certificate to Azure AD**:
   - In the app registration, select **Certificates & secrets**
   - Click the **Certificates** tab
   - Click **Upload certificate**
   - Upload the public certificate (.cer file or public part of .pfx)
   - Verify the thumbprint matches your certificate

4. **Record the certificate thumbprint** — you will need it for script configuration

**Critical Security Notes**:
- Private keys must be protected (Windows certificate store or Azure Key Vault)
- The service account or automation context running the script **must have read access** to the private key
- On shared systems, store certificates in the machine certificate store (Cert:\LocalMachine\My) with restricted access
- For Azure automation, use **Azure Key Vault** to store and manage certificates

### Step 5: Provision the App User in Dataverse

The authenticated principal (user or service principal) must have permissions to read Dataverse metadata.

#### For User Authentication (Device Code Flow):

1. Open the **Power Platform Admin Center** (https://admin.powerplatform.microsoft.com)
2. Select your **Environment**
3. Go to **Settings** > **Users + permissions** > **Users**
4. Locate and **verify your user appears in the list** (if you are running this for the first time, you may be auto-provisioned on first login)
5. Click on your user name
6. Click **Manage roles** (or scroll to the Roles section)
7. Assign at least one of the following roles:
   - **System Administrator** — full access (use for testing)
   - **System Customizer** — read Dataverse metadata (sufficient for this script)
   - **System Reader** — read-only metadata access (sufficient for this script)
8. Click **Save**

#### For Service Principal Authentication (Client Credentials or Certificate):

The app (service principal) does not automatically have environment access. You must create an **application user**:

1. Open the **Power Platform Admin Center** (https://admin.powerplatform.microsoft.com)
2. Select your **Environment**
3. Go to **Settings** > **Users + permissions** > **Application users**
4. Click **+ New app user**
5. On the "Create a new application user" panel:
   - Click **Create**
   - In the search box, enter your app registration **Application ID** or **Name** (e.g., "Dataverse Auditing Reader")
   - Select the app from the search results
   - Click **Create** again
6. The new app user is created and opened
7. Scroll to the **Roles** section and click **Manage roles**
8. Assign one of:
   - **System Administrator** — full access (not recommended for service principals)
   - **System Customizer** — read Dataverse metadata (sufficient for this script)
   - **System Reader** — read-only metadata access (sufficient for this script)
   - **Custom role** with at least these privileges:
     - `Read` on **EntityDefinitions** (to enumerate tables and metadata)
     - `Read` on **Attributes** (to enumerate and read attribute audit settings)
9. Click **Save**

### Step 6: Enable Auditing in the Dataverse Environment

Auditing must be enabled at the **organization level** (prerequisite for all table and attribute auditing).

#### Enable Organization-Level Auditing:

1. Open the **Power Platform Admin Center** (https://admin.powerplatform.microsoft.com)
2. Select your **Environment**
3. Go to **Settings** > **Auditing**
4. Under "Manage Dataverse auditing", toggle **Start recording audit logs** to **On**
   - **Important**: Organization-level auditing is a **prerequisite**; no audit logs are recorded without this setting
   - **Important**: Enabling auditing consumes database storage; review your organization's audit retention policies

#### Enable Table-Level Auditing:

1. Open the **Power Platform Maker Portal** (https://make.powerapps.com)
2. Select your **Environment** (top-right environment selector)
3. In the left sidebar, expand **Data** and click **Tables**
4. Click on the table you want to audit (e.g., "Account")
5. Go to **Settings** (upper right) > **Advanced options**
6. Scroll down to the **Auditing** section
7. Toggle **Audit (if organization auditing is enabled)** to **On**
8. Click **Save** (at the bottom-left)

#### Enable Attribute-Level Auditing (For Specific Columns):

1. Follow the steps above to open a table in the Maker Portal
2. Select the **column** (attribute) you want to audit from the list (e.g., "Account Name")
3. On the right panel, under **Properties**, scroll down to **Advanced options**
4. Toggle **Enable auditing** to **On**
5. Click **Save**

**Important**: Audit logs are only created *after* auditing is enabled. Historical data before enabling auditing is **not captured**.

### Step 7: Multi-Cloud Scenarios

The script **automatically detects** your cloud environment based on the organization URL and configures the correct Azure and Dataverse endpoints.

| Cloud | Organization URL Pattern | Azure Login Endpoint | Dataverse Resource | Notes |
|-------|---|---|---|---|
| **Commercial Cloud** | `*.crm.dynamics.com` or `*.dynamics.com` | `login.microsoftonline.com` | `crm.dynamics.com` | Default for commercial tenants |
| **GCCH (US Government Cloud)** | `*.microsoftdynamics.us` or `*.crm.microsoftdynamics.us` | `login.microsoftonline.us` | `crm.microsoftdynamics.us` | Use government tenant ID and endpoints |
| **GCC (US Government)** | `crm<number>.dynamics.com` (instance-style) | `login.microsoftonline.us` | `crm.microsoftdynamics.us` | Treat as GCC cloud; use gov endpoints |

**Special Considerations for Government Clouds**:
- **Tenant ID**: Use your government tenant ID (not the commercial tenant)
- **App Registration**: Create the app registration in your government Azure AD, not commercial Azure AD
- **Authentication Endpoints**: The script automatically uses the correct government endpoints (`login.microsoftonline.us`)
- **No manual configuration required**: The script detects the cloud automatically from your organization URL

---

## Script Configuration

Now that Azure and Power Platform are prepared, configure the script with your specific values.

### Opening the Script for Configuration

1. Download or clone the repository to your local machine
2. Open `EnvironmentAuditingSummary.ps1` in a text editor (PowerShell ISE, VS Code with PowerShell extension, or Notepad)
3. Scroll to the top of the file to find the **Configuration** section (marked by `# -------------------------`)
4. Edit the variables to match your environment (see examples below)

### Configuration Variables

| Variable | Required | Description | Example |
|----------|----------|---|---|
| `$OrgUrl` | Yes | Your Dataverse organization URL | `https://contoso.crm.dynamics.com` |
| `$TenantId` | Yes | Azure AD tenant ID (Directory (tenant) ID from app registration) | `00000000-0000-0000-0000-000000000000` |
| `$ClientId` | Yes | App registration Application (client) ID | `11111111-1111-1111-1111-111111111111` |
| `$Auth` | Yes | Authentication method: `devicecode`, `clientcertificate`, or `clientcredentials` | `devicecode` |
| `$ClientSecret` | Conditional | Required only for `clientcredentials` auth | `xxxxxxxxxxxxx` (store securely) |
| `$CertificateThumbprint` | Conditional | Required only for `clientcertificate` auth (40-char hex string) | `ABCD1234...` |
| `$IncludeFieldsFromAllTables` | No | Set to `$true` to include audited attributes even from tables with auditing disabled (advanced) | `$false` |
| `$OutDir` | No | Output directory for CSV and JSON files (defaults to current directory) | `C:\Audit Export` |
| `$OutFile` | No | Output CSV filename (defaults to `audited_table_attributes.csv`) | `audit_report.csv` |
| `$MaxRetryAttempts` | No | Maximum retries for throttled API requests (defaults to 6) | `6` |
| `$InitialBackoffSeconds` | No | Initial backoff wait time in seconds for retry logic (defaults to 2) | `2` |

### Configuration Examples

#### Example 1: Device Code (Interactive) — Recommended for Ad Hoc Runs

```powershell
$OrgUrl                 = "https://contoso.crm.dynamics.com"
$TenantId               = "00000000-0000-0000-0000-000000000000"
$ClientId               = "11111111-1111-1111-1111-111111111111"
$Auth                   = "devicecode"
$ClientSecret           = ""  # Not needed for device code
$CertificateThumbprint  = ""  # Not needed for device code
$OutDir                 = "."
$OutFile                = "audited_table_attributes.csv"
```

When you run the script, you will see a prompt:
```
To sign in, open https://microsoft.com/devicelogin and enter code: ABCDEFGH
```

Visit the URL, enter the code, and authenticate in your browser. The script will continue automatically once authenticated.

#### Example 2: Client Credentials (Non-Interactive with Secret) — Recommended for Automation

```powershell
$OrgUrl                 = "https://contoso.crm.dynamics.com"
$TenantId               = "00000000-0000-0000-0000-000000000000"
$ClientId               = "11111111-1111-1111-1111-111111111111"
$Auth                   = "clientcredentials"
$ClientSecret           = "your-client-secret"  # Store securely; do not hardcode
$CertificateThumbprint  = ""  # Not needed for client credentials
$OutDir                 = "C:\Audit Reports"
$OutFile                = "audited_attributes.csv"
```

**Security Note**: Store `$ClientSecret` in a secure secret manager:
- For local scripts: Use Azure Key Vault or Windows DPAPI
- For automation: Use CI/CD secure variables or Azure Automation secure variables
- Never hardcode secrets in the script or commit to source control

#### Example 3: Client Certificate (Non-Interactive with Certificate) — Recommended for High-Security Scenarios

```powershell
$OrgUrl                 = "https://contoso.crm.dynamics.com"
$TenantId               = "00000000-0000-0000-0000-000000000000"
$ClientId               = "11111111-1111-1111-1111-111111111111"
$Auth                   = "clientcertificate"
$ClientSecret           = ""  # Not needed for certificate auth
$CertificateThumbprint  = "ABCD1234567890ABCD1234567890ABCD12345678"  # 40-character hex string
$OutDir                 = "."
$OutFile                = "audited_attributes.csv"
```

**Security Note**: Ensure the certificate's private key is:
- Stored in the Windows certificate store with restricted access
- Or stored in Azure Key Vault for cloud automation
- The service account running the script must have read access to the private key

---

## Running the Script

### Prerequisites Checklist

Before running the script, verify the following:

- ✅ **Azure AD app registration is created** with Client ID and Tenant ID recorded
- ✅ **API permissions are granted** with admin consent (Dynamics CRM > user_impersonation)
- ✅ **Authentication credentials are created and secured**:
  - For device code: No additional setup needed
  - For client secret: Secret is stored securely and accessible
  - For client certificate: Certificate is in the certificate store and thumbprint is recorded
- ✅ **App user is created and provisioned in Dataverse** (for service principal auth)
- ✅ **Environment user is assigned a role** (System Customizer or System Reader minimum)
- ✅ **Organization-level auditing is enabled** in Power Platform Admin Center
- ✅ **Table-level auditing is enabled** for tables you want to audit
- ✅ **Attribute-level auditing is enabled** for specific attributes you want to track
- ✅ **PowerShell Core 7+ is installed** or Windows PowerShell 5.1+ available
- ✅ **Script configuration is updated** with your environment values

### Step-by-Step Execution

1. **Open PowerShell**:
   - Windows: Press `Win+X` > "Windows PowerShell" or "Terminal"
   - macOS/Linux: Open Terminal and type `pwsh` (if PowerShell Core is installed)

2. **Navigate to the script directory**:
   ```powershell
   cd C:\path\to\script\directory
   ```

3. **Run the script**:
   ```powershell
   pwsh -File .\EnvironmentAuditingSummary.ps1
   ```
   Or on Windows PowerShell:
   ```powershell
   powershell -File .\EnvironmentAuditingSummary.ps1
   ```

4. **Wait for script completion**:
   - If using device code: Follow the browser prompt to authenticate
   - The script will display progress and any warnings
   - Output will indicate successful completion with the file path

5. **Review the output files**:
   - **`audited_table_attributes.csv`** (or your configured filename): Contains audited attributes by table
   - **`org_audit_status.json`** (optional): Contains organization-level audit settings if available

### Sample Output

#### CSV Output (audited_table_attributes.csv)

```csv
table_logical,table_display,table_auditing_enabled,attribute_logical,attribute_display,attribute_auditing_enabled
account,Account,true,name,Account Name,true
account,Account,true,accountnumber,Account Number,true
contact,Contact,true,emailaddress1,Email,true
```

#### JSON Output (org_audit_status.json)

```json
[
  {
    "isauditenabled": true,
    "isuseraccessauditenabled": false,
    "auditretentionperiodv2": 30
  }
]
```

---

## Troubleshooting Common Issues

### Authentication Errors

#### Error: "401 Unauthorized"

**Symptoms**: Script terminates with "401 Unauthorized" when calling the Dataverse API

**Causes**:
- Token was issued for the wrong audience (resource)
- App registration permissions are not granted or not consented
- Token expired or incorrect credentials

**Solutions**:
1. Verify admin consent was granted:
   - Azure Portal > App registration > API permissions
   - Ensure "Granted for [your-org]" is shown (green checkmark)
   - If not, click "Grant admin consent for [your-org]"

2. For service principal (client secret/certificate):
   - Verify the app user is created in the environment
   - Verify the app user has a role assigned (System Customizer minimum)

3. For device code:
   - Verify you signed in with an account that has access to the environment
   - Try again with a fresh device code

4. The script has built-in fallback logic:
   - If initial token request fails, it automatically retries with the organization URL as the resource
   - Check console output for fallback attempts

#### Error: "403 Forbidden"

**Symptoms**: Script runs but API returns 403 Forbidden

**Causes**:
- User or service principal lacks Dataverse permissions
- Missing or insufficient role assignment

**Solutions**:
1. Verify the user or app user has a role assigned:
   - Power Platform Admin Center > Environment > Users or Application users
   - Select the user/app
   - Ensure a role is assigned (System Customizer or System Reader minimum)

2. Verify the role has the required permissions:
   - Ensure the role includes "Read" on EntityDefinitions and Attributes
   - System Customizer and System Reader roles include these by default

3. If using a custom role, add the following privileges:
   - `Read` on **EntityDefinitions**
   - `Read` on **Attributes**

#### Error: "Module Az.Accounts not found"

**Symptoms**: Script fails to import Az.Accounts module

**Causes**:
- Module not installed
- PowerShell execution policy prevents installation
- User permissions do not allow module install

**Solutions**:
1. Install the module manually:
   ```powershell
   Install-Module -Name Az.Accounts -Scope CurrentUser -Force
   ```

2. If that fails, try system-wide install (requires administrator):
   ```powershell
   Install-Module -Name Az.Accounts -Force
   ```

3. Verify the module is installed:
   ```powershell
   Get-Module -ListAvailable -Name Az.Accounts
   ```

### API Throttling

#### Error: "429 Too Many Requests" or "503 Service Unavailable"

**Symptoms**: Script encounters repeated 429/503 errors even after retries

**Causes**:
- High API request volume from multiple concurrent scripts
- Dataverse throttling policies (limits per minute)
- Running during peak usage hours

**Solutions**:
1. **The script includes automatic retry logic**:
   - Default: 6 retries with exponential backoff starting at 2 seconds
   - Configure via `$MaxRetryAttempts` and `$InitialBackoffSeconds`

2. **Reduce concurrency**:
   - Only run one audit script at a time per environment
   - Stagger multiple environment scripts

3. **Run during off-peak hours**:
   - Schedule audits for low-usage periods
   - Avoid running during business hours

4. **Increase retry settings** (temporary):
   ```powershell
   $MaxRetryAttempts = 10
   $InitialBackoffSeconds = 5
   ```

### Output Issues

#### Error: "No write access to output directory"

**Symptoms**: Script fails to write CSV file; error mentions output directory permissions

**Causes**:
- Output directory is read-only
- User lacks write permissions on the directory
- Disk full or path invalid

**Solutions**:
1. Change the output directory:
   ```powershell
   $OutDir = "C:\Users\$env:USERNAME\Documents"  # User Documents folder (usually writable)
   ```

2. Verify permissions:
   - Right-click the folder > Properties > Security tab
   - Ensure your user has "Modify" or "Write" permissions

3. Choose a different directory:
   - Desktop: `$OutDir = "$env:USERPROFILE\Desktop"`
   - Temp folder: `$OutDir = $env:TEMP`

#### Output CSV is empty

**Symptoms**: Script runs successfully but CSV contains no data rows (only headers)

**Causes**:
- No tables have auditing enabled
- No attributes have auditing enabled
- Filters are excluding all results

**Solutions**:
1. Verify auditing is enabled:
   - Power Platform Admin Center > Environment > Auditing
   - Ensure "Start recording audit logs" is **On**

2. Verify table-level auditing:
   - Maker Portal > Table > Settings > Advanced options > Auditing
   - Ensure "Audit (if organization auditing is enabled)" is **On**

3. Verify attribute-level auditing:
   - Maker Portal > Table > Select column > Properties > Advanced options > Auditing
   - Ensure "Enable auditing" is **On**

4. Try the advanced option to include all tables:
   ```powershell
   $IncludeFieldsFromAllTables = $true
   ```
   This will export audited attributes even if the table-level flag is off (useful for diagnostics)

#### Token stored in temporary directory (diagnostics)

**Symptoms**: Script creates `dv_access_token.txt` in the temp folder

**Causes**:
- For device code flow, the script writes the access token to `%TEMP%\dv_access_token.txt` for diagnostics

**Solutions**:
- **Production/Security**: Delete `dv_access_token.txt` after script execution
  ```powershell
  Remove-Item -Path "$env:TEMP\dv_access_token.txt" -ErrorAction SilentlyContinue
  ```
- **For Development**: Keep the file for token inspection using:
  ```powershell
  (Get-Content "$env:TEMP\dv_access_token.txt") | ConvertTo-SecureString -AsPlainText -Force
  # Use jwt.ms to decode the token for troubleshooting
  ```

---

## Advanced Usage

### Fine-Grained Output Control

#### Custom CSV Formatting

The script exports to CSV with default UTF-8 encoding (no BOM). To customize output:

1. **Change column order**: Edit the `pscustomobject` in the script where rows are created
2. **Add or remove columns**: Add properties to the output object and update the CSV columns
3. **Change encoding**: Edit the final export line:
   ```powershell
   # For UTF-8 with BOM:
   $exportRows | ConvertTo-Csv -NoTypeInformation | Out-File -Path $outPath -Encoding UTF8
   
   # For ASCII:
   $exportRows | ConvertTo-Csv -NoTypeInformation | Out-File -Path $outPath -Encoding ASCII
   ```

#### Export to Alternative Formats

Convert CSV to other formats after export:

```powershell
# Convert to Excel (requires ImportExcel module)
Install-Module ImportExcel -Scope CurrentUser
$csv = Import-Csv -Path "audited_table_attributes.csv"
$csv | Export-Excel -Path "audited_table_attributes.xlsx" -AutoSize

# Convert to JSON
$csv = Import-Csv -Path "audited_table_attributes.csv"
$csv | ConvertTo-Json -Depth 3 | Out-File "audited_attributes.json"
```

### Scheduling for Automated Audits

#### Windows Task Scheduler (Windows Only)

Create a scheduled task to run the script at regular intervals:

1. **Open Task Scheduler**:
   - Press `Win+R`, type `taskschd.msc`, and press Enter
   - Or: Control Panel > Administrative Tools > Task Scheduler

2. **Create a new task**:
   - Right-click **Task Scheduler Library** > **Create Basic Task**
   - Name: `Dataverse Auditing Export`
   - Description: `Periodic export of audited attributes`

3. **Set the trigger** (when to run):
   - **Daily**: Trigger > New > Repeat daily at a specific time
   - **Weekly**: Repeat on specific days
   - Example: Every Monday at 2:00 AM

4. **Set the action** (what to run):
   - Action: **Start a program**
   - Program: `pwsh` (or `powershell` for Windows PowerShell)
   - Arguments: `-File "C:\path\to\EnvironmentAuditingSummary.ps1" -NoExit`
   - Start in: `C:\path\to\script\directory`

5. **Set conditions and settings**:
   - **Run with highest privileges**: Check (if script needs admin)
   - **Run if user is logged in**: Select based on your scenario
   - **Stop the task if it runs longer than**: Set to 1-2 hours

6. **Click OK** and provide credentials when prompted

#### PowerShell Scheduled Job (Cross-Platform)

For PowerShell Core 7+ (Windows, macOS, Linux):

```powershell
# Register a scheduled job
$trigger = New-JobTrigger -Daily -At 2:00 AM
$options = New-ScheduledJobOption -RunElevated -StartIfOnBattery
Register-ScheduledJob -Name "DataverseAuditingExport" `
  -ScriptBlock { & "C:\path\to\EnvironmentAuditingSummary.ps1" } `
  -Trigger $trigger -ScheduledJobOption $options

# View registered jobs
Get-ScheduledJob

# Remove a job
Unregister-ScheduledJob -Name "DataverseAuditingExport" -Force
```

#### Azure Automation Runbook (Cloud Automation)

To run the script in Azure Automation:

1. Create an Azure Automation Account
2. Import the `Az.Accounts` module
3. Create a PowerShell runbook:
   - Paste the script content
   - For client secret: Store in Key Vault and use `Get-AzKeyVaultSecret`
   - For certificate: Import the certificate into Automation Account
4. Configure a schedule and identity (Managed Identity or Run As account)
5. Monitor execution via the Automation Account Activity log

Example: Retrieve secret from Key Vault in runbook:
```powershell
$keyVaultName = "my-keyvault"
$secretName = "DataverseClientSecret"
$secret = Get-AzKeyVaultSecret -VaultName $keyVaultName -Name $secretName
$ClientSecret = $secret.SecretValueText
```

---

## Security Best Practices

### Credential Management

- **Client Secrets**: 
  - Store in Azure Key Vault, not in the script or source control
  - Rotate secrets every 6 months
  - Use separate secrets for different environments (dev/test/prod)

- **Certificates**:
  - Store private keys in protected certificate stores or Key Vault
  - Use SHA256 or stronger algorithms
  - Rotate certificates annually or per organizational policy

- **Device Code Tokens**:
  - The script writes access tokens to `%TEMP%\dv_access_token.txt` for diagnostics
  - **Delete this file after troubleshooting**
  - Do not use this behavior in production without modification

### Least Privilege

- **Role Assignment**:
  - Assign "System Reader" (read-only) for service principals if only reading metadata
  - Use "System Customizer" only if modification is required
  - Do not assign "System Administrator" unless necessary

- **Environment Access**:
  - Limit service principals to specific environments (not all environments)
  - Use separate app registrations for different tenants or scenarios

### Audit Trail

- Script execution should be logged:
  - Scheduled task logs (Task Scheduler history)
  - Azure Automation logs (if using cloud automation)
  - Syslog or centralized logging (for compliance)
- Regularly review who has access to credentials and scripts
- Monitor output reports for unexpected changes in audit configuration

---

## Limitations and Known Considerations

- **Read-Only**: The script performs no modifications; it only reads and exports audit metadata.
- **Requires Auditing Enabled**: The script can only export attributes that have auditing enabled. If no tables or attributes have auditing enabled, the output will be empty.
- **Subject to Dataverse Throttling**: High-frequency requests may trigger API throttling (HTTP 429); the script includes automatic retry logic with exponential backoff to handle this gracefully.
- **API Availability**: Some organization-level audit endpoints may not be available in all environments or versions; the script gracefully handles these cases.

---

## Support and Contribution

If you encounter issues or have suggestions for improvement:

1. **Check the Troubleshooting section** above for common problems and solutions
2. **Review script logs** for detailed error messages and diagnostics
3. **Verify Azure AD and Power Platform configuration** matches the setup steps
4. **Consult Microsoft documentation**:
   - [Dataverse Web API documentation](https://learn.microsoft.com/power-apps/developer/data-platform/webapi/overview)
   - [Power Platform auditing](https://learn.microsoft.com/power-platform/admin/audit-data-user-activity)
   - [Azure AD app registration guide](https://learn.microsoft.com/azure/active-directory/develop/quickstart-register-app)

For code contributions or issue reports, follow the repository's contributing guidelines.

---

## Script Logic Overview

This section provides a high-level overview of how the script works, useful for understanding its behavior and customizing it if needed.

### Authentication Flow

1. **Detect Cloud Environment**: Based on the organization URL, the script determines whether to target commercial Azure, GCCH, or GCC
2. **Acquire Access Token**: Using the specified auth method (device code, client credentials, or certificate), acquire an access token for the Dataverse resource
3. **Token Validation**: Decode and validate the token to confirm it has the correct audience and permissions
4. **Fallback Logic**: If the initial token fails (401 Unauthorized), automatically retry using the organization URL as the token resource

### Data Collection

1. **Enumerate Tables**: Query EntityDefinitions with `IsAuditEnabled eq true` filter (or all entities if `$IncludeFieldsFromAllTables` is true)
2. **Follow Paging**: If results are paginated, follow `@odata.nextLink` to retrieve all pages
3. **Enumerate Attributes**: For each table, query Attributes with `IsAuditEnabled eq true` filter
4. **Normalize Values**: Handle different data types for the `IsAuditEnabled` property (BooleanManagedProperty vs. plain boolean)

### Error Handling and Resilience

1. **Retry on Throttling**: HTTP 429 (Too Many Requests) and 503 (Service Unavailable) trigger automatic retry with exponential backoff
2. **Graceful Degradation**: Non-critical errors (e.g., org audit endpoint unavailable) are logged as warnings but do not stop execution
3. **Output Validation**: Before export, rows are filtered to ensure only attributes with `attribute_auditing_enabled = true` are included

### Output Generation

1. **Create Output Directory**: Ensure the output directory exists and is writable; create it if necessary
2. **Export to CSV**: Convert collected data to CSV format with UTF-8 encoding (no BOM) and sort by table and attribute logical names
3. **Optional JSON Export**: If available, export organization-level audit settings to JSON for reference



