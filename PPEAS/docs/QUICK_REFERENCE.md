# EnvironmentAuditingSummary.ps1 - Quick Reference Guide

## What This Script Does

This PowerShell script connects to your Dataverse environment and exports a list of all tables and attributes that have auditing enabled. The results are saved to a CSV file that you can review, analyze, and share with your team.

## Output

The script produces:
1. **audited_table_attributes.csv** - Contains all audited tables and their audited attributes
2. **org_audit_status.json** - (Optional) Organization-level audit settings

### CSV Columns

| Column | Description |
|--------|-------------|
| `table_logical` | Technical name of the table (e.g., "account") |
| `table_display` | Display name of the table (e.g., "Account") |
| `table_auditing_enabled` | Whether the table has auditing turned on |
| `attribute_logical` | Technical name of the attribute (e.g., "name") |
| `attribute_display` | Display name of the attribute (e.g., "Account Name") |
| `attribute_auditing_enabled` | Whether the attribute has auditing turned on |

## Quick Start (3 Steps)

### Step 1: Configure the Script

Open `EnvironmentAuditingSummary.ps1` in Notepad or VS Code and edit these values:

```powershell
$OrgUrl = "https://contoso.crm.dynamics.com"        # Your organization URL
$TenantId = "00000000-0000-0000-0000-000000000000"  # Your tenant ID
$ClientId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"  # Your app ID
$Auth = "devicecode"                                 # Or "clientcredentials" or "clientcertificate"
$ClientSecret = ""                                   # If using clientcredentials, set this
$CertificateThumbprint = ""                         # If using clientcertificate, set this
```

**Don't have these values?** See the detailed setup in README.md.

### Step 2: Open PowerShell

Press `Win+X` and select **Windows PowerShell** or **Terminal**.

### Step 3: Run the Script

```powershell
cd C:\path\to\script
pwsh -File .\EnvironmentAuditingSummary.ps1
```

Or just:

```powershell
.\EnvironmentAuditingSummary.ps1
```

## Authentication Options

### Option 1: Device Code (Easiest for Testing)

```powershell
$Auth = "devicecode"
$ClientId = "your-app-id"
# No client secret or certificate needed
```

When you run the script:
1. A browser window opens
2. You're asked to enter a code on https://microsoft.com/devicelogin
3. Script continues automatically

### Option 2: Client Credentials (Best for Scheduled Tasks)

```powershell
$Auth = "clientcredentials"
$ClientId = "your-app-id"
$ClientSecret = "your-secret"  # Store securely, don't hardcode
```

Unattended authentication using an app registration secret.

### Option 3: Certificate (Most Secure)

```powershell
$Auth = "clientcertificate"
$ClientId = "your-app-id"
$CertificateThumbprint = "ABCD1234..."  # Your certificate thumbprint
```

Authentication using a certificate instead of a secret.

## Viewing Results

After the script completes:

1. **Open the CSV file** in Excel or any spreadsheet program
2. **Analyze** the audit coverage:
   - How many tables have auditing enabled?
   - Which attributes are audited?
   - Are important attributes missing?
3. **Share** with your team for review and compliance

## Understanding the Output

### Example CSV Content

```csv
table_logical,table_display,table_auditing_enabled,attribute_logical,attribute_display,attribute_auditing_enabled
account,Account,true,name,Account Name,true
account,Account,true,accountnumber,Account Number,true
account,Account,true,numberofemployees,Number of Employees,true
contact,Contact,true,emailaddress1,Email,true
contact,Contact,true,telephone1,Business Phone,true
```

This means:
- The Account table has auditing enabled
- Three Account attributes are being audited: Name, Account Number, Employees
- The Contact table has auditing enabled
- Two Contact attributes are being audited: Email, Business Phone

## Troubleshooting

### "401 Unauthorized" Error

**Possible causes:**
- Wrong Client ID or Tenant ID
- Missing admin consent for app permissions
- User not assigned to the environment

**Solution:**
1. Verify Client ID and Tenant ID are correct
2. Check Azure Portal > App registrations > API permissions > "Grant admin consent"
3. Verify user is assigned to Dataverse environment

### "403 Forbidden" Error

**Possible cause:**
- User or app doesn't have permission to access Dataverse metadata

**Solution:**
1. Go to Power Platform Admin Center > Environments
2. Select your environment > Users or Application users
3. Find the user/app and assign a role: System Reader or System Customizer

### "Module Az.Accounts not found"

**Solution:**
The script will try to install automatically. If it fails:

```powershell
Install-Module -Name Az.Accounts -Scope CurrentUser -Force
```

### Script runs but CSV is empty

**Possible causes:**
- Organization auditing is not enabled
- No tables/attributes have auditing enabled
- Auditing was just enabled (takes a moment to appear)

**Solution:**
1. Power Platform Admin Center > Environments > Settings > Auditing
2. Ensure "Start recording audit logs" is **ON**
3. For specific tables: Maker Portal > Tables > [Table] > Settings > Auditing
4. For specific attributes: Select attribute > Properties > Advanced > Auditing **ON**

### "API request throttled" Warning

This is normal for large environments. The script automatically retries and continues. Wait for it to complete.

## Advanced Usage

### Running on a Schedule (Windows Task Scheduler)

1. Open **Task Scheduler**
2. Create Basic Task
3. Set trigger: Daily at 2:00 AM
4. Set action:
   - Program: `pwsh`
   - Arguments: `-File "C:\path\to\EnvironmentAuditingSummary.ps1"`
5. Click OK

### Including All Tables (Even Unaudited Ones)

For diagnostics, see all tables with potential auditable attributes:

```powershell
$IncludeFieldsFromAllTables = $true
```

Then run the script.

### Using with Azure Key Vault (Secure Secrets)

Instead of hardcoding the secret:

```powershell
$secret = Get-AzKeyVaultSecret -VaultName "my-vault" -Name "DataverseClientSecret"
$ClientSecret = $secret.SecretValueText
```

## Security Tips

1. **Never hardcode secrets** in the script
2. **Never commit** secrets to source control (Git, etc.)
3. **Store secrets** in:
   - Azure Key Vault (cloud automation)
   - Windows Credential Manager (local use)
   - CI/CD pipeline secure variables
4. **Rotate secrets** every 6 months
5. **Delete token files** after troubleshooting (`%TEMP%\dv_access_token.txt`)
6. **Restrict file permissions** on the script file
7. **Use certificates** instead of secrets when possible

## Getting Help

1. **Check README.md** for detailed setup instructions
2. **Review SCRIPT_IMPROVEMENTS.md** to understand the code structure
3. **Look at the .NOTES section** in the script itself (run: `Get-Help .\EnvironmentAuditingSummary.ps1 -Full`)
4. **Check the console output** - the script provides detailed error messages

## What Happens During Execution

```
[STEP 1/6] Detecting cloud environment...
  ?
[STEP 2/6] Authenticating to Azure AD...
  ?
[STEP 3/6] Validating token with test API call...
  ?
[STEP 4/6] Preparing output directory...
  ?
[STEP 5/6] Querying Dataverse for audited tables and attributes...
  ?
[STEP 6/6] Exporting results to CSV...
  ?
? SCRIPT COMPLETED SUCCESSFULLY
```

Each step is reported, so you know what's happening.

## Support Matrix

| Environment | Supported |
|------------|-----------|
| Commercial Cloud (*.crm.dynamics.com) | ? |
| GCCH (*.microsoftdynamics.us) | ? |
| GCC (crm#.dynamics.com) | ? |
| Sovereign clouds (China, etc.) | ? |

## Key Features

? **Automatic cloud detection** - Works with commercial, GCCH, and GCC  
? **Three auth methods** - Device code, certificate, or secret  
? **Automatic retry** - Handles API throttling gracefully  
? **Progress reporting** - Know what's happening  
? **Multi-page support** - Handles large result sets  
? **Error recovery** - Continues on non-critical failures  
? **Security focused** - No secrets logged, secure token handling  
? **Beginner-friendly** - Detailed messages and error explanations  

## Next Steps After Export

1. **Review** the CSV file with your team
2. **Identify** gaps in audit coverage
3. **Decide** if more tables/attributes should be audited
4. **Enable auditing** for those tables/attributes
5. **Run the script again** to verify changes

---

**Happy Auditing!** ??

For questions or issues, refer to README.md or contact your Power Platform administrator.
