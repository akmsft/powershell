<#
.SYNOPSIS
    Enumerate Dataverse tables with auditing enabled and export their audited attributes to CSV.

.DESCRIPTION
    This script connects to a Microsoft Dataverse environment, queries all tables and attributes that have 
    auditing enabled, and exports the results to a CSV file. The CSV contains:
    
    - table_logical: The logical name of the table (e.g., "account")
    - table_display: The display name of the table (e.g., "Account")
    - table_auditing_enabled: Whether the table has auditing enabled (true/false)
    - attribute_logical: The logical name of the audited attribute (e.g., "name")
    - attribute_display: The display name of the audited attribute (e.g., "Account Name")
    - attribute_auditing_enabled: Whether the attribute has auditing enabled (true/false)

.AUTHENTICATION METHODS
    The script supports three authentication methods:
    
    1. DEVICE CODE (Interactive, Delegated)
       - Best for: Ad hoc audits, manual testing, non-automated scenarios
       - Setup: Set $Auth = 'devicecode' and provide $ClientId
       - Flow: You will be prompted to visit a URL and enter an alphanumeric code
    
    2. CLIENT SECRET (Non-Interactive, Service Principal)
       - Best for: Scheduled automation, CI/CD pipelines, Azure Automation runbooks
       - Setup: Set $Auth = 'clientcredentials' and provide $ClientId and $ClientSecret
       - Security: Store $ClientSecret securely (never hardcode in script)
    
    3. CLIENT CERTIFICATE (Non-Interactive, Service Principal)
       - Best for: High-security environments, certificate-pinned automation
       - Setup: Set $Auth = 'clientcertificate' and provide $ClientId and $CertificateThumbprint
       - Security: Ensure certificate private key is protected and accessible to the script runtime

.CLOUD SUPPORT
    Automatically detects and handles:
    - Commercial Cloud (*.crm.dynamics.com)
    - GCCH / US Government Cloud (*.microsoftdynamics.us)
    - GCC / US Government Instance (crm#.dynamics.com)

.ERROR HANDLING & RESILIENCE
    - Automatic retry with exponential backoff for throttled requests (HTTP 429/503)
    - OData paging support (automatically follows @odata.nextLink)
    - Token audience fallback: If 401 error occurs, automatically retries with org URL as resource
    - Graceful handling of missing org audit endpoints

.EXAMPLES
    # Device code (interactive) - simple testing
    $OrgUrl = 'https://contoso.crm.dynamics.com'
    $TenantId = '00000000-0000-0000-0000-000000000000'
    $ClientId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    $Auth = 'devicecode'
    & .\EnvironmentAuditingSummary.ps1

    # Client credentials (automated) - scheduled task
    $OrgUrl = 'https://contoso.crm.dynamics.com'
    $TenantId = '00000000-0000-0000-0000-000000000000'
    $ClientId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    $ClientSecret = 'your-secret-here'  # Store securely
    $Auth = 'clientcredentials'
    & .\EnvironmentAuditingSummary.ps1

.NOTES
    Author:      Dataverse Audit Export Script
    Updated:     $(Get-Date -Format 'yyyy-MM-dd')
    Required:    PowerShell 5.1+ (7.0+ recommended), Az.Accounts module
    
    Before running:
    1. Create an Azure AD app registration
    2. Grant Dynamics CRM API permissions (user_impersonation)
    3. Configure authentication (device code, secret, or certificate)
    4. Assign app user to Dataverse environment (for service principal auth)
    5. Enable organization and table/attribute auditing in Dataverse
    
    See README.md for detailed setup instructions.

.LINK
    https://github.com/akmsft/powershell
#>


# =======================================================================================
# CONFIGURATION SECTION - Edit these values to match your environment
# =======================================================================================

# REQUIRED: Your Dataverse organization URL
# Examples:
#   Commercial:  https://contoso.crm.dynamics.com
#   Government:  https://contoso.microsoftdynamics.us  (GCCH)
#   Government:  https://crm9.dynamics.com             (GCC instance-style)
$OrgUrl = "[YOUR ENVIRONMENT URL]"

# REQUIRED: Azure AD Tenant ID (also called Directory ID)
# Find this in Azure Portal > Azure AD > Properties > Tenant ID
# Format: GUID (e.g., 00000000-0000-0000-0000-000000000000)
$TenantId = "[YOUR AZURE TENANT ID]"

# REQUIRED: Authentication Method
# Valid values: 'devicecode', 'clientcredentials', 'clientcertificate'
$Auth = "clientcredentials"

# REQUIRED: App Registration Client ID (also called Application ID)
# Find this in Azure Portal > App registrations > [Your app] > Client ID
$ClientId = "[YOUR APP REGISTRATION ID]"

# CONDITIONAL: Client Secret (required only if $Auth = 'clientcredentials')
# ⚠️ SECURITY WARNING: Never hardcode secrets in production scripts
# Instead, retrieve from: Azure Key Vault, environment variables, or secure vaults
# Example: $ClientSecret = [Environment]::GetEnvironmentVariable('DATAVERSE_CLIENT_SECRET')
$ClientSecret = "[YOUR APP REGISTRATION CLIENT SECRET]"

# CONDITIONAL: Certificate Thumbprint (required only if $Auth = 'clientcertificate')
# Find this in Certificates & secrets > Certificates > Thumbprint column
# Format: 40-character hexadecimal string (e.g., ABCD1234...)
$CertificateThumbprint = ""

# OPTIONAL: Include audited attributes from all tables, even if table-level auditing is off
# Useful for diagnostics; set to $true to see what attributes could be audited
# Default: $false (only show attributes from tables with auditing enabled)
$IncludeFieldsFromAllTables = $false

# OPTIONAL: Output directory for CSV and JSON files
# Use "." for current directory, or specify a full path
# Default: "." (script directory)
$OutDir = "."

# OPTIONAL: Output CSV filename
# Default: "audited_table_attributes.csv"
$OutFile = "audited_table_attributes.csv"

# OPTIONAL: Maximum retry attempts for throttled requests (HTTP 429/503)
# The script will retry with exponential backoff up to this many times
# Default: 6 (maximum recommended to avoid long delays)
$MaxRetryAttempts = 6

# OPTIONAL: Initial backoff wait time in seconds for retry logic
# Wait time doubles with each retry (2, 4, 8, 16, 32, 60 seconds max)
# Default: 2 seconds
$InitialBackoffSeconds = 2

# =======================================================================================
# END CONFIGURATION SECTION
# =======================================================================================




# =======================================================================================
# HELPER FUNCTIONS - Do not modify unless you understand the code
# =======================================================================================

<#
.SYNOPSIS
    Ensures that a required PowerShell module is installed and imported.

.DESCRIPTION
    Checks if the specified module is available. If not, automatically installs it 
    from the PowerShell Gallery with CurrentUser scope. Then imports the module.

.PARAMETER Name
    The name of the PowerShell module to ensure is installed.
    
.EXAMPLE
    Ensure-ModuleInstalled -Name "Az.Accounts"
#>
function Ensure-ModuleInstalled {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    
    # Check if module is already installed
    if (-not (Get-Module -ListAvailable -Name $Name)) {
        Write-Host "Module '$Name' not found. Installing from PowerShell Gallery..."
        try {
            Install-Module -Name $Name -Scope CurrentUser -Force -AllowClobber -Repository PSGallery -ErrorAction Stop
            Write-Host "Successfully installed '$Name'."
        } catch {
            throw "Failed to install module '$Name': $($_.Exception.Message)"
        }
    }
    
    # Import the module
    try {
        Import-Module $Name -ErrorAction Stop
        Write-Host "Module '$Name' imported successfully."
    } catch {
        throw "Failed to import module '$Name': $($_.Exception.Message)"
    }
}

# Ensure Az.Accounts is available (required for device code and certificate authentication)
Ensure-ModuleInstalled -Name "Az.Accounts"

<#
.SYNOPSIS
    Determines Azure environment and Dataverse resource URLs based on organization URL.

.DESCRIPTION
    Analyzes the Dataverse organization URL and returns the appropriate Azure environment
    (Commercial, AzureUSGovernment), and the corresponding resource URLs for authentication
    and API calls.

.PARAMETER OrgUrl
    The Dataverse organization URL (e.g., https://contoso.crm.dynamics.com)

.OUTPUTS
    Hashtable with keys:
    - AzEnvironment: The Azure environment name ('AzureCloud' or 'AzureUSGovernment')
    - ResourceUrl: The base resource URL for API calls
    - LoginHost: The authentication endpoint
    - Cloud: Human-readable cloud name ('Commercial', 'GCCH', or 'GCC')
    - Supported: Whether this cloud is supported by the script

.EXAMPLE
    $envInfo = Get-EnvironmentInfo -OrgUrl "https://contoso.microsoftdynamics.us"
    # Returns: AzEnvironment='AzureUSGovernment', ResourceUrl='https://crm.microsoftdynamics.us', ...
#>
function Get-EnvironmentInfo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OrgUrl
    )
    
    $uriHost = ([uri]$OrgUrl).Host.ToLower()
    
    # GCCH (US Government Cloud for Dynamics): *.microsoftdynamics.us
    if ($uriHost -like "*.microsoftdynamics.us" -or $uriHost -like "*.crm.microsoftdynamics.us") {
        return @{
            AzEnvironment = 'AzureUSGovernment'
            ResourceUrl   = 'https://crm.microsoftdynamics.us'
            LoginHost     = 'https://login.microsoftonline.us'
            Cloud         = 'GCCH'
            Supported     = $true
        }
    }
    
    # GCC (US Government): Instance-style hosts (crm#.dynamics.com)
    if ($uriHost -match '^crm\d+\.dynamics\.com$') {
        return @{
            AzEnvironment = 'AzureUSGovernment'
            ResourceUrl   = 'https://crm.microsoftdynamics.us'
            LoginHost     = 'https://login.microsoftonline.us'
            Cloud         = 'GCC'
            Supported     = $true
        }
    }
    
    # Default to Commercial Cloud
    return @{
        AzEnvironment = 'AzureCloud'
        ResourceUrl   = 'https://crm.dynamics.com'
        LoginHost     = 'https://login.microsoftonline.com'
        Cloud         = 'Commercial'
        Supported     = $true
    }
}

<#
.SYNOPSIS
    Decodes a JWT (JSON Web Token) access token to extract claims.

.DESCRIPTION
    Extracts the payload from a JWT token and decodes it from Base64URL to JSON.
    Used for diagnostics to inspect token audience, tenant ID, and scopes.

.PARAMETER jwt
    The JWT token string (access token from Azure AD)

.OUTPUTS
    PSCustomObject with decoded claims, or $null if decoding fails

.EXAMPLE
    $claims = Decode-JwtPayload -jwt $accessToken
    Write-Host "Token audience: $($claims.aud)"
    Write-Host "Tenant ID: $($claims.tid)"
#>
function Decode-JwtPayload {
    param(
        [Parameter(Mandatory = $true)]
        [string]$jwt
    )
    
    if (-not $jwt) { return $null }
    
    # JWT format: header.payload.signature
    $parts = $jwt -split '\.'
    if ($parts.Count -lt 2) { return $null }
    
    # Decode Base64URL (replace URL-safe characters)
    $payload = $parts[1].Replace('-', '+').Replace('_', '/')
    
    # Add padding as needed
    switch ($payload.Length % 4) {
        2 { $payload += '==' }
        3 { $payload += '=' }
    }
    
    # Convert from Base64 to string
    try {
        $bytes = [Convert]::FromBase64String($payload)
        $json = [System.Text.Encoding]::UTF8.GetString($bytes)
        
        # Verify it's valid JSON before returning
        if ($json.TrimStart().StartsWith('{') -or $json.TrimStart().StartsWith('[')) {
            return $json | ConvertFrom-Json -ErrorAction Stop
        }
    } catch {
        # Silently return $null on decode failure
    }
    
    return $null
}

<#
.SYNOPSIS
    Makes an HTTP request to Dataverse API with automatic retry and backoff logic.

.DESCRIPTION
    Wraps Invoke-RestMethod to add resilience for throttled requests (HTTP 429/503).
    Implements exponential backoff: waits 2, 4, 8, 16, 32, 60 seconds between retries.

.PARAMETER Method
    HTTP method (Get, Post, etc.)

.PARAMETER Uri
    The API endpoint URL

.PARAMETER Headers
    HTTP headers (Authorization, Accept, etc.)

.PARAMETER Body
    Optional request body (for POST/PATCH)

.PARAMETER MaxAttempts
    Maximum number of retry attempts

.OUTPUTS
    The API response object

.EXAMPLE
    $response = Invoke-Dataverse -Method Get -Uri "https://org.crm.dynamics.com/api/data/v9.2/accounts" -Headers $headers
#>
function Invoke-Dataverse {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Method,
        
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        
        [hashtable]$Headers = @{ Accept = "application/json" },
        
        $Body = $null,
        
        [int]$MaxAttempts = $MaxRetryAttempts
    )
    
    $attempt = 0
    $backoff = $InitialBackoffSeconds
    
    while ($true) {
        try {
            # Make the API call
            if ($Body -ne $null) {
                return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Headers -Body $Body `
                    -ContentType "application/json" -ErrorAction Stop
            } else {
                return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Headers -ErrorAction Stop
            }
        } catch {
            $attempt++
            
            # Extract HTTP status code from exception
            $resp = $_.Exception.Response
            $status = $null
            try { $status = [int]($resp.StatusCode) } catch { }
            
            # Handle throttling (429) and service unavailable (503)
            if (($status -eq 429 -or $status -eq 503) -and ($attempt -lt $MaxAttempts)) {
                # Determine wait time from Retry-After header or use exponential backoff
                $retryAfter = $null
                try { $retryAfter = $resp.Headers["Retry-After"] } catch { }
                
                if ([int]::TryParse($retryAfter, [ref]$null)) {
                    $wait = [int]$retryAfter
                } elseif ($retryAfter) {
                    try {
                        $dt = [DateTime]::Parse($retryAfter)
                        $wait = [int]([Math]::Max(1, ($dt - (Get-Date)).TotalSeconds))
                    } catch {
                        $wait = $backoff
                    }
                } else {
                    $wait = $backoff
                }
                
                Write-Warning "API request throttled (HTTP $status). Waiting $wait seconds before retry ($attempt/$MaxAttempts)..."
                Start-Sleep -Seconds $wait
                
                # Double the backoff time for next retry (max 60 seconds)
                $backoff = [Math]::Min($backoff * 2, 60)
                continue
            }
            
            # Re-throw non-throttling errors
            throw $_
        }
    }
}

<#
.SYNOPSIS
    Retrieves all paginated results from a Dataverse API query.

.DESCRIPTION
    Automatically follows OData @odata.nextLink to retrieve all pages of results.
    Aggregates all items into a single array.

.PARAMETER Url
    The initial API query URL

.PARAMETER Headers
    HTTP headers for authentication

.OUTPUTS
    Array of all result items across all pages

.EXAMPLE
    $allTables = Get-AllPages -Url $tablesUrl -Headers $headers
#>
function Get-AllPages {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url,
        
        [hashtable]$Headers
    )
    
    $results = @()
    $next = $Url
    
    while ($next) {
        $resp = Invoke-Dataverse -Method Get -Uri $next -Headers $Headers
        
        if ($resp -eq $null) { break }
        
        # Accumulate items from this page
        if ($resp.value) {
            $results += $resp.value
        }
        
        # Check for next page link
        $next = $null
        try {
            $next = $resp.'@odata.nextLink'
        } catch { }
    }
    
    return $results
}



<#
.SYNOPSIS
    Acquires an access token for Dataverse API using the specified authentication method.

.DESCRIPTION
    Supports three authentication flows:
    1. Device Code: Interactive user authentication
    2. Client Certificate: Service principal with certificate
    3. Client Credentials: Service principal with client secret

.PARAMETER Auth
    Authentication method: 'devicecode', 'clientcertificate', or 'clientcredentials'

.PARAMETER TenantId
    Azure AD Tenant ID

.PARAMETER ClientId
    Azure AD App Registration Client ID

.PARAMETER ClientSecret
    Client secret (required for 'clientcredentials' flow only)

.PARAMETER CertificateThumbprint
    Certificate thumbprint (required for 'clientcertificate' flow only)

.PARAMETER AzEnvironment
    Azure environment name ('AzureCloud' or 'AzureUSGovernment')

.PARAMETER ResourceUrl
    Base resource URL for token requests (e.g., https://crm.dynamics.com)

.PARAMETER LoginHost
    Authentication endpoint (e.g., https://login.microsoftonline.com)

.PARAMETER OrgUrl
    Dataverse organization URL (used as fallback resource)

.PARAMETER UseOrgResource
    If $true, request token for org URL; if $false, use $ResourceUrl

.OUTPUTS
    String containing the access token

.EXAMPLE
    $token = Get-DvToken -Auth 'devicecode' -TenantId $tenantId -ClientId $clientId `
        -AzEnvironment 'AzureCloud' -ResourceUrl 'https://crm.dynamics.com' `
        -LoginHost 'https://login.microsoftonline.com' -OrgUrl 'https://contoso.crm.dynamics.com'
#>
function Get-DvToken {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('devicecode', 'clientcertificate', 'clientcredentials')]
        [string]$Auth,
        
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        
        [string]$ClientId,
        [string]$ClientSecret,
        [string]$CertificateThumbprint,
        [string]$AzEnvironment,
        [string]$ResourceUrl,
        [string]$LoginHost,
        [string]$OrgUrl,
        [switch]$UseOrgResource
    )
    
    # Determine which resource to request token for
    $resourceForToken = if ($UseOrgResource) { $OrgUrl } else { $ResourceUrl }
    
    # DEVICE CODE or CERTIFICATE AUTH: Use Az.Accounts module
    if ($Auth -in @('devicecode', 'clientcertificate')) {
        if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
            throw "Az.Accounts module is required. Install it with: Install-Module Az.Accounts -Scope CurrentUser"
        }
        
        if ($Auth -eq 'devicecode') {
            Write-Host "=========================================="
            Write-Host "Device Code Authentication"
            Write-Host "=========================================="
            Write-Host "Opening device code login..."
            
            try {
                Connect-AzAccount -Environment $AzEnvironment -Tenant $TenantId `
                    -UseDeviceAuthentication -ErrorAction Stop | Out-Null
                Write-Host "Successfully authenticated with Azure."
            } catch {
                Write-Warning "Tenant-scoped device login failed. Trying non-tenant authentication..."
                Connect-AzAccount -Environment $AzEnvironment -UseDeviceAuthentication -ErrorAction Stop | Out-Null
            }
        } else {
            # CLIENT CERTIFICATE AUTH
            if (-not $CertificateThumbprint) {
                throw "CertificateThumbprint is required for clientcertificate authentication."
            }
            
            Write-Host "=========================================="
            Write-Host "Certificate-Based Service Principal Auth"
            Write-Host "=========================================="
            Write-Host "Authenticating with certificate (thumbprint: $($CertificateThumbprint.Substring(0, 8))...)..."
            
            try {
                Connect-AzAccount -ServicePrincipal -Tenant $TenantId -ApplicationId $ClientId `
                    -CertificateThumbprint $CertificateThumbprint -Environment $AzEnvironment -ErrorAction Stop | Out-Null
                Write-Host "Successfully authenticated with Azure."
            } catch {
                throw "Failed to authenticate with certificate: $($_.Exception.Message)"
            }
        }
        
        # Acquire access token
        try {
            $tokenResponse = Get-AzAccessToken -ResourceUrl $resourceForToken -TenantId $TenantId -ErrorAction Stop
            return $tokenResponse.Token
        } catch {
            # Fallback if resource-specific token fails
            try {
                Write-Warning "Token acquisition with resource '$resourceForToken' failed. Trying tenant-scoped token..."
                $tokenResponse = Get-AzAccessToken -TenantId $TenantId -ErrorAction Stop
                return $tokenResponse.Token
            } catch {
                throw "Failed to acquire access token: $($_.Exception.Message)"
            }
        }
    }
    
    # CLIENT CREDENTIALS AUTH: Use REST API directly
    elseif ($Auth -eq 'clientcredentials') {
        if (-not $ClientSecret) {
            throw "ClientSecret is required for clientcredentials authentication."
        }
        
        Write-Host "=========================================="
        Write-Host "Client Credentials Service Principal Auth"
        Write-Host "=========================================="
        Write-Host "Acquiring token for service principal..."
        
        # Prefer org-specific audience (most tenants have org-level service principal)
        $orgAudience = $OrgUrl.TrimEnd('/') + '/.default'
        $baseAudience = "$($resourceForToken.TrimEnd('/'))/.default"
        $tokenEndpoint = "$LoginHost/$TenantId/oauth2/v2.0/token"
        
        # Try org-specific audience first
        try {
            $body = @{
                client_id     = $ClientId
                client_secret = $ClientSecret
                scope         = $orgAudience
                grant_type    = "client_credentials"
            }
            Write-Host "Requesting token for org-specific audience..."
            $resp = Invoke-RestMethod -Method Post -Uri $tokenEndpoint -Body $body `
                -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
            Write-Host "Successfully acquired token with org audience."
            return $resp.access_token
        } catch {
            Write-Warning "Org audience failed. Trying Dataverse resource base audience..."
            # Fallback to base Dataverse resource
            try {
                $body = @{
                    client_id     = $ClientId
                    client_secret = $ClientSecret
                    scope         = $baseAudience
                    grant_type    = "client_credentials"
                }
                $resp = Invoke-RestMethod -Method Post -Uri $tokenEndpoint -Body $body `
                    -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
                Write-Host "Successfully acquired token with resource audience."
                return $resp.access_token
            } catch {
                throw "Failed to acquire token with both org and resource audiences: $($_.Exception.Message)"
            }
        }
    } else {
        throw "Unsupported authentication method: $Auth"
    }
}




# =======================================================================================
# MAIN EXECUTION
# =======================================================================================

Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════════════════════╗"
Write-Host "║     Dataverse Audited Attributes Export                                    ║"
Write-Host "║     Script Version: 2.0                                                    ║"
Write-Host "╚════════════════════════════════════════════════════════════════════════════╝"
Write-Host ""

# STEP 1: Detect cloud environment and get authentication endpoints
Write-Host "[STEP 1/6] Detecting cloud environment..."
$envInfo = Get-EnvironmentInfo -OrgUrl $OrgUrl
$AzEnvironment = $envInfo.AzEnvironment
$ResourceUrl = $envInfo.ResourceUrl
$LoginHost = $envInfo.LoginHost

Write-Host "  Detected cloud: $($envInfo.Cloud)"
Write-Host "  Azure environment: $AzEnvironment"
Write-Host "  Dataverse resource: $ResourceUrl"

if ($envInfo.ContainsKey('Supported') -and -not $envInfo.Supported) {
    Write-Error "ERROR: Your organization URL appears to be in the '$($envInfo.Cloud)' cloud, which is not supported."
    Write-Error "Please use a supported cloud (Commercial, GCCH, or GCC) or update the script."
    exit 1
}

# STEP 2: Authenticate and acquire access token
Write-Host ""
Write-Host "[STEP 2/6] Authenticating to Azure AD..."
$useOrgFallback = $false
try {
    $token = Get-DvToken -Auth $Auth -TenantId $TenantId -ClientId $ClientId `
        -ClientSecret $ClientSecret -CertificateThumbprint $CertificateThumbprint `
        -AzEnvironment $AzEnvironment -ResourceUrl $ResourceUrl -LoginHost $LoginHost `
        -OrgUrl $OrgUrl -UseOrgResource:$useOrgFallback
} catch {
    Write-Error "Failed to authenticate: $($_.Exception.Message)"
    exit 1
}

# Set up headers for API calls
$base = "$OrgUrl/api/data/v9.2"
$hdrs = @{ Authorization = "Bearer $token"; Accept = "application/json" }

# Display token diagnostics
Write-Host ""
Write-Host "[STEP 2a] Token Diagnostics:"
$claims = Decode-JwtPayload -jwt $token
if ($claims) {
    Write-Host "  ✓ Token audience (aud): $($claims.aud)"
    if ($claims.roles) { Write-Host "  ✓ Roles: $($claims.roles -join ', ')" }
    if ($claims.scp) { Write-Host "  ✓ Scopes: $($claims.scp)" }
    
    $expiryTime = [DateTimeOffset]::FromUnixTimeSeconds([int]$claims.exp).ToLocalTime()
    $timeRemaining = $expiryTime - (Get-Date)
    Write-Host "  ✓ Token expires: $expiryTime ($($timeRemaining.TotalMinutes.ToString('F0')) minutes remaining)"
} else {
    Write-Warning "  ⚠ Unable to decode token payload (token may not be a JWT)"
}

# STEP 3: Validate token by making a test API call
Write-Host ""
Write-Host "[STEP 3/6] Validating token with test API call..."
try {
    $whoAmI = Invoke-Dataverse -Method Get -Uri "$base/WhoAmI" -Headers $hdrs | Out-Null
    Write-Host "  ✓ Token validated successfully"
} catch {
    $err = $_
    $is401 = $false
    try { $is401 = ($err.Exception.Response.StatusCode -eq 401) } catch { }
    
    if ($is401 -and -not $useOrgFallback) {
        Write-Warning "  ⚠ Initial token failed (401 Unauthorized). Retrying with org URL as resource..."
        $useOrgFallback = $true
        try {
            $token = Get-DvToken -Auth $Auth -TenantId $TenantId -ClientId $ClientId `
                -ClientSecret $ClientSecret -CertificateThumbprint $CertificateThumbprint `
                -AzEnvironment $AzEnvironment -ResourceUrl $ResourceUrl -LoginHost $LoginHost `
                -OrgUrl $OrgUrl -UseOrgResource:$useOrgFallback
            $hdrs = @{ Authorization = "Bearer $token"; Accept = "application/json" }
            $claims = Decode-JwtPayload -jwt $token
            if ($claims) { Write-Host "  ✓ New token audience: $($claims.aud)" }
            
            # Re-test with new token
            Invoke-Dataverse -Method Get -Uri "$base/WhoAmI" -Headers $hdrs | Out-Null
            Write-Host "  ✓ Token validated successfully (with fallback)"
        } catch {
            Write-Error "Failed even after fallback: $($_.Exception.Message)"
            exit 1
        }
    } else {
        Write-Error "Token validation failed: $($_.Exception.Message)"
        exit 1
    }
}

# STEP 4: Validate and prepare output directory
Write-Host ""
Write-Host "[STEP 4/6] Preparing output directory..."

# Normalize path (handle relative paths)
if ([string]::IsNullOrWhiteSpace($OutDir)) { $OutDir = $PSScriptRoot }
if (-not [IO.Path]::IsPathRooted($OutDir)) {
    $OutDir = Join-Path -Path $PSScriptRoot -ChildPath $OutDir
}

# Create or validate directory
if (Test-Path -LiteralPath $OutDir) {
    try {
        $item = Get-Item -LiteralPath $OutDir -ErrorAction Stop
        if (-not $item.PSIsContainer) {
            throw "Path '$OutDir' exists but is not a directory."
        }
    } catch {
        Write-Error "Cannot validate output directory: $($_.Exception.Message)"
        exit 1
    }
} else {
    try {
        New-Item -ItemType Directory -Path $OutDir -ErrorAction Stop | Out-Null
        Write-Host "  Created output directory: $OutDir"
    } catch {
        Write-Error "Failed to create output directory '$OutDir': $($_.Exception.Message)"
        exit 1
    }
}

# Test write access
$testFile = Join-Path $OutDir (".write_test_{0}.tmp" -f [Guid]::NewGuid())
try {
    Set-Content -Path $testFile -Value 'ok' -ErrorAction Stop
    Remove-Item -Path $testFile -ErrorAction SilentlyContinue
    Write-Host "  ✓ Output directory is writable"
} catch {
    Write-Error "No write access to output directory. Error: $($_.Exception.Message)"
    exit 1
}

# STEP 5a: Retrieve organization-level audit settings (optional)
Write-Host ""
Write-Host "[STEP 5/6] Querying Dataverse for audited tables and attributes..."
Write-Host "  This may take a few minutes depending on the number of tables..."

try {
    Write-Host "  Retrieving organization audit settings..."
    $orgQuery = "$base/organizations?`$select=isauditenabled,isuseraccessauditenabled,auditretentionperiodv2,auditsettings"
    $orgResp = Invoke-Dataverse -Method Get -Uri $orgQuery -Headers $hdrs
    if ($orgResp -and $orgResp.value) {
        $orgResp.value | ConvertTo-Json -Depth 6 | Out-File (Join-Path $OutDir "org_audit_status.json") -Encoding UTF8
        Write-Host "  ✓ Organization audit settings exported to org_audit_status.json"
    }
} catch {
    $status = $null
    try { $status = [int]$_.Exception.Response.StatusCode } catch { }
    
    if ($status -in 400, 404) {
        Write-Host "  ⚠ Organization audit endpoint not available (HTTP $status - this environment may not support it)"
    } else {
        Write-Warning "  ⚠ Unable to retrieve organization audit settings: $($_.Exception.Message)"
    }
}

# STEP 5b: Query tables with auditing enabled
Write-Host ""
Write-Host "  Retrieving tables with auditing enabled..."
$tablesFilter = "IsAuditEnabled/Value eq true"
if ($IncludeFieldsFromAllTables) {
    $tablesFilter = "LogicalName ne null"
    Write-Host "  (Advanced mode: including all tables)"
}

$entitySelect = "LogicalName,SchemaName,DisplayName,EntitySetName,ObjectTypeCode,IsActivity,IsAuditEnabled"
$tablesUrl = "$base/EntityDefinitions?`$select=$entitySelect&`$filter=$tablesFilter"

try {
    $tables = Get-AllPages -Url $tablesUrl -Headers $hdrs
    Write-Host "  ✓ Found $($tables.Count) table(s)"
} catch {
    Write-Error "Failed to query tables: $($_.Exception.Message)"
    exit 1
}

# STEP 5c: Process each table and collect audited attributes
Write-Host "  Processing audited attributes..."
$rows = New-Object System.Collections.Generic.List[Object]
$processedCount = 0

foreach ($t in $tables) {
    $processedCount++
    $tableLogical = $t.LogicalName
    $tableDisplay = if ($t.DisplayName -and $t.DisplayName.UserLocalizedLabel) {
        $t.DisplayName.UserLocalizedLabel.Label
    } else {
        $null
    }
    $tableAuditEnabled = if ($t.IsAuditEnabled) { $t.IsAuditEnabled.Value } else { $false }
    
    # Progress indicator every 10 tables
    if ($processedCount % 10 -eq 0) {
        Write-Host "    Processing table $processedCount of $($tables.Count)..."
    }
    
    # Query audited attributes for this table
    $attrFilter = "IsAuditEnabled/Value eq true"
    $attrSelect = "LogicalName,SchemaName,AttributeType,DisplayName,IsAuditEnabled"
    $attrUrl = "$base/EntityDefinitions(LogicalName='$tableLogical')/Attributes?`$select=$attrSelect&`$filter=$attrFilter"
    
    try {
        $attrs = Get-AllPages -Url $attrUrl -Headers $hdrs
        $attrs = @($attrs)  # Ensure it's an array
        
        # Filter to only audited attributes (handle data type variations)
        $auditedAttrs = @()
        foreach ($attr in $attrs) {
            $isAudited = $false
            try {
                # Try to get the Value property first (BooleanManagedProperty)
                $raw = $attr.IsAuditEnabled.Value
            } catch {
                # Fall back to direct value
                $raw = $attr.IsAuditEnabled
            }
            
            # Normalize boolean values
            if ($raw -is [string]) {
                $isAudited = ($raw.Trim().ToLower() -eq 'true')
            } elseif ($raw -is [bool]) {
                $isAudited = $raw
            } elseif ($raw -is [int] -or $raw -is [double]) {
                $isAudited = ($raw -ne 0)
            }
            
            if ($isAudited) {
                $auditedAttrs += $attr
            }
        }
        
        # Add rows for each audited attribute
        foreach ($attr in $auditedAttrs) {
            $attrDisplay = if ($attr.DisplayName -and $attr.DisplayName.UserLocalizedLabel) {
                $attr.DisplayName.UserLocalizedLabel.Label
            } else {
                $null
            }
            
            $rows.Add([PSCustomObject]@{
                table_logical               = $tableLogical
                table_display               = $tableDisplay
                table_auditing_enabled      = $tableAuditEnabled
                attribute_logical           = $attr.LogicalName
                attribute_display           = $attrDisplay
                attribute_auditing_enabled  = $true
            })
        }
    } catch {
        Write-Warning "  ⚠ Failed to query attributes for table '$tableLogical': $($_.Exception.Message)"
    }
}

Write-Host "  ✓ Collected $($rows.Count) audited attribute(s)"

# STEP 6: Export results to CSV
Write-Host ""
Write-Host "[STEP 6/6] Exporting results to CSV..."

$outPath = Join-Path $OutDir $OutFile

try {
    # Final filter and sort
    $exportRows = $rows | Where-Object {
        $_.attribute_auditing_enabled -eq $true -and -not [string]::IsNullOrWhiteSpace($_.attribute_logical)
    } | Sort-Object table_logical, attribute_logical
    
    # Convert to CSV with UTF-8 encoding (no BOM)
    $csvLines = $exportRows | ConvertTo-Csv -NoTypeInformation
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllLines($outPath, $csvLines, $utf8NoBom)
    
    Write-Host "  ✓ Exported $($exportRows.Count) row(s) to CSV"
    Write-Host "  ✓ Output file: $outPath"
} catch {
    Write-Error "Failed to export CSV: $($_.Exception.Message)"
    exit 1
}

# Completion summary
Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════════════════════╗"
Write-Host "║                       ✓ SCRIPT COMPLETED SUCCESSFULLY                     ║"
Write-Host "╚════════════════════════════════════════════════════════════════════════════╝"
Write-Host ""
Write-Host "Summary:"
Write-Host "  • Tables found: $($tables.Count)"
Write-Host "  • Audited attributes found: $($rows.Count)"
Write-Host "  • Output files:"
Write-Host "      - CSV: $outPath"
if (Test-Path (Join-Path $OutDir "org_audit_status.json")) {
    Write-Host "      - JSON: $(Join-Path $OutDir "org_audit_status.json")"
}
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Review the CSV file for audit coverage"
Write-Host "  2. Verify all necessary attributes are being audited"
Write-Host "  3. Consider enabling auditing for additional tables/attributes as needed"
Write-Host ""

