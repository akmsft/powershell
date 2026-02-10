<#
.SYNOPSIS
  Enumerate Dataverse tables with auditing enabled and their audited attributes.
.DESCRIPTION
  Outputs a CSV with columns:
    table_logical, table_display, table_auditing_enabled,
    attribute_logical, attribute_display, attribute_auditing_enabled

  Supports:
    - User auth (device code) -> interactive
    - App-only auth with certificate (non-interactive) -> service principal + cert
    - App-only auth with client secret (non-interactive)

  Automatically detects GCCH (Azure US Gov) when the organization URL contains
  ".microsoftdynamics.us" and uses the proper Azure environment and endpoints.
  Implements retry with exponential backoff for 429/503 throttling responses
  and follows OData paging (@odata.nextLink).

  Added token diagnostics and token-acquisition fallback to handle 401 caused
  by tokens issued for the wrong audience/resource. 
#>

# -------------------------
# Configuration (edit)
# -------------------------
$OrgUrl                 = "[YOUR ENVIRONMENT URL]"  # e.g., https://contoso.crm.dynamics.com or .microsoftdynamics.us
$TenantId               = "[YOUR AZURE TENANT ID]"               # GUID
$Auth                   = "clientcredentials"  # 'devicecode' | 'clientcertificate' | 'clientcredentials'
$ClientId               = "[YOUR APP REGISTRATION ID]"               # App (client) ID
$ClientSecret           = "[YOUR APP REGISTRATION CLIENT SECRET]"              # Required for 'clientcredentials'
$CertificateThumbprint  = "" # Required for 'clientcertificate'
$IncludeFieldsFromAllTables = $false         # If set, will return audited columns even when table-level audit flag is off
$OutDir                 = "."                # Output directory
$OutFile                = "audited_table_attributes.csv"
$MaxRetryAttempts       = 6
$InitialBackoffSeconds  = 2
$Environment = $null
 
# -------------------------

# Ensure Az.Accounts available (used for device & certificate flows)
function Ensure-ModuleInstalled {
    param([string]$Name)
    if (-not (Get-Module -ListAvailable -Name $Name)) {
        Write-Host "Installing module $Name..."
        Install-Module -Name $Name -Scope CurrentUser -Force -AllowClobber -Repository PSGallery
    }
    Import-Module $Name -ErrorAction Stop
}
Ensure-ModuleInstalled -Name "Az.Accounts"

# Helper: decide Azure Environment and Dataverse resource based on OrgUrl
function Get-EnvironmentInfo {
    param([string]$OrgUrl)
    $uriHost = ([uri]$OrgUrl).Host.ToLower()
    # Determine environment strictly from the OrgUrl domain pattern.
    # Commercial: *.crm.dynamics.com or other commercial domains
    # GCCH (US Gov Cloud for Dynamics): *.microsoftdynamics.us or *.crm.microsoftdynamics.us
    # Some GCC organizations use instance-style hosts such as crm9.dynamics.com; treat those as GCC.

    if ($uriHost -like "*.microsoftdynamics.us" -or $uriHost -like "*.crm.microsoftdynamics.us") {
        return @{ AzEnvironment = 'AzureUSGovernment'; ResourceUrl = 'https://crm.microsoftdynamics.us'; LoginHost = 'https://login.microsoftonline.us'; Cloud = 'GCCH'; Supported = $true }
    }

    # Instance-style GCC host names (e.g. crm9.dynamics.com)
    if ($uriHost -match '^crm\d+\.dynamics\.com$') {
        return @{ AzEnvironment = 'AzureUSGovernment'; ResourceUrl = 'https://crm.microsoftdynamics.us'; LoginHost = 'https://login.microsoftonline.us'; Cloud = 'GCC'; Supported = $true }
    }

    # Default to commercial
    return @{ AzEnvironment = 'AzureCloud'; ResourceUrl = 'https://crm.dynamics.com'; LoginHost = 'https://login.microsoftonline.com'; Cloud = 'Commercial'; Supported = $true }
}

# Decode JWT payload (for debug)
# Replace/insert the following helper functions (token device flow + JWT decode) into the script.
# These replace the previous Get-GcchDvToken device-path to ensure a real JWT is requested
# (bypass WAM/SharedTokenCache opaque tokens) and to diagnose audience/tenant problems.

function Decode-JwtPayload {
    param([string]$jwt)
    if (-not $jwt) { return $null }
    $parts = $jwt -split '\.'
    if ($parts.Count -lt 2) { return $null }

    $payload = $parts[1].Replace('-','+').Replace('_','/')
    switch ($payload.Length % 4) {
        2 { $payload += '==' }
        3 { $payload += '=' }
        default { }
    }

    try {
        $bytes = [Convert]::FromBase64String($payload)
    } catch {
        return $null
    }

    $json = [System.Text.Encoding]::UTF8.GetString($bytes)
    if ($json.TrimStart().StartsWith('{') -or $json.TrimStart().StartsWith('[')) {
        try { return $json | ConvertFrom-Json -ErrorAction Stop } catch { return $null }
    }
    return $null
}

function Get-GcchDvToken {
  param(
    [string]$TenantId,
    [string]$ClientId,
    [string]$ClientSecret,
    [ValidateSet('devicecode','clientcredentials')]
    [string]$Auth
  )

  # Dataverse resource base for GCCH, GCC (DoD) or commercial
  if ($OrgUrl -match "\.microsoftdynamics\.us") {
    $resource = "https://crm.microsoftdynamics.us"
    $loginHost = "https://login.microsoftonline.us"
  } else {
    $resource = "https://crm.dynamics.com"
    $loginHost = "https://login.microsoftonline.com"
  }
  $orgResource = $OrgUrl.TrimEnd('/')

  if ($Auth -eq 'devicecode') {
    if (-not $ClientId) { throw "ClientId is required for devicecode auth." }

    function Invoke-DeviceCodeFlow {
      param([string]$ScopeResource)

      $deviceCodeEndpoint = "$loginHost/$TenantId/oauth2/v2.0/devicecode"
      $tokenEndpoint = "$loginHost/$TenantId/oauth2/v2.0/token"

      # IMPORTANT: request the Dataverse delegated scope from the Dataverse resource base.
      # This avoids odd audiences or app-consent issues when requesting per-org audiences first.
      $scope = "$($resource.TrimEnd('/'))/user_impersonation offline_access openid profile"
      $body = @{ client_id = $ClientId; scope = $scope }

      $dcResp = Invoke-RestMethod -Method Post -Uri $deviceCodeEndpoint -Body $body -ContentType "application/x-www-form-urlencoded"
      Write-Host "To sign in, open $($dcResp.verification_uri) and enter code: $($dcResp.user_code)"
      if ($dcResp.message) { Write-Host $dcResp.message }

      $interval = [int]$dcResp.interval
      $deviceCode = $dcResp.device_code

      while ($true) {
        Start-Sleep -Seconds $interval
        $pollBody = @{
          grant_type  = "urn:ietf:params:oauth:grant-type:device_code"
          client_id   = $ClientId
          device_code = $deviceCode
        }
        try {
          $tokenResp = Invoke-RestMethod -Method Post -Uri $tokenEndpoint -Body $pollBody -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
          # persist raw token for offline inspection
          $tokenResp.access_token | Out-File -FilePath (Join-Path $env:TEMP "dv_access_token.txt") -Encoding utf8
          return $tokenResp.access_token
        } catch {
          $err = $_.Exception.Response
          if ($err -ne $null) {
            try {
              $txt = (New-Object System.IO.StreamReader($err.GetResponseStream())).ReadToEnd()
              $obj = $null
              try { $obj = $txt | ConvertFrom-Json -ErrorAction Stop } catch {}
              if ($obj -and $obj.error -and $obj.error -eq 'authorization_pending') { continue }
              if ($obj -and $obj.error -and $obj.error -eq 'slow_down') { $interval += 5; continue }
              throw "Device-code polling error: $txt"
            } catch {
              throw $_
            }
          } else {
            throw $_
          }
        }
      }
    }

    # Request token from Dataverse resource base (explicit delegated scope)
    $token = $null
    try {
      $token = Invoke-DeviceCodeFlow -ScopeResource $resource
      Write-Host "Acquired token (requested Dataverse delegated scope). Token written to $($env:TEMP)\dv_access_token.txt"
    } catch {
      throw "Device-code flow failed: $($_.Exception.Message)"
    }

    # Diagnostics: attempt to decode token and show aud/tid
    try {
      $claims = Decode-JwtPayload -jwt $token
      if ($claims) {
        Write-Host "Token audience (aud): $($claims.aud)"
        if ($claims.tid) { Write-Host "Token tenant id (tid): $($claims.tid)" }
        if ($claims.upn) { Write-Host "UPN: $($claims.upn)" }
        if ($claims.scp) { Write-Host "Scopes: $($claims.scp)" }
        if ($claims.roles) { Write-Host "Roles: $($claims.roles -join ', ')" }
      } else {
        Write-Warning "Acquired token is not a decodable JWT payload."
      }
    } catch { Write-Warning "Token decode failed: $($_.Exception.Message)" }

    return $token
  }
  else {
    if (-not $ClientSecret) { throw "ClientSecret is required for clientcredentials auth." }
    $tokenEndpoint = "$loginHost/$TenantId/oauth2/v2.0/token"
    $body = @{
      client_id     = $ClientId
      client_secret = $ClientSecret
      scope         = "$resource/.default"
      grant_type    = "client_credentials"
    }
    return (Invoke-RestMethod -Method Post -Uri $tokenEndpoint -Body $body -ContentType "application/x-www-form-urlencoded").access_token
  }
}

# Wrapper: robust Invoke-RestMethod with retry for 429/503 and exponential backoff
function Invoke-Dataverse {
    param(
        [Parameter(Mandatory=$true)][string]$Method,
        [Parameter(Mandatory=$true)][string]$Uri,
        [hashtable]$Headers = @{ Accept = "application/json" },
        $Body = $null,
        [int]$MaxAttempts = $MaxRetryAttempts
    )

    $attempt = 0
    $backoff = $InitialBackoffSeconds

    while ($true) {
        try {
            if ($Body -ne $null) {
                return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Headers -Body $Body -ContentType "application/json" -ErrorAction Stop
            } else {
                return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Headers -ErrorAction Stop
            }
        } catch {
            $attempt++
            $resp = $_.Exception.Response
            $status = $null
            try { $status = [int]($resp.StatusCode) } catch {}
            if (($status -eq 429 -or $status -eq 503) -and ($attempt -lt $MaxAttempts)) {
                $retryAfter = $null
                try { $retryAfter = $resp.Headers["Retry-After"] } catch {}
                if ([int]::TryParse($retryAfter, [ref]$null)) {
                    $wait = [int]$retryAfter
                } elseif ($retryAfter) {
                    try {
                        $dt = [DateTime]::Parse($retryAfter)
                        $wait = [int]([Math]::Max(1, ($dt - (Get-Date)).TotalSeconds))
                    } catch { $wait = $backoff }
                } else { $wait = $backoff }

                Write-Warning "Request throttled (HTTP $status). Waiting $wait seconds before retry ($attempt/$MaxAttempts)..."
                Start-Sleep -Seconds $wait
                $backoff = [Math]::Min($backoff * 2, 60)
                continue
            }

            throw $_
        }
    }
}

# Follow OData paging; returns aggregated 'value' items
function Get-AllPages {
    param([Parameter(Mandatory=$true)][string]$Url, [hashtable]$Headers)

    $results = @()
    $next = $Url
    while ($next) {
        $resp = Invoke-Dataverse -Method Get -Uri $next -Headers $Headers
        if ($resp -eq $null) { break }
        if ($resp.value) { $results += $resp.value }
        $next = $null
        try { $next = $resp.'@odata.nextLink' } catch {}
    }
    return $results
}

# Acquire token using chosen auth method
function Get-DvToken {
    param(
        [Parameter(Mandatory=$true)][string]$Auth,
        [Parameter(Mandatory=$true)][string]$TenantId,
        [string]$ClientId,
        [string]$ClientSecret,
        [string]$CertificateThumbprint,
        [string]$AzEnvironment,
        [string]$ResourceUrl,
        [string]$LoginHost,
        [string]$OrgUrl,
        [switch]$UseOrgResource
    )

    # Determine which resource to request a token for. Some tenants/apps require token for the org URL.
    $resourceForToken = if ($UseOrgResource) { $OrgUrl } else { $ResourceUrl }

    if ($Auth -in @('devicecode','clientcertificate')) {
        if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
            throw "Az.Accounts module required. Install-Module Az.Accounts -Scope CurrentUser"
        }

        if ($Auth -eq 'devicecode') {
            Write-Host "Signing in (device code) in environment $AzEnvironment..."
            try {
                Connect-AzAccount -Environment $AzEnvironment -Tenant $TenantId -UseDeviceAuthentication -ErrorAction Stop | Out-Null
            } catch {
                Write-Warning "Tenant-scoped device login failed: $($_.Exception.Message). Falling back to non-tenant device login."
                Connect-AzAccount -Environment $AzEnvironment -UseDeviceAuthentication -ErrorAction Stop | Out-Null
            }
        } else {
            if (-not $CertificateThumbprint) { throw "CertificateThumbprint is required for clientcertificate authentication." }
            Write-Host "Authenticating service principal (certificate) to tenant $TenantId..."
            Connect-AzAccount -ServicePrincipal -Tenant $TenantId -ApplicationId $ClientId -CertificateThumbprint $CertificateThumbprint -Environment $AzEnvironment -ErrorAction Stop | Out-Null
        }

        # Acquire token for chosen resource
        try {
            $tokenResponse = Get-AzAccessToken -ResourceUrl $resourceForToken -TenantId $TenantId -ErrorAction Stop
            return $tokenResponse.Token
        } catch {
            try {
                $tokenResponse = Get-AzAccessToken -TenantId $TenantId -ErrorAction Stop
                return $tokenResponse.Token
            } catch {
                throw "Failed to acquire access token via Az.Accounts: $($_.Exception.Message)"
            }
        }
    }
    elseif ($Auth -eq 'clientcredentials') {
        if (-not $ClientSecret) { throw "ClientSecret is required for clientcredentials auth." }

        # Prefer org-specific audience (this tenant's Dataverse service principal)
        $orgAudience = $OrgUrl.TrimEnd('/') + '/.default'
        $baseAudience = "$($resourceForToken.TrimEnd('/'))/.default"  # original fallback (e.g. https://crm.dynamics.com/.default)
        $tokenEndpoint = "$LoginHost/$TenantId/oauth2/v2.0/token"

        # Try org audience first (most tenants have an org-level service principal)
        try {
            $body = @{
                client_id     = $ClientId
                client_secret = $ClientSecret
                scope         = $orgAudience
                grant_type    = "client_credentials"
            }
            $resp = Invoke-RestMethod -Method Post -Uri $tokenEndpoint -Body $body -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
            return $resp.access_token
        } catch {
            Write-Warning "Token request with org audience failed: $($_.Exception.Message) — trying Dataverse resource base ($baseAudience)."
            # Fallback to resource base
            try {
                $body = @{
                    client_id     = $ClientId
                    client_secret = $ClientSecret
                    scope         = $baseAudience
                    grant_type    = "client_credentials"
                }
                $resp = Invoke-RestMethod -Method Post -Uri $tokenEndpoint -Body $body -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
                return $resp.access_token
            } catch {
                throw "Client credentials token request failed for both org and resource audiences: $($_.Exception.Message)"
            }
        }
    } else {
        throw "Unsupported Auth method: $Auth"
    }
}

# -------------------------
# Main
# -------------------------
$envInfo = Get-EnvironmentInfo -OrgUrl $OrgUrl
$AzEnvironment = $envInfo.AzEnvironment
$ResourceUrl   = $envInfo.ResourceUrl
$LoginHost     = $envInfo.LoginHost
if ($envInfo.ContainsKey('Supported') -and -not $envInfo.Supported) {
    Write-Error "The organization URL you provided appears to be in the '$($envInfo.Cloud)' cloud. This script is not designed to run against that cloud. Please use a supported cloud (Commercial or GCCH) or update the script to handle your environment."
    exit 1
}

# Acquire token (try resource base first, fallback to org URL resource if server returns 401)
$useOrgFallback = $false
$token = Get-DvToken -Auth $Auth -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -CertificateThumbprint $CertificateThumbprint -AzEnvironment $AzEnvironment -ResourceUrl $ResourceUrl -LoginHost $LoginHost -OrgUrl $OrgUrl -UseOrgResource:$useOrgFallback
$base = "$OrgUrl/api/data/v9.2"
$hdrs = @{ Authorization = "Bearer $token"; Accept = "application/json" }

# Quick token diagnostic
$claims = Decode-JwtPayload -jwt $token
if ($claims) {
    Write-Host "Token audience (aud): $($claims.aud)"
    if ($claims.roles) { Write-Host "Roles: $($claims.roles -join ', ')" }
    if ($claims.scp)   { Write-Host "Scopes: $($claims.scp)" }
    Write-Host ("Token expires: {0}" -f ([DateTimeOffset]::FromUnixTimeSeconds([int]$claims.exp).ToLocalTime()))
} else {
    Write-Warning "Unable to decode token payload for diagnostics."
}

# Test token with a simple API call and fallback if 401 (try acquiring token using the org URL as resource)
try {
    Invoke-Dataverse -Method Get -Uri "$base/WhoAmI" -Headers $hdrs | Out-Null
} catch {
    $err = $_
    $is401 = $false
    try { $is401 = ($err.Exception.Response.StatusCode -eq 401) } catch {}
    if ($is401 -and -not $useOrgFallback) {
        Write-Warning "API returned 401 Unauthorized with token for resource '$ResourceUrl'. Retrying token acquisition using the org URL as resource..."
        $useOrgFallback = $true
        $token = Get-DvToken -Auth $Auth -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -CertificateThumbprint $CertificateThumbprint -AzEnvironment $AzEnvironment -ResourceUrl $ResourceUrl -LoginHost $LoginHost -OrgUrl $OrgUrl -UseOrgResource:$useOrgFallback
        $hdrs = @{ Authorization = "Bearer $token"; Accept = "application/json" }
        $claims = Decode-JwtPayload -jwt $token
        if ($claims) { Write-Host "New token audience (aud): $($claims.aud)" }
        try {
            Invoke-Dataverse -Method Get -Uri "$base/WhoAmI" -Headers $hdrs | Out-Null
        } catch {
            throw "API still returned error after reacquiring token with org resource: $($_.Exception.Message)"
        }
    } else {
        throw "API returned error when testing token: $($_.Exception.Message)"
    }
}

# If we reach here the token is valid for API calls
Write-Host "Token validated for Dataverse Web API."

# Ensure output dir exists and is writable (normalize relative paths)
if ([string]::IsNullOrWhiteSpace($OutDir)) { $OutDir = $PSScriptRoot }

if (-not [IO.Path]::IsPathRooted($OutDir)) {
    $OutDir = Join-Path -Path $PSScriptRoot -ChildPath $OutDir
}

# If path exists, ensure it's a directory. If it doesn't, create it.
if (Test-Path -LiteralPath $OutDir) {
    try {
        $it = Get-Item -LiteralPath $OutDir -ErrorAction Stop
        if (-not $it.PSIsContainer) {
            throw "Path '$OutDir' exists but is not a directory. Remove or choose a different OutDir."
        }
    } catch {
        throw "Unable to validate existing output path '$OutDir': $($_.Exception.Message)"
    }
} else {
    try {
        New-Item -ItemType Directory -Path $OutDir -ErrorAction Stop | Out-Null
    } catch {
        throw "Unable to create output directory '$OutDir': $($_.Exception.Message)"
    }
}

# Quick write-check
$testFile = Join-Path $OutDir ('.write_test_{0}.tmp' -f ([Guid]::NewGuid()))
try {
    Set-Content -Path $testFile -Value 'ok' -ErrorAction Stop
    Remove-Item -Path $testFile -ErrorAction SilentlyContinue
} catch {
    throw "No write access to output directory '$OutDir'. Change `\$OutDir` to a writable location or fix permissions. Error: $($_.Exception.Message)"
}

# Org-level audit context (optional) with error-body diagnostics
try {
    $orgUrl = "$base/organizations?$select=isauditenabled,isuseraccessauditenabled,auditretentionperiodv2,auditsettings"
    $orgResp = Invoke-Dataverse -Method Get -Uri $orgUrl -Headers $hdrs
    $orgResp.value | ConvertTo-Json -Depth 6 | Out-File (Join-Path $OutDir "org_audit_status.json") -Encoding UTF8
} catch {
    $body = $null
    $status = $null
    try {
        $resp = $_.Exception.Response
        if ($resp) {
            try { $status = [int]$resp.StatusCode } catch {}
            try { $body = (New-Object System.IO.StreamReader($resp.GetResponseStream())).ReadToEnd() } catch {}
        }
    } catch {}

    # Treat 400/404 as non-fatal/unavailable (some orgs/versions may not expose this endpoint)
    if ($status -in 400,404) {
        Write-Host "Organization audit settings endpoint returned HTTP $status; skipping org-level audit JSON (this environment may not support that call)."
    } else {
        Write-Warning "Unable to read organization audit settings: $($_.Exception.Message)"
        if ($body) { Write-Host "Organization API response body:`n$body" }
    }
}

# Build tables filter
$tablesFilter = "IsAuditEnabled/Value eq true"
if ($IncludeFieldsFromAllTables) { $tablesFilter = "LogicalName ne null" }

$entitySelect = "LogicalName,SchemaName,DisplayName,EntitySetName,ObjectTypeCode,IsActivity,IsAuditEnabled"
$tablesUrl = "$base/EntityDefinitions?`$select=$entitySelect&`$filter=$tablesFilter"

# Get all tables (handles paging)
$tables = Get-AllPages -Url $tablesUrl -Headers $hdrs

# Prepare output rows
$rows = New-Object System.Collections.Generic.List[Object]

foreach ($t in $tables) {
    $tableLogical = $t.LogicalName
    $tableDisplay = if ($t.DisplayName -and $t.DisplayName.UserLocalizedLabel) { $t.DisplayName.UserLocalizedLabel.Label } else { $null }
    $tableAuditEnabled = if ($t.IsAuditEnabled) { $t.IsAuditEnabled.Value } else { $false }

    $attrFilter = "IsAuditEnabled/Value eq true"
    $attrSelect = "LogicalName,SchemaName,AttributeType,DisplayName,IsAuditEnabled"
    $attrUrl = "$base/EntityDefinitions(LogicalName='$($tableLogical)')/Attributes?`$select=$attrSelect&`$filter=$attrFilter"

    try {
        $attrs = Get-AllPages -Url $attrUrl -Headers $hdrs

        # Normalize to an array so Count and filtering behave consistently even when a single
        # attribute object is returned.
        $attrs = @($attrs)

        # Apply robust client-side filter to include only attributes with auditing enabled.
        # Some endpoints return a BooleanManagedProperty object with a .Value boolean, while
        # others may return a plain boolean. Handle both cases.
        $attrs = $attrs | Where-Object {
            $prop = $_.PSObject.Properties.Match('IsAuditEnabled') | Select-Object -First 1
            if (-not $prop) { return $false }
            try { $raw = $prop.Value.Value } catch { $raw = $prop.Value }

            if ($raw -is [string]) {
                return ($raw.Trim().ToLower() -eq 'true')
            } elseif ($raw -is [bool]) {
                return $raw
            } elseif ($raw -is [int] -or $raw -is [double]) {
                return ($raw -ne 0)
            }
            return $false
        }
    } catch {
        Write-Warning "Failed attribute read for $($tableLogical): $($_.Exception.Message)"
        $attrs = @()
    }

    if ($attrs.Count -eq 0) {
        # No audited attributes for this table; skip adding a placeholder row so we don't
        # produce rows with attribute_auditing_enabled = $false.
        continue
    } else {
        foreach ($a in $attrs) {
            $attrLogical = $a.LogicalName
            $attrDisplay = if ($a.DisplayName -and $a.DisplayName.UserLocalizedLabel) { $a.DisplayName.UserLocalizedLabel.Label } else { $null }
            # Normalize the IsAuditEnabled value (handle BooleanManagedProperty or plain boolean)
            $attrAuditEnabled = $false
            if ($a.PSObject.Properties.Match('IsAuditEnabled')) {
                try { $raw = $a.IsAuditEnabled.Value } catch { $raw = $a.IsAuditEnabled }
                if ($raw -is [string]) { $attrAuditEnabled = ($raw.Trim().ToLower() -eq 'true') }
                elseif ($raw -is [bool]) { $attrAuditEnabled = $raw }
                elseif ($raw -is [int] -or $raw -is [double]) { $attrAuditEnabled = ($raw -ne 0) }
                else { $attrAuditEnabled = $false }
            }

            # Final guard: only add rows for attributes that are actually audited.
            if (-not $attrAuditEnabled) { continue }

            $rows.Add([pscustomobject]@{
                table_logical               = $tableLogical
                table_display               = $tableDisplay
                table_auditing_enabled      = $tableAuditEnabled
                attribute_logical           = $attrLogical
                attribute_display           = $attrDisplay
                attribute_auditing_enabled  = $attrAuditEnabled
            })
        }
    }
}

# Final safety filter: ensure we only export rows where the attribute auditing flag is true

$outPath = Join-Path $OutDir $OutFile

$exportRows = $rows | Where-Object { $_.attribute_auditing_enabled -eq $true -and -not [string]::IsNullOrWhiteSpace($_.attribute_logical) }
$csvLines = $exportRows | Sort-Object table_logical, attribute_logical | ConvertTo-Csv -NoTypeInformation
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllLines($outPath, $csvLines, $utf8NoBom)

Write-Host "Done -> $outPath (and org_audit_status.json if available)"