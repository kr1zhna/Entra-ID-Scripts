# ==============================
# Inventory of apps whose delegated consent grants include ONLY
# the OIDC scopes + specific directory scopes listed below.
#
# Enhancements incorporated:
#  - Use HashSet (case-insensitive) per clientId for fast union + uniqueness
#  - Pull oauth2PermissionGrants with $select=clientId,scope,consentType (future-proof)
#  - Add user sign-in count (last 30 days) per app
#
# Output:
#  - ServicePrincipalObjectId (oauth2PermissionGrants.clientId = SP object id)
#  - AppId
#  - AppDisplayName
#  - AppOwnerOrganizationId (for classification)
#  - Scopes (union of delegated scopes granted)
#  - UserSigninsLast30Days (Successful + Failed)
# ==============================

$TenantId = Read-Host "Enter your Microsoft Entra tenant ID (GUID)"

$BaselineScopes = @(
  "openid", "profile", "email", "offline_access",
  "User.Read", "User.Read.All", "User.ReadBasic.All",
  "People.Read", "People.Read.All",
  "GroupMember.Read.All", "Member.Read.Hidden"
)

Disconnect-MgGraph -ErrorAction SilentlyContinue

Connect-MgGraph -TenantId $TenantId -Scopes @(
  "DelegatedPermissionGrant.Read.All",
  "Directory.Read.All",
  "Reports.Read.All"
)

# ------------------------------
# Pull oauth2PermissionGrants (paging)
# ------------------------------
$uri = "https://graph.microsoft.com/beta/oauth2PermissionGrants?`$select=clientId,scope,consentType"
$grants = @()
while ($uri) {
  $resp = Invoke-MgGraphRequest -Method GET -Uri $uri
  $grants += $resp.value
  $uri = $resp.'@odata.nextLink'
}

# ------------------------------
# Build baseline-only candidate set (HashSet per clientId)
# ------------------------------
$scopesByClient = @{}  # key: clientId (SP objectId), value: HashSet[string] (case-insensitive)

foreach ($g in $grants) {
  $cid = $g.clientId.ToString().Trim()
  if (-not $cid) { continue }

  if (-not $scopesByClient.ContainsKey($cid)) {
    $scopesByClient[$cid] = [System.Collections.Generic.HashSet[string]]::new(
      [System.StringComparer]::OrdinalIgnoreCase
    )
  }

  foreach ($s in ($g.scope -split '\s+')) {
    if ($s -and $s.Trim().Length -gt 0) {
      [void]$scopesByClient[$cid].Add($s.Trim())
    }
  }
}

$candidates = foreach ($cid in $scopesByClient.Keys) {
  $scopes = $scopesByClient[$cid]
  if ($scopes.Count -le 0) { continue }

  $outside = $scopes | Where-Object { $_ -notin $BaselineScopes }
  if ($outside.Count -eq 0) {
    [PSCustomObject]@{
      ServicePrincipalObjectId = $cid
      Scopes = ($scopes -join ' ')
    }
  }
}

# ------------------------------
# Pull per-app sign-in summary for last 30 days
# Endpoint: GET /beta/reports/getAzureADApplicationSignInSummary(period='D30')
# In this API output, 'id' corresponds to the appId (clientId)
# ------------------------------
$signInSummary = @()
$signInUri = "https://graph.microsoft.com/beta/reports/getAzureADApplicationSignInSummary(period='D30')"

while ($signInUri) {
  $resp = Invoke-MgGraphRequest -Method GET -Uri $signInUri

  if ($resp -and $resp.value) {
    $signInSummary += $resp.value
  }

  # Paging (if present)
  $signInUri = $resp.'@odata.nextLink'
}

# appId -> total sign-ins (30d)
$signInCountByAppId = @{}
foreach ($s in $signInSummary) {
  $appId = $s.id
  if (-not $appId) { continue }

  # PS5.1-safe null handling
  $success = 0
  $failed  = 0
  if ($null -ne $s.successfulSignInCount) { $success = [int]$s.successfulSignInCount }
  if ($null -ne $s.failedSignInCount)     { $failed  = [int]$s.failedSignInCount }

  $signInCountByAppId[$appId] = $success + $failed
}

$resultsTenantOwned = @()
$resultsNotTenantOwned = @()

# ------------------------------
# Filter to tenant-owned or external apps; enrich with appId/displayName + sign-in counts
# ------------------------------
foreach ($c in $candidates) {
  try {
    $spUri = "https://graph.microsoft.com/beta/servicePrincipals/$($c.ServicePrincipalObjectId)?`$select=id,appId,displayName,appOwnerOrganizationId"
    $sp = Invoke-MgGraphRequest -Method GET -Uri $spUri

    $signinCount30d = 0
    if ($sp.appId -and $signInCountByAppId.ContainsKey($sp.appId)) {
      $signinCount30d = $signInCountByAppId[$sp.appId]
    }

    $row = [PSCustomObject]@{
      ServicePrincipalObjectId = $c.ServicePrincipalObjectId
      AppId                    = $sp.appId
      AppDisplayName           = $sp.displayName
      AppOwnerOrganizationId   = $sp.appOwnerOrganizationId
      Scopes                   = $c.Scopes
      UserSigninsLast30Days    = $signinCount30d
    }

    if ($sp.appOwnerOrganizationId -eq $TenantId) {
      $resultsTenantOwned += $row
    }
    else {
      $resultsNotTenantOwned += $row
    }
  }
  catch {
    # Ignore non-enumerable / missing service principals
  }
}

# ------------------------------
# Output
# ------------------------------
'=== Tenant-owned apps whose delegated consent grants include ONLY baseline scopes + user sign-ins (last 30 days) ==='
$resultsTenantOwned |
  Sort-Object UserSigninsLast30Days -Descending |
  Format-Table -AutoSize

'=== External apps whose delegated consent grants include ONLY baseline scopes + user sign-ins (last 30 days) ==='
$resultsNotTenantOwned |
  Sort-Object UserSigninsLast30Days -Descending |
  Format-Table -AutoSize
