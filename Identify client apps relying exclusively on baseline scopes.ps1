<#
.SYNOPSIS
    Queries Microsoft Graph sign-in logs and filters to entries where
    conditionalAccessAudiences contains ONLY the specified audience.
    Splits results into tenant-owned apps vs external apps (excludes 1P Microsoft apps).
.NOTES
    Compatible with PowerShell 5.1+ and 7.x. Requires the Microsoft.Graph module.
#>

param(
    [Parameter(Mandatory=$true, HelpMessage="The audience ID (GUID) to filter on")]
    [string]$AudienceId,
    [Parameter(Mandatory=$true, HelpMessage="The tenant ID (GUID) to connect to")]
    [string]$TenantId,
    [Parameter(Mandatory=$true, HelpMessage="Start date in ISO 8601 format (e.g. 2026-06-01T00:00:00Z)")]
    [string]$StartDate,
    [Parameter(Mandatory=$true, HelpMessage="End date in ISO 8601 format (e.g. 2026-06-02T00:00:00Z)")]
    [string]$EndDate
)

# Ensure Microsoft Graph module is available
if (-not (Get-Command Get-MgContext -ErrorAction SilentlyContinue)) {
    Write-Error "Microsoft.Graph module not found. Install with: Install-Module Microsoft.Graph -Scope CurrentUser"
    exit 1
}

# Connect if not already connected
$context = Get-MgContext
if (-not $context) {
    Connect-MgGraph -Scopes "AuditLog.Read.All", "Directory.Read.All" -TenantId $TenantId
}

$filter = "createdDateTime ge $StartDate and createdDateTime lt $EndDate and conditionalAccessAudiences/any(a:a eq '$AudienceId')"
$uri = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=$filter"

$allResults = [System.Collections.ArrayList]@()
$nextLink = $uri

# Page through all results
while ($nextLink) {
    $response = Invoke-MgGraphRequest -Method GET -Uri $nextLink -OutputType PSObject
    
    if ($response.value) {
        foreach ($item in $response.value) {
            [void]$allResults.Add($item)
        }
    }
    
    $nextLink = $response.'@odata.nextLink'
}

# Client-side filter: keep only entries where conditionalAccessAudiences
# contains EXACTLY the target audience and nothing else
$filtered = $allResults | Where-Object {
    $audiences = $_.conditionalAccessAudiences
    ($audiences.Count -eq 1) -and ($audiences[0] -eq $AudienceId)
}

# Look up appOwnerOrganizationId for each unique appId to classify apps
$uniqueAppIds = $filtered | ForEach-Object { $_.appId } | Sort-Object -Unique
$appOwnerMap = @{}  # appId -> appOwnerOrganizationId

foreach ($appId in $uniqueAppIds) {
    if (-not $appId) { continue }
    try {
        $spUri = "https://graph.microsoft.com/beta/servicePrincipals?`$filter=appId eq '$appId'&`$select=appId,appOwnerOrganizationId"
        $spResp = Invoke-MgGraphRequest -Method GET -Uri $spUri -OutputType PSObject
        if ($spResp.value -and $spResp.value.Count -gt 0) {
            $appOwnerMap[$appId] = $spResp.value[0].appOwnerOrganizationId
        }
    }
    catch {
        # Skip apps we can't look up
    }
}

# Microsoft Services tenant ID (1P apps)
$MicrosoftTenantId = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"

# Split into tenant-owned vs external, excluding Microsoft 1P apps
$tenantOwned = $filtered | Where-Object { $appOwnerMap[$_.appId] -eq $TenantId }
$external = $filtered | Where-Object {
    $owner = $appOwnerMap[$_.appId]
    $owner -and ($owner -ne $TenantId) -and ($owner -ne $MicrosoftTenantId)
}

Write-Host "Tenant-owned app sign-ins: $($tenantOwned.Count)" -ForegroundColor Green
Write-Host "External app sign-ins: $($external.Count)" -ForegroundColor Green

# Helper function for null-safe column selection
function Format-Output {
    param($Data)
    $Data | Select-Object `
        @{Name='id';Expression={if ($_.id) { $_.id } else { '' }}},
        @{Name='createdDateTime';Expression={if ($_.createdDateTime) { $_.createdDateTime } else { '' }}},
        @{Name='appId';Expression={if ($_.appId) { $_.appId } else { '' }}},
        @{Name='appDisplayName';Expression={if ($_.appDisplayName) { $_.appDisplayName } else { '' }}},
        @{Name='userDisplayName';Expression={if ($_.userDisplayName) { $_.userDisplayName } else { '' }}},
        @{Name='resourceId';Expression={if ($_.resourceId) { $_.resourceId } else { '' }}},
        @{Name='resourceDisplayName';Expression={if ($_.resourceDisplayName) { $_.resourceDisplayName } else { '' }}},
        @{Name='userPrincipalName';Expression={if ($_.userPrincipalName) { $_.userPrincipalName } else { '' }}},
        @{Name='ipAddress';Expression={if ($_.ipAddress) { $_.ipAddress } else { '' }}},
        @{Name='conditionalAccessStatus';Expression={if ($_.conditionalAccessStatus) { $_.conditionalAccessStatus } else { '' }}}
}

# Display results
Write-Host "`n=== Tenant-owned apps ===" -ForegroundColor White
$outputTenantOwned = Format-Output -Data $tenantOwned
$outputTenantOwned | Format-Table -AutoSize

Write-Host "`n=== External apps ===" -ForegroundColor White
$outputExternal = Format-Output -Data $external
$outputExternal | Format-Table -AutoSize

# Export to CSV
$csvPathTenantOwned = ".\FilteredSignIns_TenantOwned.csv"
$csvPathExternal = ".\FilteredSignIns_External.csv"
$outputTenantOwned | Export-Csv -Path $csvPathTenantOwned -NoTypeInformation
$outputExternal | Export-Csv -Path $csvPathExternal -NoTypeInformation
Write-Host "`nExported to: $csvPathTenantOwned, $csvPathExternal" -ForegroundColor Green
 