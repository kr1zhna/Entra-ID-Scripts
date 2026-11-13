#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '2.0.0' }

<#
.SYNOPSIS
Provisions and verifies the Microsoft Graph-only access package from the supplied guide.
.DESCRIPTION
Uses the Microsoft Graph PowerShell SDK and interactive browser authentication. The only
configuration prompt is for the fallback approver's Entra user object ID (a GUID).
For sign-in, complete the browser prompt from Microsoft Graph. Complete consent and
any MFA prompts; the script waits for completion.
No application registration, client secret, package resource, or test request is created.

Prerequisites: licensed Entra entitlement management, an Identity Governance
Administrator (or equivalent delegated rights), and admin consent for delegated
EntitlementManagement.ReadWrite.All and Application.Read.All.

Install the SDK module once if needed:
    Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Repository PSGallery

The JSON state file stores tenant/object IDs, not tokens. Keep it to resume a
partial deployment or re-verify a completed deployment without creating duplicates.
Do not delete it to work around an uncertain POST result.

The package is hidden and users cannot self-request or self-remove it; only the
Microsoft Graph on-behalf requestor can submit requests. Independent administrator
permissions are not restricted. The primary approver is the REQUESTOR'S
manager, not necessarily the recipient's manager. Assignment lifetime is 15 minutes;
approval timeout is one day. Assignment notification emails remain enabled.

After provisioning, allow RBAC propagation and test manager/fallback routing,
assignment expiry, and rejection of other applications in the consuming feature.
.PARAMETER FallbackApproverUserId
The fallback approver's user object ID, not a UPN/email. Prompted for if omitted.
.PARAMETER CatalogDisplayName
Name for a new dedicated catalog. Defaults to the guide's Human Approval Catalog.
Saved in the checkpoint and reused on subsequent runs without another prompt.
Use a distinct name and StatePath for a separate deployment.
.PARAMETER StatePath
Local checkpoint file. Defaults to HumanApprovalAccessPackage.state.json beside
this script. A deployment is bound to the tenant and approver recorded in this file.
.EXAMPLE
.\New-HumanApprovalAccessPackage.ps1
.EXAMPLE
.\New-HumanApprovalAccessPackage.ps1 -FallbackApproverUserId '11111111-1111-1111-1111-111111111111'
#>
[CmdletBinding()]
param(
    [string]$FallbackApproverUserId,
    [ValidateScript({ -not [string]::IsNullOrWhiteSpace($_) })]
    [string]$CatalogDisplayName = 'Human Approval Catalog',
    [ValidateNotNullOrEmpty()]
    [string]$StatePath = (Join-Path $PSScriptRoot 'HumanApprovalAccessPackage.state.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$graphBase = 'https://graph.microsoft.com/v1.0'
$graphAppId = '00000003-0000-0000-c000-000000000000'
$assignmentManagerRoleId = 'e2182095-804a-4656-ae11-64734e9b7ae5'

function Save-ProvisioningState {
    $temporaryPath = $script:resolvedStatePath + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    try {
        $json = $script:provisioningState | ConvertTo-Json -Depth 10
        [System.IO.File]::WriteAllText($temporaryPath, $json, [System.Text.UTF8Encoding]::new($false))
        if ([System.IO.File]::Exists($script:resolvedStatePath)) {
            [System.IO.File]::Replace($temporaryPath, $script:resolvedStatePath, [NullString]::Value)
        }
        else {
            [System.IO.File]::Move($temporaryPath, $script:resolvedStatePath)
        }
    }
    finally {
        if ([System.IO.File]::Exists($temporaryPath)) {
            [System.IO.File]::Delete($temporaryPath)
        }
    }
}

function Invoke-GraphJson {
    param(
        [ValidateSet('GET', 'POST')]
        [string]$Method = 'GET',
        [string]$Uri,
        [System.Collections.IDictionary]$Body
    )

    $arguments = @{
        Method      = $Method
        Uri         = $Uri
        OutputType  = 'PSObject'
        ErrorAction = 'Stop'
    }
    if ($PSBoundParameters.ContainsKey('Body')) {
        $arguments.Body = ConvertTo-Json -InputObject $Body -Depth 30
        $arguments.ContentType = 'application/json'
    }
    Invoke-MgGraphRequest @arguments
}

function Get-GraphCollection {
    param([string]$Uri)

    while ($Uri) {
        $pageUri = [uri]$Uri
        if ($pageUri.Scheme -ne 'https' -or $pageUri.Host -ne 'graph.microsoft.com' -or
            -not $pageUri.AbsolutePath.StartsWith('/v1.0/')) {
            throw "Unexpected Graph pagination URL: $Uri"
        }
        $page = Invoke-GraphJson -Uri $Uri
        if ($null -eq $page -or $null -eq $page.PSObject.Properties['value'] -or $null -eq $page.value) {
            throw "Graph did not return a collection for $Uri."
        }
        $page.value
        $nextLink = $page.PSObject.Properties['@odata.nextLink']
        $Uri = if ($null -ne $nextLink) { [string]$nextLink.Value } else { $null }
    }
}

function Test-GraphConfiguration {
    param(
        [AllowNull()][AllowEmptyCollection()]$Actual,
        [AllowNull()][AllowEmptyCollection()]$Expected,
        [string]$Path
    )

    if ($Expected -is [System.Collections.IDictionary]) {
        foreach ($key in $Expected.Keys) {
            if ($null -eq $Actual -or $null -eq $Actual.PSObject.Properties[$key]) {
                throw "Verification failed: missing $Path.$key."
            }
            Test-GraphConfiguration -Actual $Actual.PSObject.Properties[$key].Value `
                -Expected $Expected[$key] -Path "$Path.$key"
        }
    }
    elseif ($Expected -is [array]) {
        if ($null -eq $Actual -or $Actual -isnot [array] -or $Actual.Count -ne $Expected.Count) {
            throw "Verification failed: $Path must contain exactly $($Expected.Count) entries."
        }
        for ($index = 0; $index -lt $Expected.Count; $index++) {
            Test-GraphConfiguration -Actual $Actual[$index] -Expected $Expected[$index] -Path "$Path[$index]"
        }
    }
    elseif (($Expected -is [bool] -and $Actual -isnot [bool]) -or $Actual -cne $Expected) {
        throw "Verification failed: $Path expected '$Expected', received '$Actual'."
    }
}

function Get-ProvisionedGraphObject {
    param(
        [string]$StateProperty,
        [string]$CollectionUri,
        [System.Collections.IDictionary]$Body,
        [string]$ReadQuery = ''
    )

    $id = $script:provisioningState.$StateProperty
    if ($id) {
        $existing = Invoke-GraphJson -Uri "$CollectionUri/$([uri]::EscapeDataString($id))$ReadQuery"
        Test-GraphConfiguration -Actual $existing -Expected $Body -Path $StateProperty
        return $id
    }

    # A pending marker prevents blindly repeating a POST after an uncertain result.
    $script:provisioningState.PendingOperation = $StateProperty
    Save-ProvisioningState
    $created = Invoke-GraphJson -Method POST -Uri $CollectionUri -Body $Body
    if ($null -eq $created -or $null -eq $created.PSObject.Properties['id'] -or
        $created.id -isnot [string] -or [string]::IsNullOrWhiteSpace($created.id)) {
        throw "Creation of $StateProperty returned no valid object ID. Reconcile the pending operation in $script:resolvedStatePath."
    }
    $id = $created.id
    $script:provisioningState.$StateProperty = $id
    $script:provisioningState.PendingOperation = $null
    Save-ProvisioningState
    Write-Host "Created $StateProperty`: $id"
    return $id
}

if ([string]::IsNullOrWhiteSpace($FallbackApproverUserId)) {
    $FallbackApproverUserId = Read-Host 'Fallback approver user object ID (GUID)'
}
$approverId = [guid]::Empty
if (-not [guid]::TryParse($FallbackApproverUserId, [ref]$approverId) -or $approverId -eq [guid]::Empty) {
    throw 'The fallback approver must be a non-empty Entra user object ID (GUID), not an email address.'
}
$FallbackApproverUserId = $approverId.ToString()
$script:resolvedStatePath = [System.IO.Path]::GetFullPath($StatePath)
$stateDirectory = [System.IO.Path]::GetDirectoryName($script:resolvedStatePath)
if (-not [System.IO.Directory]::Exists($stateDirectory)) {
    throw "State directory does not exist: $stateDirectory"
}

$stateLock = $null
$connected = $false
try {
    try {
        $stateLock = [System.IO.File]::Open(
            ($script:resolvedStatePath + '.lock'),
            [System.IO.FileMode]::OpenOrCreate,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None
        )
    }
    catch {
        throw "Cannot lock $script:resolvedStatePath. Another run may be active, or the directory is not writable. $($_.Exception.Message)"
    }

    $script:provisioningState = [pscustomobject][ordered]@{
        SchemaVersion                    = 1
        TenantId                         = $null
        FallbackApproverUserId            = $FallbackApproverUserId
        CatalogDisplayName               = $CatalogDisplayName
        MicrosoftGraphServicePrincipalId = $null
        CatalogId                        = $null
        GraphCatalogRoleAssignmentId     = $null
        AccessPackageId                  = $null
        AssignmentPolicyId               = $null
        PendingOperation                 = $null
        Verified                         = $false
    }
    if (Test-Path -LiteralPath $script:resolvedStatePath) {
        $saved = Get-Content -LiteralPath $script:resolvedStatePath -Raw | ConvertFrom-Json
        if ($null -ne $saved -and $null -ne $saved.PSObject.Properties['SchemaVersion'] -and
            $saved.SchemaVersion -eq 1 -and $null -eq $saved.PSObject.Properties['CatalogDisplayName']) {
            $saved | Add-Member -NotePropertyName CatalogDisplayName -NotePropertyValue 'Human Approval Catalog'
        }
        foreach ($property in $script:provisioningState.PSObject.Properties.Name) {
            if ($null -eq $saved -or $null -eq $saved.PSObject.Properties[$property]) {
                throw "Invalid state file: missing $property. Do not discard existing deployment IDs."
            }
        }
        if ($saved.SchemaVersion -ne 1 -or $saved.FallbackApproverUserId -ne $FallbackApproverUserId) {
            throw 'The state version or fallback approver does not match. Use the original approver to resume this deployment.'
        }
        if ($saved.CatalogDisplayName -isnot [string] -or [string]::IsNullOrWhiteSpace($saved.CatalogDisplayName)) {
            throw 'Invalid state file: CatalogDisplayName must be a non-empty string.'
        }
        if ($PSBoundParameters.ContainsKey('CatalogDisplayName') -and $CatalogDisplayName -cne $saved.CatalogDisplayName) {
            throw 'CatalogDisplayName must match the saved deployment. Existing catalogs will not be renamed.'
        }
        foreach ($property in @(
            'TenantId', 'FallbackApproverUserId', 'MicrosoftGraphServicePrincipalId'
        )) {
            $savedId = [guid]::Empty
            if (($property -eq 'TenantId' -or $null -ne $saved.$property) -and
                (-not [guid]::TryParse([string]$saved.$property, [ref]$savedId) -or $savedId -eq [guid]::Empty)) {
                throw "Invalid state file: $property is not a non-empty GUID."
            }
        }
        $missingPredecessor = -not $saved.MicrosoftGraphServicePrincipalId
        foreach ($property in @('CatalogId', 'GraphCatalogRoleAssignmentId', 'AccessPackageId', 'AssignmentPolicyId')) {
            if ($null -ne $saved.$property -and
                ($saved.$property -isnot [string] -or [string]::IsNullOrWhiteSpace($saved.$property) -or $missingPredecessor)) {
                throw "Invalid state file: $property is invalid or a preceding deployment ID is missing."
            }
            if ($null -eq $saved.$property) {
                $missingPredecessor = $true
            }
        }
        $script:provisioningState = $saved
        if ($saved.PendingOperation) {
            throw "Uncertain previous creation: $($saved.PendingOperation). Inspect the tenant and reconcile that ID in $script:resolvedStatePath before clearing PendingOperation. Do not blindly retry or delete the state file."
        }
    }

    $connectArguments = @{
        Scopes        = @('EntitlementManagement.ReadWrite.All', 'Application.Read.All')
        ContextScope  = 'Process'
        Environment   = 'Global'
        NoWelcome     = $true
        ErrorAction   = 'Stop'
    }
    if ($script:provisioningState.TenantId) {
        $connectArguments.TenantId = $script:provisioningState.TenantId
    }
    Write-Host 'Microsoft Graph sign-in is required (interactive browser authentication).'
    Write-Host 'Sign in with an Identity Governance Administrator account in the intended tenant. Complete any consent/MFA prompts; this script waits for sign-in to finish.'
    Connect-MgGraph @connectArguments | Out-Null
    $connected = $true
    $context = Get-MgContext
    $tenantId = [guid]::Empty
    if ($null -eq $context -or $context.AuthType -ne 'Delegated' -or
        -not [guid]::TryParse([string]$context.TenantId, [ref]$tenantId) -or $tenantId -eq [guid]::Empty) {
        throw 'Interactive sign-in did not return a delegated tenant context.'
    }
    if ($script:provisioningState.TenantId -and $script:provisioningState.TenantId -ne $tenantId.ToString()) {
        throw 'The authenticated tenant does not match the saved deployment.'
    }
    $script:provisioningState.TenantId = $tenantId.ToString()
    $script:provisioningState.Verified = $false
    Save-ProvisioningState

    $spFilter = [uri]::EscapeDataString("appId eq '$graphAppId'")
    $servicePrincipals = @(Get-GraphCollection -Uri "$graphBase/servicePrincipals?`$filter=$spFilter&`$select=id,appId,displayName")
    if ($servicePrincipals.Count -ne 1) {
        throw "Expected exactly one Microsoft Graph service principal; found $($servicePrincipals.Count)."
    }
    $graphSpId = [guid]::Empty
    if ($servicePrincipals[0].appId -ne $graphAppId -or
        -not [guid]::TryParse([string]$servicePrincipals[0].id, [ref]$graphSpId) -or $graphSpId -eq [guid]::Empty) {
        throw 'Microsoft Graph service principal lookup returned an invalid object.'
    }
    $graphServicePrincipalId = $graphSpId.ToString()
    if ($script:provisioningState.MicrosoftGraphServicePrincipalId -and
        $script:provisioningState.MicrosoftGraphServicePrincipalId -ne $graphServicePrincipalId) {
        throw 'The resolved Microsoft Graph service principal does not match the saved deployment.'
    }
    $script:provisioningState.MicrosoftGraphServicePrincipalId = $graphServicePrincipalId
    Save-ProvisioningState

    $catalogBody = @{
        displayName         = $script:provisioningState.CatalogDisplayName
        description         = 'Dedicated catalog for approval-only access packages.'
        state               = 'published'
        isExternallyVisible = $false
    }
    $catalogId = Get-ProvisionedGraphObject -StateProperty 'CatalogId' `
        -CollectionUri "$graphBase/identityGovernance/entitlementManagement/catalogs" -Body $catalogBody

    $roleBody = @{
        principalId      = $graphServicePrincipalId
        roleDefinitionId = $assignmentManagerRoleId
        appScopeId       = "/AccessPackageCatalog/$catalogId"
    }
    $roleId = Get-ProvisionedGraphObject -StateProperty 'GraphCatalogRoleAssignmentId' `
        -CollectionUri "$graphBase/roleManagement/entitlementManagement/roleAssignments" -Body $roleBody

    $packageBody = @{
        displayName = 'Human Approval Access Package'
        description = 'Approval-only package; no resource roles.'
        isHidden    = $true
        catalog     = @{ id = $catalogId }
    }
    $packageUri = "$graphBase/identityGovernance/entitlementManagement/accessPackages"
    $packageId = Get-ProvisionedGraphObject -StateProperty 'AccessPackageId' `
        -CollectionUri $packageUri -ReadQuery '?$expand=catalog' -Body $packageBody

    $policyBody = @{
        displayName            = 'Human Approval - Microsoft Graph Requestor'
        description            = 'Users cannot self-request; Microsoft Graph is the only on-behalf requestor. Approval is required.'
        allowedTargetScope     = 'allMemberUsers'
        specificAllowedTargets = @()
        expiration             = @{ type = 'afterDuration'; duration = 'PT15M' }
        requestorSettings      = @{
            enableTargetsToSelfAddAccess           = $false
            enableTargetsToSelfUpdateAccess        = $false
            enableTargetsToSelfRemoveAccess        = $false
            allowCustomAssignmentSchedule         = $false
            enableOnBehalfRequestorsToAddAccess    = $true
            enableOnBehalfRequestorsToUpdateAccess = $false
            enableOnBehalfRequestorsToRemoveAccess = $false
            onBehalfRequestors                    = @(
                @{
                    '@odata.type'      = '#microsoft.graph.singleServicePrincipal'
                    servicePrincipalId = $graphServicePrincipalId
                    description        = 'Microsoft Graph as the only on-behalf application requestor'
                }
            )
        }
        requestApprovalSettings = @{
            isApprovalRequiredForAdd        = $true
            isApprovalRequiredForUpdate     = $false
            isRequestorJustificationRequired = $false
            stages                         = @(
                @{
                    durationBeforeAutomaticDenial   = 'P1D'
                    isApproverJustificationRequired = $false
                    isEscalationEnabled             = $false
                    durationBeforeEscalation        = 'PT0S'
                    primaryApprovers                = @(
                        @{ '@odata.type' = '#microsoft.graph.requestorManager'; managerLevel = 1 }
                    )
                    fallbackPrimaryApprovers        = @(
                        @{ '@odata.type' = '#microsoft.graph.singleUser'; userId = $FallbackApproverUserId }
                    )
                    escalationApprovers             = @()
                    fallbackEscalationApprovers     = @()
                }
            )
        }
        notificationSettings = @{ isAssignmentNotificationDisabled = $false }
        accessPackage        = @{ id = $packageId }
    }
    $policyUri = "$graphBase/identityGovernance/entitlementManagement/assignmentPolicies"
    $policyId = Get-ProvisionedGraphObject -StateProperty 'AssignmentPolicyId' `
        -CollectionUri $policyUri -ReadQuery '?$expand=accessPackage' -Body $policyBody

    Write-Host 'Verifying the persisted policy, package, and catalog role assignment...'
    $policy = Invoke-GraphJson -Uri "$policyUri/$([uri]::EscapeDataString($policyId))`?`$expand=accessPackage"
    Test-GraphConfiguration -Actual $policy -Expected $policyBody -Path 'assignmentPolicy'

    $package = Invoke-GraphJson -Uri "$packageUri/$([uri]::EscapeDataString($packageId))`?`$expand=catalog,resourceRoleScopes,assignmentPolicies"
    foreach ($navigation in @('resourceRoleScopes', 'assignmentPolicies')) {
        $nextLink = $package.PSObject.Properties["$navigation@odata.nextLink"]
        if ($null -ne $nextLink -and $nextLink.Value) {
            $package.$navigation = @($package.$navigation) + @(Get-GraphCollection -Uri $nextLink.Value)
        }
    }
    Test-GraphConfiguration -Actual $package -Expected @{
        id                 = $packageId
        catalog            = @{ id = $catalogId }
        resourceRoleScopes = @()
        assignmentPolicies = @(@{ id = $policyId })
    } -Path 'accessPackage'

    $roleFilter = [uri]::EscapeDataString("principalId eq '$graphServicePrincipalId'")
    $roles = @(Get-GraphCollection -Uri "$graphBase/roleManagement/entitlementManagement/roleAssignments?`$filter=$roleFilter&`$select=id,principalId,roleDefinitionId,appScopeId")
    $matchingRoles = @($roles | Where-Object {
        $_.principalId -eq $roleBody.principalId -and
        $_.roleDefinitionId -eq $roleBody.roleDefinitionId -and $_.appScopeId -eq $roleBody.appScopeId
    })
    if ($matchingRoles.Count -ne 1 -or $matchingRoles[0].id -ne $roleId) {
        throw 'Verification failed: expected exactly the saved Graph assignment-manager role for this catalog.'
    }
    $script:provisioningState.Verified = $true
    Save-ProvisioningState

    Write-Host "Provisioning verified. Keep the checkpoint: $script:resolvedStatePath"
    Write-Warning 'Allow RBAC propagation, then test approval routing, 15-minute expiry, and other-application rejection in the actual consuming feature. These runtime tests have not been performed.'
    [pscustomobject][ordered]@{
        TenantId                         = $script:provisioningState.TenantId
        MicrosoftGraphServicePrincipalId = $graphServicePrincipalId
        CatalogId                        = $catalogId
        CatalogDisplayName               = $script:provisioningState.CatalogDisplayName
        GraphCatalogRoleAssignmentId     = $roleId
        AccessPackageId                  = $packageId
        AssignmentPolicyId               = $policyId
        FallbackApproverUserId            = $FallbackApproverUserId
        StatePath                        = $script:resolvedStatePath
        ConfigurationVerified            = $true
    }
}
catch {
    if ($null -ne $stateLock -and $null -ne (Get-Variable -Name provisioningState -Scope Script -ErrorAction SilentlyContinue) -and
        $script:provisioningState.PendingOperation) {
        Write-Warning "Creation of $($script:provisioningState.PendingOperation) was not checkpointed. It may have succeeded on the server. Reconcile $script:resolvedStatePath before retrying."
    }
    throw
}
finally {
    try {
        if ($connected) {
            Disconnect-MgGraph -ErrorAction Continue | Out-Null
        }
    }
    finally {
        if ($null -ne $stateLock) {
            $stateLock.Dispose()
        }
    }
}
