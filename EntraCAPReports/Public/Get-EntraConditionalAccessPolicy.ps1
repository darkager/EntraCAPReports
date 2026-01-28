function Get-EntraConditionalAccessPolicy {
    <#
    .SYNOPSIS
        Retrieves Conditional Access Policies with resolved names and classification.

    .DESCRIPTION
        Queries Microsoft Entra ID for Conditional Access Policies and enriches them
        with human-readable names for all GUIDs (users, groups, roles, applications,
        locations). Also classifies each policy by its intent pattern.

    .PARAMETER PolicyId
        Optional array of specific policy IDs to retrieve. If not specified,
        retrieves all policies.

    .PARAMETER ResolveNames
        If true (default), resolves GUIDs to display names. Set to false for
        faster execution when only raw data is needed.

    .PARAMETER ProgressParentId
        Parent progress bar ID for nested progress reporting.

    .EXAMPLE
        Get-EntraConditionalAccessPolicy

        Retrieves all Conditional Access Policies with resolved names.

    .EXAMPLE
        Get-EntraConditionalAccessPolicy -PolicyId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'

        Retrieves a specific policy by ID.

    .EXAMPLE
        Get-EntraConditionalAccessPolicy -ResolveNames $false

        Retrieves all policies without resolving GUIDs (faster).

    .OUTPUTS
        PSCustomObject with comprehensive policy details including resolved names
        and classification.

    .NOTES
        Requires Microsoft.Graph.Identity.SignIns module and Policy.Read.All permission.
        For name resolution, also requires Directory.Read.All and Application.Read.All.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter()]
        [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
        [String[]]$PolicyId,

        [Parameter()]
        [Bool]$ResolveNames = $true,

        [Parameter(DontShow)]
        [Int32]$ProgressParentId = -1
    )

    begin {
        Write-Verbose -Message 'Starting Get-EntraConditionalAccessPolicy'

        $results = New-Object -TypeName 'System.Collections.Generic.List[PSCustomObject]'
        $progressId = if ($ProgressParentId -ge 0) { $ProgressParentId + 1 } else { 0 }
    }

    process {
        try {
            # Retrieve policies
            if ($PolicyId) {
                Write-Verbose -Message "Retrieving $($PolicyId.Count) specific policy/policies"
                $policies = foreach ($id in $PolicyId) {
                    try {
                        Get-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $id -ErrorAction Stop
                    }
                    catch {
                        Write-Warning -Message "Failed to retrieve policy $id : $PSItem"
                    }
                }
            }
            else {
                Write-Verbose -Message 'Retrieving all Conditional Access Policies'
                $policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
            }

            $policyCount = @($policies).Count
            Write-Verbose -Message "Retrieved $policyCount policy/policies"

            if ($policyCount -eq 0) {
                return
            }

            # Process each policy
            $processedCount = 0
            foreach ($policy in $policies) {
                $processedCount++

                # Progress reporting
                $percentComplete = [Math]::Round(($processedCount / $policyCount) * 100)
                $progressParams = @{
                    Id              = $progressId
                    Activity        = 'Processing Conditional Access Policies'
                    Status          = "Policy $processedCount of $policyCount"
                    CurrentOperation = $policy.DisplayName
                    PercentComplete = $percentComplete
                }
                if ($ProgressParentId -ge 0) {
                    $progressParams['ParentId'] = $ProgressParentId
                }
                Write-Progress @progressParams

                Write-Verbose -Message "Processing policy: $($policy.DisplayName)"

                $conditions = $policy.Conditions
                $grantControls = $policy.GrantControls
                $sessionControls = $policy.SessionControls

                # Initialize resolved values
                $resolvedIncludeUsers = @()
                $resolvedExcludeUsers = @()
                $resolvedIncludeGroups = @()
                $resolvedExcludeGroups = @()
                $resolvedIncludeRoles = @()
                $resolvedExcludeRoles = @()
                $resolvedIncludeApps = @()
                $resolvedExcludeApps = @()
                $resolvedIncludeLocations = @()
                $resolvedExcludeLocations = @()
                $expandedIncludeLocations = @()
                $expandedExcludeLocations = @()
                $resolvedUserActions = @()
                $resolvedAuthContexts = @()
                $resolvedIncludeGuests = $null
                $resolvedExcludeGuests = $null
                $authStrengthName = $null

                if ($ResolveNames) {
                    # Resolve users
                    $usersResult = Resolve-CAPUsers -UserIds $conditions.Users.IncludeUsers
                    $resolvedIncludeUsers = $usersResult.Details

                    $usersExcludeResult = Resolve-CAPUsers -UserIds $conditions.Users.ExcludeUsers
                    $resolvedExcludeUsers = $usersExcludeResult.Details

                    # Resolve groups
                    $groupsResult = Resolve-CAPGroups -GroupIds $conditions.Users.IncludeGroups
                    $resolvedIncludeGroups = $groupsResult.Details

                    $groupsExcludeResult = Resolve-CAPGroups -GroupIds $conditions.Users.ExcludeGroups
                    $resolvedExcludeGroups = $groupsExcludeResult.Details

                    # Resolve roles
                    $rolesResult = Resolve-CAPRoles -RoleIds $conditions.Users.IncludeRoles
                    $resolvedIncludeRoles = $rolesResult.Details

                    $rolesExcludeResult = Resolve-CAPRoles -RoleIds $conditions.Users.ExcludeRoles
                    $resolvedExcludeRoles = $rolesExcludeResult.Details

                    # Resolve guest settings
                    $resolvedIncludeGuests = Resolve-CAPGuestsOrExternalUsers -GuestSettings $conditions.Users.IncludeGuestsOrExternalUsers
                    $resolvedExcludeGuests = Resolve-CAPGuestsOrExternalUsers -GuestSettings $conditions.Users.ExcludeGuestsOrExternalUsers

                    # Resolve applications
                    $appsResult = Resolve-CAPApplications -ApplicationIds $conditions.Applications.IncludeApplications
                    $resolvedIncludeApps = $appsResult.Details

                    $appsExcludeResult = Resolve-CAPApplications -ApplicationIds $conditions.Applications.ExcludeApplications
                    $resolvedExcludeApps = $appsExcludeResult.Details

                    # Resolve user actions
                    $userActionsResult = Resolve-CAPUserActions -UserActions $conditions.Applications.IncludeUserActions
                    $resolvedUserActions = $userActionsResult.Details

                    # Resolve auth contexts
                    $authContextsResult = Resolve-CAPAuthContexts -AuthContextIds $conditions.Applications.IncludeAuthenticationContextClassReferences
                    $resolvedAuthContexts = $authContextsResult.Details

                    # Resolve locations
                    $locationsResult = Resolve-CAPLocations -LocationIds $conditions.Locations.IncludeLocations
                    $resolvedIncludeLocations = $locationsResult.Details
                    $expandedIncludeLocations = $locationsResult.ExpandedDetails

                    $locationsExcludeResult = Resolve-CAPLocations -LocationIds $conditions.Locations.ExcludeLocations
                    $resolvedExcludeLocations = $locationsExcludeResult.Details
                    $expandedExcludeLocations = $locationsExcludeResult.ExpandedDetails

                    # Resolve authentication strength
                    if ($null -ne $grantControls.AuthenticationStrength) {
                        $authStrengthId = $grantControls.AuthenticationStrength.Id
                        if ($authStrengthId) {
                            # Initialize auth strength cache if needed
                            if ($script:AuthStrengthCache.Count -eq 0) {
                                try {
                                    $authStrengths = Get-MgPolicyAuthenticationStrengthPolicy -All -ErrorAction Stop
                                    foreach ($as in $authStrengths) {
                                        $script:AuthStrengthCache.Add($as.Id, [PSCustomObject]@{
                                            Id          = $as.Id
                                            DisplayName = $as.DisplayName
                                            PolicyType  = $as.PolicyType
                                        })
                                    }
                                }
                                catch {
                                    Write-Warning -Message "Failed to retrieve authentication strength policies: $PSItem"
                                }
                            }

                            if ($script:AuthStrengthCache.ContainsKey($authStrengthId)) {
                                $authStrengthName = $script:AuthStrengthCache[$authStrengthId].DisplayName
                            }
                            else {
                                $authStrengthName = $authStrengthId
                            }
                        }
                    }
                }

                # Get classification
                $classification = Get-CAPClassification -Policy $policy

                # Format summary descriptions
                $userScopeDescription = Format-CAPUserScope `
                    -Users $conditions.Users `
                    -ResolvedIncludeUsers $resolvedIncludeUsers `
                    -ResolvedExcludeUsers $resolvedExcludeUsers `
                    -ResolvedIncludeGroups $resolvedIncludeGroups `
                    -ResolvedExcludeGroups $resolvedExcludeGroups `
                    -ResolvedIncludeRoles $resolvedIncludeRoles `
                    -ResolvedExcludeRoles $resolvedExcludeRoles

                $appScopeDescription = Format-CAPAppScope `
                    -Applications $conditions.Applications `
                    -ResolvedIncludeApps $resolvedIncludeApps `
                    -ResolvedExcludeApps $resolvedExcludeApps `
                    -ResolvedUserActions $resolvedUserActions `
                    -ResolvedAuthContexts $resolvedAuthContexts

                $grantDescription = Format-CAPGrantControls `
                    -GrantControls $grantControls `
                    -AuthStrengthName $authStrengthName

                $sessionDescription = Format-CAPSessionControls -SessionControls $sessionControls

                $conditionsDescription = Format-CAPConditions -Conditions $conditions

                # Build result object
                $result = [PSCustomObject]@{
                    # Policy metadata
                    PolicyId                         = $policy.Id
                    DisplayName                      = $policy.DisplayName
                    Description                      = $policy.Description
                    State                            = $policy.State
                    CreatedDateTime                  = $policy.CreatedDateTime
                    ModifiedDateTime                 = $policy.ModifiedDateTime
                    TemplateId                       = $policy.TemplateId

                    # Classification
                    Classification                   = $classification.PrimaryClassification
                    AllClassifications               = $classification.AllClassifications

                    # User scope - resolved names
                    IncludedUsers                    = ($resolvedIncludeUsers | ForEach-Object -Process { $PSItem.DisplayName }) -join '; '
                    ExcludedUsers                    = ($resolvedExcludeUsers | ForEach-Object -Process { $PSItem.DisplayName }) -join '; '
                    IncludedGroups                   = ($resolvedIncludeGroups | ForEach-Object -Process { $PSItem.DisplayName }) -join '; '
                    ExcludedGroups                   = ($resolvedExcludeGroups | ForEach-Object -Process { $PSItem.DisplayName }) -join '; '
                    IncludedRoles                    = ($resolvedIncludeRoles | ForEach-Object -Process { $PSItem.DisplayName }) -join '; '
                    ExcludedRoles                    = ($resolvedExcludeRoles | ForEach-Object -Process { $PSItem.DisplayName }) -join '; '
                    IncludedGuestsOrExternalUsers    = $resolvedIncludeGuests.Description
                    ExcludedGuestsOrExternalUsers    = $resolvedExcludeGuests.Description
                    UserScopeDescription             = $userScopeDescription

                    # User scope - raw IDs
                    IncludedUserIds                  = $conditions.Users.IncludeUsers -join '; '
                    ExcludedUserIds                  = $conditions.Users.ExcludeUsers -join '; '
                    IncludedGroupIds                 = $conditions.Users.IncludeGroups -join '; '
                    ExcludedGroupIds                 = $conditions.Users.ExcludeGroups -join '; '
                    IncludedRoleIds                  = $conditions.Users.IncludeRoles -join '; '
                    ExcludedRoleIds                  = $conditions.Users.ExcludeRoles -join '; '

                    # Application scope - resolved names
                    IncludedApplications             = ($resolvedIncludeApps | ForEach-Object -Process { $PSItem.DisplayName }) -join '; '
                    ExcludedApplications             = ($resolvedExcludeApps | ForEach-Object -Process { $PSItem.DisplayName }) -join '; '
                    IncludedUserActions              = ($resolvedUserActions | ForEach-Object -Process { $PSItem.DisplayName }) -join '; '
                    IncludedAuthContexts             = ($resolvedAuthContexts | ForEach-Object -Process { $PSItem.DisplayName }) -join '; '
                    ApplicationFilter                = $conditions.Applications.ApplicationFilter.Rule
                    AppScopeDescription              = $appScopeDescription

                    # Application scope - raw IDs
                    IncludedApplicationIds           = $conditions.Applications.IncludeApplications -join '; '
                    ExcludedApplicationIds           = $conditions.Applications.ExcludeApplications -join '; '

                    # Conditions
                    ClientAppTypes                   = $conditions.ClientAppTypes -join '; '
                    IncludedPlatforms                = $conditions.Platforms.IncludePlatforms -join '; '
                    ExcludedPlatforms                = $conditions.Platforms.ExcludePlatforms -join '; '
                    IncludedLocations                = ($resolvedIncludeLocations | ForEach-Object -Process { $PSItem.DisplayName }) -join '; '
                    ExcludedLocations                = ($resolvedExcludeLocations | ForEach-Object -Process { $PSItem.DisplayName }) -join '; '
                    IncludedLocationIds              = $conditions.Locations.IncludeLocations -join '; '
                    ExcludedLocationIds              = $conditions.Locations.ExcludeLocations -join '; '
                    DeviceFilterMode                 = $conditions.Devices.DeviceFilter.Mode
                    DeviceFilterRule                 = $conditions.Devices.DeviceFilter.Rule
                    SignInRiskLevels                 = $conditions.SignInRiskLevels -join '; '
                    UserRiskLevels                   = $conditions.UserRiskLevels -join '; '
                    ServicePrincipalRiskLevels       = $conditions.ServicePrincipalRiskLevels -join '; '
                    InsiderRiskLevels                = $conditions.InsiderRiskLevels
                    AuthenticationFlowsTransferMethods = $conditions.AuthenticationFlows.TransferMethods -join '; '
                    ClientApplicationsIncludeServicePrincipals = $conditions.ClientApplications.IncludeServicePrincipals -join '; '
                    ClientApplicationsExcludeServicePrincipals = $conditions.ClientApplications.ExcludeServicePrincipals -join '; '
                    ClientApplicationsServicePrincipalFilter = $conditions.ClientApplications.ServicePrincipalFilter.Rule
                    ConditionsDescription            = $conditionsDescription

                    # Grant controls
                    GrantOperator                    = $grantControls.Operator
                    BuiltInControls                  = $grantControls.BuiltInControls -join '; '
                    AuthenticationStrength           = $authStrengthName
                    AuthenticationStrengthId         = $grantControls.AuthenticationStrength.Id
                    TermsOfUse                       = $grantControls.TermsOfUse -join '; '
                    CustomAuthenticationFactors      = $grantControls.CustomAuthenticationFactors -join '; '
                    GrantDescription                 = $grantDescription

                    # Session controls
                    SignInFrequencyEnabled           = $sessionControls.SignInFrequency.IsEnabled
                    SignInFrequencyValue             = $sessionControls.SignInFrequency.Value
                    SignInFrequencyType              = $sessionControls.SignInFrequency.Type
                    SignInFrequencyInterval          = $sessionControls.SignInFrequency.FrequencyInterval
                    PersistentBrowserEnabled         = $sessionControls.PersistentBrowser.IsEnabled
                    PersistentBrowserMode            = $sessionControls.PersistentBrowser.Mode
                    CloudAppSecurityEnabled          = $sessionControls.CloudAppSecurity.IsEnabled
                    CloudAppSecurityType             = $sessionControls.CloudAppSecurity.CloudAppSecurityType
                    AppEnforcedRestrictionsEnabled   = $sessionControls.ApplicationEnforcedRestrictions.IsEnabled
                    ContinuousAccessEvaluationMode   = $sessionControls.ContinuousAccessEvaluation.Mode
                    DisableResilienceDefaults        = $sessionControls.DisableResilienceDefaults
                    SessionDescription               = $sessionDescription

                    # Detailed data for flattening
                    _IncludeUsersDetails             = $resolvedIncludeUsers
                    _ExcludeUsersDetails             = $resolvedExcludeUsers
                    _IncludeGroupsDetails            = $resolvedIncludeGroups
                    _ExcludeGroupsDetails            = $resolvedExcludeGroups
                    _IncludeRolesDetails             = $resolvedIncludeRoles
                    _ExcludeRolesDetails             = $resolvedExcludeRoles
                    _IncludeAppsDetails              = $resolvedIncludeApps
                    _ExcludeAppsDetails              = $resolvedExcludeApps
                    _IncludeLocationsDetails         = $resolvedIncludeLocations
                    _ExcludeLocationsDetails         = $resolvedExcludeLocations
                    _IncludeLocationsExpanded        = $expandedIncludeLocations
                    _ExcludeLocationsExpanded        = $expandedExcludeLocations
                    _UserActionsDetails              = $resolvedUserActions
                    _AuthContextsDetails             = $resolvedAuthContexts
                }

                $results.Add($result)
            }

            # Complete progress
            Write-Progress -Id $progressId -Activity 'Processing Conditional Access Policies' -Completed
        }
        catch {
            Write-Progress -Id $progressId -Activity 'Processing Conditional Access Policies' -Completed
            Write-Error -Message "Failed to retrieve Conditional Access Policies: $PSItem"
            throw
        }
    }

    end {
        Write-Verbose -Message "Returning $($results.Count) policy/policies"
        $results
    }
}
