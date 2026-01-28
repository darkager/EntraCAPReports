function Get-CAPClassification {
    <#
    .SYNOPSIS
        Classifies a Conditional Access policy by its intent pattern.

    .DESCRIPTION
        Analyzes a Conditional Access policy and determines its classification(s)
        based on the conditions and controls configured. Returns both a primary
        classification (highest priority) and all matching classifications.

    .PARAMETER Policy
        The conditionalAccessPolicy object to classify.

    .OUTPUTS
        PSCustomObject with PrimaryClassification and AllClassifications properties.

    .NOTES
        Internal function - not exported.

        Priority Order (highest to lowest):
        BlockPolicy > AdminProtection > WorkloadIdentity > RiskBased > GuestPolicy >
        DeviceCompliance > LocationBased > AuthenticationFlowRestriction > AppSpecific >
        MFAEnforcement > SessionControl > General
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [Object]$Policy
    )

    process {
        $classifications = New-Object -TypeName 'System.Collections.Generic.List[String]'

        $conditions = $Policy.Conditions
        $grantControls = $Policy.GrantControls
        $sessionControls = $Policy.SessionControls

        # Check for BlockPolicy
        if ($grantControls.BuiltInControls -contains 'block') {
            $classifications.Add('BlockPolicy')
        }

        # Check for AdminProtection (targets directory roles)
        $hasRoles = ($conditions.Users.IncludeRoles -and $conditions.Users.IncludeRoles.Count -gt 0)
        if ($hasRoles) {
            $classifications.Add('AdminProtection')
        }

        # Check for WorkloadIdentity (targets service principals / workload identities)
        $hasClientApps = ($null -ne $conditions.ClientApplications)
        $hasIncludeSPs = ($hasClientApps -and $conditions.ClientApplications.IncludeServicePrincipals -and
            $conditions.ClientApplications.IncludeServicePrincipals.Count -gt 0)
        $hasSpFilter = ($hasClientApps -and $null -ne $conditions.ClientApplications.ServicePrincipalFilter -and
            $null -ne $conditions.ClientApplications.ServicePrincipalFilter.Rule)
        if ($hasIncludeSPs -or $hasSpFilter) {
            $classifications.Add('WorkloadIdentity')
        }

        # Check for RiskBased (has risk level conditions)
        $hasSignInRisk = ($conditions.SignInRiskLevels -and $conditions.SignInRiskLevels.Count -gt 0)
        $hasUserRisk = ($conditions.UserRiskLevels -and $conditions.UserRiskLevels.Count -gt 0)
        $hasServicePrincipalRisk = ($conditions.ServicePrincipalRiskLevels -and $conditions.ServicePrincipalRiskLevels.Count -gt 0)
        $hasInsiderRisk = ($null -ne $conditions.InsiderRiskLevels)
        if ($hasSignInRisk -or $hasUserRisk -or $hasServicePrincipalRisk -or $hasInsiderRisk) {
            $classifications.Add('RiskBased')
        }

        # Check for GuestPolicy (targets guests/external users)
        $hasGuestInclude = ($null -ne $conditions.Users.IncludeGuestsOrExternalUsers)
        $includesGuestSpecialValue = ($conditions.Users.IncludeUsers -contains 'GuestsOrExternalUsers')
        if ($hasGuestInclude -or $includesGuestSpecialValue) {
            $classifications.Add('GuestPolicy')
        }

        # Check for DeviceCompliance (requires compliant/domain-joined device)
        $requiresCompliantDevice = ($grantControls.BuiltInControls -contains 'compliantDevice')
        $requiresDomainJoined = ($grantControls.BuiltInControls -contains 'domainJoinedDevice')
        $hasDeviceFilter = ($null -ne $conditions.Devices -and $null -ne $conditions.Devices.DeviceFilter)
        if ($requiresCompliantDevice -or $requiresDomainJoined -or $hasDeviceFilter) {
            $classifications.Add('DeviceCompliance')
        }

        # Check for LocationBased (has non-trivial location conditions)
        $hasLocationInclude = ($conditions.Locations.IncludeLocations -and
            $conditions.Locations.IncludeLocations.Count -gt 0 -and
            $conditions.Locations.IncludeLocations -notcontains 'All')
        $hasLocationExclude = ($conditions.Locations.ExcludeLocations -and
            $conditions.Locations.ExcludeLocations.Count -gt 0)
        if ($hasLocationInclude -or $hasLocationExclude) {
            $classifications.Add('LocationBased')
        }

        # Check for AuthenticationFlowRestriction (blocks device code flow or auth transfer)
        $hasAuthFlows = ($null -ne $conditions.AuthenticationFlows -and
            $conditions.AuthenticationFlows.TransferMethods -and
            $conditions.AuthenticationFlows.TransferMethods.Count -gt 0)
        if ($hasAuthFlows) {
            $classifications.Add('AuthenticationFlowRestriction')
        }

        # Check for AppSpecific (targets specific apps, not All)
        $includeApps = $conditions.Applications.IncludeApplications
        $isAllApps = ($includeApps -contains 'All')
        $isSpecificApps = ($includeApps -and $includeApps.Count -gt 0 -and -not $isAllApps)
        $hasUserActions = ($conditions.Applications.IncludeUserActions -and
            $conditions.Applications.IncludeUserActions.Count -gt 0)
        $hasAuthContexts = ($conditions.Applications.IncludeAuthenticationContextClassReferences -and
            $conditions.Applications.IncludeAuthenticationContextClassReferences.Count -gt 0)
        if ($isSpecificApps -or $hasUserActions -or $hasAuthContexts) {
            $classifications.Add('AppSpecific')
        }

        # Check for MFAEnforcement (requires MFA)
        $requiresMfa = ($grantControls.BuiltInControls -contains 'mfa')
        $hasAuthStrength = ($null -ne $grantControls.AuthenticationStrength)
        if ($requiresMfa -or $hasAuthStrength) {
            # Only add if not already classified as something more specific
            if (-not ($classifications -contains 'AdminProtection' -or
                      $classifications -contains 'RiskBased' -or
                      $classifications -contains 'GuestPolicy')) {
                $classifications.Add('MFAEnforcement')
            }
        }

        # Check for SessionControl (has session controls configured)
        $hasSignInFrequency = ($null -ne $sessionControls.SignInFrequency -and
            $sessionControls.SignInFrequency.IsEnabled -eq $true)
        $hasPersistentBrowser = ($null -ne $sessionControls.PersistentBrowser -and
            $sessionControls.PersistentBrowser.IsEnabled -eq $true)
        $hasCloudAppSecurity = ($null -ne $sessionControls.CloudAppSecurity -and
            $sessionControls.CloudAppSecurity.IsEnabled -eq $true)
        $hasAppEnforcedRestrictions = ($null -ne $sessionControls.ApplicationEnforcedRestrictions -and
            $sessionControls.ApplicationEnforcedRestrictions.IsEnabled -eq $true)
        if ($hasSignInFrequency -or $hasPersistentBrowser -or $hasCloudAppSecurity -or $hasAppEnforcedRestrictions) {
            $classifications.Add('SessionControl')
        }

        # Default to General if no other classification
        if ($classifications.Count -eq 0) {
            $classifications.Add('General')
        }

        # Priority order for primary classification
        $priorityOrder = @(
            'BlockPolicy'
            'AdminProtection'
            'WorkloadIdentity'
            'RiskBased'
            'GuestPolicy'
            'DeviceCompliance'
            'LocationBased'
            'AuthenticationFlowRestriction'
            'AppSpecific'
            'MFAEnforcement'
            'SessionControl'
            'General'
        )

        # Determine primary classification (first match in priority order)
        $primaryClassification = 'General'
        foreach ($priority in $priorityOrder) {
            if ($classifications -contains $priority) {
                $primaryClassification = $priority
                break
            }
        }

        return [PSCustomObject]@{
            PrimaryClassification = $primaryClassification
            AllClassifications    = $classifications -join '; '
            ClassificationList    = $classifications.ToArray()
        }
    }
}
