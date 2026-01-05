function Format-CAPUserScope {
    <#
    .SYNOPSIS
        Creates a human-readable summary of the user scope.

    .DESCRIPTION
        Analyzes the user conditions and generates a concise description
        of who the policy applies to.

    .PARAMETER Users
        The conditionalAccessUsers object.

    .PARAMETER ResolvedUsers
        Pre-resolved user names.

    .PARAMETER ResolvedGroups
        Pre-resolved group names.

    .PARAMETER ResolvedRoles
        Pre-resolved role names.

    .OUTPUTS
        String description of the user scope.

    .NOTES
        Internal function - not exported.
    #>
    [CmdletBinding()]
    [OutputType([String])]
    param(
        [Parameter()]
        [Object]$Users,

        [Parameter()]
        [Object]$ResolvedIncludeUsers,

        [Parameter()]
        [Object]$ResolvedExcludeUsers,

        [Parameter()]
        [Object]$ResolvedIncludeGroups,

        [Parameter()]
        [Object]$ResolvedExcludeGroups,

        [Parameter()]
        [Object]$ResolvedIncludeRoles,

        [Parameter()]
        [Object]$ResolvedExcludeRoles
    )

    process {
        $parts = New-Object -TypeName 'System.Collections.Generic.List[String]'

        # Include side
        $includeUsers = $Users.IncludeUsers
        $includeGroups = $Users.IncludeGroups
        $includeRoles = $Users.IncludeRoles
        $includeGuests = $Users.IncludeGuestsOrExternalUsers

        if ($includeUsers -contains 'All') {
            $parts.Add('All users')
        }
        elseif ($includeUsers -contains 'None') {
            $parts.Add('No users')
        }
        else {
            if ($includeUsers -contains 'GuestsOrExternalUsers') {
                $parts.Add('Guests/external users')
            }
            elseif ($ResolvedIncludeUsers.Count -gt 0) {
                $parts.Add("$($ResolvedIncludeUsers.Count) user(s)")
            }

            if ($ResolvedIncludeGroups.Count -gt 0) {
                $parts.Add("$($ResolvedIncludeGroups.Count) group(s)")
            }

            if ($ResolvedIncludeRoles.Count -gt 0) {
                $parts.Add("$($ResolvedIncludeRoles.Count) role(s)")
            }

            if ($null -ne $includeGuests) {
                $parts.Add('guests/external')
            }
        }

        # Exclude side
        $excludeParts = New-Object -TypeName 'System.Collections.Generic.List[String]'

        if ($ResolvedExcludeUsers.Count -gt 0) {
            $excludeParts.Add("$($ResolvedExcludeUsers.Count) user(s)")
        }
        if ($ResolvedExcludeGroups.Count -gt 0) {
            $excludeParts.Add("$($ResolvedExcludeGroups.Count) group(s)")
        }
        if ($ResolvedExcludeRoles.Count -gt 0) {
            $excludeParts.Add("$($ResolvedExcludeRoles.Count) role(s)")
        }

        if ($parts.Count -eq 0) {
            return 'No users specified'
        }

        $result = $parts -join ', '
        if ($excludeParts.Count -gt 0) {
            $result += " (excludes $($excludeParts -join ', '))"
        }

        return $result
    }
}

function Format-CAPAppScope {
    <#
    .SYNOPSIS
        Creates a human-readable summary of the application scope.

    .DESCRIPTION
        Analyzes the application conditions and generates a concise description
        of what applications the policy applies to.

    .PARAMETER Applications
        The conditionalAccessApplications object.

    .PARAMETER ResolvedIncludeApps
        Pre-resolved included application names.

    .PARAMETER ResolvedExcludeApps
        Pre-resolved excluded application names.

    .OUTPUTS
        String description of the application scope.

    .NOTES
        Internal function - not exported.
    #>
    [CmdletBinding()]
    [OutputType([String])]
    param(
        [Parameter()]
        [Object]$Applications,

        [Parameter()]
        [Object]$ResolvedIncludeApps,

        [Parameter()]
        [Object]$ResolvedExcludeApps,

        [Parameter()]
        [Object]$ResolvedUserActions,

        [Parameter()]
        [Object]$ResolvedAuthContexts
    )

    process {
        $parts = New-Object -TypeName 'System.Collections.Generic.List[String]'

        $includeApps = $Applications.IncludeApplications
        $userActions = $Applications.IncludeUserActions
        $authContexts = $Applications.IncludeAuthenticationContextClassReferences

        # Check for special values
        if ($includeApps -contains 'All') {
            $parts.Add('All applications')
        }
        elseif ($includeApps -contains 'Office365') {
            $parts.Add('Office 365')
        }
        elseif ($includeApps -contains 'MicrosoftAdminPortals') {
            $parts.Add('Microsoft Admin Portals')
        }
        elseif ($includeApps -contains 'None' -or ($null -eq $includeApps -and $null -eq $userActions -and $null -eq $authContexts)) {
            $parts.Add('No applications')
        }
        else {
            if ($ResolvedIncludeApps.Count -gt 0) {
                $parts.Add("$($ResolvedIncludeApps.Count) application(s)")
            }
        }

        # User actions
        if ($ResolvedUserActions.Count -gt 0) {
            $parts.Add("$($ResolvedUserActions.Count) user action(s)")
        }

        # Auth contexts
        if ($ResolvedAuthContexts.Count -gt 0) {
            $parts.Add("$($ResolvedAuthContexts.Count) auth context(s)")
        }

        # Exclusions
        if ($ResolvedExcludeApps.Count -gt 0) {
            $parts.Add("(excludes $($ResolvedExcludeApps.Count) app(s))")
        }

        # Application filter
        if ($null -ne $Applications.ApplicationFilter -and $null -ne $Applications.ApplicationFilter.Rule) {
            $parts.Add('(with filter)')
        }

        if ($parts.Count -eq 0) {
            return 'No applications specified'
        }

        return $parts -join ' '
    }
}

function Format-CAPGrantControls {
    <#
    .SYNOPSIS
        Creates a human-readable summary of the grant controls.

    .DESCRIPTION
        Analyzes the grant controls and generates a description of what
        controls must be satisfied.

    .PARAMETER GrantControls
        The conditionalAccessGrantControls object.

    .PARAMETER AuthStrengthName
        Pre-resolved authentication strength policy name.

    .OUTPUTS
        String description of the grant controls.

    .NOTES
        Internal function - not exported.
    #>
    [CmdletBinding()]
    [OutputType([String])]
    param(
        [Parameter()]
        [Object]$GrantControls,

        [Parameter()]
        [String]$AuthStrengthName
    )

    process {
        if ($null -eq $GrantControls) {
            return 'No grant controls'
        }

        $controls = New-Object -TypeName 'System.Collections.Generic.List[String]'

        # Map built-in controls to friendly names
        $controlNames = @{
            'block'              = 'Block access'
            'mfa'                = 'MFA'
            'compliantDevice'    = 'Compliant device'
            'domainJoinedDevice' = 'Hybrid Azure AD joined device'
            'approvedApplication' = 'Approved client app'
            'compliantApplication' = 'App protection policy'
            'passwordChange'     = 'Password change'
        }

        foreach ($control in $GrantControls.BuiltInControls) {
            if ($controlNames.ContainsKey($control)) {
                $controls.Add($controlNames[$control])
            }
            else {
                $controls.Add($control)
            }
        }

        # Authentication strength
        if ($AuthStrengthName) {
            $controls.Add("Auth strength: $AuthStrengthName")
        }

        # Terms of use
        if ($GrantControls.TermsOfUse -and $GrantControls.TermsOfUse.Count -gt 0) {
            $controls.Add("$($GrantControls.TermsOfUse.Count) Terms of Use")
        }

        # Custom authentication factors
        if ($GrantControls.CustomAuthenticationFactors -and $GrantControls.CustomAuthenticationFactors.Count -gt 0) {
            $controls.Add("$($GrantControls.CustomAuthenticationFactors.Count) custom factor(s)")
        }

        if ($controls.Count -eq 0) {
            return 'Grant access (no controls)'
        }

        $operator = if ($GrantControls.Operator) { $GrantControls.Operator } else { 'OR' }

        if ($controls.Count -eq 1) {
            return "Require $($controls[0])"
        }

        return "Require $($controls -join " $operator ")"
    }
}

function Format-CAPSessionControls {
    <#
    .SYNOPSIS
        Creates a human-readable summary of the session controls.

    .DESCRIPTION
        Analyzes the session controls and generates a description of what
        session restrictions are applied.

    .PARAMETER SessionControls
        The conditionalAccessSessionControls object.

    .OUTPUTS
        String description of the session controls.

    .NOTES
        Internal function - not exported.
    #>
    [CmdletBinding()]
    [OutputType([String])]
    param(
        [Parameter()]
        [Object]$SessionControls
    )

    process {
        if ($null -eq $SessionControls) {
            return $null
        }

        $parts = New-Object -TypeName 'System.Collections.Generic.List[String]'

        # Sign-in frequency
        $signInFreq = $SessionControls.SignInFrequency
        if ($null -ne $signInFreq -and $signInFreq.IsEnabled -eq $true) {
            if ($signInFreq.FrequencyInterval -eq 'everyTime') {
                $parts.Add('Sign-in: every time')
            }
            elseif ($signInFreq.Value -and $signInFreq.Type) {
                $parts.Add("Sign-in: every $($signInFreq.Value) $($signInFreq.Type)")
            }
            else {
                $parts.Add('Sign-in frequency enabled')
            }
        }

        # Persistent browser
        $persistentBrowser = $SessionControls.PersistentBrowser
        if ($null -ne $persistentBrowser -and $persistentBrowser.IsEnabled -eq $true) {
            $mode = $persistentBrowser.Mode
            if ($mode -eq 'always') {
                $parts.Add('Persistent browser: always')
            }
            elseif ($mode -eq 'never') {
                $parts.Add('Persistent browser: never')
            }
            else {
                $parts.Add('Persistent browser enabled')
            }
        }

        # Cloud App Security
        $cloudAppSec = $SessionControls.CloudAppSecurity
        if ($null -ne $cloudAppSec -and $cloudAppSec.IsEnabled -eq $true) {
            $casType = $cloudAppSec.CloudAppSecurityType
            switch ($casType) {
                'monitorOnly' { $parts.Add('MCAS: monitor only') }
                'blockDownloads' { $parts.Add('MCAS: block downloads') }
                'mcasConfigured' { $parts.Add('MCAS: use app control') }
                default { $parts.Add('Cloud App Security enabled') }
            }
        }

        # App enforced restrictions
        $appRestrictions = $SessionControls.ApplicationEnforcedRestrictions
        if ($null -ne $appRestrictions -and $appRestrictions.IsEnabled -eq $true) {
            $parts.Add('App-enforced restrictions')
        }

        # Disable resilience defaults
        if ($SessionControls.DisableResilienceDefaults -eq $true) {
            $parts.Add('Resilience defaults disabled')
        }

        if ($parts.Count -eq 0) {
            return $null
        }

        return $parts -join '; '
    }
}

function Format-CAPConditions {
    <#
    .SYNOPSIS
        Creates a human-readable summary of additional conditions.

    .DESCRIPTION
        Analyzes the conditions (platforms, client apps, risk levels, etc.)
        and generates a description.

    .PARAMETER Conditions
        The conditionalAccessConditionSet object.

    .OUTPUTS
        String description of the conditions.

    .NOTES
        Internal function - not exported.
    #>
    [CmdletBinding()]
    [OutputType([String])]
    param(
        [Parameter()]
        [Object]$Conditions
    )

    process {
        $parts = New-Object -TypeName 'System.Collections.Generic.List[String]'

        # Platforms
        $platforms = $Conditions.Platforms
        if ($null -ne $platforms) {
            $includePlatforms = $platforms.IncludePlatforms
            $excludePlatforms = $platforms.ExcludePlatforms

            if ($includePlatforms -contains 'all') {
                if ($excludePlatforms -and $excludePlatforms.Count -gt 0) {
                    $parts.Add("All platforms except $($excludePlatforms -join ', ')")
                }
                else {
                    $parts.Add('All platforms')
                }
            }
            elseif ($includePlatforms -and $includePlatforms.Count -gt 0) {
                $parts.Add("Platforms: $($includePlatforms -join ', ')")
            }
        }

        # Client app types
        $clientAppTypes = $Conditions.ClientAppTypes
        if ($clientAppTypes -and $clientAppTypes.Count -gt 0 -and $clientAppTypes -notcontains 'all') {
            $parts.Add("Client apps: $($clientAppTypes -join ', ')")
        }

        # Sign-in risk levels
        $signInRisk = $Conditions.SignInRiskLevels
        if ($signInRisk -and $signInRisk.Count -gt 0) {
            $parts.Add("Sign-in risk: $($signInRisk -join ', ')")
        }

        # User risk levels
        $userRisk = $Conditions.UserRiskLevels
        if ($userRisk -and $userRisk.Count -gt 0) {
            $parts.Add("User risk: $($userRisk -join ', ')")
        }

        # Service principal risk levels
        $spRisk = $Conditions.ServicePrincipalRiskLevels
        if ($spRisk -and $spRisk.Count -gt 0) {
            $parts.Add("SP risk: $($spRisk -join ', ')")
        }

        # Insider risk
        $insiderRisk = $Conditions.InsiderRiskLevels
        if ($null -ne $insiderRisk) {
            $parts.Add("Insider risk: $insiderRisk")
        }

        # Device filter
        $devices = $Conditions.Devices
        if ($null -ne $devices -and $null -ne $devices.DeviceFilter) {
            $mode = $devices.DeviceFilter.Mode
            $parts.Add("Device filter ($mode)")
        }

        if ($parts.Count -eq 0) {
            return $null
        }

        return $parts -join '; '
    }
}
