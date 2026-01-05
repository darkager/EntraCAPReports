function Resolve-CAPUsers {
    <#
    .SYNOPSIS
        Resolves user IDs to display names.

    .DESCRIPTION
        Takes an array of user IDs from a Conditional Access policy and resolves
        them to human-readable names. Handles special values like 'All', 'None',
        and 'GuestsOrExternalUsers'.

    .PARAMETER UserIds
        Array of user IDs to resolve.

    .OUTPUTS
        PSCustomObject with ResolvedNames (semicolon-separated string) and Details (array).

    .NOTES
        Internal function - not exported.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyCollection()]
        [String[]]$UserIds
    )

    process {
        if ($null -eq $UserIds -or $UserIds.Count -eq 0) {
            return [PSCustomObject]@{
                ResolvedNames = $null
                Details       = @()
                Count         = 0
            }
        }

        $resolvedNames = New-Object -TypeName 'System.Collections.Generic.List[String]'
        $details = New-Object -TypeName 'System.Collections.Generic.List[PSCustomObject]'

        foreach ($userId in $UserIds) {
            $resolvedName = $null
            $userType = 'User'

            # Handle special values
            switch ($userId) {
                'All' {
                    $resolvedName = 'All users'
                    $userType = 'Special'
                }
                'None' {
                    $resolvedName = 'None'
                    $userType = 'Special'
                }
                'GuestsOrExternalUsers' {
                    $resolvedName = 'All guests and external users'
                    $userType = 'Special'
                }
                default {
                    # Check cache first
                    if ($script:UserCache.ContainsKey($userId)) {
                        $cached = $script:UserCache[$userId]
                        $resolvedName = $cached.DisplayName
                        $userType = $cached.Type
                    }
                    else {
                        # Try to look up via Graph API
                        try {
                            $user = Get-MgUser -UserId $userId -Property Id, DisplayName, UserPrincipalName -ErrorAction Stop
                            $resolvedName = if ($user.UserPrincipalName) { $user.UserPrincipalName } else { $user.DisplayName }
                            $userType = 'User'

                            # Cache for future lookups
                            $script:UserCache.Add($userId, [PSCustomObject]@{
                                Id                = $userId
                                DisplayName       = $resolvedName
                                UserPrincipalName = $user.UserPrincipalName
                                Type              = $userType
                            })
                        }
                        catch {
                            Write-Verbose -Message "Failed to resolve user $userId : $PSItem"
                            $resolvedName = $userId
                            $userType = 'Unknown'
                        }
                    }
                }
            }

            $resolvedNames.Add($resolvedName)
            $details.Add([PSCustomObject]@{
                Id          = $userId
                DisplayName = $resolvedName
                Type        = $userType
            })
        }

        return [PSCustomObject]@{
            ResolvedNames = $resolvedNames -join '; '
            Details       = $details.ToArray()
            Count         = $details.Count
        }
    }
}

function Resolve-CAPGroups {
    <#
    .SYNOPSIS
        Resolves group IDs to display names.

    .DESCRIPTION
        Takes an array of group IDs from a Conditional Access policy and resolves
        them to human-readable names.

    .PARAMETER GroupIds
        Array of group IDs to resolve.

    .OUTPUTS
        PSCustomObject with ResolvedNames (semicolon-separated string) and Details (array).

    .NOTES
        Internal function - not exported.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyCollection()]
        [String[]]$GroupIds
    )

    process {
        if ($null -eq $GroupIds -or $GroupIds.Count -eq 0) {
            return [PSCustomObject]@{
                ResolvedNames = $null
                Details       = @()
                Count         = 0
            }
        }

        $resolvedNames = New-Object -TypeName 'System.Collections.Generic.List[String]'
        $details = New-Object -TypeName 'System.Collections.Generic.List[PSCustomObject]'

        foreach ($groupId in $GroupIds) {
            $resolvedName = $null
            $groupType = 'Group'

            # Check cache first
            if ($script:GroupCache.ContainsKey($groupId)) {
                $cached = $script:GroupCache[$groupId]
                $resolvedName = $cached.DisplayName
                $groupType = $cached.Type
            }
            else {
                # Try to look up via Graph API
                try {
                    $group = Get-MgGroup -GroupId $groupId -Property Id, DisplayName, GroupTypes -ErrorAction Stop
                    $resolvedName = $group.DisplayName

                    # Determine group type
                    if ($group.GroupTypes -contains 'Unified') {
                        $groupType = 'M365Group'
                    }
                    else {
                        $groupType = 'SecurityGroup'
                    }

                    # Cache for future lookups
                    $script:GroupCache.Add($groupId, [PSCustomObject]@{
                        Id          = $groupId
                        DisplayName = $resolvedName
                        Type        = $groupType
                    })
                }
                catch {
                    Write-Verbose -Message "Failed to resolve group $groupId : $PSItem"
                    $resolvedName = $groupId
                    $groupType = 'Unknown'
                }
            }

            $resolvedNames.Add($resolvedName)
            $details.Add([PSCustomObject]@{
                Id          = $groupId
                DisplayName = $resolvedName
                Type        = $groupType
            })
        }

        return [PSCustomObject]@{
            ResolvedNames = $resolvedNames -join '; '
            Details       = $details.ToArray()
            Count         = $details.Count
        }
    }
}

function Resolve-CAPRoles {
    <#
    .SYNOPSIS
        Resolves directory role IDs to display names.

    .DESCRIPTION
        Takes an array of directory role template IDs from a Conditional Access policy
        and resolves them to human-readable names. Uses well-known role IDs and falls
        back to Graph API lookup.

    .PARAMETER RoleIds
        Array of role template IDs to resolve.

    .OUTPUTS
        PSCustomObject with ResolvedNames (semicolon-separated string) and Details (array).

    .NOTES
        Internal function - not exported.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyCollection()]
        [String[]]$RoleIds
    )

    process {
        if ($null -eq $RoleIds -or $RoleIds.Count -eq 0) {
            return [PSCustomObject]@{
                ResolvedNames = $null
                Details       = @()
                Count         = 0
            }
        }

        # Initialize role cache if needed (pre-fetch all role definitions)
        if ($script:RoleCache.Count -eq 0) {
            Write-Verbose -Message 'Initializing directory role cache...'
            try {
                $roles = Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction Stop
                foreach ($role in $roles) {
                    $script:RoleCache.Add($role.Id, [PSCustomObject]@{
                        Id          = $role.Id
                        DisplayName = $role.DisplayName
                        IsBuiltIn   = $role.IsBuiltIn
                    })
                }
                Write-Verbose -Message "Cached $($script:RoleCache.Count) directory role(s)"
            }
            catch {
                Write-Warning -Message "Failed to retrieve directory roles: $PSItem"
            }
        }

        $resolvedNames = New-Object -TypeName 'System.Collections.Generic.List[String]'
        $details = New-Object -TypeName 'System.Collections.Generic.List[PSCustomObject]'

        foreach ($roleId in $RoleIds) {
            $resolvedName = $null
            $isBuiltIn = $null

            # Check cache first
            if ($script:RoleCache.ContainsKey($roleId)) {
                $cached = $script:RoleCache[$roleId]
                $resolvedName = $cached.DisplayName
                $isBuiltIn = $cached.IsBuiltIn
            }
            # Check well-known role template IDs
            elseif ($script:KnownRoleTemplateIds.ContainsKey($roleId)) {
                $resolvedName = $script:KnownRoleTemplateIds[$roleId]
                $isBuiltIn = $true
            }
            else {
                $resolvedName = $roleId
                $isBuiltIn = $null
            }

            $resolvedNames.Add($resolvedName)
            $details.Add([PSCustomObject]@{
                Id          = $roleId
                DisplayName = $resolvedName
                Type        = 'DirectoryRole'
                IsBuiltIn   = $isBuiltIn
            })
        }

        return [PSCustomObject]@{
            ResolvedNames = $resolvedNames -join '; '
            Details       = $details.ToArray()
            Count         = $details.Count
        }
    }
}

function Resolve-CAPGuestsOrExternalUsers {
    <#
    .SYNOPSIS
        Formats guest/external user settings to human-readable description.

    .DESCRIPTION
        Takes a conditionalAccessGuestsOrExternalUsers object and formats it
        to a human-readable description.

    .PARAMETER GuestSettings
        The conditionalAccessGuestsOrExternalUsers object.

    .OUTPUTS
        PSCustomObject with Description and Details.

    .NOTES
        Internal function - not exported.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter()]
        [AllowNull()]
        [Object]$GuestSettings
    )

    process {
        if ($null -eq $GuestSettings) {
            return [PSCustomObject]@{
                Description = $null
                Details     = $null
            }
        }

        $parts = New-Object -TypeName 'System.Collections.Generic.List[String]'

        # Guest or external user types
        $guestTypes = $GuestSettings.GuestOrExternalUserTypes
        if ($guestTypes) {
            # This is a flags enum, can contain multiple values
            $typeDescriptions = @{
                'none'                           = 'None'
                'internalGuest'                  = 'Internal guests'
                'b2bCollaborationGuest'          = 'B2B collaboration guests'
                'b2bCollaborationMember'         = 'B2B collaboration members'
                'b2bDirectConnectUser'           = 'B2B direct connect users'
                'otherExternalUser'              = 'Other external users'
                'serviceProvider'                = 'Service providers'
                'unknownFutureValue'             = 'Unknown'
            }

            foreach ($type in $guestTypes -split ',') {
                $trimmedType = $type.Trim()
                if ($typeDescriptions.ContainsKey($trimmedType)) {
                    $parts.Add($typeDescriptions[$trimmedType])
                }
                else {
                    $parts.Add($trimmedType)
                }
            }
        }

        # External tenants
        $externalTenants = $GuestSettings.ExternalTenants
        if ($externalTenants) {
            $membershipKind = $externalTenants.AdditionalProperties.'@odata.type'
            if ($membershipKind -eq '#microsoft.graph.conditionalAccessAllExternalTenants') {
                $parts.Add('from all external tenants')
            }
            elseif ($membershipKind -eq '#microsoft.graph.conditionalAccessEnumeratedExternalTenants') {
                $tenantIds = $externalTenants.AdditionalProperties.members
                if ($tenantIds) {
                    $parts.Add("from $($tenantIds.Count) specific tenant(s)")
                }
            }
        }

        $description = if ($parts.Count -gt 0) { $parts -join ', ' } else { $null }

        return [PSCustomObject]@{
            Description = $description
            Details     = $GuestSettings
        }
    }
}
