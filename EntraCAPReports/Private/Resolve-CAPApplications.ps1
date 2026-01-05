function Resolve-CAPApplications {
    <#
    .SYNOPSIS
        Resolves application IDs to display names.

    .DESCRIPTION
        Takes an array of application IDs (appId) from a Conditional Access policy and
        resolves them to human-readable names. Uses a static list of well-known Microsoft
        app IDs and falls back to Graph API lookup for custom applications.

    .PARAMETER ApplicationIds
        Array of application IDs to resolve.

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
        [String[]]$ApplicationIds
    )

    process {
        # Handle null or empty
        if ($null -eq $ApplicationIds -or $ApplicationIds.Count -eq 0) {
            return [PSCustomObject]@{
                ResolvedNames = $null
                Details       = @()
                Count         = 0
            }
        }

        $resolvedNames = New-Object -TypeName 'System.Collections.Generic.List[String]'
        $details = New-Object -TypeName 'System.Collections.Generic.List[PSCustomObject]'

        foreach ($appId in $ApplicationIds) {
            $resolvedName = $null
            $appType = 'Application'

            # Handle special values
            switch ($appId) {
                'All' {
                    $resolvedName = 'All applications'
                    $appType = 'Special'
                }
                'None' {
                    $resolvedName = 'None'
                    $appType = 'Special'
                }
                'Office365' {
                    $resolvedName = 'Office 365 (Exchange, SharePoint, Teams, etc.)'
                    $appType = 'AppSuite'
                }
                'MicrosoftAdminPortals' {
                    $resolvedName = 'Microsoft Admin Portals'
                    $appType = 'AppSuite'
                }
                default {
                    # Check cache first
                    if ($script:AppCache.ContainsKey($appId)) {
                        $cached = $script:AppCache[$appId]
                        $resolvedName = $cached.DisplayName
                        $appType = $cached.Type
                    }
                    # Check well-known app IDs
                    elseif ($script:KnownAppIds.ContainsKey($appId)) {
                        $resolvedName = $script:KnownAppIds[$appId]
                        $appType = 'MicrosoftFirstParty'

                        # Cache for future lookups
                        $script:AppCache.Add($appId, [PSCustomObject]@{
                            Id          = $appId
                            DisplayName = $resolvedName
                            Type        = $appType
                        })
                    }
                    else {
                        # Try to look up via Graph API
                        try {
                            $sp = Get-MgServicePrincipal -Filter "appId eq '$appId'" -Top 1 -ErrorAction Stop
                            if ($sp) {
                                $resolvedName = $sp.DisplayName
                                $appType = if ($sp.AppOwnerOrganizationId -eq 'f8cdef31-a31e-4b4a-93e4-5f571e91255a') {
                                    'MicrosoftFirstParty'
                                }
                                else {
                                    'Application'
                                }

                                # Cache for future lookups
                                $script:AppCache.Add($appId, [PSCustomObject]@{
                                    Id          = $appId
                                    DisplayName = $resolvedName
                                    Type        = $appType
                                })
                            }
                            else {
                                $resolvedName = $appId
                                $appType = 'Unknown'
                            }
                        }
                        catch {
                            Write-Verbose -Message "Failed to resolve application $appId : $PSItem"
                            $resolvedName = $appId
                            $appType = 'Unknown'
                        }
                    }
                }
            }

            $resolvedNames.Add($resolvedName)
            $details.Add([PSCustomObject]@{
                Id          = $appId
                DisplayName = $resolvedName
                Type        = $appType
            })
        }

        return [PSCustomObject]@{
            ResolvedNames = $resolvedNames -join '; '
            Details       = $details.ToArray()
            Count         = $details.Count
        }
    }
}

function Resolve-CAPUserActions {
    <#
    .SYNOPSIS
        Resolves user action URNs to display names.

    .DESCRIPTION
        Takes an array of user action URNs and resolves them to human-readable names.

    .PARAMETER UserActions
        Array of user action URNs to resolve.

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
        [String[]]$UserActions
    )

    process {
        if ($null -eq $UserActions -or $UserActions.Count -eq 0) {
            return [PSCustomObject]@{
                ResolvedNames = $null
                Details       = @()
                Count         = 0
            }
        }

        $resolvedNames = New-Object -TypeName 'System.Collections.Generic.List[String]'
        $details = New-Object -TypeName 'System.Collections.Generic.List[PSCustomObject]'

        foreach ($action in $UserActions) {
            $resolvedName = switch ($action) {
                'urn:user:registersecurityinfo' { 'Register security information' }
                'urn:user:registerdevice' { 'Register or join devices' }
                default { $action }
            }

            $resolvedNames.Add($resolvedName)
            $details.Add([PSCustomObject]@{
                Id          = $action
                DisplayName = $resolvedName
                Type        = 'UserAction'
            })
        }

        return [PSCustomObject]@{
            ResolvedNames = $resolvedNames -join '; '
            Details       = $details.ToArray()
            Count         = $details.Count
        }
    }
}

function Resolve-CAPAuthContexts {
    <#
    .SYNOPSIS
        Resolves authentication context class reference IDs to display names.

    .DESCRIPTION
        Takes an array of authentication context IDs (c1-c25) and resolves them
        to their configured display names.

    .PARAMETER AuthContextIds
        Array of authentication context IDs to resolve.

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
        [String[]]$AuthContextIds
    )

    process {
        if ($null -eq $AuthContextIds -or $AuthContextIds.Count -eq 0) {
            return [PSCustomObject]@{
                ResolvedNames = $null
                Details       = @()
                Count         = 0
            }
        }

        # Initialize auth context cache if needed
        if ($script:AuthContextCache.Count -eq 0) {
            Write-Verbose -Message 'Initializing authentication context cache...'
            try {
                $authContexts = Get-MgIdentityConditionalAccessAuthenticationContextClassReference -All -ErrorAction Stop
                foreach ($ctx in $authContexts) {
                    $script:AuthContextCache.Add($ctx.Id, [PSCustomObject]@{
                        Id          = $ctx.Id
                        DisplayName = $ctx.DisplayName
                        Description = $ctx.Description
                        IsAvailable = $ctx.IsAvailable
                    })
                }
                Write-Verbose -Message "Cached $($script:AuthContextCache.Count) authentication context(s)"
            }
            catch {
                Write-Warning -Message "Failed to retrieve authentication contexts: $PSItem"
            }
        }

        $resolvedNames = New-Object -TypeName 'System.Collections.Generic.List[String]'
        $details = New-Object -TypeName 'System.Collections.Generic.List[PSCustomObject]'

        foreach ($contextId in $AuthContextIds) {
            $resolvedName = $null

            if ($script:AuthContextCache.ContainsKey($contextId)) {
                $cached = $script:AuthContextCache[$contextId]
                $resolvedName = $cached.DisplayName
            }
            else {
                $resolvedName = "Auth Context: $contextId"
            }

            $resolvedNames.Add($resolvedName)
            $details.Add([PSCustomObject]@{
                Id          = $contextId
                DisplayName = $resolvedName
                Type        = 'AuthenticationContext'
            })
        }

        return [PSCustomObject]@{
            ResolvedNames = $resolvedNames -join '; '
            Details       = $details.ToArray()
            Count         = $details.Count
        }
    }
}
