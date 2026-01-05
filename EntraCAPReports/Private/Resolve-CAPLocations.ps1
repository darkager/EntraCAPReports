function Resolve-CAPLocations {
    <#
    .SYNOPSIS
        Resolves named location GUIDs to display names.

    .DESCRIPTION
        Takes an array of location IDs from a Conditional Access policy and resolves
        them to human-readable names. Handles special values like 'All' and 'AllTrusted'.
        Pre-fetches all named locations on first call for efficiency.

    .PARAMETER LocationIds
        Array of location IDs to resolve.

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
        [String[]]$LocationIds
    )

    process {
        # Handle null or empty
        if ($null -eq $LocationIds -or $LocationIds.Count -eq 0) {
            return [PSCustomObject]@{
                ResolvedNames = $null
                Details       = @()
                Count         = 0
            }
        }

        # Initialize location cache if needed
        if ($script:LocationCache.Count -eq 0) {
            Write-Verbose -Message 'Initializing named location cache...'
            try {
                $locations = Get-MgIdentityConditionalAccessNamedLocation -All -ErrorAction Stop
                foreach ($loc in $locations) {
                    $locationType = 'Unknown'
                    if ($loc.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.ipNamedLocation') {
                        $locationType = 'IP'
                    }
                    elseif ($loc.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.countryNamedLocation') {
                        $locationType = 'Country'
                    }

                    $script:LocationCache.Add($loc.Id, [PSCustomObject]@{
                        Id          = $loc.Id
                        DisplayName = $loc.DisplayName
                        Type        = $locationType
                        IsTrusted   = $loc.AdditionalProperties.isTrusted
                    })
                }
                Write-Verbose -Message "Cached $($script:LocationCache.Count) named location(s)"
            }
            catch {
                Write-Warning -Message "Failed to retrieve named locations: $PSItem"
            }
        }

        $resolvedNames = New-Object -TypeName 'System.Collections.Generic.List[String]'
        $details = New-Object -TypeName 'System.Collections.Generic.List[PSCustomObject]'

        foreach ($locationId in $LocationIds) {
            $resolvedName = $null
            $locationType = $null
            $isTrusted = $null

            # Handle special values
            switch ($locationId) {
                'All' {
                    $resolvedName = 'All locations'
                    $locationType = 'Special'
                }
                'AllTrusted' {
                    $resolvedName = 'All trusted locations'
                    $locationType = 'Special'
                    $isTrusted = $true
                }
                '00000000-0000-0000-0000-000000000000' {
                    $resolvedName = 'Unknown location'
                    $locationType = 'Special'
                }
                default {
                    # Look up in cache
                    if ($script:LocationCache.ContainsKey($locationId)) {
                        $cached = $script:LocationCache[$locationId]
                        $resolvedName = $cached.DisplayName
                        $locationType = $cached.Type
                        $isTrusted = $cached.IsTrusted
                    }
                    else {
                        $resolvedName = $locationId
                        $locationType = 'Unknown'
                    }
                }
            }

            $resolvedNames.Add($resolvedName)
            $details.Add([PSCustomObject]@{
                Id          = $locationId
                DisplayName = $resolvedName
                Type        = $locationType
                IsTrusted   = $isTrusted
            })
        }

        return [PSCustomObject]@{
            ResolvedNames = $resolvedNames -join '; '
            Details       = $details.ToArray()
            Count         = $details.Count
        }
    }
}
