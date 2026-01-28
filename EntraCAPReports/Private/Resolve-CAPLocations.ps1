function Resolve-CAPLocations {
    <#
    .SYNOPSIS
        Resolves named location GUIDs to display names with IP/country details.

    .DESCRIPTION
        Takes an array of location IDs from a Conditional Access policy and resolves
        them to human-readable names. Handles special values like 'All' and 'AllTrusted'.
        Pre-fetches all named locations on first call for efficiency.

        For IP named locations, captures all IP ranges (IPv4/IPv6 CIDR).
        For country named locations, captures all country codes.
        Both types capture the IsTrusted status.

    .PARAMETER LocationIds
        Array of location IDs to resolve.

    .OUTPUTS
        PSCustomObject with ResolvedNames (semicolon-separated string), Details (array),
        and ExpandedDetails (array with one entry per IP range or country).

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
                ResolvedNames   = $null
                Details         = @()
                ExpandedDetails = @()
                Count           = 0
            }
        }

        # Initialize location cache if needed
        if ($script:LocationCache.Count -eq 0) {
            Write-Verbose -Message 'Initializing named location cache...'
            try {
                $locations = Get-MgIdentityConditionalAccessNamedLocation -All -ErrorAction Stop
                foreach ($loc in $locations) {
                    $locationType = 'Unknown'
                    $ipRanges = @()
                    $countries = @()
                    $isTrusted = $null
                    $includeUnknownCountries = $null

                    if ($loc.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.ipNamedLocation') {
                        $locationType = 'IP'
                        $isTrusted = $loc.AdditionalProperties.isTrusted

                        # Extract IP ranges
                        if ($loc.AdditionalProperties.ipRanges) {
                            foreach ($range in $loc.AdditionalProperties.ipRanges) {
                                $ipRanges += [PSCustomObject]@{
                                    CidrAddress = $range.cidrAddress
                                    Type        = if ($range.'@odata.type' -like '*iPv6*') { 'IPv6' } else { 'IPv4' }
                                }
                            }
                        }
                    }
                    elseif ($loc.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.countryNamedLocation') {
                        $locationType = 'Country'
                        # Country locations don't have isTrusted - only IP locations do
                        $isTrusted = $null

                        # Extract countries
                        if ($loc.AdditionalProperties.countriesAndRegions) {
                            $countries = @($loc.AdditionalProperties.countriesAndRegions)
                        }
                        $includeUnknownCountries = $loc.AdditionalProperties.includeUnknownCountriesAndRegions
                    }

                    $script:LocationCache.Add($loc.Id, [PSCustomObject]@{
                        Id                       = $loc.Id
                        DisplayName              = $loc.DisplayName
                        Type                     = $locationType
                        IsTrusted                = $isTrusted
                        IpRanges                 = $ipRanges
                        Countries                = $countries
                        IncludeUnknownCountries  = $includeUnknownCountries
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
        $expandedDetails = New-Object -TypeName 'System.Collections.Generic.List[PSCustomObject]'

        foreach ($locationId in $LocationIds) {
            $resolvedName = $null
            $locationType = $null
            $isTrusted = $null
            $ipRanges = @()
            $countries = @()
            $includeUnknownCountries = $null

            # Handle special values
            switch ($locationId) {
                'All' {
                    $resolvedName = 'All locations'
                    $locationType = 'Special'
                    # Add single expanded entry for special values
                    $expandedDetails.Add([PSCustomObject]@{
                        LocationId      = $locationId
                        LocationName    = $resolvedName
                        LocationType    = $locationType
                        IsTrusted       = $null
                        Value           = 'All locations'
                        ValueType       = 'Special'
                    })
                }
                'AllTrusted' {
                    $resolvedName = 'All trusted locations'
                    $locationType = 'Special'
                    $isTrusted = $true
                    $expandedDetails.Add([PSCustomObject]@{
                        LocationId      = $locationId
                        LocationName    = $resolvedName
                        LocationType    = $locationType
                        IsTrusted       = $true
                        Value           = 'All trusted locations'
                        ValueType       = 'Special'
                    })
                }
                '00000000-0000-0000-0000-000000000000' {
                    $resolvedName = 'Unknown location'
                    $locationType = 'Special'
                    $expandedDetails.Add([PSCustomObject]@{
                        LocationId      = $locationId
                        LocationName    = $resolvedName
                        LocationType    = $locationType
                        IsTrusted       = $null
                        Value           = 'Unknown location'
                        ValueType       = 'Special'
                    })
                }
                default {
                    # Look up in cache
                    if ($script:LocationCache.ContainsKey($locationId)) {
                        $cached = $script:LocationCache[$locationId]
                        $resolvedName = $cached.DisplayName
                        $locationType = $cached.Type
                        $isTrusted = $cached.IsTrusted
                        $ipRanges = $cached.IpRanges
                        $countries = $cached.Countries
                        $includeUnknownCountries = $cached.IncludeUnknownCountries

                        # Create expanded entries for each IP range or country
                        if ($locationType -eq 'IP' -and $ipRanges.Count -gt 0) {
                            foreach ($range in $ipRanges) {
                                $expandedDetails.Add([PSCustomObject]@{
                                    LocationId      = $locationId
                                    LocationName    = $resolvedName
                                    LocationType    = $locationType
                                    IsTrusted       = $isTrusted
                                    Value           = $range.CidrAddress
                                    ValueType       = $range.Type
                                })
                            }
                        }
                        elseif ($locationType -eq 'Country' -and $countries.Count -gt 0) {
                            foreach ($country in $countries) {
                                $expandedDetails.Add([PSCustomObject]@{
                                    LocationId      = $locationId
                                    LocationName    = $resolvedName
                                    LocationType    = $locationType
                                    IsTrusted       = $isTrusted
                                    Value           = $country
                                    ValueType       = 'CountryCode'
                                })
                            }
                            # Add entry for unknown countries if enabled
                            if ($includeUnknownCountries) {
                                $expandedDetails.Add([PSCustomObject]@{
                                    LocationId      = $locationId
                                    LocationName    = $resolvedName
                                    LocationType    = $locationType
                                    IsTrusted       = $isTrusted
                                    Value           = '(Unknown countries/regions)'
                                    ValueType       = 'UnknownCountries'
                                })
                            }
                        }
                        else {
                            # No IP ranges or countries found, add single entry
                            $expandedDetails.Add([PSCustomObject]@{
                                LocationId      = $locationId
                                LocationName    = $resolvedName
                                LocationType    = $locationType
                                IsTrusted       = $isTrusted
                                Value           = $resolvedName
                                ValueType       = $locationType
                            })
                        }
                    }
                    else {
                        $resolvedName = $locationId
                        $locationType = 'Unknown'
                        $expandedDetails.Add([PSCustomObject]@{
                            LocationId      = $locationId
                            LocationName    = $resolvedName
                            LocationType    = $locationType
                            IsTrusted       = $null
                            Value           = $locationId
                            ValueType       = 'Unknown'
                        })
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
            ResolvedNames   = $resolvedNames -join '; '
            Details         = $details.ToArray()
            ExpandedDetails = $expandedDetails.ToArray()
            Count           = $details.Count
        }
    }
}
