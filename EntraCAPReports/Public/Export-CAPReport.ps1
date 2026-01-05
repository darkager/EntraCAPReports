function Export-CAPReport {
    <#
    .SYNOPSIS
        Exports Conditional Access Policy reports to CSV.

    .DESCRIPTION
        Generates comprehensive CSV reports for Conditional Access Policies:
        1. Summary Report (*-Summary.csv): One row per policy with key metrics
        2. Detail Report (*-Detail.csv): Flattened view with one row per condition value

        The detail report can be generated in two modes:
        - Default: One row per unique value (best for Excel filtering/pivoting)
        - Flatten: One row per category with semicolon-separated values (compact)

    .PARAMETER OutputPath
        Base path for the CSV outputs. The function appends '-Summary.csv' and '-Detail.csv'.
        If not specified, outputs to CAPReport_<timestamp> in the current directory.
        If a directory is specified, uses that directory with auto-generated filename.

    .PARAMETER PolicyId
        Optional array of specific policy IDs to include.

    .PARAMETER StateFilter
        Filter policies by state. Default is 'All'.
        Values: All, Enabled, Disabled, ReportOnly

    .PARAMETER Flatten
        If specified, generates compact detail report with one row per category
        and semicolon-separated values instead of one row per value.

    .PARAMETER IncludeRawData
        If specified, includes raw ID columns in addition to resolved names.

    .PARAMETER PassThru
        If specified, returns the policy objects in addition to exporting CSV.

    .EXAMPLE
        Export-CAPReport

        Exports all policies to timestamped CSV files in current directory.

    .EXAMPLE
        Export-CAPReport -OutputPath 'C:\Reports\CAP'

        Exports to C:\Reports\CAP-Summary.csv and C:\Reports\CAP-Detail.csv

    .EXAMPLE
        Export-CAPReport -StateFilter Enabled -Flatten

        Exports only enabled policies with compact detail format.

    .EXAMPLE
        $policies = Export-CAPReport -PassThru
        $policies | Where-Object { $PSItem.Classification -eq 'BlockPolicy' }

        Exports and returns policies for further filtering.

    .OUTPUTS
        PSCustomObject with SummaryReport and DetailReport FileInfo properties.
        If -PassThru is specified, also returns the policy objects.

    .NOTES
        Requires Microsoft.Graph.Identity.SignIns module and Policy.Read.All permission.
        For name resolution, also requires Directory.Read.All and Application.Read.All.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter()]
        [String]$OutputPath,

        [Parameter()]
        [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
        [String[]]$PolicyId,

        [Parameter()]
        [ValidateSet('All', 'Enabled', 'Disabled', 'ReportOnly')]
        [String]$StateFilter = 'All',

        [Parameter()]
        [Switch]$Flatten,

        [Parameter()]
        [Switch]$IncludeRawData,

        [Parameter()]
        [Switch]$PassThru
    )

    begin {
        Write-Verbose -Message 'Starting Export-CAPReport'

        # Generate output paths
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        if (-not $OutputPath) {
            $basePath = Join-Path -Path (Get-Location) -ChildPath "CAPReport_$timestamp"
        }
        elseif (Test-Path -Path $OutputPath -PathType Container) {
            $basePath = Join-Path -Path $OutputPath -ChildPath "CAPReport_$timestamp"
        }
        else {
            # Remove any extension if provided
            $basePath = $OutputPath -replace '\.(csv|xlsx?)$', ''
        }

        $summaryPath = "$basePath-Summary.csv"
        $detailPath = "$basePath-Detail.csv"

        # Ensure directory exists
        $outputDir = Split-Path -Path $summaryPath -Parent
        if ($outputDir -and -not (Test-Path -Path $outputDir)) {
            New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
        }

        $summaryData = New-Object -TypeName 'System.Collections.Generic.List[PSCustomObject]'
        $detailData = New-Object -TypeName 'System.Collections.Generic.List[PSCustomObject]'

        # Progress tracking
        $parentProgressId = 0
    }

    process {
        try {
            # Step 1: Retrieve policies
            Write-Progress -Id $parentProgressId -Activity 'Exporting CAP Report' `
                -Status '[1/3] Retrieving Conditional Access Policies' `
                -PercentComplete 0

            $getParams = @{
                ProgressParentId = $parentProgressId
            }
            if ($PolicyId) {
                $getParams['PolicyId'] = $PolicyId
            }
            $policies = Get-ConditionalAccessPolicy @getParams

            # Apply state filter
            if ($StateFilter -ne 'All') {
                $stateValue = switch ($StateFilter) {
                    'Enabled' { 'enabled' }
                    'Disabled' { 'disabled' }
                    'ReportOnly' { 'enabledForReportingButNotEnforced' }
                }
                $policies = $policies | Where-Object -FilterScript { $PSItem.State -eq $stateValue }
            }

            $policyCount = @($policies).Count
            Write-Verbose -Message "Processing $policyCount policies after filter"

            if ($policyCount -eq 0) {
                Write-Warning -Message 'No policies found matching the specified criteria.'
                Write-Progress -Id $parentProgressId -Activity 'Exporting CAP Report' -Completed
                return
            }

            # Step 2: Build summary and detail data
            Write-Progress -Id $parentProgressId -Activity 'Exporting CAP Report' `
                -Status '[2/3] Processing policy data' `
                -PercentComplete 33

            $processedCount = 0
            foreach ($policy in $policies) {
                $processedCount++

                # Summary row - DisplayName first, PolicyId near the end
                $summaryRow = [PSCustomObject]@{
                    DisplayName             = $policy.DisplayName
                    State                   = $policy.State
                    Classification          = $policy.Classification
                    AllClassifications      = $policy.AllClassifications
                    UserScope               = $policy.UserScopeDescription
                    AppScope                = $policy.AppScopeDescription
                    HasLocationConditions   = [Bool]($policy.IncludedLocations -or $policy.ExcludedLocations)
                    HasPlatformConditions   = [Bool]($policy.IncludedPlatforms -or $policy.ExcludedPlatforms)
                    HasRiskConditions       = [Bool]($policy.SignInRiskLevels -or $policy.UserRiskLevels -or $policy.ServicePrincipalRiskLevels)
                    HasDeviceFilter         = [Bool]$policy.DeviceFilterRule
                    GrantControls           = $policy.GrantDescription
                    SessionControls         = $policy.SessionDescription
                    CreatedDateTime         = $policy.CreatedDateTime
                    ModifiedDateTime        = $policy.ModifiedDateTime
                    PolicyId                = $policy.PolicyId
                }

                if ($IncludeRawData) {
                    $summaryRow | Add-Member -NotePropertyName 'IncludedUserIds' -NotePropertyValue $policy.IncludedUserIds
                    $summaryRow | Add-Member -NotePropertyName 'IncludedGroupIds' -NotePropertyValue $policy.IncludedGroupIds
                    $summaryRow | Add-Member -NotePropertyName 'IncludedRoleIds' -NotePropertyValue $policy.IncludedRoleIds
                    $summaryRow | Add-Member -NotePropertyName 'IncludedApplicationIds' -NotePropertyValue $policy.IncludedApplicationIds
                }

                $summaryData.Add($summaryRow)

                # Detail rows
                if ($Flatten) {
                    # Compact mode: One row per category
                    $categories = @(
                        @{ Category = 'Users'; Type = 'IncludeUsers'; Direction = 'Include'; Value = $policy.IncludedUsers; RawValue = $policy.IncludedUserIds }
                        @{ Category = 'Users'; Type = 'ExcludeUsers'; Direction = 'Exclude'; Value = $policy.ExcludedUsers; RawValue = $policy.ExcludedUserIds }
                        @{ Category = 'Users'; Type = 'IncludeGroups'; Direction = 'Include'; Value = $policy.IncludedGroups; RawValue = $policy.IncludedGroupIds }
                        @{ Category = 'Users'; Type = 'ExcludeGroups'; Direction = 'Exclude'; Value = $policy.ExcludedGroups; RawValue = $policy.ExcludedGroupIds }
                        @{ Category = 'Users'; Type = 'IncludeRoles'; Direction = 'Include'; Value = $policy.IncludedRoles; RawValue = $policy.IncludedRoleIds }
                        @{ Category = 'Users'; Type = 'ExcludeRoles'; Direction = 'Exclude'; Value = $policy.ExcludedRoles; RawValue = $policy.ExcludedRoleIds }
                        @{ Category = 'Users'; Type = 'IncludeGuestsOrExternalUsers'; Direction = 'Include'; Value = $policy.IncludedGuestsOrExternalUsers; RawValue = $null }
                        @{ Category = 'Users'; Type = 'ExcludeGuestsOrExternalUsers'; Direction = 'Exclude'; Value = $policy.ExcludedGuestsOrExternalUsers; RawValue = $null }
                        @{ Category = 'Applications'; Type = 'IncludeApplications'; Direction = 'Include'; Value = $policy.IncludedApplications; RawValue = $policy.IncludedApplicationIds }
                        @{ Category = 'Applications'; Type = 'ExcludeApplications'; Direction = 'Exclude'; Value = $policy.ExcludedApplications; RawValue = $policy.ExcludedApplicationIds }
                        @{ Category = 'Applications'; Type = 'UserActions'; Direction = 'Include'; Value = $policy.IncludedUserActions; RawValue = $null }
                        @{ Category = 'Applications'; Type = 'AuthContexts'; Direction = 'Include'; Value = $policy.IncludedAuthContexts; RawValue = $null }
                        @{ Category = 'Conditions'; Type = 'Locations'; Direction = 'Include'; Value = $policy.IncludedLocations; RawValue = $policy.IncludedLocationIds }
                        @{ Category = 'Conditions'; Type = 'Locations'; Direction = 'Exclude'; Value = $policy.ExcludedLocations; RawValue = $policy.ExcludedLocationIds }
                        @{ Category = 'Conditions'; Type = 'Platforms'; Direction = 'Include'; Value = $policy.IncludedPlatforms; RawValue = $null }
                        @{ Category = 'Conditions'; Type = 'Platforms'; Direction = 'Exclude'; Value = $policy.ExcludedPlatforms; RawValue = $null }
                        @{ Category = 'Conditions'; Type = 'ClientAppTypes'; Direction = 'Include'; Value = $policy.ClientAppTypes; RawValue = $null }
                        @{ Category = 'Conditions'; Type = 'SignInRiskLevels'; Direction = 'Include'; Value = $policy.SignInRiskLevels; RawValue = $null }
                        @{ Category = 'Conditions'; Type = 'UserRiskLevels'; Direction = 'Include'; Value = $policy.UserRiskLevels; RawValue = $null }
                        @{ Category = 'GrantControls'; Type = 'BuiltInControls'; Direction = 'Require'; Value = $policy.BuiltInControls; RawValue = $null }
                        @{ Category = 'GrantControls'; Type = 'AuthenticationStrength'; Direction = 'Require'; Value = $policy.AuthenticationStrength; RawValue = $policy.AuthenticationStrengthId }
                    )

                    foreach ($cat in $categories) {
                        if ($cat.Value) {
                            $detailRow = [PSCustomObject]@{
                                PolicyId          = $policy.PolicyId
                                PolicyDisplayName = $policy.DisplayName
                                State             = $policy.State
                                Classification    = $policy.Classification
                                RecordCategory    = $cat.Category
                                RecordType        = $cat.Type
                                Direction         = $cat.Direction
                                Value             = $cat.Value
                            }
                            if ($IncludeRawData) {
                                $detailRow | Add-Member -NotePropertyName 'RawValue' -NotePropertyValue $cat.RawValue
                            }
                            $detailData.Add($detailRow)
                        }
                    }
                }
                else {
                    # Expanded mode: One row per unique value
                    # Users
                    foreach ($item in $policy._IncludeUsersDetails) {
                        $detailData.Add([PSCustomObject]@{
                            PolicyId          = $policy.PolicyId
                            PolicyDisplayName = $policy.DisplayName
                            State             = $policy.State
                            Classification    = $policy.Classification
                            RecordCategory    = 'Users'
                            RecordType        = 'User'
                            Direction         = 'Include'
                            Value             = $item.DisplayName
                            RawValue          = if ($IncludeRawData) { $item.Id } else { $null }
                        })
                    }
                    foreach ($item in $policy._ExcludeUsersDetails) {
                        $detailData.Add([PSCustomObject]@{
                            PolicyId          = $policy.PolicyId
                            PolicyDisplayName = $policy.DisplayName
                            State             = $policy.State
                            Classification    = $policy.Classification
                            RecordCategory    = 'Users'
                            RecordType        = 'User'
                            Direction         = 'Exclude'
                            Value             = $item.DisplayName
                            RawValue          = if ($IncludeRawData) { $item.Id } else { $null }
                        })
                    }

                    # Groups
                    foreach ($item in $policy._IncludeGroupsDetails) {
                        $detailData.Add([PSCustomObject]@{
                            PolicyId          = $policy.PolicyId
                            PolicyDisplayName = $policy.DisplayName
                            State             = $policy.State
                            Classification    = $policy.Classification
                            RecordCategory    = 'Users'
                            RecordType        = 'Group'
                            Direction         = 'Include'
                            Value             = $item.DisplayName
                            RawValue          = if ($IncludeRawData) { $item.Id } else { $null }
                        })
                    }
                    foreach ($item in $policy._ExcludeGroupsDetails) {
                        $detailData.Add([PSCustomObject]@{
                            PolicyId          = $policy.PolicyId
                            PolicyDisplayName = $policy.DisplayName
                            State             = $policy.State
                            Classification    = $policy.Classification
                            RecordCategory    = 'Users'
                            RecordType        = 'Group'
                            Direction         = 'Exclude'
                            Value             = $item.DisplayName
                            RawValue          = if ($IncludeRawData) { $item.Id } else { $null }
                        })
                    }

                    # Roles
                    foreach ($item in $policy._IncludeRolesDetails) {
                        $detailData.Add([PSCustomObject]@{
                            PolicyId          = $policy.PolicyId
                            PolicyDisplayName = $policy.DisplayName
                            State             = $policy.State
                            Classification    = $policy.Classification
                            RecordCategory    = 'Users'
                            RecordType        = 'DirectoryRole'
                            Direction         = 'Include'
                            Value             = $item.DisplayName
                            RawValue          = if ($IncludeRawData) { $item.Id } else { $null }
                        })
                    }
                    foreach ($item in $policy._ExcludeRolesDetails) {
                        $detailData.Add([PSCustomObject]@{
                            PolicyId          = $policy.PolicyId
                            PolicyDisplayName = $policy.DisplayName
                            State             = $policy.State
                            Classification    = $policy.Classification
                            RecordCategory    = 'Users'
                            RecordType        = 'DirectoryRole'
                            Direction         = 'Exclude'
                            Value             = $item.DisplayName
                            RawValue          = if ($IncludeRawData) { $item.Id } else { $null }
                        })
                    }

                    # Applications
                    foreach ($item in $policy._IncludeAppsDetails) {
                        $detailData.Add([PSCustomObject]@{
                            PolicyId          = $policy.PolicyId
                            PolicyDisplayName = $policy.DisplayName
                            State             = $policy.State
                            Classification    = $policy.Classification
                            RecordCategory    = 'Applications'
                            RecordType        = 'Application'
                            Direction         = 'Include'
                            Value             = $item.DisplayName
                            RawValue          = if ($IncludeRawData) { $item.Id } else { $null }
                        })
                    }
                    foreach ($item in $policy._ExcludeAppsDetails) {
                        $detailData.Add([PSCustomObject]@{
                            PolicyId          = $policy.PolicyId
                            PolicyDisplayName = $policy.DisplayName
                            State             = $policy.State
                            Classification    = $policy.Classification
                            RecordCategory    = 'Applications'
                            RecordType        = 'Application'
                            Direction         = 'Exclude'
                            Value             = $item.DisplayName
                            RawValue          = if ($IncludeRawData) { $item.Id } else { $null }
                        })
                    }

                    # User Actions
                    foreach ($item in $policy._UserActionsDetails) {
                        $detailData.Add([PSCustomObject]@{
                            PolicyId          = $policy.PolicyId
                            PolicyDisplayName = $policy.DisplayName
                            State             = $policy.State
                            Classification    = $policy.Classification
                            RecordCategory    = 'Applications'
                            RecordType        = 'UserAction'
                            Direction         = 'Include'
                            Value             = $item.DisplayName
                            RawValue          = if ($IncludeRawData) { $item.Id } else { $null }
                        })
                    }

                    # Auth Contexts
                    foreach ($item in $policy._AuthContextsDetails) {
                        $detailData.Add([PSCustomObject]@{
                            PolicyId          = $policy.PolicyId
                            PolicyDisplayName = $policy.DisplayName
                            State             = $policy.State
                            Classification    = $policy.Classification
                            RecordCategory    = 'Applications'
                            RecordType        = 'AuthContext'
                            Direction         = 'Include'
                            Value             = $item.DisplayName
                            RawValue          = if ($IncludeRawData) { $item.Id } else { $null }
                        })
                    }

                    # Locations
                    foreach ($item in $policy._IncludeLocationsDetails) {
                        $detailData.Add([PSCustomObject]@{
                            PolicyId          = $policy.PolicyId
                            PolicyDisplayName = $policy.DisplayName
                            State             = $policy.State
                            Classification    = $policy.Classification
                            RecordCategory    = 'Conditions'
                            RecordType        = 'Location'
                            Direction         = 'Include'
                            Value             = $item.DisplayName
                            RawValue          = if ($IncludeRawData) { $item.Id } else { $null }
                        })
                    }
                    foreach ($item in $policy._ExcludeLocationsDetails) {
                        $detailData.Add([PSCustomObject]@{
                            PolicyId          = $policy.PolicyId
                            PolicyDisplayName = $policy.DisplayName
                            State             = $policy.State
                            Classification    = $policy.Classification
                            RecordCategory    = 'Conditions'
                            RecordType        = 'Location'
                            Direction         = 'Exclude'
                            Value             = $item.DisplayName
                            RawValue          = if ($IncludeRawData) { $item.Id } else { $null }
                        })
                    }

                    # Platforms (from raw values since not in detail objects)
                    if ($policy.IncludedPlatforms) {
                        foreach ($platform in ($policy.IncludedPlatforms -split '; ')) {
                            if ($platform) {
                                $detailData.Add([PSCustomObject]@{
                                    PolicyId          = $policy.PolicyId
                                    PolicyDisplayName = $policy.DisplayName
                                    State             = $policy.State
                                    Classification    = $policy.Classification
                                    RecordCategory    = 'Conditions'
                                    RecordType        = 'Platform'
                                    Direction         = 'Include'
                                    Value             = $platform
                                    RawValue          = $null
                                })
                            }
                        }
                    }
                    if ($policy.ExcludedPlatforms) {
                        foreach ($platform in ($policy.ExcludedPlatforms -split '; ')) {
                            if ($platform) {
                                $detailData.Add([PSCustomObject]@{
                                    PolicyId          = $policy.PolicyId
                                    PolicyDisplayName = $policy.DisplayName
                                    State             = $policy.State
                                    Classification    = $policy.Classification
                                    RecordCategory    = 'Conditions'
                                    RecordType        = 'Platform'
                                    Direction         = 'Exclude'
                                    Value             = $platform
                                    RawValue          = $null
                                })
                            }
                        }
                    }

                    # Grant Controls
                    if ($policy.BuiltInControls) {
                        foreach ($control in ($policy.BuiltInControls -split '; ')) {
                            if ($control) {
                                $detailData.Add([PSCustomObject]@{
                                    PolicyId          = $policy.PolicyId
                                    PolicyDisplayName = $policy.DisplayName
                                    State             = $policy.State
                                    Classification    = $policy.Classification
                                    RecordCategory    = 'GrantControls'
                                    RecordType        = 'BuiltInControl'
                                    Direction         = 'Require'
                                    Value             = $control
                                    RawValue          = $null
                                })
                            }
                        }
                    }

                    # Authentication Strength
                    if ($policy.AuthenticationStrength) {
                        $detailData.Add([PSCustomObject]@{
                            PolicyId          = $policy.PolicyId
                            PolicyDisplayName = $policy.DisplayName
                            State             = $policy.State
                            Classification    = $policy.Classification
                            RecordCategory    = 'GrantControls'
                            RecordType        = 'AuthenticationStrength'
                            Direction         = 'Require'
                            Value             = $policy.AuthenticationStrength
                            RawValue          = if ($IncludeRawData) { $policy.AuthenticationStrengthId } else { $null }
                        })
                    }
                }
            }

            # Step 3: Export to CSV
            Write-Progress -Id $parentProgressId -Activity 'Exporting CAP Report' `
                -Status '[3/3] Writing CSV files' `
                -PercentComplete 66

            # Remove RawValue column if not including raw data
            if (-not $IncludeRawData -and $detailData.Count -gt 0) {
                $detailData = $detailData | Select-Object -Property PolicyId, PolicyDisplayName, State, Classification, RecordCategory, RecordType, Direction, Value
            }

            # Export summary
            if ($summaryData.Count -gt 0) {
                $summaryData | Export-Csv -Path $summaryPath -NoTypeInformation -Encoding UTF8
                Write-Verbose -Message "Exported summary report to: $summaryPath"
            }

            # Export detail
            if ($detailData.Count -gt 0) {
                $detailData | Export-Csv -Path $detailPath -NoTypeInformation -Encoding UTF8
                Write-Verbose -Message "Exported detail report to: $detailPath"
            }

            Write-Progress -Id $parentProgressId -Activity 'Exporting CAP Report' -Completed

            # Output summary
            Write-Host "CAP Report exported successfully" -ForegroundColor Green
            Write-Host "  Summary: $summaryPath" -ForegroundColor Cyan
            Write-Host "  Detail:  $detailPath" -ForegroundColor Cyan
            Write-Host "  Policies: $policyCount" -ForegroundColor Cyan
            Write-Host "  Detail records: $($detailData.Count)" -ForegroundColor Cyan

            # Classification summary
            $classificationSummary = $policies | Group-Object -Property Classification | Sort-Object -Property Count -Descending
            Write-Host "`nClassification Summary:" -ForegroundColor Yellow
            foreach ($group in $classificationSummary) {
                Write-Host "  $($group.Name): $($group.Count)" -ForegroundColor White
            }

            # State summary
            $stateSummary = $policies | Group-Object -Property State | Sort-Object -Property Count -Descending
            Write-Host "`nState Summary:" -ForegroundColor Yellow
            foreach ($group in $stateSummary) {
                $color = switch ($group.Name) {
                    'enabled' { 'Green' }
                    'disabled' { 'Red' }
                    'enabledForReportingButNotEnforced' { 'Yellow' }
                    default { 'White' }
                }
                Write-Host "  $($group.Name): $($group.Count)" -ForegroundColor $color
            }

            # Return result object
            $result = [PSCustomObject]@{
                SummaryReport = if (Test-Path -Path $summaryPath) { Get-Item -Path $summaryPath } else { $null }
                DetailReport  = if (Test-Path -Path $detailPath) { Get-Item -Path $detailPath } else { $null }
                PolicyCount   = $policyCount
                DetailCount   = $detailData.Count
            }

            if ($PassThru) {
                $result | Add-Member -NotePropertyName 'Policies' -NotePropertyValue $policies
            }

            return $result
        }
        catch {
            Write-Progress -Id $parentProgressId -Activity 'Exporting CAP Report' -Completed
            Write-Error -Message "Failed to export CAP report: $PSItem"
            throw
        }
    }
}
