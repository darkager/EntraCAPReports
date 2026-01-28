@{
    RootModule           = 'EntraCAPReports.psm1'
    ModuleVersion        = '0.5.0'
    CompatiblePSEditions = @('Desktop', 'Core')
    PowerShellVersion    = '5.1'
    GUID                 = 'da156b6d-7191-4e7a-9999-8436a372c214'
    Author               = 'Your Name'
    CompanyName          = 'Your Company'
    Copyright            = '(c) 2026. All rights reserved.'
    Description          = 'PowerShell module for reporting on Microsoft Entra Conditional Access Policies. Provides descriptive quantification of CAP configurations with resolved names and policy classification.'

    RequiredModules      = @(
        @{ ModuleName = 'Microsoft.Graph.Identity.SignIns'; ModuleVersion = '2.0.0' }
        @{ ModuleName = 'Microsoft.Graph.Groups'; ModuleVersion = '2.0.0' }
        @{ ModuleName = 'Microsoft.Graph.Users'; ModuleVersion = '2.0.0' }
        @{ ModuleName = 'Microsoft.Graph.Applications'; ModuleVersion = '2.0.0' }
    )

    FunctionsToExport    = @(
        'Get-EntraConditionalAccessPolicy'
        'Export-EntraCAPReport'
    )

    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()

    PrivateData          = @{
        PSData = @{
            Tags         = @('Entra', 'ConditionalAccess', 'CAP', 'Azure', 'Security', 'Reporting')
            LicenseUri   = ''
            ProjectUri   = ''
            ReleaseNotes = @'
## 0.5.0 (2026-01-28)
- Named Locations Enhancement: Detail report expands each IP range or country code into its own row
- IP named locations show CIDR ranges with trust status [Trusted] or [Not Trusted]
- Country named locations show each country code (no trust indicator)
- RecordType includes value type: Location (IPv4), Location (CountryCode), Location (Special)
- Expansion only applies in non-Flatten mode
- Restructured README with Table of Contents and reordered sections

## 0.4.0 (2026-01-09)
- Added AuthenticationFlowsTransferMethods condition (device code flow, authentication transfer)
- Added ClientApplications conditions for workload identity (service principal targeting)
- Added WorkloadIdentity classification for policies targeting service principals
- Added AuthenticationFlowRestriction classification for policies restricting auth flows
- Updated ConditionsDescription to include auth flows and workload identity info

## 0.3.0 (2026-01-09)
- Added Description field to policy output and summary report
- Added ContinuousAccessEvaluationMode session control output
- Updated SessionDescription to include CAE status

## 0.2.0 (2026-01-05)
- Fixed Export-EntraCAPReport failing when PolicyId not specified
- Reordered summary report columns (DisplayName first, PolicyId last)

## 0.1.0 (2026-01-04)
- Initial release
- Get-EntraConditionalAccessPolicy: Retrieve CAPs with resolved names
- Export-EntraCAPReport: Generate summary and detail CSV reports
- Policy classification by intent pattern
'@
        }
    }
}
