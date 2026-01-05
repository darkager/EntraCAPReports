@{
    RootModule           = 'EntraCAPReports.psm1'
    ModuleVersion        = '0.1.0'
    CompatiblePSEditions = @('Desktop', 'Core')
    PowerShellVersion    = '5.1'
    GUID                 = 'a3b8c5d2-4e6f-4a8b-9c1d-2e3f4a5b6c7d'
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
        'Get-ConditionalAccessPolicy'
        'Export-CAPReport'
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
## 0.1.0 (2026-01-02)
- Initial release
- Get-ConditionalAccessPolicy: Retrieve CAPs with resolved names
- Export-CAPReport: Generate summary and detail CSV reports
- Policy classification by intent pattern
'@
        }
    }
}
