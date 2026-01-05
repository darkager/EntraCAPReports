#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Microsoft.Graph.Identity.SignIns'; ModuleVersion = '2.0.0' }
#Requires -Modules @{ ModuleName = 'Microsoft.Graph.Groups'; ModuleVersion = '2.0.0' }
#Requires -Modules @{ ModuleName = 'Microsoft.Graph.Users'; ModuleVersion = '2.0.0' }
#Requires -Modules @{ ModuleName = 'Microsoft.Graph.Applications'; ModuleVersion = '2.0.0' }

# Get public and private function definition files
$Public = @(Get-ChildItem -Path "$PSScriptRoot\Public\*.ps1" -ErrorAction SilentlyContinue)
$Private = @(Get-ChildItem -Path "$PSScriptRoot\Private\*.ps1" -ErrorAction SilentlyContinue)

# Dot-source the files
foreach ($import in @($Public + $Private)) {
    try {
        . $import.FullName
        Write-Verbose -Message "Imported function: $($import.BaseName)"
    }
    catch {
        Write-Error -Message "Failed to import function $($import.FullName): $PSItem"
    }
}

# Module-scoped caching variables
$script:UserCache = New-Object -TypeName 'System.Collections.Generic.Dictionary[[String],[PSCustomObject]]'
$script:GroupCache = New-Object -TypeName 'System.Collections.Generic.Dictionary[[String],[PSCustomObject]]'
$script:RoleCache = New-Object -TypeName 'System.Collections.Generic.Dictionary[[String],[PSCustomObject]]'
$script:AppCache = New-Object -TypeName 'System.Collections.Generic.Dictionary[[String],[PSCustomObject]]'
$script:LocationCache = New-Object -TypeName 'System.Collections.Generic.Dictionary[[String],[PSCustomObject]]'
$script:AuthStrengthCache = New-Object -TypeName 'System.Collections.Generic.Dictionary[[String],[PSCustomObject]]'
$script:AuthContextCache = New-Object -TypeName 'System.Collections.Generic.Dictionary[[String],[PSCustomObject]]'

# Flag to track if caches have been initialized
$script:CachesInitialized = $false

# Well-known Microsoft application IDs
$script:KnownAppIds = @{
    # Office 365 / Microsoft 365
    '00000002-0000-0ff1-ce00-000000000000' = 'Office 365 Exchange Online'
    '00000003-0000-0ff1-ce00-000000000000' = 'Office 365 SharePoint Online'
    '00000004-0000-0ff1-ce00-000000000000' = 'Skype for Business Online'
    '00000006-0000-0ff1-ce00-000000000000' = 'Microsoft Office 365 Portal'

    # Azure / Microsoft Graph
    '00000003-0000-0000-c000-000000000000' = 'Microsoft Graph'
    '00000002-0000-0000-c000-000000000000' = 'Windows Azure Active Directory'
    '797f4846-ba00-4fd7-ba43-dac1f8f63013' = 'Windows Azure Service Management API'

    # Teams
    'cc15fd57-2c6c-4117-a88c-83b1d56b4bbe' = 'Microsoft Teams'
    '1fec8e78-bce4-4aaf-ab1b-5451cc387264' = 'Microsoft Teams Web Client'

    # Power Platform
    '871c010f-5e61-4fb1-83ac-98610a7e9110' = 'Power BI Service'
    'a672d62c-fc7b-4e81-a576-e60dc46e951d' = 'Power Apps'
    '6204c1d1-4712-4c46-a7d9-3ed63d992571' = 'Power Automate'

    # Intune / Endpoint
    '0000000a-0000-0000-c000-000000000000' = 'Microsoft Intune'
    'd4ebce55-015a-49b5-a083-c84d1797ae8c' = 'Microsoft Intune Enrollment'

    # Azure DevOps
    '499b84ac-1321-427f-aa17-267ca6975798' = 'Azure DevOps'

    # Dynamics
    '00000007-0000-0000-c000-000000000000' = 'Dynamics CRM Online'

    # Visual Studio
    '872cd9fa-d31f-45e0-9eab-6e460a02d1f1' = 'Visual Studio'

    # Windows
    '1b730954-1685-4b74-9bfd-dac224a7b894' = 'Azure Active Directory PowerShell'
    '04b07795-8ddb-461a-bbee-02f9e1bf7b46' = 'Microsoft Azure CLI'
    '1950a258-227b-4e31-a9cf-717495945fc2' = 'Microsoft Azure PowerShell'

    # Security
    '05a65629-4c1b-48c1-a78b-804c4abdd4af' = 'Microsoft Defender for Cloud Apps'
    '7df0a125-d3be-4c96-aa54-591f83ff541c' = 'Microsoft Information Protection Sync Service'

    # Yammer / Viva
    '00000005-0000-0ff1-ce00-000000000000' = 'Yammer'
}

# Well-known directory role template IDs
$script:KnownRoleTemplateIds = @{
    '62e90394-69f5-4237-9190-012177145e10' = 'Global Administrator'
    'fe930be7-5e62-47db-91af-98c3a49a38b1' = 'User Administrator'
    '729827e3-9c14-49f7-bb1b-9608f156bbb8' = 'Helpdesk Administrator'
    '194ae4cb-b126-40b2-bd5b-6091b380977d' = 'Security Administrator'
    'e8611ab8-c189-46e8-94e1-60213ab1f814' = 'Privileged Role Administrator'
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' = 'Application Administrator'
    '29232cdf-9323-42fd-ade2-1d097af3e4de' = 'Exchange Administrator'
    'f28a1f50-f6e7-4571-818b-6a12f2af6b6c' = 'SharePoint Administrator'
    '69091246-20e8-4a56-aa4d-066075b2a7a8' = 'Teams Administrator'
    '3a2c62db-5318-420d-8d74-23affee5d9d5' = 'Intune Administrator'
    'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9' = 'Cloud Application Administrator'
    'c4e39bd9-1100-46d3-8c65-fb160da0071f' = 'Authentication Administrator'
    '7be44c8a-adaf-4e2a-84d6-ab2649e08a13' = 'Privileged Authentication Administrator'
    'b0f54661-2d74-4c50-afa3-1ec803f12efe' = 'Billing Administrator'
    '158c047a-c907-4556-b7ef-446551a6b5f7' = 'Cloud Device Administrator'
    '966707d0-3269-4727-9be2-8c3a10f19b9d' = 'Password Administrator'
    'cf1c38e5-3621-4004-a7cb-879624dced7c' = 'Application Developer'
    'f2ef992c-3afb-46b9-b7cf-a126ee74c451' = 'Global Reader'
    '9360feb5-f418-4baa-8175-e2a00bac4301' = 'Directory Writers'
    '38a96431-2bdf-4b4c-8b6e-5d3d8abac1a4' = 'Desktop Analytics Administrator'
    '4d6ac14f-3453-41d0-bef9-a3e0c569773a' = 'License Administrator'
    '5f2222b1-57c3-48ba-8ad5-d4759f1fde6f' = 'Security Operator'
    '5d6b6bb7-de71-4623-b4af-96380a352509' = 'Security Reader'
    '17315797-102d-40b4-93e0-432062caca18' = 'Compliance Administrator'
    'd29b2b05-8046-44ba-8758-1e26182fcf32' = 'Directory Synchronization Accounts'
}

# Export public functions
Export-ModuleMember -Function @(
    'Get-ConditionalAccessPolicy'
    'Export-CAPReport'
)
