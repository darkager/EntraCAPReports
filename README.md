# EntraCAPReports

PowerShell module for reporting on Microsoft Entra ID Conditional Access Policies. Provides descriptive quantification of CAP configurations with resolved human-readable names and policy classification.

## Overview

This module retrieves Conditional Access Policies from Microsoft Entra ID and generates comprehensive reports that:

- **Resolve all GUIDs** to human-readable names (users, groups, roles, applications, locations)
- **Classify policies** by their intent pattern (MFA enforcement, admin protection, risk-based, etc.)
- **Export detailed reports** for analysis in Excel with filtering and pivoting capabilities

## Requirements

- PowerShell 5.1 or later (Desktop or Core)
- Microsoft Graph PowerShell modules (v2.0.0 or later):
  - Microsoft.Graph.Identity.SignIns
  - Microsoft.Graph.Groups
  - Microsoft.Graph.Users
  - Microsoft.Graph.Applications

### Installation

1. Install the required Microsoft Graph modules:

```powershell
Install-Module -Name Microsoft.Graph.Identity.SignIns -MinimumVersion 2.0.0
Install-Module -Name Microsoft.Graph.Groups -MinimumVersion 2.0.0
Install-Module -Name Microsoft.Graph.Users -MinimumVersion 2.0.0
Install-Module -Name Microsoft.Graph.Applications -MinimumVersion 2.0.0
```

2. Copy the `EntraCAPReports` folder to a location in your `$env:PSModulePath`

3. Import the module:

```powershell
Import-Module EntraCAPReports
```

### Required Graph API Permissions (Scopes)

| Permission | Purpose |
|------------|---------|
| `Policy.Read.All` | Read Conditional Access Policies, named locations, authentication contexts, authentication strength policies |
| `Directory.Read.All` | Resolve user, group, and directory role GUIDs to display names |
| `Application.Read.All` | Resolve application IDs to display names |

### Authentication

Connect to Microsoft Graph with the required scopes before using the module:

```powershell
Connect-MgGraph -Scopes 'Policy.Read.All', 'Directory.Read.All', 'Application.Read.All'
```

---

## Functions

### Get-ConditionalAccessPolicy

Retrieves Conditional Access Policies with all GUIDs resolved to human-readable names and policy classification.

```powershell
# Get all policies with resolved names
Get-ConditionalAccessPolicy

# Get a specific policy by ID
Get-ConditionalAccessPolicy -PolicyId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'

# Get raw data without name resolution (faster)
Get-ConditionalAccessPolicy -ResolveNames $false
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| PolicyId | String[] | - | Specific policy IDs to retrieve |
| ResolveNames | Bool | $true | Resolve GUIDs to display names |
| ProgressParentId | Int32 | -1 | Parent progress bar ID for nested progress |

**Output Properties:**

| Category | Properties |
|----------|------------|
| Metadata | PolicyId, DisplayName, State, CreatedDateTime, ModifiedDateTime, TemplateId |
| Classification | Classification (primary), AllClassifications (all matches) |
| Users | IncludedUsers, ExcludedUsers, IncludedGroups, ExcludedGroups, IncludedRoles, ExcludedRoles, IncludedGuestsOrExternalUsers, ExcludedGuestsOrExternalUsers, UserScopeDescription |
| Applications | IncludedApplications, ExcludedApplications, IncludedUserActions, IncludedAuthContexts, ApplicationFilter, AppScopeDescription |
| Conditions | ClientAppTypes, IncludedPlatforms, ExcludedPlatforms, IncludedLocations, ExcludedLocations, DeviceFilterMode, DeviceFilterRule, SignInRiskLevels, UserRiskLevels, ServicePrincipalRiskLevels, InsiderRiskLevels, ConditionsDescription |
| Grant Controls | GrantOperator, BuiltInControls, AuthenticationStrength, TermsOfUse, CustomAuthenticationFactors, GrantDescription |
| Session Controls | SignInFrequencyEnabled, SignInFrequencyValue, SignInFrequencyType, PersistentBrowserEnabled, PersistentBrowserMode, CloudAppSecurityEnabled, CloudAppSecurityType, AppEnforcedRestrictionsEnabled, DisableResilienceDefaults, SessionDescription |

---

### Export-CAPReport

Generates CSV reports with summary and detail views.

```powershell
# Export all policies to timestamped CSV files in current directory
Export-CAPReport

# Export to a specific directory
Export-CAPReport -OutputPath 'C:\Reports'

# Export to a specific base filename
Export-CAPReport -OutputPath 'C:\Reports\CAP'
# Creates: CAP-Summary.csv and CAP-Detail.csv

# Export only enabled policies
Export-CAPReport -StateFilter Enabled

# Export with compact detail format (one row per category)
Export-CAPReport -Flatten

# Export with raw ID columns
Export-CAPReport -IncludeRawData

# Export and return policy objects
$result = Export-CAPReport -PassThru
$result.Policies | Where-Object { $_.Classification -eq 'BlockPolicy' }
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| OutputPath | String | Auto-generated | Output directory or base file path |
| PolicyId | String[] | - | Specific policy IDs to include |
| StateFilter | String | All | Filter by state: All, Enabled, Disabled, ReportOnly |
| Flatten | Switch | - | Compact detail report (one row per category with semicolon-separated values) |
| IncludeRawData | Switch | - | Include raw ID columns in addition to resolved names |
| PassThru | Switch | - | Return policy objects in addition to exporting |

**Output Files:**

1. `*-Summary.csv` - One row per policy with key metrics
2. `*-Detail.csv` - Flattened view with one row per condition value

---

## Report Schemas

### Summary Report Columns

| Column | Description |
|--------|-------------|
| PolicyId | Policy GUID |
| DisplayName | Policy name |
| State | enabled, disabled, enabledForReportingButNotEnforced |
| Classification | Primary intent pattern |
| AllClassifications | All matching patterns (semicolon-separated) |
| UserScope | Human-readable user scope summary |
| AppScope | Human-readable application scope summary |
| HasLocationConditions | Boolean |
| HasPlatformConditions | Boolean |
| HasRiskConditions | Boolean |
| HasDeviceFilter | Boolean |
| GrantControls | Human-readable grant controls summary |
| SessionControls | Human-readable session controls summary |
| CreatedDateTime | When the policy was created |
| ModifiedDateTime | When the policy was last modified |

### Detail Report Columns

| Column | Description |
|--------|-------------|
| PolicyId | Policy GUID |
| PolicyDisplayName | Policy name |
| State | enabled, disabled, enabledForReportingButNotEnforced |
| Classification | Primary classification |
| RecordCategory | Users, Applications, Conditions, GrantControls, SessionControls |
| RecordType | Specific type (User, Group, DirectoryRole, Application, Location, Platform, etc.) |
| Direction | Include, Exclude, or Require |
| Value | Resolved name or value |
| RawValue | Original GUID (only with -IncludeRawData) |

### Detail Report Modes

- **Default (Expanded)**: One row per unique value - best for Excel filtering and pivot tables
  - Example: A policy with 15 included roles generates 15 detail rows
- **Flatten (Compact)**: One row per category with semicolon-separated values
  - Example: A policy with 15 included roles generates 1 row with all roles joined

---

## Policy Classification

Policies are automatically classified by their intent pattern. Each policy receives:
- **Primary Classification**: The highest-priority matching classification
- **All Classifications**: All matching classifications (semicolon-separated)

### Classification Types

| Classification | Detection Logic |
|----------------|-----------------|
| BlockPolicy | Uses the "block" grant control |
| AdminProtection | Targets directory roles |
| RiskBased | Has signInRiskLevels, userRiskLevels, servicePrincipalRiskLevels, or insiderRiskLevels |
| GuestPolicy | Targets GuestsOrExternalUsers |
| DeviceCompliance | Requires compliantDevice, domainJoinedDevice, or has device filter |
| LocationBased | Has non-trivial location conditions (not just "All") |
| AppSpecific | Targets specific applications (not "All") |
| MFAEnforcement | Requires MFA or authentication strength (without other specific conditions) |
| SessionControl | Has session controls configured (sign-in frequency, persistent browser, MCAS, etc.) |
| General | Default/catch-all when no other classification applies |

### Priority Order

When multiple classifications match, the primary classification is determined by priority:

```
BlockPolicy > AdminProtection > RiskBased > GuestPolicy > DeviceCompliance >
LocationBased > AppSpecific > MFAEnforcement > SessionControl > General
```

---

## Examples

### Weekly CAP Audit Report

```powershell
Connect-MgGraph -Scopes 'Policy.Read.All', 'Directory.Read.All', 'Application.Read.All'

Export-CAPReport -OutputPath 'C:\Reports\WeeklyCAP' -StateFilter Enabled

Disconnect-MgGraph
```

### Find All Block Policies

```powershell
$result = Export-CAPReport -PassThru

$result.Policies |
    Where-Object { $_.Classification -eq 'BlockPolicy' } |
    Format-Table DisplayName, State, UserScopeDescription, AppScopeDescription
```

### Analyze Admin Protection Policies

```powershell
$policies = Get-ConditionalAccessPolicy

$adminPolicies = $policies | Where-Object {
    $_.AllClassifications -like '*AdminProtection*'
}

$adminPolicies | Format-Table DisplayName, IncludedRoles, GrantDescription
```

### Export Compact Report for Quick Review

```powershell
Export-CAPReport -OutputPath 'C:\Reports\QuickReview' -Flatten -StateFilter Enabled
```

### Compare Report-Only vs Enforced Policies

```powershell
$reportOnly = Export-CAPReport -StateFilter ReportOnly -PassThru
$enabled = Export-CAPReport -StateFilter Enabled -PassThru

Write-Host "Report-only policies: $($reportOnly.PolicyCount)"
Write-Host "Enforced policies: $($enabled.PolicyCount)"
```

---

## Caching and Performance

The module uses intelligent caching to minimize API calls:

- **Pre-fetched on first use**: Named locations, directory role definitions, authentication strength policies, authentication contexts
- **Cached per-object**: Users, groups, applications (cached as encountered)
- **Well-known IDs**: Static lookup tables for common Microsoft first-party apps and built-in roles

For large tenants with many policies, the first run may take longer while caches are populated. Subsequent policy retrievals within the same session will be faster.

---

## Changelog

### v0.1.0 (2026-01-04)

- Initial release
- `Get-ConditionalAccessPolicy` - Retrieve CAPs with resolved names and classification
- `Export-CAPReport` - Generate summary and detail CSV reports
- Policy classification by intent pattern (10 categories)
- Name resolution for users, groups, roles, applications, locations, auth contexts, auth strengths
- Dual detail report modes (expanded vs. compact)
- State filtering and raw data inclusion options

---

## Future Roadmap

- Standalone convenience functions for named locations and authentication strength policies
- Policy comparison/diff functionality
- Policy template detection
- HTML/Excel report generation

---

## License

MIT License
