# EntraCAPReports

PowerShell module for reporting on Microsoft Entra ID Conditional Access Policies. Provides descriptive quantification of CAP configurations with resolved human-readable names and policy classification.

## Table of Contents

- [Quick Start / Authentication](#quick-start--authentication)
- [Export Commands](#export-commands)
  - [Export-EntraCAPReport](#export-entracapreport)
- [Get-EntraConditionalAccessPolicy](#get-entraconditionalaccesspolicy)
- [Report Schemas](#report-schemas)
  - [Summary Report Columns](#summary-report-columns)
  - [Detail Report Columns](#detail-report-columns)
  - [Detail Report Modes](#detail-report-modes)
- [Policy Classification](#policy-classification)
  - [Classification Types](#classification-types)
  - [Priority Order](#priority-order)
- [Additional Examples](#additional-examples)
- [Caching and Performance](#caching-and-performance)
- [Changelog](#changelog)
- [Future Roadmap](#future-roadmap)
- [License](#license)

---

## Quick Start / Authentication

### Requirements

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

## Export Commands

### Export-EntraCAPReport

Generates CSV reports with summary and detail views.

```powershell
# Export all policies to timestamped CSV files in current directory
Export-EntraCAPReport

# Export to a specific directory
Export-EntraCAPReport -OutputPath 'C:\Reports'

# Export to a specific base filename
Export-EntraCAPReport -OutputPath 'C:\Reports\EntraCAP'
# Creates: EntraCAP-Summary.csv and EntraCAP-Detail.csv

# Export only enabled policies
Export-EntraCAPReport -StateFilter Enabled

# Export with compact detail format (one row per category)
Export-EntraCAPReport -Flatten

# Export with raw ID columns
Export-EntraCAPReport -IncludeRawData

# Export and return policy objects
$result = Export-EntraCAPReport -PassThru
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

## Get-EntraConditionalAccessPolicy

Retrieves Conditional Access Policies with all GUIDs resolved to human-readable names and policy classification.

```powershell
# Get all policies with resolved names
Get-EntraConditionalAccessPolicy

# Get a specific policy by ID
Get-EntraConditionalAccessPolicy -PolicyId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'

# Get raw data without name resolution (faster)
Get-EntraConditionalAccessPolicy -ResolveNames $false
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
| Metadata | PolicyId, DisplayName, Description, State, CreatedDateTime, ModifiedDateTime, TemplateId |
| Classification | Classification (primary), AllClassifications (all matches) |
| Users | IncludedUsers, ExcludedUsers, IncludedGroups, ExcludedGroups, IncludedRoles, ExcludedRoles, IncludedGuestsOrExternalUsers, ExcludedGuestsOrExternalUsers, UserScopeDescription |
| Applications | IncludedApplications, ExcludedApplications, IncludedUserActions, IncludedAuthContexts, ApplicationFilter, AppScopeDescription |
| Conditions | ClientAppTypes, IncludedPlatforms, ExcludedPlatforms, IncludedLocations, ExcludedLocations, DeviceFilterMode, DeviceFilterRule, SignInRiskLevels, UserRiskLevels, ServicePrincipalRiskLevels, InsiderRiskLevels, AuthenticationFlowsTransferMethods, ClientApplicationsIncludeServicePrincipals, ClientApplicationsExcludeServicePrincipals, ClientApplicationsServicePrincipalFilter, ConditionsDescription |
| Grant Controls | GrantOperator, BuiltInControls, AuthenticationStrength, TermsOfUse, CustomAuthenticationFactors, GrantDescription |
| Session Controls | SignInFrequencyEnabled, SignInFrequencyValue, SignInFrequencyType, PersistentBrowserEnabled, PersistentBrowserMode, CloudAppSecurityEnabled, CloudAppSecurityType, AppEnforcedRestrictionsEnabled, ContinuousAccessEvaluationMode, DisableResilienceDefaults, SessionDescription |

---

## Report Schemas

### Summary Report Columns

| Column | Description |
|--------|-------------|
| DisplayName | Policy name |
| Description | Policy description (if set) |
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
| PolicyId | Policy GUID |

### Detail Report Columns

| Column | Description |
|--------|-------------|
| PolicyDisplayName | Policy name |
| State | enabled, disabled, enabledForReportingButNotEnforced |
| Classification | Primary classification |
| RecordCategory | Users, Applications, Conditions, GrantControls, SessionControls |
| RecordType | Specific type (User, Group, DirectoryRole, Application, Platform, BuiltInControl, etc.). For locations: `Location (IPv4)`, `Location (IPv6)`, `Location (CountryCode)`, `Location (Special)` |
| Direction | Include, Exclude, or Require |
| Value | Resolved name or value |
| RawValue | Original GUID (only with -IncludeRawData) |
| PolicyId | Policy GUID |

### Detail Report Modes

- **Default (Expanded)**: One row per unique value - best for Excel filtering and pivot tables
  - Example: A policy with 15 included roles generates 15 detail rows
  - Location expansion: Each IP range (IPv4/IPv6 CIDR) or country code gets its own row with trust status
- **Flatten (Compact)**: One row per category with semicolon-separated values
  - Example: A policy with 15 included roles generates 1 row with all roles joined
  - Note: Location expansion is not applied in Flatten mode - shows location names only

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
| WorkloadIdentity | Targets service principals via clientApplications condition |
| RiskBased | Has signInRiskLevels, userRiskLevels, servicePrincipalRiskLevels, or insiderRiskLevels |
| GuestPolicy | Targets GuestsOrExternalUsers |
| DeviceCompliance | Requires compliantDevice, domainJoinedDevice, or has device filter |
| LocationBased | Has non-trivial location conditions (not just "All") |
| AuthenticationFlowRestriction | Restricts authentication flows (device code flow, authentication transfer) |
| AppSpecific | Targets specific applications (not "All") |
| MFAEnforcement | Requires MFA or authentication strength (without other specific conditions) |
| SessionControl | Has session controls configured (sign-in frequency, persistent browser, MCAS, etc.) |
| General | Default/catch-all when no other classification applies |

### Priority Order

When multiple classifications match, the primary classification is determined by priority:

```
BlockPolicy > AdminProtection > WorkloadIdentity > RiskBased > GuestPolicy >
DeviceCompliance > LocationBased > AuthenticationFlowRestriction > AppSpecific >
MFAEnforcement > SessionControl > General
```

---

## Additional Examples

### Weekly CAP Audit Report

```powershell
Connect-MgGraph -Scopes 'Policy.Read.All', 'Directory.Read.All', 'Application.Read.All'

Export-EntraCAPReport -OutputPath 'C:\Reports\WeeklyCAP' -StateFilter Enabled

Disconnect-MgGraph
```

### Find All Block Policies

```powershell
$result = Export-EntraCAPReport -PassThru

$result.Policies |
    Where-Object { $_.Classification -eq 'BlockPolicy' } |
    Format-Table DisplayName, State, UserScopeDescription, AppScopeDescription
```

### Analyze Admin Protection Policies

```powershell
$policies = Get-EntraConditionalAccessPolicy

$adminPolicies = $policies | Where-Object {
    $_.AllClassifications -like '*AdminProtection*'
}

$adminPolicies | Format-Table DisplayName, IncludedRoles, GrantDescription
```

### Export Compact Report for Quick Review

```powershell
Export-EntraCAPReport -OutputPath 'C:\Reports\QuickReview' -Flatten -StateFilter Enabled
```

### Compare Report-Only vs Enforced Policies

```powershell
$reportOnly = Export-EntraCAPReport -StateFilter ReportOnly -PassThru
$enabled = Export-EntraCAPReport -StateFilter Enabled -PassThru

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

### v0.5.0 (2026-01-28)

- **Named Locations Enhancement**: Detail report now expands each IP range or country code into its own row (non-Flatten mode only)
  - IP named locations show each CIDR range (IPv4/IPv6) with trust status `[Trusted]` or `[Not Trusted]`
  - Country named locations show each country code (no trust indicator - not applicable to country locations)
  - Special locations (All, AllTrusted) show as single rows without trust indicator
  - RecordType now includes the value type (e.g., `Location (IPv4)`, `Location (CountryCode)`, `Location (Special)`)
  - Value format: `"Location Name [Trusted] - 10.0.0.0/8"` or `"Location Name - US"` for countries
- Restructured README with Table of Contents and reordered sections

### v0.4.0 (2026-01-09)

- Added `AuthenticationFlowsTransferMethods` condition (device code flow, authentication transfer)
- Added `ClientApplications` conditions for workload identity (service principal targeting)
- Added `WorkloadIdentity` classification for policies targeting service principals
- Added `AuthenticationFlowRestriction` classification for policies restricting auth flows
- Updated `ConditionsDescription` to include auth flows and workload identity info

### v0.3.0 (2026-01-09)

- Added `Description` field to policy output and summary report
- Added `ContinuousAccessEvaluationMode` session control output
- Updated `SessionDescription` to include CAE status (strict enforcement/disabled)

### v0.2.0 (2026-01-05)

- Fixed `Export-EntraCAPReport` failing when `-PolicyId` not specified
- Reordered summary report columns (DisplayName first, PolicyId last)

### v0.1.0 (2026-01-04)

- Initial release
- `Get-EntraConditionalAccessPolicy` - Retrieve CAPs with resolved names and classification
- `Export-EntraCAPReport` - Generate summary and detail CSV reports
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
