# SDK Audit: jamfprotect-go-sdk vs bin/schema.graphql

Audited 2026-04-11.

---

## Part 1: Field-Level Audit of Implemented Resources

Detailed field-by-field comparison of every implemented resource against the schema.

### Plan (`plan.go`)

**PlanInput (Go) vs PlanInput (Schema)**

| Go struct fields | Schema fields |
|---|---|
| Name | name |
| Description | description |
| LogLevel | logLevel |
| ActionConfigs | actionConfigs |
| ExceptionSets | exceptionSets |
| Telemetry | telemetry |
| TelemetryV2 | telemetryV2 |
| TelemetryV2Null _(helper flag, not in schema)_ | — |
| AnalyticSets | analyticSets |
| USBControlSet | usbControlSet |
| CommsConfig | commsConfig |
| InfoSync | infoSync |
| AutoUpdate | autoUpdate |
| SignaturesFeedConfig | signaturesFeedConfig |
| — | **threatPreventionStrategy** (missing) |
| — | **customEngineConfig** (missing) |

**Plan response (Go) vs Plan type (Schema)**

| Go struct fields | Schema fields |
|---|---|
| ID | id |
| Hash | hash |
| Name | name |
| Description | description |
| Created | created |
| Updated | updated |
| LogLevel | logLevel |
| AutoUpdate | autoUpdate |
| CommsConfig | commsConfig |
| InfoSync | infoSync |
| SignaturesFeedConfig | signaturesFeedConfig |
| ActionConfigs | actionConfigs |
| ExceptionSets | exceptionSets |
| USBControlSet | usbControlSet |
| Telemetry | telemetry |
| TelemetryV2 | telemetryV2 |
| AnalyticSets | analyticSets |
| — | **uuid** (missing) |
| — | **profileVersion** (missing) |
| — | **analytics** (missing) |
| — | **threatPreventionStrategy** (missing) |
| — | **customEngineConfig** (missing) |

`threatPreventionStrategy` and `customEngineConfig` are the biggest gaps — they control the threat prevention engine mode (LEGACY/MANAGED/CUSTOM_ENGINES) and per-engine toggles. Anyone using the SDK to manage plans can't configure these.

---

### Analytic (`analytic.go`)

**AnalyticInput (Go) vs AnalyticInput (Schema)**

| Go struct fields | Schema fields |
|---|---|
| Name | name |
| InputType | inputType |
| Description | description |
| Actions | actions |
| AnalyticActions | analyticActions |
| Tags | tags |
| Categories | categories |
| Filter | filter |
| Context | context |
| Level | level |
| Severity | severity |
| SnapshotFiles | snapshotFiles |
| — | **label** (missing) |
| — | **longDescription** (missing) |
| — | **startup** (missing) |
| — | **remediation** (missing) |
| — | **matchReason** (missing) |

**Analytic response (Go) vs Analytic type (Schema)**

| Go struct fields | Schema fields |
|---|---|
| UUID | uuid |
| Name | name |
| Label | label |
| InputType | inputType |
| Filter | filter |
| Description | description |
| LongDescription | longDescription |
| Created | created |
| Updated | updated |
| Actions | actions |
| AnalyticActions | analyticActions |
| TenantActions | tenantActions |
| Tags | tags |
| Level | level |
| Severity | severity |
| TenantSeverity | tenantSeverity |
| SnapshotFiles | snapshotFiles |
| Context | context |
| Categories | categories |
| Jamf | jamf |
| Remediation | remediation |
| — | **hash** (missing) |
| — | **startup** (missing) |
| — | **udm** (missing) |
| — | **exceptions** (missing) |
| — | **matchReason** (missing) |
| — | **osVersion** (missing) |
| — | **extVersion** (missing) |
| — | **plans** (missing) |
| — | **analyticSets** (missing) |

The SDK can read `label`, `longDescription`, and `remediation` from the response but can't _set_ them via the input.

---

### Computer (`computer.go`)

**Computer response (Go) vs Computer type (Schema)**

| Go struct fields | Schema fields |
|---|---|
| UUID | uuid |
| Serial | serial |
| HostName | hostName |
| ModelName | modelName |
| OSMajor | osMajor |
| OSMinor | osMinor |
| OSPatch | osPatch |
| Arch | arch |
| CertID | certid |
| MemorySize | memorySize |
| OSString | osString |
| KernelVersion | kernelVersion |
| InstallType | installType |
| Label | label |
| Created | created |
| Updated | updated |
| Version | version |
| Checkin | checkin |
| ConfigHash | configHash |
| Tags | tags |
| SignaturesVersion | signaturesVersion |
| Plan | plan |
| InsightsStatsFail | insightsStatsFail |
| InsightsUpdated | insightsUpdated |
| ConnectionStatus | connectionStatus |
| LastConnection | lastConnection |
| LastConnectionIP | lastConnectionIp |
| LastDisconnection | lastDisconnection |
| LastDisconnectionReason | lastDisconnectionReason |
| WebProtectionActive | webProtectionActive |
| FullDiskAccess | fullDiskAccess |
| PendingPlan | pendingPlan |
| — | **insights** (missing) |
| — | **insightsStatsPass** (missing) |
| — | **insightsStatsUnknown** (missing) |
| — | **scorecard** (missing) |
| — | **insightsReport** (missing) |
| — | **insightsIssueCount** (missing) |
| — | **provisioningUDID** (missing) |

The fragment doesn't request these fields so they're silently dropped. `insightsStatsPass` and `insightsStatsUnknown` are notable — the SDK has `insightsStatsFail` but not the other two.

---

### ActionConfig (`action_configuration.go`)

**ActionConfigInput (Go) vs ActionConfigsInput (Schema)**

| Go struct fields | Schema fields |
|---|---|
| Name | name |
| Description | description |
| AlertConfig | alertConfig |
| Clients | clients |

Status: Perfect match.

**ActionConfig response (Go) vs ActionConfigs type (Schema)**

| Go struct fields | Schema fields |
|---|---|
| ID | id |
| Name | name |
| Description | description |
| Hash | hash |
| Created | created |
| Updated | updated |
| AlertConfig | alertConfig |
| Clients | clients |
| — | **plans** (missing) |

---

### ExceptionSet (`exception_set.go`)

**ExceptionInput (Go) vs ExceptionInput (Schema)**

| Go struct fields | Schema fields |
|---|---|
| Type | type |
| Value | value |
| AppSigningInfo | appSigningInfo |
| IgnoreActivity | ignoreActivity |
| AnalyticTypes | analyticTypes |
| AnalyticUuid | analyticUuid |

Status: Perfect match.

**EsExceptionInput (Go) vs EsExceptionInput (Schema)**

| Go struct fields | Schema fields |
|---|---|
| Type | type |
| Value | value |
| AppSigningInfo | appSigningInfo |
| IgnoreActivity | ignoreActivity |
| IgnoreListType | ignoreListType |
| IgnoreListSubType | ignoreListSubType |
| EventType | eventType |

Status: Perfect match.

**Exception response (Go) vs Exception type (Schema)**

| Go struct fields | Schema fields |
|---|---|
| Type | type |
| Value | value |
| AppSigningInfo | appSigningInfo |
| IgnoreActivity | ignoreActivity |
| AnalyticTypes | analyticTypes |
| AnalyticUuid | — _(not in schema response, only in input)_ |
| Analytic | analytic |
| — | **exceptionSet** (missing) |
| — | **created** (missing) |
| — | **updated** (missing) |

**EsException response (Go) vs EsException type (Schema)**

| Go struct fields | Schema fields |
|---|---|
| Type | type |
| Value | value |
| AppSigningInfo | appSigningInfo |
| IgnoreActivity | ignoreActivity |
| IgnoreListType | ignoreListType |
| IgnoreListSubType | ignoreListSubType |
| EventType | eventType |
| — | **exceptionSet** (missing) |
| — | **created** (missing) |
| — | **updated** (missing) |

---

### User (`user.go`)

**UserInput (Go) vs UserCreateInput / UserUpdateInput (Schema)**

| Go struct fields | Schema (create) | Schema (update) |
|---|---|---|
| Email | email | — |
| RoleIDs | roleIds | roleIds |
| GroupIDs | groupIds | groupIds |
| ConnectionID | connectionId | — |
| ReceiveEmailAlert | receiveEmailAlert | receiveEmailAlert |
| EmailAlertMinSeverity | emailAlertMinSeverity | emailAlertMinSeverity |

Status: Perfect match for both create and update.

**User response (Go) vs User type (Schema)**

| Go struct fields | Schema fields |
|---|---|
| ID | id |
| Email | email |
| Sub | sub |
| Connection | connection |
| AssignedRoles | assignedRoles |
| AssignedGroups | assignedGroups |
| LastLogin | lastLogin |
| Source | source |
| ReceiveEmailAlert | receiveEmailAlert |
| EmailAlertMinSeverity | emailAlertMinSeverity |
| ExtraAttrs | extraAttrs |
| Created | created |
| Updated | updated |

Status: Perfect match.

---

### Group (`group.go`)

**GroupInput (Go) vs GroupCreateInput / GroupUpdateInput (Schema)**

| Go struct fields | Schema (create) | Schema (update) |
|---|---|---|
| Name | name | name |
| ConnectionID | connectionId | — |
| AccessGroup | accessGroup | accessGroup |
| RoleIDs | roleIds | roleIds |

Status: Perfect match for both create and update.

**Group response (Go) vs Group type (Schema)**

| Go struct fields | Schema fields |
|---|---|
| ID | id |
| Name | name |
| Connection | connection |
| AssignedRoles | assignedRoles |
| AccessGroup | accessGroup |
| Created | created |
| Updated | updated |

Status: Perfect match.

---

### Connection / Identity Provider (`identity_provider.go`)

**Connection response (Go) vs Connection type (Schema)**

| Go struct fields | Schema fields |
|---|---|
| ID | id |
| Name | name |
| RequireKnownUsers | requireKnownUsers |
| Button | button |
| Created | created |
| Updated | updated |
| Strategy | strategy |
| GroupsSupport | groupsSupport |
| Source | source |

Status: Perfect match.

Note: Schema supports full CRUD (`getConnection`, `createConnection`, `updateConnection`, `deleteConnection`) but SDK only implements `ListConnections`.

---

### Role (`role.go`)

**RoleInput (Go) vs RoleInput (Schema)**

| Go struct fields | Schema fields |
|---|---|
| Name | name |
| ReadResources | readResources |
| WriteResources | writeResources |

Status: Perfect match.

**Role response (Go) vs Role type (Schema)**

| Go struct fields | Schema fields |
|---|---|
| ID | id |
| Name | name |
| Permissions | permissions |
| Created | created |
| Updated | updated |

Status: Perfect match.

---

### TelemetryV2 (`telemetry_v2.go`)

**TelemetryV2Input (Go) vs TelemetryInputV2 (Schema)**

| Go struct fields | Schema fields |
|---|---|
| Name | name |
| Description | description |
| LogFiles | logFiles |
| LogFileCollection | logFileCollection |
| PerformanceMetrics | performanceMetrics |
| Events | events |
| FileHashing | fileHashing |

Status: Perfect match.

**TelemetryV2 response (Go) vs TelemetryV2 type (Schema)**

| Go struct fields | Schema fields |
|---|---|
| ID | id |
| Name | name |
| Description | description |
| Created | created |
| Updated | updated |
| LogFiles | logFiles |
| LogFileCollection | logFileCollection |
| PerformanceMetrics | performanceMetrics |
| Plans | plans |
| Events | events |
| FileHashing | fileHashing |

Status: Perfect match.

---

### RemovableStorageControlSet (`removable_storage_control_set.go`)

**RemovableStorageControlSetInput (Go) vs USBControlSetInput (Schema)**

| Go struct fields | Schema fields |
|---|---|
| Name | name |
| Description | description |
| DefaultMountAction | defaultMountAction |
| DefaultMessageAction | defaultMessageAction |
| Rules | rules |

Status: Perfect match.

**RemovableStorageControlRuleInput (Go) vs USBControlRuleInput (Schema)**

| Go struct fields | Schema fields |
|---|---|
| Type | type |
| EncryptionRule | encryptionRule |
| VendorRule | vendorRule |
| SerialRule | serialRule |
| ProductRule | productRule |

Status: Perfect match.

---

### DataForwarding (`data_forwarding.go`)

**ForwardS3Input (Go) vs OrganizationS3ForwardInput (Schema)**

| Go struct fields | Schema fields |
|---|---|
| Bucket | bucket |
| Enabled | enabled |
| Encrypted | encrypted |
| Prefix | prefix |
| Role | role |

Status: Perfect match.

**ForwardSentinelInput (Go) vs OrganizationSentinelForwardInput (Schema)**

| Go struct fields | Schema fields |
|---|---|
| Enabled | enabled |
| CustomerID | customerId |
| SharedKey | sharedKey |
| LogType | logType |
| Domain | domain |

Status: Perfect match.

**ForwardSentinelV2Input (Go) vs OrganizationSentinelV2ForwardInput (Schema)**

| Go struct fields | Schema fields |
|---|---|
| Enabled | enabled |
| AzureTenantID | azureTenantId |
| AzureClientID | azureClientId |
| AzureClientSecret | azureClientSecret |
| Endpoint | endpoint |
| Alerts | alerts |
| ULogs | ulogs |
| Telemetries | telemetries |
| TelemetriesV2 | telemetriesV2 |

Status: Perfect match.

**DataStreamInput (Go) vs DataStreamInput (Schema)**

| Go struct fields | Schema fields |
|---|---|
| Enabled | enabled |
| DcrImmutableID | dcrImmutableId |
| StreamName | streamName |

Status: Perfect match.

**ForwardS3 response (Go) vs ForwardS3 type (Schema)**

| Go struct fields | Schema fields |
|---|---|
| Bucket | bucket |
| Enabled | enabled |
| Encrypted | encrypted |
| Prefix | prefix |
| Role | role |
| CloudFormation | cloudformation |

Status: Perfect match.

---

### DataRetention (`data_retention.go`)

**DataRetentionInput (Go) vs OrganizationRetentionInput (Schema)**

| Issue | Detail |
|---|---|
| **Structural simplification** | Go SDK uses a flat input (`DatabaseLogDays`, `DatabaseAlertDays`, `ColdAlertDays`) while the schema uses deeply nested inputs (`OrganizationRetentionInput` > `OrganizationRetentionInputs` > `DbStorageRetentionInput` / `ColdStorageRetentionInput` > `RecordCountInput` / `ColdStorageSettingsInput`). This is an acceptable SDK-side simplification — the mutation handler builds the nested structure. |

**DataRetentionSettings response (Go) vs Retention type (Schema)**

| Issue | Detail |
|---|---|
| **Missing field** | Schema `DbStorageRetention` contains `RecordCount` with both `recordCount` and `numberOfDays`. SDK `DataRetentionDays` only maps `numberOfDays`. The `recordCount` field (actual record count in storage) is dropped. |

---

### AnalyticSet (`analytic_set.go`)

Status: Perfect match on both input and response types. All fields aligned.

---

### CustomPreventList (`custom_prevent_list.go`)

Status: Perfect match on both input and response types. All fields aligned.

---

### UnifiedLoggingFilter (`unified_logging_filter.go`)

Status: Perfect match on both input and response types. All fields aligned.

---

### ApiClient (`api_client.go`)

Status: Perfect match on both input and response types. All fields aligned.

---

### ChangeManagement (`change_management.go`)

Status: Perfect match. Uses `getAppInitializationData` to read `configFreeze` and `updateOrganizationConfigFreeze` to set it.

---

### Downloads (`downloads.go`)

Status: Perfect match. `OrganizationDownloads` and `VanillaPackage` structs align with schema.

---

## Part 2: Inconsistency Summary

### Resources with field gaps

| Resource | Missing Input Fields | Missing Response Fields |
|---|---|---|
| **Plan** | `threatPreventionStrategy`, `customEngineConfig` | `uuid`, `profileVersion`, `analytics`, `threatPreventionStrategy`, `customEngineConfig` |
| **Analytic** | `label`, `longDescription`, `startup`, `remediation`, `matchReason` | `hash`, `startup`, `udm`, `exceptions`, `matchReason`, `osVersion`, `extVersion`, `plans`, `analyticSets` |
| **Computer** | _(read-only)_ | `insights`, `insightsStatsPass`, `insightsStatsUnknown`, `scorecard`, `insightsReport`, `insightsIssueCount`, `provisioningUDID` |
| **ActionConfig** | — | `plans` |
| **Exception** | — | `exceptionSet`, `created`, `updated` |
| **EsException** | — | `exceptionSet`, `created`, `updated` |
| **DataRetention** | — | `recordCount` on `DbStorageRetention` |

### Resources with perfect schema alignment

- User
- Group
- Role
- Connection (response type — but missing CRUD methods)
- TelemetryV2
- RemovableStorageControlSet
- DataForwarding
- AnalyticSet
- CustomPreventList
- UnifiedLoggingFilter
- ApiClient
- ChangeManagement
- Downloads

### Design notes

- `data_retention.go`: Uses flat input structure where schema is nested. Acceptable simplification — the mutation handler builds the nested structure.
- `plan.go`: `TelemetryV2Null` flag is a helper for conditional nulling. Not in schema; reasonable SDK addition.

---

## Part 3: Unimplemented Schema Operations

### High-Value CRUD Gaps (Configurable Resources)

| Resource | Schema Operations | Status |
|---|---|---|
| **Connection** | get, create, update, delete | Only `list` implemented |
| **Telemetry v1** | full CRUD + list | Not implemented at all |
| **Computer** (write) | `createOrUpdateComputer`, `updateComputer`, `deleteComputer`, `setComputerPlan` | Only read (get/list) implemented |
| **Insight** | `listInsights`, `listInsightComputers`, `listInsightsCounts`, `updateInsightStatus` | Not implemented |
| **setPlanAnalytics** | Directly set analytics on a plan | Not implemented |

### Alert Operations (Read/Update)

| Operation | Description |
|---|---|
| `getAlert` | Get single alert by UUID |
| `listAlerts` | List/filter alerts with pagination |
| `updateAlerts` | Bulk update alert status |
| `getAlertsMetadata` | Count + min timestamp |
| `getAlertStatusCounts` | Counts by status |
| `listAlertsAnalytics` | Analytics that triggered alerts |
| `listAlertsEvents` | Event types in alerts |
| `listAlertsNames` | Alert names |
| `listAlertsTags` | Tags on alerts |
| `listAlertsTimeSeries` | Alert volume over time |
| `listAlertsContextValues` | Context value facets |
| `listAlertsEventValues` | Event value facets |

Alerts are the core security output of Protect. No alert operations exist in the SDK.

### Computer Diagnostic / Fleet Queries

| Operation | Description |
|---|---|
| `listComputersAlertCounts` | Alert counts per computer |
| `listComputersStats` | Fleet stats by field |
| `listComputersTags` | All tags in use |
| `listRiskiestComputers` | Computers ranked by risk |
| `getComputerCount` | Filtered count |
| `requestComputerTimeline` | Request timeline download URL |

### Compliance / Insights

| Operation | Description |
|---|---|
| `getFleetComplianceBaselineScore` | Fleet-wide compliance score |
| `getComputerComplianceBaselineScore` | Per-computer compliance score |
| `listFleetComplianceBaselineScores` | Historical compliance scores |
| `listInsights` | All insight definitions |
| `listInsightComputers` | Computers affected by an insight |
| `listInsightsCounts` | Pass/fail counts per benchmark |
| `updateInsightStatus` | Enable/disable an insight |

### Audit Logs

| Operation | Description |
|---|---|
| `listAuditLogsByDate` | Audit logs filtered by date range |
| `listAuditLogsByOp` | Audit logs filtered by operation |
| `listAuditLogsByUser` | Audit logs filtered by user |

### Organization / Tenant

| Operation | Description |
|---|---|
| `getOrganization` | Full org object (SDK only uses it indirectly for data forwarding/retention) |
| `getTenantServiceInfo` | Tenant service environment info |
| `getCurrentPermissions` | Current API client's RBAC permissions |
| `getCount` | Aggregated counts (computers, alerts, etc.) |
| `listThreatPreventionVersions` | Available TP signature versions |

### Miscellaneous

| Operation | Description |
|---|---|
| `generateUninstallerToken` | Generate agent uninstaller token |
| `sendCheckinMessage` | Force computer check-in |
| `sendUninstallMessage` | Send uninstall command |
| `updateInstallerUuid` | Rotate installer UUID |
| `updateBetaAcceptanceStatus` | Accept beta features |
| `updateSlasaAcceptance` | Accept SLASA terms |
| `updateInternalAnalytic` | Update tenant overrides on Jamf-managed analytics |
| `getUserSettings` / `updateUserUxSettings` | User UI preferences |
| `getLoginStateToken` | SSO state token |
| `getApiClientAltairConfig` | GraphQL IDE config |
| `listAnalyticsCategories` / `listAnalyticsTags` | Facet queries for analytics |
| `listUnifiedLoggingFilterTags` | Facet query for ULF tags |

---

## Part 4: Coverage Summary

| Category | Schema | Implemented | Coverage |
|---|---|---|---|
| **Queries** | ~73 | ~22 | ~30% |
| **Mutations** | ~62 | ~19 | ~31% |
| **Full CRUD resources** | 17 | 14 | 82% |

**Resources with complete CRUD:** ActionConfig, Analytic, AnalyticSet, ApiClient, CustomPreventList, ExceptionSet, Group, Plan, RemovableStorageControlSet, Role, TelemetryV2, UnifiedLoggingFilter, User (13 resources)

**Resources with partial implementation:** Computer (read-only), Connection (list-only), DataForwarding (get/update), DataRetention (get/update), ChangeManagement (get/update), Downloads (get-only)

**Entirely missing resource domains:** Alerts, Audit Logs, Insights/Compliance, Telemetry v1, Fleet Statistics

---

## Part 5: Recommendations (Priority Order)

1. **Fix field gaps in Plan** — `threatPreventionStrategy` and `customEngineConfig` are actively used features that SDK consumers can't manage
2. **Fix field gaps in Analytic** — `label`, `longDescription`, `startup`, `remediation`, `matchReason` missing from input
3. **Add Connection CRUD** — only list exists, schema supports full lifecycle
4. **Add Alert operations** — alerts are the primary security output; at minimum `listAlerts`, `getAlert`, `updateAlerts`
5. **Add Computer write operations** — `setComputerPlan`, `updateComputer` (tags/label), `deleteComputer`
6. **Add Insight/Compliance queries** — compliance scoring is a key Protect feature
7. **Backfill missing Computer response fields** — especially `insightsStatsPass`, `insightsStatsUnknown`, `provisioningUDID`
8. **Audit Logs** — valuable for automation/compliance workflows
9. **Telemetry v1** — lower priority if it's being superseded by v2, but schema still exposes it

---

## Part 6: Implementation Progress

Tracked as of 2026-04-11 on branch `feature/plug-resource-field-gaps`.

### Completed

| Change | Commit |
|---|---|
| Plan: add `threatPreventionStrategy`, `customEngineConfig`, `uuid`, `profileVersion` | `69a7b44` |
| Analytic: add `label`, `longDescription`, `startup`, `remediation`, `matchReason` to input; `hash`, `startup`, `matchReason` to response | `69a7b44` |
| Computer: add `insightsStatsPass`, `insightsStatsUnknown`, `provisioningUDID` to response | `69a7b44` |
| ActionConfig: add `plans` reference to response | `69a7b44` |
| ExceptionSet: add `created`, `updated` to Exception and EsException responses | `69a7b44` |
| DataRetention: add `recordCount` to response | `69a7b44` |
| Computer: add `SetComputerPlan`, `UpdateComputer` methods | `69a7b44` |
| Alerts: `GetAlert`, `ListAlerts`, `UpdateAlerts` | `b687baf` |
| Alerts: `GetAlertStatusCounts` | `12c3639` |
| Computer: `DeleteComputer` | `295fae9` |
| Insights/Compliance: `ListInsights`, `UpdateInsightStatus`, `ListInsightComputers`, `GetFleetComplianceScore` | `b3b235b` |

### Remaining — CLI-Prioritized Backlog

#### High Value (directly actionable from a terminal)

| Operations | Schema | CLI Use Case |
|---|---|---|
| `listAuditLogsByDate`, `listAuditLogsByOp`, `listAuditLogsByUser` | Query | `protect audit-logs list` — who changed what, when. Essential for MSP compliance and change tracking. Needs browser captures for filter types. |
| `generateUninstallerToken` | Query | `protect computers uninstaller-token --uuid <uuid>` — generate agent uninstall token without visiting the UI |
| `sendCheckinMessage` | Mutation | `protect computers checkin --uuid <uuid>` — force a computer to check in |
| `sendUninstallMessage` | Mutation | `protect computers uninstall --uuid <uuid>` — remote agent uninstall |
| `getCurrentPermissions` | Query | `protect auth permissions` — show what the current API client can do. Debugging gold for MSPs setting up new clients. |

#### Medium Value (dashboard/overview enrichment)

| Operations | Schema | CLI Use Case |
|---|---|---|
| `listRiskiestComputers` | Query | `protect computers riskiest` — top N computers by risk score |
| `getComputerCount` | Query | Quick fleet size without pulling all records |
| `getCount` | Query | Aggregated counts (computers, alerts, etc.) for overview dashboard |
| `getTenantServiceInfo` | Query | Tenant environment info for `protect overview` or `protect auth info` |

#### Low Value (defer)

| Operations | Reason |
|---|---|
| Telemetry v1 full CRUD | Being superseded by v2, already implemented |
| `listComputersStats`, `listComputersTags` | Facet queries, more useful for building UIs than CLI workflows |
| `getComputerComplianceBaselineScore` | Per-computer compliance — niche, add when needed |
| Alert facet queries (`listAlertsAnalytics`, `listAlertsEvents`, `listAlertsNames`, `listAlertsTags`, `listAlertsTimeSeries`, `listAlertsContextValues`, `listAlertsEventValues`) | Dashboard/chart data, not CLI workflows |
