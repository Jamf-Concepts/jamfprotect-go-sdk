# Static-file audit — `tools/generate/_static/`

Goal: per-file verdict on whether each file can move into the dynamic generator (config.json + `resource.go.tmpl`) or must stay static-emitted.

Verdict legend:
- **KEEP-STATIC** — genuine one-off, no reasonable templating path.
- **GENERATABLE** — small config delta only, template already supports it.
- **GEN-WITH-TEMPLATE-CHANGE** — needs N specific additions to `ResourceConfig`/`OperationConfig`/template.

Ordered small → large.

> **Caveat:** every `schemaName` / `gqlTypeName` in the sketched config entries below was **inferred from the existing Go source**, not verified against `testing/schema.graphql`. Names like `OrganizationDatabaseRetention`, `RetentionDaysCount`, `EventTypeAlertConfig`, `USBControlSetInput`, `ProfileOptionsInput`, and the discriminator field on `USBControlRuleInput` must be cross-checked against the schema before any of these sketches are turned into working config. Mismatches will surface as "schema type not found" at generator runtime.

---

## 1. `errors.go` (17 lines) — **KEEP-STATIC**

Contains: re-exports `ErrAuthentication`, `ErrGraphQL`, `ErrNotFound` from `internal/client`.

Why static today: not a resource. No GQL, no types, no methods. Just three `var` aliases at package scope. Template is `package → constants → input types → response types → methods` — no place for raw aliases.

Verdict: **KEEP-STATIC.** Cheapest possible form already. Templating gains nothing.

---

## 2. `doc.go` (29 lines) — **KEEP-STATIC**

Contains: package godoc with the `package jamfprotect` declaration.

Why static today: prose-only file used by Go for package docs. Nothing schema-derived.

Verdict: **KEEP-STATIC.** Codegen has no input to vary it on.

---

## 3. `types.go` (32 lines) — **KEEP-STATIC**

Contains: `Logger` interface, `TokenCache` interface, `Token` struct. Public extension points consumed by hand-written `client.go`.

Why static today: not schema-bound. Tied to the transport contract, not any GQL type.

Verdict: **KEEP-STATIC.** Edits here should be hand-driven alongside `client.go`.

---

## 4. `rbac.go` (51 lines) — **KEEP-STATIC** (with note)

Contains: five `map[string]any` RBAC flag tables (`rbacUser`, `rbacGroup`, `rbacComputer`, `rbacPlan`, `rbacAnalytic`) plus the `mergeVars` helper.

Why static today: resource config already references map names via `rbacMap: "rbacPlan"`, but the maps themselves are cross-resource constants. Template emits per-file content; package-level shared maps don't fit the per-resource shape. `mergeVars` imports `maps` which the template doesn't.

Could-be-generated path: add top-level `rbacMaps map[string]map[string]bool` to `Config`, add a second tiny template (`rbac.go.tmpl`) emitted once. Cost: new emit path, new template, validation that resource `rbacMap` names exist in the table. Benefit: removes one cross-resource duplication.

Verdict: **KEEP-STATIC** for now. Worth revisiting only if a third or fourth cross-resource shared file appears.

> Cleanup note: `rbacAnalytic` in this file is currently unused by any resource. One-line delete, orthogonal to this audit.

---

## 5. `audit_log_helpers.go` (91 lines) — **KEEP-STATIC**

Contains: `MaxAuditLogDays` const, `AuditLogDateRange` type, `auditLogCondition` clamp helper, `fetchAllAuditLogs` method on `Client` (custom cursor loop using `transport.DoGraphQL` directly).

Why static today: the 7-day date clamp + bespoke pagination loop (no `pageInfo.next` consistency with `client.ListAll`) is one-off business logic. The `audit_log.go` resource (kind `date_paginated`) covers the typed surface; this file holds the operations the kind-handler ultimately calls into.

Verdict: **KEEP-STATIC.** Reusing-once helper code, no reuse anywhere else.

> Side note (orthogonal): `fetchAllAuditLogs` is structurally `client.ListAll` with a date-range cursor instead of a generic `next` cursor. If `internal/client` grew a `ListAllByDate` generic helper, this file would shrink to ~30 lines. Doesn't change the static-vs-generated verdict.

---

## 6. `dashboard.go` (124 lines) — **GEN-WITH-TEMPLATE-CHANGE** (low priority)

Contains: 3 queries (`getCount`, `getComputerCount`, `listRiskiestComputers`), 4 response types (`CountResponse`, `RiskyComputer`, `RiskyComputerRef`, `RiskyComputerAlerts`), 3 Client methods.

Why static today:
- `getCount` always passes `input: {}` (empty input wrapper) — no current kind builds that for a query with no args.
- `listRiskiestComputers` returns `{items: [T]}` (no `pageInfo`, no pagination). Current `list_simple` returns `[T]` directly; current paginated `list` requires `pageInfo`. No kind matches.
- `RiskyComputer.AlertCounts` is a slice of a sub-struct that's only used by this query.

Template additions needed:
1. New kind `list_items` (or extend `list_simple` with `useItemsWrapper: true`): emits `field { items { ... } }` and unwraps `.items` without pagination.
2. `singleton_get` already covers `getCount` and `getComputerCount` once you allow `forceEmptyInput: true` (pass `{input: {}}`) — or just sidestep with `inlineArgs: []` + a new `wrapInEmptyInput` flag.

Sketch config (3 entries or 1 with `extraResponseTypes`):

```json
{
  "file": "dashboard.go",
  "typeName": "CountResponse",
  "fields": ["computers", "alerts", "alertsComputers", "insightsComputers"],
  "nullableResponseFields": ["computers", "alerts", "alertsComputers", "insightsComputers"],
  "extraResponseTypes": [
    {"goName": "RiskyComputer", "schemaName": "...", "fields": ["computer", "alertCounts"]},
    {"goName": "RiskyComputerRef", "schemaName": "Computer", "fields": ["uuid", "hostName", "serial"]},
    {"goName": "RiskyComputerAlerts", "schemaName": "...", "fields": ["severity", "count"]}
  ],
  "operations": [
    {"name": "GetCount", "gqlName": "getCount", "kind": "singleton_get", "wrapInEmptyInput": true, ...},
    {"name": "GetComputerCount", "gqlName": "getComputerCount", "kind": "singleton_get", "resultPath": "getComputerCount.computers", "returnType": "int64", ...},
    {"name": "ListRiskiestComputers", "gqlName": "listRiskiestComputers", "kind": "list_items", "returnType": "RiskyComputer", "inlineArgs": [{"name": "limit", "goType": "int", "gqlVar": "limit", "gqlType": "Int", "isOptional": true}, {"name": "createdInterval", "goType": "string", "gqlVar": "createdInterval", "gqlType": "String", "isOptional": true}], ...}
  ]
}
```

Verdict: **GEN-WITH-TEMPLATE-CHANGE.** Modest payoff (124 lines, 3 unique methods). Defer unless the new `list_items` kind is justified by another resource.

---

## 7. `data_retention.go` (129 lines) — **GEN-WITH-TEMPLATE-CHANGE**

Contains: get + update on `Organization.retention`. Response types `DataRetentionDays`, `DataRetentionDatabase`, `DataRetentionCold`, `DataRetentionSettings`. Input `DataRetentionInput{DatabaseLogDays, DatabaseAlertDays, ColdAlertDays}`. Update mutation hand-crafts a deeply-nested input literal mapping each scalar to `retention.database.log.numberOfDays` / `retention.database.alert.numberOfDays` / `retention.cold.alert.numberOfDays`.

Why static today:
- Read side fits `singleton_get` + `resultPath: "getOrganization.retention"` — already supported.
- Write side is the blocker. `singleton_update` builds `input: {gqlVar: $gqlVar, ...}` flat. No mechanism to nest a primitive arg into a multi-level input literal.

Template additions needed:
1. Extend `InlineArg` with `inputPath` (dot-path into the GQL input object). When set, the mutation builder emits the nested literal: `input: {retention: {database: {log: {numberOfDays: $databaseLogDays}, alert: {numberOfDays: $databaseAlertDays}}, cold: {alert: {numberOfDays: $coldAlertDays}}}}`. Build by walking each arg's `inputPath`, merging into a map, then printing the literal.
2. Allow `singleton_update` to skip ID arg (already supported via `inlineArgs[].isId` semantics — none of the args have `isId: true` here, so it should already skip).

Sketch:
```json
{
  "file": "data_retention.go",
  "typeName": "DataRetentionSettings",
  "gqlTypeName": "OrganizationRetention",
  "fields": ["database", "cold", "updated"],
  "nestedTypes": [
    {"schemaName": "OrganizationDatabaseRetention", "goName": "DataRetentionDatabase", "fields": ["log", "alert"]},
    {"schemaName": "OrganizationColdRetention", "goName": "DataRetentionCold", "fields": ["alert"]},
    {"schemaName": "RetentionDaysCount", "goName": "DataRetentionDays", "fields": ["recordCount", "numberOfDays"]}
  ],
  "operations": [
    {"name": "GetDataRetention", "gqlName": "getOrganization", "kind": "singleton_get", "resultPath": "getOrganization.retention", "resultKey": "getOrganization", ...},
    {"name": "UpdateDataRetention", "gqlName": "updateOrganizationRetention", "kind": "singleton_update", "resultPath": "updateOrganizationRetention.retention",
      "inlineArgs": [
        {"name": "databaseLogDays", "goType": "int64", "gqlVar": "databaseLogDays", "gqlType": "Int!", "inputPath": "retention.database.log.numberOfDays"},
        {"name": "databaseAlertDays", "goType": "int64", "gqlVar": "databaseAlertDays", "gqlType": "Int!", "inputPath": "retention.database.alert.numberOfDays"},
        {"name": "coldAlertDays", "goType": "int64", "gqlVar": "coldAlertDays", "gqlType": "Int!", "inputPath": "retention.cold.alert.numberOfDays"}
      ]}
  ]
}
```

Also need a way to wrap the three primitive Go args into a single `DataRetentionInput` struct for the Go signature (today inline args go straight on the method). Add `groupInputAs: "DataRetentionInput"` on the operation.

Verdict: **GEN-WITH-TEMPLATE-CHANGE.** Two new knobs (`inputPath`, `groupInputAs`). Worth doing because the same pattern reappears in `data_forwarding.go` and partly in `plan.go`'s profile-options.

---

## 8. `data_forwarding.go` (249 lines) — **GEN-WITH-TEMPLATE-CHANGE**

Contains: get + update on `Organization.forward`. Big nested response (`ForwardS3`, `ForwardSentinel`, `ForwardSentinelV2` with sub-`DataStream`). Multiple flat input structs (`ForwardS3Input`, `ForwardSentinelInput`, `DataStreamInput`, `ForwardSentinelV2Input`, `DataForwardingInput`). Update mutation declares **three top-level wrapped inputs**: `$s3: OrganizationS3ForwardInput!, $sentinel: ..., $sentinelV2: ...` and passes them as `input: {s3: $s3, sentinel: $sentinel, sentinelV2: $sentinelV2}`.

Why static today:
- Existing `wrappedInput: true` supports only **one** input variable named `$input`. No mechanism for multiple named wrapped inputs.
- Nested input types (`DataStreamInput` used by 4 different parent input fields) need de-duplication: today nested types come from the schema's input types. Generator can already follow input-type references — confirm by checking schema scope.

Template additions needed:
1. New `multiWrappedInputs` on `OperationConfig`:
   ```json
   "multiWrappedInputs": [
     {"goField": "S3",         "gqlVar": "s3",         "inputType": "OrganizationS3ForwardInput",         "goInputType": "ForwardS3Input"},
     {"goField": "Sentinel",   "gqlVar": "sentinel",   "inputType": "OrganizationSentinelForwardInput",   "goInputType": "ForwardSentinelInput"},
     {"goField": "SentinelV2", "gqlVar": "sentinelV2", "inputType": "OrganizationSentinelV2ForwardInput", "goInputType": "ForwardSentinelV2Input"}
   ]
   ```
   Generator emits `$s3: T!, $sentinel: T!, $sentinelV2: T!` decls, `input: {s3: $s3, sentinel: $sentinel, sentinelV2: $sentinelV2}` body, and a `DataForwardingInput` Go struct with the three goField/goInputType members.

2. Generator already supports input-type recursion for nested input shapes (used by Analytic, ExceptionSet, Plan).

Sketch resource: similar shape to data_retention with `gqlTypeName: "Organization"`, plus `nullableResponseFields: ["dcrImmutableId", "streamName"]` for the DataStream pointer fields, plus the `multiWrappedInputs` op above. Get is `singleton_get` with `resultPath: "getOrganization"`.

Verdict: **GEN-WITH-TEMPLATE-CHANGE.** Bigger payoff than data_retention (249 lines). The `multiWrappedInputs` knob is narrow but the `dataRetentionFragment` / nested-input-types machinery is already there. Real cost is the multi-wrapped input plumbing and verifying nested input recursion handles the depth.

---

## 9. `removable_storage_control_set.go` (263 lines) — **GEN-WITH-TEMPLATE-CHANGE**

Contains: standard CRUD shape. One wrinkle: `Rules` is a GraphQL **union** (`... on VendorRule | SerialRule | ProductRule`) flattened in the Go response into a single `RemovableStorageControlRule` struct. Input uses a tagged-variant struct (`RemovableStorageControlRuleInput` with `*VendorRule`, `*SerialRule`, `*ProductRule`, `*EncryptionRule` pointer fields, `Type` discriminator).

Why static today:
- Template can emit a fragment ref or an inline scalar field list. No support for **inline-fragment selections** (`... on VariantType`).
- Nested response struct merging — the union's per-variant fields (`vendors`, `serials`, `products`) get unified into one Go struct. No config knob for "merge these variants into struct X".
- Tagged-variant Go input emission isn't supported either.

Template additions needed:
1. New `unionField` on `NestedTypeConfig` (or on the resource for top-level union fields):
   ```json
   "unionFields": {
     "rules": {
       "common": ["mountAction", "messageAction", "type"],
       "variants": {
         "VendorRule":  ["vendors", "applyTo"],
         "SerialRule":  ["serials", "applyTo"],
         "ProductRule": ["products { vendor product }", "applyTo"]
       },
       "goStruct": "RemovableStorageControlRule"
     }
   }
   ```
   Emits the inline-fragment selection and the merged Go struct.

2. New `taggedInputVariants` knob to emit the input struct with discriminator + pointer-variant fields:
   ```json
   "taggedInputVariants": [
     {"goName": "RemovableStorageControlRuleInput", "discriminator": "Type",
      "variants": {
        "VendorRule":     {"goField": "VendorRule",     "goType": "RemovableStorageControlRuleDetails"},
        "SerialRule":     {"goField": "SerialRule",     "goType": "RemovableStorageControlRuleDetails"},
        "ProductRule":    {"goField": "ProductRule",    "goType": "RemovableStorageControlProductRuleDetails"},
        "EncryptionRule": {"goField": "EncryptionRule", "goType": "RemovableStorageControlRuleDetails"}
      }}
   ]
   ```

Sketch:
```json
{
  "file": "removable_storage_control_set.go",
  "typeName": "RemovableStorageControlSet",
  "gqlTypeName": "USBControlSet",
  "fields": ["id", "name", "description", "defaultMountAction", "defaultMessageAction", "rules", "plans", "created", "updated"],
  "nestedTypes": [
    {"schemaName": "Plan", "goName": "RemovableStorageControlSetPlan", "fields": ["id", "name"]},
    /* RemovableStorageControlRule emitted by unionFields */
  ],
  "unionFields": { "rules": { ... see above ... } },
  "taggedInputVariants": [ ... see above ... ],
  "operations": [
    {"name": "CreateRemovableStorageControlSet", "gqlName": "createUSBControlSet", "kind": "create", "inputType": "USBControlSetInput", "inputTypeGoName": "RemovableStorageControlSetInput"},
    /* get / update / delete / list following Role's shape */
  ]
}
```

Verdict: **GEN-WITH-TEMPLATE-CHANGE.** Union support is a sizeable generator addition but is **reused by `action_configuration.go`** below — payoff is two files plus future-proofing for any other GraphQL union. Highest-leverage template change in the audit.

---

## 10. `action_configuration.go` (318 lines) — **GEN-WITH-TEMPLATE-CHANGE** (partial — likely keep static)

Contains: standard CRUD + 2 awkward shapes.

Awkward shape 1 — `AlertConfig` and `Clients` inputs are typed as `map[string]any` and `[]map[string]any`. The author punted on typed input modelling for the deeply-nested per-event-type attribute lists.

Awkward shape 2 — `clients[].params` is a GraphQL union (`... on JamfCloudClientParams | HttpClientParams | KafkaClientParams | SyslogClientParams | LogFileClientParams`). Same flat-merged Go-struct trick as USB rules.

Awkward shape 3 — `ActionConfigListItem` is a totally different (smaller) shape than `ActionConfig`. Existing `listItemFields` on the list op handles this, plus `returnType: "ActionConfigListItem"`.

Template additions needed:
1. Union support — same as USB (already counted as a shared template change).
2. Opaque-map input fields — new `mapInputFields` on `ResourceConfig`:
   ```json
   "mapInputFields": {
     "alertConfig": "map[string]any",
     "clients":     "[]map[string]any"
   }
   ```
   Emit those fields as `map[string]any` in the Go input struct and pass them straight through to `vars`.

Sketch:
```json
{
  "file": "action_configuration.go",
  "typeName": "ActionConfig",
  "gqlTypeName": "ActionConfigs",
  "fields": ["id", "name", "description", "hash", "created", "updated", "alertConfig", "clients", "plans"],
  "nestedTypes": [
    {"schemaName": "ActionConfigsAlertConfig", "goName": "AlertConfig", "fields": ["data"]},
    {"schemaName": "AlertConfigData", "goName": "AlertData", "fields": [...14 event types...]},
    {"schemaName": "EventTypeAlertConfig", "goName": "AlertEventType", "fields": ["attrs", "related"]},
    {"schemaName": "ReportClient", "goName": "ReportClient", "fields": ["id", "type", "supportedReports", "batchConfig", "params"]},
    {"schemaName": "BatchConfig", "goName": "BatchConfig", "fields": [...]},
    {"schemaName": "Plan", "goName": "ActionConfigPlan", "fields": ["id", "name"]}
  ],
  "unionFields": { "clients.params": { ... 5 variants → ReportClientParams ... }},
  "mapInputFields": {"alertConfig": "map[string]any", "clients": "[]map[string]any"},
  "extraResponseTypes": [
    {"goName": "ActionConfigListItem", "schemaName": "ActionConfigs", "fields": ["id", "name", "description", "created", "updated"]}
  ],
  "operations": [ /* create, get, update, delete with inputFields ["name","description"] + mapInputFields */
                  /* list with returnType: "ActionConfigListItem", listItemFields: [...] */ ]
}
```

Verdict: **GEN-WITH-TEMPLATE-CHANGE** in principle, **KEEP-STATIC** in practice. Reasoning: even with union support + map input fields, the typed input remains an escape hatch (`map[string]any`), which means callers gain no compile-time safety either way. Codegen of an opaque field saves trivial scaffolding only. Defer until the API team commits to a proper typed input schema for `alertConfig`/`clients`.

---

## 11. `plan.go` (506 lines) — **GEN-WITH-TEMPLATE-CHANGE** (highest value, highest cost)

Contains: standard 5-method CRUD + 1 bonus method `GetPlansConfigProfile`. Heavy nested response types (CustomEngineConfig, PlanCommsConfig, PlanInfoSync, PlanSignaturesFeed, PlanRef, PlanExceptionSet, PlanAnalyticSet, PlanAnalyticSetRef, PlanAnalytic). Custom `buildPlanVariables` with conditional includes and a special three-state `TelemetryV2Null`.

Why static today:
1. **Three-state field (`TelemetryV2Null`).** Today `optionalInputFields` collapses "nil and zero" into "omit". Plan distinguishes nil (omit), set (pass value), and an explicit "null sentinel" (pass `nil` to clear). No existing knob models this.
2. **Custom JSON-tagged nested input** (`buildPlanConfigProfileInput`). Maps `KeychainClientID` → `keychain_client_id` (underscored snake case differing from default lowerCamel). Nested input types built via `inputTypeRenames` don't carry per-field rename rules.
3. **Bonus method `GetPlansConfigProfile`** taking a struct-typed *optional* input arg (`*PlanConfigProfileOptionsInput`). Today `singleton_get` accepts only primitive `inlineArgs`. No way to declare a struct-typed Go arg that's marshalled into a nested input map.
4. The main CRUD fragment is large but flat — the existing template handles it once you list nested types.

Template additions needed:
1. **Tweak `optionalInputFields` buildVars emitter** to support the three-state form: when a field is listed in both `nullableInputFields` (so it's already `*T`) and a new `explicitNullInputFields` flag-set, add a companion `FieldNull bool` to the Go input struct and emit `if input.FieldNull { vars[gql] = nil } else if input.Field != nil { vars[gql] = *input.Field }`. This is a buildVars-body extension, not a fresh design surface — it composes with the existing optional/nullable knobs.
2. Per-field rename inside Go input structs: extend `inputTypeRenames` to take a map-of-maps (`{InputType → {GoField → "json_tag"}}`) **or** add an explicit `inputFieldRenames` knob. Open design question for whoever implements — both work; the sibling-map form is probably cleaner since `inputTypeRenames` already carries a different meaning (schema-name → Go-name remapping).
3. `extraMethods` on `ResourceConfig` — a list of one-off operations whose Go arg is a pointer to a struct that's separately defined under the resource (a sub-config like `extraInputType`). The generator emits a typed Go struct + a method that wraps it into a GQL input map. Alternative: extend `inlineArgs` to allow `goType: "*PlanConfigProfileOptionsInput"` with a sibling block defining how that struct marshals to GQL.

Sketch (abbreviated):
```json
{
  "file": "plan.go",
  "typeName": "Plan",
  "fields": [ /* 17 fields */ ],
  "nullableInputFields": ["logLevel", "telemetry", "telemetryV2", "usbControlSet", "customEngineConfig"],
  "explicitNullInputFields": ["telemetryV2"],
  "optionalInputFields": ["logLevel", "exceptionSets", "telemetry", "telemetryV2", "usbControlSet", "analyticSets", "threatPreventionStrategy", "customEngineConfig"],
  "nestedTypes": [ /* PlanCommsConfig, PlanInfoSync, PlanSignaturesFeed, CustomEngineConfig, PlanRef, PlanExceptionSet, PlanAnalyticSet, PlanAnalyticSetRef, PlanAnalytic */ ],
  "inputTypeRenames": { /* nested input type renames */ },
  "operations": [
    /* create, get, update, delete, list — standard */
    {
      "name": "GetPlansConfigProfile",
      "gqlName": "getPlansConfigProfile",
      "kind": "singleton_get",
      "returnType": "string",
      "structInputArg": {
        "goType": "*PlanConfigProfileOptionsInput",
        "gqlVar": "input",
        "gqlType": "ProfileOptionsInput",
        "fieldsToGQL": {
          "TokenOptions.XPC":               "tokenOptions.xpc",
          "TokenOptions.KeychainClientID":  "tokenOptions.keychain_client_id",
          "Sign":                            "sign",
          "PPPC":                            "pppc",
          "Token":                           "token",
          "CA":                              "ca",
          "CSR":                             "csr",
          "Websocket":                       "websocket",
          "SystemExtension":                 "systemExtension",
          "ServiceManagement":               "serviceManagement"
        }
      },
      "inlineArgs": [{"name": "id", "goType": "string", "gqlVar": "id", "gqlType": "ID!", "isId": true}]
    }
  ]
}
```

Verdict: **GEN-WITH-TEMPLATE-CHANGE.** Highest payoff in the audit (506 lines eliminated), but also the heaviest template work (three independent knobs). Best done **after** the union + multi-wrapped-input changes land, because some of the plumbing (struct-typed inline args, per-field input renames) overlaps with `action_configuration.go` and `data_forwarding.go`.

---

# Summary table

| File | Lines | Verdict | Generator work needed |
|---|---:|---|---|
| `errors.go` | 17 | KEEP-STATIC | none |
| `doc.go` | 29 | KEEP-STATIC | none |
| `types.go` | 32 | KEEP-STATIC | none |
| `rbac.go` | 51 | KEEP-STATIC | (optional second template; low value) |
| `audit_log_helpers.go` | 91 | KEEP-STATIC | none |
| `dashboard.go` | 124 | GEN-W/-TEMPLATE | new `list_items` kind + `wrapInEmptyInput` |
| `data_retention.go` | 129 | GEN-W/-TEMPLATE | `InlineArg.inputPath` (nested literal), `groupInputAs` |
| `data_forwarding.go` | 249 | GEN-W/-TEMPLATE | `multiWrappedInputs` |
| `removable_storage_control_set.go` | 263 | GEN-W/-TEMPLATE | union fragments + `taggedInputVariants` |
| `action_configuration.go` | 318 | GEN-W/-TEMPLATE (defer) | union fragments + `mapInputFields` |
| `plan.go` | 506 | GEN-W/-TEMPLATE | `explicitNullInputFields` (buildVars tweak) + input-field renames + struct-typed inline arg |

# Recommended sequencing

1. **Union/inline-fragment support** — retires `removable_storage_control_set.go` (263 lines). Future-proofs the generator for `action_configuration.go`'s `clients.params` union and any other GraphQL unions in the schema, even though ActionConfig itself is deferred for unrelated reasons (its typed input remains `map[string]any` regardless).
2. **`InlineArg.inputPath` + `multiWrappedInputs`** — together retire `data_retention.go` (129) and `data_forwarding.go` (249). Both build on nested-input-literal plumbing.
3. **Plan-specific knobs** (`explicitNullInputFields` buildVars tweak, input-field renames, struct-typed inline arg) — retire `plan.go` (506). Most code per step but lands last so it benefits from prior input-handling refactors.
4. Skip `dashboard.go` until it shares a kind with another resource.
5. Leave `errors.go`, `doc.go`, `types.go`, `rbac.go`, `audit_log_helpers.go` as static permanently.
6. ActionConfig (318) stays static until the API team types `alertConfig` / `clients` properly — generating opaque-map input fields buys nothing.

Total retire-able under above plan: ~1147 lines of static code (USB 263 + data_retention 129 + data_forwarding 249 + plan 506) moved into config, costing roughly 200 lines of generator additions.
