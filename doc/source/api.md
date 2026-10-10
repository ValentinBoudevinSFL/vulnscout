# REST API

VulnScout exposes a REST API served by the Flask backend, available at `http://localhost:7275/api/` by default.
Successful responses return JSON unless otherwise noted. Most routes are registered directly on the Flask application; the local agent API uses a blueprint with the same `/api` namespace. Some error responses (including Flask-generated errors) are plain text or HTML.

The backend also exposes a machine-readable OpenAPI document at `GET /api/openapi`.
For compatibility, the same document is also available at `GET /api` and `GET /api/openapi.json`.
An interactive Swagger UI is available at `GET /api/openapi/ui` and is preconfigured to load the canonical spec from `/api/openapi`.
This JSON document is generated from the registered Flask routes and is intended to be the canonical API specification for external tooling.
It is fully route-driven: every registered `GET`, `POST`, `PUT`, `PATCH`, and `DELETE` operation under `/api` is included, and operation descriptions and request metadata are inferred from route docstrings when available.
Inferred schemas and metadata are not exhaustive validation contracts; the request and response shapes below describe the implemented behavior.

Unless stated otherwise, successful reads and updates return `200 OK`. Routes protected by the initial-scan middleware return `503` with `{"error": "Scan not finished"}` during bootstrap. Version, scan status, OpenAPI, and the event stream remain available; the agent blueprint and routes registered with Flask's `get`/`post`/`patch` shortcuts do not use that middleware.

The default request-body limit is 5 MiB plus 64 KiB of multipart overhead; oversized requests return `413`. Scan JSON import has a separate 100 MiB limit. Individual upload endpoints may impose additional limits.

---

## Version & Status

### Get Server Version

```
GET /api/version
```

Returns the running VulnScout version.

**Response:**
```json
{ "version": "1.2.3" }
```

The value comes from the `VULNSCOUT_VERSION` environment variable (`"unknown"` when unset).

### Get Initial Scan Status

```
GET /api/scan/status
```

Returns the progress of the container entrypoint import script. This endpoint is available even while the import is still running.

**Response:**
```json
{
  "status": "running",
  "maxsteps": 8,
  "step": 3,
  "message": "Merging SBOMs"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | `"running"` or `"done"` |
| `maxsteps` | int | Total number of import steps |
| `step` | int | Current step number |
| `message` | string | Human-readable progress label |

---

## Config

### Get Current Config

```
GET /api/config
```

Returns the project matching `PROJECT_NAME` and its variant matching `VARIANT_NAME` (default: `"default"`). If no project matches, the first project in the database is returned, without selecting a fallback variant.

**Response:**
```json
{
  "project": { "id": "...", "name": "..." },
  "variant": { "id": "...", "name": "...", "project_id": "..." },
  "product_name": "",
  "author_name": "vulnscout",
  "client_name": "",
  "contact_email": "",
  "grype_memlimit": ""
}
```

`project` and `variant` may be `null`. The other values come from their uppercase environment variables; the example shows their defaults.

### Update Config

```
PATCH /api/config
```

Accepts any subset of `product_name`, `author_name`, `client_name`, `contact_email`, and `grype_memlimit`. Values must be strings or `null`; whitespace is trimmed, and an empty value or `null` removes the setting. `project` and `variant` are not writable here.

`contact_email` must be a valid email-shaped value when non-empty. `grype_memlimit` accepts integer bytes, a memory size such as `"4GiB"` or `"512MB"`, or `"off"` / `"disabled"`. Updates affect the running process and are persisted to `config.env`.

**Response:** Same shape as `GET /api/config`. `400` for unsupported keys or invalid values; `500` if persistence fails.

### Manage the NVD API Key

```
GET /api/config/nvd-api-key
PUT /api/config/nvd-api-key
```

`GET` returns `{"has_key": false, "masked_key": ""}` or the masked configured key; it never returns the full key.

`PUT` accepts `{"api_key": "..."}`. A non-empty key is probed against NVD before saving; an empty string removes it. Returns `{"status": "ok", "has_key": true, "masked_key": "..."}`, optionally with a `warning` if the probe returned a non-authentication error. `400` for invalid input or a rejected key, `503` if validation cannot reach NVD, and `500` if persistence fails.

---

## Projects

### List Projects

```
GET /api/projects
```

Returns all projects.

**Response:** JSON array of project objects.

### Create Project

```
POST /api/projects
```

**Request body:**
```json
{ "name": "my-project" }
```

**Response:** `201 Created` — serialized project. `400` for a missing, non-string, or blank name; `409 Conflict` if the name is already taken. Names are trimmed.

### Rename Project

```
PATCH /api/projects/<project_id>/rename
```

**Request body:**
```json
{ "name": "new-name" }
```

**Response:** Serialized project. `400` for an invalid UUID or name, `404` if the project is missing, and `409 Conflict` if the name is already taken.

### Delete Project

```
DELETE /api/projects/<project_id>
```

Deletes the project, its variants/scans, and variant-scoped context, assessment targets, metrics, and time estimates. Globally shared package, finding, and vulnerability records are not automatically removed merely by deleting a project.

**Response:**
```json
{ "message": "Project deleted." }
```

`400` for an invalid UUID; `404` if the project is missing.

---

## Variants

### List All Variants

```
GET /api/variants
```

Returns all variants across all projects.

### List Variants for a Project

```
GET /api/projects/<project_id>/variants
```

**Response:** JSON array of variant objects. `404` if project not found.

### Create Variant

```
POST /api/projects/<project_id>/variants
```

**Request body:**
```json
{ "name": "x86_64" }
```

**Response:** `201 Created` — serialized variant. `400` for an invalid UUID or missing, non-string, or blank name; `404` if the project is missing; `409 Conflict` if the name already exists within the project. Names are trimmed.

### Rename Variant

```
PATCH /api/variants/<variant_id>/rename
```

**Request body:**
```json
{ "name": "aarch64" }
```

**Response:** Serialized variant. `400` for an invalid UUID or name, `404` if the variant is missing, and `409 Conflict` if the name is already taken within the project.

### Delete Variant

```
DELETE /api/variants/<variant_id>
```

**Response:**
```json
{ "message": "Variant deleted." }
```

`400` for an invalid UUID; `404` if the variant is missing.

### Copy Custom Assessments Between Variants

```
POST /api/variants/copy-assessments/preview
POST /api/variants/copy-assessments
```

Both accept:

```json
{
  "source_variant_id": "source-uuid",
  "target_variant_id": "target-uuid",
  "match_mode": "exact",
  "version_precision": 1,
  "copy_condition": "no_custom"
}
```

Variants must belong to the same project. Only custom source assessments are copied, onto matching vulnerability findings for packages in the target's active SBOM.

`match_mode` is `"exact"` (name and version, default), `"ignore_minor_version"` (same name and leading version components), or `"ignore_version"` (same name, any version). `version_precision` defaults to `1` and controls the leading components in `ignore_minor_version` mode. `copy_condition` is `"no_custom"` (default), `"different_status"`, or `"different_value"`.

Preview returns `count`, `skipped`, `message`, `mode`, and either `entries` (exact mode) or `groups` with candidate targets (other modes). Entries include source assessment/finding IDs, target finding IDs, package identities, assessment details, and selection flags.

Copy may also accept `selections`, an array of `{"source_assessment_id": "...", "target_finding_id": "..."}` pairs from the preview. Without selections, eligible matches are computed automatically. It returns `{"copied": 3, "skipped": 1, "message": "..."}`. Invalid input or cross-project scopes return `400`; missing variants return `404`.

---

## Context

### Get Merged Context

```
GET /api/context?project_id=<project_id>&variant_id=<variant_id>
```

Returns the merged project and variant context, including supplemental file metadata. Both UUID parameters are required,
and the variant must belong to the selected project.

The response contains `project_id`, project `description`, `variant_id`, `variant_description`, `codebase_path`, `environment`, `threat_model`, `risks`, `other_info`, and `files`. Unset text fields are `null` and absent files are `[]`. Invalid or mismatched UUIDs return `400`; missing projects or variants return `404`.

### Get or Update Project Context

```
GET /api/projects/<project_id>/context
PUT /api/projects/<project_id>/context
```

The `GET` response is `{"project_id": "...", "description": null}` when no context is set. `PUT` accepts a JSON object with a `description` field and returns the same shape. Omitting `description` or sending `null` clears it.

### Update Variant Context

```
PUT /api/variants/<variant_id>/context
```

Accepts a JSON object containing any of `variant_description`, `codebase_path`, `environment`, `threat_model`, `risks`,
and `other_info`.

This replaces all variant text fields: omitted fields become `null`, so send all values that should be retained. The response includes the stored fields, `variant_id`, `updated_at` (ISO datetime or `null`), and `files`. Both context update endpoints return `400` for an invalid UUID and `404` for a missing project or variant.

### Import or Export Context

```
GET /api/context/export
POST /api/context/import
```

Export accepts either a `project_id` and `variant_id` pair, a comma-separated `variant_ids` filter, or no filter to
export all context. The response envelope is `{"version": "1.0", "exported_at": "...", "projects": [...]}`. Each project contains `project_name`, `project_description`, and `variants`; each variant contains `variant_name` and the variant text fields above. Supplemental files are not exported.

Import accepts that envelope or a bare array of project entries. Projects and variants are resolved by name and must already exist. Each imported variant requires non-blank `project_description` and `threat_model`. All valid entries are committed atomically; invalid entries are classified rather than causing valid entries to be rejected. The response is `{"imported": [...], "ignored": [...], "failed": [...]}`, with names and (for ignored/failed entries) reasons. Malformed documents return `400`; persistence failures return `500`.

### Manage Supplemental Context Files

```
POST /api/variants/<variant_id>/context/files
DELETE /api/variants/<variant_id>/context/files/<file_id>
```

Upload uses `multipart/form-data` with a required `file`, an optional `description`, and a per-file 10 MiB limit (the default overall request limit is smaller; see above). It returns file metadata with `201`; deletion returns `204` with no body. Invalid identifiers, missing files, or files above the per-file limit return `400`; missing variants or files return `404`. These
endpoints are retained for API compatibility but are not currently exposed by the frontend.

---

## Packages

### List Packages

```
GET /api/packages
```

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `variant_id` | UUID | Filter by variant |
| `project_id` | UUID | Filter by project |
| `compare_variant_id` | UUID | Second variant for comparison (requires `variant_id`) |
| `variant_ids` | string | Comma-separated variant IDs for multi-variant selection |
| `operation` | string | Pairwise: `"difference"` (default) or `"intersection"`; multi-variant: `"union"` (default) or `"intersection"` |
| `format` | string | `"list"` (default) or `"dict"` (keyed by `name@version`) |
| `include_outdated` | string | `"1"`, `"true"`, or `"yes"` to include historical finding packages absent from the active SBOM |
| `outdated_only` | string | Same truthy values; return only outdated packages (implies `include_outdated`) |

**Response:** JSON array of package objects with `id` (`name@version`, optionally `::supplier`), `package_id` (database UUID), `name`, `version`, `cpe` and `purl` arrays, `licences`, and `supplier`, enriched with `variants` (names), `sources` (formats), `sbom_documents` (source filenames), and `outdated`.

Scoped normal results use active SBOM packages; with no scope, all stored packages are returned. Pairwise difference means packages in `compare_variant_id` but **not** in `variant_id`. Multi-variant selection uses a union or intersection across the selected variants. Selection precedence is pairwise comparison, `variant_ids`, `variant_id`, then `project_id`.

Outdated results require a variant/project scope (`400` otherwise) and carry `variant_id`, `finding_ids`, and `vulnerability_ids`. Outdatedness is determined by name/version, not supplier; a package can be current in one variant and outdated in another. Pairwise outdated rows use the comparison variant's scope. In dict format, outdated keys append `@<variant_uuid>` to `name@version`; use list format to avoid collisions between supplier-qualified packages. Invalid scope UUIDs return `400`.

### Package Dependencies

```
GET /api/package-dependencies
```

**Query parameters:** at least one of `variant_id`, `project_id` or `variant_ids` is required.

| Parameter | Type | Description |
|-----------|------|-------------|
| `variant_id` | UUID | Filter by variant |
| `project_id` | UUID | Filter by project |
| `variant_ids` | string | Comma-separated variant IDs |
| `compare_variant_id` | UUID | Second variant for comparison (requires `variant_id`) |
| `operation` | string | `"difference"` (default for comparison), `"intersection"` or `"union"` (default for `variant_ids`) |
| `counts` | string | `"1"` to return only per-package `in`/`out` totals |

**Response:** `{"documents": [...]}` where each active SBOM document lists its `variant_id`, `variant_name`, `dependencies_recorded`, `packages` and directed `edges` (`package_id` depends on `dependency_id`), or `{"counts": {"name@version": {"in": n, "out": n}}, "unrecorded": ["name@version", ...]}` when `counts=1` (`in`: packages it depends on, `out`: packages that depend on it). `dependencies_recorded` is `false` for documents imported before dependency support, and `unrecorded` lists packages found only in such documents, whose relationships are unknown rather than zero. An edge is listed under the dependent package's document; its dependency may appear in another document of the same scan (SPDX 2 `DocumentRef-` links). Package selection follows the same comparison rules as `GET /api/packages`.

Document entries also contain `id` and `source_name`. Their packages have `id`, `name`, and `version`; edge IDs and count keys are package string identities, including suppliers when present. Only edges whose endpoints are in the selected package set are returned. Counts deduplicate edge pairs and omit known zero-degree packages; `unrecorded` distinguishes unknown relationships. Missing scope or malformed UUIDs/`variant_ids` return `400`.

---

## Vulnerabilities

### List Vulnerabilities

```
GET /api/vulnerabilities
```

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `variant_id` | UUID | Filter by variant |
| `project_id` | UUID | Filter by project |
| `compare_variant_id` | UUID | Second variant for comparison (requires `variant_id`) |
| `variant_ids` | string | Comma-separated variant IDs |
| `operation` | string | Pairwise: `"difference"` (default) or `"intersection"`; multi-variant: `"union"` (default) or `"intersection"` |
| `format` | string | `"list"` (default), `"dict"` (keyed by vulnerability ID), or `"compact"` |

**Response:** JSON array of vulnerability objects enriched with `packages_current`, `packages_current_by_variant` (UUID-keyed package lists for scoped results), `variants`, `first_scan_date`, `found_by`, and description `texts`. Compact format returns an array without `texts`, `urls`, or `cpes`, sets `details_loaded` to `false`, and reduces CVSS entries to `version`, `base_score`, and `attack_vector`.

With no scope, all stored vulnerabilities are returned. Pairwise difference means vulnerabilities in `compare_variant_id` but **not** in `variant_id`; variant-scoped CVSS and effort values then use the comparison variant. Selection precedence is pairwise comparison, `variant_ids`, `variant_id`, then `project_id`. Invalid scope UUIDs return `400`.

> **Note:** Scoped selections use active scans. When the scope has active SBOM packages, tool-scan findings are filtered to those package IDs; with no active SBOM packages, that filter is not applied. SBOM-scan findings are not subject to the tool-package filter.

### Get Single Vulnerability

```
GET /api/vulnerabilities/<id>
```

Optional query parameters: `variant_id` applies variant-scoped CVSS/effort overrides and description scope; `project_id` scopes description and CVSS data to that project when no variant is supplied. `agent_scoped=1` together with `variant_id` also requires active variant membership and returns scoped `packages`, `packages_current`, `packages_current_by_variant`, and `found_by`.

**Response:** Vulnerability object including `texts`. `404` if not found (plain-text `"Not found"`), or if outside the requested agent scope; `400` for an invalid scope UUID.

### Get Variant Snapshots

```
GET /api/vulnerabilities/<id>/variant-snapshots
```

Returns an array of `{"variant_id": "...", "effort": {...}, "custom_cvss": [...]}` for variants observing the vulnerability, optionally filtered by `project_id`. CVSS entries use the usual metric fields, and effort durations are ISO 8601 strings. `404` if the vulnerability is missing; `400` for an invalid project UUID.

### Update Vulnerability

```
PATCH /api/vulnerabilities/<id>
```

Update effort estimates and/or CVSS scoring for a vulnerability.

**Request body:**
```json
{
  "effort": {
    "optimistic": 1,
    "likely": 2,
    "pessimistic": 4
  },
  "cvss": {
    "base_score": 7.5,
    "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "version": "3.1"
  },
  "variant_id": "optional-uuid"
}
```

Effort values are integer **hours** or ISO 8601 duration strings, truncated to whole hours. All three values are required when `effort` is supplied, with `optimistic <= likely <= pessimistic`. A `cvss` update requires `base_score`, `vector_string`, and `version`; `author` is optional, and `origin` defaults to `"custom"`.

`variant_id` scopes the write to one variant. When omitted, the update is applied to every variant observing the vulnerability (or unscoped storage when there are no observations).

**Response:** Updated vulnerability object. `400` for invalid effort/CVSS data or a malformed variant UUID; `404` if the vulnerability is missing.

### Batch Update Vulnerabilities

```
PATCH /api/vulnerabilities/batch
```

**Request body:**
```json
{
  "vulnerabilities": [
    { "id": "CVE-2024-1234", "effort": { "optimistic": 1, "likely": 2, "pessimistic": 4 } },
    { "id": "CVE-2024-5678", "cvss": { "base_score": 7.5, "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "version": "3.1" } }
  ]
}
```

**Response:**
```
{
  "status": "success",
  "vulnerabilities": [...],
  "count": 2
}
```

Each item accepts the same fields and variant scoping as the single update. This is not an atomic batch: valid writes may succeed alongside failures. `errors` and `error_count` are present only when errors occurred. The status is `"success"` and HTTP `200` if any item succeeds, otherwise `"error"` and `400`.

### Evaluate a Match Condition

```
POST /api/vulnerabilities/match-condition
```

Evaluates a condition expression against supplied objects and returns the matching IDs.

**Request body:**
```json
{
  "condition": "severity.cvss.base_score >= 7",
  "items": [{ "id": "CVE-2026-0001", "data": { "severity": { "cvss": { "base_score": 8.1 } } } }]
}
```

**Response:** `{"matching_ids": ["CVE-2026-0001"]}`. Conditions are limited to 1,000 characters and `items` to 50,000 entries; malformed input or condition errors return `400`.

### Search Vulnerability Descriptions

```
POST /api/vulnerabilities/search-descriptions
```

Searches the supplied vulnerability IDs for each term. Optional `variant_id` or `project_id` query parameters scope
observation descriptions to active scans.

**Request body:**
```json
{
  "vulnerability_ids": ["CVE-2026-0001"],
  "terms": ["buffer overflow"]
}
```

**Response:** `{"matches": {"buffer overflow": ["CVE-2026-0001"]}}`. Terms are case-folded and matched as substrings against stored vulnerability descriptions and scoped SBOM observation descriptions. Unknown IDs simply do not match. Accepts up to 100,000 IDs and 50 terms, each at most 256 characters; invalid input returns `400`.

---

## Assessments

### List Assessments

```
GET /api/assessments
```

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `variant_id` | UUID | Filter by variant |
| `project_id` | UUID | Filter by project |
| `format` | string | `"list"` (default), `"dict"` (assessment-ID keys), or `"compact"` |

Pending AI assessments are excluded. Full results fold all in-scope targets into one object per assessment, with `packages`, `variant_ids`, exact `targets`, and outdated annotations. `variant_id` is the sole targeted variant or `null` for a multi-variant row.
Outdated annotations are `outdated`, `superseded_by`, `stale_packages`, `superseded_map`, and `stale_targets`. They apply to custom assessments; scan-imported and AI rows retain false/empty defaults. Full list rows are ordered oldest first; compact rows are likewise ordered by timestamp.
Assessment outdatedness differs from package outdatedness: an assessed package name must have no assessed version left in the active SBOM, while a replacement version is present and still has the same vulnerability in active scans. A removed package with no affected replacement does not by itself mark the assessment outdated.

Compact format returns the latest non-AI assessment per vulnerability/package/variant as positional arrays: `[id, vuln_id, package, variant_id, timestamp, status]`. Invalid scope UUIDs return `400`.

### Get Single Assessment

```
GET /api/assessments/<assessment_id>
```

**Response:** Assessment object, `404` if not found. Its `targets` array holds
every `(variant_id, package)` pair the assessment covers, each annotated with
`project_id` and `outdated`:

```json
{
  "id": "uuid",
  "source": "",
  "vuln_id": "CVE-2024-1234",
  "packages": ["pkg@1.0::supplier"],
  "variant_id": "uuid",
  "variant_ids": ["uuid"],
  "project_id": "project-uuid",
  "status": "not_affected",
  "status_notes": "",
  "justification": "vulnerable_code_not_present",
  "impact_statement": "",
  "workaround": "",
  "origin": "custom",
  "responses": [],
  "timestamp": "2024-01-01T00:00:00+00:00",
  "last_update": "2024-01-01T00:00:00+00:00",
  "assessment_fingerprint": "sha256-fingerprint",
  "reviews": [],
  "outdated": false,
  "superseded_by": [],
  "stale_packages": [],
  "superseded_map": {},
  "stale_targets": [],
  "targets": [
    { "variant_id": "uuid", "project_id": "project-uuid", "package": "pkg@1.0::supplier", "outdated": false }
  ]
}
```

### List Assessments for a Vulnerability

```
GET /api/vulnerabilities/<vuln_id>/assessments
```

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `format` | string | `"list"` (default) or `"dict"` |
| `project_id` | UUID | Restrict results to variants of one project |

**Response:** Array of assessment objects, newest first, including pending AI rows. The `project_id` filter selects assessments with targets in that project. Targets carry outdated annotations; pending AI rows also carry `context_outdated`. Unlike the single-assessment endpoint, these rows do not include `assessment_fingerprint`, `reviews`, or project annotations.

### List Assessments for Review

```
GET /api/reviews/assessments
```

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `variant_id` | UUID | Restrict results to one variant |
| `project_id` | UUID | Restrict results to variants of one project |
| `origin` | string | Restrict results to one origin (e.g. `custom`, `ai`) |

**Response:** array of assessment objects, each enriched with a `vuln_texts`
array holding the vulnerability texts of its CVE for front-end tooltips.
With no `origin` filter this includes scan-imported, custom, and pending AI assessments. `origin=ai` also adds `context_outdated`; scope UUID errors return `400`.

### List Variants for a Vulnerability

```
GET /api/vulnerabilities/<vuln_id>/variants
```

Returns all distinct variants that have a finding for this vulnerability.
This includes historical observations, not just active SBOM membership.

**Response:**
```json
[
  { "id": "...", "name": "x86_64", "project_id": "..." }
]
```

### List Active Packages for a Vulnerability by Variant

```
GET /api/vulnerabilities/<vuln_id>/variant-active-packages
```

Optional `project_id` restricts the result to one project. Returns an array of objects with `variant_id`, `active_packages` (exact package string identities present in that variant's active SBOM), and `findings` (`finding_id`, `package`, `outdated`) for historically observed findings. Finding outdatedness is based on name/version, independent of supplier. Invalid project UUIDs return `400`.

### Reconcile an Assessment

Brings an assessment to the requested state in a single transaction: its
targets are added or removed so it ends up covering exactly the given
packages and variants, and its content is updated at the same time.

```
POST /api/assessments/<assessment_id>/reconcile
```

**Request body:**
```json
{
  "vuln_id": "CVE-2024-1234",
  "packages": ["pkg@1.0::supplier"],
  "variant_ids": ["uuid"],
  "targets": [
    { "package": "pkg@1.0::supplier", "variant_id": "uuid" }
  ],
  "status": "not_affected",
  "status_notes": "",
  "justification": "vulnerable_code_not_present",
  "impact_statement": "",
  "workaround": "",
  "responses": [],
  "update_timestamp": true,
  "timestamp": "2024-01-01T00:00:00+00:00"
}
```

When present, `targets` is the authoritative exact list of package/variant
pairs. This preserves sparse scopes without implicitly creating the
cross-product of the flattened fields. An explicitly empty `targets` list
removes every target and deletes the now-empty assessment. Legacy clients may
omit `targets` and provide non-empty `packages` and `variant_ids`; those fields
resolve the observed combinations of that selection (unobserved cells do not create targets). `vuln_id` must match the assessment's
vulnerability. `responses` is only applied when the key is present, so
omitting it preserves the stored VEX responses. `update_timestamp` defaults to
`true`.
`status` is required, and omitted content fields other than `responses` are reset to empty/default values. Editing a scan-imported assessment converts it to `custom`; a pending AI assessment remains `ai`.

**Response:**
```json
{
  "status": "success",
  "updated": [],
  "created": [],
  "deleted": []
}
```

`400` on an invalid payload, a `vuln_id` that does not match the assessment, or
a request that would delete a target from a pending AI assessment. `404` if
the assessment does not exist.

### Approve an AI Assessment

Converts a pending AI assessment to `custom` origin.

```
POST /api/assessments/<assessment_id>/approve
```

**Response:**
```json
{
  "status": "success",
  "assessments": [ { } ]
}
```

`400` if the assessment is not a pending AI assessment. `404` if it does not
exist.

### Reject an AI Assessment

Deletes a pending AI assessment.

```
POST /api/assessments/<assessment_id>/reject
```

**Response:**
```json
{
  "status": "success",
  "deleted": ["uuid"]
}
```

`400` if the assessment is not a pending AI assessment. `404` if it does not
exist.

### Create Assessment

```
POST /api/vulnerabilities/<vuln_id>/assessments
```

**Request body:**
```json
{
  "packages": ["package-name@1.0.0"],
  "status": "affected",
  "variant_id": "variant-uuid",
  "status_notes": "Confirmed by manual review",
  "impact_statement": "",
  "workaround": "",
  "responses": ["update"]
}
```

`packages`, `status`, and either `variant_id` or a non-empty `variant_ids` list are required. `variant_ids` takes precedence when non-empty. One row covers the observed combinations of the selected packages and variants, which must belong to one project. Packages must already exist and must have been observed for this vulnerability in at least one selected variant; historical findings are valid targets too.

Alternatively, a non-empty `targets` array of `{"package": "pkg@1.0::supplier", "variant_id": "..."}` pairs is authoritative and derives the flattened selection. Each explicit pair must be observed. Use the package string identities returned by the API, including suppliers when present.

Accepted statuses are OpenVEX (`under_investigation`, `not_affected`, `affected`, `fixed`) or CycloneDX VEX (`in_triage`, `false_positive`, `exploitable`, `resolved`, `resolved_with_pedigree`, and `not_affected`). `not_affected` requires a valid OpenVEX or CycloneDX justification. Omit `justification` when unused; an empty string is not a valid creation/reconcile justification. `responses` accepts CycloneDX response values (`can_not_fix`, `will_not_fix`, `update`, `rollback`, `workaround_available`). An optional ISO datetime `timestamp` overrides the statement date.

Set `"ai_generated": true` to create a pending
AI assessment (`origin` `"ai"`) instead of a `custom` one.

**Response:**
```
{
  "status": "success",
  "assessments": [...],
  "assessment": { ... },
  "replaced": [ { "id": "...", "action": "trimmed", "variant_ids": ["..."] } ]
}
```

`replaced` is present only when an AI-generated write replaced a pending AI
assessment. Such a write replaces every pending AI assessment on the same
vulnerability and variant(s), whatever its packages, in the same transaction as
the create, so a failed write leaves the old assessment untouched. `action` is
`"deleted"` when the old assessment had no other targets left and `"trimmed"`
when it also covered other variants and keeps those. Approved (`custom`) and
scan-imported assessments are never replaced.
Success returns `200`, not `201`; invalid payloads or target selections return `400`, and database failures return `500`.

### Batch Create Assessments

```
POST /api/assessments/batch
```

**Request body:**
```json
{
  "assessments": [
    { "vuln_id": "CVE-2024-1234", "packages": ["pkg@1.0"], "variant_ids": ["uuid-a", "uuid-b"], "status": "affected" },
    { "vuln_id": "CVE-2024-5678", "packages": ["pkg@2.0"], "variant_id": "uuid", "status": "not_affected", "justification": "code_not_reachable" }
  ]
}
```

Each item requires either `variant_id` or a non-empty `variant_ids` array. The
plural form takes precedence when both are present. One item creates one
assessment row covering every observed package/variant target; separate items
remain separate rows. If any item is invalid, nothing in the batch is written.
This endpoint creates `custom` rows; `ai_generated` and exact `targets` are not supported here. Use the single-vulnerability creation endpoint for those features.

**Response (abbreviated):**
```
{
  "status": "success",
  "assessments": [...],
  "count": 2,
  "vuln_count": 2
}
```

On failure (`400` for an invalid payload, `500` for a database error) the same
shape is returned with `status` `"error"`, empty `assessments`, and the failures
listed:

```json
{
  "status": "error",
  "assessments": [],
  "count": 0,
  "vuln_count": 0,
  "errors": [ { "vuln_id": "CVE-2024-1234", "error": "variant_id is required" } ],
  "error_count": 1
}
```

### Update Assessment

```
PUT /api/assessments/<assessment_id>
PATCH /api/assessments/<assessment_id>
```

**Request body:**
```json
{
  "status": "not_affected",
  "status_notes": "False positive",
  "justification": "vulnerable_code_not_present",
  "impact_statement": "Component is not included in our build",
  "workaround": ""
}
```

Content fields shown above are optional, but the request body must not be empty. `update_timestamp` defaults to `true`; set it to `false` to preserve the statement date, or supply an ISO datetime `timestamp` to use a particular date when updating.

The existing target scope is unchanged. Scan-imported rows become `custom`; pending AI rows remain pending. `responses` is preserved by this endpoint; use reconcile to edit it. An optional non-empty `allowed_variant_ids` UUID list guards against target scope changes and returns `409` if current targets fall outside that set.

Invalid content or unobserved target relationships return `400`; missing assessments return `404`.

**Response:**
```
{
  "status": "success",
  "assessment": { ... }
}
```

### Delete Assessment

```
DELETE /api/assessments/<assessment_id>
```

**Response:**
```json
{
  "status": "success",
  "message": "Assessment deleted successfully"
}
```

Pending AI rows must be rejected through the dedicated endpoint (`400` otherwise). Missing assessments return `404`.

### Review Assessments (User-Created)

#### List Review Assessments

```
GET /api/assessments/review
```

Returns only `custom` assessments, including vulnerability texts and target outdated annotations (not scan-imported or pending AI rows).

**Query parameters:** `variant_id`, `project_id`.

#### List Pending AI Assessments

```
GET /api/assessments/review/ai
```

Same scope parameters as the custom list. Returns pending `ai` assessments with `vuln_texts`, target outdated annotations, and `context_outdated` (whether any targeted variant's or project's context changed after the assessment was created). It does not approve or reject them.

#### List or Delete Time Estimates and Custom CVSS

```
GET /api/assessments/review/time-estimates
GET /api/assessments/review/custom-cvss
DELETE /api/assessments/review/time-estimates
DELETE /api/assessments/review/custom-cvss
```

Lists accept `variant_id` or `project_id`. Time estimates include non-zero records, with `id`, `vuln_id`, `variant_id`, integer-hour `optimistic`/`likely`/`pessimistic` values, their `*_iso` duration strings, and `vuln_texts`. Custom CVSS entries contain `id`, `vuln_id`, `variant_id`, `version`, `vector_string`, `base_score`, `author`, `origin`, and `vuln_texts`; scanner-authored entries are excluded. Legacy unscoped values may appear with `variant_id: null`.

Deletion requires a JSON body `{"ids": ["record-uuid", "..."]}` using the **record** IDs from the corresponding list. All IDs are validated before deletion; missing records (or non-custom CVSS records) return `404`, malformed IDs or empty lists return `400`. Success returns `{"status": "success", "deleted": ["record-uuid", "..."]}`.

#### Export Review Assessments

```
GET /api/assessments/review/export
```

Downloads one OpenVEX JSON document for a selected variant.

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `author` | string | Author name in the export (default: `"Savoir-faire Linux"`) |
| `variant_id` | UUID | Required. The single variant to export. |

**Response:** OpenVEX JSON file (`Content-Type: application/json`).
Exactly one `variant_id` is required (`400` otherwise); missing variants or no custom assessments return `404`.

#### Import Review Assessments

```
POST /api/assessments/review/import
```

Upload an OpenVEX `.json` file into a selected variant. The uploaded filename is not used to select the target.

**Request:** Multipart form-data with the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `file` | file | OpenVEX `.json` document (required) |
| `variant_id` | UUID | Required target variant. |
| `timestamp_policy` | string | `"original"` (default) preserves statement dates; `"current"` uses server time |

**Response:**
```json
{
  "status": "success",
  "imported": 15,
  "skipped": 2,
  "errors": []
}
```

Malformed uploads or invalid timestamp policies return `400`; missing target variants return `404`. Statement-level import errors are returned in `errors` alongside the imported/skipped counts.

### Custom Data Import / Export

#### Export Custom Data

```
GET /api/assessments/review/export-custom-data
```

Exports handmade review assessments, pending AI assessments, custom CVSS scores,
and time estimates as a single JSON file. Pending AI assessments can be reviewed
from the **AI Assessments** tab after import.

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `variant_id` | UUID | Restrict to selected variants; may be repeated. |
| `project_id` | UUID | Restrict to all variants in a project. |

**Response:** JSON file download (`Content-Disposition: attachment`) named `custom_data_<project_name>.json` when a project name can be resolved, otherwise `custom_data.json`, containing (abbreviated):

```text
{
  "version": 2,
  "exported_at": "2026-10-10T21:28:00+00:00",
  "assessments": [...],
  "ai_assessments": [...],
  "cvss": [...],
  "time_estimates": [...]
}
```

Version 2 assessment records store their scope exclusively as exact target
pairs such as `{"variant": "x86", "package": "openssl@3.0"}`. Exported
records do not contain database variant UUIDs, so files can be transferred to
another VulnScout instance. CVSS and time-estimate records likewise identify
their variant by name. Legacy version 1 files remain importable; unsupported
future versions are rejected explicitly.

Returns `404` if there is no custom data to export.

#### Import Custom Data

```
POST /api/assessments/review/import-custom-data
```

Imports assessments, pending AI assessments, custom CVSS scores, and time
estimates from a custom-data JSON file. Imported AI assessments retain their
pending state and appear in the **AI Assessments** tab.

Accepts either:

- `multipart/form-data` with a `file` field containing a `.json` file.
- `application/json` body with the custom-data payload directly.

Supply the destination `project_id` UUID in the JSON body or multipart form. Version 2 variant
names are resolved only within that project. Version 1 retains its legacy
variant ID/name resolution for existing backups.
Optional `timestamp_policy` in the **JSON payload** is `"current"` (default) or `"original"`. Query-string `variant_id` filters are rejected; targets are resolved from the file within the destination project.

**Response:**
```json
{
  "status": "success",
  "assessments_imported": 12,
  "assessments_skipped": 0,
  "ai_assessments_imported": 4,
  "ai_assessments_skipped": 0,
  "cvss_imported": 5,
  "time_estimates_imported": 3,
  "errors": []
}
```

Returns `400` for invalid format, timestamp policy, missing project scope, or unsupported content type; `404` if the destination project is missing. Per-record outcomes are reported in the counts and `errors`.

#### Update an Existing Review Export

```
POST /api/assessments/review/export-update
```

Multipart fields: required `.json` `file`, `project_id`, and one or more repeated `variant_id` values; optional `author` for OpenVEX. All selected variants must belong to the project. The input selects the format (VulnScout custom-data JSON or OpenVEX); OpenVEX requires exactly one variant.

Returns an updated JSON download under the uploaded filename. Matching records retain their order, out-of-selection variant records are removed, and new records are appended. Invalid input or scope returns `400`; missing variants return `404`.

### Per-Target Second-Opinion Reviews

These reviews are stored alongside a `custom` assessment, without modifying its content or approving a pending AI assessment. There is at most one review per assessment/variant/finding target; writing again overwrites that target's review.

```
GET /api/custom-assessments
GET /api/assessment-reviews
GET /api/assessments/<assessment_id>/reviews
GET /api/assessments/<assessment_id>/review
PUT /api/assessments/<assessment_id>/review
DELETE /api/assessments/<assessment_id>/review
```

`GET /api/custom-assessments` returns an array of custom assessments. It accepts repeated `variant_id`, optional `project_id`, `has_review` (`"true"`: any review exists; `"false"`: any scoped target lacks a fresh review), `order` (`"timestamp_desc"` default or `"timestamp_asc"`), `limit` (default `50`, at least `1`), and `offset` (default `0`, non-negative). Targets and flattened scope fields are restricted to the requested variants. Rows include `assessment_fingerprint`, `project_id`, `has_review`, and per-target `target_reviews` with `has_review` / `is_stale`.

`GET /api/assessment-reviews` accepts the same variant/project scope and optional `vulnerability_id`, returning `{"<assessment_id>": [<review>, ...]}`. The plural per-assessment endpoint returns `{"reviews": [...]}`.

Single-target `GET` and `DELETE` require query parameters `variant_id` and either `finding_id` or `package`; the pair must belong to the assessment. `GET` returns `{"review": {...}}`; deletion returns `{"status": "success", "deleted": "<assessment_id>"}`. Missing assessments/reviews return `404`; invalid targets or UUIDs return `400`.

`PUT` takes the target identifiers in its JSON body plus:

```json
{
  "variant_id": "variant-uuid",
  "package": "pkg@1.0::supplier",
  "expected_assessment_fingerprint": "fingerprint-from-assessment-read",
  "status": "not_affected",
  "justification": "vulnerable_code_not_present",
  "rationale": "Independent explanation of the verdict"
}
```

`status` must be an OpenVEX status; non-blank `rationale` and the fingerprint from `GET /api/custom-assessments` or the single-assessment read are required. `not_affected` requires an OpenVEX justification. Optional fields are `status_notes`, `impact_statement`, `workaround`, and list-valued `responses`; omitted optional fields are reset. Returns `{"status": "success", "review": {...}}`.

Reviews include `id`, `assessment_id`, `variant_id`, `package`, the VEX fields, `rationale`, `timestamp`, `verdict` (`"agrees"` or `"differs"`), and `is_stale`. `PUT` returns `400` for invalid content/targets, `404` for a missing assessment, or `409` for non-custom origin or a changed fingerprint (`code: "assessment_changed"` with the current `assessment_fingerprint`).

---

## Documents

### List Available Documents

```
GET /api/documents
```

Returns all available report templates, SBOM/VEX export formats, and uploaded raster image assets.

**Response:**
```json
[
  { "id": "summary.adoc", "extension": "adoc | pdf | html", "is_template": true, "category": ["built-in"] },
  { "id": "CycloneDX 1.6", "extension": "json", "is_template": false, "category": ["sbom"] },
  { "id": "logo.png", "extension": "png", "is_template": false, "category": ["assets"] }
]
```

`category` is an array; `extension` may contain several pipe-separated choices. Available SBOM/VEX selections are CycloneDX 1.4/1.5/1.6 (JSON), SPDX 2.3 (JSON/XML), SPDX 3.0 (JSON), and `OpenVex` (JSON).

### Upload Report Templates or Image Assets

```
POST /api/documents/templates
POST /api/documents/assets
```

Both require `multipart/form-data` with a single `file`. Template uploads accept `adoc`, `asciidoc`, `html`, `htm`, `md`, `markdown`, `csv`, `txt`, `json`, `xml`, `tex`, `j2`, `jinja`, and `jinja2`; they return `201` with `{"id": "...", "category": ["custom"], "message": "Template imported."}`.

Assets accept genuine PNG, JPEG (`jpg`/`jpeg`), GIF, or WebP images matching their extension, limited to 5 MiB; SVG uploads are not accepted. Success returns `201` with `{"name": "...", "message": "Asset uploaded."}`. Files are saved under a writable templates/assets directory and become available through the document list and named download. A same-name upload replaces the stored file.

Invalid uploads return `400`, oversized uploads `413`, and storage failures `500`.

### Generate / Download Document

```
GET /api/documents/<doc_name>
```

Generate a report from a template, export an SBOM/VEX document, or download a named image asset.

**Path parameter:** `doc_name` — template name (e.g. `summary.adoc`) or SBOM format (e.g. `CycloneDX 1.6`, `SPDX 2.3`, `SPDX 3.0`, `OpenVex`).

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `ext` | string | Target output format / extension |
| `author` | string | Author name for the document |
| `client_name` | string | Client name for the document |
| `export_date` | string | Export date override |
| `ignore_before` | ISO datetime | Ignore vulnerabilities assessed before this date |
| `only_epss_greater` | float | Only include vulns with EPSS score above this value |
| `variant_id` | UUID | Restrict report/SBOM/VEX data to one variant (takes precedence) |
| `project_id` | UUID | Restrict to all variants of one project if no variant is supplied |

**Response:** File download with appropriate `Content-Type` and `Content-Disposition` headers. Supports JSON, XML, PDF, and HTML outputs depending on the template.
No scope means global data. For SBOM/VEX formats, supply `ext` from the choices returned by the document list (for example `ext=json`). Metadata/filter query parameters also apply to `POST /api/documents/export`; they are not JSON-body fields. Defaults are `AUTHOR_NAME` (or `"Savoir-faire Linux"`) / `CLIENT_NAME` (or empty), today's export date, `ignore_before=1970-01-01T00:00`, and `only_epss_greater=0.0`.

Invalid identifiers or unsupported conversions return `400`; missing conversion tools return `503`; other rendering failures return `500`.

### Export Multiple Documents

```
POST /api/documents/export
```

Renders selected document formats for every variant in one project. `consolidated` creates one project-wide file per selection; `per_variant` creates one file per selection and variant. Both modes return a ZIP archive.

**Request body:**

```json
{
  "project_id": "11111111-1111-1111-1111-111111111111",
  "variant_ids": [
    "22222222-2222-2222-2222-222222222222"
  ],
  "mode": "per_variant",
  "documents": [
    { "name": "summary.adoc", "extension": "pdf" }
  ],
  "async": true
}
```

`variant_ids` selects one or more variants belonging to the project. When omitted, all project variants are exported. Reports support either output mode. SBOM selections (for example `{"name": "CycloneDX 1.6", "extension": "json"}`) require `per_variant` mode and cannot be mixed with reports in the same request. Document and extension pairs must match non-asset entries returned by `GET /api/documents`. Assets cannot be selected for this ZIP export; they can be downloaded separately through the named-document endpoint.

With `"async": true`, returns `202 Accepted` with `{ "op_id": "export:<uuid>" }`. Watch `GET /api/events/stream` for a `done` operation, then download the retained ZIP from `GET /api/documents/export/<op_id>/download`. The archive is consumed on the first download and retained for up to one hour, subject to server limits. A repeat request or one after expiry normally returns `404` because the operation has been removed; request a new export rather than relying on `410` to identify those cases. An archive missing while its operation still exists can return `410`, and an unfinished export returns `409`. Without `async`, the response is a ZIP file (`Content-Type: application/zip`).

```
GET /api/documents/export/<op_id>/download
```

Invalid document selections, empty variant lists, or variants outside the project return `400`; missing projects return `404`. Busy export service/queue responses return `503` with `Retry-After: 5`. Archives and total retained archive storage are bounded to 512 MiB.

---

## Scans

### List Scans

```
GET /api/scans
```

Returns scans with diff statistics. Optional comma-separated `variant_ids` selects multiple variants; an accompanying `project_id` requires every selected variant to belong to that project. `project_id` alone does not filter this endpoint: use the project-specific route below. Invalid identifiers or mismatched project selection return `400`; unknown selected variants return `404`.

**Response:** JSON array of scan objects including:
- `finding_count`, `package_count`, `vuln_count`
- `findings_added`, `findings_removed`, `findings_upgraded`
- `packages_added`, `packages_removed`, `packages_upgraded`
- `vulns_added`, `vulns_removed`
- `assessment_count`, `assessments_added`, `assessments_removed`, `assessments_unchanged`
- `variant_name`, `project_name`, `is_first`
- `run_id`: operation queue id shared by the tool scans launched together, or `null`
- `run`: for a tool scan that shares its `run_id` with other tool scans of the same variant, the combined
  summary of that scan run (`id`, `scan_ids`, `sources`, `vuln_count`, `finding_count`, `assessment_count`,
  `newly_detected_vulns`, `newly_detected_findings`, `newly_detected_assessments`); `null` otherwise

### List Scans for a Project

```
GET /api/projects/<project_id>/scans
```

### List Scans for a Variant

```
GET /api/variants/<variant_id>/scans
```

### Update Scan Description

```
PATCH /api/scans/<scan_id>
```

**Request body:**
```json
{ "description": "Weekly CI scan" }
```

**Response:** Updated scan object. `400` for an invalid scan UUID or missing/non-string description; `404` for a missing scan.

### Delete Scan

```
DELETE /api/scans/<scan_id>
```

Deletes the scan and its observations. Findings that are no longer referenced by any observation are also removed.
Assessment targets referencing those orphaned findings are removed too; an assessment is deleted if it has no targets left.

**Response:**
```json
{
  "deleted": true,
  "scan_id": "...",
  "orphaned_findings_removed": 3
}
```

`400` for an invalid scan UUID; `404` if the scan is missing. The diff, global-result, and single-scan export endpoints use the same UUID/not-found status codes.

### Get Scan Diff

```
GET /api/scans/<scan_id>/diff
```

Returns a detailed diff between this scan and the previous scan of the same type (and source) for the same variant.

For **SBOM scans with a predecessor**, finding/vulnerability change arrays compare the merged SBOM and active tool-scan result filtered by SBOM packages. A first SBOM diff lists the imported scan's own contents as additions. The detailed diff's `finding_count` and `vuln_count` describe that scan's own observations; use global-result counts for the full merged state.

For **tool scans**, the diff reflects the change in the *global result* (SBOM ∪ tool scans) caused by this scan. `newly_detected_*` identifies new global findings/vulnerabilities/assessments; `all_*` provides the raw tool-scan contents.
Tool diffs have `package_count: 0` and empty package-change arrays; `finding_count` / `vuln_count` describe the tool scan's own contents.

**Response:**
```
{
  "scan_id": "...",
  "scan_type": "sbom",
  "previous_scan_id": "...",
  "is_first": false,
  "finding_count": 120,
  "package_count": 45,
  "vuln_count": 80,
  "findings_added": [...],
  "findings_removed": [...],
  "findings_upgraded": [...],
  "findings_unchanged": [...],
  "packages_added": [...],
  "packages_removed": [...],
  "packages_upgraded": [...],
  "packages_unchanged": [...],
  "vulns_added": [...],
  "vulns_removed": [...],
  "vulns_unchanged": [...],
  "assessment_count": 20,
  "assessments_added": [...],
  "assessments_removed": [...],
  "assessments_unchanged": [...],
  "newly_detected_findings": null,
  "newly_detected_vulns": null,
  "newly_detected_findings_list": null,
  "newly_detected_vulns_list": null,
  "newly_detected_assessments_list": null,
  "all_findings": null,
  "all_vulns": null
}
```

| Field | Type | Scope | Description |
|-------|------|-------|-------------|
| `scan_type` | string | all | `"sbom"` or `"tool"` |
| `findings_unchanged` | array | all | Findings present in both the current and previous scan result |
| `packages_unchanged` | array | SBOM | Packages present in both scans |
| `vulns_unchanged` | array | all | Vulnerability IDs present in both scan results |
| `newly_detected_findings` | int\|null | tool | Count of findings new in the global result |
| `newly_detected_vulns` | int\|null | tool | Count of vulnerabilities new in the global result |
| `newly_detected_findings_list` | array\|null | tool | Finding objects newly detected in the global result |
| `newly_detected_vulns_list` | array\|null | tool | Vulnerability IDs newly detected |
| `newly_detected_assessments_list` | array\|null | tool | Newly detected scan assessment objects |
| `all_findings` | array\|null | tool | All raw findings from this tool scan |
| `all_vulns` | array\|null | tool | All vulnerability IDs from this tool scan |

### Get Scan Global Result

```
GET /api/scans/<scan_id>/global-result
```

Returns every active finding, vulnerability, and package at the time of the given scan, combining SBOM and tool-scan data with source attribution. Tool-scan findings are filtered to packages present in the SBOM.

**Response:** JSON object with `scan_id`, `scan_type`, `findings`, `vulnerabilities`, `packages`, and `assessments`, plus `finding_count`, `vuln_count`, `package_count`, and `assessment_count`. Package/finding/vulnerability entries carry a `sources` array of labels (SBOM document name/format or tool scan attribution), not a single `origin` field.

### Export Scan Diff

```
GET /api/scans/<scan_id>/export-diff
```

Exports a single scan's diff as a cleaned JSON download. The response strips internal fields and normalises supplier names for a portable, human-readable report.

For **SBOM scans** the export includes `vulnerabilities`, `findings`, `packages`, `assessments`, and (when the scan is not the first) a `diff` object with `*_added`, `*_removed`, `*_upgraded`, and `*_unchanged` arrays.

For **tool scans** the export includes `vulnerabilities`, `findings`, `newly_detected_vulns`, `newly_detected_findings`, and `newly_detected_assessments`.

**Response:** JSON file download (`Content-Disposition: attachment`).

### Export Scan Global Result

```
GET /api/scans/<scan_id>/export-result
```

Exports a single scan's global result (SBOM + tool data merged) as a cleaned JSON download. The response includes `packages`, `findings`, and `vulnerabilities` arrays with source attribution.
It also includes scan-imported `assessments`.

**Response:** JSON file download (`Content-Disposition: attachment`).

### Export All Scans

```
GET /api/scans/export
```

Exports all visible scans, optionally filtered by variant or project.

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `variant_id` | UUID | Restrict to a single variant |
| `project_id` | UUID | Restrict to all variants of a project |
| `type` | string | `"diff"` (default) or `"total"` — selects the diff or global-result export format |

**Response:** Flat JSON array of export objects ordered in variant groups, served as a file download (`Content-Disposition: attachment`). No matching scans returns `200` with `[]` (without download headers). A missing selected project returns `404`; invalid filters/type or more than 200 scans return `400`.

### Import Scan Exports

```
POST /api/scans/import
```

Accepts a JSON scan export object or a non-empty array of at most 200 objects produced by `export-diff`, `export-result`, or `scans/export`. Versioned exports use `export_version: 1` and `export_format: "scan-diff"` or `"full-result"`; legacy unversioned full-result exports are also accepted.

Each export identifies the destination by `project_name` and `variant_name`, which must already exist. Export metadata includes `scan_id` (source UUID), `scan_type` (`"import_sbom"` or `"vulnerability_scan"`), `scan_source`, and ISO datetime `timestamp`. Complete top-level `packages` / `findings` are imported; the source `diff` is ignored and recomputed against destination history. New destination scan IDs are generated. Existing scans with the same variant, scan type/source, and timestamp are skipped; duplicate entries within one request return `409`.

The complete request is validated and persisted atomically. The 100 MiB body limit returns `413`; malformed/unsupported exports return `400`, missing destinations `404`, and persistence failures `500`.

**Response:** `201 Created` with `imported_count`, `skipped_count`, and `scans` (one summary per imported scan with IDs, `format` `"diff"` / `"full"`, project/variant names, counts, and `is_first`). Top-level `scan_id`, `format`, and `is_first` describe the last imported scan or are `null` if all were skipped; `package_count`, `finding_count`, `vulnerability_count`, and `assessment_count` sum the imported summaries.

### Preview or Remove Obsolete Data

```
GET /api/outdated-data
DELETE /api/outdated-data
GET /api/empty-scans
DELETE /api/empty-scans
GET /api/orphaned-vulnerabilities
DELETE /api/orphaned-vulnerabilities
```

These operations are global, not project/variant-filtered. Always fetch a fresh preview before deleting:

| Endpoint | Preview | Required JSON deletion body |
|----------|---------|-----------------------------|
| `outdated-data` | `candidate_ids`, package/assessment details, counts | `{"candidate_ids": <entire candidate_ids object from preview>}` |
| `empty-scans` | `{"scans": [{"id": "...", ...}, ...]}` | `{"scan_ids": [<all preview scan IDs>]}` |
| `orphaned-vulnerabilities` | `{"vulnerabilities": [{"id": "...", "assessments": 0}, ...]}` | `{"vulnerability_ids": [<all preview vulnerability IDs>]}` |

Outdated cleanup removes evidence and assessment targets for name/version pairs no longer active in their variant, pruning shared rows only after their final reference disappears. Empty-scan cleanup removes non-initial **tool** scans whose recorded diff has no changes. Orphan cleanup removes vulnerabilities lacking scan/SBOM evidence, time estimates, or variant-scoped metrics, along with associated orphaned findings and assessments.

Deletion bodies must reproduce the full candidate set, not arbitrary subsets. Invalid bodies return `400`, changed previews `409`, and cleanup failures `500`. Success returns deletion counters (for example `{"scans_deleted": 3}`); outdated cleanup includes counters for removed targets, assessments, observations, SBOM rows, findings, vulnerabilities, and packages.

---

## NVD Refresh

These endpoints update cached NVD data (description, CVSS scores, references) for vulnerabilities already present in the database. Unlike the NVD scan, refresh does not create new findings — it only enriches existing `Vulnerability` records.

NVD refresh accepts a `mode` field (under `options` for operation-queue jobs) to select the data source:

- **`local`** (default) — reads from the local NVD-FKIE advisory database; no network calls, no API key needed.
- **`api`** — queries the NVD REST API v2; requires network access and honours the `NVD_API_KEY` environment variable.

### Refresh a Single CVE

```
POST /api/vulnerabilities/<cve_id>/nvd-refresh
```

Fetches NVD data for the given CVE and updates the stored description, CVSS scores, and references.

**Request body:**
```json
{ "mode": "local" }
```

| Field | Type | Description |
|-------|------|-------------|
| `mode` | string | `"local"` (default) or `"api"`. |

**Response:** `{"vulnerabilities": [<updated vulnerability object>]}`, including refreshed description texts.

**Error responses:**

| Code | `error_code` | Condition |
|------|--------------|-----------|
| `503` | `unavailable` | Local mode: CVE not found in the local database. API mode: NVD API unreachable or returned no data. |
| `429` | `rate_limited` | API mode only: NVD rate limit exceeded. |
| `401`/`403` | `unauthorized` | API mode only: API key rejected by NVD. |

An unknown stored CVE returns `404`. API-mode errors also include `api_key_configured`.

### Refresh EPSS or GHSA Data for One Vulnerability

```
POST /api/vulnerabilities/<cve_id>/epss-refresh
POST /api/vulnerabilities/<ghsa_id>/ghsa-refresh
```

These synchronous endpoints update existing vulnerability records and return `{"vulnerabilities": [<updated object>]}`. EPSS returns `404` for an unknown stored CVE or `503` when the upstream API has no data. GHSA requires `GHSA-xxxx-xxxx-xxxx` (`400` otherwise); missing stored/upstream advisories return `404`, other upstream HTTP errors `502`, and unavailable/invalid upstream data `503`. EUVD refreshes are submitted through the operation queue below.

### Operation Queue and Event Stream

```
POST /api/operations
GET /api/operations
GET /api/events/stream
POST /api/operations/<op_id>/cancel
POST /api/operations/queue/<queue_id>/cancel
DELETE /api/operations/<op_id>
```

Submit scans and vulnerability-data refreshes as one ordered batch. Scans run in Grype, NVD, OSV, sbom-cve-check order on the pipeline lane, followed by NVD, EPSS, GHSA, and EUVD refreshes. A batch may expand to at most 100 operations.

**Request body:**
```json
{
  "jobs": [
    { "kind": "scan", "source": "grype", "variant_ids": ["<variant-uuid>"], "options": { "exclude_kernel": true, "exclude_native": false } },
    { "kind": "refresh", "source": "nvd", "variant_ids": ["<variant-uuid>"], "exclude_ids": ["CVE-2024-1234"] }
  ]
}
```

For a standalone refresh, supply `ids` (CVE IDs for NVD/EPSS/EUVD, GHSA IDs for GHSA) instead of `variant_ids`. Deferred refresh jobs resolve the variant's newly discovered IDs after preceding scans; `exclude_ids` omits the pre-scan baseline. Scan options `exclude_kernel` and `exclude_native` default to `true` and `false`, respectively. `options.mode` accepts `"local"` (default) or `"api"` where supported. Duplicate or invalid operations are rejected before any job is queued; active conflicts return `409` with the conflicting operation IDs.

Explicit NVD API refreshes accept at most 1,000 CVE IDs; explicit GHSA refreshes at most 500 advisory IDs. Identifiers are trimmed, uppercased, deduplicated, and malformed identifiers discarded; a request with no usable IDs returns `400`. EPSS additionally requires at least one known CVE. `ids` and `variant_ids` cannot be combined in a refresh job. One scan operation is created per variant; one refresh operation per source (so submit each refresh source only once per batch).

**Response:** `202 Accepted` with `{ "queue_id": "q-...", "operations": [ ... ] }`. Each operation contains `op_id`, `kind`, `source`, `label`, `lane`, `queue_id`, `position`, `options`, `status`, `progress` (`current`, `total`, `message`), `logs`, `error`, `result`, `scope`, `cancellable`, and `created_at` / `started_at` / `finished_at` timestamps. `GET /api/operations` returns `{ "operations": [ ... ] }` with the current snapshot. Status values are `queued`, `running`, `done`, `error`, and `cancelled`; do not infer completion from the HTTP 202 response.

`GET /api/events/stream` returns `text/event-stream`. A fresh connection starts with a `snapshot` containing `seq` and `operations`. Each `operation` event replaces the full state for one `op_id`; `operation_removed` contains only the removed `op_id`. Idle clients receive `heartbeat` events every 15 seconds. Server shutdown sends `bye` and the client reconnects. For example, a fresh empty stream begins with:

```text
id: <epoch>:0
event: snapshot
data: {"seq": 0, "operations": []}
```

The cursor is instance-specific and changes on server restart. Reconnect with the **complete** `<epoch>:<seq>` `Last-Event-ID` header (or a URL-encoded `last_event_id` query parameter) to replay buffered updates. An invalid or too-old cursor yields a new snapshot. The SSE stream has a default limit of 32 concurrent clients (`VULNSCOUT_SSE_MAX_STREAMS`); requests above the limit return `503`. `GET /api/operations` is a diagnostic snapshot endpoint, not an automatic fallback in the web UI.

To stop one queued/running operation, `POST /api/operations/<op_id>/cancel` returns `200` with `{"status":"cancelling","op_id":"..."}` if accepted, `404` when no active operation has that ID, or `409` for a known non-cancellable operation. Cancellation of running work is cooperative, so wait for a `cancelled` event. `POST /api/operations/queue/<queue_id>/cancel` returns `{"cancelled": <count>}`. For terminal work, `DELETE /api/operations/<op_id>` returns `200` on dismissal or `409` if the operation is unknown or still active; dismissal does not remove its scan results. Upload, export, and boot-enrichment operations also appear in the stream, but not every kind supports cancellation.

Invalid job bodies or batches above 100 expanded operations return `400`; unknown variants return `404`, and active operation conflicts return `409`. The server may return `503` if the SSE stream or document export queue is full.

The registry and replay buffer are process-local, so a restart clears queued and retained operations. Terminal items remain for up to one hour unless dismissed sooner. For queue behavior and user-facing recovery, see {ref}`Operation Queue <operation-queue>`.

---

## Scan Sources

`POST /api/operations` accepts `scan` jobs for `grype`, `nvd`, `osv`, and `scc` (sbom-cve-check). Each scan takes one or more `variant_ids`. The Grype job exports CycloneDX, runs Grype, merges the results and processes findings. NVD scans use the local advisory database by default; set `options.mode` to `"api"` to query NVD by CPE. OSV scans query every package PURL. SCC scans match packages against the local NVD-FKIE and CVEList databases. Progress and errors arrive as operation events, not separate per-scanner status responses.

The SCC databases live at `SBOM_CVE_CHECK_DATABASES_DIR` inside the container (default: `/cache/vulnscout/local_databases`). Set `$VULNSCOUT_SBOM_CVE_CHECK_DB_DIR` on the host to mount a shared clone, or `SBOM_CVE_CHECK_AUTO_UPDATE=1` to update before scans.

---

## SBOM Upload

### Upload SBOM Files

```
POST /api/sbom/upload
```

Upload one or more SBOM files for asynchronous processing.

**Request:** Multipart form-data.

| Field | Type | Description |
|-------|------|-------------|
| `files` | file(s) | One or more SBOM files |
| `project_id` | UUID | Target project |
| `variant_id` | UUID | Target variant |
| `format` | string | Optional parser-format override; otherwise detected from each file |
| `refresh_sources` | repeated string | `nvd`, `epss`, `ghsa`, `euvd`; omitted defaults to `epss`, and `none` alone disables post-import refreshes |

`files`, `project_id`, and `variant_id` are required, and the variant must belong to the project. All uploaded files are registered under one scan. JSON SBOM/VEX/tool-result formats are auto-detected; supported SPDX 2 tar archives are expanded into their `.spdx.json` documents. Invalid payloads/formats or cross-project targets return `400`; missing projects/variants return `404`; oversized requests return `413`.

**Response:** `202 Accepted`
```json
{
  "op_id": "upload:<uuid>",
  "scan_id": "...",
  "message": "Upload accepted. Processing started."
}
```

Follow the returned `op_id` in `GET /api/events/stream` (or `GET /api/operations`) for progress, completion, and errors. There is no separate upload-status endpoint.

---

## Local Agent Chat

The browser's agent API is localhost-only, unlike the other REST endpoints. Requests require a loopback host and a trusted local/container-forwarded client address; non-GET requests with an `Origin` header must match the request host. Rejected access returns `403`. Preserve the HTTP-only, same-site `vulnscout_agent` cookie across requests. Optional `X-Agent-Thread: <uuid>` selects a separate conversation thread sharing the same credentials; malformed thread UUIDs return `400`. Sessions expire after one hour of inactivity and are process-local.

### Get Agent State

```
GET /api/agent
```

Returns `authenticated`, `login`, `configured` (bundled MCP server availability), `device_login`, `token_connected`, `provider`, `messages` (role/content pairs), `model`, and `usage` (`cost`, `input_tokens`, `output_tokens`, which may be `null`). Credentials are not included.

### Connect or Disconnect a Provider

```
POST /api/agent/provider
DELETE /api/agent/provider
```

`POST` accepts `provider` (`"openai"`, `"azure"`, `"anthropic"`, or `"local"`), optional `model`, `api_key`, and `base_url`. Hosted providers require a key and HTTPS for custom URLs; Azure and local providers require `base_url`. Local endpoints must use HTTP on loopback or a supported container-host/gateway address; no key is required. Hosted credentials stay in the process's conversation state, not `config.env`.

Returns `{"provider": "openai", "model": "..."}` (or `provider: null` after deletion). Changing the provider clears previous conversation threads. Invalid configuration/model discovery returns `400`, a busy conversation `409`, and conversation-cleanup failures `503`.

### GitHub Device Sign-In

```
POST /api/agent/auth
POST /api/agent/auth/poll
DELETE /api/agent/auth
```

Start sign-in with `POST /auth` (no token body); it returns `user_code`, `verification_uri`, and polling `interval` seconds. After completing the browser device flow, poll at that interval: pending responses contain `{"status": "pending", "interval": 5}`, and success contains `{"status": "connected", "authenticated": true, "login": "..."}`. Expired device codes return `410`, rejected sign-in/no Copilot access `401`, and upstream connectivity/verification failures `503`.

`DELETE /auth` clears credentials and conversations and returns `{"authenticated": false, "cleanup_error": null}`; `cleanup_error` reports remote conversation deletion failures.

### Select a Model or Reset a Conversation

```
GET /api/agent/models
POST /api/agent/model
DELETE /api/agent/conversation
```

The model list is `{"models": [{"id": "...", "name": "..."}]}`. Select with `{"model": "<available-model-id>"}`; success returns `{"model": "..."}`. Invalid/unavailable selections return `400`, busy work `409`, and model verification failures `503`.

Reset deletes the current conversation while keeping credentials and returns `{"messages": [], "usage": {"cost": null, "input_tokens": null, "output_tokens": null}}`; remote cleanup failure returns `503`.

### Send a Message

```
POST /api/agent/messages
```

Accepts a non-blank `message` of at most 8,000 characters, optional `model` (defaults to the selected model), and optional browser `context`:

```json
{
  "message": "Summarize this project's assessment state.",
  "context": {
    "page": "review",
    "projectId": "project-uuid",
    "variantId": "variant-uuid"
  }
}
```

Context pages are `metrics`, `packages`, `vulnerabilities`, `scans`, `review`, `exports`, `settings`, `ai`, or `unknown`. Context also supports `baseVariantId`, `variantIds` (at most 1,000), `compareOperation`, `multiOperation`, and `view` selection metadata. Selected variants must belong to `projectId`. No context normally allows all projects/variants; the `ai` page uses `view.selectedProjectId` / `view.selectedVariantId` and starts with no scope when no project is selected.

By default returns `{"reply": "...", "model": "...", "usage": {...}}`. Send exactly `Accept: application/x-ndjson` for newline-delimited JSON streaming: `status`, `delta` (`message_id`, `text`), `tool_start` (`id`, `name`), `tool_end` (`id`, `success`, `write`), and `heartbeat` events are followed by `done` (`reply`, `model`, `usage`) or `error` (`error`). This is not the operation SSE stream and has no replay cursor.

Invalid messages, models, or context return `400`; concurrent conversation work returns `409`; missing MCP installation or agent/provider failures return `503`. Once streaming has started, failures arrive as `error` records rather than a changed HTTP status.
