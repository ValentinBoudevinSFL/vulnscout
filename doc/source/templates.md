# Writing Report Templates

## Templating System

VulnScout uses [Jinja2](https://jinja.palletsprojects.com/) as its templating engine, which has great community support, documentation, and supports any text-based format (AsciiDoc, HTML, Markdown, CSV, plain text, etc.).

### Template Locations

| Path | Purpose |
|------|---------|
| `src/views/templates/` | Built-in templates shipped with VulnScout. |
| `.vulnscout/cache/templates/` | Persistent host templates with the default cache path; mounted at `/cache/vulnscout/templates/`. |

Inside the container, custom templates are searched in
`/cache/vulnscout/templates`, `.vulnscout/templates`, `templates`, and
`/scan/templates`, in that order, before built-in templates. These relative
fallback paths refer to the backend's working directory; the host wrapper does
not mount a host `.vulnscout/templates/` directory.

### Adding a Custom Template

Pass the file path directly to `--report` — it stages and runs the template in one step:

```bash
./vulnscout --project demo --report /path/to/my-report.adoc
```

### Generating Additional Templates

`GENERATE_DOCUMENTS` adds templates whenever the Flask `report` command is
invoked. It does not generate reports for a scan-only invocation. Multiple
templates are comma-separated (values are trimmed):

```bash
./vulnscout config GENERATE_DOCUMENTS "summary.adoc, all_assessments.adoc"
./vulnscout --project demo --report summary.adoc
```

Generated files are written to the outputs directory (default: `.vulnscout/outputs/`).
All templates can also be run on-demand from the web interface using the export button in the toolbar.

---

### Global Variables Available in Templates

| Variable | Type | Description |
|----------|------|-------------|
| `vulnerabilities` | dict | In-scope vulnerabilities with approved or scan-imported assessments, subject to report filters, keyed by ID. Use `vulnerabilities \| as_list` to get a list. |
| `packages` | dict | In-scope packages, keyed by package string ID. Use `packages \| as_list` to get a list. |
| `assessments` | dict | In-scope non-pending-AI assessments, expanded per target and subject to the assessment-date filter. Use `assessments \| as_list` to get a list. |
| `author` | string | Company name producing this document (from `AUTHOR_NAME` config). |
| `export_date` | string | Date of export as `YYYY-MM-DD`. |
| `scan_date` | string | Scan date supplied by the caller; the Flask report CLI currently passes `unknown date`. |
| `client_name` | string | Customer company name. Set via `CLIENT_NAME` config or overridden per-export from the web UI. May be empty. |
| `unfiltered_vulnerabilities` | dict | All vulnerabilities in the selected export scope, bypassing report filters, not project/variant scope. Use `\| as_list` to get a list. |
| `unfiltered_assessments` | dict | In-scope non-pending-AI assessments before report filters, expanded per target. Single-target entries use the assessment UUID; multiple in-scope targets use composite `assessment_id:variant_id:finding_id` keys. |
| `failed_vulns` | list[string] | List of vulnerability IDs that triggered the `--match-condition` expression. Empty when no condition was set or no vulnerability matched. Use `unfiltered_vulnerabilities[vuln_id]` to get the full object. |
| `projects` | dict | In-scope projects, keyed by UUID. Use `projects \| as_list` to get a list. Each value has the fields described in the Project Object section below. |
| `variants` | dict | All in-scope variants, keyed by UUID. A variant-scoped report contains only its selected variant. Use `variants \| as_list` to get a list. Each value has the fields described in the Variant Object section below. |
| `scans` | dict | In-scope scans, keyed by UUID. Use `scans \| as_list` to get a list. Each value has the fields described in the Scan Object section below. |
| `sbom_documents` | dict | In-scope SBOM documents, keyed by UUID. Use `sbom_documents \| as_list` to get a list. Each value has the fields described in the SBOM Document Object section below. |

---

### Environment Variables Available in Templates

Use `env(name, default="")` to access explicitly allowed template variables.
The helper reads only `VULNSCOUT_TPL_<name>` from the backend's environment;
it does not expose arbitrary host or server environment variables.

For example, to fetch the value of the `DISTRO` environment variable:

```
{{ env("DISTRO") }}
{{ env("DISTRO", "unknown") }}
```

With the host wrapper, set the prefixed variable in persistent configuration:

```bash
./vulnscout --config VULNSCOUT_TPL_DISTRO poky
```

When running the backend directly, export `VULNSCOUT_TPL_DISTRO=poky` instead.
`env("DISTRO", "unknown")` returns `unknown` if that prefixed variable is absent.

When exporting, users can add filters to export only some vulnerabilities. To bypass these filters and access all vulnerabilities, use `unfiltered_vulnerabilities` instead of `vulnerabilities` and `unfiltered_assessments` instead of `assessments`. This is useful when producing a summary or showing the number of filtered-out vulnerabilities.

---

### Vulnerability Object

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | CVE / vulnerability ID. |
| `found_by` | list[string] | Tools that found the vulnerability (e.g. `grype`, `yocto`, `spdx3`). |
| `datasource` | string | Primary URL for the vulnerability. |
| `namespace` | string | Database name (e.g. `nvd`). |
| `aliases` | list[string] | Alternative IDs for this vulnerability. |
| `related_vulnerabilities` | list[string] | IDs of related vulnerabilities. |
| `urls` | list[string] | Additional reference URLs. |
| `description` | string | Description of the vulnerability. |
| `severity.severity` | string | Severity level: `low`, `medium`, `high`, `critical`, `unknown`. |
| `severity.min_score` | float | Minimum CVSS score (0–10). |
| `severity.max_score` | float | Maximum CVSS score (0–10). |
| `severity.cvss` | list[CVSS] | List of CVSS scoring objects (version, score, vector, author). |
| `epss.score` | float | EPSS probability score (0–1). |
| `epss.percentile` | float | EPSS rank relative to all CVEs (0–1). |
| `effort.optimistic` | string | Optimistic fix time estimate in ISO 8601 duration (e.g. `PT5H`). |
| `effort.likely` | string | Likely fix time estimate in ISO 8601 duration (e.g. `P1D`). |
| `effort.pessimistic` | string | Pessimistic fix time estimate in ISO 8601 duration (e.g. `P2DT4H`). |
| `packages` | list[string] | Packages affected by the vulnerability, in form `name@version`. |
| `published` | string | CVE publish date as ISO 8601, or empty if unknown. |
| `status` | string | Current status string (see Assessment object for possible values). |
| `last_assessment` | Assessment | Most recent non-pending-AI assessment before the report's assessment-date filter. |
| `assessments` | list[Assessment] | All assessments, sorted most recent first. |
| `variant_ids` | list[string] | UUIDs of every variant in which this vulnerability has at least one assessment. |
| `assessments_by_variant` | dict[string, list[Assessment]] | Assessments grouped by variant ID. Key is the variant UUID, value is the list of assessments for that variant. |
| `euvd.id` | string or null | ENISA EUVD alias, when known. |
| `euvd.known_exploited` | boolean | Whether the vulnerability is in the EU KEV catalogue. |
| `euvd.sources` | list[string] | KEV sources such as `cisa_kev`. |
| `euvd.date_added` | string or null | Date the vulnerability was added to the KEV catalogue. |

`last_assessment`, `status`, and the assessment grouping fields are populated
for vulnerabilities with non-pending-AI assessments. The serialized
vulnerability does not provide a separate `simplified_status` field; use the
status filters to group statuses. Scores and effort values may be `null` when
not available.

---

### Package Object

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Portable package identifier: `name@version`, optionally `::supplier`. |
| `package_id` | string or null | Instance-local package UUID. |
| `name` | string | Name of the package. |
| `version` | string | Version of the package. |
| `supplier` | string or null | Package supplier. |
| `licences` | string | Recorded licence information. |
| `cpe` | list[string] | List of CPE identifiers. |
| `purl` | list[string] | List of PURL identifiers. |
| `sbom_documents` | dict[string, SBOM Document] | SBOM documents that list this package, keyed by UUID. |
| `variants` | list[string] | UUIDs of variants in which this package appears (derived from its SBOM documents). |
| `vulnerabilities` | dict[string, Vulnerability] | Vulnerabilities affecting this package, keyed by vulnerability ID. |

---

### Assessment Object

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Assessment ID (UUID). |
| `vuln_id` | string | ID of the vulnerability this assessment affects. |
| `packages` | list[string] | List of packages concerned. |
| `timestamp` | string | Creation datetime in ISO 8601 format. |
| `last_update` | string | Last update datetime in ISO 8601 format. |
| `status` | string | Status of the assessment (see possible values below). |
| `status_notes` | string | Free-text note about the status. |
| `justification` | string | Justification for the status (see possible values below). |
| `impact_statement` | string | Text explaining why the vulnerability does not apply. |
| `responses` | list[string] | List of remediation responses (see possible values below). |
| `workaround` | string | Workaround description. |
| `variant_id` | string | UUID of the variant this assessment belongs to, or empty. |
| `origin` | string | `sbom` or `custom`; pending `ai` assessments are excluded from reports. |
| `source` | string | Assessment source name. |

An assessment covering several variant/package pairs is expanded into one
report entry per in-scope target, each with one `variant_id` and package.
Those entries share the authored assessment's `id`; use dictionary keys rather
than `id` alone when indexing the expanded entries. The assessment serializer
does not expose `simplified_status` or `workaround_timestamp`.

---

### Project Object

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Project ID (UUID). |
| `name` | string | Name of the project. |

---

### Variant Object

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Variant ID (UUID). |
| `name` | string | Name of the variant (e.g. build configuration). |
| `project_id` | string | UUID of the project this variant belongs to. |
| `scans` | dict[string, Scan] | All scans belonging to this variant, keyed by UUID. |
| `sbom_documents` | dict[string, SBOM Document] | All SBOM documents belonging to this variant (across all its scans), keyed by UUID. |
| `packages` | dict[string, Package] | All packages found in this variant, keyed by `name@version`. |
| `assessments` | list[Assessment] | All assessments scoped to this variant. |
| `vulnerabilities` | dict[string, Vulnerability] | All vulnerabilities that have at least one assessment in this variant, keyed by vulnerability ID. |

---

### Scan Object

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Scan ID (UUID). |
| `description` | string | Description of the scan (may be empty). |
| `timestamp` | string | Scan datetime in ISO 8601 format. |
| `variant_id` | string | UUID of the variant this scan belongs to. |
| `scan_type` | string | `sbom` or `tool`. |
| `scan_source` | string or null | Scanner name for a tool scan. |
| `run_id` | string or null | Operation-queue batch identifier shared by grouped tool scans. |
| `variant` | Variant | The variant object this scan belongs to. |
| `sbom_documents` | dict[string, SBOM Document] | All SBOM documents produced by this scan, keyed by UUID. |
| `packages` | dict[string, Package] | All packages found across this scan's SBOM documents, keyed by `name@version`. |

---

### SBOM Document Object

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | SBOM document ID (UUID). |
| `path` | string | File path of the SBOM document. |
| `source_name` | string | Name of the source that produced this document. |
| `format` | string | Format of the document (e.g. `spdx`, `cdx`, `openvex`, `yocto_cve_check`). |
| `scan_id` | string | UUID of the scan this document belongs to. |
| `variant_id` | string | UUID of the variant this document belongs to (derived from its scan). |
| `packages` | dict[string, Package] | All packages listed in this document, keyed by `name@version`. |
| `vulnerabilities` | dict[string, Vulnerability] | All vulnerabilities affecting any package in this document, keyed by vulnerability ID. |

#### Possible values for `status`

| Value | Description | Filter |
|-------|-------------|--------|
| `in_triage`, `under_investigation` | Vulnerability found but presence not confirmed. Default status. | `status_pending`, `status_active` |
| `affected`, `exploitable` | Vulnerability confirmed and affecting the product. | `status_affected`, `status_active` |
| `fixed`, `resolved`, `resolved_with_pedigree` | Vulnerability is fixed and no longer exploitable. | `status_fixed`, `status_inactive` |
| `not_affected`, `false_positive` | Vulnerability is a false positive or not affecting us. | `status_ignored`, `status_inactive` |

#### Possible values for `justification`

- `component_not_present`
- `vulnerable_code_not_present`
- `vulnerable_code_not_in_execute_path`
- `vulnerable_code_cannot_be_controlled_by_adversary`
- `inline_mitigations_already_exist`
- `code_not_present`
- `code_not_reachable`
- `requires_configuration`
- `requires_dependency`
- `requires_environment`
- `protected_by_compiler`
- `protected_at_runtime`
- `protected_at_perimeter`
- `protected_by_mitigating_control`

#### Possible values for `responses`

- `can_not_fix`
- `will_not_fix`
- `update`
- `rollback`
- `workaround_available`

---

## Filters and Helpers

In addition to [Jinja built-in filters](https://jinja.palletsprojects.com/en/3.1.x/templates/#list-of-builtin-filters), the following custom filters are available.

### Conversion

| Filter | Description |
|--------|-------------|
| `as_list` | Convert a dict to a list using `.values()`. |
| `limit(n)` | Limit the number of results to `n` (int). |
| `print_iso8601` | Transform an ISO 8601 duration string into a human-readable format (e.g. `P2DT4H` → `2d 4h`) or format a datetime string. |
| `escape_adoc` | Decode HTML entities, strip HTML tags, and neutralize structural AsciiDoc headings/block fences in free text. Apply after truncation when embedding descriptions or notes in AsciiDoc. |

### Status Filtering

| Filter | Description |
|--------|-------------|
| `status(x)` | Keep only vulnerabilities with status in `x` (str or list of str). |
| `status_pending` | Shorthand for `in_triage` + `under_investigation`. |
| `status_affected` | Shorthand for `affected` + `exploitable`. |
| `status_fixed` | Shorthand for `fixed` + `resolved` + `resolved_with_pedigree`. |
| `status_ignored` | Shorthand for `not_affected` + `false_positive`. |
| `status_active` | `status_pending` + `status_affected`. |
| `status_inactive` | `status_fixed` + `status_ignored`. |

### Score Filtering

| Filter | Description |
|--------|-------------|
| `severity(x)` | Keep only vulnerabilities with severity in `x` (str or list of str). |
| `epss_score(x)` | Keep only vulnerabilities with EPSS score ≥ `x`. `x` is a percentage in [0, 100]. |

### Date Filtering

Both `last_assessment_date` and `filter_by_publish_date` accept date expressions in the following formats:

| Format | Meaning |
|--------|---------|
| `'>2026-01-01'` | After this date (exclusive) |
| `'>=2026-01-01'` | After or on this date (inclusive) |
| `'<2026-01-01'` | Before this date (exclusive) |
| `'<=2026-01-01'` | Before or on this date (inclusive) |
| `'2026-01-01..2026-01-31'` | Between two dates (inclusive) |
| `'2026-01-01'` | Exact date match |

| Filter | Description |
|--------|-------------|
| `last_assessment_date(x)` | Filter vulnerabilities by their last assessment date. |
| `filter_by_publish_date(x, include_unknown=False)` | Filter by CVE publish date. Pass `include_unknown=True` to also include vulnerabilities with no known publish date. |

> **Note for `filter_by_publish_date`:** Exact date match ignores time (hours, minutes, seconds). When `include_unknown=True`, also includes vulnerabilities without a published date.

### Sorting

| Filter | Description |
|--------|-------------|
| `sort_by_epss` | Sort vulnerabilities by EPSS score, highest first. |
| `sort_by_effort` | Sort vulnerabilities by effort (`effort.likely`), most effort first. |
| `sort_by_last_modified` | Sort vulnerabilities by latest assessment date, most recent first. |
| `sort_by_scan_date` | Sort scans by timestamp, most recent first. Accepts a dict (keyed by ID) or a list. |

### Relational Filtering

| Filter | Description |
|--------|-------------|
| `filter_by_variant(variant_id)` | Keep only items that belong to the given variant. Works on assessments, scans, and vulnerabilities (matches against `variant_ids`). Accepts a dict or a list. |
| `filter_by_project(project_id)` | Keep only items whose `project_id` matches. Works on variants. Accepts a dict or a list. |

---

## Common Examples and Tips

**Get total count of active/open vulnerabilities:**
```
{{ vulnerabilities | as_list | status_active | length }}
```

**Get active vulnerability with highest EPSS score:**
```
{{ vulnerabilities | as_list | status_active | sort_by_epss | first }}
```

**Get vulnerabilities assessed after a specific date:**
```
{{ vulnerabilities | as_list | last_assessment_date('>2026-01-01') | length }}
```

**Get vulnerabilities assessed in January 2026:**
```
{{ vulnerabilities | as_list | last_assessment_date('2026-01-01..2026-01-31') }}
```

**Get critical vulnerabilities assessed recently (after or on 2026-01-15):**
```
{{ vulnerabilities | as_list | severity('critical') | last_assessment_date('>=2026-01-15') | sort_by_last_modified }}
```

**List all critical unresolved vulnerabilities, sorted by most recent assessment:**
```
{% for vuln in vulnerabilities | as_list | severity('critical') | status_active | sort_by_last_modified %}
- {{ vuln.id }} (CVSS: {{ vuln.severity.max_score }})
{% endfor %}
```

**Use an environment variable in a template:**
```
Product: {{ env("PRODUCT_NAME", "unknown") }}
Version: {{ env("PRODUCT_VERSION", "unknown") }}
```

**List all projects and their variants:**
```
{% for project in projects | as_list %}
Project: {{ project.name }}
  {% for variant in variants | filter_by_project(project.id) %}
  - Variant: {{ variant.name }}
  {% endfor %}
{% endfor %}
```

**List most recent scans for a variant:**
```
{% for scan in scans | filter_by_variant(variant_id) | sort_by_scan_date | limit(5) %}
- {{ scan.timestamp | print_iso8601 }}: {{ scan.description }}
{% endfor %}
```

**List SBOM documents:**
```
{% for doc in sbom_documents | as_list %}
- {{ doc.source_name }} ({{ doc.format }}): {{ doc.path }}
{% endfor %}
```

---

## Traversing the data models

The template renderer embeds the related entities listed below, allowing
reports to traverse projects, variants, scans, documents, and packages.

The relationships are:

```
Project
  └─ Variant  (.scans, .sbom_documents, .packages, .vulnerabilities, .assessments)
       └─ Scan  (.sbom_documents, .packages, .variant)
            └─ SBOM Document  (.packages, .vulnerabilities, .scan_id)
                 └─ Package  (.sbom_documents, .variants, .vulnerabilities)
                      └─ Vulnerability  (.variant_ids, .assessments_by_variant)
```

References are added explicitly by the template renderer. For example, an SBOM
document has `scan_id` and `variant_id`, but no embedded `.scan` object.

**Loop over vulnerabilities per variant:**
```
{% for variant in variants | as_list %}
{{ variant.name }}
  {% for vuln in variant.vulnerabilities.values() | sort_by_epss %}
  - {{ vuln.id }} (EPSS: {{ vuln.epss.score }})
  {% endfor %}
{% endfor %}
```

**Loop over packages per SBOM document:**
```
{% for doc in sbom_documents | as_list %}
{{ doc.source_name }} — {{ doc.path }}
  {% for pkg_id, pkg in doc.packages.items() %}
  - {{ pkg.name }} {{ pkg.version }}
  {% endfor %}
{% endfor %}
```

**Full traversal:**
```
{% for project in projects | as_list %}
  {% for variant in variants | filter_by_project(project.id) %}
    {% for doc in variant.sbom_documents.values() %}
      {% for vuln in doc.vulnerabilities.values() | status_active | sort_by_epss %}
        {{ vuln.id }} in {{ doc.path }}
      {% endfor %}
    {% endfor %}
  {% endfor %}
{% endfor %}
```

**Per-variant assessment breakdown for a single vulnerability:**
```
{% for variant_id, assessments in vuln.assessments_by_variant.items() %}
  Variant {{ variant_id }}: {{ assessments | first | attr('status') }}
{% endfor %}
```

**Packages that appear in multiple variants:**
```
{% for pkg_id, pkg in packages.items() %}
  {% if pkg.variants | length > 1 %}
  {{ pkg.name }} {{ pkg.version }} appears in {{ pkg.variants | length }} variants
  {% endif %}
{% endfor %}
```

**Most recent scan for a variant (using embedded `.scans`):**
```
{% for variant in variants | as_list %}
  {% set latest = variant.scans | sort_by_scan_date | first %}
  {{ variant.name }}: last scanned {{ latest.timestamp | print_iso8601 }}
{% endfor %}
```

---

## Using Images and Logos in Reports

VulnScout provides a first-class image embedding mechanism that produces self-contained output in every format (raw AsciiDoc, HTML, and PDF) without any `imagesdir` or safe-mode configuration on the template author's side.

### `embed_image(name, width=None, alt="")`

Inlines a named asset as a base64 data-URI AsciiDoc block image macro.

| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | string | Filename of the image (e.g. `"logo.png"`). Plain basename only — no directory separators. |
| `width` | integer | Optional rendered width in pixels. |
| `alt` | string | Optional alt text / caption. |

Returns an `image::data:…[…]` AsciiDoc macro, or an **empty string** if the file cannot be found, so `{% if embed_image(…) %}` guards work.

**Example — optional logo at the top of a report:**

```jinja
{% set _logo = embed_image("logo.png") or embed_image("logo.svg") %}
{% if _logo %}
[.right]
{{ _logo }}

{% endif %}
= My Report
```

**Example — sized, captioned logo:**

```jinja
{{ embed_image("logo.png", width=150, alt="Company Logo") }}
```

### `find_asset(name)`

Returns the absolute path to a named asset, or `None` if not found.  Useful when you need to pass the path elsewhere (e.g. to an external tool invoked from a template).

### Asset Search Order

Assets are resolved from the following directories in order; the first match wins:

| Priority | Path |
|----------|------|
| 1 (highest) | `/cache/vulnscout/templates/assets` |
| 2 | `.vulnscout/templates/assets` |
| 3 | `templates/assets` |
| 4 | `/scan/templates/assets` |
| 5 (lowest) | Built-in `src/views/templates/assets` (inside the container image) |

Rendering accepts `png`, `jpg`, `jpeg`, `gif`, `svg`, and `webp`. HTTP uploads
accept only verified raster images (`png`, `jpg`, `jpeg`, `gif`, `webp`); SVG is
not accepted through the browser/API upload endpoint. Trusted local SVG assets
can still be staged through the CLI or installed manually.

### Adding Assets

**Via the web UI:**
Use **Settings → Custom reports & assets** to upload or manage report templates
and raster images. Assets are saved to the first writable `assets` directory.

**Via the CLI:**
```bash
./vulnscout --add-asset /path/to/logo.png --report my_report.adoc
```
The image is staged to `/cache/vulnscout/templates/assets/logo.png` before the report runs.

**Via the API:**
```http
POST /api/documents/assets HTTP/1.1
Host: localhost:7275
Content-Type: multipart/form-data

file=<image file>
```
Returns `{"name": "logo.png", "message": "Asset uploaded."}` on success (HTTP 201).

**Manually (host-side):**
With the default host cache path, drop the image into
`.vulnscout/cache/templates/assets/` (or `$VULNSCOUT_CACHE_DIR/templates/assets/`
with a custom cache). The existing cache mount makes it available on the next
report generation without a container restart.

### Native `image::` Macros (secondary mechanism)

Template authors who prefer the standard AsciiDoc `image::filename[]` syntax are also supported.  At conversion time VulnScout automatically passes:

* `-S safe` with `-B <temp-dir>` — restricts asciidoctor to reading files from
  a sandboxed temporary directory populated only with the referenced,
  resolved assets (no arbitrary filesystem access, unlike `unsafe` mode).
* `-a imagesdir=<copied-assets-dir>` — resolves relative image paths.
* `-a data-uri` (HTML output only) — inlines resolved images as base64 in the HTML file.

`allow-uri-read` remains **disabled** — remote image fetching is never enabled.
