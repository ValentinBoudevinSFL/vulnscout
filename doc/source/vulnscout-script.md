# VulnScout CLI

The `./vulnscout` script is the main host-side entry point for running VulnScout.
It manages the container lifecycle (Docker or Podman) and forwards commands to the container's entrypoint.

```
./vulnscout [options] [command]
```

---

## Container Lifecycle

The `vulnscout` script manages the container automatically (using Docker or Podman, whichever is available). You can also control it explicitly:

```bash
# Start the container (done automatically by most commands)
./vulnscout start

# Stop and remove the container
./vulnscout stop

# Restart the container (useful after changing config)
./vulnscout restart
```

---

## Updating VulnScout

To update VulnScout to the latest version, pull the latest container image and restart:

```bash
./vulnscout --update
```

Then verify the new version is correctly running:

```bash
./vulnscout --version
```

---

## Interactive Mode (Web UI)

Use `--serve` to start the web dashboard after importing any supplied inputs.
Running `./vulnscout` without arguments shows help; `start` starts only the
background container, not the web server.

```bash
./vulnscout --serve \
  --add-spdx $(pwd)/example/spdx3/core-image-minimal-qemux86-64.rootfs.spdx.json \
  --add-cve-check $(pwd)/example/spdx3/core-image-minimal-qemux86-64.rootfs.json
```

After starting the scan, open:

```
http://localhost:7275
```

If data has already been imported, the web UI can be started without any additional arguments:

```bash
./vulnscout --serve
```

### Web Interface Settings

The web interface includes a **Settings** tab that provides:

- **Rename Project** — Select a project and give it a new name (must be unique across all projects).
- **Rename Variant** — Select a variant within a project and rename it (must be unique within the project).
- **Import SBOM** — In **Variants**, select a project and variant, then upload one
  or more files directly from the browser. Create the project/variant first if needed.
  Formats are auto-detected: SPDX (2/3), CycloneDX, OpenVEX, Yocto CVE check,
  Yocto VEX, and Grype. Select no refresh, a complete refresh, or custom
  vulnerability-data sources after the import.
- **Data Maintenance** — In **General Settings**, remove outdated data, empty scans, or CVEs no longer included in any project or variant.
  This action is not limited to the project or variant currently selected in the web interface.

### Removing Outdated Data

VulnScout retains historical package evidence after an SBOM changes so it can identify
outdated findings and assessments. After the replacement SBOM and scans have been
reviewed, remove this obsolete data from **Settings → General Settings → Data Maintenance**.

The confirmation dialog previews every package/variant and custom assessment selected
for deletion. The cleanup applies to every project and variant in the database.

The same global cleanup is available to automation and CI:

```bash
./vulnscout --delete-outdated
./vulnscout --delete-empty-scans
./vulnscout --delete-orphaned-vulns
```

The cleanup removes outdated package observations, SBOM links, and custom assessments.
It then removes a finding, package, or vulnerability only when nothing else references it.
When an orphaned vulnerability is removed, its exclusive metrics and refresh metadata are
removed as well. Vulnerabilities and package records that are still referenced by current
or other-variant data are preserved.

Empty-scan cleanup preserves each variant's initial scan and removes later scans only when
the scan-history diff contains no package, finding, CVE, or assessment changes. Orphaned-CVE
cleanup removes vulnerabilities with no scan evidence in any variant, together with their
findings, assessments, metrics, and refresh metadata.

---

## Projects and Variants

VulnScout organises data into **projects** and **variants**. A project typically maps to a product, and variants represent different builds or architectures (e.g. `x86_64`, `aarch64`).

Both flags are optional. Imports and scanner commands use `default/default`
when omitted. Reports, SBOM exports, custom VulnScout JSON exports, and context
exports include every variant of the selected project unless `--variant` is
provided. Custom OpenVEX transfers operate on one variant, defaulting to
`default`. Match-condition scope is described below.

```bash
./vulnscout --project <name> --variant <name> <command>
```

Example:

```bash
./vulnscout --project demo --variant x86 \
  --add-spdx $(pwd)/example/spdx3/core-image-minimal-qemux86-64.rootfs.spdx.json \
  --add-cve-check $(pwd)/example/spdx3/core-image-minimal-qemux86-64.rootfs.json
```

## Input Sources

VulnScout accepts multiple input file types. Commands can be chained and will automatically trigger a scan.

### Refresh Vulnerability Data

Use `--refresh-vulnerability-data` with an input command to enrich the vulnerabilities
imported by that run with current EPSS, NVD, ENISA EUVD, and GitHub Advisory data:

```bash
./vulnscout \
  --add-spdx $(pwd)/example/spdx3/core-image-minimal-qemux86-64.rootfs.spdx.json \
  --refresh-vulnerability-data
```

Inside the container, the equivalent Flask command is:

```bash
flask --app src.bin.webapp process --refresh-vulnerability-data
```

The option can also refresh vulnerability data already in the database. Omit
`--project` to refresh every vulnerability, or supply it to restrict the refresh to
that project's active vulnerabilities:

```bash
./vulnscout --refresh-vulnerability-data
./vulnscout --project demo --refresh-vulnerability-data
./vulnscout --project demo --variant x86 --refresh-vulnerability-data
```

Inside the container, use `flask --app src.bin.webapp refresh-vulnerability-data`
with optional `--project` and `--variant` arguments. A variant requires its project
because variant names are project-local.

The refresh enriches existing imported CVE and GHSA records; it does not discover new
findings. Providers with no applicable vulnerability identifiers are skipped. If any
applicable provider fails, processing continues through the remaining providers and the
command exits with an error listing the failed sources.

### SPDX SBOM

```
--add-spdx <path>
```

Path to an SPDX 2 or SPDX 3 JSON SBOM named `*.spdx.json`, or an archive
(`.tar`, `.tar.gz`, `.tar.zst`) containing files with that suffix. The underlying
SPDX parser supports tag-value (`.spdx`) files, but the host/container scan
wrapper currently does not load them.

---

### CycloneDX SBOM

```
--add-cdx <path>
```

Path to a CycloneDX file.

---

### Yocto CVE Check Output

```
--add-cve-check <path>
```

JSON output from the Yocto `cve-check` task.

---

### Yocto VEX Output

```
--add-yocto-vex <path>
```

JSON output from the Yocto `vex.bbclass` task.  Carries richer CPE and
patch-file information than the plain cve-check output.

---

### OpenVEX

```
--add-openvex <path>
```

Include vulnerability assessments provided as OpenVEX. The filename must
contain `openvex` and end with `.json`, for example `assessments.openvex.json`.

---

### Grype

```
--add-grype <path>
```

Import a Grype native JSON file. Files should end with `.grype.json`.

---

### Combining Inputs

Multiple inputs can be chained in a single command:

```bash
./vulnscout --project demo --variant x86 \
  --add-spdx /path/to/sbom.spdx.json \
  --add-cve-check /path/to/cve-check.json \
  --add-openvex /path/to/assessments.openvex.json
```

```{tip}
The CLI flag selects the input directory, but the scan pipeline also checks
filenames: SPDX must end with `.spdx.json`, OpenVEX must match `*openvex*.json`,
Grype must end with `.grype.json`, and the other input types must end with
`.json`. Non-matching files are not imported. SPDX archives are automatically
extracted and their `.spdx.json` contents imported.
To enable the tolerant SPDX parser, use `./vulnscout --config IGNORE_PARSING_ERRORS true`.
```

---

## Performing a Grype Scan

VulnScout can run Grype on the current database contents:

```bash
./vulnscout --project demo --variant x86 --perform-scans grype
```

`--perform-scans` accepts `grype`, `nvd` (CPE-based), `osv` (PURL-based), and `sbom-cve-check` (local advisory databases). Select several with commas (`--perform-scans nvd,osv`) or by repeating the option, or select every available scanner with `--perform-scans all`. Scans always run in the order Grype, NVD, OSV, sbom-cve-check after inputs are merged. Vulnerability-data refresh is a separate option.

The NVD scanner uses the local NVD-FKIE database by default. To explicitly use
the NVD REST API, invoke the Flask CLI inside the container:

```bash
docker exec vulnscout flask --app src.bin.webapp nvd-scan \
  --project demo --variant x86 --mode api
```

Use `podman exec` instead when the host wrapper selected Podman. The wrapper
checks that the running image supports `--perform-scans`; older images must
be updated or run with `--dev` against this checkout.

The previous `--perform-grype-scan`, `--perform-nvd-scan`, `--perform-osv-scan`, and `--perform-sbom-cve-check-scan` flags remain supported as aliases.

This can be chained with other inputs to scan newly added files immediately:

```bash
./vulnscout --project demo \
  --add-spdx example/spdx3/core-image-minimal-qemux86-64.rootfs.spdx.json \
  --perform-scans grype
```

`--perform-scans grype` can consume significant RAM on large SBOMs.
VulnScout automatically caps Grype's memory at ~80 % of the container/cgroup limit.
Use `GRYPE_MEMLIMIT` to override:

```bash
# Set a persistent limit
./vulnscout --config GRYPE_MEMLIMIT 6GiB

# Or export it on the host before running (forwarded into the container)
export GRYPE_MEMLIMIT=24GiB
./vulnscout --project demo --perform-scans grype

# Disable the limit entirely
./vulnscout --config GRYPE_MEMLIMIT off
```

Accepts any value valid for Go's `GOMEMLIMIT` (`4GiB`, `8192MiB`, plain bytes).
Set to `off`, `0`, or `disabled` to remove the cap.

---

## Performing an sbom-cve-check Scan

`--perform-scans sbom-cve-check` runs a CVE scan powered by [sbom-cve-check](https://github.com/savoirfairelinux/sbom-cve-check). Unlike the NVD and OSV scanners, and once the databases are synced, this scan never makes network calls during analysis; it queries locally-cloned advisory databases (NVD-FKIE JSON feeds and CVEList V5).

```bash
./vulnscout --project demo --variant x86 --perform-scans sbom-cve-check
```

The scan can be chained with other inputs:

```bash
./vulnscout --project demo \
  --add-spdx example/spdx3/core-image-minimal-qemux86-64.rootfs.spdx.json \
  --perform-scans sbom-cve-check
```

---

## Non-Interactive Mode (CI / Automation)

For CI pipelines or automated scans, use the `--match-condition` argument instead of the web UI:

```bash
./vulnscout --project demo \
  --add-spdx /path/to/sbom.spdx.json \
  --add-cve-check /path/to/cve-check.json \
  --match-condition "((cvss >= 9.0 or (cvss >= 7.0 and epss >= 30%)) and (pending or affected))"
```

If vulnerabilities match the condition, the script exits with **code 2**, allowing CI systems to fail the pipeline.

Match conditions evaluate stored vulnerability data and do not automatically
refresh provider metadata. With inputs or scanners, add
`--refresh-vulnerability-data` to refresh before matching. For existing data
only, run the refresh first and the match condition separately: the host
wrapper's standalone-refresh branch does not forward match conditions or
report/export options.

When `--project demo` is supplied without `--variant`, the condition is evaluated across all variants in `demo`. Supplying both options limits evaluation to one variant. Omitting both options evaluates `default/default`; supplying only `--variant` selects that variant from the `default` project. Unknown names exit with **code 1**.

See the [Match Conditions](ci_conditions.md) page for the full syntax and token reference.

---

## Report Generation

Reports are generated from templates. VulnScout ships with built-in templates and also supports custom ones.
Use `--project` to select the report scope; when omitted, the `default` project is used. A project report includes all its variants. Add `--variant` to restrict the report to one variant in that project. Unknown project or variant names exit with **code 1** instead of broadening the report scope.

```bash
# Generate a report from a built-in template
./vulnscout --project demo --report summary.adoc

# Generate a report for one variant only
./vulnscout --project demo --variant x86 --report summary.adoc

# Generate a match-condition report
./vulnscout --project demo --match-condition "cvss >= 9.0" --report match_condition.adoc

# Pass a local template file path — stages and runs it in one step
./vulnscout --project demo --report /path/to/my-custom-report.adoc
```

Multiple reports can be generated in one command:

```bash
./vulnscout --project demo --report summary.adoc --report all_assessments.adoc
```

Reports are written to the outputs directory (default: `.vulnscout/outputs/`).

See the [Templates](templates.md) page for documentation on writing custom report templates.

---

## Exporting SBOM Files

VulnScout can export the enriched project data as standard SBOM formats. Exported files are written to the outputs directory (default: `.vulnscout/outputs/`).

```bash
# Export as SPDX 3.0 SBOM
./vulnscout --project demo --export-spdx

# Export as CycloneDX 1.6 SBOM
./vulnscout --project demo --export-cdx

# Export as OpenVEX document (vulnerabilities + assessments)
./vulnscout --project demo --export-openvex
```

Export commands can be chained with inputs and reports in a single invocation:

```bash
./vulnscout --project demo \
  --add-spdx /path/to/sbom.spdx.json \
  --add-cve-check /path/to/cve-check.json \
  --export-spdx --export-cdx --export-openvex \
  --report summary.adoc
```

With `--project` but no `--variant`, SBOM exports include every variant in that
project. Unlike report generation, the underlying SBOM export command currently
warns and broadens scope when a name is unknown: a missing project exports all
data, and a missing variant exports the whole project. Verify scope names before
using exports in automation.

The Flask CLI also supports SPDX 2.3 and CycloneDX 1.4/1.5 using
`export --format spdx2`, `cdx14`, or `cdx15`; the host flags select SPDX 3.0,
CycloneDX 1.6, and OpenVEX.

---

## Exporting and Importing Custom Assessments

VulnScout lets you export and re-import the assessments you have manually created through the web interface (review / triage decisions). This is useful for:

- Backing up your review work before re-importing SBOMs.
- Sharing assessment decisions across different VulnScout instances.
- Restoring triage state in CI pipelines after a database reset.

### VulnScout JSON

The `--export-custom-vulnscout-data` flag exports custom assessments, pending AI
assessments, CVSS scores, and time estimates as one VulnScout JSON file. It
includes every variant in the selected project unless `--variant` is provided.
After import, pending AI assessments are available from the Review page's **AI
Assessments** tab for approval or rejection.

```bash
./vulnscout --project demo --export-custom-vulnscout-data
```

Export one variant:

```bash
./vulnscout --project demo --variant x86 --export-custom-vulnscout-data
```

The `--import-custom-vulnscout-data` command restores entries according to the
variant metadata stored in the file. Imported assessments use the current
system time by default. Add `--use-original-timestamps` to preserve assessment
timestamps from the file. `--use-current-timestamps` is also accepted to select
the default explicitly.

Current version 2 exports identify targets with variant names and packages,
not instance-local variant UUIDs. Legacy version 1 files remain importable;
unsupported future versions are rejected explicitly.

See [VulnScout JSON format](custom-data-format.md) for the interchange schema.

```bash
./vulnscout --project demo --import-custom-vulnscout-data /path/to/custom_vulnscout_data_all.json

./vulnscout --project demo --import-custom-vulnscout-data /path/to/custom_vulnscout_data_all.json --use-original-timestamps
```

### OpenVEX

OpenVEX custom-assessment transfers operate on one JSON document and one
variant. The host and container wrappers use `default` when `--variant` is
omitted; the underlying Flask custom-OpenVEX commands require it explicitly.

```bash
# Export a variant
./vulnscout --project demo --variant x86 --export-custom-openvex-assessments

# Import into a variant
./vulnscout --project demo --variant x86 --import-custom-openvex-assessments /path/to/custom_openvex_x86.json

# Ignore OpenVEX statement timestamps and use the current system time
./vulnscout --project demo --variant x86 --import-custom-openvex-assessments /path/to/custom_openvex_x86.json --use-current-timestamps
```

OpenVEX imports preserve statement timestamps by default. Add
`--use-current-timestamps` to use the current system time, or use
`--use-original-timestamps` to select the default explicitly.

### Updating an Existing Review Export

Add `--amend` to either custom export command to update the existing output file
in `.vulnscout/outputs/`. Unchanged records keep their order, changed records are
replaced, and new records are appended, reducing Git diffs. Data outside the
selected variants is removed. The output file must already exist.

```bash
./vulnscout --project demo --export-custom-vulnscout-data --amend
./vulnscout --project demo --variant x86 --export-custom-openvex-assessments --amend
```

### AI Assessment Context

Context transfers are separate from assessment transfers:

```bash
./vulnscout --project demo --export-context
./vulnscout --project demo --variant x86 --export-context
./vulnscout --import-context /path/to/context-export.json
```

Exports write `context-export.json` to the outputs directory and include all
project variants unless one is selected. Import uses the project and variant
names recorded in the file, not the wrapper's scope flags; it overwrites matching
context and reports missing destinations or invalid entries. See
[AI Assessments](ai-assessments.md) for context fields and the import format.

---

## Configuration

### Configuration Commands

Persistent configuration is stored in `.vulnscout/cache/config.env` and is automatically loaded on each run.

```bash
# Set a config value
./vulnscout config <key> <value>

# List current configuration (prints the host config file verbatim)
./vulnscout config-list

# Remove a config key
./vulnscout config-clear <key>
```

Example — set an NVD API key for higher rate limits:

```bash
./vulnscout config NVD_API_KEY abc123
```

Host `config-list` does not mask secrets; do not share its output. The container
entrypoint's `--config-list` masks keys ending in `API_KEY`, `PASSWORD`, or
`SECRET`, but is not a general-purpose secret scrubber.

### Environment Variables

Use `vulnscout config` for persistent container settings. Host environment
variables configure the wrapper's `VULNSCOUT_*` paths and image; it also forwards
`GRYPE_MEMLIMIT` and `SBOM_CVE_CHECK_AUTO_UPDATE` when starting a container.
Arbitrary exported host variables are not automatically passed through. Stored
configuration is sourced on each run and can override host values.

Example:

```bash
./vulnscout config NVD_API_KEY abc123
```

#### Container & Runtime

| Variable | Description | Default |
|----------|-------------|---------|
| `VULNSCOUT_CONTAINER` | Name of the container | `vulnscout` |
| `VULNSCOUT_IMAGE` | Container image to use | `docker.io/sflinux/vulnscout:v0.22` |
| `VULNSCOUT_BUILD_DIR` | Root build directory on the host | `./.vulnscout` |
| `VULNSCOUT_OUTPUTS_DIR` | Directory for output files on the host | `$VULNSCOUT_BUILD_DIR/outputs` |
| `VULNSCOUT_CACHE_DIR` | Cache directory (SQLite database and config) | `$VULNSCOUT_BUILD_DIR/cache` |
| `FLASK_RUN_PORT` | Port inside the container; the host wrapper publishes the fixed mapping `7275:7275` | `7275` |
| `FLASK_RUN_HOST` | Host address for the web UI | `0.0.0.0` |
| `VITE_API_URL` | Optional backend API URL for the dev frontend (empty uses Vite's same-origin `/api` proxy) | empty |
| `USER_UID` | UID used to write output files | current user |
| `USER_GID` | GID used to write output files | current group |
| `REFRESH_REMOTE_DELAY` | Provider refresh interval (`never`, `always`, `48h`, `7d`, `2w`, etc.) | `2w` in a generated host config; `48h` in the container without that setting |

#### Scan & Enrichment

| Variable | Description | Default |
|----------|-------------|---------|
| `NVD_API_KEY` | NVD API key for higher rate limits | _(none)_ |
| `IGNORE_PARSING_ERRORS` | Continue scanning even if input files contain errors | `false` |
| `VERBOSE_MODE` | Enable verbose logging in the container | `false` |
| `GRYPE_MEMLIMIT` | Go soft memory limit for Grype (`4GiB`, bytes, or `off`) | auto, about 80% of available memory |
| `SBOM_CVE_CHECK_AUTO_UPDATE` | Clone/update local advisory databases before use; `0` allows offline use of existing clones | `1` |
| `VULNSCOUT_SBOM_CVE_CHECK_DB_DIR` | Optional host advisory directory mounted at `/local_databases` | unset; uses `$VULNSCOUT_CACHE_DIR/local_databases` |

`SBOM_CVE_CHECK_DATABASES_DIR` is the corresponding **container** path, normally
`/cache/vulnscout/local_databases`. When configuring a shared host clone, set
`VULNSCOUT_SBOM_CVE_CHECK_DB_DIR` and restart the container to apply the mount.

#### Report Metadata

| Variable | Description | Default |
|----------|-------------|---------|
| `PRODUCT_NAME` | Product name embedded in reports and SBOMs | _(none)_ |
| `PRODUCT_VERSION` | Product version embedded in reports | _(none)_ |
| `AUTHOR_NAME` | Author/company name embedded in reports | _(none)_ |
| `CLIENT_NAME` | Customer company name (optional, may be empty) | _(none)_ |
| `CONTACT_EMAIL` | Contact email embedded in reports | _(none)_ |
| `DOCUMENT_URL` | URL embedded in exported SBOM documents | _(none)_ |

---

## HTTP Proxy Configuration

VulnScout supports HTTP proxies. Set them via the config command:

```bash
./vulnscout config HTTP_PROXY http://proxy.example.com:8080
./vulnscout config HTTPS_PROXY http://proxy.example.com:8080
./vulnscout config NO_PROXY localhost,127.0.0.1
```

For the host wrapper, store proxy settings in its config file before starting
the container. When managing a container directly, pass them using the
container engine's `-e` options.
