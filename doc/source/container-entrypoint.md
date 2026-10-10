# Using Container Entrypoint

The VulnScout container ships with an entrypoint script at `/scan/src/entrypoint.sh`.
This is what the `./vulnscout` host wrapper calls under the hood. You can also invoke it directly via `docker exec` (or `podman exec`) for advanced workflows or CI pipeline integration where you manage the container yourself.

```bash
docker exec <container> /scan/src/entrypoint.sh [OPTIONS]
# or
podman exec <container> /scan/src/entrypoint.sh [OPTIONS]
```

> **Note:** VulnScout is compatible with both **Docker** and **Podman**. All `docker` commands shown in this page can be replaced with `podman`.

---

## Container Lifecycle

When the container starts with no arguments, it enters **daemon mode** — it stays alive and waits for commands sent via `docker exec` (or `podman exec`). This is the mode used by the `./vulnscout` host wrapper.

```bash
# The container starts in daemon mode by default
docker run -d --name vulnscout sflinux/vulnscout:v0.22

# Then send commands to it
docker exec vulnscout /scan/src/entrypoint.sh --serve
```

---

## Command Reference

### Settings

| Flag | Description |
|------|-------------|
| `--project <name>` | Project name for the invocation (default: `default`) |
| `--variant <name>` | Variant name for the invocation. Imports/scans and custom OpenVEX transfers default to `default`; reports and other exports include all project variants when omitted |

### Input Commands

| Flag | Description |
|------|-------------|
| `--add-spdx <path>` | Add an SPDX 2/3 JSON SBOM named `*.spdx.json`, or an archive (`.tar`, `.tar.gz`, `.tar.zst`) containing such files. Tag-value `.spdx` files are not loaded by this wrapper |
| `--add-cve-check <path>` | Add a Yocto CVE check JSON file |
| `--add-yocto-vex <path>` | Add a Yocto VEX JSON file (from `vex.bbclass`) |
| `--add-openvex <path>` | Add an OpenVEX JSON file matching `*openvex*.json` |
| `--add-cdx <path>` | Add a CycloneDX `.json` file |
| `--add-grype <path>` | Add a Grype results file (`.grype.json`) |
| `--perform-scans <types|all>` | Run one or more scanners: `grype`, `nvd`, `osv`, `sbom-cve-check`, or `all`. Separate types with commas or repeat the option. Grype exports the current DB as CycloneDX, runs Grype and merges results; memory is capped by `GRYPE_MEMLIMIT` (default: auto ~80 % of cgroup limit). |

`all` runs every available scanner in the order Grype, NVD, OSV, sbom-cve-check. `--refresh-vulnerability-data` is separate: it enriches existing vulnerability records rather than discovering new findings.

The previous `--perform-grype-scan`, `--perform-nvd-scan`, `--perform-osv-scan`, and `--perform-sbom-cve-check-scan` flags remain supported as aliases.

### Scan & Output Commands

| Flag | Description |
|------|-------------|
| `--serve` | Run scan then start the interactive web UI (port 7275). Incompatible with `--match-condition` |
| `--refresh-vulnerability-data` | Refresh stored EPSS, NVD, EUVD, and GHSA data on demand. Without new inputs, `--project` and `--variant` can limit the refresh scope |
| `--report <template>` | Generate a report from a template (name or path). `--project` includes every project variant; adding `--variant` restricts the report to that variant. The `default` project is used when `--project` is omitted. Unknown scopes fail rather than broadening the report. If a path is given, the template is staged automatically |
| `--export-spdx` | Export project as SPDX 3.0 SBOM to `/scan/outputs/` |
| `--export-cdx` | Export project as CycloneDX 1.6 SBOM to `/scan/outputs/` |
| `--export-openvex` | Export project as OpenVEX document to `/scan/outputs/` |
| `--export-custom-vulnscout-data` | Export custom VulnScout JSON data for all project variants, or the selected `--variant`, to `/scan/outputs/` |
| `--amend` | Update the existing custom VulnScout/OpenVEX output file while preserving stable record ordering; fails if the file does not exist |
| `--import-custom-vulnscout-data <path>` | Import custom VulnScout JSON data using the variant metadata in the file |
| `--use-original-timestamps` | With either custom import, preserve file timestamps |
| `--export-custom-openvex-assessments` | Export custom assessments for the selected `--variant` as an OpenVEX `.json` file |
| `--import-custom-openvex-assessments <path>` | Import an OpenVEX `.json` file into the selected `--variant` |
| `--use-current-timestamps` | With either custom import, use the current system time |
| `--match-condition <expr>` | Exit with code 2 if expression matches stored data for any in-scope vulnerability; it does not refresh EPSS. A project without a variant includes all its variants. Incompatible with `--serve` |
| `--delete-scan <id>` | Delete a past scan by its ID |
| `--delete-outdated` | Delete outdated package evidence and custom assessments across all projects and variants |
| `--delete-empty-scans` | Delete later scans with no recorded changes, preserving each variant's initial scan |
| `--delete-orphaned-vulns` | Delete vulnerabilities with no scan evidence in any project or variant |
| `--add-asset <path>` | Stage a report image under `/cache/vulnscout/templates/assets/` |
| `--export-context` | Export the selected project's AI context to `/scan/outputs/context-export.json`, optionally restricted by `--variant` |
| `--import-context <path>` | Restore AI context using project/variant names in the file; invocation scope does not remap destinations |

Custom VulnScout imports use the current time by default; custom OpenVEX imports
preserve file timestamps by default. The timestamp flags override these defaults.
Only the underlying Flask custom-OpenVEX commands require an explicit variant;
the entrypoint supplies `default` when omitted.

SBOM exports include all project variants unless `--variant` is supplied. Unlike
reports, an unknown export project currently warns and exports all data; an
unknown export variant warns and exports its whole project.

### Data Retrieval Commands

| Flag | Description |
|------|-------------|
| `--list-projects` | List all projects and their variants |
| `--list-scans` | List all past scans |
| `--json` | Output objects in JSON format |

### Configuration Commands

| Flag | Description |
|------|-------------|
| `--config <key> <value>` | Set a persistent config value in `/etc/vulnscout/config.env` |
| `--config-list` | Show current configuration (sensitive values masked) |
| `--config-clear <key>` | Remove a config key |

### Other Commands

| Flag | Description |
|------|-------------|
| `--help`, `-h` | Show help message |
| `--version` | Print the VulnScout version |
| `daemon` | Enter daemon mode (default when no arguments are given) |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Execution error (invalid arguments, scan failure, configuration error) |
| `2` | Match condition triggered — at least one vulnerability matched the expression |

---

## Execution Order

When multiple flags are provided in a single invocation, the entrypoint processes them in this order:

1. **Input staging** — Files specified with `--add-*` are copied into `/scan/inputs/<type>/`
2. **Scan** — If inputs, `--serve`, a match condition, a scanner, or a refresh was requested, the scan pipeline runs:
   - Web server started in background (if `--serve`)
   - Database migration (`flask db upgrade`)
   - Input files merged into the database
   - Grype scan (if `grype` or `all` was selected; the legacy `--perform-grype-scan` flag is also supported)
   - NVD CPE scan (local NVD-FKIE mode by default, if `nvd` or `all` was selected)
   - OSV PURL scan (if `osv` or `all` was selected)
   - sbom-cve-check scan (if `sbom-cve-check` or `all` was selected)
   - Vulnerability processing; stored NVD, EPSS, EUVD, and GHSA data is refreshed only when `--refresh-vulnerability-data` is requested
   - Input files cleaned up after processing
   - With only a refresh and no inputs/scanners/condition, existing vulnerability data is refreshed directly
3. **Reports** — Templates specified with `--report` are generated for every variant in the selected project, or only the selected `--variant`
4. **Exports** — SBOM formats specified with `--export-*` are written
5. **Custom data and context** — Export/import of review data and AI context

When `--serve` is used, the scan step waits in the web server's foreground
process; later reports and exports are not produced until that process exits.
Use a separate invocation for those commands while the web UI is running.

---

## Internal Paths

The following paths inside the container are relevant:

| Path | Purpose |
|------|---------|
| `/scan/` | Base directory for the VulnScout application |
| `/scan/src/` | Python/Flask backend source code |
| `/scan/inputs/` | Staging area for input files (cleaned after each scan) |
| `/scan/outputs/` | Default output directory for reports and exports |
| `/cache/vulnscout/templates/` | Custom report templates (user-installed, persisted via cache volume) |
| `/scan/src/views/templates/` | Built-in report templates |
| `/cache/vulnscout/vulnscout.db` | SQLite database |
| `/etc/vulnscout/config.env` | Persistent configuration file |
| `/cache/vulnscout/local_databases/` | Local sbom-cve-check advisory database clones (NVD-FKIE + CVEList), stored inside the cache volume next to `vulnscout.db`. Override the host path with `$VULNSCOUT_SBOM_CVE_CHECK_DB_DIR` (then mounted at `/local_databases`) |
| `/scan/status.txt` | Scan progress status (used by the web UI) |

For local execution outside the container, `VULNSCOUT_BASE_DIR` and `VULNSCOUT_INPUTS_DIR` can override `/scan` and `/scan/inputs`; container defaults are unchanged.

---

## Examples

**Add inputs and start the web UI:**
```bash
docker exec vulnscout /scan/src/entrypoint.sh \
  --project demo --variant x86 \
  --add-spdx /scan/inputs/sbom.spdx.json \
  --add-cve-check /scan/inputs/cve-check.json \
  --add-yocto-vex /scan/inputs/vex.json \
  --serve
```

**Run a CI scan with a match condition:**
```bash
docker exec vulnscout /scan/src/entrypoint.sh \
  --project demo \
  --add-spdx /scan/inputs/sbom.spdx.json \
  --match-condition "cvss >= 9.0 or (cvss >= 7.0 and epss >= 50%)"
```

This evaluates all variants in `demo`. Add `--variant x86` to evaluate only that variant. With neither option, matching uses `default/default`.

**Generate reports and export SBOMs without a new scan:**
```bash
docker exec vulnscout /scan/src/entrypoint.sh \
  --project demo --variant x86 \
  --report summary.adoc \
  --report all_assessments.adoc \
  --export-spdx --export-cdx
```

Omit `--variant x86` to include every variant in `demo`.

**Run a sbom-cve-check scan:**
```bash
docker exec vulnscout /scan/src/entrypoint.sh \
  --project demo --variant x86 \
  --add-spdx /scan/inputs/sbom.spdx.json \
  --perform-scans sbom-cve-check
```

> By default the sbom-cve-check databases live in `/cache/vulnscout/local_databases` (inside the cache volume, next to `vulnscout.db`); set `$VULNSCOUT_SBOM_CVE_CHECK_DB_DIR` to use a shared host clone mounted at `/local_databases` instead. With `SBOM_CVE_CHECK_AUTO_UPDATE=1` the databases are cloned automatically on first use and refreshed before every scan.

**Set persistent configuration:**
```bash
docker exec vulnscout /scan/src/entrypoint.sh --config NVD_API_KEY abc123
docker exec vulnscout /scan/src/entrypoint.sh --config-list
```
