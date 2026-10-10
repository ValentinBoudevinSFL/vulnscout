# VulnScout

**Savoir-faire Linux**

![vulnscout logo](_static/vulnscout_logo.jpeg)

![License](https://img.shields.io/badge/License-GPL%203.0-green.svg)

---

## Introduction

VulnScout is designed to analyse and identify vulnerabilities in software components and dependencies using an **SBOM (Software Bill Of Materials)**.

It discovers vulnerabilities with **Grype**, **NVD**, **OSV**, and **sbom-cve-check**, and enriches existing vulnerability records with **NVD**, **EPSS**, **GitHub Advisory**, and **ENISA EUVD** data.

VulnScout also provides a **web interface** for visualisation, triage and assessment, and a **command-line interface** to generate enriched output files.

### VulnScout Features

- Analyse SBOMs and vulnerability files (SPDX 2/3, CycloneDX, Yocto CVE check, Yocto VEX, OpenVEX, Grype)
- Discover vulnerabilities with Grype, NVD, OSV, and sbom-cve-check; refresh risk and advisory metadata separately
- Manage **projects and variants** for multi-target builds
- Web interface for visualisation, triage, and assessment
- **Vulnerability review** — assess, justify, and track the status of each vulnerability
- **Operation queue** — track scans, refreshes, uploads, and exports across browser tabs
- **Dependency graph** — explore package dependencies recorded in SPDX and CycloneDX SBOMs
- **AI-assisted triage** — review pending AI assessments and request independent reviews of custom assessments
- **Local agent chat** — use a Copilot or provider-backed assistant with the current project context
- Non-interactive / CI mode with configurable **match conditions**
- Generate customisable reports (AsciiDoc, HTML, PDF, CSV)
- Export enriched SBOMs (SPDX 2.3, SPDX 3.0, CycloneDX 1.4–1.6, OpenVEX)
- Custom CVSS scoring per vulnerability
- Time estimation tracking for remediation effort
- Import and export custom assessments for backup and sharing

---

## Architecture

![Architecture](_static/architecture_with_logo.png)

### Supported Input Files

- **SPDX 2.2 and 2.3** (Packages) — JSON; the SPDX parser also supports tag-value files, but the host/container scan wrapper currently loads only `*.spdx.json`
- **SPDX 3.0** (Packages + vulnerabilities)
- **CycloneDX 1.4, 1.5, 1.6** (Packages + vulnerabilities)
- **Grype native JSON format** (Packages + vulnerabilities)
- **Yocto JSON output** of the `cve-check` module (Packages + vulnerabilities)
- **Yocto VEX JSON** from `vex.bbclass` (Packages + vulnerabilities + patch information)
- **OpenVEX JSON** (Vulnerability assessments)

SPDX archives (`.tar`, `.tar.gz`, `.tar.zst`) can contain multiple `*.spdx.json` documents.

### Supported Output Files

- SPDX 2.3 (Packages) — JSON through the Flask CLI; JSON/XML through the document export API
- SPDX 3.0 (Packages + vulnerabilities)
- CycloneDX 1.4, 1.5, 1.6 (Packages + vulnerabilities)
- OpenVEX (vulnerabilities + assessments)

Reports:

- AsciiDoc
- HTML
- PDF

Other outputs:

- Summary: AsciiDoc, HTML, PDF
- Time estimates: CSV
- Vulnerabilities: CSV, TXT

---

### Vulnerability Data Sources

VulnScout pulls vulnerability and risk data from multiple trusted sources:

- **NVD (National Vulnerability Database)**
- All data sources supported by **Grype**
- **OSV (Open Source Vulnerabilities)**
- Local **NVD-FKIE** and **CVEList V5** advisory databases via **sbom-cve-check**
- **EPSS (Exploit Prediction Scoring System)**
- **GitHub Security Advisories (GHSA)**
- **ENISA EUVD**, including the EU Known Exploited Vulnerabilities catalogue
- Information embedded in input files

---

### Custom CVSS Scoring

VulnScout allows you to add a **custom CVSS vector string** to a vulnerability, enabling organisation-specific vulnerability scoring.

---

## Licence

Copyright (C) 2017–2026 Savoir-faire Linux, Inc.

VulnScout is released under the **GPL-3.0 license**.

[Savoir-faire Linux](https://savoirfairelinux.com/fr)
