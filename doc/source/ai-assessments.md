# AI Assessments

VulnScout can accept **AI-written vulnerability assessments**. An AI agent
researches a CVE, decides on a VEX status, and submits the assessment to
VulnScout, where it is stored as **pending review**. A pending AI assessment is
never treated as official — it does **not** affect a vulnerability's status and
is **not** included in the exported VEX — until a human reviewer explicitly
**approves** it in the web interface.

This page describes how to set up and use that workflow, as well as how to
request an AI second opinion on existing user-authored assessments.

---

## How it works

The following pieces work together:

- **VulnScout** — runs the API and web interface, stores assessments, and
  provides the review UI.
- **vulnscout_mcp** — an [MCP](https://modelcontextprotocol.io)
  (Model Context Protocol) server that exposes VulnScout's assessment and
  variant-context APIs as tools an AI agent can call.
- **cve-assessment skill** — an agent skill (shipped in this repository under
  `.github/skills/cve-assessment/`) that guides the agent through researching a
  CVE and submitting the result via the MCP tools.
- **assessment-review skill** — an agent skill under
  `.github/skills/assessment-review/` that independently reviews existing
  user-authored assessments, without changing them.

```
CVE / GHSA id
    ↓
AI agent + cve-assessment skill
    ↓  (calls MCP tools)
vulnscout_mcp  ──HTTP──▶  VulnScout API
    ↓
Pending AI assessment (origin = "ai")
    ↓
Human review in the web UI  ──▶  Approve (becomes official) / Reject (deleted)
```

A vulnerability has at most one pending AI assessment per variant. Submitting a
new AI assessment **replaces** the pending one on the same variant(s), without
any confirmation. If the old pending assessment also covered other variants, it
keeps those and only loses the overlapping ones. Approved assessments are never
replaced.

---

## Prerequisites

- A running VulnScout instance, reachable over HTTP (see
  [Getting Started](getting-started.md)). By default the API is served at
  `http://localhost:7275`.
- Python 3.10+ on the host that runs the MCP server.
- A clone of this `vulnscout` repository (the MCP server is vendored under
  `vulnscout_mcp/`).
- An MCP-capable agent client — either the **GitHub Copilot CLI** or
  **VS Code** with the GitHub Copilot extension.

---

## Step 1 — Configure the vulnscout_mcp server

`vulnscout_mcp` speaks MCP over stdio and is launched as a subprocess by the
agent client — there is no port or daemon to manage yourself. Its
`vulnscout_mcp/run_server.py` launcher is self-bootstrapping: on first run it
creates a local `venv/`, then starts the server. On every launch it synchronizes
runtime dependencies from `requirements/mcp.txt`, including when the virtual
environment already exists.

The server reads a single environment variable:

| Environment variable | Default                 | Description                          |
| -------------------- | ----------------------- | ------------------------------------ |
| `VULNSCOUT_BASE_URL` | `http://localhost:7275` | Base URL of the VulnScout API server |

### GitHub Copilot CLI

Run `/mcp add` in interactive mode and fill in the form (**Type:** STDIO,
**Command:** `python3 /path/to/vulnscout/vulnscout_mcp/run_server.py`,
**Environment Variables:** `{"VULNSCOUT_BASE_URL":"http://localhost:7275"}`).

Equivalently, edit `~/.copilot/mcp-config.json` directly:

```json
{
  "mcpServers": {
    "vulnscout": {
      "type": "local",
      "command": "python3",
      "args": ["/path/to/vulnscout/vulnscout_mcp/run_server.py"],
      "env": {
        "VULNSCOUT_BASE_URL": "http://localhost:7275"
      },
      "tools": ["*"]
    }
  }
}
```

### VS Code (GitHub Copilot extension)

Add a server entry to your workspace `.vscode/mcp.json` (or run
**MCP: Add Server** from the Command Palette and choose **Workspace** or
**Global**):

```json
{
  "servers": {
    "vulnscout": {
      "type": "stdio",
      "command": "python3",
      "args": ["/path/to/vulnscout/vulnscout_mcp/run_server.py"],
      "env": {
        "VULNSCOUT_BASE_URL": "http://localhost:7275"
      }
    }
  }
}
```

### Available MCP tools

Once configured, the agent can call these tools (prefixed with `vulnscout-`):

| Tool                       | Description                                                  |
| -------------------------- | ----------------------------------------------------------- |
| `write_assessment`         | Create a VEX assessment for a CVE on one or more packages   |
| `update_ai_assessment`     | Revise the content of an existing pending AI assessment (its targets cannot change) |
| `get_assessment`           | Retrieve a single VEX assessment by ID                      |
| `list_assessments_by_vuln` | List all VEX assessments recorded for a CVE                 |
| `has_ai_assessment`        | Check whether a pending AI assessment exists for a variant (informational; a new write replaces it automatically) |
| `get_vulnerability`        | Retrieve a vulnerability with variant-scoped details        |
| `find_project_id` / `find_variant_id` | Resolve a project / variant by name             |
| `list_variants`            | List every variant across all projects                      |
| `get_merged_context`       | Fetch merged project + variant context, including codebase path(s) and attached file names |
| `get_project_context` / `update_project_context` | Read / replace a project's description |
| `update_variant_context`   | Replace a variant's context fields (description, codebase path(s), environment, threat model, risks, other info) — full replacement, not a partial update |
| `get_custom_assessment`    | Fetch one user-authored assessment and its per-target reviews |
| `list_custom_assessments`  | List user-authored assessments, optionally scoped to a project variant |
| `write_assessment_review`  | Record an AI second opinion for one (variant, package) target |

---

## Step 2 — Use the cve-assessment skill

The `cve-assessment` skill lives in this repository at
`.github/skills/cve-assessment/`. An MCP-capable agent that has access to this
repository will discover the skill automatically and invoke it when you ask it
to assess a CVE.

Invoke it by describing the CVE and (optionally) the project context, for
example:

```
Assess CVE-2024-XXXXX for project "my-product", variant "production".
```

The skill resolves platform context using three tiers:

1. **MCP fetch** — if you provide a `project_name` (and optionally one or more
   variant names), the skill fetches each variant's context from VulnScout via
   the MCP tools. The resolved `variant_id`s are required to submit the
   assessment.
2. **Inline context** — if you describe the platform (package manager, build
   system, deployment environment) directly in the prompt, the skill uses that.
3. **Default fallback** — otherwise it proceeds with generic default
   objectives and no extra context.

The skill then researches the vulnerability, evaluates it against the project's
security objectives, assigns a status, and submits it via
`vulnscout-write_assessment` as a pending AI assessment.

### Assessing several variants at once

The skill can assess more than one variant of a project in a single run:

- **Named variants** — list them in the prompt (for example, *variants
  "production" and "staging"*) and only those are assessed.
- **No variants named** — every variant of the project is assessed. This
  requires a `project_name`; the skill never guesses a project.

The CVE research is done once, but the component analysis and confidence score
are done **per variant**, using each variant's own context, because the same CVE
can have a different verdict in different variants. Variants that end up with
the same status and justification are then submitted together as **one
multi-target assessment**, not one assessment per variant. Variants with a
different verdict get their own assessment. The skill finishes with a summary of
every group, the assessment ids, any skipped variants, and any pending AI
assessments it replaced.

### Confidence and Strict Assessments

By default, **HIGH** and **MEDIUM** confidence can yield a definitive status;
**LOW** confidence always yields `under_investigation`. Explicitly request a
**strict assessment** to require HIGH confidence for a definitive status:
MEDIUM and LOW then both yield `under_investigation`. Confidence and unresolved
uncertainties are recorded in `status_notes`.

Multi-variant submissions are grouped by their submitted status and, for
`not_affected`, justification. Per-variant reasoning is merged into the shared
assessment text; variants with different conclusions receive separate records.

### Managing AI Context

Use the **AI Context** page to save a project description and each variant's
description, codebase path(s), environment, threat model, risks, and other
information. The project description and variant threat model are required
when saving a complete variant context. Separate multiple local source paths
with semicolons. External agents can use those paths when the corresponding
source trees are available on their machine; the built-in chat exposes only
VulnScout MCP tools, not filesystem or shell tools.

Changing saved context can mark pending AI assessments as **context outdated**.
They remain pending and should be regenerated against the updated context.
This differs from a **stale AI review**, which means the custom assessment
content changed after the review.

Context import/export is separate from Review-page exports. The web UI can
export all or selected variants; the host wrapper exports the selected project
(all its variants unless `--variant` is set):

```bash
./vulnscout --project demo --export-context
./vulnscout --import-context /path/to/context-export.json
```

The current context envelope has `version: "1.0"`, `exported_at`, and a
`projects` array. Each project has `project_name`, `project_description`, and
nested `variants`; each variant has `variant_name`, `variant_description`,
`codebase_path`, `environment`, `threat_model`, `risks`, and `other_info`.
Import also accepts a bare array of those project objects. Matching context
is overwritten; missing destination projects/variants are reported as ignored,
and entries lacking required description/threat-model fields are reported as
failed. Valid entries can still be imported when other entries fail.

```{note}
The skill's **security objectives profiles** and **report templates** are
customizable. See `.github/skills/cve-assessment/objectives/README.md` and the
`.github/skills/cve-assessment/report-templates/` directory for details.
```

---

## Step 3 — Review AI assessments in the web interface

Pending AI assessments must be reviewed by a human before they become official.

1. Open the assessed vulnerability in the VulnScout web interface.
2. A pending AI assessment appears in a highlighted panel **above** the normal
   assessment timeline, labelled **"AI-generated · Pending review"**. It shows
   the same details as a normal assessment (status, justification, impact
   statement, notes, packages, and variant).
3. Click **Edit** on the vulnerability modal to enter editing mode — the
   **Approve** / **Reject** buttons only appear on the panel once editing mode
   is active.
4. Use the panel's action buttons:
   - **Approve** — promotes the assessment to an official (`custom`)
     assessment. It now affects the vulnerability's status and is included in
     the OpenVEX export.
   - **Reject** — deletes the pending AI assessment.

Alternatively, use the **Review → AI Assessments** tab to inspect and
approve/reject pending suggestions without opening every vulnerability modal.

Until it is approved, a pending AI assessment has no effect on the
vulnerability's status, on scan history/diffs, reports, or exported SBOM/VEX.
Custom VulnScout JSON backups include pending suggestions separately in
`ai_assessments`; importing them does not approve them.

---

## Step 4 — AI review of custom assessments

This is a separate workflow from approving a pending AI assessment. Ask an
agent with access to this repository and the `assessment-review` skill to
review an existing **user-authored** assessment (`origin = "custom"`). The
skill does not review scan-imported assessments or pending AI suggestions.
For example:

```
Review assessment assessment:<uuid>.
Review custom assessments for project "my-product", variant "production".
Review all custom assessments.
```

You can copy an assessment ID from the **Review** page; the tool accepts a
bare UUID or a copied `assessment:<uuid>` (and `group:<uuid>` for a
multi-target assessment). If you specify a project without a variant, the
skill uses its `"default"` variant. With no scope, it lists custom assessments
across all variants; larger scopes are paginated. By default, it skips targets
with a current review and revisits unreviewed or stale targets.

The agent independently derives a conclusion for **each (variant, package)
target**, then saves a separate review for each one via
`vulnscout-write_assessment_review`. An assessment covering multiple targets
can therefore have different review verdicts for different targets. Each
write supplies the target's `variant_id` and `package` and the
`assessment_fingerprint` obtained when the assessment was read. If the
authored content changed meanwhile, the write is rejected: fetch the updated
assessment and review it again rather than reusing the old conclusion.
Re-reviewing a target replaces only that target's previous review; **no review
changes the underlying assessment**.

The **Review** page's **AI review** column and filter show which targets
agree (✓), differ (⚠), are stale (⚠ stale), or have no review (—).
Multi-target rows show counts for each state. Open the vulnerability detail
modal to read each target's AI review and rationale (`why:`). A stale review
warns that the assessment was edited after the review was generated; in edit
mode, **Discard review** removes a target's review without changing the
assessment.

---

## Troubleshooting

- **The agent cannot reach VulnScout** — verify that VulnScout is running and
  that `VULNSCOUT_BASE_URL` in the MCP configuration points to the correct API
  URL (default `http://localhost:7275`).
- **Submission is blocked with a missing `variant_id`** — the skill needs a
  `variant_id` to submit. Provide a `project_name`/`variant_name` (so it can be
  resolved via MCP) or a `variant_id` UUID directly in the prompt.
- **A pending AI assessment disappeared, or now covers fewer variants** —
  this is expected. A new AI assessment replaces the pending one on the same
  variant(s); if the old one also covered other variants, it keeps those. Approve
  an assessment first if you want to keep it, since approved assessments are
  never replaced.
- **409 Conflict on submission** — you are running a VulnScout version from
  before AI assessments replaced each other. Upgrade VulnScout, or approve or
  reject the existing pending assessment first.
- **Review rejected because its assessment fingerprint changed** — the
  user-authored assessment was edited since the agent read it. Fetch the
  updated assessment and independently review the affected targets again.
