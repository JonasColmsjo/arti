# Arti: Forensic Analysis Framework

**Instructions for agentic AI assistants.** Validated with Claude Code; adaptable to other agentic AI systems.

**This file contains generic forensic investigation instructions.**
Projects using Arti should reference this file from their CLAUDE.md.

## Project CLAUDE.md Template

Each project using Arti should have its own CLAUDE.md with:
- **Reference to Arti**: `Read ~/repos/gizur-arti/CLAUDE.md for generic forensic methodology.`
- **Environment**: Project-specific env vars (`$EVIDENCE_PATH`, etc.) and setup instructions
- **Artifact/Evidence structure**: Tree showing where artifacts live per tier
- **IP disambiguation table**: Org suffixes and subnet assignments (if multi-org)
- **Known IOCs**: From prior tiers to guide current investigation
- **Project-specific justfile targets**: Table of targets not in Arti's generic set

## Environment

- **Forensic tools**: `$ARTI_PATH/scripts/` (added to PATH via `.envrc`)
- **Artifacts path**: `$ARTIFACTS_PATH` (project-specific, set in project `.envrc`)
- **Project root**: `$PROJECT_ROOT` (auto-set to project repo directory)

Scripts are loaded from Arti via PYTHONPATH + PATH in each project's `.envrc`.

Run `direnv allow` after cloning a project to activate the environment.

## Output Rules
- When asked to show a file, show the **complete, unsummarized** file contents — never truncate, paraphrase, or add summary tables around it
- "raw" means unsummarized — show exact file contents as-is
- Markdown files should be rendered with formatting (not as code blocks)

## Automation Rule

**Always create `just` targets for tasks requiring more than a few lines of code.**

- Multi-step shell commands → add to project `justfile`
- Registry extraction, KAPE parsing, disk forensics → justfile targets
- Repetitive analysis across artifact tiers → justfile targets
- This ensures reproducibility and documents the methodology

## Critical Rules

### IP Address Disambiguation (Multi-Org Investigations)
When multiple organizations use overlapping RFC1918 subnets (e.g., both use 192.168.x.x), **suffix IPs with an org identifier** to avoid confusion. Define the suffixes in the project CLAUDE.md.

**Example:** `192.168.2.2/Sp` (Spader) vs `192.168.2.2/Al` (Alset) — same IP, different orgs.

**Rule:** When referencing internal IPs in findings, timelines, and docs, ALWAYS include the org suffix.

### Never Hardcode Artifact Paths
**IMPORTANT**: Never reference artifact files directly in justfile targets or scripts. All artifact paths MUST be read from `config/artifacts.yaml`. This is the single source of truth for where artifact files live. If a new artifact is added, update `artifacts.yaml` first — scripts and targets read from it at runtime.

### Three-Stage Exploration (Tier 2+)
| Stage | File | Purpose |
|-------|------|---------|
| 1 | `*_EXPLORATION_FINDINGS.md` | Factual observations only, NO interpretation |
| 2 | `*_INVESTIGATION_PLAN.md` | Plan deeper investigation, NO hypotheses |
| 3 | `*_DEEP_DIVE_FINDINGS.md` | Results from manual investigation |
| 3b | `*_CONSOLIDATED_TIMELINE.md` | WHO did WHAT WHEN (REQUIRED!) |

**Workflow**: Extract → Analyze → Exploration findings → Investigation plan → Deep dive → Timeline

### Artifact Tier Isolation
- Tier 1: Use ONLY Tier 1 artifacts
- Tier 2: Use Tier 1 + Tier 2 (NOT Tier 3)
- Tier 3: All tiers

### Investigation Log
**MANDATORY**: Update `INVESTIGATION-LOG.md` after EVERY significant action.
- **APPEND-ONLY**: Never modify existing entries
- Log in real-time, not batched

### CSV Standards
- **REQUIRED**: Every CSV must have `timestamp_utc` or `datetime_utc` column
- All timestamps in UTC
- Review existing CSVs before creating new ones for consistent structure

### Visualization Rules
- **NEVER edit HTML files directly** - update visualization scripts and regenerate
- **ASCII first, Plotly later** - validate concept with ASCII before fancy charts
- Read from extracted CSVs, never raw artifacts

### Extract Once, Reuse Always
Save extracted data to CSV/text during exploration. These become source for:
- Visualizations
- Timelines
- Correlation analysis
- Final report

### FINDINGS.md Required
Every artifact folder MUST have a FINDINGS.md documenting key observations.

## Investigation Phases

### Phase 1: Artifact Intake
Hash all artifacts (MD5 + SHA256), document chain of custody.

### Phase 2: Exploratory
**ALLOWED**: Factual observations, visualizations, IOC research, timelines
**NOT ALLOWED**: Interpret intentions, form hypotheses, speculate on goals

**Exploration chains**: When examining artifact X leads to artifact Y, document it:
> "While examining [X] → Observed [Y] → This indicates [Z] should be explored because [reason]"

### Phase 3: Hypothesis Development
Form testable hypotheses with falsification criteria. Reference only artifacts from Phase 2.

**Hypothesis template:**
```markdown
## Hypothesis N: [Title]
### Statement — [Clear, testable claim]
### Supporting Evidence — [References to Phase 2 findings]
### Contradicting Evidence — [What argues against it]
### Falsification Criteria — This hypothesis is FALSE if: [conditions]
### Status — [Supported / Partially Supported / Inconclusive / Disproved]
### Confidence — [High/Medium/Low] because [reasoning]
```

### Phase 4: Hypothesis Testing
Actively seek CONTRADICTING evidence. Assign confidence levels (High/Medium/Low).

### Phase 5: Cross-Layer Correlation
Link findings across all tiers. Build unified timeline. Map to MITRE ATT&CK.

## Artifact Analysis Checklist

When analyzing each artifact, address:
1. Name/identification
2. Original filename/source
3. Timestamps (creation, modification, compilation)
4. Technical details (language, framework, subsystem)
5. Obfuscation/packing indicators
6. Behavioral indicators (what it does)
7. IoCs (IPs, domains, hashes, filenames)
8. Artifact references (specific locations, frame numbers)
9. Purpose/impact assessment
10. Confidence level and reasoning

## Documentation Standards

- Keep docs **50-150 lines** — one document = one purpose
- Prefer bullet points and tables over prose
- For complex analysis, create a dedicated folder with:
  - `README.md` — overview and file index
  - `*-ANALYSIS.md` — findings and interpretation
  - `*-RECOVERY-METHOD.md` — extraction process (chain of custody)
  - Raw extracted files (headers, artifacts)

## Tools

### forensic_analysis.py (Primary)
Unified CLI for artifact extraction and analysis. **Creates directory structure automatically.**

```bash
forensic_analysis.py <module> <command> [target] --tier N
```

| Module | Artifacts | Output Directory |
|--------|-----------|------------------|
| `memory` | Memory dumps | `work/tierN/automated/memory/` |
| `network` | PCAP files | `work/tierN/automated/network/` |
| `disk` | Triage data | `work/tierN/automated/disk/` |

**Commands:**
```bash
forensic_analysis.py network status              # Show what's done
forensic_analysis.py network extract all --tier 2   # Extract from artifacts
forensic_analysis.py network analyze all --tier 2   # Run analysis
forensic_analysis.py disk extract all --tier 2      # Disk extractions
```

**Output structure** (created automatically):
```
work/tierN/
├── automated/                   # Script outputs (DO NOT edit manually)
│   ├── network/
│   │   ├── .analysis_status.json
│   │   ├── extractions/
│   │   └── analysis/
│   ├── disk/
│   └── memory/
└── manual/                      # Investigator notes and manual analysis
    ├── *_EXPLORATION_FINDINGS.md
    ├── *_INVESTIGATION_PLAN.md
    ├── *_DEEP_DIVE_FINDINGS.md
    └── custom analysis files
```

**Important**: Script outputs go to `automated/<module>/`. Place investigation notes, findings docs, and custom analysis in `manual/`.

### Other Tools
- **Volatility 3**: `vol3.sh -f <dump> <plugin>` (on PATH via Arti)
- **tshark**: Network capture analysis
- **YARA**: Pattern matching

### Justfile Structure

Generic forensic targets are in `~/repos/gizur-arti/justfile` (imported via `import?`).
Project-specific targets are in each project's `justfile`.

Run `just --list` to see all available targets.

**Generic targets** (from Arti, use `just <target>`):
- `project-status`, `project-reset` — analysis status
- `memory-*` — 18 memory analysis targets
- `network-flows-*` — flow queries (summary, ip, port, top-ips, etc.)
- `network-dns-*` / `network-tls-*` — DNS and TLS queries
- `network-query-*` — packet DB queries (ip, mac, port, ja3, sql)
- `network-router-*` / `network-files-*` — infrastructure analysis
- `kape-*` — ~25 KAPE/triage investigation targets
- `kape-reg-*` — 8 registry analysis targets
- `viz-*` — visualization targets
- `project-ioc-*`, `project-hash-*` — IOC and hash management
- `disk-extract-raw`, `file-analyze-binary`, `file-compare-binary`

## Git
- Commit after each milestone
- Never commit: `*.pcap`, `*.mem`, `*.vmdk`, `artifacts/`
- Safe to commit: `.md`, `.py`, `.html`, `.txt`, `.csv`, `.yaml`

## Key Reminders
1. NEVER modify original artifacts
2. Show your work - process > conclusions
3. Be explicit about uncertainty
4. Consider benign explanations
5. Every claim needs artifact references
