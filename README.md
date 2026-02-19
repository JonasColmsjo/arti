# Arti — AI-Assisted Digital Forensics Framework

Arti is a methodology and toolset for AI-assisted digital forensic investigations. It provides structured investigation workflows, automated artifact extraction, and analysis pipelines designed to work with agentic AI systems.

Currently validated with [Claude Code](https://claude.com/claude-code); migration to other agentic AI systems is straightforward since all methodology is encoded in markdown instruction files.

## Key Concepts

- **Artifacts**: Digital evidence files (PCAPs, memory dumps, disk images, triage packages)
- **Tiers**: Investigation scope levels (t1, t2, t3) — each tier adds new artifacts and builds on previous analysis
- **Three-stage exploration**: Factual findings → investigation plan → deep dive (prevents premature conclusions)
- **Tier isolation**: Each tier uses only artifacts from its own tier and below

## Methodology

Arti enforces a phased investigation workflow:

1. **Intake** — Hash artifacts, document chain of custody
2. **Exploratory** — Extract data, build timelines, identify IOCs (no hypotheses)
3. **Hypothesis development** — Form testable claims with falsification criteria
4. **Hypothesis testing** — Actively seek contradicting evidence
5. **Cross-tier correlation** — Unified timeline, MITRE ATT&CK mapping

All methodology rules live in `CLAUDE.md` (agentic AI instructions) and template files.

## Toolset

### Forensic Analysis CLI

```bash
forensic_analysis.py <module> <command> [target] --tier <t1|t2|t3>
```

| Module | Artifacts | Tools |
|--------|-----------|-------|
| `network` | PCAP files | tshark, Python |
| `disk` | Plaso timelines, KAPE/triage | pandas, Python |
| `memory` | Memory dumps | Volatility 3 |

### Query Scripts

| Script | Purpose |
|--------|---------|
| `query_flows.py` | Network flow analysis |
| `query_dns.py` | DNS traffic queries |
| `query_tls.py` | TLS/JA3 fingerprint analysis |
| `query_kape.py` | KAPE triage artifact queries |
| `query_plaso.py` | Plaso timeline queries |
| `visualize_ascii.py` | ASCII/PNG/Plotly forensic visualizations |
| `ascii_flows.py` | Network flow diagrams |

All scripts support `--help` for usage.

### Justfile Targets

Generic forensic targets (imported by projects via `import?`):

- `project-status`, `project-reset` — analysis status
- `memory-*` — memory forensics (18 targets)
- `network-flows` — flow queries (summary, ip, port, top-ips, etc.)
- `network-dns-*` / `network-tls-*` — DNS and TLS queries
- `network-query-*` — packet DB queries (ip, mac, port, ja3, sql)
- `kape-*` — ~25 KAPE/triage investigation targets
- `kape-reg-*` — 8 registry analysis targets
- `viz-*` — visualization targets
- `project-ioc-*`, `project-hash-*` — IOC and hash management

## Agents (Beta)

18 specialized security agents for Claude Code in `agents/`:

| Category | Agents |
|----------|--------|
| **Offensive** | `red-team-operator`, `bug-bounty-hunter`, `replay-attack-specialist`, `wifi-security-tester` |
| **Defensive** | `blue-team-defender`, `soc-analyst`, `threat-intelligence-analyst` |
| **Forensics** | `dfir-investigator`, `memory-forensics-expert`, `network-security-analyst`, `reverse-engineer` |
| **Code Security** | `source-code-analyzer`, `android-sast-specialist`, `vulnerability-validator` |
| **Specialized** | `email-security-analyst`, `rf-security-expert`, `security-developer`, `security-reporter` |

**Note:** The specialized agents are in **beta**. The core Arti methodology and toolset has been developed and validated on projects with a wide variety of evidence types — network captures, log files, disk images, memory dumps, and more. In practice, the specialized agents have not been necessary for these projects; the methodology encoded in `CLAUDE.md` has been sufficient to guide the agentic AI through complex investigations. However, the agents may serve as a useful starting point for more specialized or narrowly scoped projects.

**The key takeaway:** Building project-specific instructions for the agentic AI (`CLAUDE.md`) is far more important than relying on pre-built agents. A well-crafted `CLAUDE.md` tailored to your investigation's artifacts, scope, and objectives will consistently outperform generic agent profiles.

## Quick Start

```bash
# Create a new forensic investigation project
just init ~/cases/new-investigation /path/to/artifacts

# Or add Arti to an existing project via .envrc:
export PROJECT_ROOT=$(pwd)
export ARTIFACTS_PATH=/path/to/artifacts
export ARTI_PATH="${ARTI_PATH:-$HOME/repos/gizur-arti}"
export PYTHONPATH="$ARTI_PATH/scripts:$PYTHONPATH"
export PATH="$ARTI_PATH/scripts:$PATH"
```

Run `direnv allow`, then `just --list` to see available commands.

## Project Integration

Projects consume Arti via PYTHONPATH. Each project has:

- `config/artifacts.yaml` — artifact file paths per tier
- `config/settings.yaml` — analysis thresholds and timeframes
- `config/findings.yaml` — tracked IOCs
- `CLAUDE.md` — project-specific AI instructions (references Arti's CLAUDE.md)
- `justfile` — imports Arti's generic targets + adds project-specific ones

## Requirements

- **Python 3.10+** with dependencies: `pip install -r requirements.txt`
- **just** (`cargo install just` or `brew install just`)
- **direnv** (for automatic environment activation)
- **tshark** (for network analysis)
- **Optional**: Volatility 3 (memory analysis), Ansible (for `just install-deps`)

## License

MIT
