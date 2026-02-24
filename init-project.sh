#!/bin/bash
#
# init-project.sh - Initialize a new forensic investigation project
#
# Usage:
#   ./init-project.sh                        # Interactive — prompts for all options
#   ./init-project.sh new-case               # Create and initialize new-case/
#   ./init-project.sh new-case /artifacts    # Create with artifacts path set
#
# Modules (e.g., l1, l2, l3) are chosen interactively. Each module creates
# a work/<module>/ directory and corresponding config sections.
#
# To add modules to an existing project, use add-module.sh instead.
#

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Script location (gizur-arti root)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Parse arguments
PROJECT_DIR="${1:-.}"
ARTIFACTS_PATH="${2:-}"

# Resolve to absolute path
if [[ "$PROJECT_DIR" != /* ]]; then
    PROJECT_DIR="$(pwd)/$PROJECT_DIR"
fi

echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Forensic Investigation Project Initializer            ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
echo
echo -e "Project directory: ${YELLOW}$PROJECT_DIR${NC}"
echo -e "Template source:   ${YELLOW}$SCRIPT_DIR/templates${NC}"
echo

# Prompt for artifacts path if not provided
if [[ -z "$ARTIFACTS_PATH" ]]; then
    read -r -p "Artifacts path [/path/to/artifacts]: " ARTIFACTS_PATH
    ARTIFACTS_PATH="${ARTIFACTS_PATH:-/path/to/artifacts}"
fi
echo -e "Artifacts path:    ${YELLOW}$ARTIFACTS_PATH${NC}"
echo

# Prompt for tiers
read -r -p "Artifact tiers (space-separated) [t1 t2 t3]: " MODULES_INPUT
MODULES_INPUT="${MODULES_INPUT:-t1 t2 t3}"
# shellcheck disable=SC2206
MODULES=($MODULES_INPUT)

# Validate module names
for mod in "${MODULES[@]}"; do
    if [[ "$mod" =~ [[:space:]/\\] || -z "$mod" ]]; then
        echo -e "\033[0;31mError: Invalid module name '$mod' (no spaces or slashes)\033[0m"
        exit 1
    fi
done

echo -e "Tiers:             ${YELLOW}${MODULES[*]}${NC}"
echo

# Create project directory
mkdir -p "$PROJECT_DIR"
cd "$PROJECT_DIR"

# ─── Directory structure ─────────────────────────────────────────────────────

echo -e "${GREEN}Creating directory structure...${NC}"
mkdir -p config
mkdir -p scripts

# Per-module work directories
for mod in "${MODULES[@]}"; do
    mkdir -p "work/$mod/manual"
    mkdir -p "work/$mod/automated/network/extractions"
    mkdir -p "work/$mod/automated/memory/extractions"
    mkdir -p "work/$mod/automated/disk/extractions"
    mkdir -p "work/$mod/timelines"
    echo "  Created: work/$mod/"
done

# Report structure
mkdir -p report/literature
mkdir -p report/claude-report/figures
mkdir -p report/claude-report/scripts
mkdir -p report/final-report/figures
mkdir -p report/final-report/scripts
echo "  Created: report/"

# ─── Config files (generated dynamically per modules) ────────────────────────

echo -e "${GREEN}Generating config files...${NC}"

# artifacts.yaml
if [ ! -f "config/artifacts.yaml" ]; then
    {
        echo "# Artifact file paths per tier"
        echo "# All paths are relative to \$ARTIFACTS_PATH/"
        echo ""
        for mod in "${MODULES[@]}"; do
            cat <<YAML
$mod:
  # $mod artifacts
  network:
    core_pcap: ""           # Main internal network capture
    dns_pcap: ""            # DNS traffic capture
    egress_pcap: ""         # Egress/perimeter capture
    firewall_logs: ""       # Firewall log exports
  disk:
    host1:
      plaso: ""             # Plaso timeline CSV
      triage: ""            # KAPE/triage archive (VHDX/ZIP)
  memory:
    host1: ""               # Memory dump (raw/lime)

YAML
        done
        echo "# Work output paths (relative to project root, auto-created)"
        echo "work_paths:"
        for mod in "${MODULES[@]}"; do
            cat <<YAML
  $mod:
    network_extractions: work/$mod/automated/network/extractions
    disk_extractions: work/$mod/automated/disk/extractions
    memory_extractions: work/$mod/automated/memory/extractions
    timelines: work/$mod/timelines
YAML
        done
    } > config/artifacts.yaml
    echo "  Created: config/artifacts.yaml"
else
    echo "  Skipped: config/artifacts.yaml (already exists)"
fi

# settings.yaml
if [ ! -f "config/settings.yaml" ]; then
    {
        echo "# Analysis settings and configuration"
        echo ""
        echo "# Attack timeframes per tier"
        echo "timeframe:"
        for mod in "${MODULES[@]}"; do
            cat <<YAML
  $mod:
    start: null
    end: null
    note: $mod attack window
YAML
        done
        # Append the rest from the static template (thresholds, domains, ports)
        # Skip the first few lines (header + timeframe section) from the template
        sed -n '/^# Analysis thresholds/,$p' "$SCRIPT_DIR/templates/config/settings.yaml.template"
    } > config/settings.yaml
    echo "  Created: config/settings.yaml"
else
    echo "  Skipped: config/settings.yaml (already exists)"
fi

# iocs.yaml
if [ ! -f "config/iocs.yaml" ]; then
    {
        echo "# IOC Database - Organized by Module and Type"
        echo "# For cross-tier correlation searches"
        echo ""
        for mod in "${MODULES[@]}"; do
            cat <<YAML
$mod:
  # $mod IOCs
  ips_external: []
  ips_internal: []
  domains: []
  usernames: []
  credentials: []
  hashes_sha256: []
  filenames: []
  ja3: []
  ports: []
  mac_addresses: []
  processes: []

YAML
        done
        echo "# Search paths per module (glob patterns relative to PROJECT_ROOT)"
        echo "# Used by ioc_search.py to find files to search"
        echo "search_paths:"
        for mod in "${MODULES[@]}"; do
            cat <<YAML
  $mod:
    - work/$mod/automated/**/*.csv
    - work/$mod/timelines/*.csv
YAML
        done
    } > config/iocs.yaml
    echo "  Created: config/iocs.yaml"
else
    echo "  Skipped: config/iocs.yaml (already exists)"
fi

# findings.yaml (static — no per-module sections)
if [ ! -f "config/findings.yaml" ]; then
    cp "$SCRIPT_DIR/templates/config/findings.yaml.template" "config/findings.yaml"
    echo "  Created: config/findings.yaml"
else
    echo "  Skipped: config/findings.yaml (already exists)"
fi

# ─── Report templates ────────────────────────────────────────────────────────

echo -e "${GREEN}Creating report templates...${NC}"

if [ ! -f "report/CLAUDE.md" ]; then
    cp "$SCRIPT_DIR/templates/report-CLAUDE.md.template" "report/CLAUDE.md"
    echo "  Created: report/CLAUDE.md"
else
    echo "  Skipped: report/CLAUDE.md (already exists)"
fi

if [ ! -f "report/claude-report/CLAUDE.md" ]; then
    cp "$SCRIPT_DIR/templates/claude-report-CLAUDE.md.template" "report/claude-report/CLAUDE.md"
    echo "  Created: report/claude-report/CLAUDE.md"
else
    echo "  Skipped: report/claude-report/CLAUDE.md (already exists)"
fi

if [ ! -f "report/claude-report/justfile" ]; then
    cp "$SCRIPT_DIR/templates/claude-report-justfile.template" "report/claude-report/justfile"
    echo "  Created: report/claude-report/justfile"
else
    echo "  Skipped: report/claude-report/justfile (already exists)"
fi

if [ ! -f "report/final-report/CLAUDE.md" ]; then
    cp "$SCRIPT_DIR/templates/final-report-CLAUDE.md.template" "report/final-report/CLAUDE.md"
    echo "  Created: report/final-report/CLAUDE.md"
else
    echo "  Skipped: report/final-report/CLAUDE.md (already exists)"
fi

if [ ! -f "report/final-report/justfile" ]; then
    cp "$SCRIPT_DIR/templates/final-report-justfile.template" "report/final-report/justfile"
    echo "  Created: report/final-report/justfile"
else
    echo "  Skipped: report/final-report/justfile (already exists)"
fi

# ─── Project-root templates ──────────────────────────────────────────────────

echo -e "${GREEN}Copying project templates...${NC}"

if [ ! -f "CLAUDE.md" ]; then
    cp "$SCRIPT_DIR/templates/project-CLAUDE.md.template" "CLAUDE.md"
    echo "  Created: CLAUDE.md"
else
    echo "  Skipped: CLAUDE.md (already exists)"
fi

if [ ! -f "justfile" ]; then
    cp "$SCRIPT_DIR/templates/justfile.template" "justfile"
    echo "  Created: justfile"
else
    echo "  Skipped: justfile (already exists)"
fi

# Create .envrc from template
echo -e "${GREEN}Creating .envrc...${NC}"
if [ ! -f ".envrc" ]; then
    sed -e "s|/path/to/artifacts|$ARTIFACTS_PATH|g" \
        -e "s|\$HOME/repos/gizur-arti|$SCRIPT_DIR|g" \
        "$SCRIPT_DIR/templates/envrc.template" > .envrc
    echo "  Created: .envrc"
else
    echo "  Skipped: .envrc (already exists)"
fi

# Create .gitignore
echo -e "${GREEN}Creating .gitignore...${NC}"
if [ ! -f ".gitignore" ]; then
    cat > .gitignore << 'EOF'
# Artifacts (large files, sensitive)
artifacts/
*.pcap
*.mem
*.vmdk
*.vhdx
*.raw
*.E01
*.img

# Work output (regenerable)
work/

# Python
__pycache__/
*.pyc
.venv/
venv/

# IDE
.idea/
.vscode/
*.swp

# OS
.DS_Store
Thumbs.db

# Secrets
.env
*.key
*.pem
EOF
    echo "  Created: .gitignore"
else
    echo "  Skipped: .gitignore (already exists)"
fi

# Create investigation-log/ directory
echo -e "${GREEN}Creating investigation log...${NC}"
if [ ! -d "investigation-log" ]; then
    investigation-log.sh init
    echo "  Created: investigation-log/"
else
    echo "  Skipped: investigation-log/ (already exists)"
fi

# Initialize git if not exists
if [ ! -d ".git" ]; then
    echo -e "${GREEN}Initializing git repository...${NC}"
    git init --quiet
    echo "  Initialized git repository"
fi

# ─── Summary ─────────────────────────────────────────────────────────────────

echo
echo -e "${GREEN}════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Project initialized successfully!${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════${NC}"
echo
echo -e "Directory structure:"
echo "  $PROJECT_DIR/"
echo "  ├── config/           # Configuration files"
echo "  ├── scripts/          # Project-specific scripts"
for mod in "${MODULES[@]}"; do
    echo "  ├── work/$mod/        # $mod analysis output (gitignored)"
done
echo "  ├── report/"
echo "  │   ├── CLAUDE.md     # Report protection rules"
echo "  │   ├── literature/   # Reference materials"
echo "  │   ├── claude-report/ # Claude-editable working draft"
echo "  │   └── final-report/  # Human-only final submission"
echo "  ├── .envrc            # Environment variables"
echo "  ├── CLAUDE.md         # Claude Code instructions"
echo "  ├── justfile          # Just commands"
echo "  └── investigation-log/"
echo
echo -e "${YELLOW}Next steps:${NC}"
echo "  1. Install dependencies: just -f $SCRIPT_DIR/justfile install-deps"
echo "  2. Edit .envrc - verify ARTIFACTS_PATH ($ARTIFACTS_PATH)"
echo "  3. Run 'direnv allow' to load environment variables"
echo "  4. Edit config/artifacts.yaml - map your artifact files"
echo "  5. Run 'forensic_analysis.py network status' to verify setup"
echo "  6. To add more tiers later: just add-module <name>"
echo
echo -e "${BLUE}Tiers created: ${MODULES[*]}${NC}"
echo
