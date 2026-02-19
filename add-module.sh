#!/bin/bash
#
# add-module.sh - Add an artifact tier to an existing project
#
# Usage:
#   ./add-module.sh <module-name>
#   ./add-module.sh l3
#
# Idempotent — skips existing directories and config sections.
# Must be run from a project root (directory with config/).
#

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

MODULE="$1"

if [[ -z "$MODULE" ]]; then
    echo -e "${RED}Usage: add-module.sh <module-name>${NC}"
    echo "  Example: add-module.sh l3"
    exit 1
fi

# Validate module name
if [[ "$MODULE" =~ [[:space:]/\\] ]]; then
    echo -e "${RED}Error: Invalid module name '$MODULE' (no spaces or slashes)${NC}"
    exit 1
fi

# Check we're in a project root
if [[ ! -d "config" ]]; then
    echo -e "${RED}Error: No config/ directory found. Run from a project root.${NC}"
    exit 1
fi

echo -e "${GREEN}Adding module '$MODULE'...${NC}"
echo

# ─── Work directories ────────────────────────────────────────────────────────

CREATED=0

for dir in \
    "work/$MODULE/manual" \
    "work/$MODULE/automated/network/extractions" \
    "work/$MODULE/automated/memory/extractions" \
    "work/$MODULE/automated/disk/extractions" \
    "work/$MODULE/timelines"; do
    if [[ ! -d "$dir" ]]; then
        mkdir -p "$dir"
        echo "  Created: $dir"
        CREATED=1
    fi
done

if [[ $CREATED -eq 0 ]]; then
    echo -e "  ${YELLOW}Skipped: work/$MODULE/ (already exists)${NC}"
fi

# ─── Config: artifacts.yaml ──────────────────────────────────────────────────

if [[ -f "config/artifacts.yaml" ]]; then
    if ! grep -q "^${MODULE}:" "config/artifacts.yaml"; then
        echo "  Appending $MODULE to config/artifacts.yaml"
        # Insert artifact section before "# Work output paths" comment or work_paths:
        ARTIFACT_BLOCK="${MODULE}:\\
  # ${MODULE} artifacts\\
  network:\\
    core_pcap: \"\"\\
    dns_pcap: \"\"\\
    egress_pcap: \"\"\\
    firewall_logs: \"\"\\
  disk:\\
    host1:\\
      plaso: \"\"\\
      triage: \"\"\\
  memory:\\
    host1: \"\"\\
"
        if grep -q "^# Work output paths" "config/artifacts.yaml"; then
            sed -i "/^# Work output paths/i \\
${ARTIFACT_BLOCK}" "config/artifacts.yaml"
        elif grep -q "^work_paths:" "config/artifacts.yaml"; then
            sed -i "/^work_paths:/i \\
${ARTIFACT_BLOCK}" "config/artifacts.yaml"
        else
            cat >> "config/artifacts.yaml" <<YAML

${MODULE}:
  # ${MODULE} artifacts
  network:
    core_pcap: ""
    dns_pcap: ""
    egress_pcap: ""
    firewall_logs: ""
  disk:
    host1:
      plaso: ""
      triage: ""
  memory:
    host1: ""
YAML
        fi

        # Append work_paths entry
        cat >> "config/artifacts.yaml" <<YAML
  ${MODULE}:
    network_extractions: work/${MODULE}/automated/network/extractions
    disk_extractions: work/${MODULE}/automated/disk/extractions
    memory_extractions: work/${MODULE}/automated/memory/extractions
    timelines: work/${MODULE}/timelines
YAML
    else
        echo -e "  ${YELLOW}Skipped: config/artifacts.yaml ($MODULE already present)${NC}"
    fi
fi

# ─── Config: settings.yaml ───────────────────────────────────────────────────

if [[ -f "config/settings.yaml" ]]; then
    if ! grep -q "^  ${MODULE}:" "config/settings.yaml"; then
        echo "  Appending $MODULE to config/settings.yaml"
        # Insert after the last timeframe entry (before # Analysis thresholds)
        if grep -q "^# Analysis thresholds" "config/settings.yaml"; then
            sed -i "/^# Analysis thresholds/i \\
  ${MODULE}:\\
    start: null\\
    end: null\\
    note: ${MODULE} attack window" "config/settings.yaml"
        else
            # Fallback: append to timeframe section
            cat >> "config/settings.yaml" <<YAML
  ${MODULE}:
    start: null
    end: null
    note: ${MODULE} attack window
YAML
        fi
    else
        echo -e "  ${YELLOW}Skipped: config/settings.yaml ($MODULE already present)${NC}"
    fi
fi

# ─── Config: iocs.yaml ───────────────────────────────────────────────────────

if [[ -f "config/iocs.yaml" ]]; then
    if ! grep -q "^${MODULE}:" "config/iocs.yaml"; then
        echo "  Appending $MODULE to config/iocs.yaml"
        # Insert before search_paths
        if grep -q "^# Search paths" "config/iocs.yaml"; then
            sed -i "/^# Search paths/i \\
${MODULE}:\\
  # ${MODULE} IOCs\\
  ips_external: []\\
  ips_internal: []\\
  domains: []\\
  usernames: []\\
  credentials: []\\
  hashes_sha256: []\\
  filenames: []\\
  ja3: []\\
  ports: []\\
  mac_addresses: []\\
  processes: []\\
" "config/iocs.yaml"
        else
            cat >> "config/iocs.yaml" <<YAML

${MODULE}:
  # ${MODULE} IOCs
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
        fi

        # Append search_paths entry
        cat >> "config/iocs.yaml" <<YAML
  ${MODULE}:
    - work/${MODULE}/automated/**/*.csv
    - work/${MODULE}/timelines/*.csv
YAML
    else
        echo -e "  ${YELLOW}Skipped: config/iocs.yaml ($MODULE already present)${NC}"
    fi
fi

echo
echo -e "${GREEN}Module '$MODULE' added successfully.${NC}"
echo
