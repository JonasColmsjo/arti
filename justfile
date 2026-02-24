# Forensic Analysis Framework (gizur-arti)
# Import this justfile from project repos:
#   import? '~/repos/gizur-arti/justfile'

# Note: importing project must set allow-duplicate-recipes/variables

# Use mdcat for markdown if available, otherwise cat
md := if `which mdcat 2>/dev/null || echo ""` != "" { "mdcat" } else { "cat" }

# Arti root directory
arti_dir := justfile_directory()

# Configurable tier defaults — override these in consuming project justfiles
default_net_tier := "t2"
default_mem_tier := "t1"
tier_pattern := '^[tl][0-9]+$'
work_dir_prefix := "tier"

# List available targets
default:
    @just --list

# =============================================================================
# Project Initialization
# =============================================================================

# Initialize new forensic project: just init [dir] [artifacts-path]
init *args:
    "$(dirname "$(realpath "{{justfile()}}")")/init-project.sh" {{args}}

# Install forensic tool dependencies via Ansible: just install-deps [--tags core,python,...] [extra ansible args]
install-deps *args:
    #!/usr/bin/env bash
    set -e
    echo "Installing forensic tool dependencies..."
    cd "{{arti_dir}}/ansible"
    ansible-playbook -i inventory/hosts.yml playbook.yml {{args}}

# Add artifact tier to existing project: just add-module <name>
add-module name:
    "$(dirname "$(realpath "{{justfile()}}")")/add-module.sh" {{name}}

# =============================================================================
# Project Status
# =============================================================================

# Show project config: just config [tier] [network|disk|memory|docs]
config *args:
    artifacts_helper.py config {{args}}

# Show analysis status: just project-status [module] [tier]
project-status module="network" tier=default_net_tier:
    forensic_analysis.py {{module}} status --tier {{tier}}

# Reset analysis status: just project-reset [module] [tier]
project-reset module="network" tier=default_net_tier:
    forensic_analysis.py {{module}} reset --tier {{tier}}

# =============================================================================
# Extraction Commands
# =============================================================================

# Extract all network data (packets, flows, DNS, TLS, etc.): just network-extract-all [tier]
network-extract-all tier=default_net_tier:
    forensic_analysis.py network extract all --tier {{tier}}

# Extract all disk data: just disk-extract [tier]
disk-extract tier=default_net_tier:
    forensic_analysis.py disk extract all --tier {{tier}}

# Extract flows to CSV: just network-flows extract [tier]
network-flows-extract tier=default_net_tier:
    forensic_analysis.py network extract flows --tier {{tier}} --force

# Extract per-packet CSV with MACs from all PCAPs: just network-extract-packets [tier]
network-extract-packets tier=default_net_tier:
    forensic_analysis.py network extract packets --tier {{tier}} --force

# Extract DNS queries (T2 unified format, T1 already extracted): just network-dns-extract [tier]
network-dns-extract tier=default_net_tier:
    #!/usr/bin/env bash
    tier="{{tier}}"
    [[ "$tier" =~ {{tier_pattern}} ]] || { echo "Invalid tier: $tier"; exit 1; }
    case "$tier" in
        t1|l1)
            echo "DNS extraction not needed for T1 - data already extracted."
            echo "T1 DNS files (raw tshark format):"
            echo "  - dns-queries.csv: work/{{work_dir_prefix}}1/automated/network/extractions/dns-queries.csv"
            echo ""
            head -5 work/{{work_dir_prefix}}1/automated/network/extractions/dns-queries.csv
            exit 0
            ;;
        *)
            forensic_analysis.py network extract dns --tier "$tier" --force
            ;;
    esac

# Extract TLS fingerprints (T2 unified format, T1 already extracted): just network-tls-extract [tier]
network-tls-extract tier=default_net_tier:
    #!/usr/bin/env bash
    tier="{{tier}}"
    [[ "$tier" =~ {{tier_pattern}} ]] || { echo "Invalid tier: $tier"; exit 1; }
    case "$tier" in
        t1|l1)
            echo "TLS extraction not needed for T1 - data already extracted."
            echo "T1 TLS files (raw tshark format):"
            echo "  - core-tls.csv: work/{{work_dir_prefix}}1/automated/network/extractions/core-tls.csv"
            echo "  - egress-tls.csv: work/{{work_dir_prefix}}1/automated/network/extractions/egress-tls.csv"
            echo "  - egress-ja3.csv: work/{{work_dir_prefix}}1/automated/network/extractions/egress-ja3.csv"
            echo ""
            head -5 work/{{work_dir_prefix}}1/automated/network/extractions/core-tls.csv
            exit 0
            ;;
        *)
            forensic_analysis.py network extract tls --tier "$tier" --force
            ;;
    esac

# =============================================================================
# Memory Analysis Commands
# =============================================================================

# Extract all memory data (volatility plugins): just memory-extract [tier]
memory-extract tier=default_mem_tier:
    forensic_analysis.py memory extract all --tier {{tier}}

# Run all memory analyses: just memory-analyze [tier]
memory-analyze tier=default_mem_tier:
    forensic_analysis.py memory analyze all --tier {{tier}} --show

# Show memory analysis status: just memory-status [tier]
memory-status tier=default_mem_tier:
    forensic_analysis.py memory status --tier {{tier}}

# Extract pslist: just memory-pslist [tier]
memory-pslist tier=default_mem_tier:
    #!/usr/bin/env bash
    tier="{{tier}}"; [[ "$tier" =~ {{tier_pattern}} ]] || { echo "Invalid tier: $tier"; exit 1; }; dir="work/{{work_dir_prefix}}${tier#?}"
    forensic_analysis.py memory extract pslist --tier {{tier}} --force
    cat "$dir"/automated/memory/extractions/*-pslist.txt 2>/dev/null || echo "Run memory-extract first"

# Extract pstree: just memory-pstree [tier]
memory-pstree tier=default_mem_tier:
    #!/usr/bin/env bash
    tier="{{tier}}"; [[ "$tier" =~ {{tier_pattern}} ]] || { echo "Invalid tier: $tier"; exit 1; }; dir="work/{{work_dir_prefix}}${tier#?}"
    forensic_analysis.py memory extract pstree --tier {{tier}} --force
    cat "$dir"/automated/memory/extractions/*-pstree.txt 2>/dev/null || echo "Run memory-extract first"

# Extract netscan: just memory-netscan [tier]
memory-netscan tier=default_mem_tier:
    #!/usr/bin/env bash
    tier="{{tier}}"; [[ "$tier" =~ {{tier_pattern}} ]] || { echo "Invalid tier: $tier"; exit 1; }; dir="work/{{work_dir_prefix}}${tier#?}"
    forensic_analysis.py memory extract netscan --tier {{tier}} --force
    cat "$dir"/automated/memory/extractions/*-netscan.txt 2>/dev/null || echo "Run memory-extract first"

# Extract malfind: just memory-malfind [tier]
memory-malfind tier=default_mem_tier:
    #!/usr/bin/env bash
    tier="{{tier}}"; [[ "$tier" =~ {{tier_pattern}} ]] || { echo "Invalid tier: $tier"; exit 1; }; dir="work/{{work_dir_prefix}}${tier#?}"
    forensic_analysis.py memory extract malfind --tier {{tier}} --force
    cat "$dir"/automated/memory/extractions/*-malfind.txt 2>/dev/null || echo "Run memory-extract first"

# Extract cmdline: just memory-cmdline [tier]
memory-cmdline tier=default_mem_tier:
    #!/usr/bin/env bash
    tier="{{tier}}"; [[ "$tier" =~ {{tier_pattern}} ]] || { echo "Invalid tier: $tier"; exit 1; }; dir="work/{{work_dir_prefix}}${tier#?}"
    forensic_analysis.py memory extract cmdline --tier {{tier}} --force
    cat "$dir"/automated/memory/extractions/*-cmdline.txt 2>/dev/null || echo "Run memory-extract first"

# Extract dlllist: just memory-dlllist [tier]
memory-dlllist tier=default_mem_tier:
    #!/usr/bin/env bash
    tier="{{tier}}"; [[ "$tier" =~ {{tier_pattern}} ]] || { echo "Invalid tier: $tier"; exit 1; }; dir="work/{{work_dir_prefix}}${tier#?}"
    forensic_analysis.py memory extract dlllist --tier {{tier}} --force
    cat "$dir"/automated/memory/extractions/*-dlllist.txt 2>/dev/null || echo "Run memory-extract first"

# Extract handles: just memory-handles [tier]
memory-handles tier=default_mem_tier:
    forensic_analysis.py memory extract handles --tier {{tier}} --force

# Extract svcscan: just memory-svcscan [tier]
memory-svcscan tier=default_mem_tier:
    #!/usr/bin/env bash
    tier="{{tier}}"; [[ "$tier" =~ {{tier_pattern}} ]] || { echo "Invalid tier: $tier"; exit 1; }; dir="work/{{work_dir_prefix}}${tier#?}"
    forensic_analysis.py memory extract svcscan --tier {{tier}} --force
    cat "$dir"/automated/memory/extractions/*-svcscan.txt 2>/dev/null || echo "Run memory-extract first"

# Extract credentials from memory: just memory-credentials [tier]
# Runs hashdump, lsadump, cachedump, and SAM account flags (printkey)
memory-credentials tier=default_mem_tier:
    #!/usr/bin/env bash
    VOL="${VOL3_PATH:-$HOME/micromamba-volatility3/bin/vol}"
    tier="{{tier}}"; [[ "$tier" =~ {{tier_pattern}} ]] || { echo "Invalid tier: $tier"; exit 1; }; dir="work/{{work_dir_prefix}}${tier#?}"
    outdir="$dir/automated/memory/extractions"
    mkdir -p "$outdir"
    # Find memory dump via artifacts_helper
    mem=$(artifacts_helper.py artifact-path "{{tier}}" memory stsupport10 2>/dev/null | head -1)
    if [[ -z "$mem" || ! -f "$mem" ]]; then
        echo "No memory dump found for {{tier}}. Check config/artifacts.yaml"
        exit 1
    fi
    echo "Memory dump: $mem"
    echo ""
    for plugin in windows.registry.hashdump.Hashdump windows.lsadump.Lsadump windows.cachedump.Cachedump; do
        short="${plugin##*.}"
        out="$outdir/${short,,}.txt"
        echo "=== $short ==="
        "$VOL" -f "$mem" "$plugin" 2>&1 | grep -v "^Progress:" | tee "$out"
        echo ""
    done
    echo "=== SAM Account Flags ==="
    out="$outdir/sam-accounts.txt"
    for rid in 000001F4 000001F5 000001F7 000003ED; do
        echo "--- RID $rid ---"
        "$VOL" -f "$mem" windows.registry.printkey.PrintKey \
            --key "SAM\\Domains\\Account\\Users\\$rid" 2>&1 | grep -v "^Progress:"
        echo ""
    done | tee "$out"
    echo ""
    echo "Results saved to $outdir/"

# Analyze processes: just memory-analyze-processes [tier]
memory-analyze-processes tier=default_mem_tier:
    forensic_analysis.py memory analyze process_analysis --tier {{tier}} --force --show

# Analyze network connections: just memory-analyze-network [tier]
memory-analyze-network tier=default_mem_tier:
    forensic_analysis.py memory analyze network_analysis --tier {{tier}} --force --show

# Analyze code injection: just memory-analyze-injection [tier]
memory-analyze-injection tier=default_mem_tier:
    forensic_analysis.py memory analyze injection_analysis --tier {{tier}} --force --show

# Analyze execution artifacts: just memory-analyze-execution [tier]
memory-analyze-execution tier=default_mem_tier:
    forensic_analysis.py memory analyze execution_analysis --tier {{tier}} --force --show

# View process analysis report: just memory-report-processes [tier]
memory-report-processes tier=default_mem_tier:
    #!/usr/bin/env bash
    tier="{{tier}}"; [[ "$tier" =~ {{tier_pattern}} ]] || { echo "Invalid tier: $tier"; exit 1; }; dir="work/{{work_dir_prefix}}${tier#?}"
    {{md}} "$dir"/automated/memory/analysis/process-analysis.md

# View network connections report: just memory-report-network [tier]
memory-report-network tier=default_mem_tier:
    #!/usr/bin/env bash
    tier="{{tier}}"; [[ "$tier" =~ {{tier_pattern}} ]] || { echo "Invalid tier: $tier"; exit 1; }; dir="work/{{work_dir_prefix}}${tier#?}"
    {{md}} "$dir"/automated/memory/analysis/network-connections.md

# View injection analysis report: just memory-report-injection [tier]
memory-report-injection tier=default_mem_tier:
    #!/usr/bin/env bash
    tier="{{tier}}"; [[ "$tier" =~ {{tier_pattern}} ]] || { echo "Invalid tier: $tier"; exit 1; }; dir="work/{{work_dir_prefix}}${tier#?}"
    {{md}} "$dir"/automated/memory/analysis/injection-analysis.md

# View malware extraction report: just memory-report-malware [tier]
memory-report-malware tier=default_mem_tier:
    #!/usr/bin/env bash
    tier="{{tier}}"; [[ "$tier" =~ {{tier_pattern}} ]] || { echo "Invalid tier: $tier"; exit 1; }; dir="work/{{work_dir_prefix}}${tier#?}"
    {{md}} "$dir"/automated/memory/analysis/MALWARE-EXTRACTION-SUMMARY.md

# =============================================================================
# Network Flow Query Commands
# =============================================================================

# Query network flows: summary, ip, port, top-ips, top-ports, external, beacon, mac-ip, mac-correlate, extract, ascii
network-flows *args:
    #!/usr/bin/env bash
    set -eo pipefail
    all=({{args}})
    cmd="${all[0]:-help}"
    tier="${all[1]:-{{default_net_tier}}}"
    case "$cmd" in
        extract)
            forensic_analysis.py network extract flows --tier "$tier" --force
            ;;
        summary|external|beacon|mac-ip)
            query_flows.py "$cmd" --tier "$tier"
            ;;
        ip)
            ip="${all[2]:-}"
            [[ -n "$ip" ]] || { echo "Usage: just network-flows ip <tier> <ip>"; exit 1; }
            query_flows.py ip "$ip" --tier "$tier"
            ;;
        port)
            port="${all[2]:-}"
            [[ -n "$port" ]] || { echo "Usage: just network-flows port <tier> <port> [--hex]"; exit 1; }
            extra="${all[*]:3}"
            query_flows.py port "$port" --tier "$tier" $extra
            ;;
        top-ips)
            n="${all[2]:-20}"
            query_flows.py top-ips "$n" --tier "$tier"
            ;;
        top-ports)
            n="${all[2]:-20}"
            query_flows.py top-ports "$n" --tier "$tier"
            ;;
        mac-correlate)
            query_flows.py mac-correlate
            ;;
        ascii)
            labels_file="${all[2]:-}"
            readarray -t csvs < <(artifacts_helper.py work-path "$tier" flows_csv)
            existing=()
            for f in "${csvs[@]}"; do
                [[ -f "$f" ]] && existing+=("$f")
            done
            if [[ ${#existing[@]} -eq 0 ]]; then
                echo "No flows CSVs found for $tier."
                echo "Run 'just network-flows extract $tier' first."
                exit 1
            elif [[ ${#existing[@]} -eq 1 ]]; then
                csv="${existing[0]}"
            else
                echo "Flows CSVs for $tier:"
                for i in "${!existing[@]}"; do
                    name=$(basename "${existing[$i]}")
                    lines=$(($(wc -l < "${existing[$i]}") - 1))
                    printf "  %d) %s (%d flows)\n" $((i+1)) "$name" "$lines"
                done
                echo ""
                read -p "Which file? [1-${#existing[@]}]: " choice
                idx=$((choice - 1))
                if [[ $idx -ge 0 && $idx -lt ${#existing[@]} ]]; then
                    csv="${existing[$idx]}"
                else
                    echo "Invalid choice."; exit 1
                fi
            fi
            echo "Using: $(basename "$csv")"
            if [[ -n "$labels_file" ]]; then
                ascii_flows.py "$csv" -n "$labels_file" --view interactive
            else
                ascii_flows.py "$csv" --view interactive
            fi
            ;;
        help|*)
            echo "Usage: just network-flows <command> [tier] [args...]"
            echo ""
            echo "Commands:"
            echo "  summary     [tier]                Flow summary statistics"
            echo "  ip          <tier> <ip>            Find flows by IP (wildcards: x, *)"
            echo "  port        <tier> <port> [--hex]  Find flows by port"
            echo "  top-ips     [tier] [N]             Top N IPs by frame count (default 20)"
            echo "  top-ports   [tier] [N]             Top N ports by frame count (default 20)"
            echo "  external    [tier]                 External IPs with WHOIS"
            echo "  beacon      [tier]                 Detect beacon patterns"
            echo "  mac-ip      [tier]                 MAC to IP mappings"
            echo "  mac-correlate                       Correlate MACs across tiers"
            echo "  extract     [tier]                 Extract flows to CSV"
            echo "  ascii       [tier] [labels.yaml]   Interactive flow visualization"
            echo ""
            echo "Default tier: {{default_net_tier}}"
            exit 1
            ;;
    esac

# =============================================================================
# Network DNS Query Commands
# =============================================================================

# Show DNS query summary (T2 unified, T1 uses grep): just network-dns-summary [tier]
network-dns-summary tier=default_net_tier:
    #!/usr/bin/env bash
    tier="{{tier}}"
    [[ "$tier" =~ {{tier_pattern}} ]] || { echo "Invalid tier: $tier"; exit 1; }
    case "$tier" in
        t1|l1)
            echo "DNS summary not available for T1 (different CSV format)."
            echo "T1 DNS queries: work/{{work_dir_prefix}}1/automated/network/extractions/dns-queries.csv"
            echo ""
            echo "Quick stats:"
            wc -l work/{{work_dir_prefix}}1/automated/network/extractions/dns-queries.csv | awk '{print "  Total queries: " $1-1}'
            cut -d',' -f4 work/{{work_dir_prefix}}1/automated/network/extractions/dns-queries.csv | sort | uniq -c | sort -rn | head -10 | awk '{print "  " $1 " - " $2}'
            exit 0
            ;;
        *)
            query_dns.py summary --tier "$tier"
            ;;
    esac

# Find DNS queries by client IP: just network-dns-ip <tier> <ip>
network-dns-ip tier ip:
    #!/usr/bin/env bash
    tier="{{tier}}"
    [[ "$tier" =~ {{tier_pattern}} ]] || { echo "Invalid tier: $tier"; exit 1; }
    case "$tier" in
        t1|l1) grep "{{ip}}" work/{{work_dir_prefix}}1/automated/network/extractions/dns-queries.csv ;;
        *) query_dns.py ip {{ip}} --tier "$tier" ;;
    esac

# Show NXDOMAIN responses (DGA detection): just network-dns-nxdomain [tier]
network-dns-nxdomain tier=default_net_tier:
    #!/usr/bin/env bash
    tier="{{tier}}"
    [[ "$tier" =~ {{tier_pattern}} ]] || { echo "Invalid tier: $tier"; exit 1; }
    case "$tier" in
        t1|l1)
            echo "NXDOMAIN query not available for T1 (different CSV format)."
            echo "Search manually: grep NXDOMAIN work/{{work_dir_prefix}}1/automated/network/extractions/dns-queries.csv"
            ;;
        *) query_dns.py nxdomain --tier "$tier" ;;
    esac

# Search DNS by domain pattern: just network-dns-domain <tier> <pattern>
network-dns-domain tier pattern:
    #!/usr/bin/env bash
    tier="{{tier}}"
    [[ "$tier" =~ {{tier_pattern}} ]] || { echo "Invalid tier: $tier"; exit 1; }
    case "$tier" in
        t1|l1) grep -i "{{pattern}}" work/{{work_dir_prefix}}1/automated/network/extractions/dns-queries.csv | head -50 ;;
        *) query_dns.py domain {{pattern}} --tier "$tier" ;;
    esac

# Show external DNS queries: just network-dns-external [tier]
network-dns-external tier=default_net_tier:
    #!/usr/bin/env bash
    tier="{{tier}}"
    [[ "$tier" =~ {{tier_pattern}} ]] || { echo "Invalid tier: $tier"; exit 1; }
    case "$tier" in
        t1|l1)
            echo "External DNS query not available for T1 (different CSV format)."
            echo "T1 DNS file: work/{{work_dir_prefix}}1/automated/network/extractions/dns-queries.csv"
            ;;
        *) query_dns.py external --tier "$tier" ;;
    esac

# =============================================================================
# Network TLS Query Commands
# =============================================================================

# Show TLS/JA3 summary (T2 unified, T1 uses raw CSVs): just network-tls-summary [tier]
network-tls-summary tier=default_net_tier:
    #!/usr/bin/env bash
    tier="{{tier}}"
    [[ "$tier" =~ {{tier_pattern}} ]] || { echo "Invalid tier: $tier"; exit 1; }
    case "$tier" in
        t1|l1)
            echo "TLS summary not available for T1 (different CSV format)."
            echo "T1 TLS files:"
            echo "  - core-tls.csv: work/{{work_dir_prefix}}1/automated/network/extractions/core-tls.csv"
            echo "  - egress-tls.csv: work/{{work_dir_prefix}}1/automated/network/extractions/egress-tls.csv"
            echo "  - egress-ja3.csv: work/{{work_dir_prefix}}1/automated/network/extractions/egress-ja3.csv"
            echo ""
            echo "Quick stats:"
            wc -l work/{{work_dir_prefix}}1/automated/network/extractions/core-tls.csv | awk '{print "  Core TLS: " $1-1 " connections"}'
            wc -l work/{{work_dir_prefix}}1/automated/network/extractions/egress-tls.csv | awk '{print "  Egress TLS: " $1-1 " connections"}'
            wc -l work/{{work_dir_prefix}}1/automated/network/extractions/egress-ja3.csv | awk '{print "  Egress JA3: " $1-1 " fingerprints"}'
            exit 0
            ;;
        *)
            query_tls.py summary --tier "$tier"
            ;;
    esac

# Find TLS connections by IP: just network-tls-ip <tier> <ip>
network-tls-ip tier ip:
    #!/usr/bin/env bash
    tier="{{tier}}"
    [[ "$tier" =~ {{tier_pattern}} ]] || { echo "Invalid tier: $tier"; exit 1; }
    case "$tier" in
        t1|l1)
            echo "=== Core TLS ==="
            grep "{{ip}}" work/{{work_dir_prefix}}1/automated/network/extractions/core-tls.csv | head -20
            echo ""
            echo "=== Egress TLS ==="
            grep "{{ip}}" work/{{work_dir_prefix}}1/automated/network/extractions/egress-tls.csv | head -20
            ;;
        *) query_tls.py ip {{ip}} --tier "$tier" ;;
    esac

# List all SNI values: just network-tls-sni [tier]
network-tls-sni tier=default_net_tier:
    #!/usr/bin/env bash
    tier="{{tier}}"
    [[ "$tier" =~ {{tier_pattern}} ]] || { echo "Invalid tier: $tier"; exit 1; }
    case "$tier" in
        t1|l1)
            echo "SNI list not available for T1 (different CSV format)."
            echo "Search for SNI in TLS files manually."
            ;;
        *) query_tls.py sni --tier "$tier" ;;
    esac

# Find connections by JA3 hash: just network-tls-ja3 <tier> <hash>
network-tls-ja3 tier hash:
    #!/usr/bin/env bash
    tier="{{tier}}"
    [[ "$tier" =~ {{tier_pattern}} ]] || { echo "Invalid tier: $tier"; exit 1; }
    case "$tier" in
        t1|l1) grep "{{hash}}" work/{{work_dir_prefix}}1/automated/network/extractions/egress-ja3.csv ;;
        *) query_tls.py ja3 {{hash}} --tier "$tier" ;;
    esac

# Show external TLS connections: just network-tls-external [tier]
network-tls-external tier=default_net_tier:
    #!/usr/bin/env bash
    tier="{{tier}}"
    [[ "$tier" =~ {{tier_pattern}} ]] || { echo "Invalid tier: $tier"; exit 1; }
    case "$tier" in
        t1|l1)
            echo "External TLS query not available for T1 (different CSV format)."
            echo "T1 TLS files: work/{{work_dir_prefix}}1/automated/network/extractions/egress-tls.csv"
            ;;
        *) query_tls.py external --tier "$tier" ;;
    esac

# =============================================================================
# Network Infrastructure Commands
# =============================================================================

# Extract MAC-IP inventory: just network-inventory <tier>
network-inventory tier:
    #!/usr/bin/env bash
    tier="{{tier}}"
    [[ "$tier" =~ {{tier_pattern}} ]] || { echo "Invalid tier: $tier"; exit 1; }
    case "$tier" in
        t1|l1)
            echo "MAC-IP inventory extraction not available for T1."
            echo "T1 uses 'just network-flows mac-ip t1' for MAC-IP mappings."
            exit 1
            ;;
        *)
            forensic_analysis.py network extract mac_ip_inventory --tier "$tier" --force
            cat "work/{{work_dir_prefix}}${tier#?}/automated/network/extractions/${tier}-mac-ip-inventory.csv"
            ;;
    esac

# Detect routers/gateways from traffic patterns: just network-router-detect <t2|t3>
network-router-detect tier:
    #!/usr/bin/env bash
    tier="{{tier}}"
    [[ "$tier" =~ {{tier_pattern}} ]] || { echo "Invalid tier: $tier"; exit 1; }
    case "$tier" in
        t1|l1)
            echo "Router detection not available for T1."
            echo "See T1 network diagram: just network-diagram-ascii t1"
            exit 1
            ;;
        *)
            forensic_analysis.py network analyze router_detection --tier "$tier" --force
            {{md}} "work/{{work_dir_prefix}}${tier#?}/automated/network/analysis/${tier}-router-detection.md"
            ;;
    esac

# Analyze router topology: just network-router-topology <tier>
network-router-topology tier:
    #!/usr/bin/env bash
    tier="{{tier}}"
    [[ "$tier" =~ {{tier_pattern}} ]] || { echo "Invalid tier: $tier"; exit 1; }
    case "$tier" in
        t1|l1)
            echo "Router topology analysis not available for T1."
            echo "See T1 network diagram: just network-diagram-ascii t1"
            exit 1
            ;;
        *)
            forensic_analysis.py network analyze router_analysis --tier "$tier" --force
            {{md}} "work/{{work_dir_prefix}}${tier#?}/automated/network/analysis/${tier}-router-analysis.md"
            ;;
    esac

# Run full router analysis (detection + topology): just network-router-full <tier>
network-router-full tier: (network-router-detect tier) (network-router-topology tier)

# Analyze file transfers (ICS): just network-files-transfers <tier>
network-files-transfers tier:
    #!/usr/bin/env bash
    tier="{{tier}}"
    [[ "$tier" =~ {{tier_pattern}} ]] || { echo "Invalid tier: $tier"; exit 1; }
    case "$tier" in
        t1|l1)
            echo "File transfer analysis not available for T1."
            echo "T1 triage packages include pre-extracted file listings."
            echo "Check: work/{{work_dir_prefix}}1/automated/disk/extractions/"
            exit 1
            ;;
        *)
            forensic_analysis.py network analyze file_transfers --tier "$tier" --force
            {{md}} "work/{{work_dir_prefix}}${tier#?}/automated/network/analysis/${tier}-file-transfers.md"
            ;;
    esac

# Scan extracted files for malware (PE analysis, YARA): just network-files-malware <tier>
network-files-malware tier:
    #!/usr/bin/env bash
    tier="{{tier}}"
    [[ "$tier" =~ {{tier_pattern}} ]] || { echo "Invalid tier: $tier"; exit 1; }
    case "$tier" in
        t1|l1)
            echo "Malware scan not available for T1."
            echo "T1 triage packages include pre-extracted malware analysis."
            echo "Check: work/{{work_dir_prefix}}1/automated/disk/extractions/"
            exit 1
            ;;
        *)
            forensic_analysis.py network analyze malware_scan --tier "$tier" --force
            {{md}} "work/{{work_dir_prefix}}${tier#?}/automated/network/analysis/${tier}-malware-scan.md"
            ;;
    esac

# =============================================================================
# Packet Index & Query Commands (SQLite-based, includes TLS/JA3)
# =============================================================================

# Query packets by IP address: just network-query-ip <tier> <ip>
network-query-ip tier ip:
    #!/usr/bin/env bash
    tier="{{tier}}"; [[ "$tier" =~ {{tier_pattern}} ]] || { echo "Invalid tier: $tier"; exit 1; }
    db="work/{{work_dir_prefix}}${tier#?}/automated/network/packets.db"
    pcap_index.py query "$db" --ip {{ip}}

# Query packets by MAC address: just network-query-mac <tier> <mac>
network-query-mac tier mac:
    #!/usr/bin/env bash
    tier="{{tier}}"; [[ "$tier" =~ {{tier_pattern}} ]] || { echo "Invalid tier: $tier"; exit 1; }
    db="work/{{work_dir_prefix}}${tier#?}/automated/network/packets.db"
    pcap_index.py query "$db" --mac {{mac}}

# Query packets by port number: just network-query-port <tier> <port>
network-query-port tier port:
    #!/usr/bin/env bash
    tier="{{tier}}"; [[ "$tier" =~ {{tier_pattern}} ]] || { echo "Invalid tier: $tier"; exit 1; }
    db="work/{{work_dir_prefix}}${tier#?}/automated/network/packets.db"
    pcap_index.py query "$db" --port {{port}}

# Query packets by JA3 hash: just network-query-ja3 <tier> <hash>
network-query-ja3 tier hash:
    #!/usr/bin/env bash
    tier="{{tier}}"; [[ "$tier" =~ {{tier_pattern}} ]] || { echo "Invalid tier: $tier"; exit 1; }
    db="work/{{work_dir_prefix}}${tier#?}/automated/network/packets.db"
    pcap_index.py query "$db" --ja3 {{hash}}

# Execute custom SQL query on packet database: just network-query-sql <tier> "<query>"
network-query-sql tier query:
    #!/usr/bin/env bash
    tier="{{tier}}"; [[ "$tier" =~ {{tier_pattern}} ]] || { echo "Invalid tier: $tier"; exit 1; }
    db="work/{{work_dir_prefix}}${tier#?}/automated/network/packets.db"
    pcap_index.py query "$db" --sql "{{query}}"

# Show packet database statistics: just network-stats [tier]
network-stats tier=default_net_tier:
    #!/usr/bin/env bash
    tier="{{tier}}"; [[ "$tier" =~ {{tier_pattern}} ]] || { echo "Invalid tier: $tier"; exit 1; }
    db="work/{{work_dir_prefix}}${tier#?}/automated/network/packets.db"
    pcap_index.py stats "$db"

# =============================================================================
# PCAP Indexing (reads artifact paths from config/artifacts.yaml)
# =============================================================================

# Index PCAPs into SQLite database (single tier only): just network-index [tier]
network-index tier=default_net_tier:
    #!/usr/bin/env bash
    set -e
    tier="{{tier}}"; [[ "$tier" =~ {{tier_pattern}} ]] || { echo "Invalid tier: $tier"; exit 1; }
    dbdir="work/{{work_dir_prefix}}${tier#?}"
    DB="$dbdir/automated/network/packets.db"
    mkdir -p "$(dirname "$DB")"
    rm -f "$DB"  # Start fresh
    echo "Indexing PCAPs into $DB..."
    artifacts_helper.py pcaps "{{tier}}" | while read -r pcap; do
        echo "  Indexing: $(basename "$pcap")"
        pcap_index.py index "$pcap" --db "$DB" --tier "{{tier}}"
    done
    echo "Done. Database: $DB"
    pcap_index.py stats "$DB"

# (Moved to consolidated 'network-flows ascii' target above)

# =============================================================================
# Project IOC Commands
# =============================================================================

# Search IOCs from one tier in another: just project-ioc-search <from_tier> <in_tier>
project-ioc-search from_tier in_tier:
    ioc_search.py search {{from_tier}} {{in_tier}}

# List IOCs for a tier: just project-ioc-list <tier>
project-ioc-list tier:
    ioc_search.py list {{tier}}

# Show overlapping IOCs across tiers
project-ioc-overlap:
    ioc_search.py overlap

# =============================================================================
# Visualization Commands
# =============================================================================

# Plaso timeline visualization: just viz-plaso [--hourly|--monthly] [--plotly|--png] [--start DATE] [--end DATE]
viz-plaso *args:
    visualize_ascii.py plaso {{args}}

# Plaso by user visualization: just viz-plaso-user <users> [--hourly] [--plotly]
viz-plaso-user users *args:
    visualize_ascii.py plaso --by-user --users {{users}} {{args}}

# Firewall timeline visualization: just viz-firewall [--hourly|--monthly] [--plotly|--png]
viz-firewall *args:
    visualize_ascii.py firewall {{args}}

# Proxy timeline visualization: just viz-proxy [--hourly|--monthly] [--plotly|--png]
viz-proxy *args:
    visualize_ascii.py proxy {{args}}

# List available visualization sources
viz-list:
    visualize_ascii.py --list

# =============================================================================
# KAPE/Triage Investigation
# Investigation Flow:
#   1. kape-files       - Start here: what files are available?
#   2. kape-ps-hist     - Check for commands run
#   3. kape-timeline    - When were programs executed?
#   4. kape-activities  - What GUI activity occurred?
#   5. kape-browser     - What sites were visited?
#   6. kape-evtx        - What events are logged?
#   7. kape-logons      - Who logged in from where?
#   8. kape-lateral     - Any lateral movement?
# =============================================================================

# List large files in KAPE extraction: just kape-files [t1|t2|t3]
kape-files *args:
    #!/usr/bin/env bash
    tier="{{default_net_tier}}"; extra=""
    for arg in {{args}}; do
        [[ "$arg" =~ {{tier_pattern}} ]] && tier="$arg" || extra="$extra $arg"
    done
    query_kape.py files --tier "$tier" $extra

# Live system state (system info + files + processes + network): just kape-live [t1|t2|t3]
kape-live *args:
    #!/usr/bin/env bash
    tier="{{default_net_tier}}"; extra=""
    for arg in {{args}}; do
        [[ "$arg" =~ {{tier_pattern}} ]] && tier="$arg" || extra="$extra $arg"
    done
    query_kape.py live --tier "$tier" $extra

# PowerShell console history: just kape-ps-hist [tier]
kape-ps-hist tier=default_net_tier:
    query_kape.py ps-hist --tier {{tier}}

# Program usage timeline (compact by default): just kape-timeline [t1|t2|t3] [--detailed]
kape-timeline *args:
    #!/usr/bin/env bash
    tier="{{default_net_tier}}"; extra=""
    for arg in {{args}}; do
        [[ "$arg" =~ {{tier_pattern}} ]] && tier="$arg" || extra="$extra $arg"
    done
    query_kape.py timeline --tier "$tier" --compact $extra

# Windows Timeline (ActivitiesCache.db): just kape-activities [t1|t2|t3]
kape-activities *args:
    #!/usr/bin/env bash
    tier="{{default_net_tier}}"; extra=""
    for arg in {{args}}; do
        [[ "$arg" =~ {{tier_pattern}} ]] && tier="$arg" || extra="$extra $arg"
    done
    query_kape.py activities --tier "$tier" $extra

# Browser history (Firefox/Edge): just kape-browser [t1|t2|t3]
kape-browser *args:
    #!/usr/bin/env bash
    tier="{{default_net_tier}}"; extra=""
    for arg in {{args}}; do
        [[ "$arg" =~ {{tier_pattern}} ]] && tier="$arg" || extra="$extra $arg"
    done
    query_kape.py browser --tier "$tier" $extra

# Extract Security.evtx to CSV: just kape-evtx-extract [t1|t2|t3]
kape-evtx-extract *args:
    #!/usr/bin/env bash
    tier="{{default_net_tier}}"; extra=""
    for arg in {{args}}; do
        [[ "$arg" =~ {{tier_pattern}} ]] && tier="$arg" || extra="$extra $arg"
    done
    query_kape.py evtx-extract --tier "$tier" $extra

# EVTX timeline: events per day: just kape-evtx-timeline <log> [t1|t2|t3] [--hourly] [--from DATE] [--to DATE]
kape-evtx-timeline log *args:
    #!/usr/bin/env bash
    tier="{{default_net_tier}}"; extra=""
    for arg in {{args}}; do
        [[ "$arg" =~ {{tier_pattern}} ]] && tier="$arg" || extra="$extra $arg"
    done
    query_kape.py evtx-timeline {{log}} --tier "$tier" $extra

# Security.evtx event summary (count by event ID): just kape-evtx [t1|t2|t3]
kape-evtx *args:
    #!/usr/bin/env bash
    tier="{{default_net_tier}}"; extra=""
    for arg in {{args}}; do
        [[ "$arg" =~ {{tier_pattern}} ]] && tier="$arg" || extra="$extra $arg"
    done
    query_kape.py evtx-summary --tier "$tier" $extra

# Logon events (4624): just kape-logons [t1|t2|t3]
kape-logons *args:
    #!/usr/bin/env bash
    tier="{{default_net_tier}}"; extra=""
    for arg in {{args}}; do
        [[ "$arg" =~ {{tier_pattern}} ]] && tier="$arg" || extra="$extra $arg"
    done
    query_kape.py evtx-logons --tier "$tier" $extra

# Explicit credential logons (4648) - lateral movement: just kape-lateral [t1|t2|t3]
kape-lateral *args:
    #!/usr/bin/env bash
    tier="{{default_net_tier}}"; extra=""
    for arg in {{args}}; do
        [[ "$arg" =~ {{tier_pattern}} ]] && tier="$arg" || extra="$extra $arg"
    done
    query_kape.py evtx-lateral --tier "$tier" $extra

# Prefetch analysis: just kape-prefetch [t1|t2|t3]
kape-prefetch *args:
    #!/usr/bin/env bash
    tier="{{default_net_tier}}"; extra=""
    for arg in {{args}}; do
        [[ "$arg" =~ {{tier_pattern}} ]] && tier="$arg" || extra="$extra $arg"
    done
    query_kape.py prefetch --tier "$tier" $extra

# Amcache program entries: just kape-amcache [t1|t2|t3]
kape-amcache *args:
    #!/usr/bin/env bash
    tier="{{default_net_tier}}"; extra=""
    for arg in {{args}}; do
        [[ "$arg" =~ {{tier_pattern}} ]] && tier="$arg" || extra="$extra $arg"
    done
    query_kape.py amcache --tier "$tier" $extra

# Check Amcache hashes against CIRCL hashlookup: just kape-amcache-malware [t1|t2|t3]
kape-amcache-malware *args:
    #!/usr/bin/env bash
    tier="{{default_net_tier}}"; extra=""
    for arg in {{args}}; do
        [[ "$arg" =~ {{tier_pattern}} ]] && tier="$arg" || extra="$extra $arg"
    done
    query_kape.py amcache-hash-check --tier "$tier" $extra

# User accounts: just kape-users [tier]
kape-users tier=default_net_tier:
    query_kape.py users --tier {{tier}}

# Windows services: just kape-services [t1|t2|t3]
kape-services *args:
    #!/usr/bin/env bash
    tier="{{default_net_tier}}"; extra=""
    for arg in {{args}}; do
        [[ "$arg" =~ {{tier_pattern}} ]] && tier="$arg" || extra="$extra $arg"
    done
    query_kape.py services --tier "$tier" $extra

# UserAssist (GUI execution): just kape-userassist [t1|t2|t3]
kape-userassist *args:
    #!/usr/bin/env bash
    tier="{{default_net_tier}}"; extra=""
    for arg in {{args}}; do
        [[ "$arg" =~ {{tier_pattern}} ]] && tier="$arg" || extra="$extra $arg"
    done
    query_kape.py userassist --tier "$tier" $extra

# Recent documents: just kape-recentdocs [t1|t2|t3]
kape-recentdocs *args:
    #!/usr/bin/env bash
    tier="{{default_net_tier}}"; extra=""
    for arg in {{args}}; do
        [[ "$arg" =~ {{tier_pattern}} ]] && tier="$arg" || extra="$extra $arg"
    done
    query_kape.py recentdocs --tier "$tier" $extra

# Jump list analysis: just kape-jumplists [t1|t2|t3]
kape-jumplists *args:
    #!/usr/bin/env bash
    tier="{{default_net_tier}}"; extra=""
    for arg in {{args}}; do
        [[ "$arg" =~ {{tier_pattern}} ]] && tier="$arg" || extra="$extra $arg"
    done
    query_kape.py jumplists --tier "$tier" $extra

# DLL load analysis from Prefetch: just kape-dlls [t1|t2|t3] [exe-name|--raw]
kape-dlls *args:
    #!/usr/bin/env bash
    tier="{{default_net_tier}}"; extra=""
    for arg in {{args}}; do
        [[ "$arg" =~ {{tier_pattern}} ]] && tier="$arg" || extra="$extra $arg"
    done
    query_kape.py dlls --tier "$tier" $extra

# DLL load timeline: just kape-dll-timeline [t1|t2|t3] [--hourly] [--from DATE] [--to DATE]
kape-dll-timeline *args:
    #!/usr/bin/env bash
    tier="{{default_net_tier}}"; extra=""
    for arg in {{args}}; do
        [[ "$arg" =~ {{tier_pattern}} ]] && tier="$arg" || extra="$extra $arg"
    done
    query_kape.py dll-timeline --tier "$tier" $extra

# File system timeline (LNK + Amcache + Prefetch): just kape-fstimeline [t1|t2|t3] [--search term]
kape-fstimeline *args:
    #!/usr/bin/env bash
    tier="{{default_net_tier}}"; extra=""
    for arg in {{args}}; do
        [[ "$arg" =~ {{tier_pattern}} ]] && tier="$arg" || extra="$extra $arg"
    done
    query_kape.py fstimeline --tier "$tier" $extra

# Process snapshots (CIM and Get-Process CSVs): just kape-ps [t1|t2|t3]
kape-ps *args:
    #!/usr/bin/env bash
    tier="{{default_net_tier}}"; extra=""
    for arg in {{args}}; do
        [[ "$arg" =~ {{tier_pattern}} ]] && tier="$arg" || extra="$extra $arg"
    done
    query_kape.py ps --tier "$tier" $extra

# Deleted files (Recycle Bin): just kape-deleted [t1|t2|t3]
kape-deleted *args:
    #!/usr/bin/env bash
    tier="{{default_net_tier}}"; extra=""
    for arg in {{args}}; do
        [[ "$arg" =~ {{tier_pattern}} ]] && tier="$arg" || extra="$extra $arg"
    done
    query_kape.py deleted --tier "$tier" $extra

# =============================================================================
# Registry Analysis
# =============================================================================

# Registry overview: just kape-reg-overview [t1|t2|t3] [--raw]
kape-reg-overview *args:
    #!/usr/bin/env bash
    tier="{{default_net_tier}}"; extra=""
    for arg in {{args}}; do
        [[ "$arg" =~ {{tier_pattern}} ]] && tier="$arg" || extra="$extra $arg"
    done
    query_kape.py registry-overview --tier "$tier" $extra

# Mounted devices (USB/drive history): just kape-reg-devices [t1|t2|t3]
kape-reg-devices *args:
    #!/usr/bin/env bash
    tier="{{default_net_tier}}"; extra=""
    for arg in {{args}}; do
        [[ "$arg" =~ {{tier_pattern}} ]] && tier="$arg" || extra="$extra $arg"
    done
    query_kape.py mounted-devices --tier "$tier" $extra

# Known networks (WiFi/network profiles): just kape-reg-networks [t1|t2|t3]
kape-reg-networks *args:
    #!/usr/bin/env bash
    tier="{{default_net_tier}}"; extra=""
    for arg in {{args}}; do
        [[ "$arg" =~ {{tier_pattern}} ]] && tier="$arg" || extra="$extra $arg"
    done
    query_kape.py known-networks --tier "$tier" $extra

# RDP connection history: just kape-reg-rdp [t1|t2|t3]
kape-reg-rdp *args:
    #!/usr/bin/env bash
    tier="{{default_net_tier}}"; extra=""
    for arg in {{args}}; do
        [[ "$arg" =~ {{tier_pattern}} ]] && tier="$arg" || extra="$extra $arg"
    done
    query_kape.py rdp-history --tier "$tier" $extra

# File Open/Save dialog history: just kape-reg-opensave [t1|t2|t3]
kape-reg-opensave *args:
    #!/usr/bin/env bash
    tier="{{default_net_tier}}"; extra=""
    for arg in {{args}}; do
        [[ "$arg" =~ {{tier_pattern}} ]] && tier="$arg" || extra="$extra $arg"
    done
    query_kape.py opensave --tier "$tier" $extra

# Last visited folders per application: just kape-reg-lastvisited [t1|t2|t3]
kape-reg-lastvisited *args:
    #!/usr/bin/env bash
    tier="{{default_net_tier}}"; extra=""
    for arg in {{args}}; do
        [[ "$arg" =~ {{tier_pattern}} ]] && tier="$arg" || extra="$extra $arg"
    done
    query_kape.py lastvisited --tier "$tier" $extra

# Win+R run dialog history: just kape-reg-run [t1|t2|t3]
kape-reg-run *args:
    #!/usr/bin/env bash
    tier="{{default_net_tier}}"; extra=""
    for arg in {{args}}; do
        [[ "$arg" =~ {{tier_pattern}} ]] && tier="$arg" || extra="$extra $arg"
    done
    query_kape.py run-history --tier "$tier" $extra

# ShellBags — folder browsing history: just kape-reg-shellbags [t1|t2|t3]
kape-reg-shellbags *args:
    #!/usr/bin/env bash
    tier="{{default_net_tier}}"; extra=""
    for arg in {{args}}; do
        [[ "$arg" =~ {{tier_pattern}} ]] && tier="$arg" || extra="$extra $arg"
    done
    query_kape.py shellbags --tier "$tier" $extra

# NTUSER.DAT Run/RunOnce keys (persistence check): just kape-reg-autorun [t1|t2|t3]
kape-reg-autorun *args:
    #!/usr/bin/env bash
    tier="{{default_net_tier}}"; extra=""
    for arg in {{args}}; do
        [[ "$arg" =~ {{tier_pattern}} ]] && tier="$arg" || extra="$extra $arg"
    done
    query_kape.py ntuser-autorun --tier "$tier" $extra

# =============================================================================
# Project Hash Verification
# =============================================================================

# Generate hashes for artifacts: just project-hash-generate <tier> [folder]
project-hash-generate tier folder="":
    #!/usr/bin/env bash
    hashdir="${PROJECT_ROOT:-.}/artifact-intake/hashes/{{tier}}"
    mkdir -p "$hashdir"
    if [ -n "{{folder}}" ]; then
        hash-folder.sh "{{folder}}" -o "$hashdir"
    else
        while IFS= read -r dir; do
            echo "=== Hashing: $dir ==="
            hash-folder.sh "$dir" -o "$hashdir"
            echo ""
        done < <(artifacts_helper.py artifact-dirs "{{tier}}")
    fi

# Verify hashes for artifacts: just project-hash-verify <tier> [folder]
project-hash-verify tier folder="":
    #!/usr/bin/env bash
    hashdir="${PROJECT_ROOT:-.}/artifact-intake/hashes/{{tier}}"
    if [[ ! -d "$hashdir" ]]; then
        echo "Error: Hash directory not found: $hashdir"
        echo "Hint: Generate hashes first with: just project-hash-generate {{tier}}"
        exit 1
    fi
    if [ -n "{{folder}}" ]; then
        hash-folder.sh "{{folder}}" -o "$hashdir" --verify
    else
        failed=0
        while IFS= read -r dir; do
            echo "=== Verifying: $dir ==="
            hash-folder.sh "$dir" -o "$hashdir" --verify || failed=1
            echo ""
        done < <(artifacts_helper.py artifact-dirs "{{tier}}")
        exit $failed
    fi

# =============================================================================
# Raw Disk Extraction
# =============================================================================

# Extract artifacts from raw disk image to KAPE-compatible format: just disk-extract-raw <partition> <output>
disk-extract-raw partition output:
    #!/usr/bin/env bash
    set -e
    if [[ ! -f "{{partition}}" ]]; then
        echo "ERROR: Partition not found: {{partition}}"
        echo ""
        echo "For VHDX files, first convert to raw:"
        echo "  qemu-img convert -f vhdx -O raw input.vhdx output.raw"
        echo ""
        echo "Then check partition layout:"
        echo "  mmls output.raw"
        echo ""
        echo "For KAPE triage images, use the raw file directly."
        exit 1
    fi

    echo "=== Extracting KAPE-style artifacts from {{partition}} ==="
    echo "Output: {{output}}"
    echo ""
    extract_disk_artifacts.py all "{{partition}}" "{{output}}"
    echo ""
    echo "Done! Now use kape-* commands to analyze:"
    echo "  just kape-files t1"
    echo "  just kape-userassist t1"
    echo "  just kape-services t1"

# =============================================================================
# File/Binary Analysis Commands
# =============================================================================

# Deep binary analysis with radare2: just file-analyze-binary <tier> <file> [name]
file-analyze-binary tier file name="":
    #!/usr/bin/env bash
    tier="{{tier}}"
    [[ "$tier" =~ {{tier_pattern}} ]] || { echo "Invalid tier: $tier"; exit 1; }
    outdir="work/{{work_dir_prefix}}${tier#?}/manual/binary-analysis"
    mkdir -p "$outdir"
    if [ -n "{{name}}" ]; then
        python -m scripts.forensic_analysis.binary analyze "{{file}}" -o "$outdir" -n "{{name}}"
    else
        python -m scripts.forensic_analysis.binary analyze "{{file}}" -o "$outdir"
    fi
    {{md}} "$outdir"/*.md

# Compare two binary files: just file-compare-binary <file1> <file2>
file-compare-binary file1 file2:
    python -m scripts.forensic_analysis.binary compare "{{file1}}" "{{file2}}"

# Run unit tests: just test [--coverage]
test *args:
    #!/usr/bin/env bash
    eval "$(micromamba shell hook -s bash)" && micromamba activate ~/micromamba-base
    cd "$(dirname "$(realpath "{{justfile()}}")")"
    args="{{args}}"
    if [[ "$args" == *"--coverage"* ]]; then
        pytest tests/ -v --tb=short --cov=scripts --cov-report=term-missing
    else
        pytest tests/ -v --tb=short
    fi

# =============================================================================
# Investigation Log Management
# =============================================================================

# Investigation log: add "title", show [date], list, lock, migrate [file], init
inv-log *args:
    investigation-log.sh {{args}}
