#!/usr/bin/env python3
"""
ASCII Network Flow Visualization

Visualizes network communication flows from CSV data in ASCII art.
Designed for terminal output with mdcat rendering.

CSV Format (with optional timestamp):
  timestamp_utc,src_ip,src_port,dst_ip,dst_port,protocol,process_account,explanation,evidence_source

  OR (for MAC-based flows):
  timestamp_utc,src_mac,src_ip,dst_mac,dst_ip,dst_port,protocol,explanation,evidence_source

  - timestamp_utc: ISO format (2020-11-06T18:35:09) - CRITICAL for forensic timeline!
  - If timestamp_utc is missing, a warning will be displayed
  - src_mac/dst_mac: Optional MAC addresses (00:0c:29:ab:c1:c9)
  - When MAC is present, it's used as the primary identifier with IP as fallback

Optional labels file (YAML):
  # IP labels
  10.10.2.10: stsupport10
  10.10.200.207: LARIAT-C2
  # MAC labels (use lowercase with colons)
  00:0c:29:ab:c1:c9: EWS-VM
  00:00:bc:47:7d:81: Rockwell-PLC
"""

import argparse
import csv
import sys
from collections import defaultdict
from pathlib import Path

# ANSI colors for warnings
WARN_COLOR = "\033[93m"  # Yellow
ERROR_COLOR = "\033[91m"  # Red
RESET = "\033[0m"

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


def get_timestamp_column(flows: list[dict]) -> str | None:
    """Get the name of the timestamp column if it exists."""
    if not flows:
        return None
    if 'timestamp_utc' in flows[0]:
        return 'timestamp_utc'
    if 'datetime_utc' in flows[0]:
        return 'datetime_utc'
    return None


def has_mac_columns(flows: list[dict]) -> bool:
    """Check if flows have MAC address columns."""
    if not flows:
        return False
    return 'src_mac' in flows[0] or 'dst_mac' in flows[0]


def get_src_id(flow: dict) -> str:
    """Get source identifier - prefer MAC if available, fallback to IP."""
    mac = flow.get('src_mac', '').strip()
    if mac and mac not in ['-', '*', '']:
        return mac.lower()
    return flow.get('src_ip', '?')


def get_dst_id(flow: dict) -> str:
    """Get destination identifier - prefer MAC if available, fallback to IP."""
    mac = flow.get('dst_mac', '').strip()
    if mac and mac not in ['-', '*', '']:
        return mac.lower()
    return flow.get('dst_ip', '?')


def normalize_mac(mac: str) -> str:
    """Normalize MAC address to lowercase with colons."""
    if not mac:
        return mac
    # Remove common separators and convert to lowercase
    clean = mac.lower().replace('-', '').replace(':', '').replace('.', '')
    if len(clean) == 12:
        return ':'.join(clean[i:i+2] for i in range(0, 12, 2))
    return mac.lower()


def is_mac_address(identifier: str) -> bool:
    """Check if identifier looks like a MAC address."""
    if not identifier:
        return False
    # MAC format: xx:xx:xx:xx:xx:xx or xx-xx-xx-xx-xx-xx
    clean = identifier.lower().replace('-', ':')
    parts = clean.split(':')
    if len(parts) == 6:
        return all(len(p) == 2 and all(c in '0123456789abcdef' for c in p) for p in parts)
    return False


def check_timestamps(flows: list[dict]) -> bool:
    """Check if flows have timestamps and warn if missing."""
    if not flows:
        return False

    ts_col = get_timestamp_column(flows)

    if not ts_col:
        print(f"{WARN_COLOR}", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print("⚠️  WARNING: NO TIMESTAMPS IN DATA!", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print("", file=sys.stderr)
        print("TIMESTAMPS ARE CRITICAL FOR FORENSIC INVESTIGATION!", file=sys.stderr)
        print("", file=sys.stderr)
        print("Without timestamps, you cannot:", file=sys.stderr)
        print("  - Establish sequence of events (WHO did WHAT and WHEN)", file=sys.stderr)
        print("  - Correlate network and disk artifacts", file=sys.stderr)
        print("  - Build a defensible forensic timeline", file=sys.stderr)
        print("  - Prove causation vs correlation", file=sys.stderr)
        print("", file=sys.stderr)
        print("Add 'timestamp_utc' or 'datetime_utc' column (ISO format: 2020-11-06T18:35:09)", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print(f"{RESET}", file=sys.stderr)
        return False

    # Check how many rows have actual timestamp values
    rows_with_ts = sum(1 for f in flows if f.get(ts_col, '').strip())
    total_rows = len(flows)

    if rows_with_ts == 0:
        print(f"{WARN_COLOR}⚠️  WARNING: {ts_col} column exists but ALL values are empty!{RESET}", file=sys.stderr)
        return False
    elif rows_with_ts < total_rows:
        print(f"{WARN_COLOR}⚠️  WARNING: Only {rows_with_ts}/{total_rows} rows have timestamps{RESET}", file=sys.stderr)

    return True


def load_flows(csv_path: Path) -> list[dict]:
    """Load communication flows from CSV, sorted by timestamp if available."""
    flows = []
    with open(csv_path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            flows.append(row)

    # Sort by timestamp if available (supports both column names)
    if flows:
        ts_col = get_timestamp_column(flows)
        if ts_col:
            flows.sort(key=lambda x: x.get(ts_col, '') or 'zzzz')

    return flows


def load_labels(labels_path: Path) -> dict[str, str]:
    """Load IP/MAC->label mappings from YAML file."""
    if not labels_path.exists():
        return {}

    if not HAS_YAML:
        print(f"Warning: PyYAML not installed, cannot load labels from {labels_path}", file=sys.stderr)
        return {}

    with open(labels_path) as f:
        data = yaml.safe_load(f)

    if not data:
        return {}

    # Check if this is a network config file with 'labels' key
    if 'labels' in data:
        data = data['labels']

    # Convert all keys to strings and normalize MAC addresses
    labels = {}
    for k, v in data.items():
        key = str(k)
        # Normalize MAC addresses to lowercase with colons
        if is_mac_address(key):
            key = normalize_mac(key)
        labels[key] = str(v)
    return labels


# Global network configuration
NETWORK_CONFIG = None


def load_network_config(config_path: Path) -> dict:
    """Load network zone configuration from YAML file."""
    global NETWORK_CONFIG

    if not config_path.exists():
        return {}

    if not HAS_YAML:
        return {}

    with open(config_path) as f:
        data = yaml.safe_load(f)

    if data and 'zones' in data:
        NETWORK_CONFIG = data
        return data

    return {}


def get_zone_for_ip(ip: str) -> int:
    """Get zone index for an IP based on network config."""
    global NETWORK_CONFIG

    if not NETWORK_CONFIG or 'zones' not in NETWORK_CONFIG:
        return -1  # Use default logic

    zones = NETWORK_CONFIG['zones']

    # Check each zone for explicit IP match first
    for idx, zone in enumerate(zones):
        if ip in zone.get('ips', []):
            return idx

    # Then check subnet matches
    for idx, zone in enumerate(zones):
        for subnet in zone.get('subnets', []):
            if ip_in_subnet(ip, subnet):
                return idx

    return -1  # Not found


def ip_in_subnet(ip: str, subnet: str) -> bool:
    """Check if IP is in subnet (simple /24 check)."""
    if '/' not in subnet:
        return ip == subnet

    try:
        net_addr, prefix = subnet.split('/')
        prefix = int(prefix)

        ip_parts = [int(p) for p in ip.split('.')]
        net_parts = [int(p) for p in net_addr.split('.')]

        if len(ip_parts) != 4 or len(net_parts) != 4:
            return False

        # Simple check for /8, /16, /24
        if prefix == 8:
            return ip_parts[0] == net_parts[0]
        elif prefix == 16:
            return ip_parts[:2] == net_parts[:2]
        elif prefix == 24:
            return ip_parts[:3] == net_parts[:3]
        else:
            return False
    except (ValueError, IndexError):
        return False


def get_zone_labels() -> list[str]:
    """Get zone labels from config or default."""
    global NETWORK_CONFIG

    if NETWORK_CONFIG and 'zones' in NETWORK_CONFIG:
        labels = [z['name'] for z in NETWORK_CONFIG['zones']]
        if 'EXTERNAL' not in labels:
            labels.append('EXTERNAL')
        return labels

    return ["WORKSTATIONS", "MANAGEMENT", "LOCAL", "SERVERS", "DC", "EXTERNAL"]


def _is_public_ip(ip: str) -> bool:
    """Check if IP is a public (non-RFC1918/multicast/loopback) address."""
    if not ip or ip == '-':
        return False
    return not ip.startswith(('192.168.', '10.', '172.16.', '172.17.', '172.18.',
                              '172.19.', '172.2', '172.30.', '172.31.',
                              '224.', '239.', '255.', '127.', 'fe80', 'ff0'))


def build_labels_from_data(flows: list[dict]) -> dict[str, str]:
    """Build IP->label mappings from flow data itself."""
    labels = {}

    for flow in flows:
        # Use process_account as label if it looks like a hostname/account
        account = flow.get('process_account', '')
        if account and account not in ['-', '*', '']:
            # Check if it's a machine account (ends with $) or has useful name
            src_ip = flow.get('src_ip', '')
            if account.endswith('$') or account.endswith('.exe'):
                # For machine accounts, associate with src_ip
                if src_ip and src_ip not in labels:
                    labels[src_ip] = account.rstrip('.exe')

    return labels


def get_host_label(identifier: str, labels: dict[str, str], max_len: int = 14) -> str:
    """Get label for IP/MAC, with fallback to identifier itself."""
    # Normalize MAC for lookup
    lookup_key = normalize_mac(identifier) if is_mac_address(identifier) else identifier
    label = labels.get(lookup_key, identifier)
    if len(label) > max_len:
        label = label[:max_len-1] + "…"
    return label


def is_broadcast_or_multicast(identifier: str) -> bool:
    """Check if IP/MAC is broadcast or multicast (for filtering in matrix)."""
    if not identifier or identifier in ['*', '-']:
        return True

    # Check if it's a MAC address
    if is_mac_address(identifier):
        mac = normalize_mac(identifier)
        # Broadcast MAC
        if mac == 'ff:ff:ff:ff:ff:ff':
            return True
        # Multicast MAC (first byte has LSB set)
        first_byte = int(mac[:2], 16)
        if first_byte & 0x01:
            return True
        return False

    # IPv6 multicast (ff00::/8) and link-local (fe80::/10)
    if identifier.startswith('ff0') or identifier.startswith('fe80'):
        return True

    # IP-based checks
    if identifier.startswith('224.') or identifier.startswith('239.'):  # Multicast
        return True
    if identifier.endswith('.255'):  # Broadcast
        return True
    return False


def has_timestamps(flows: list[dict]) -> bool:
    """Check if flows have timestamp data."""
    ts_col = get_timestamp_column(flows)
    if not ts_col:
        return False
    return any(f.get(ts_col, '').strip() for f in flows)


def get_time_str(flow: dict, full: bool = False) -> str:
    """Extract time portion from timestamp (HH:MM:SS) or full timestamp if full=True."""
    # Try both column names
    ts = flow.get('timestamp_utc', '').strip() or flow.get('datetime_utc', '').strip()
    if not ts:
        return ""
    if full:
        return ts[:19] if len(ts) >= 19 else ts
    if len(ts) >= 19:
        return ts[11:19]
    elif len(ts) > 10:
        return ts[11:]
    return ""


def render_sankey_ascii(flows: list[dict], labels: dict[str, str]) -> str:
    """Render flows as ASCII Sankey-style diagram, chronologically if timestamps exist."""
    lines = []
    lines.append("=" * 100)
    lines.append("NETWORK COMMUNICATION FLOWS" + (" (CHRONOLOGICAL)" if has_timestamps(flows) else ""))
    lines.append("=" * 100)
    lines.append("")

    show_time = has_timestamps(flows)

    # Group by source, but preserve chronological order within each group
    by_source = defaultdict(list)
    for f in flows:
        src = get_src_id(f)
        by_source[src].append(f)

    # Sort sources by their first timestamp if available
    def first_timestamp(src_ip):
        src_flows = by_source[src_ip]
        for f in src_flows:
            ts = f.get('timestamp_utc', '')
            if ts:
                return ts
        return 'zzzz'

    sorted_sources = sorted(by_source.keys(), key=first_timestamp) if show_time else sorted(by_source.keys())

    for src_id in sorted_sources:
        src_flows = by_source[src_id]
        src_label = get_host_label(src_id, labels)
        box_width = max(len(src_label), len(src_id)) + 4

        lines.append(f"┌{'─' * box_width}┐")
        lines.append(f"│  {src_label:<{box_width-4}}  │")
        lines.append(f"│  {src_id:<{box_width-4}}  │")
        lines.append(f"└{'─' * box_width}┘")

        for i, flow in enumerate(src_flows):
            dst_id = get_dst_id(flow)
            dst_port = flow.get('dst_port', '?')
            protocol = flow.get('protocol', '?')
            explanation = flow.get('explanation', '')
            dst_label = get_host_label(dst_id, labels)
            time_str = get_time_str(flow) if show_time else ""

            is_last = (i == len(src_flows) - 1)
            prefix = "└" if is_last else "├"

            # Draw the flow line with optional timestamp
            port_info = f":{dst_port}" if dst_port and dst_port not in ['-', '0', '*', ''] else ""
            arrow = f"──({protocol})──▶"
            time_prefix = f"[{time_str}] " if time_str else ""

            lines.append(f"    {prefix}───{time_prefix}{arrow} {dst_label} ({dst_id}{port_info})")
            if explanation:
                lines.append(f"    {'    ' if is_last else '│   '}         └─ {explanation}")

        lines.append("")

    return "\n".join(lines)


def render_matrix_ascii(flows: list[dict], labels: dict[str, str]) -> str:
    """Render flows as connection matrix."""
    lines = []
    lines.append("=" * 80)
    lines.append("CONNECTION MATRIX")
    lines.append("=" * 80)
    lines.append("")

    # Collect all unique identifiers (excluding broadcast/multicast)
    all_ids = set()
    for f in flows:
        src = get_src_id(f)
        dst = get_dst_id(f)
        if not is_broadcast_or_multicast(src):
            all_ids.add(src)
        if not is_broadcast_or_multicast(dst):
            all_ids.add(dst)

    all_ids = sorted(all_ids)

    if not all_ids:
        lines.append("No unicast connections found.")
        return "\n".join(lines)

    # Build connection map
    connections = defaultdict(set)
    for f in flows:
        src = get_src_id(f)
        dst = get_dst_id(f)
        proto = f.get('protocol', '?')
        if src in all_ids and dst in all_ids:
            connections[(src, dst)].add(proto)

    # Get labels with max width
    col_width = 13
    id_labels = {id: get_host_label(id, labels, col_width - 1) for id in all_ids}

    # Header
    header = " " * 16 + "│"
    for id in all_ids:
        header += f" {id_labels[id]:<{col_width-1}}│"
    lines.append(header)
    lines.append("─" * 16 + "┼" + ("─" * col_width + "┼") * len(all_ids))

    # Rows
    for src_id in all_ids:
        row = f" {id_labels[src_id]:<14} │"
        for dst_id in all_ids:
            if src_id == dst_id:
                cell = "     ·"
            elif (src_id, dst_id) in connections:
                protos = ",".join(sorted(connections[(src_id, dst_id)]))[:10]
                cell = f"  ──▶ {protos}"
            else:
                cell = "      "
            row += f" {cell:<{col_width-1}}│"
        lines.append(row)

    lines.append("")
    return "\n".join(lines)


def render_timeline_ascii(flows: list[dict], labels: dict[str, str]) -> str:
    """Render flows grouped by evidence source, chronologically ordered if timestamps exist."""
    lines = []
    lines.append("=" * 100)
    lines.append("FLOWS BY EVIDENCE SOURCE" + (" (CHRONOLOGICAL)" if has_timestamps(flows) else ""))
    lines.append("=" * 100)
    lines.append("")

    show_time = has_timestamps(flows)

    # Group by evidence source
    by_source = defaultdict(list)
    for f in flows:
        source = f.get('evidence_source', 'unknown')
        by_source[source].append(f)

    # Sort sources by their first timestamp if available
    def first_timestamp(source):
        source_flows = by_source[source]
        for f in source_flows:
            ts = f.get('timestamp_utc', '')
            if ts:
                return ts
        return 'zzzz'

    sorted_sources = sorted(by_source.keys(), key=first_timestamp) if show_time else sorted(by_source.keys())

    for source in sorted_sources:
        source_flows = by_source[source]
        lines.append(f"┏━━ {source.upper()} ━━{'━' * max(0, 80 - len(source))}┓")
        lines.append("┃")

        for flow in source_flows:
            src_id = get_src_id(flow)
            dst_id = get_dst_id(flow)
            dst_port = flow.get('dst_port', '?')
            protocol = flow.get('protocol', '?')
            explanation = flow.get('explanation', '')
            time_str = get_time_str(flow) if show_time else ""

            src_label = get_host_label(src_id, labels, 12)
            dst_label = get_host_label(dst_id, labels, 12)

            port_str = f":{dst_port}" if dst_port and dst_port not in ['-', '0', '*', ''] else ""
            time_prefix = f"[{time_str}] " if time_str else ""

            lines.append(f"┃  {time_prefix}{src_label:<12} ──({protocol:^8})──▶ {dst_label}{port_str}")
            if explanation:
                pad = len(time_prefix) if time_prefix else 0
                lines.append(f"┃  {' ' * pad}{'':12}    └─ {explanation}")
            lines.append("┃")

        lines.append(f"┗{'━' * 96}┛")
        lines.append("")

    return "\n".join(lines)


def render_graph_wired(flows: list[dict], labels: dict[str, str]) -> str:
    """Render graph with all connections shown as wired arrows between nodes."""

    # ANSI color codes
    COLORS = [
        "\033[91m",  # Red
        "\033[92m",  # Green
        "\033[93m",  # Yellow
        "\033[94m",  # Blue
        "\033[95m",  # Magenta
        "\033[96m",  # Cyan
        "\033[97m",  # White
        "\033[33m",  # Orange-ish
    ]
    RESET = "\033[0m"
    DIM = "\033[2m"

    lines = []
    lines.append("=" * 120)
    lines.append("WIRED NETWORK GRAPH - All connections shown")
    lines.append("=" * 120)
    lines.append("")

    # Collect nodes and edges
    nodes = set()
    edges = []
    for f in flows:
        src = f.get('src_ip', '?')
        dst = f.get('dst_ip', '?')
        proto = f.get('protocol', '?')
        if not is_broadcast_or_multicast(src):
            nodes.add(src)
        if not is_broadcast_or_multicast(dst):
            nodes.add(dst)
        if not is_broadcast_or_multicast(src) and not is_broadcast_or_multicast(dst):
            edges.append((src, dst, proto))

    # Layer classification - use configurable zones if available
    zone_labels = get_zone_labels()
    num_zones = len(zone_labels)

    def get_layer(ip: str) -> int:
        # Try configurable zones first
        zone = get_zone_for_ip(ip)
        if zone >= 0:
            return zone
        # Fallback to default logic
        if ip.startswith('127.'):
            return num_zones // 2  # middle
        parts = ip.split('.')
        if len(parts) == 4:
            try:
                third = int(parts[2])
                if third in [0, 1, 2]:
                    return 0
                elif third in [200, 254]:
                    return 1
                elif third in [4, 5]:
                    return min(3, num_zones - 1)
            except ValueError:
                pass
        if ip.startswith('172.'):
            return num_zones - 1
        return num_zones // 2  # default middle

    # Group nodes by layer
    layers = [[] for _ in range(num_zones)]
    for node in nodes:
        layer_idx = get_layer(node)
        if 0 <= layer_idx < num_zones:
            layers[layer_idx].append(node)
    for layer in layers:
        layer.sort()

    layer_labels = zone_labels
    col_width = max(20, 100 // num_zones)  # Dynamic column width
    max_nodes = max(len(l) for l in layers) if layers else 1

    # Build node position map: ip -> (layer, row)
    node_pos = {}
    for layer_idx, layer_nodes in enumerate(layers):
        for row, node in enumerate(layer_nodes):
            node_pos[node] = (layer_idx, row)

    # Create a 2D grid for the diagram
    # Each node takes 3 rows (label, ip, spacing)
    # Add extra rows between for connection routing
    row_height = 4  # rows per node slot
    # Calculate number of unique edges for sizing
    edge_set = set()
    for src, dst, proto in edges:
        edge_set.add((src, dst, proto))
    num_edges = len(edge_set)
    total_rows = max_nodes * row_height + num_edges + 15  # extra for routing
    total_cols = col_width * num_zones

    # Initialize grid with spaces
    grid = [[' ' for _ in range(total_cols)] for _ in range(total_rows)]
    color_grid = [[None for _ in range(total_cols)] for _ in range(total_rows)]

    def put_str(row, col, s, color=None):
        """Put a string on the grid."""
        for i, ch in enumerate(s):
            if 0 <= row < total_rows and 0 <= col + i < total_cols:
                grid[row][col + i] = ch
                if color:
                    color_grid[row][col + i] = color

    # Draw layer headers
    for i, label in enumerate(layer_labels):
        col_start = i * col_width
        centered = label.center(col_width)
        put_str(0, col_start, centered)

    put_str(1, 0, "─" * total_cols)

    # Draw nodes
    node_positions = {}  # ip -> (center_row, center_col)
    for layer_idx, layer_nodes in enumerate(layers):
        col_center = layer_idx * col_width + col_width // 2
        for row_idx, node in enumerate(layer_nodes):
            grid_row = 3 + row_idx * row_height
            label = get_host_label(node, labels, col_width - 6)

            # Draw box
            box_left = col_center - len(label) // 2 - 2
            put_str(grid_row, box_left, f"[{label}]")
            put_str(grid_row + 1, col_center - len(node) // 2, node)

            # Store center position for connections
            node_positions[node] = (grid_row, col_center)

    # Draw connections
    # Route connections using horizontal tracks at different levels below the nodes
    base_track_row = 3 + max_nodes * row_height + 1

    # Deduplicate edges and assign colors
    unique_edges = []
    seen = set()
    for src, dst, proto in edges:
        key = (src, dst, proto)
        if key not in seen:
            seen.add(key)
            unique_edges.append((src, dst, proto))

    for edge_idx, (src, dst, proto) in enumerate(unique_edges):
        color = COLORS[edge_idx % len(COLORS)]
        track_row = base_track_row + edge_idx

        if src not in node_positions or dst not in node_positions:
            continue

        src_row, src_col = node_positions[src]
        dst_row, dst_col = node_positions[dst]

        # Determine direction
        if src_col < dst_col:
            left_col, right_col = src_col, dst_col
            arrow_char = "▶"
            start_char = "○"
        elif src_col > dst_col:
            left_col, right_col = dst_col, src_col
            arrow_char = "◀"
            start_char = "○"
        else:
            # Same column - vertical connection
            if src_row < dst_row:
                for r in range(src_row + 2, dst_row):
                    put_str(r, src_col, "│", color)
                put_str(dst_row - 1, src_col, "▼", color)
            else:
                for r in range(dst_row + 2, src_row):
                    put_str(r, src_col, "│", color)
                put_str(src_row - 1, src_col, "▲", color)
            continue

        # Draw vertical line down from source (with down arrow at start)
        put_str(src_row + 2, src_col, "│", color)  # Start of line from source
        for r in range(src_row + 3, track_row):
            if grid[r][src_col] == ' ':
                put_str(r, src_col, "│", color)
            elif grid[r][src_col] == "─":
                put_str(r, src_col, "┼", color)

        # Draw corner at source
        if src_col == left_col:
            put_str(track_row, src_col, "└", color)
        else:
            put_str(track_row, src_col, "┘", color)

        # Draw horizontal line
        for c in range(left_col + 1, right_col):
            if grid[track_row][c] == ' ':
                put_str(track_row, c, "─", color)
            elif grid[track_row][c] == "│":
                put_str(track_row, c, "┼", color)

        # Draw corner at destination (line comes from track, goes UP to node)
        if dst_col == right_col:
            put_str(track_row, dst_col, "┘", color)  # from left, up
        else:
            put_str(track_row, dst_col, "└", color)  # from right, up

        # Draw vertical line up to destination (arrow pointing UP at destination)
        for r in range(dst_row + 3, track_row):
            if grid[r][dst_col] == ' ':
                put_str(r, dst_col, "│", color)
            elif grid[r][dst_col] == "─":
                put_str(r, dst_col, "┼", color)

        # Add UP arrow at destination (connection arrives from below)
        put_str(dst_row + 2, dst_col, "▲", color)

    # Convert grid to string with colors
    for row_idx in range(min(total_rows, base_track_row + len(unique_edges) + 2)):
        line = ""
        for col_idx in range(total_cols):
            ch = grid[row_idx][col_idx]
            color = color_grid[row_idx][col_idx]
            if color:
                line += color + ch + RESET
            else:
                line += ch
        lines.append(line.rstrip())

    lines.append("")
    lines.append("─" * 120)
    lines.append("")

    # Legend
    lines.append("LEGEND:")
    for edge_idx, (src, dst, proto) in enumerate(unique_edges):
        color = COLORS[edge_idx % len(COLORS)]
        src_label = get_host_label(src, labels, 14)
        dst_label = get_host_label(dst, labels, 14)
        lines.append(f"  {color}━━━{RESET} [{edge_idx+1:2d}] {src_label} ──({proto})──▶ {dst_label}")

    lines.append("")
    lines.append(f"Total: {len(unique_edges)} unique connections")

    return "\n".join(lines)


def render_graph_interactive(flows: list[dict], labels: dict[str, str]) -> None:
    """Interactive graph visualization - step through connections with forward/back navigation."""
    import tty
    import termios

    # Navigation keys
    KEY_QUIT = ('q', '\x03')  # q or Ctrl+C
    KEY_NEXT = ('n', ' ', '\x1b[C')  # n, space, right arrow
    KEY_PREV = ('p', '\x1b[D')  # p, left arrow
    KEY_FIRST = ('f', '\x1b[H')  # f, home
    KEY_LAST = ('l', '\x1b[F')  # l, end
    KEY_HELP = ('h', '?')  # h or ? for help
    KEY_SEARCH = ('/',)  # / to search/filter
    KEY_EXTERNAL = ('e',)  # e to filter external IPs
    KEY_CLEAR = ('\x1b',)  # Esc to clear filter

    def read_key():
        """Read a single keypress, handling escape sequences for arrows."""
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = sys.stdin.read(1)
            # Handle escape sequences (arrow keys)
            if ch == '\x1b':
                import select
                if select.select([sys.stdin], [], [], 0.05)[0]:
                    ch2 = sys.stdin.read(1)
                    ch3 = sys.stdin.read(1)
                    return ch + ch2 + ch3
                return '\x1b'  # bare Esc
            return ch
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    def read_line(prompt_str):
        """Read a line of input with echo, supporting backspace. Returns string or None on Esc."""
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        buf = []
        print(prompt_str, end="", flush=True)
        try:
            tty.setraw(fd)
            while True:
                ch = sys.stdin.read(1)
                if ch == '\r' or ch == '\n':
                    print("\r\n", end="", flush=True)
                    return "".join(buf)
                elif ch == '\x1b':
                    print("\r\n", end="", flush=True)
                    return None
                elif ch == '\x03':  # Ctrl+C
                    print("\r\n", end="", flush=True)
                    return None
                elif ch in ('\x7f', '\x08'):  # backspace
                    if buf:
                        buf.pop()
                        print("\b \b", end="", flush=True)
                else:
                    buf.append(ch)
                    print(ch, end="", flush=True)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    def match_edge(edge, pattern):
        """Check if any field in an edge matches the search pattern (fnmatch-style)."""
        from fnmatch import fnmatch
        pat = f"*{pattern}*" if '*' not in pattern and '?' not in pattern else pattern
        pat_lower = pat.lower()
        for field in edge:  # src, dst, proto, explanation, timestamp, source
            if fnmatch(str(field).lower(), pat_lower):
                return True
        return False

    def has_external_ip(edge):
        """Check if src or dst is a public IP address."""
        return _is_public_ip(edge[0]) or _is_public_ip(edge[1])

    def clear_screen():
        print("\033[2J\033[H", end="")  # Clear screen and move cursor to top

    # Collect all nodes and edges (with timestamps)
    nodes = set()
    edges = []
    show_time = has_timestamps(flows)
    for f in flows:
        src = f.get('src_ip', '?')
        dst = f.get('dst_ip', '?')
        proto = f.get('protocol', '?')
        explanation = f.get('explanation', '')
        source = f.get('evidence_source', '')
        timestamp = get_time_str(f, full=True) if show_time else ""
        if not is_broadcast_or_multicast(src):
            nodes.add(src)
        if not is_broadcast_or_multicast(dst):
            nodes.add(dst)
        if not is_broadcast_or_multicast(src) and not is_broadcast_or_multicast(dst):
            edges.append((src, dst, proto, explanation, timestamp, source))

    if not edges:
        print("No connections to display.")
        return

    # Classify nodes into layers - use configurable zones
    zone_labels = get_zone_labels()
    num_zones = len(zone_labels)

    def get_layer(ip: str) -> int:
        zone = get_zone_for_ip(ip)
        if zone >= 0:
            return zone
        if _is_public_ip(ip):
            return num_zones - 1  # EXTERNAL (last column)
        if ip.startswith('127.'):
            return num_zones // 2
        parts = ip.split('.')
        if len(parts) == 4:
            try:
                third = int(parts[2])
                if third in [0, 1, 2]:
                    return 0
                elif third in [200, 254]:
                    return 1
                elif third in [4, 5]:
                    return min(3, num_zones - 2)
            except ValueError:
                pass
        if ip.startswith('172.'):
            return num_zones - 2
        return num_zones // 2

    # Group nodes by layer
    layers = [[] for _ in range(num_zones)]
    for node in nodes:
        layer = get_layer(node)
        if 0 <= layer < num_zones:
            layers[layer].append(node)
    for layer in layers:
        layer.sort()

    layer_labels = zone_labels
    col_width = max(18, 90 // num_zones)
    max_nodes_per_layer = max(len(l) for l in layers) if layers else 1

    def render_frame(conn_idx, edges_list, search_pattern=""):
        """Render the graph with current connection highlighted and event table."""
        lines = []

        import shutil
        term_width = shutil.get_terminal_size((120, 40)).columns

        # Get current edge data
        if conn_idx >= 0 and conn_idx < len(edges_list):
            src, dst, proto, explanation, timestamp, source = edges_list[conn_idx]
            highlight_src, highlight_dst = src, dst
        else:
            highlight_src = highlight_dst = proto = explanation = timestamp = source = None

        # Header
        lines.append("=" * term_width)
        ts_display = f"  [{timestamp}]" if timestamp else ""
        nav_help = "[n]ext  [p]rev  [/]search  [e]xternal  [f]irst  [l]ast  [h]elp  [q]uit"
        lines.append(f"INTERACTIVE TIMELINE{ts_display}    Event {conn_idx + 1}/{len(edges_list)}    {nav_help}")
        if search_pattern:
            lines.append(f"\033[93mFILTER: \"{search_pattern}\" ({len(edges_list)} matching events)  [Esc] clear\033[0m")
        lines.append("=" * term_width)
        lines.append("")

        # Compute visible event window (same logic as table below)
        window_size = 15
        start_idx = max(0, conn_idx - window_size // 2)
        end_idx = min(len(edges_list), start_idx + window_size)
        if end_idx - start_idx < window_size:
            start_idx = max(0, end_idx - window_size)

        # Collect only hosts visible in the current window
        visible_nodes = set()
        for i in range(start_idx, end_idx):
            e_src, e_dst = edges_list[i][0], edges_list[i][1]
            visible_nodes.add(e_src)
            visible_nodes.add(e_dst)

        # Build layers from visible nodes only
        vis_layers = [[] for _ in range(num_zones)]
        for node in visible_nodes:
            layer = get_layer(node)
            if 0 <= layer < num_zones:
                vis_layers[layer].append(node)
        for layer in vis_layers:
            layer.sort()
        vis_max_rows = max((len(l) for l in vis_layers), default=1)

        # Network graph header
        header = ""
        for label in layer_labels:
            header += f"{label:^{col_width}}"
        lines.append(header)
        lines.append("─" * (col_width * num_zones))

        # Render nodes - only those in visible window
        for row in range(vis_max_rows):
            if not any(row < len(vis_layers[li]) for li in range(num_zones)):
                continue

            row_str = ""
            for layer_idx in range(num_zones):
                if row < len(vis_layers[layer_idx]):
                    node = vis_layers[layer_idx][row]
                    label = get_host_label(node, labels, col_width - 4)

                    if node == highlight_src:
                        row_str += f" \033[92m▶[{label:^{col_width-6}}]◀\033[0m "
                    elif node == highlight_dst:
                        row_str += f" \033[91m▶[{label:^{col_width-6}}]◀\033[0m "
                    else:
                        row_str += f"  [{label:^{col_width-6}}]  "
                else:
                    row_str += " " * col_width
            lines.append(row_str)

            # IP line - only show if any node has a label different from its IP
            has_label_diff = False
            for layer_idx in range(num_zones):
                if row < len(vis_layers[layer_idx]):
                    node = vis_layers[layer_idx][row]
                    node_label = get_host_label(node, labels, col_width - 4)
                    if node_label != node:
                        has_label_diff = True
                        break
            if has_label_diff:
                ip_str = ""
                for layer_idx in range(num_zones):
                    if row < len(vis_layers[layer_idx]):
                        node = vis_layers[layer_idx][row]
                        if node == highlight_src:
                            ip_str += f" \033[92m>{node:^{col_width-4}}<\033[0m "
                        elif node == highlight_dst:
                            ip_str += f" \033[91m>{node:^{col_width-4}}<\033[0m "
                        else:
                            ip_str += f"  {node:^{col_width-4}}  "
                    else:
                        ip_str += " " * col_width
                lines.append(ip_str)
            lines.append("")

        lines.append("─" * (col_width * num_zones))

        # Current connection details
        if highlight_src and highlight_dst:
            lines.append("")
            src_label = get_host_label(highlight_src, labels, 14)
            dst_label = get_host_label(highlight_dst, labels, 14)
            lines.append(f"  \033[1mCURRENT EVENT:\033[0m")
            lines.append(f"    \033[92m{src_label}\033[0m ({highlight_src})")
            lines.append(f"         │")
            lines.append(f"         │  \033[93m{proto}\033[0m")
            lines.append(f"         ▼")
            lines.append(f"    \033[91m{dst_label}\033[0m ({highlight_dst})")
            if explanation or source:
                lines.append(f"")
                if explanation:
                    lines.append(f"    \033[96m{explanation}\033[0m")
                if source:
                    lines.append(f"    \033[2mSource: {source}\033[0m")
            lines.append("")

        # Events table
        lines.append("─" * term_width)
        lines.append("  \033[1mEVENTS TIMELINE:\033[0m")
        lines.append("")

        # Check if any edge has evidence_source
        has_source = any(e[5] for e in edges_list if len(e) > 5)
        src_col_w = 16 if has_source else 0

        # Calculate description width from terminal width
        # Fixed columns: 2(indent) + 3(indicator) + 1 + 3(#) + 1 + 16(src) + 1 + 10(proto) + 1 + 16(dst) + 1 = 55
        # With timestamps: + 20(ts) + 1 = 76
        # With source: + src_col_w + 1
        fixed_cols = (76 if show_time else 55) + (src_col_w + 1 if has_source else 0)
        desc_width = max(20, term_width - fixed_cols)

        # Table header
        if show_time and has_source:
            lines.append(f"  {'':3} {'#':>3} {'TIMESTAMP':<20} {'SOURCE':<16} {'PROTOCOL':<10} {'DESTINATION':<16} {'EVIDENCE':<{src_col_w}} {'DESCRIPTION':<{desc_width}}")
        elif show_time:
            lines.append(f"  {'':3} {'#':>3} {'TIMESTAMP':<20} {'SOURCE':<16} {'PROTOCOL':<10} {'DESTINATION':<16} {'DESCRIPTION':<{desc_width}}")
        elif has_source:
            lines.append(f"  {'':3} {'#':>3} {'SOURCE':<16} {'PROTOCOL':<10} {'DESTINATION':<16} {'EVIDENCE':<{src_col_w}} {'DESCRIPTION':<{desc_width}}")
        else:
            lines.append(f"  {'':3} {'#':>3} {'SOURCE':<16} {'PROTOCOL':<10} {'DESTINATION':<16} {'DESCRIPTION':<{desc_width}}")
        lines.append("  " + "─" * (term_width - 2))

        # Show events with indicator for current
        # Show a window of events around current (to fit screen)
        window_size = 15
        start_idx = max(0, conn_idx - window_size // 2)
        end_idx = min(len(edges_list), start_idx + window_size)
        if end_idx - start_idx < window_size:
            start_idx = max(0, end_idx - window_size)

        if start_idx > 0:
            lines.append(f"  ... ({start_idx} earlier events)")

        for i in range(start_idx, end_idx):
            e_src, e_dst, e_proto, e_expl, e_ts = edges_list[i][:5]
            e_evidence = edges_list[i][5] if len(edges_list[i]) > 5 else ""
            e_src_label = get_host_label(e_src, labels, 14)
            e_dst_label = get_host_label(e_dst, labels, 14)
            max_expl = desc_width - 2
            e_expl_short = e_expl[:max_expl] + ".." if len(e_expl) > desc_width else e_expl
            e_ev_short = e_evidence[:src_col_w-2] + ".." if len(e_evidence) > src_col_w else e_evidence
            row_num = i + 1  # 1-based row number

            if has_source:
                cols = f"{row_num:>3} "
                cols += f"{e_ts:<20} " if show_time else ""
                cols += f"{e_src_label:<16} {e_proto:<10} {e_dst_label:<16} {e_ev_short:<{src_col_w}} {e_expl_short}"
            else:
                cols = f"{row_num:>3} "
                cols += f"{e_ts:<20} " if show_time else ""
                cols += f"{e_src_label:<16} {e_proto:<10} {e_dst_label:<16} {e_expl_short}"

            if i == conn_idx:
                indicator = "\033[1m▶▶\033[0m"
                line = f"  {indicator} \033[1;97m{cols}\033[0m"
            else:
                indicator = "  "
                line = f"  {indicator} \033[2m{cols}\033[0m"
            lines.append(line)

        if end_idx < len(edges_list):
            lines.append(f"  ... ({len(edges_list) - end_idx} more events)")

        lines.append("")
        return "\n".join(lines)

    def show_help():
        """Display help screen."""
        lines = []
        lines.append("")
        lines.append("=" * 60)
        lines.append("  INTERACTIVE TIMELINE - NAVIGATION HELP")
        lines.append("=" * 60)
        lines.append("")
        lines.append("  \033[1mKEY          ACTION\033[0m")
        lines.append("  ─────────────────────────────────────")
        lines.append("  \033[93mn\033[0m / Space    \033[1mN\033[0mext event (forward)")
        lines.append("  \033[93mp\033[0m / ←        \033[1mP\033[0mrevious event (back)")
        lines.append("  \033[93mf\033[0m / Home     \033[1mF\033[0mirst event (jump to start)")
        lines.append("  \033[93ml\033[0m / End      \033[1mL\033[0mast event (jump to end)")
        lines.append("  \033[93m/\033[0m            Search/filter events")
        lines.append("  \033[93me\033[0m            Filter: \033[1me\033[0mxternal IPs only")
        lines.append("  \033[93mEsc\033[0m          Clear search filter")
        lines.append("  \033[93mh\033[0m / ?        \033[1mH\033[0melp (this screen)")
        lines.append("  \033[93mq\033[0m / Ctrl+C   \033[1mQ\033[0muit")
        lines.append("")
        lines.append("  ─────────────────────────────────────")
        lines.append("  \033[2mArrow keys (← →) also work for prev/next\033[0m")
        lines.append("")
        lines.append("  \033[1mSEARCH:\033[0m")
        lines.append("  Type a pattern after pressing /")
        lines.append("  Matches IP, protocol, description")
        lines.append("  Supports wildcards: 192.168.24.1*")
        lines.append("  Press Esc to cancel or clear filter")
        lines.append("")
        lines.append("  \033[1mPress any key to continue...\033[0m")
        lines.append("")
        return "\n".join(lines)

    # Main navigation loop
    current_idx = 0
    active_edges = edges  # current view (all or filtered)
    search_pattern = ""
    while True:
        clear_screen()
        print(render_frame(current_idx, active_edges, search_pattern))

        key = read_key()

        if key in KEY_QUIT:
            break
        elif key in KEY_SEARCH:
            clear_screen()
            pattern = read_line("\033[93m/\033[0m Search: ")
            if pattern is not None and pattern.strip():
                filtered = [e for e in edges if match_edge(e, pattern.strip())]
                if filtered:
                    active_edges = filtered
                    search_pattern = pattern.strip()
                    current_idx = 0
                else:
                    # No matches — flash message then stay
                    search_pattern = ""
                    active_edges = edges
                    clear_screen()
                    print(f"\n  No events matching \"{pattern.strip()}\"\n  Press any key...")
                    read_key()
            elif pattern is not None and pattern.strip() == "":
                # Empty search clears filter
                search_pattern = ""
                active_edges = edges
                current_idx = 0
        elif key in KEY_EXTERNAL:
            filtered = [e for e in edges if has_external_ip(e)]
            if filtered:
                active_edges = filtered
                search_pattern = "external IPs"
                current_idx = 0
            else:
                clear_screen()
                print("\n  No events with external IPs\n  Press any key...")
                read_key()
        elif key in KEY_CLEAR:
            if search_pattern:
                search_pattern = ""
                active_edges = edges
                current_idx = 0
        elif key in KEY_HELP:
            clear_screen()
            print(show_help())
            read_key()  # Wait for any key
        elif key in KEY_NEXT or key == '\r' or key == '\n':
            if current_idx < len(active_edges) - 1:
                current_idx += 1
        elif key in KEY_PREV:
            if current_idx > 0:
                current_idx -= 1
        elif key in KEY_FIRST:
            current_idx = 0
        elif key in KEY_LAST:
            current_idx = len(active_edges) - 1

    # Final summary
    clear_screen()
    print("=" * 100)
    print("DONE - Interactive review complete")
    print("=" * 100)
    print(f"\nTotal events: {len(edges)}" + (f" (filtered to {len(active_edges)})" if search_pattern else ""))
    print("\nOther views: -v graph, -v chronological, -v wired")


def render_graph_ascii(flows: list[dict], labels: dict[str, str]) -> str:
    """Render flows as unified network graph with layered layout, chronologically if timestamps exist."""
    lines = []
    lines.append("=" * 110)
    lines.append("UNIFIED NETWORK GRAPH" + (" (CHRONOLOGICAL)" if has_timestamps(flows) else ""))
    lines.append("=" * 110)
    lines.append("")

    show_time = has_timestamps(flows)

    # Collect all nodes and edges (with timestamp)
    nodes = set()
    edges = []  # (src, dst, proto, time_str)
    for f in flows:
        src = f.get('src_ip', '?')
        dst = f.get('dst_ip', '?')
        proto = f.get('protocol', '?')
        time_str = get_time_str(f) if show_time else ""
        if not is_broadcast_or_multicast(src):
            nodes.add(src)
        if not is_broadcast_or_multicast(dst):
            nodes.add(dst)
        if not is_broadcast_or_multicast(src) and not is_broadcast_or_multicast(dst):
            edges.append((src, dst, proto, time_str))

    # Classify nodes into layers - use configurable zones
    zone_labels = get_zone_labels()
    num_zones = len(zone_labels)

    def get_layer(ip: str) -> int:
        """Assign layer based on network config or IP pattern."""
        zone = get_zone_for_ip(ip)
        if zone >= 0:
            return zone
        if _is_public_ip(ip):
            return num_zones - 1  # EXTERNAL (last column)
        if ip.startswith('127.'):
            return num_zones // 2
        parts = ip.split('.')
        if len(parts) == 4:
            try:
                third = int(parts[2])
                if third in [0, 1, 2]:
                    return 0
                elif third in [200, 254]:
                    return 1
                elif third in [4, 5]:
                    return min(3, num_zones - 2)
            except ValueError:
                pass
        if ip.startswith('172.'):
            return num_zones - 2
        return num_zones // 2

    # Group nodes by layer
    layers = [[] for _ in range(num_zones)]
    for node in nodes:
        layer = get_layer(node)
        if 0 <= layer < num_zones:
            layers[layer].append(node)

    # Sort nodes within each layer
    for layer in layers:
        layer.sort()

    # Calculate layout dimensions
    max_nodes_per_layer = max(len(l) for l in layers) if layers else 1
    layer_labels = zone_labels

    # Build node positions (layer, position within layer)
    node_pos = {}
    for layer_idx, layer_nodes in enumerate(layers):
        for pos, node in enumerate(layer_nodes):
            node_pos[node] = (layer_idx, pos)

    # Render each layer as a column
    col_width = max(18, 90 // num_zones)
    total_width = col_width * num_zones

    # Header
    header = ""
    for i, label in enumerate(layer_labels):
        header += f"{label:^{col_width}}"
    lines.append(header)
    lines.append("─" * total_width)

    # Render nodes row by row
    for row in range(max_nodes_per_layer):
        row_str = ""
        for layer_idx in range(num_zones):
            if row < len(layers[layer_idx]):
                node = layers[layer_idx][row]
                label = get_host_label(node, labels, col_width - 4)
                row_str += f"  [{label:^{col_width-6}}]  "
            else:
                row_str += " " * col_width
        lines.append(row_str)

        # Show IPs on next line
        ip_str = ""
        for layer_idx in range(num_zones):
            if row < len(layers[layer_idx]):
                node = layers[layer_idx][row]
                ip_str += f"  {node:^{col_width-4}}  "
            else:
                ip_str += " " * col_width
        lines.append(ip_str)
        lines.append("")

    lines.append("─" * total_width)
    lines.append("")

    # Show connections as list with visual grouping
    lines.append("CONNECTIONS:" + (" (in chronological order)" if show_time else ""))
    lines.append("")

    if show_time:
        # Show all connections in chronological order (already sorted)
        conn_num = 1
        for src, dst, proto, time_str in edges:
            src_label = get_host_label(src, labels, 14)
            dst_label = get_host_label(dst, labels, 14)
            time_prefix = f"[{time_str}] " if time_str else ""
            lines.append(f"    [{conn_num:2d}] {time_prefix}{src_label:<14} ──({proto:^8})──▶ {dst_label}")
            conn_num += 1
    else:
        # Group edges by source layer -> dest layer (original behavior)
        edge_groups = {}
        for src, dst, proto, _ in edges:
            src_layer = get_layer(src)
            dst_layer = get_layer(dst)
            key = (src_layer, dst_layer)
            if key not in edge_groups:
                edge_groups[key] = []
            edge_groups[key].append((src, dst, proto))

        conn_num = 1
        for (src_layer, dst_layer), group_edges in sorted(edge_groups.items()):
            direction = "→" if src_layer <= dst_layer else "←"
            lines.append(f"  {layer_labels[src_layer]} {direction} {layer_labels[dst_layer]}:")
            for src, dst, proto in group_edges:
                src_label = get_host_label(src, labels, 14)
                dst_label = get_host_label(dst, labels, 14)
                lines.append(f"    [{conn_num:2d}] {src_label:<14} ──({proto:^8})──▶ {dst_label}")
                conn_num += 1
            lines.append("")

    lines.append("")
    lines.append(f"Total: {conn_num - 1} connections")
    return "\n".join(lines)


def render_summary_ascii(flows: list[dict], labels: dict[str, str]) -> str:
    """Render a summary of key flows."""
    lines = []
    lines.append("=" * 80)
    lines.append("COMMUNICATION FLOW SUMMARY")
    lines.append("=" * 80)
    lines.append("")

    # Count protocols
    proto_counts = defaultdict(int)
    for f in flows:
        proto_counts[f.get('protocol', '?')] += 1

    lines.append("Protocols:")
    max_count = max(proto_counts.values()) if proto_counts else 1
    for proto, count in sorted(proto_counts.items(), key=lambda x: -x[1]):
        bar_len = int((count / max_count) * 40)
        bar = "█" * bar_len
        lines.append(f"  {proto:<10} {bar} ({count})")
    lines.append("")

    # Key hosts
    lines.append("Key Hosts:")
    hosts = defaultdict(lambda: {'in': 0, 'out': 0})
    for f in flows:
        src = get_src_id(f)
        dst = get_dst_id(f)
        if not is_broadcast_or_multicast(src):
            hosts[src]['out'] += 1
        if not is_broadcast_or_multicast(dst):
            hosts[dst]['in'] += 1

    max_total = max((h['in'] + h['out'] for h in hosts.values()), default=1)
    for id, counts in sorted(hosts.items(), key=lambda x: -(x[1]['in'] + x[1]['out'])):
        label = get_host_label(id, labels)
        in_count = counts['in']
        out_count = counts['out']
        in_bar = "◀" * min(in_count, 10)
        out_bar = "▶" * min(out_count, 10)
        lines.append(f"  {label:<14} {in_bar:>10} │ {out_bar:<10} (in:{in_count}, out:{out_count})")

    lines.append("")
    return "\n".join(lines)


def render_chronological_ascii(flows: list[dict], labels: dict[str, str]) -> str:
    """Render flows in chronological order - WHO did WHAT and WHEN."""
    lines = []
    lines.append("=" * 100)
    lines.append("CHRONOLOGICAL TIMELINE - WHO did WHAT and WHEN")
    lines.append("=" * 100)
    lines.append("")

    # Check if we have timestamps
    has_timestamps = any(f.get('timestamp_utc', '').strip() for f in flows)

    if not has_timestamps:
        lines.append(f"{WARN_COLOR}ERROR: No timestamps available! Cannot create chronological view.{RESET}")
        lines.append("")
        lines.append("Add 'timestamp_utc' column to your CSV with ISO format timestamps.")
        lines.append("Example: 2020-11-06T18:35:09")
        lines.append("")
        return "\n".join(lines)

    # Sort by timestamp (already done in load_flows, but ensure it)
    sorted_flows = sorted(flows, key=lambda x: x.get('timestamp_utc', '') or 'zzzz')

    # Header
    lines.append("┌" + "─" * 22 + "┬" + "─" * 74 + "┐")
    lines.append("│ {:^20} │ {:^72} │".format("TIMESTAMP (UTC)", "EVENT"))
    lines.append("├" + "─" * 22 + "┼" + "─" * 74 + "┤")

    prev_date = None
    for flow in sorted_flows:
        ts = flow.get('timestamp_utc', '').strip()
        if not ts:
            continue

        # Extract date for grouping
        current_date = ts[:10] if len(ts) >= 10 else ts

        # Add date separator if new day
        if current_date != prev_date:
            if prev_date is not None:
                lines.append("├" + "─" * 22 + "┼" + "─" * 74 + "┤")
            lines.append("│ {:^20} │ {:^72} │".format(f"── {current_date} ──", ""))
            lines.append("├" + "─" * 22 + "┼" + "─" * 74 + "┤")
            prev_date = current_date

        # Format the event
        src_id = get_src_id(flow)
        dst_id = get_dst_id(flow)
        dst_port = flow.get('dst_port', '')
        protocol = flow.get('protocol', '?')
        explanation = flow.get('explanation', '')

        src_label = get_host_label(src_id, labels, 12)
        dst_label = get_host_label(dst_id, labels, 12)

        port_str = f":{dst_port}" if dst_port and dst_port not in ['-', '0', '*', ''] else ""

        # Time only (after T)
        time_str = ts[11:19] if len(ts) >= 19 else ts

        # Build event string
        event = f"{src_label} ──({protocol})──▶ {dst_label}{port_str}"
        if len(event) > 72:
            event = event[:69] + "..."

        lines.append("│ {:^20} │ {:<72} │".format(time_str, event))

        # Add explanation on next line if present
        if explanation:
            expl_str = f"    └─ {explanation}"
            if len(expl_str) > 72:
                expl_str = expl_str[:69] + "..."
            lines.append("│ {:^20} │ {:<72} │".format("", expl_str))

    lines.append("└" + "─" * 22 + "┴" + "─" * 74 + "┘")
    lines.append("")

    # Summary
    timestamps = [f.get('timestamp_utc', '') for f in sorted_flows if f.get('timestamp_utc', '').strip()]
    if timestamps:
        lines.append(f"Timeline span: {min(timestamps)} → {max(timestamps)}")
        lines.append(f"Total events: {len(timestamps)}")

    lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="ASCII Network Flow Visualization",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s flows.csv                      # Visualize all flows
  %(prog)s flows.csv -v sankey            # Just sankey view
  %(prog)s flows.csv -l labels.yaml       # Use custom labels
  %(prog)s flows.csv -v chronological     # Timeline sorted by timestamp

CSV Format (timestamp_utc is CRITICAL for forensic investigations!):
  timestamp_utc,src_ip,src_port,dst_ip,dst_port,protocol,process_account,explanation,evidence_source

  timestamp_utc: ISO format (2020-11-06T18:35:09) - establishes WHO did WHAT and WHEN

Labels YAML Format:
  10.10.2.10: stsupport10
  10.10.200.207: LARIAT-C2
        """
    )
    parser.add_argument("csv_file", help="CSV file with communication flows")
    parser.add_argument("--labels", "-l", metavar="FILE",
                        help="YAML file with IP->label mappings")
    parser.add_argument("--network", "-n", metavar="FILE",
                        help="YAML file with network zone configuration")
    parser.add_argument("--view", "-v", choices=["sankey", "matrix", "timeline", "summary", "graph", "wired", "interactive", "chronological", "all"],
                        default="all", help="Visualization type (default: all)")
    parser.add_argument("--list-views", action="store_true",
                        help="List available views and exit")
    parser.add_argument("--no-timestamp-warning", action="store_true",
                        help="Suppress timestamp warning (not recommended)")
    args = parser.parse_args()

    if args.list_views:
        print("Available views:")
        print("  sankey       - Tree-style flow diagram from each source")
        print("  matrix       - Connection matrix showing all pairs")
        print("  timeline     - Flows grouped by evidence source")
        print("  chronological- Flows sorted by timestamp (REQUIRES timestamp_utc)")
        print("  summary      - Protocol and host statistics")
        print("  graph        - Unified network graph with layered layout")
        print("  wired        - Graph with all connections drawn as colored lines")
        print("  interactive  - Step through connections one by one")
        print("  all          - All views except interactive/wired (default)")
        return

    csv_path = Path(args.csv_file)
    if not csv_path.exists():
        print(f"Error: CSV file not found: {csv_path}", file=sys.stderr)
        sys.exit(1)

    flows = load_flows(csv_path)

    if not flows:
        print("Error: No flows found in CSV file", file=sys.stderr)
        sys.exit(1)

    # Check for timestamps - critical for forensic investigations
    if not args.no_timestamp_warning:
        check_timestamps(flows)

    # Build labels: start with data-derived labels, then overlay file labels
    labels = build_labels_from_data(flows)

    if args.labels:
        labels_path = Path(args.labels)
        file_labels = load_labels(labels_path)
        labels.update(file_labels)  # File labels override data-derived

    # Load network zone configuration if provided
    if args.network:
        network_path = Path(args.network)
        config = load_network_config(network_path)
        # Also extract labels from network config
        if config and 'labels' in config:
            for k, v in config['labels'].items():
                if str(k) not in labels:
                    labels[str(k)] = str(v)

    if args.view == "sankey" or args.view == "all":
        print(render_sankey_ascii(flows, labels))

    if args.view == "matrix" or args.view == "all":
        print(render_matrix_ascii(flows, labels))

    if args.view == "timeline" or args.view == "all":
        print(render_timeline_ascii(flows, labels))

    if args.view == "summary" or args.view == "all":
        print(render_summary_ascii(flows, labels))

    if args.view == "graph" or args.view == "all":
        print(render_graph_ascii(flows, labels))

    if args.view == "chronological" or args.view == "all":
        print(render_chronological_ascii(flows, labels))

    if args.view == "wired":
        print(render_graph_wired(flows, labels))

    if args.view == "interactive":
        render_graph_interactive(flows, labels)


if __name__ == "__main__":
    main()
