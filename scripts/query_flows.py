#!/usr/bin/env python3
"""Query network flows extracted from PCAPs.

Usage:
    query_flows.py                      # Show summary (Tier 2)
    query_flows.py ip 42.157.192.132    # Find flows for IP
    query_flows.py port 21              # Find flows on port
    query_flows.py port 41100 --hex     # Show hex dump of first packet
    query_flows.py external             # Show external IPs with WHOIS
    query_flows.py top-ips 20           # Top 20 IPs by frames
    query_flows.py top-ports 20         # Top 20 ports by frames
    query_flows.py --tier t1 summary    # Query Tier 1 flows
"""

import argparse
import re
import csv
import os
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

# Import tier helpers from forensic_analysis framework
try:
    from forensic_analysis.base import get_extractions_path, get_available_tiers
except ImportError:
    # Fallback if not in PYTHONPATH
    sys.path.insert(0, str(Path(__file__).parent))
    from forensic_analysis.base import get_extractions_path, get_available_tiers


def get_flows_file(level: str) -> Path:
    """Get the flows CSV file path for a level."""
    return get_extractions_path(level, 'network') / f'{level}-flows.csv'

# Well-known port to protocol mapping
# WHOIS cache to avoid repeated lookups
WHOIS_CACHE = {}

def whois_lookup(ip):
    """Perform WHOIS lookup and extract org/country info."""
    if ip in WHOIS_CACHE:
        return WHOIS_CACHE[ip]

    try:
        result = subprocess.run(['whois', ip], capture_output=True, text=True, timeout=10)
        output = result.stdout.lower()

        org = country = ''
        for line in result.stdout.split('\n'):
            line_lower = line.lower()
            if not org and ('orgname:' in line_lower or 'org-name:' in line_lower or 'organization:' in line_lower):
                org = line.split(':', 1)[1].strip()[:40]
            elif not org and 'netname:' in line_lower:
                org = line.split(':', 1)[1].strip()[:40]
            elif not country and 'country:' in line_lower:
                country = line.split(':', 1)[1].strip()[:2].upper()

        WHOIS_CACHE[ip] = (org or 'Unknown', country or '??')
    except (subprocess.TimeoutExpired, Exception):
        WHOIS_CACHE[ip] = ('Lookup failed', '??')

    return WHOIS_CACHE[ip]

PORT_PROTOCOLS = {
    '20': 'FTP-DATA',
    '21': 'FTP',
    '22': 'SSH',
    '23': 'TELNET',
    '25': 'SMTP',
    '53': 'DNS',
    '80': 'HTTP',
    '110': 'POP3',
    '123': 'NTP',
    '135': 'RPC',
    '137': 'NETBIOS',
    '138': 'NETBIOS',
    '139': 'NETBIOS',
    '143': 'IMAP',
    '161': 'SNMP',
    '443': 'HTTPS',
    '445': 'SMB',
    '465': 'SMTPS',
    '514': 'SYSLOG',
    '587': 'SMTP',
    '993': 'IMAPS',
    '995': 'POP3S',
    '1194': 'OPENVPN',
    '1195': 'OPENVPN',
    '1433': 'MSSQL',
    '1521': 'ORACLE',
    '3306': 'MYSQL',
    '3389': 'RDP',
    '5432': 'POSTGRES',
    '5900': 'VNC',
    '5985': 'WINRM',
    '5986': 'WINRM-S',
    '8080': 'HTTP-ALT',
    '8443': 'HTTPS-ALT',
    '44818': 'ENIP/CIP',  # EtherNet/IP - industrial protocol
    '502': 'MODBUS',
    '102': 'S7COMM',  # Siemens S7
    '2222': 'ENIP-CIP',  # EtherNet/IP implicit
    '1962': 'PCCC',  # Allen-Bradley PCCC (PLC programming)
    '41100': 'AB-DATA',  # Allen-Bradley data channel (seen with PCCC)
}

def get_port_protocol(port):
    """Get well-known protocol name for a port."""
    return PORT_PROTOCOLS.get(str(port), '')

def is_private_ip(ip):
    """Check if IP is private/multicast."""
    return ip.startswith(('192.168.', '10.', '172.16.', '172.17.', '172.18.',
                          '172.19.', '172.2', '172.30.', '172.31.',
                          '224.', '239.', 'fe80', 'ff0'))

def _normalize_row(row):
    """Normalize column names from different extraction formats."""
    # Map alternate column names to canonical names
    aliases = {
        'source_artifact': 'capture',
        'protocol': 'proto',
        'frame_count': 'frames',
        'total_bytes': 'bytes',
        'first_seen': 'timestamp_utc',
    }
    for alt, canonical in aliases.items():
        if alt in row and canonical not in row:
            row[canonical] = row[alt]
    # Ensure all expected columns have defaults
    for col in ('capture', 'proto', 'src_mac', 'dst_mac', 'src_ip', 'dst_ip',
                'src_port', 'dst_port', 'frames', 'bytes', 'timestamp_utc'):
        row.setdefault(col, '')
    # Convert unix timestamp to ISO if needed (e.g. 1604355329.671124)
    ts = row.get('timestamp_utc', '')
    if ts and '.' in ts and ts.replace('.', '').replace('-', '').isdigit():
        try:
            from datetime import datetime, timezone
            dt = datetime.fromtimestamp(float(ts), tz=timezone.utc)
            row['timestamp_utc'] = dt.strftime('%Y-%m-%dT%H:%M:%S')
        except (ValueError, OSError):
            pass
    return row


def load_flows(flows_file):
    """Load flows from CSV."""
    flows = []
    with open(flows_file) as f:
        reader = csv.DictReader(f)
        for row in reader:
            row = _normalize_row(row)
            row['frames'] = int(row['frames'].replace(',', '')) if row['frames'].replace(',', '').isdigit() else 0
            # Parse bytes (handle kB, MB suffixes)
            bytes_str = row['bytes'].strip()
            try:
                if bytes_str.endswith('kB'):
                    row['bytes_num'] = int(float(bytes_str[:-2].strip()) * 1024)
                elif bytes_str.endswith('MB'):
                    row['bytes_num'] = int(float(bytes_str[:-2].strip()) * 1024 * 1024)
                elif bytes_str.endswith('bytes'):
                    row['bytes_num'] = int(bytes_str.replace('bytes', '').replace(',', '').strip() or 0)
                elif bytes_str.replace(',', '').isdigit():
                    row['bytes_num'] = int(bytes_str.replace(',', ''))
                else:
                    row['bytes_num'] = 0
            except (ValueError, AttributeError):
                row['bytes_num'] = 0
            flows.append(row)
    return flows

def print_flows(flows, limit=None, show_service=False):
    """Print flows in table format."""
    if show_service:
        print(f"{'timestamp':<20} {'proto':<5} {'src_ip':<18} {'src_port':<8} {'dst_ip':<18} {'dst_port':<8} {'frames':>8} {'bytes':>12} {'service':<10}")
        print("-" * 130)
    else:
        print(f"{'timestamp':<20} {'proto':<5} {'src_ip':<18} {'src_port':<8} {'dst_ip':<18} {'dst_port':<8} {'frames':>8} {'bytes':>12}")
        print("-" * 115)
    for i, f in enumerate(flows):
        if limit and i >= limit:
            print(f"... and {len(flows) - limit} more")
            break
        ts = f.get('timestamp_utc', '')[:19]  # Trim to YYYY-MM-DDTHH:MM:SS
        if show_service:
            # Check both src and dst ports for service
            service = get_port_protocol(f['dst_port']) or get_port_protocol(f['src_port']) or ''
            print(f"{ts:<20} {f['proto']:<5} {f['src_ip']:<18} {f['src_port']:<8} {f['dst_ip']:<18} {f['dst_port']:<8} {f['frames']:>8} {f['bytes']:>12} {service:<10}")
        else:
            print(f"{ts:<20} {f['proto']:<5} {f['src_ip']:<18} {f['src_port']:<8} {f['dst_ip']:<18} {f['dst_port']:<8} {f['frames']:>8} {f['bytes']:>12}")

def cmd_summary(flows):
    """Show summary statistics."""
    print(f"Total flows: {len(flows)}")
    print(f"Total frames: {sum(f['frames'] for f in flows):,}")
    print(f"Total bytes: {sum(f['bytes_num'] for f in flows):,}")

    # By protocol
    by_proto = defaultdict(int)
    for f in flows:
        by_proto[f['proto']] += f['frames']
    print("\nBy protocol:")
    for proto, frames in sorted(by_proto.items(), key=lambda x: x[1], reverse=True):
        print(f"  {proto}: {frames:,} frames")

    # By capture
    by_capture = defaultdict(int)
    for f in flows:
        by_capture[f['capture']] += f['frames']
    print("\nBy capture:")
    for cap, frames in sorted(by_capture.items()):
        print(f"  {cap}: {frames:,} frames")

def ip_matches(ip, pattern):
    """Check if IP matches pattern. Supports:
    - Exact match: 192.168.24.2
    - Wildcards: 192.168.24.x or 192.168.24.*
    - Substring: 192.168.24 or 168.24
    - Regex: any pattern containing backslash or regex metacharacters
    """
    if '\\' in pattern or any(c in pattern for c in '[]()+?{}|^$'):
        # Regex match
        return bool(re.fullmatch(pattern, ip))
    elif 'x' in pattern or '*' in pattern:
        # Convert pattern to prefix match (192.168.24.x -> 192.168.24.)
        prefix = pattern.replace('x', '').replace('*', '').rstrip('.')
        return ip.startswith(prefix + '.')
    else:
        # Exact or substring match
        return pattern in ip

def cmd_ip(flows, ip):
    """Find flows involving an IP (supports wildcards like 192.168.24.x)."""
    matches = [f for f in flows if ip_matches(f['src_ip'], ip) or ip_matches(f['dst_ip'], ip)]
    print(f"Flows involving {ip}: {len(matches)}")
    print_flows(matches)

def get_pcap_path(capture_name, tier):
    """Get the path to a PCAP file based on capture name and tier."""
    artifacts_path = os.environ.get('ARTIFACTS_PATH', str(PROJECT_ROOT / 'artifacts'))

    # Add .pcap extension if not present
    if not capture_name.endswith('.pcap'):
        capture_name = capture_name + '.pcap'

    if tier == 't2':
        return Path(artifacts_path) / 'Tier_2_Artifacts' / capture_name
    elif tier == 't1':
        t1_path = Path(artifacts_path) / 'Tier_1_Artifacts'
        # Search for the capture file
        for p in t1_path.rglob(capture_name):
            return p
    elif tier == 't3':
        return Path(artifacts_path) / 'Tier_3_Artifacts' / capture_name
    return None


def show_hex_dump(flow, num_bytes=256, tier='t2', flow_num=1, total_flows=1):
    """Show hex dump of first packet with payload in a flow using tshark."""
    capture = flow.get('capture', '')
    if not capture:
        print("Error: No capture file specified in flow")
        return

    pcap_path = get_pcap_path(capture, tier)
    if not pcap_path or not pcap_path.exists():
        print(f"Error: PCAP file not found: {capture}")
        return

    # Build filter to match this specific flow
    src_ip = flow['src_ip']
    dst_ip = flow['dst_ip']
    src_port = flow['src_port']
    dst_port = flow['dst_port']

    # Determine protocol and build appropriate filter
    proto = flow.get('proto', 'TCP').upper()

    if proto == 'UDP':
        # Filter for UDP packets in this flow with payload
        filter_str = f"ip.src=={src_ip} && ip.dst=={dst_ip} && udp.srcport=={src_port} && udp.dstport=={dst_port} && udp.payload"
    else:
        # Filter for TCP packets in this flow with payload (include src port for uniqueness)
        filter_str = f"ip.addr=={src_ip} && ip.addr=={dst_ip} && tcp.port=={src_port} && tcp.port=={dst_port} && tcp.payload"

    print("=" * 70)
    print(f"HEX DUMP [{flow_num}/{total_flows}]: First packet with payload")
    print(f"  Flow: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
    print(f"  PCAP: {pcap_path.name}")
    print("=" * 70)

    # Use tshark to get first packet with payload as hex
    # Note: -2 -R is required for payload filter to work
    if proto == 'UDP':
        cmd = [
            'tshark', '-r', str(pcap_path),
            '-2', '-R', filter_str,
            '-c', '1',  # Get first packet with payload
            '-T', 'fields',
            '-e', 'frame.number',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'udp.srcport',
            '-e', 'udp.dstport',
            '-e', 'udp.payload'  # UDP payload (works for dissected protocols like ENIP)
        ]
    else:
        cmd = [
            'tshark', '-r', str(pcap_path),
            '-2', '-R', filter_str,
            '-c', '1',  # Get first packet with payload
            '-T', 'fields',
            '-e', 'frame.number',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'tcp.srcport',
            '-e', 'tcp.dstport',
            '-e', 'tcp.payload'
        ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            print(f"tshark error: {result.stderr}")
            return

        lines = result.stdout.strip().split('\n')
        if not lines or not lines[0]:
            print(f"No packets with {proto} payload found in this flow")
            return

        for line in lines:
            parts = line.split('\t')
            if len(parts) >= 6 and parts[5]:
                frame_num = parts[0]
                pkt_src = parts[1]
                pkt_dst = parts[2]
                pkt_sport = parts[3]
                pkt_dport = parts[4]
                hex_payload = parts[5].replace(':', '')

                # Truncate to requested bytes
                hex_payload = hex_payload[:num_bytes * 2]

                print(f"\nFrame {frame_num} ({proto}): {pkt_src}:{pkt_sport} -> {pkt_dst}:{pkt_dport}")
                print(f"Payload: {len(hex_payload)//2} bytes")
                print()

                # Format hex dump with ASCII
                hex_dump_formatted(bytes.fromhex(hex_payload))
                return

        print(f"No packets with {proto} payload found in this flow")

    except subprocess.TimeoutExpired:
        print("tshark timeout - try a more specific filter")
    except Exception as e:
        print(f"Error: {e}")


def hex_dump_formatted(data, bytes_per_line=16):
    """Format data as hex dump with ASCII representation."""
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i + bytes_per_line]
        # Hex portion
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        hex_part = hex_part.ljust(bytes_per_line * 3 - 1)

        # ASCII portion (printable chars or '.')
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)

        print(f"{i:08x}  {hex_part}  |{ascii_part}|")


def cmd_port(flows, port, hex_dump=False, hex_bytes=256, tier='t2'):
    """Find flows on a port."""
    matches = [f for f in flows if f['src_port'] == port or f['dst_port'] == port]
    print(f"Flows on port {port}: {len(matches)}")
    print_flows(matches)

    if hex_dump and matches:
        print()
        # Show hex dump for ALL flows, not just the first one
        for i, flow in enumerate(matches):
            show_hex_dump(flow, hex_bytes, tier, flow_num=i+1, total_flows=len(matches))

def cmd_external(flows):
    """Show flows with external IPs."""
    matches = []
    external_ips = {}  # ip -> {frames, bytes, services}

    for f in flows:
        src_ext = not is_private_ip(f['src_ip'])
        dst_ext = not is_private_ip(f['dst_ip'])
        if src_ext or dst_ext:
            matches.append(f)
            # Track external IPs
            for ip, port in [(f['src_ip'], f['src_port']), (f['dst_ip'], f['dst_port'])]:
                if not is_private_ip(ip):
                    if ip not in external_ips:
                        external_ips[ip] = {'frames': 0, 'bytes': 0, 'services': set()}
                    external_ips[ip]['frames'] += f['frames']
                    external_ips[ip]['bytes'] += f['bytes_num']
                    svc = get_port_protocol(port)
                    if svc:
                        external_ips[ip]['services'].add(svc)

    # Show external IP summary with WHOIS
    print("=" * 100)
    print("EXTERNAL IP SUMMARY (with WHOIS)")
    print("=" * 100)
    print(f"{'IP':<18} {'Frames':>10} {'Bytes':>12} {'Country':<4} {'Organization':<35} {'Services'}")
    print("-" * 100)

    # Sort by frames descending
    for ip, stats in sorted(external_ips.items(), key=lambda x: x[1]['frames'], reverse=True):
        org, country = whois_lookup(ip)
        services = ', '.join(sorted(stats['services'])) if stats['services'] else '-'
        bytes_str = f"{stats['bytes']:,}"
        print(f"{ip:<18} {stats['frames']:>10,} {bytes_str:>12} {country:<4} {org:<35} {services}")

    print()
    print(f"Flows with external IPs: {len(matches)}")
    # Sort by frames
    matches.sort(key=lambda x: x['frames'], reverse=True)
    print_flows(matches, limit=50, show_service=True)

def cmd_top_ips(flows, n):
    """Show top N IPs by total frames."""
    ip_stats = defaultdict(lambda: {'frames': 0, 'bytes': 0, 'flows': 0})

    for f in flows:
        for ip in [f['src_ip'], f['dst_ip']]:
            ip_stats[ip]['frames'] += f['frames']
            ip_stats[ip]['bytes'] += f['bytes_num']
            ip_stats[ip]['flows'] += 1

    print(f"Top {n} IPs by frames:")
    print(f"{'IP':<20} {'Frames':>12} {'Bytes':>14} {'Flows':>8}")
    print("-" * 60)

    for ip, stats in sorted(ip_stats.items(), key=lambda x: x[1]['frames'], reverse=True)[:n]:
        print(f"{ip:<20} {stats['frames']:>12,} {stats['bytes']:>14,} {stats['flows']:>8,}")

def cmd_top_ports(flows, n):
    """Show top N ports by total frames."""
    # Key is (port, proto) tuple to separate TCP/UDP on same port
    port_stats = defaultdict(lambda: {'frames': 0, 'bytes': 0, 'flows': 0})

    for f in flows:
        proto = f.get('proto', 'TCP')
        for port in [f['src_port'], f['dst_port']]:
            if port:  # Skip empty ports
                key = (port, proto)
                port_stats[key]['frames'] += f['frames']
                port_stats[key]['bytes'] += f['bytes_num']
                port_stats[key]['flows'] += 1

    print(f"Top {n} ports by frames:")
    print(f"{'Port':<8} {'Proto':<6} {'Service':<12} {'Frames':>12} {'Bytes':>14} {'Flows':>8}")
    print("-" * 68)

    for (port, proto), stats in sorted(port_stats.items(), key=lambda x: x[1]['frames'], reverse=True)[:n]:
        service = get_port_protocol(port) or '-'
        print(f"{port:<8} {proto:<6} {service:<12} {stats['frames']:>12,} {stats['bytes']:>14,} {stats['flows']:>8,}")


def cmd_beacon(flows):
    """Detect potential beacon patterns in flows.

    Beacons are characterized by:
    - Regular connection intervals (low jitter)
    - Same destination IP:port
    - Consistent packet sizes
    - Long duration activity
    """
    from datetime import datetime
    import statistics

    # Group flows by (src_ip, dst_ip, dst_port)
    flow_groups = defaultdict(list)
    for f in flows:
        if f.get('timestamp_utc'):
            key = (f['src_ip'], f['dst_ip'], f['dst_port'])
            try:
                ts = datetime.fromisoformat(f['timestamp_utc'])
                flow_groups[key].append({
                    'timestamp': ts,
                    'frames': f['frames'],
                    'bytes': f['bytes_num']
                })
            except ValueError:
                continue

    print("=" * 90)
    print("BEACON DETECTION ANALYSIS")
    print("=" * 90)
    print()

    # Known suspicious ports
    suspicious_ports = {'4444', '8443', '8080', '443', '80', '53', '8888', '9999'}

    beacons = []

    for (src, dst, port), connections in flow_groups.items():
        if len(connections) < 4:  # Need at least 4 connections to detect pattern
            continue

        # Sort by timestamp
        connections.sort(key=lambda x: x['timestamp'])

        # Calculate inter-arrival times (in seconds)
        intervals = []
        for i in range(1, len(connections)):
            delta = (connections[i]['timestamp'] - connections[i-1]['timestamp']).total_seconds()
            if delta > 0:  # Skip same-second connections
                intervals.append(delta)

        if len(intervals) < 3:
            continue

        # Calculate statistics
        try:
            mean_interval = statistics.mean(intervals)
            if mean_interval < 5:  # Skip very fast connections (not beacons)
                continue

            stdev_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0
            jitter_pct = (stdev_interval / mean_interval * 100) if mean_interval > 0 else 100

            # Calculate duration
            duration_sec = (connections[-1]['timestamp'] - connections[0]['timestamp']).total_seconds()
            duration_min = duration_sec / 60

            # Calculate byte statistics
            byte_counts = [c['bytes'] for c in connections]
            mean_bytes = statistics.mean(byte_counts)
            stdev_bytes = statistics.stdev(byte_counts) if len(byte_counts) > 1 else 0
            byte_consistency = (1 - stdev_bytes / mean_bytes) * 100 if mean_bytes > 0 else 0

            # Score the beacon likelihood
            score = 0

            # Low jitter (regular interval) - most important
            if jitter_pct < 10:
                score += 4
            elif jitter_pct < 20:
                score += 3
            elif jitter_pct < 35:
                score += 2
            elif jitter_pct < 50:
                score += 1

            # Many connections
            if len(connections) >= 20:
                score += 2
            elif len(connections) >= 10:
                score += 1

            # Long duration
            if duration_min >= 60:
                score += 2
            elif duration_min >= 30:
                score += 1

            # Consistent packet size
            if byte_consistency > 80:
                score += 1

            # Suspicious port
            if port in suspicious_ports:
                score += 1

            # External destination
            if not dst.startswith(('192.168.', '10.', '172.')):
                score += 1

            # Only report if score is significant
            if score >= 3:
                beacons.append({
                    'src': src,
                    'dst': dst,
                    'port': port,
                    'connections': len(connections),
                    'mean_interval': mean_interval,
                    'jitter_pct': jitter_pct,
                    'duration_min': duration_min,
                    'mean_bytes': mean_bytes,
                    'score': score
                })

        except (statistics.StatisticsError, ZeroDivisionError):
            continue

    # Sort by score
    beacons.sort(key=lambda x: x['score'], reverse=True)

    if not beacons:
        print("No significant beacon patterns detected.")
        print("\nCriteria: 4+ connections, interval >5s, score >= 3")
        return

    print(f"Potential beacons detected: {len(beacons)}")
    print()

    # Categorize by severity
    high = [b for b in beacons if b['score'] >= 6]
    medium = [b for b in beacons if 4 <= b['score'] < 6]
    low = [b for b in beacons if b['score'] < 4]

    for severity, beacon_list, marker in [('HIGH', high, '[!]'), ('MEDIUM', medium, '[*]'), ('LOW', low, '[-]')]:
        if not beacon_list:
            continue

        print(f"\n{marker} {severity} LIKELIHOOD ({len(beacon_list)})")
        print("-" * 85)

        for b in beacon_list[:10]:  # Limit to top 10 per category
            service = get_port_protocol(b['port']) or ''
            print(f"\n  {b['src']} -> {b['dst']}:{b['port']} {service}")
            print(f"    Connections: {b['connections']}")
            print(f"    Interval:    {b['mean_interval']:.1f}s (+/-{b['jitter_pct']:.1f}% jitter)")
            print(f"    Duration:    {b['duration_min']:.1f} min")
            print(f"    Avg bytes:   {b['mean_bytes']:,.0f}")
            print(f"    Score:       {b['score']}/10")

    # Summary table
    print("\n" + "=" * 90)
    print("BEACON SUMMARY TABLE")
    print("=" * 90)
    print(f"{'Src IP':<18} {'Dst IP':<18} {'Port':<8} {'Conns':>6} {'Interval':>10} {'Jitter':>8} {'Score':>6}")
    print("-" * 80)

    for b in beacons[:30]:
        interval_str = f"{b['mean_interval']:.0f}s"
        jitter_str = f"{b['jitter_pct']:.0f}%"
        print(f"{b['src']:<18} {b['dst']:<18} {b['port']:<8} {b['connections']:>6} {interval_str:>10} {jitter_str:>8} {b['score']:>6}")


def cmd_mac_ip(flows):
    """Show IPs seen per MAC address."""
    # Collect IPs per MAC
    mac_ips = defaultdict(lambda: {'ips': set(), 'frames': 0, 'bytes': 0})

    for f in flows:
        src_mac = f.get('src_mac', '')
        dst_mac = f.get('dst_mac', '')
        src_ip = f.get('src_ip', '')
        dst_ip = f.get('dst_ip', '')

        if src_mac:
            mac_ips[src_mac]['ips'].add(src_ip)
            mac_ips[src_mac]['frames'] += f['frames']
            mac_ips[src_mac]['bytes'] += f['bytes_num']

        if dst_mac:
            mac_ips[dst_mac]['ips'].add(dst_ip)
            mac_ips[dst_mac]['frames'] += f['frames']
            mac_ips[dst_mac]['bytes'] += f['bytes_num']

    # Filter out empty MACs
    mac_ips = {k: v for k, v in mac_ips.items() if k}

    print(f"MAC addresses with associated IPs: {len(mac_ips)}")
    print()

    # Sort by frame count descending
    print(f"{'MAC Address':<20} {'IPs':>4} {'Frames':>12} {'Bytes':>14} IP Addresses")
    print("-" * 100)

    for mac, data in sorted(mac_ips.items(), key=lambda x: x[1]['frames'], reverse=True):
        ips_sorted = sorted(data['ips'])
        ips_str = ', '.join(ips_sorted[:5])
        if len(ips_sorted) > 5:
            ips_str += f' (+{len(ips_sorted) - 5} more)'
        print(f"{mac:<20} {len(data['ips']):>4} {data['frames']:>12,} {data['bytes']:>14,} {ips_str}")

    # Show MACs with multiple IPs (potential DHCP, NAT, or spoofing)
    multi_ip_macs = {k: v for k, v in mac_ips.items() if len(v['ips']) > 1}
    if multi_ip_macs:
        print()
        print("=" * 100)
        print("MACs WITH MULTIPLE IPs (may indicate DHCP, NAT, or spoofing)")
        print("=" * 100)
        for mac, data in sorted(multi_ip_macs.items(), key=lambda x: len(x[1]['ips']), reverse=True):
            print(f"\n  {mac}")
            for ip in sorted(data['ips']):
                print(f"    - {ip}")


def cmd_mac_correlate():
    """Correlate MAC addresses across artifact tiers."""
    # Collect MACs per tier
    level_macs = {}

    for level in get_available_tiers():
        flows_file = get_flows_file(level)
        if not flows_file.exists():
            continue

        flows = load_flows(flows_file)
        mac_data = defaultdict(lambda: {'ips': set(), 'frames': 0, 'bytes': 0})

        for f in flows:
            src_mac = f.get('src_mac', '')
            dst_mac = f.get('dst_mac', '')

            if src_mac:
                mac_data[src_mac]['ips'].add(f.get('src_ip', ''))
                mac_data[src_mac]['frames'] += f['frames']
                mac_data[src_mac]['bytes'] += f['bytes_num']

            if dst_mac:
                mac_data[dst_mac]['ips'].add(f.get('dst_ip', ''))
                mac_data[dst_mac]['frames'] += f['frames']
                mac_data[dst_mac]['bytes'] += f['bytes_num']

        # Filter empty MACs and broadcast
        mac_data = {k: v for k, v in mac_data.items()
                    if k and not k.startswith('ff:ff:ff') and not k.startswith('01:00:5e')}
        level_macs[level] = mac_data

    if not level_macs:
        print("No flow data found. Run extractions first.")
        return

    print("=" * 100)
    print("MAC ADDRESS CORRELATION ACROSS EVIDENCE LEVELS")
    print("=" * 100)
    print()

    # Show which levels have data
    print("Levels with flow data:")
    for level, macs in level_macs.items():
        print(f"  {level.upper()}: {len(macs)} MAC addresses")
    print()

    # Find MACs that appear in multiple levels
    all_macs = set()
    for macs in level_macs.values():
        all_macs.update(macs.keys())

    # Build cross-level map
    cross_level = {}
    for mac in all_macs:
        levels_present = [lvl for lvl in level_macs if mac in level_macs[lvl]]
        if len(levels_present) > 1:
            cross_level[mac] = levels_present

    if not cross_level:
        print("No MAC addresses found in multiple levels.")
        print()
        print("This suggests the captures are from different network segments")
        print("with no shared physical devices.")
        return

    print(f"MACs FOUND IN MULTIPLE LEVELS: {len(cross_level)}")
    print("-" * 100)
    print()

    for mac, levels in sorted(cross_level.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"MAC: {mac}")
        print(f"  Present in: {', '.join(lvl.upper() for lvl in levels)}")
        print()

        for level in levels:
            data = level_macs[level][mac]
            ips = sorted(data['ips'])
            print(f"  [{level.upper()}] Frames: {data['frames']:,}, Bytes: {data['bytes']:,}")
            print(f"       IPs: {', '.join(ips[:5])}", end='')
            if len(ips) > 5:
                print(f" (+{len(ips) - 5} more)")
            else:
                print()

        print()

    # Summary analysis
    print("=" * 100)
    print("CORRELATION ANALYSIS")
    print("=" * 100)
    print()

    # Check for same MAC with different IPs across levels (possible pivoting)
    for mac, levels in cross_level.items():
        all_ips = set()
        level_ips = {}
        for level in levels:
            level_ips[level] = level_macs[level][mac]['ips']
            all_ips.update(level_ips[level])

        # Find IPs unique to each level
        unique_per_level = {}
        for level in levels:
            unique = level_ips[level] - set().union(*(level_ips[l] for l in levels if l != level))
            if unique:
                unique_per_level[level] = unique

        if unique_per_level:
            print(f"PIVOT INDICATOR - {mac}")
            print(f"  Same device seen with different IPs across levels:")
            for level, ips in unique_per_level.items():
                print(f"    {level.upper()} only: {', '.join(sorted(ips))}")
            print()


def main():
    # Get available tiers from config
    available_tiers = get_available_tiers()
    default_tier = 't2' if 't2' in available_tiers else (available_tiers[0] if available_tiers else 't2')

    parser = argparse.ArgumentParser(description='Query network flows')
    parser.add_argument('command', nargs='?', default='summary',
                        help='Command: summary, ip, port, external, top-ips, top-ports, mac-correlate')
    parser.add_argument('arg', nargs='?', help='Command argument')
    parser.add_argument('--tier', default=default_tier, choices=available_tiers if available_tiers else ['t1', 't2', 't3'],
                        help=f'Artifact tier (default: {default_tier})')
    # Legacy alias
    parser.add_argument('--level', default=None, help=argparse.SUPPRESS)
    parser.add_argument('--hex', action='store_true',
                        help='Show hex dump of first packet (for port command)')
    parser.add_argument('--hex-bytes', type=int, default=256,
                        help='Number of bytes to show in hex dump (default: 256)')
    args = parser.parse_args()

    # Support legacy --level flag
    if args.level is not None:
        args.tier = args.level

    # mac-correlate is special - it loads all tiers
    if args.command == 'mac-correlate':
        cmd_mac_correlate()
        return

    flows_file = get_flows_file(args.tier)
    if not flows_file.exists():
        print(f"Error: {flows_file} not found")
        print(f"Run: forensic_analysis.py network extract {args.tier}_flows --tier {args.tier}")
        sys.exit(1)

    print(f"[{args.tier.upper()} flows: {flows_file.name}]\n")
    flows = load_flows(flows_file)

    if args.command == 'summary':
        cmd_summary(flows)
    elif args.command == 'ip':
        if not args.arg:
            print("Usage: query_flows.py ip <ip_address>")
            sys.exit(1)
        cmd_ip(flows, args.arg)
    elif args.command == 'port':
        if not args.arg:
            print("Usage: query_flows.py port <port_number>")
            sys.exit(1)
        cmd_port(flows, args.arg, hex_dump=args.hex, hex_bytes=args.hex_bytes, tier=args.tier)
    elif args.command == 'external':
        cmd_external(flows)
    elif args.command == 'top-ips':
        n = int(args.arg) if args.arg else 20
        cmd_top_ips(flows, n)
    elif args.command == 'top-ports':
        n = int(args.arg) if args.arg else 20
        cmd_top_ports(flows, n)
    elif args.command == 'beacon':
        cmd_beacon(flows)
    elif args.command == 'mac-ip':
        cmd_mac_ip(flows)
    else:
        print(f"Unknown command: {args.command}")
        print("Commands: summary, ip, port, external, top-ips, top-ports, beacon, mac-ip, mac-correlate")
        sys.exit(1)

if __name__ == '__main__':
    main()
