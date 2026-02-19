#!/usr/bin/env python3
"""Query TLS fingerprints extracted from PCAPs.

Usage:
    query_tls.py                     # Show JA3 summary per client
    query_tls.py ip 192.168.24.100   # TLS connections from specific client
    query_tls.py sni                 # Show all SNI values
    query_tls.py ja3 <hash>          # Find connections with specific JA3
    query_tls.py --tier t1 summary   # Query Tier 1 TLS
"""

import argparse
import csv
import os
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


def get_tls_file(level: str) -> Path:
    """Get the TLS CSV file path for a level."""
    return get_extractions_path(level, 'network') / f'{level}-tls.csv'

# Known malicious JA3 hashes (subset - extend as needed)
KNOWN_MALICIOUS_JA3 = {
    'a0e9f5d64349fb13191bc781f81f42e1': 'Cobalt Strike',
    '72a589da586844d7f0818ce684948eea': 'Cobalt Strike',
    '3b5074b1b5d032e5620f69f9f700ff0e': 'Trickbot',
    '51c64c77e60f3980eea90869b68c58a8': 'Metasploit',
    '9e729c51d4ccf02e6ee6c8e7a4d23bc0': 'IcedID',
    '6734f37431670b3ab4292b8f60f29984': 'Dridex',
    'e7d705a3286e19ea42f587b344ee6865': 'Emotet',
}


def load_tls(tls_file):
    """Load TLS records from CSV."""
    records = []
    with open(tls_file) as f:
        reader = csv.DictReader(f)
        for row in reader:
            records.append(row)
    return records


def cmd_summary(records):
    """Show JA3 fingerprint summary per client."""
    # Group by client IP
    client_ja3 = defaultdict(lambda: {'ja3s': defaultdict(int), 'snis': set(), 'servers': set()})

    for r in records:
        client = r['client_ip']
        ja3 = r['ja3'] or 'unknown'
        client_ja3[client]['ja3s'][ja3] += 1
        if r['sni']:
            client_ja3[client]['snis'].add(r['sni'])
        if r['server_ip']:
            client_ja3[client]['servers'].add(r['server_ip'])

    print(f"Total TLS handshakes: {len(records)}")
    print(f"Unique clients: {len(client_ja3)}")
    print()

    # Check for malicious JA3
    malicious_found = []
    for client, info in client_ja3.items():
        for ja3 in info['ja3s']:
            if ja3 in KNOWN_MALICIOUS_JA3:
                malicious_found.append((client, ja3, KNOWN_MALICIOUS_JA3[ja3]))

    if malicious_found:
        print("=" * 80)
        print("[!] KNOWN MALICIOUS JA3 FINGERPRINTS DETECTED")
        print("=" * 80)
        for client, ja3, malware in malicious_found:
            print(f"  {client}: {ja3[:32]}... ({malware})")
        print()

    print(f"{'Client IP':<18} {'Handshakes':>10} {'JA3s':>6} {'SNIs':>6} {'Servers':>8}")
    print("-" * 55)

    for client, info in sorted(client_ja3.items(), key=lambda x: sum(x[1]['ja3s'].values()), reverse=True):
        total = sum(info['ja3s'].values())
        num_ja3 = len(info['ja3s'])
        num_sni = len(info['snis'])
        num_servers = len(info['servers'])
        print(f"{client:<18} {total:>10} {num_ja3:>6} {num_sni:>6} {num_servers:>8}")

    # Show unique JA3 fingerprints
    print()
    print("=" * 80)
    print("UNIQUE JA3 FINGERPRINTS")
    print("=" * 80)

    all_ja3 = defaultdict(lambda: {'count': 0, 'clients': set()})
    for r in records:
        ja3 = r['ja3'] or 'unknown'
        all_ja3[ja3]['count'] += 1
        all_ja3[ja3]['clients'].add(r['client_ip'])

    print(f"\n{'JA3 Hash':<35} {'Count':>8} {'Clients':>8} {'Malware':<15}")
    print("-" * 70)

    for ja3, info in sorted(all_ja3.items(), key=lambda x: x[1]['count'], reverse=True)[:30]:
        malware = KNOWN_MALICIOUS_JA3.get(ja3, '-')
        ja3_disp = ja3[:33] + '..' if len(ja3) > 35 else ja3
        print(f"{ja3_disp:<35} {info['count']:>8} {len(info['clients']):>8} {malware:<15}")


def cmd_ip(records, ip):
    """Show TLS connections from specific client IP."""
    matches = [r for r in records if ip in r['client_ip']]

    print(f"TLS connections from {ip}: {len(matches)}")
    print()

    if not matches:
        return

    # Check for malicious JA3
    for r in matches:
        if r['ja3'] in KNOWN_MALICIOUS_JA3:
            print(f"[!] MALICIOUS JA3 DETECTED: {KNOWN_MALICIOUS_JA3[r['ja3']]}")
            print()
            break

    print(f"{'Timestamp':<20} {'Server':<18} {'Port':>6} {'SNI':<30} {'JA3':<20}")
    print("-" * 100)

    for r in matches[:100]:
        ts = r['timestamp_utc'][:19] if r['timestamp_utc'] else ''
        sni = r['sni'][:28] + '..' if len(r['sni']) > 30 else r['sni'] or '-'
        ja3 = r['ja3'][:18] + '..' if len(r['ja3']) > 20 else r['ja3'] or '-'
        print(f"{ts:<20} {r['server_ip']:<18} {r['server_port']:>6} {sni:<30} {ja3:<20}")

    if len(matches) > 100:
        print(f"\n... and {len(matches) - 100} more")


def cmd_sni(records):
    """Show all SNI (Server Name Indication) values."""
    sni_info = defaultdict(lambda: {'count': 0, 'clients': set(), 'servers': set()})

    for r in records:
        sni = r['sni'] or '(no SNI)'
        sni_info[sni]['count'] += 1
        sni_info[sni]['clients'].add(r['client_ip'])
        sni_info[sni]['servers'].add(r['server_ip'])

    print(f"Total TLS handshakes: {len(records)}")
    print(f"Unique SNI values: {len(sni_info)}")
    print()
    print(f"{'SNI':<50} {'Count':>8} {'Clients':>8} {'Server IPs'}")
    print("-" * 100)

    for sni, info in sorted(sni_info.items(), key=lambda x: x[1]['count'], reverse=True)[:100]:
        servers = ','.join(sorted(info['servers']))[:25] or '-'
        sni_disp = sni[:48] + '..' if len(sni) > 50 else sni
        print(f"{sni_disp:<50} {info['count']:>8} {len(info['clients']):>8} {servers}")


def cmd_ja3(records, ja3_hash):
    """Find connections with specific JA3 fingerprint."""
    matches = [r for r in records if ja3_hash in (r['ja3'] or '')]

    print(f"Connections with JA3 containing '{ja3_hash}': {len(matches)}")

    if ja3_hash in KNOWN_MALICIOUS_JA3:
        print(f"[!] WARNING: This JA3 is associated with: {KNOWN_MALICIOUS_JA3[ja3_hash]}")

    print()

    if not matches:
        return

    print(f"{'Timestamp':<20} {'Client':<18} {'Server':<18} {'SNI':<30}")
    print("-" * 90)

    for r in matches:
        ts = r['timestamp_utc'][:19] if r['timestamp_utc'] else ''
        sni = r['sni'][:28] + '..' if len(r['sni']) > 30 else r['sni'] or '-'
        print(f"{ts:<20} {r['client_ip']:<18} {r['server_ip']:<18} {sni:<30}")


def cmd_external(records):
    """Show TLS connections to external (non-RFC1918) servers."""
    def is_private(ip):
        return ip.startswith(('192.168.', '10.', '172.16.', '172.17.', '172.18.',
                              '172.19.', '172.2', '172.30.', '172.31.'))

    external = [r for r in records if r['server_ip'] and not is_private(r['server_ip'])]

    # Group by server
    server_info = defaultdict(lambda: {'count': 0, 'clients': set(), 'snis': set()})
    for r in external:
        server = r['server_ip']
        server_info[server]['count'] += 1
        server_info[server]['clients'].add(r['client_ip'])
        if r['sni']:
            server_info[server]['snis'].add(r['sni'])

    print(f"TLS connections to external servers: {len(external)}")
    print(f"Unique external servers: {len(server_info)}")
    print()
    print(f"{'Server IP':<18} {'Count':>8} {'Clients':>8} {'SNIs'}")
    print("-" * 90)

    for server, info in sorted(server_info.items(), key=lambda x: x[1]['count'], reverse=True)[:50]:
        snis = ','.join(sorted(info['snis']))[:40] or '-'
        print(f"{server:<18} {info['count']:>8} {len(info['clients']):>8} {snis}")


def main():
    # Get available tiers from config
    available_tiers = get_available_tiers()
    default_tier = 't2' if 't2' in available_tiers else (available_tiers[0] if available_tiers else 't2')

    parser = argparse.ArgumentParser(description='Query TLS fingerprints')
    parser.add_argument('command', nargs='?', default='summary',
                        help='Command: summary, ip, sni, ja3, external')
    parser.add_argument('arg', nargs='?', help='Command argument')
    parser.add_argument('--tier', default=default_tier, choices=available_tiers if available_tiers else ['t1', 't2', 't3'],
                        help=f'Artifact tier (default: {default_tier})')
    # Legacy alias
    parser.add_argument('--level', default=None, help=argparse.SUPPRESS)
    args = parser.parse_args()

    # Support legacy --level flag
    if args.level is not None:
        args.tier = args.level

    tls_file = get_tls_file(args.tier)
    if not tls_file.exists():
        print(f"Error: {tls_file} not found")
        print(f"Run: forensic_analysis.py network extract tls --tier {args.tier}")
        sys.exit(1)

    print(f"[Tier {args.tier} TLS: {tls_file.name}]\n")
    records = load_tls(tls_file)

    if args.command == 'summary':
        cmd_summary(records)
    elif args.command == 'ip':
        if not args.arg:
            print("Usage: query_tls.py ip <ip_address>")
            sys.exit(1)
        cmd_ip(records, args.arg)
    elif args.command == 'sni':
        cmd_sni(records)
    elif args.command == 'ja3':
        if not args.arg:
            print("Usage: query_tls.py ja3 <hash>")
            sys.exit(1)
        cmd_ja3(records, args.arg)
    elif args.command == 'external':
        cmd_external(records)
    else:
        print(f"Unknown command: {args.command}")
        print("Commands: summary, ip, sni, ja3, external")
        sys.exit(1)


if __name__ == '__main__':
    main()
