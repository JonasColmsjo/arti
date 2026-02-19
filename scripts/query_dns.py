#!/usr/bin/env python3
"""Query DNS records extracted from PCAPs.

Usage:
    query_dns.py                     # Show domain summary
    query_dns.py ip 192.168.24.100   # DNS queries from specific client
    query_dns.py nxdomain            # Show NXDOMAIN responses (DGA detection)
    query_dns.py domain evil.com     # Search for domain pattern
    query_dns.py --tier t1 summary   # Query Tier 1 DNS
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


def get_dns_file(level: str) -> Path:
    """Get the DNS CSV file path for a level."""
    return get_extractions_path(level, 'network') / f'{level}-dns.csv'


def load_dns(dns_file):
    """Load DNS records from CSV."""
    records = []
    with open(dns_file) as f:
        reader = csv.DictReader(f)
        for row in reader:
            records.append(row)
    return records


def cmd_summary(records):
    """Show domain query summary with counts."""
    # Count queries per domain
    domain_counts = defaultdict(int)
    domain_clients = defaultdict(set)
    domain_responses = defaultdict(set)

    for r in records:
        domain = r['query_name'].lower().rstrip('.')
        if domain:
            domain_counts[domain] += 1
            domain_clients[domain].add(r['client_ip'])
            if r['response_code']:
                domain_responses[domain].add(r['response_code'])

    # Sort by count
    sorted_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)

    print(f"Total DNS records: {len(records)}")
    print(f"Unique domains: {len(domain_counts)}")
    print()
    print(f"{'Domain':<50} {'Count':>8} {'Clients':>8} {'Response':<12}")
    print("-" * 85)

    for domain, count in sorted_domains[:100]:
        clients = len(domain_clients[domain])
        responses = ','.join(sorted(domain_responses[domain])) or '-'
        # Truncate long domains
        disp_domain = domain[:48] + '..' if len(domain) > 50 else domain
        print(f"{disp_domain:<50} {count:>8} {clients:>8} {responses:<12}")

    if len(sorted_domains) > 100:
        print(f"\n... and {len(sorted_domains) - 100} more domains")


def cmd_ip(records, ip):
    """Show DNS queries from specific client IP."""
    matches = [r for r in records if ip in r['client_ip']]

    # Group by domain
    domain_info = defaultdict(lambda: {'count': 0, 'answers': set(), 'rcodes': set()})
    for r in matches:
        domain = r['query_name'].lower().rstrip('.')
        domain_info[domain]['count'] += 1
        if r['answer']:
            domain_info[domain]['answers'].add(r['answer'])
        if r['response_code']:
            domain_info[domain]['rcodes'].add(r['response_code'])

    print(f"DNS queries from {ip}: {len(matches)}")
    print(f"Unique domains: {len(domain_info)}")
    print()
    print(f"{'Domain':<50} {'Count':>6} {'Response':<10} {'Answer':<20}")
    print("-" * 90)

    for domain, info in sorted(domain_info.items(), key=lambda x: x[1]['count'], reverse=True):
        rcodes = ','.join(sorted(info['rcodes'])) or '-'
        answers = ','.join(sorted(info['answers']))[:18] or '-'
        disp_domain = domain[:48] + '..' if len(domain) > 50 else domain
        print(f"{disp_domain:<50} {info['count']:>6} {rcodes:<10} {answers:<20}")


def cmd_nxdomain(records):
    """Show NXDOMAIN responses - potential DGA or dead C2."""
    matches = [r for r in records if r['response_code'] == 'NXDOMAIN']

    # Group by domain
    domain_counts = defaultdict(lambda: {'count': 0, 'clients': set()})
    for r in matches:
        domain = r['query_name'].lower().rstrip('.')
        domain_counts[domain]['count'] += 1
        domain_counts[domain]['clients'].add(r['client_ip'])

    print(f"NXDOMAIN responses: {len(matches)}")
    print(f"Unique failed domains: {len(domain_counts)}")
    print()

    if not domain_counts:
        print("No NXDOMAIN responses found.")
        return

    print(f"{'Domain':<55} {'Count':>6} {'Clients':<20}")
    print("-" * 85)

    for domain, info in sorted(domain_counts.items(), key=lambda x: x[1]['count'], reverse=True)[:50]:
        clients = ','.join(sorted(info['clients']))[:18] or '-'
        disp_domain = domain[:53] + '..' if len(domain) > 55 else domain
        print(f"{disp_domain:<55} {info['count']:>6} {clients:<20}")

    # Check for DGA patterns
    print("\n" + "=" * 85)
    print("DGA ANALYSIS")
    print("=" * 85)

    # Look for random-looking domains
    import re
    dga_candidates = []
    for domain in domain_counts.keys():
        # Get second-level domain
        parts = domain.split('.')
        if len(parts) >= 2:
            sld = parts[-2]
            # Check for DGA patterns: long random strings
            if len(sld) > 10 and re.match(r'^[a-z0-9]+$', sld):
                consonant_ratio = sum(1 for c in sld if c in 'bcdfghjklmnpqrstvwxyz') / len(sld)
                if consonant_ratio > 0.6 or consonant_ratio < 0.3:
                    dga_candidates.append(domain)

    if dga_candidates:
        print(f"\nPotential DGA domains ({len(dga_candidates)}):")
        for d in dga_candidates[:20]:
            print(f"  {d}")
    else:
        print("\nNo obvious DGA patterns detected.")


def cmd_domain(records, pattern):
    """Search for domain pattern."""
    pattern_lower = pattern.lower()
    matches = [r for r in records if pattern_lower in r['query_name'].lower()]

    print(f"Domains matching '{pattern}': {len(matches)}")
    print()

    if not matches:
        return

    print(f"{'Timestamp':<20} {'Client':<18} {'Domain':<40} {'Response':<10} {'Answer'}")
    print("-" * 110)

    for r in matches[:100]:
        ts = r['timestamp_utc'][:19] if r['timestamp_utc'] else ''
        domain = r['query_name'][:38] + '..' if len(r['query_name']) > 40 else r['query_name']
        answer = r['answer'][:25] if r['answer'] else '-'
        print(f"{ts:<20} {r['client_ip']:<18} {domain:<40} {r['response_code']:<10} {answer}")


def cmd_external(records):
    """Show queries for external (non-local) domains."""
    local_suffixes = ['.local', '.lan', '.home', '.internal', '.localdomain',
                      '.in-addr.arpa', '.ip6.arpa']

    external = []
    for r in records:
        domain = r['query_name'].lower()
        if not any(domain.endswith(s) for s in local_suffixes):
            external.append(r)

    # Group by domain
    domain_counts = defaultdict(lambda: {'count': 0, 'clients': set(), 'answers': set()})
    for r in external:
        domain = r['query_name'].lower().rstrip('.')
        domain_counts[domain]['count'] += 1
        domain_counts[domain]['clients'].add(r['client_ip'])
        if r['answer']:
            domain_counts[domain]['answers'].add(r['answer'])

    print(f"External domain queries: {len(external)}")
    print(f"Unique external domains: {len(domain_counts)}")
    print()
    print(f"{'Domain':<50} {'Count':>6} {'Clients':>8} {'IPs':<25}")
    print("-" * 95)

    for domain, info in sorted(domain_counts.items(), key=lambda x: x[1]['count'], reverse=True)[:50]:
        clients = len(info['clients'])
        ips = ','.join(sorted(info['answers']))[:23] or '-'
        disp_domain = domain[:48] + '..' if len(domain) > 50 else domain
        print(f"{disp_domain:<50} {info['count']:>6} {clients:>8} {ips:<25}")


def main():
    # Get available tiers from config
    available_tiers = get_available_tiers()
    default_tier = 't2' if 't2' in available_tiers else (available_tiers[0] if available_tiers else 't2')

    parser = argparse.ArgumentParser(description='Query DNS records')
    parser.add_argument('command', nargs='?', default='summary',
                        help='Command: summary, ip, nxdomain, domain, external')
    parser.add_argument('arg', nargs='?', help='Command argument')
    parser.add_argument('--tier', default=default_tier, choices=available_tiers if available_tiers else ['t1', 't2', 't3'],
                        help=f'Artifact tier (default: {default_tier})')
    # Legacy alias
    parser.add_argument('--level', default=None, help=argparse.SUPPRESS)
    args = parser.parse_args()

    # Support legacy --level flag
    if args.level is not None:
        args.tier = args.level

    dns_file = get_dns_file(args.tier)
    if not dns_file.exists():
        print(f"Error: {dns_file} not found")
        print(f"Run: forensic_analysis.py network extract dns --tier {args.tier}")
        sys.exit(1)

    print(f"[Tier {args.tier} DNS: {dns_file.name}]\n")
    records = load_dns(dns_file)

    if args.command == 'summary':
        cmd_summary(records)
    elif args.command == 'ip':
        if not args.arg:
            print("Usage: query_dns.py ip <ip_address>")
            sys.exit(1)
        cmd_ip(records, args.arg)
    elif args.command == 'nxdomain':
        cmd_nxdomain(records)
    elif args.command == 'domain':
        if not args.arg:
            print("Usage: query_dns.py domain <pattern>")
            sys.exit(1)
        cmd_domain(records, args.arg)
    elif args.command == 'external':
        cmd_external(records)
    else:
        print(f"Unknown command: {args.command}")
        print("Commands: summary, ip, nxdomain, domain, external")
        sys.exit(1)


if __name__ == '__main__':
    main()
