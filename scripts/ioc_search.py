#!/usr/bin/env python3
"""Search IOCs from one tier in another tier's artifacts.

Usage:
    ioc_search.py search t2 t1     # Search T2 IOCs in T1 artifacts
    ioc_search.py search t1 t2     # Search T1 IOCs in T2 artifacts
    ioc_search.py list t1          # List all T1 IOCs
    ioc_search.py list t2          # List all T2 IOCs
    ioc_search.py overlap          # Show IOCs that appear in multiple tiers
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

import yaml

# Import tier helpers from forensic_analysis framework
try:
    from forensic_analysis.base import get_available_tiers, PROJECT_ROOT, CONFIG_DIR
except ImportError:
    # Fallback if not in PYTHONPATH
    sys.path.insert(0, str(Path(__file__).parent))
    from forensic_analysis.base import get_available_tiers, PROJECT_ROOT, CONFIG_DIR

IOCS_FILE = CONFIG_DIR / 'iocs.yaml'


def load_iocs():
    """Load IOCs from YAML file."""
    with open(IOCS_FILE) as f:
        return yaml.safe_load(f)


def get_iocs_for_tier(data, tier):
    """Extract all IOC values for a given tier."""
    level_data = data.get(tier, {})
    iocs = {}

    for ioc_type, values in level_data.items():
        if isinstance(values, list) and values:
            iocs[ioc_type] = values

    return iocs


def get_search_paths(data, tier):
    """Get glob patterns for files to search in a tier."""
    paths = data.get('search_paths', {}).get(tier, [])
    expanded = []
    for pattern in paths:
        expanded.extend(PROJECT_ROOT.glob(pattern))
    return expanded


def search_ioc_in_files(ioc_value, files):
    """Search for an IOC value across files using grep."""
    matches = []

    # Escape special regex chars but keep it simple
    search_term = str(ioc_value).lower()

    for filepath in files:
        try:
            result = subprocess.run(
                ['grep', '-i', '-l', search_term, str(filepath)],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                # Get match count
                count_result = subprocess.run(
                    ['grep', '-i', '-c', search_term, str(filepath)],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                count = count_result.stdout.strip()
                matches.append((filepath, count))
        except subprocess.TimeoutExpired:
            continue
        except Exception:
            continue

    return matches


def cmd_search(args):
    """Search IOCs from one tier in another tier's artifacts."""
    data = load_iocs()

    from_tier = args.from_tier
    in_tier = args.in_tier

    iocs = get_iocs_for_tier(data, from_tier)
    files = get_search_paths(data, in_tier)

    if not files:
        print(f"No files found for tier {in_tier}")
        return

    print(f"Searching {from_tier.upper()} IOCs in {in_tier.upper()} artifacts...")
    print(f"Files to search: {len(files)}")
    print("=" * 70)

    total_matches = 0
    results = {}

    for ioc_type, values in iocs.items():
        for value in values:
            matches = search_ioc_in_files(value, files)
            if matches:
                total_matches += 1
                if ioc_type not in results:
                    results[ioc_type] = []
                results[ioc_type].append((value, matches))

    # Print results grouped by type
    for ioc_type, hits in sorted(results.items()):
        print(f"\n### {ioc_type.upper()}")
        for value, matches in hits:
            print(f"\n  {value}")
            for filepath, count in matches:
                relpath = filepath.relative_to(PROJECT_ROOT)
                print(f"    -> {relpath} ({count} matches)")

    print("\n" + "=" * 70)
    print(f"SUMMARY: {total_matches} IOCs found in {in_tier.upper()} artifacts")

    if total_matches == 0:
        print(f"No {from_tier.upper()} IOCs found in {in_tier.upper()} artifacts.")


def cmd_list(args):
    """List all IOCs for a tier."""
    data = load_iocs()
    tier = args.tier

    iocs = get_iocs_for_tier(data, tier)

    print(f"IOCs for {tier.upper()}:")
    print("=" * 50)

    total = 0
    for ioc_type, values in sorted(iocs.items()):
        print(f"\n{ioc_type} ({len(values)}):")
        for v in values:
            print(f"  - {v}")
        total += len(values)

    print(f"\nTotal: {total} IOCs")


def cmd_overlap(args):
    """Show IOCs that appear in multiple tiers."""
    data = load_iocs()

    # Collect all IOCs by value
    ioc_locations = {}

    for tier in get_available_tiers():
        iocs = get_iocs_for_tier(data, tier)
        for ioc_type, values in iocs.items():
            for v in values:
                v_lower = str(v).lower()
                if v_lower not in ioc_locations:
                    ioc_locations[v_lower] = []
                ioc_locations[v_lower].append((tier, ioc_type, v))

    # Find overlaps
    print("IOCs appearing in MULTIPLE tiers:")
    print("=" * 60)

    overlaps = {k: v for k, v in ioc_locations.items() if len(v) > 1}

    if not overlaps:
        print("No overlapping IOCs found.")
        return

    for value, locations in sorted(overlaps.items()):
        tiers = set(loc[0] for loc in locations)
        types = set(loc[1] for loc in locations)
        print(f"\n  {value}")
        print(f"    Tiers: {', '.join(sorted(tiers))}")
        print(f"    Types: {', '.join(sorted(types))}")

    print(f"\nTotal: {len(overlaps)} overlapping IOCs")


def main():
    # Get available tiers from config
    available_tiers = get_available_tiers() or ['t1', 't2', 't3']

    parser = argparse.ArgumentParser(description='Search IOCs across artifact tiers')
    subparsers = parser.add_subparsers(dest='command', required=True)

    # search command
    search_parser = subparsers.add_parser('search', help='Search IOCs from one tier in another')
    search_parser.add_argument('from_tier', choices=available_tiers, help='Tier to get IOCs from')
    search_parser.add_argument('in_tier', choices=available_tiers, help='Tier to search in')
    search_parser.set_defaults(func=cmd_search)

    # list command
    list_parser = subparsers.add_parser('list', help='List IOCs for a tier')
    list_parser.add_argument('tier', choices=available_tiers, help='Tier to list')
    list_parser.set_defaults(func=cmd_list)

    # overlap command
    overlap_parser = subparsers.add_parser('overlap', help='Show IOCs in multiple tiers')
    overlap_parser.set_defaults(func=cmd_overlap)

    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
