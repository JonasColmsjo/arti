#!/usr/bin/env python3
"""
Query Plaso timeline CSV for forensic analysis.

Usage:
    python query_plaso.py summary
    python query_plaso.py search "vncviewer"
    python query_plaso.py timerange "08/15/2020" "08/16/2020"
    python query_plaso.py user "t.johnson"
    python query_plaso.py source EVT
    python query_plaso.py around "08/15/2020 03:18:00" --minutes 5

Environment:
    PLASO_CSV       Path to Plaso CSV file (direct)
    ARTIFACTS_PATH   Base path for artifacts (used if PLASO_CSV not set)
"""

import argparse
import csv
import os
import sys
from datetime import datetime, timedelta
from collections import Counter
from pathlib import Path

# Increase CSV field size limit for large Plaso descriptions
csv.field_size_limit(sys.maxsize)

# Plaso CSV path - configurable via environment
def get_plaso_path():
    """Get Plaso CSV path from environment or default."""
    if 'PLASO_CSV' in os.environ:
        return os.environ['PLASO_CSV']

    artifacts_path = os.environ.get('ARTIFACTS_PATH', '/home/me/data/bth-kurs')
    return os.path.join(
        artifacts_path,
        'artifacts-unpacked/Tier_1_Artifacts/Spader_Technologies/stsupport10-plaso-timeline/stsupport10-plaso-timeline.csv'
    )

PLASO_CSV = get_plaso_path()


def load_plaso(filepath=None, limit=None):
    """Load Plaso CSV into list of dicts."""
    if filepath is None:
        filepath = PLASO_CSV
    rows = []
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            if limit and i >= limit:
                break
            rows.append(row)
    return rows


def parse_datetime(date_str, time_str):
    """Parse Plaso date/time to datetime object."""
    try:
        return datetime.strptime(f"{date_str} {time_str}", "%m/%d/%Y %H:%M:%S")
    except:
        return None


def format_row(row, verbose=False):
    """Format a row for display."""
    dt = f"{row['date']} {row['time']}"
    source = row['source']
    user = row['user'] or '-'
    short = row['short'][:80] if row['short'] else '-'

    if verbose:
        return f"{dt} [{source:6}] [{user:20}] {row['short']}\n  -> {row['desc'][:200]}"
    else:
        return f"{dt} [{source:6}] [{user:20}] {short}"


def cmd_summary(args):
    """Show summary statistics."""
    print(f"Loading {PLASO_CSV}...")
    rows = load_plaso()

    print(f"\nTotal rows: {len(rows):,}")

    # Date range
    dates = [parse_datetime(r['date'], r['time']) for r in rows]
    dates = [d for d in dates if d]
    if dates:
        print(f"Date range: {min(dates)} to {max(dates)}")

    # Sources
    print("\nSources:")
    sources = Counter(r['source'] for r in rows)
    for src, count in sources.most_common(15):
        print(f"  {src:10} {count:>8,}")

    # Users
    print("\nTop Users:")
    users = Counter(r['user'] for r in rows if r['user'])
    for user, count in users.most_common(10):
        print(f"  {user:30} {count:>8,}")

    # Source types
    print("\nSource Types:")
    stypes = Counter(r['sourcetype'] for r in rows)
    for st, count in stypes.most_common(15):
        print(f"  {st:25} {count:>8,}")


def cmd_search(args):
    """Search for pattern in short/desc fields."""
    pattern = args.pattern.lower()
    rows = load_plaso()

    matches = []
    for row in rows:
        short = (row['short'] or '').lower()
        desc = (row['desc'] or '').lower()
        if pattern in short or pattern in desc:
            matches.append(row)

    print(f"Found {len(matches)} matches for '{args.pattern}':\n")

    for row in matches[:args.limit]:
        print(format_row(row, args.verbose))

    if len(matches) > args.limit:
        print(f"\n... and {len(matches) - args.limit} more (use --limit to show more)")


def cmd_timerange(args):
    """Show events in time range."""
    try:
        start = datetime.strptime(args.start, "%m/%d/%Y")
        end = datetime.strptime(args.end, "%m/%d/%Y") + timedelta(days=1)
    except ValueError:
        print("Date format: MM/DD/YYYY")
        sys.exit(1)

    rows = load_plaso()

    matches = []
    for row in rows:
        dt = parse_datetime(row['date'], row['time'])
        if dt and start <= dt < end:
            matches.append(row)

    # Filter by source if specified
    if args.source:
        matches = [r for r in matches if r['source'] == args.source]

    print(f"Found {len(matches)} events from {args.start} to {args.end}:\n")

    for row in matches[:args.limit]:
        print(format_row(row, args.verbose))

    if len(matches) > args.limit:
        print(f"\n... and {len(matches) - args.limit} more")


def cmd_user(args):
    """Show events for specific user."""
    rows = load_plaso()

    matches = [r for r in rows if args.username.lower() in (r['user'] or '').lower()]

    print(f"Found {len(matches)} events for user '{args.username}':\n")

    for row in matches[:args.limit]:
        print(format_row(row, args.verbose))

    if len(matches) > args.limit:
        print(f"\n... and {len(matches) - args.limit} more")


def cmd_source(args):
    """Show events from specific source."""
    rows = load_plaso()

    matches = [r for r in rows if r['source'] == args.source_type]

    # Filter by date if specified
    if args.date:
        matches = [r for r in matches if r['date'] == args.date]

    print(f"Found {len(matches)} events from source '{args.source_type}':\n")

    for row in matches[:args.limit]:
        print(format_row(row, args.verbose))

    if len(matches) > args.limit:
        print(f"\n... and {len(matches) - args.limit} more")


def cmd_around(args):
    """Show events around a specific time."""
    try:
        center = datetime.strptime(args.timestamp, "%m/%d/%Y %H:%M:%S")
    except ValueError:
        print("Timestamp format: MM/DD/YYYY HH:MM:SS")
        sys.exit(1)

    delta = timedelta(minutes=args.minutes)
    start = center - delta
    end = center + delta

    rows = load_plaso()

    matches = []
    for row in rows:
        dt = parse_datetime(row['date'], row['time'])
        if dt and start <= dt <= end:
            matches.append((dt, row))

    # Sort by time
    matches.sort(key=lambda x: x[0])

    print(f"Found {len(matches)} events within {args.minutes} minutes of {args.timestamp}:\n")

    for dt, row in matches[:args.limit]:
        print(format_row(row, args.verbose))

    if len(matches) > args.limit:
        print(f"\n... and {len(matches) - args.limit} more")


def cmd_ioc(args):
    """Search for known IOCs."""
    iocs = [
        'vncviewer',
        'topenergysupport',
        '51.11.247.89',
        '83.136.254',
        'meterpreter',
        'mimikatz',
        'dropbox',
        'alset',
        '.exe',
        'powershell',
    ]

    if args.ioc:
        iocs = [args.ioc]

    rows = load_plaso()

    for ioc in iocs:
        matches = []
        for row in rows:
            short = (row['short'] or '').lower()
            desc = (row['desc'] or '').lower()
            if ioc.lower() in short or ioc.lower() in desc:
                matches.append(row)

        if matches:
            print(f"\n{'='*60}")
            print(f"IOC: {ioc} ({len(matches)} matches)")
            print('='*60)
            for row in matches[:10]:
                print(format_row(row, False))
            if len(matches) > 10:
                print(f"  ... and {len(matches) - 10} more")


def cmd_attack_window(args):
    """Show events during known attack window (Aug 15-18, 2020)."""
    rows = load_plaso()

    start = datetime(2020, 8, 15)
    end = datetime(2020, 8, 19)

    matches = []
    for row in rows:
        dt = parse_datetime(row['date'], row['time'])
        if dt and start <= dt < end:
            matches.append((dt, row))

    matches.sort(key=lambda x: x[0])

    # Filter by source if specified
    if args.source:
        matches = [(dt, r) for dt, r in matches if r['source'] == args.source]

    print(f"Attack window (Aug 15-18, 2020): {len(matches)} events\n")

    # Group by hour
    if args.hourly:
        hourly = Counter()
        for dt, row in matches:
            hour = dt.strftime("%m/%d %H:00")
            hourly[hour] += 1

        for hour, count in sorted(hourly.items()):
            bar = '#' * min(count // 10, 50)
            print(f"{hour}  {count:>5}  {bar}")
    else:
        for dt, row in matches[:args.limit]:
            print(format_row(row, args.verbose))

        if len(matches) > args.limit:
            print(f"\n... and {len(matches) - args.limit} more")


def cmd_heatmap(args):
    """Show day-by-hour heatmap of events."""
    rows = load_plaso()

    # Filter by date range if specified
    if args.start and args.end:
        try:
            start = datetime.strptime(args.start, "%m/%d/%Y")
            end = datetime.strptime(args.end, "%m/%d/%Y") + timedelta(days=1)
        except ValueError:
            print("Date format: MM/DD/YYYY")
            sys.exit(1)
    else:
        # Default to attack window
        start = datetime(2020, 8, 11)
        end = datetime(2020, 8, 19)

    # Filter by source if specified
    if args.source:
        rows = [r for r in rows if r['source'] == args.source]

    # Build day-hour matrix
    day_hour = {}
    for row in rows:
        dt = parse_datetime(row['date'], row['time'])
        if dt and start <= dt < end:
            day = dt.strftime("%m/%d")
            hour = dt.hour
            if day not in day_hour:
                day_hour[day] = [0] * 24
            day_hour[day][hour] += 1

    if not day_hour:
        print("No events found in date range")
        return

    # Find max for scaling
    max_count = max(max(hours) for hours in day_hour.values())

    # Intensity characters
    chars = ' ▁▂▃▄▅▆▇█'

    # Print header
    print(f"Events per hour ({start.strftime('%m/%d')} to {(end - timedelta(days=1)).strftime('%m/%d')})")
    if args.source:
        print(f"Source: {args.source}")
    print()
    print("        " + "".join(f"{h:2}" for h in range(24)))
    print("        " + "-" * 48)

    # Print each day
    for day in sorted(day_hour.keys()):
        hours = day_hour[day]
        row_chars = ""
        for count in hours:
            if count == 0:
                row_chars += "  "
            else:
                # Scale to 0-8 for character selection
                idx = min(int(count / max_count * 8), 8)
                row_chars += chars[idx] + " "
        total = sum(hours)
        print(f"{day}  |{row_chars}| {total:>6}")

    print("        " + "-" * 48)
    print()

    # Legend
    print(f"Scale: 0 to {max_count} events per hour")
    print(f"Chars: {' '.join(chars)}")
    print()

    # Show peak hours
    print("Peak hours:")
    peaks = []
    for day, hours in day_hour.items():
        for h, count in enumerate(hours):
            if count > 0:
                peaks.append((count, day, h))
    peaks.sort(reverse=True)
    for count, day, h in peaks[:10]:
        print(f"  {day} {h:02d}:00  {count:>6} events")


def main():
    parser = argparse.ArgumentParser(description='Query Plaso timeline')
    parser.add_argument('--limit', '-n', type=int, default=50, help='Max results')
    parser.add_argument('--verbose', '-v', action='store_true', help='Show full descriptions')
    parser.add_argument('--file', '-f', type=str, help='Path to Plaso CSV file (overrides PLASO_CSV env)')

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # summary
    subparsers.add_parser('summary', help='Show summary statistics')

    # search
    p_search = subparsers.add_parser('search', help='Search for pattern')
    p_search.add_argument('pattern', help='Search pattern')

    # timerange
    p_time = subparsers.add_parser('timerange', help='Events in time range')
    p_time.add_argument('start', help='Start date (MM/DD/YYYY)')
    p_time.add_argument('end', help='End date (MM/DD/YYYY)')
    p_time.add_argument('--source', '-s', help='Filter by source')

    # user
    p_user = subparsers.add_parser('user', help='Events for user')
    p_user.add_argument('username', help='Username to search')

    # source
    p_source = subparsers.add_parser('source', help='Events from source')
    p_source.add_argument('source_type', help='Source type (EVT, REG, FILE, etc)')
    p_source.add_argument('--date', '-d', help='Filter by date (MM/DD/YYYY)')

    # around
    p_around = subparsers.add_parser('around', help='Events around timestamp')
    p_around.add_argument('timestamp', help='Center timestamp (MM/DD/YYYY HH:MM:SS)')
    p_around.add_argument('--minutes', '-m', type=int, default=5, help='Minutes before/after')

    # ioc
    p_ioc = subparsers.add_parser('ioc', help='Search for IOCs')
    p_ioc.add_argument('ioc', nargs='?', help='Specific IOC to search')

    # attack-window
    p_attack = subparsers.add_parser('attack-window', help='Events during attack (Aug 15-18)')
    p_attack.add_argument('--source', '-s', help='Filter by source')
    p_attack.add_argument('--hourly', action='store_true', help='Show hourly histogram')

    # heatmap
    p_heatmap = subparsers.add_parser('heatmap', help='Day-by-hour heatmap')
    p_heatmap.add_argument('--start', help='Start date (MM/DD/YYYY)')
    p_heatmap.add_argument('--end', help='End date (MM/DD/YYYY)')
    p_heatmap.add_argument('--source', '-s', help='Filter by source')

    args = parser.parse_args()

    # Override PLASO_CSV if --file provided
    global PLASO_CSV
    if args.file:
        PLASO_CSV = args.file

    if not args.command:
        parser.print_help()
        sys.exit(1)

    commands = {
        'summary': cmd_summary,
        'search': cmd_search,
        'timerange': cmd_timerange,
        'user': cmd_user,
        'source': cmd_source,
        'around': cmd_around,
        'ioc': cmd_ioc,
        'attack-window': cmd_attack_window,
        'heatmap': cmd_heatmap,
    }

    commands[args.command](args)


if __name__ == '__main__':
    main()
