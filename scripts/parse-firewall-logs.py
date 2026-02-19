#!/usr/bin/env python3
"""
Parse iptables/netfilter firewall logs to CSV format.

Input format:
<4>2020-08-12T00:06:08.684585+00:00 st-firewall kernel: [...] Rule-Name: IN=iface OUT=iface ... SRC=x.x.x.x DST=x.x.x.x ... PROTO=UDP SPT=123 DPT=456 ...
"""

import sys
import re
import csv
from datetime import datetime

# Regex to parse firewall log lines
LOG_PATTERN = re.compile(
    r'<\d+>(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[+-]\d{2}:\d{2})\s+'  # timestamp
    r'\S+\s+kernel:\s+\[\d+\.\d+\]\s+'  # host and kernel timestamp
    r'([^:]+):\s+'  # rule name
    r'(.*)'  # rest of the line with key=value pairs
)

# Pattern to extract key=value pairs
KV_PATTERN = re.compile(r'(\w+)=(\S+)')

def parse_line(line):
    """Parse a single firewall log line."""
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None

    timestamp_str, rule, rest = match.groups()

    # Parse timestamp
    try:
        # Handle timezone format
        timestamp = datetime.fromisoformat(timestamp_str)
        timestamp_utc = timestamp.strftime('%Y-%m-%d %H:%M:%S')
    except:
        timestamp_utc = timestamp_str

    # Extract key=value pairs
    kvs = dict(KV_PATTERN.findall(rest))

    return {
        'timestamp_utc': timestamp_utc,
        'rule': rule.strip(),
        'in_iface': kvs.get('IN', ''),
        'out_iface': kvs.get('OUT', ''),
        'src_ip': kvs.get('SRC', ''),
        'dst_ip': kvs.get('DST', ''),
        'proto': kvs.get('PROTO', ''),
        'src_port': kvs.get('SPT', ''),
        'dst_port': kvs.get('DPT', ''),
        'len': kvs.get('LEN', ''),
        'ttl': kvs.get('TTL', ''),
    }

def main():
    fieldnames = ['timestamp_utc', 'rule', 'in_iface', 'out_iface', 'src_ip', 'dst_ip', 'proto', 'src_port', 'dst_port', 'len', 'ttl']

    writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
    writer.writeheader()

    count = 0
    errors = 0
    for line in sys.stdin:
        result = parse_line(line)
        if result:
            writer.writerow(result)
            count += 1
        else:
            errors += 1

    print(f"# Parsed {count} lines, {errors} errors", file=sys.stderr)

if __name__ == '__main__':
    main()
