#!/usr/bin/env python3
"""
Parse Squid proxy logs to CSV format.

Input format:
<134>2020-08-12T00:06:07.829943+00:00 stproxy01 squid[859]: 192.168.2.2 - - [12/Aug/2020:00:06:07 +0000] "GET http://example.com/path HTTP/1.1" 200 2352 "-" "User-Agent" TCP_MISS:HIER_DIRECT
"""

import sys
import re
import csv
from datetime import datetime
from urllib.parse import urlparse

# Regex to parse squid log lines
LOG_PATTERN = re.compile(
    r'<\d+>(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[+-]\d{2}:\d{2})\s+'  # syslog timestamp
    r'\S+\s+squid\[\d+\]:\s+'  # host and process
    r'(\S+)\s+'  # client IP
    r'-\s+-\s+'  # ident and user (usually -)
    r'\[([^\]]+)\]\s+'  # access time
    r'"(\S+)\s+(\S+)\s+[^"]*"\s+'  # method and URL
    r'(\d+)\s+'  # status code
    r'(\d+)\s+'  # bytes
    r'"([^"]*)"\s+'  # referer
    r'"([^"]*)"\s*'  # user agent
    r'(\S+)?'  # squid result code (optional)
)

def parse_line(line):
    """Parse a single proxy log line."""
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None

    (timestamp_str, client_ip, access_time, method, url,
     status, bytes_sent, referer, user_agent, result_code) = match.groups()

    # Parse timestamp
    try:
        timestamp = datetime.fromisoformat(timestamp_str)
        timestamp_utc = timestamp.strftime('%Y-%m-%d %H:%M:%S')
    except:
        timestamp_utc = timestamp_str

    # Parse URL to extract domain
    try:
        if url.startswith('http'):
            parsed = urlparse(url)
            domain = parsed.netloc
            path = parsed.path
        else:
            # CONNECT requests: domain:port
            domain = url.split(':')[0] if ':' in url else url
            path = ''
    except:
        domain = ''
        path = url

    return {
        'timestamp_utc': timestamp_utc,
        'client_ip': client_ip,
        'method': method,
        'domain': domain,
        'url': url[:500],  # Truncate very long URLs
        'status': status,
        'bytes': bytes_sent,
        'user_agent': user_agent[:200],  # Truncate long user agents
        'result_code': result_code or '',
    }

def main():
    fieldnames = ['timestamp_utc', 'client_ip', 'method', 'domain', 'url', 'status', 'bytes', 'user_agent', 'result_code']

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
