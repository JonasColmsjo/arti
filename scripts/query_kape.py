#!/usr/bin/env python3
"""Query KAPE/triage artifacts.

Usage:
    # Phase 1: Overview & Discovery
    query_kape.py files --tier t2          # List large files (starting point)
    query_kape.py live --tier t2           # Live state (system + network)

    # Phase 2: User Activity
    query_kape.py ps-hist --tier t2        # PowerShell history
    query_kape.py timeline --tier t2       # Prefetch timeline (--compact for hour view)
    query_kape.py activities --tier t2     # Windows Timeline (ActivitiesCache.db)
    query_kape.py browser --tier t2        # Browser history (Firefox/Edge)

    # Phase 3: Security Events
    query_kape.py evtx-summary --tier t2   # Count events by ID
    query_kape.py evtx-logons --tier t2    # Logon events (4624)
    query_kape.py evtx-lateral --tier t2   # Explicit credential logons (4648)

    # Phase 4: Detailed Artifacts
    query_kape.py prefetch --tier t2       # Prefetch analysis
    query_kape.py amcache --tier t2        # Amcache entries
    query_kape.py users --tier t2          # User accounts
    query_kape.py services --tier t2       # Windows services
    query_kape.py userassist --tier t2     # UserAssist
    query_kape.py recentdocs --tier t2     # Recent documents
    query_kape.py jumplists --tier t2      # Jump lists

    # Phase 5: Registry Analysis
    query_kape.py registry-overview --tier t2  # Summary of all registry artifacts
    query_kape.py mounted-devices --tier t2    # USB/drive history
    query_kape.py known-networks --tier t2     # WiFi/network profiles
    query_kape.py rdp-history --tier t2        # RDP connections (icslab)
    query_kape.py opensave --tier t2           # File open/save dialogs
    query_kape.py lastvisited --tier t2        # Last visited folder per app
    query_kape.py run-history --tier t2        # Win+R run commands
    query_kape.py shellbags --tier t2          # Folder browsing (raw hive)
    query_kape.py ntuser-autorun --tier t2     # Run/RunOnce persistence keys

    Add --raw to any command for full output without truncation:
    query_kape.py services --tier t2 --raw
"""

import argparse
import csv
import io
import json
import os
import sys
import urllib.request
from collections import defaultdict
from datetime import datetime
from pathlib import Path

# Import tier helpers from forensic_analysis framework
try:
    from forensic_analysis.base import get_work_path, get_available_tiers
except ImportError:
    sys.path.insert(0, str(Path(__file__).parent))
    from forensic_analysis.base import get_work_path, get_available_tiers


def get_kape_path(level: str) -> Path:
    """Get KAPE extractions path for a level."""
    work = get_work_path(level)
    # Check for KAPE-style subfolder (e.g., EWS-VM)
    disk_extractions = work / 'automated/disk/extractions'
    if disk_extractions.exists():
        # Find first subfolder that looks like a KAPE collection
        for item in disk_extractions.iterdir():
            if item.is_dir() and (item / 'ProgramExecution').exists():
                return item
    return disk_extractions


def read_text_file(path: Path) -> str:
    """Read text file handling UTF-16 and UTF-8."""
    with open(path, 'rb') as f:
        content = f.read()

    # Check for UTF-16 BOM
    if content.startswith(b'\xff\xfe') or content.startswith(b'\xfe\xff'):
        try:
            return content.decode('utf-16')
        except:
            pass

    # Try UTF-8
    try:
        return content.decode('utf-8')
    except:
        return content.decode('latin-1', errors='replace')


def read_csv_file(path: Path) -> list:
    """Read CSV file handling various encodings."""
    content = read_text_file(path)
    # Remove BOM if present
    content = content.lstrip('\ufeff')
    reader = csv.DictReader(io.StringIO(content))
    return list(reader)


def find_file(base_path: Path, pattern: str) -> Path:
    """Find first file matching pattern."""
    matches = list(base_path.glob(pattern))
    return matches[0] if matches else None


def find_files(base_path: Path, pattern: str) -> list:
    """Find all files matching pattern."""
    return list(base_path.glob(pattern))


# =============================================================================
# LIVE STATE COMMANDS (L2 KAPE only)
# =============================================================================

def cmd_live(kape_path: Path, raw: bool = False):
    """Show live state - system info, file contents, process list, and network summary."""
    print("=" * 70)
    print("LIVE STATE")
    print("=" * 70)
    print(f"\nKAPE Path: {kape_path}\n")

    # =========================================================================
    # SYSTEM INFO (from SystemInfo.csv) - at top
    # =========================================================================
    sysinfo = kape_path / 'SystemInfo.csv'
    if sysinfo.exists():
        try:
            records = read_csv_file(sysinfo)
            if records:
                r = records[0]
                print("=" * 70)
                print("SYSTEM INFO")
                print("=" * 70)
                fields = [
                    ('Host Name', 'Hostname'),
                    ('OS Name', 'OS'),
                    ('OS Version', 'Version'),
                    ('System Manufacturer', 'Manufacturer'),
                    ('System Model', 'Model'),
                    ('System Type', 'Type'),
                    ('Total Physical Memory', 'RAM'),
                    ('Domain', 'Domain'),
                    ('System Boot Time', 'Boot Time'),
                    ('Original Install Date', 'Install Date'),
                ]
                for csv_field, label in fields:
                    val = r.get(csv_field, '')
                    if val:
                        print(f"  {label:<15}: {val.strip()}")
                print()
        except Exception as e:
            print(f"Error reading SystemInfo: {e}\n")

    # =========================================================================
    # LIVE STATE FILES
    # =========================================================================
    live_files = [
        ('ipconfig.txt', 'IP Configuration'),
        ('arp_cache.txt', 'ARP Cache'),
        ('dns_cache.txt', 'DNS Cache'),
        ('routing_table.txt', 'Routing Table'),
        ('qwinsta.txt', 'Remote Desktop Sessions'),
        ('netbios_cache.txt', 'NetBIOS Cache'),
        ('netbios_sessions.txt', 'NetBIOS Sessions'),
    ]

    for filename, title in live_files:
        path = kape_path / filename
        if path.exists():
            print("=" * 70)
            print(f"FILE: {filename}")
            print("=" * 70)
            content = read_text_file(path)
            for line in content.split('\n'):
                if line.strip():
                    print(line.rstrip())
            print()

    # =========================================================================
    # PROCESS LIST
    # =========================================================================
    proc_file = kape_path / 'PWSH-Get-ProcessList.csv'
    if not proc_file.exists():
        proc_file = kape_path / 'PWSH-Get-CIM_ProcessList.csv'

    if proc_file.exists():
        try:
            records = read_csv_file(proc_file)
            print("=" * 70)
            print(f"PROCESS LIST ({len(records)} processes)")
            print("=" * 70)

            by_name = defaultdict(list)
            for r in records:
                name = r.get('ProcessName', r.get('Name', 'Unknown'))
                by_name[name].append(r)

            print(f"\n{'Process':<30} {'Count':>6} {'PIDs'}")
            print("-" * 70)

            limit = None if raw else 30
            for name, procs in sorted(by_name.items(), key=lambda x: -len(x[1]))[:limit]:
                pids = [r.get('ProcessID', r.get('Id', '?')) for r in procs[:5]]
                pid_str = ', '.join(str(p) for p in pids)
                if len(procs) > 5:
                    pid_str += f' (+{len(procs)-5})'
                print(f"{name:<30} {len(procs):>6} {pid_str}")

            if not raw and len(by_name) > 30:
                print(f"  ... ({len(by_name) - 30} more unique processes)")
            print()
        except Exception as e:
            print(f"Error reading process list: {e}\n")

    # =========================================================================
    # NETWORK SUMMARY (at bottom)
    # =========================================================================
    netconn = kape_path / 'network_connections.txt'
    if netconn.exists():
        print("=" * 70)
        print("NETWORK SUMMARY")
        print("=" * 70)
        content = read_text_file(netconn)
        lines = [l.strip() for l in content.split('\n') if l.strip()]

        # Count connection states
        established = [l for l in lines if 'ESTABLISHED' in l.upper()]
        listening = [l for l in lines if 'LISTENING' in l.upper() or 'LISTEN' in l.upper()]
        time_wait = [l for l in lines if 'TIME_WAIT' in l.upper()]

        limit = None if raw else 15

        print(f"\n  ESTABLISHED: {len(established)}")
        for line in established[:limit]:
            clean = ' '.join(line.split())
            print(f"    {clean}")
        if not raw and len(established) > 15:
            print(f"    ... ({len(established) - 15} more)")

        print(f"\n  LISTENING: {len(listening)}")
        for line in listening[:limit]:
            clean = ' '.join(line.split())
            print(f"    {clean}")
        if not raw and len(listening) > 15:
            print(f"    ... ({len(listening) - 15} more)")

        if time_wait:
            print(f"\n  TIME_WAIT: {len(time_wait)}")
        print()


def cmd_live_process(kape_path: Path, raw: bool = False):
    """Show process list at capture time (standalone command)."""
    print("=" * 70)
    print("PROCESS LIST")
    print("=" * 70)

    proc_file = kape_path / 'PWSH-Get-ProcessList.csv'
    if not proc_file.exists():
        proc_file = kape_path / 'PWSH-Get-CIM_ProcessList.csv'

    if not proc_file.exists():
        print("\nNo process list found.")
        return

    try:
        records = read_csv_file(proc_file)
    except Exception as e:
        print(f"\nError reading process list: {e}")
        return

    print(f"\nTotal processes: {len(records)}\n")

    by_name = defaultdict(list)
    for r in records:
        name = r.get('ProcessName', r.get('Name', 'Unknown'))
        by_name[name].append(r)

    print(f"{'Process':<30} {'Count':>6} {'PIDs'}")
    print("-" * 70)

    limit = None if raw else 30
    for name, procs in sorted(by_name.items(), key=lambda x: -len(x[1]))[:limit]:
        pids = [r.get('ProcessID', r.get('Id', '?')) for r in procs[:5]]
        pid_str = ', '.join(str(p) for p in pids)
        if len(procs) > 5:
            pid_str += f' (+{len(procs)-5})'
        print(f"{name:<30} {len(procs):>6} {pid_str}")

    if not raw and len(by_name) > 30:
        print(f"\n  ... ({len(by_name) - 30} more unique processes)")


def _parse_wmi_datetime(val: str, utc: bool = True) -> str:
    """Convert WMI datetime (20201102101533.452742-240) to readable string.

    utc=True  → '2020-11-02 14:15:33 UTC'
    utc=False → '2020-11-02 10:15:33' (local time as recorded)
    """
    import re
    m = re.match(r'^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})\.(\d+)([+-]\d+)$', val)
    if not m:
        return val
    y, mo, d, h, mi, s = (int(x) for x in m.groups()[:6])
    if not utc:
        return f'{y:04d}-{mo:02d}-{d:02d} {h:02d}:{mi:02d}:{s:02d}'
    from datetime import datetime, timedelta, timezone
    offset_min = int(m.group(8))
    tz = timezone(timedelta(minutes=offset_min))
    dt = datetime(y, mo, d, h, mi, s, tzinfo=tz)
    dt_utc = dt.astimezone(timezone.utc)
    return dt_utc.strftime('%Y-%m-%d %H:%M:%S UTC')


def cmd_ps(kape_path: Path, raw: bool = False):
    """Show both process list CSVs from KAPE collection snapshot."""
    csv_files = [
        ('PWSH-Get-CIM_ProcessList.csv', 'CIM (Get-CimInstance Win32_Process)', False,
         ['ProcessId', 'ProcessName', 'Path', 'CommandLine', 'ParentProcessId', 'CreationDate', 'File Path MD-5']),
        ('PWSH-Get-ProcessList.csv', 'Get-Process', True,
         ['ProcessID', 'Name', 'Path', 'commandline', 'Owner', 'CreationDate', 'Security ID', 'ParentProcessId',
          'Company', 'Description', 'File Path SHA-256']),
    ]

    for fname, label, has_wmi_ts, columns in csv_files:
        print("=" * 70)
        print(f"PROCESS SNAPSHOT — {label}")
        print(f"  File: {fname}")
        print("=" * 70)

        fpath = kape_path / fname
        if not fpath.exists():
            print(f"\n  Not found: {fpath}\n")
            continue

        try:
            records = read_csv_file(fpath)
        except Exception as e:
            print(f"\n  Error reading: {e}\n")
            continue

        print(f"\n  Total processes: {len(records)}\n")

        # Determine which columns actually exist
        available = [c for c in columns if any(r.get(c) for r in records[:5])]
        # Always include key columns
        key_cols = ['ProcessId', 'ProcessID', 'ProcessName', 'Name']
        show_cols = []
        for c in columns:
            if c in available or c in key_cols:
                if c not in show_cols:
                    show_cols.append(c)

        # Print header
        widths = {}
        for c in show_cols:
            max_val = max((len(str(r.get(c, ''))) for r in records), default=0)
            widths[c] = max(min(max_val, 60), len(c))

        # For raw mode show all; otherwise show key fields in a compact table
        if raw:
            hdr = '  '.join(f"{c:<{widths[c]}}" for c in show_cols)
            print(hdr)
            print('-' * len(hdr))
            for r in records:
                vals = []
                for c in show_cols:
                    v = str(r.get(c, ''))
                    if c == 'CreationDate':
                        v = _parse_wmi_datetime(v)
                    if len(v) > 60:
                        v = v[:57] + '...'
                    vals.append(f"{v:<{widths[c]}}")
                print('  '.join(vals))
        else:
            pid_key = 'ProcessId' if 'ProcessId' in columns[0] else 'ProcessID'
            name_key = 'ProcessName' if 'ProcessName' in show_cols else 'Name'
            if has_wmi_ts:
                print(f"  {'PID':>6}  {'Name':<25} {'Local':<20} {'UTC':<22} {'CommandLine'}")
                print(f"  {'':->6}  {'':->25} {'':->20} {'':->22} {'':->50}")
                for r in records:
                    pid = r.get(pid_key, r.get('ProcessID', r.get('ProcessId', '?')))
                    name = r.get(name_key, r.get('Name', r.get('ProcessName', '?')))
                    raw_ts = r.get('CreationDate', '')
                    local_ts = _parse_wmi_datetime(raw_ts, utc=False)
                    utc_ts = _parse_wmi_datetime(raw_ts, utc=True)
                    cmdline = r.get('CommandLine', r.get('commandline', ''))
                    if len(cmdline) > 70:
                        cmdline = cmdline[:67] + '...'
                    print(f"  {str(pid):>6}  {name:<25} {local_ts:<20} {utc_ts:<22} {cmdline}")
            else:
                print(f"  {'PID':>6}  {'Name':<25} {'Created (local)':<22} {'CommandLine'}")
                print(f"  {'':->6}  {'':->25} {'':->22} {'':->50}")
                for r in records:
                    pid = r.get(pid_key, r.get('ProcessID', r.get('ProcessId', '?')))
                    name = r.get(name_key, r.get('Name', r.get('ProcessName', '?')))
                    created = r.get('CreationDate', '')
                    cmdline = r.get('CommandLine', r.get('commandline', ''))
                    if len(cmdline) > 80:
                        cmdline = cmdline[:77] + '...'
                    print(f"  {str(pid):>6}  {name:<25} {created:<22} {cmdline}")

        print()

    # --- NSRL correlation: cross-reference processes against Amcache entries ---
    # Amcache AssociatedFileEntries contains vendor/ICS binaries (mostly not in NSRL).
    # Processes WITH an Amcache entry = vendor software; WITHOUT = OS/Microsoft.
    af_files = find_files(kape_path, '**/*Amcache*AssociatedFileEntries*.csv')
    if not af_files:
        return

    # Build lookup: exe name (lower) -> (Name, FullPath, ProductName, SHA1)
    amcache_by_name = {}
    for af in af_files:
        try:
            for r in read_csv_file(af):
                name = r.get('Name', '').strip()
                if name:
                    amcache_by_name[name.lower()] = {
                        'name': name,
                        'path': r.get('FullPath', ''),
                        'product': r.get('ProductName', ''),
                        'sha1': r.get('SHA1', ''),
                    }
        except Exception:
            pass

    if not amcache_by_name:
        return

    # Read CIM process list for correlation (richer data)
    cim_path = kape_path / 'PWSH-Get-CIM_ProcessList.csv'
    if not cim_path.exists():
        return
    try:
        procs = read_csv_file(cim_path)
    except Exception:
        return

    # Match processes to amcache
    matched = []
    unmatched = []
    for p in procs:
        pname = p.get('ProcessName', '')
        pid = p.get('ProcessId', '')
        created = p.get('CreationDate', '')
        cmd = p.get('CommandLine', '')
        exe_key = pname.lower()
        if not exe_key.endswith('.exe'):
            exe_key += '.exe'
        amc = amcache_by_name.get(exe_key)
        if amc:
            matched.append((created, pid, pname, amc['product'], amc['path']))
        else:
            unmatched.append((created, pid, pname, p.get('Path', ''), cmd))

    print("=" * 70)
    print("PROCESS vs AMCACHE CORRELATION (not-in-NSRL check)")
    print("=" * 70)
    print(f"\n  Amcache binaries (mostly not in NSRL): {len(amcache_by_name)}")
    print(f"  Running processes with Amcache match:  {len(matched)}  (vendor/ICS software)")
    print(f"  Running processes without match:        {len(unmatched)}  (OS/Microsoft/other)\n")

    matched.sort()
    print("  ### VENDOR/ICS PROCESSES (in Amcache, likely not in NSRL) ###\n")
    print(f"  {'PID':>6}  {'Process':<30} {'Created (local)':<24} {'Product'}")
    print(f"  {'':->6}  {'':->30} {'':->24} {'':->40}")
    for created, pid, pname, product, path in matched:
        prod = product[:38] if product else ''
        print(f"  {pid:>6}  {pname:<30} {created:<24} {prod}")

    if raw:
        unmatched.sort()
        print(f"\n  ### OS/MICROSOFT PROCESSES (no Amcache entry) ###\n")
        print(f"  {'PID':>6}  {'Process':<30} {'Created (local)':<24} {'Path'}")
        print(f"  {'':->6}  {'':->30} {'':->24} {'':->60}")
        for created, pid, pname, path, cmd in unmatched:
            p = path[:58] if path else ''
            print(f"  {pid:>6}  {pname:<30} {created:<24} {p}")

    print()


# =============================================================================
# PROGRAM EXECUTION COMMANDS
# =============================================================================

def cmd_dlls(kape_path: Path, search: str = None, raw: bool = False,
             from_date: str = None, to_date: str = None):
    """Show DLLs loaded by processes (from Prefetch), flagging non-system paths.

    Cross-references Prefetch FilesLoaded with running process list.
    Without $MFT, per-DLL creation dates are unavailable; timestamps shown
    are the Prefetch source file dates (when the .pf was created/modified).
    """
    SYSTEM_PREFIXES = (
        'WINDOWS\\SYSTEM32', 'WINDOWS\\SYSWOW64', 'WINDOWS\\WINSXS',
        'WINDOWS\\FONTS', 'WINDOWS\\GLOBALIZATION', 'WINDOWS\\APPPATCH',
        'WINDOWS\\ASSEMBLY', 'WINDOWS\\MICROSOFT.NET',
        'PROGRAM FILES\\COMMON FILES\\SYSTEM',
        'PROGRAM FILES (X86)\\COMMON FILES\\SYSTEM',
    )

    # Load running processes
    cim_path = kape_path / 'PWSH-Get-CIM_ProcessList.csv'
    running = set()
    if cim_path.exists():
        try:
            for r in read_csv_file(cim_path):
                pn = r.get('ProcessName', '').upper()
                running.add(pn if pn.endswith('.EXE') else pn + '.EXE')
        except Exception:
            pass

    # Load Prefetch data
    pe_files = find_files(kape_path, '**/*PECmd_Output.csv')
    if not pe_files:
        print("No Prefetch data found.")
        return

    all_pf = []
    for pf in pe_files:
        try:
            all_pf.extend(read_csv_file(pf))
        except Exception:
            pass

    # Filter by search term or running processes
    if search:
        s = search.upper()
        entries = [r for r in all_pf
                   if s in r.get('ExecutableName', '').upper()
                   or s in r.get('FilesLoaded', '').upper()]
    else:
        # Default: only running processes
        entries = [r for r in all_pf if r.get('ExecutableName', '').upper() in running]

    # Filter by date range (based on LastRun UTC timestamp)
    if from_date:
        entries = [r for r in entries if r.get('LastRun', '') >= from_date]
    if to_date:
        entries = [r for r in entries if r.get('LastRun', '') <= to_date + ' 23:59:59']

    def strip_vol(path):
        """Remove volume prefix like \\VOLUME{...}\\"""
        p = path.strip()
        if '}\\' in p:
            p = p.split('}\\', 1)[1]
        return p

    def is_system(path):
        up = path.upper()
        return any(up.startswith(sp) for sp in SYSTEM_PREFIXES)

    def utc_and_local(ts_str):
        """Return '(UTC) / (local)' string from a UTC timestamp like '2020-11-05 22:31:32'."""
        from datetime import datetime, timedelta
        try:
            dt = datetime.strptime(ts_str[:19], '%Y-%m-%d %H:%M:%S')
            # EWS-VM was EST (UTC-5) after Nov 1 2020 DST change, EDT (UTC-4) before
            # Use -5 for Nov dates, -4 for earlier
            offset = 5 if dt.month >= 11 else 4
            local = dt - timedelta(hours=offset)
            return f"{ts_str[:19]} UTC / {local.strftime('%H:%M:%S')} local"
        except Exception:
            return ts_str

    print("=" * 70)
    print("DLL LOAD ANALYSIS (from Prefetch)")
    print("=" * 70)
    if search:
        print(f"  Filter: {search}")
    else:
        print(f"  Showing: running processes only (use search term for others)")
    if from_date or to_date:
        print(f"  Date range: {from_date or '...'} to {to_date or '...'}")
    print(f"  Timestamps (UTC) = process execution time (when DLL was loaded)")
    print(f"  Entries: {len(entries)}\n")

    # Collect non-system DLLs across all entries for summary
    all_nonsys = []

    for r in sorted(entries, key=lambda x: x.get('ExecutableName', '')):
        exe = r.get('ExecutableName', '')
        lastrun = r.get('LastRun', '')
        src_created = r.get('SourceCreated', '')
        src_modified = r.get('SourceModified', '')
        files_loaded = r.get('FilesLoaded', '')
        if not files_loaded:
            continue

        dlls = [strip_vol(f) for f in files_loaded.split(',') if f.strip()]
        non_sys = [d for d in dlls if not is_system(d)]
        sys_count = len(dlls) - len(non_sys)

        in_running = '(RUNNING)' if exe.upper() in running else ''

        if not raw and not non_sys:
            continue  # Skip processes that only loaded system DLLs in compact mode

        print(f"  {exe} {in_running}")
        print(f"    Last run: {utc_and_local(lastrun)}")
        print(f"    PF created: {src_created}  |  PF modified: {src_modified}")
        print(f"    DLLs loaded: {len(dlls)} total ({sys_count} system, {len(non_sys)} non-system)")

        if non_sys:
            print(f"    ### NON-SYSTEM FILES ###")
            for d in sorted(non_sys):
                print(f"      * {utc_and_local(lastrun)}  {d}")
                all_nonsys.append((exe, d, lastrun))

        if raw:
            print(f"    ### ALL FILES ###")
            for d in sorted(dlls):
                marker = ' ' if is_system(d) else '*'
                print(f"      {marker} {utc_and_local(lastrun)}  {d}")

        print()

    # Summary of non-system loads
    if all_nonsys:
        print("=" * 70)
        print(f"SUMMARY: {len(all_nonsys)} non-system file loads across {len(set(e for e,_,_ in all_nonsys))} processes")
        print("=" * 70)
        # Group by directory
        from collections import defaultdict
        by_dir = defaultdict(list)
        for exe, path, ts in all_nonsys:
            parts = path.rsplit('\\', 1)
            d = parts[0] if len(parts) > 1 else '(root)'
            by_dir[d].append((ts, exe, parts[-1] if len(parts) > 1 else path))

        for d in sorted(by_dir):
            print(f"\n  {d}")
            for ts, exe, fname in sorted(set(by_dir[d])):
                print(f"    {utc_and_local(ts)}  {fname:<40} <- {exe}")
    else:
        print("\n  No non-system DLL loads detected.")

    # --- DLL usage stats across ALL Prefetch entries ---
    from collections import defaultdict as dd
    dll_stats = dd(set)  # dll_name -> set of exes that loaded it
    for r in all_pf:
        exe = r.get('ExecutableName', '')
        files_loaded = r.get('FilesLoaded', '')
        if not files_loaded:
            continue
        for f in files_loaded.split(','):
            f = strip_vol(f.strip())
            if f:
                dll_stats[f].add(exe)

    if not dll_stats:
        return

    print("\n" + "=" * 70)
    print(f"DLL USAGE STATS (across all {len(all_pf)} Prefetch entries)")
    print("=" * 70)

    # Sort by load count descending
    ranked = sorted(dll_stats.items(), key=lambda x: -len(x[1]))
    total_dlls = len(ranked)
    sys_dlls = [d for d, _ in ranked if is_system(d)]
    nonsys_dlls = [d for d, _ in ranked if not is_system(d)]
    print(f"  Unique files loaded: {total_dlls} ({len(sys_dlls)} system, {len(nonsys_dlls)} non-system)")

    # Filter stats by search term if given
    if search:
        s = search.upper()
        ranked = [(d, exes) for d, exes in ranked if s in d.upper() or any(s in e.upper() for e in exes)]

    # Top loaded (system) - show top 20
    print(f"\n  ### TOP SYSTEM DLLs (loaded by most executables) ###\n")
    print(f"  {'Count':>5}  {'DLL'}")
    print(f"  {'':->5}  {'':->65}")
    shown = 0
    for dll, exes in ranked:
        if not is_system(dll):
            continue
        if not raw and shown >= 20:
            break
        print(f"  {len(exes):>5}  {dll}")
        shown += 1
    if not raw and shown < len(sys_dlls):
        print(f"  ... ({len(sys_dlls) - shown} more, use --raw for all)")

    # Non-system DLLs - always show all with the exes that loaded them
    print(f"\n  ### NON-SYSTEM FILES (by load count) ###\n")
    print(f"  {'Count':>5}  {'File':<55} {'Loaded by'}")
    print(f"  {'':->5}  {'':->55} {'':->50}")
    for dll, exes in ranked:
        if is_system(dll):
            continue
        exe_list = ', '.join(sorted(exes))
        if not raw and len(exe_list) > 50:
            exe_list = exe_list[:47] + '...'
        print(f"  {len(exes):>5}  {dll:<55} {exe_list}")

    # Files loaded by only 1 executable (potentially unique/suspicious)
    unique_loads = [(d, list(exes)[0]) for d, exes in ranked if len(exes) == 1 and not is_system(d)]
    if unique_loads:
        print(f"\n  ### UNIQUE NON-SYSTEM LOADS (loaded by only 1 executable) ###\n")
        print(f"  {'Executable':<35} {'File'}")
        print(f"  {'':->35} {'':->60}")
        for dll, exe in sorted(unique_loads, key=lambda x: x[1]):
            print(f"  {exe:<35} {dll}")


def cmd_dll_timeline(kape_path: Path, hourly: bool = False, raw: bool = False,
                     from_date: str = None, to_date: str = None):
    """Show DLL load counts over time, split by system vs non-system.

    Groups by date (default) or hour (--hourly). Each row shows how many
    system and non-system DLLs were loaded across all Prefetch entries
    whose LastRun falls in that bucket.
    """
    from collections import defaultdict
    from datetime import datetime, timedelta

    SYSTEM_PREFIXES = (
        'WINDOWS\\SYSTEM32', 'WINDOWS\\SYSWOW64', 'WINDOWS\\WINSXS',
        'WINDOWS\\FONTS', 'WINDOWS\\GLOBALIZATION', 'WINDOWS\\APPPATCH',
        'WINDOWS\\ASSEMBLY', 'WINDOWS\\MICROSOFT.NET',
        'PROGRAM FILES\\COMMON FILES\\SYSTEM',
        'PROGRAM FILES (X86)\\COMMON FILES\\SYSTEM',
    )

    def strip_vol(path):
        p = path.strip()
        if '}\\' in p:
            p = p.split('}\\', 1)[1]
        return p

    def is_system(path):
        up = path.upper()
        return any(up.startswith(sp) for sp in SYSTEM_PREFIXES)

    def to_local(dt):
        offset = 5 if dt.month >= 11 else 4
        return dt - timedelta(hours=offset)

    # Load Prefetch data
    pe_files = find_files(kape_path, '**/*PECmd_Output.csv')
    if not pe_files:
        print("No Prefetch data found.")
        return

    all_pf = []
    for pf in pe_files:
        try:
            all_pf.extend(read_csv_file(pf))
        except Exception:
            pass

    # Filter by date range
    if from_date:
        all_pf = [r for r in all_pf if r.get('LastRun', '') >= from_date]
    if to_date:
        all_pf = [r for r in all_pf if r.get('LastRun', '') <= to_date + ' 23:59:59']

    if not all_pf:
        print("No Prefetch entries in the specified range.")
        return

    # Bucket key: date or date+hour
    def bucket_key(ts_str):
        try:
            dt = datetime.strptime(ts_str[:19], '%Y-%m-%d %H:%M:%S')
            if hourly:
                return dt.strftime('%Y-%m-%d %H:00')
            else:
                return dt.strftime('%Y-%m-%d')
        except Exception:
            return None

    def bucket_key_local(ts_str):
        try:
            dt = datetime.strptime(ts_str[:19], '%Y-%m-%d %H:%M:%S')
            loc = to_local(dt)
            if hourly:
                return loc.strftime('%Y-%m-%d %H:00')
            else:
                return loc.strftime('%Y-%m-%d')
        except Exception:
            return None

    # Count DLLs per bucket (keyed by UTC)
    # Each bucket tracks: sys_dll_count, nonsys_dll_count, exe_names, local_key
    buckets = defaultdict(lambda: {'sys': 0, 'nonsys': 0, 'exes': set(), 'local': ''})

    for r in all_pf:
        lastrun = r.get('LastRun', '')
        exe = r.get('ExecutableName', '')
        files_loaded = r.get('FilesLoaded', '')
        if not files_loaded or not lastrun:
            continue

        bk_utc = bucket_key(lastrun)
        bk_local = bucket_key_local(lastrun)

        dlls = [strip_vol(f) for f in files_loaded.split(',') if f.strip()]
        sys_count = sum(1 for d in dlls if is_system(d))
        nonsys_count = len(dlls) - sys_count

        if bk_utc:
            buckets[bk_utc]['sys'] += sys_count
            buckets[bk_utc]['nonsys'] += nonsys_count
            buckets[bk_utc]['exes'].add(exe)
            if bk_local:
                buckets[bk_utc]['local'] = bk_local

    granularity = 'hour' if hourly else 'date'
    print("=" * 90)
    print(f"DLL LOAD TIMELINE (by {granularity})")
    print("=" * 90)
    if from_date or to_date:
        print(f"  Date range: {from_date or '...'} to {to_date or '...'}")
    print(f"  Prefetch entries: {len(all_pf)}")
    print(f"  Counts = total DLL/file references loaded per execution in each bucket\n")

    # Determine column widths based on granularity
    tw = 16 if hourly else 10  # time column width
    utc_hdr = 'UTC'
    local_hdr = 'Local (EST)'

    print(f"  {utc_hdr:<{tw}}  {local_hdr:<{tw}}  {'Exes':>5}  {'System':>7}  {'Non-Sys':>7}  {'Total':>7}  {'Bar'}")
    print(f"  {'':->{tw}}  {'':->{tw}}  {'':->5}  {'':->7}  {'':->7}  {'':->7}  {'':->25}")
    max_total = max((v['sys'] + v['nonsys'] for v in buckets.values()), default=1)
    for bk in sorted(buckets):
        v = buckets[bk]
        total = v['sys'] + v['nonsys']
        bar_len = int(25 * total / max_total) if max_total else 0
        sys_bar = int(25 * v['sys'] / max_total) if max_total else 0
        nonsys_bar = bar_len - sys_bar
        bar = '█' * sys_bar + '░' * nonsys_bar
        local_str = v['local'] or ''
        print(f"  {bk:<{tw}}  {local_str:<{tw}}  {len(v['exes']):>5}  {v['sys']:>7}  {v['nonsys']:>7}  {total:>7}  {bar}")

    # Show which executables ran in each bucket (with --raw)
    if raw:
        print(f"\n  ### EXECUTABLES PER BUCKET (UTC) ###")
        for bk in sorted(buckets):
            v = buckets[bk]
            local_str = v['local'] or ''
            print(f"\n  {bk}  ({local_str} local)  —  {len(v['exes'])} executables")
            for e in sorted(v['exes']):
                print(f"    {e}")

    print(f"\n  Legend: █ = system DLLs, ░ = non-system DLLs")


def cmd_prefetch(kape_path: Path, search: str = None, raw: bool = False):
    """Show prefetch analysis."""
    print("=" * 70)
    print("PREFETCH ANALYSIS")
    print("=" * 70)

    # Find PECmd output (handles timestamped filenames like 20201111_PECmd_Output.csv)
    pe_files = find_files(kape_path, '**/*PECmd_Output.csv') or \
               find_files(kape_path, '**/*prefetch*.csv')

    if not pe_files:
        print("\nNo prefetch data found.")
        return

    all_records = []
    for pf in pe_files:
        try:
            records = read_csv_file(pf)
            all_records.extend(records)
        except:
            pass

    if not all_records:
        print("\nNo prefetch records parsed.")
        return

    # Filter if search term provided
    if search:
        search_lower = search.lower()
        all_records = [r for r in all_records
                       if search_lower in r.get('ExecutableName', '').lower() or
                          search_lower in r.get('SourceFilename', '').lower()]
        print(f"\nFiltered by: {search}")

    print(f"\nTotal entries: {len(all_records)}\n")

    print(f"{'Run Count':>10} {'Last Run':<20} {'Executable'}")
    print("-" * 70)

    # Sort by run count descending
    limit = None if raw else 40
    sorted_records = sorted(all_records, key=lambda x: int(x.get('RunCount', 0)), reverse=True)
    for r in sorted_records[:limit]:
        name = r.get('ExecutableName', r.get('SourceFilename', 'Unknown'))
        count = r.get('RunCount', '?')
        last_run = r.get('LastRun', r.get('SourceModified', ''))[:19]
        print(f"{count:>10} {last_run:<20} {name}")

    if not raw and len(all_records) > 40:
        print(f"\n  ... ({len(all_records) - 40} more entries)")


def cmd_amcache(kape_path: Path, search: str = None, raw: bool = False):
    """Show Amcache program entries."""
    print("=" * 70)
    print("AMCACHE PROGRAMS")
    print("=" * 70)

    # Find Amcache files
    am_files = find_files(kape_path, '**/*Amcache_ProgramEntries*.csv')

    if not am_files:
        print("\nNo Amcache data found.")
        return

    all_records = []
    for af in am_files:
        try:
            records = read_csv_file(af)
            all_records.extend(records)
        except:
            pass

    if search:
        search_lower = search.lower()
        all_records = [r for r in all_records
                       if search_lower in r.get('Name', '').lower() or
                          search_lower in r.get('Publisher', '').lower()]
        print(f"\nFiltered by: {search}")

    print(f"\nTotal programs: {len(all_records)}\n")

    print(f"{'Install Date':<12} {'Publisher':<30} {'Name'}")
    print("-" * 80)

    limit = None if raw else 40
    sorted_records = sorted(all_records, key=lambda x: x.get('InstallDate', ''), reverse=True)
    for r in sorted_records[:limit]:
        name = r.get('Name', 'Unknown') if raw else r.get('Name', 'Unknown')[:40]
        publisher = r.get('Publisher', '') if raw else r.get('Publisher', '')[:28]
        install = r.get('InstallDate', '')[:10]
        print(f"{install:<12} {publisher:<30} {name}")

    if not raw and len(all_records) > 40:
        print(f"\n  ... ({len(all_records) - 40} more entries)")


def cmd_amcache_hash_check(kape_path: Path, raw: bool = False):
    """Check Amcache SHA1 hashes against CIRCL hashlookup (NSRL database)."""
    print("=" * 70)
    print("AMCACHE HASH CHECK (CIRCL hashlookup)")
    print("=" * 70)

    # Load AssociatedFileEntries (has SHA1 per binary)
    af_files = find_files(kape_path, '**/*Amcache_AssociatedFileEntries*.csv')
    if not af_files:
        print("\nNo Amcache AssociatedFileEntries data found.")
        return

    entries = []
    seen_sha1 = set()
    for af in af_files:
        try:
            for r in read_csv_file(af):
                sha1 = r.get('SHA1', '').strip().lower()
                if not sha1 or sha1 in seen_sha1:
                    continue
                seen_sha1.add(sha1)
                entries.append({
                    'sha1': sha1,
                    'name': r.get('Name', ''),
                    'full_path': r.get('FullPath', ''),
                    'product': r.get('ProductName', ''),
                })
        except Exception:
            pass

    if not entries:
        print("\nNo SHA1 hashes found in Amcache data.")
        return

    # Bulk lookup via CIRCL hashlookup
    sha1_list = [e['sha1'] for e in entries]
    print(f"\nLooking up {len(sha1_list)} unique SHA1 hashes against CIRCL NSRL database...")

    try:
        req_data = json.dumps({"hashes": sha1_list}).encode()
        req = urllib.request.Request(
            'https://hashlookup.circl.lu/bulk/sha1',
            data=req_data,
            headers={'Content-Type': 'application/json', 'Accept': 'application/json'},
            method='POST',
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            results = json.loads(resp.read().decode())
    except Exception as e:
        print(f"\nError querying CIRCL hashlookup: {e}")
        return

    # Build set of known hashes from response (API returns uppercase SHA-1)
    known_hashes = set()
    known_info = {}
    for item in results:
        sha1 = item.get('SHA-1', '').strip().lower()
        if sha1:
            known_hashes.add(sha1)
            known_info[sha1] = item.get('FileName', '')

    known = [e for e in entries if e['sha1'] in known_hashes]
    unknown = [e for e in entries if e['sha1'] not in known_hashes]

    print(f"\nKNOWN (in NSRL):   {len(known)}")
    print(f"UNKNOWN (not in NSRL): {len(unknown)}  <- investigate these\n")

    if unknown:
        print("### UNKNOWN BINARIES (not in NSRL) ###\n")
        print(f"{'SHA1':<42} {'Name':<28} {'Product'}")
        print("-" * 100)
        for e in sorted(unknown, key=lambda x: x['name']):
            name = e['name'] if raw else e['name'][:26]
            product = e['product'] if raw else e['product'][:28]
            print(f"{e['sha1']:<42} {name:<28} {product}")
        if not raw:
            print(f"\nUse --raw for full paths and untruncated names.")

    if raw and known:
        print(f"\n### KNOWN BINARIES (in NSRL) ###\n")
        print(f"{'SHA1':<42} {'Name':<28} {'Product'}")
        print("-" * 100)
        for e in sorted(known, key=lambda x: x['name']):
            print(f"{e['sha1']:<42} {e['name']:<28} {e['product']}")


# =============================================================================
# REGISTRY COMMANDS
# =============================================================================

def cmd_users(kape_path: Path):
    """Show user accounts."""
    print("=" * 70)
    print("USER ACCOUNTS")
    print("=" * 70)

    user_files = find_files(kape_path, '**/*UserAccounts*.csv')

    if not user_files:
        print("\nNo user account data found.")
        return

    all_records = []
    for uf in user_files:
        try:
            records = read_csv_file(uf)
            all_records.extend(records)
        except:
            pass

    print(f"\n{'User':<20} {'UID':>6} {'Logins':>8} {'Groups'}")
    print("-" * 70)

    for r in all_records:
        user = r.get('UserName', 'Unknown')
        uid = r.get('UserId', '?')
        logins = r.get('TotalLoginCount', '0')
        groups = r.get('Groups', '')[:30]
        disabled = r.get('AccountDisabled', 'FALSE')
        status = ' [DISABLED]' if disabled.upper() == 'TRUE' else ''
        print(f"{user:<20} {uid:>6} {logins:>8} {groups}{status}")


def cmd_services(kape_path: Path, search: str = None, raw: bool = False):
    """Show Windows services."""
    print("=" * 70)
    print("WINDOWS SERVICES")
    print("=" * 70)

    svc_files = find_files(kape_path, '**/*Services*.csv')

    if not svc_files:
        print("\nNo services data found.")
        return

    all_records = []
    for sf in svc_files:
        try:
            records = read_csv_file(sf)
            all_records.extend(records)
        except:
            pass

    if search:
        search_lower = search.lower()
        all_records = [r for r in all_records
                       if search_lower in r.get('Name', '').lower() or
                          search_lower in r.get('ImagePath', '').lower()]
        print(f"\nFiltered by: {search}")

    print(f"\nTotal services: {len(all_records)}\n")

    # Group by start type
    by_start = defaultdict(list)
    for r in all_records:
        start = r.get('StartMode', r.get('Start', 'Unknown'))
        by_start[start].append(r)

    limit = None if raw else 10
    for start_type in ['Auto', 'Automatic', 'Manual', 'Disabled', 'System', 'Boot']:
        services = by_start.get(start_type, [])
        if services:
            print(f"\n### {start_type.upper()} ({len(services)}) ###")
            for r in services[:limit]:
                name = r.get('Name', 'Unknown') if raw else r.get('Name', 'Unknown')[:30]
                path = r.get('ImagePath', '') if raw else r.get('ImagePath', '')[:40]
                print(f"  {name:<30} {path}")
            if not raw and len(services) > 10:
                print(f"  ... ({len(services) - 10} more)")


def cmd_userassist(kape_path: Path, raw: bool = False):
    """Show UserAssist (GUI program execution)."""
    print("=" * 70)
    print("USERASSIST (GUI EXECUTION)")
    print("=" * 70)

    ua_files = find_files(kape_path, '**/*UserAssist*.csv')

    if not ua_files:
        print("\nNo UserAssist data found.")
        return

    all_records = []
    for uf in ua_files:
        try:
            records = read_csv_file(uf)
            all_records.extend(records)
        except:
            pass

    print(f"\nTotal entries: {len(all_records)}\n")

    print(f"{'Count':>6} {'Last Run':<20} {'Program'}")
    print("-" * 70)

    limit = None if raw else 40
    sorted_records = sorted(all_records, key=lambda x: int(x.get('RunCounter', 0)), reverse=True)
    for r in sorted_records[:limit]:
        name = r.get('ProgramName', r.get('Name', 'Unknown'))
        # Clean up GUID paths
        if '{' in name:
            name = name.split('}')[-1].lstrip('\\')
        if not raw:
            name = name[:50]
        count = r.get('RunCounter', '?')
        last = r.get('LastExecuted', '')[:19]
        print(f"{count:>6} {last:<20} {name}")

    if not raw and len(all_records) > 40:
        print(f"\n  ... ({len(all_records) - 40} more entries)")


def cmd_fstimeline(kape_path: Path, search: str = None, raw: bool = False):
    """Build file system timeline from all available sources (no raw $MFT needed).

    Consolidates timestamps from: LECmd (LNK targets), Amcache (file entries),
    Prefetch (execution times). Sorted chronologically.
    """
    from datetime import datetime
    events = []  # list of (datetime_str, source, path_or_name, detail)

    # 1. LECmd — LNK target timestamps
    lnk_files = find_files(kape_path, '**/*LECmd_Output*.csv')
    for f in (lnk_files or []):
        try:
            for r in read_csv_file(f):
                local_path = r.get('LocalPath', '') or r.get('TargetIDAbsolutePath', '')
                if not local_path:
                    continue
                for ts_field, ts_type in [('TargetCreated', 'Created'),
                                           ('TargetModified', 'Modified'),
                                           ('TargetAccessed', 'Accessed')]:
                    ts = r.get(ts_field, '')
                    if ts:
                        events.append((ts, 'LNK', local_path, ts_type))
        except Exception:
            pass

    # 2. Amcache AssociatedFileEntries — file reference timestamps
    amc_files = find_files(kape_path, '**/*Amcache*AssociatedFileEntries*.csv')
    for f in (amc_files or []):
        try:
            for r in read_csv_file(f):
                name = r.get('Name', '') or r.get('FileName', '')
                full_path = r.get('FullPath', '') or r.get('FilePath', '') or name
                for ts_field, ts_type in [('FileKeyLastWriteTimestamp', 'Amcache-LastWrite'),
                                           ('LinkDate', 'Amcache-LinkDate')]:
                    ts = r.get(ts_field, '')
                    if ts:
                        events.append((ts, 'Amcache', full_path, ts_type))
        except Exception:
            pass

    # 3. Amcache ProgramEntries — install timestamps
    prog_files = find_files(kape_path, '**/*Amcache*ProgramEntries*.csv')
    for f in (prog_files or []):
        try:
            for r in read_csv_file(f):
                name = r.get('Name', '') or r.get('ProgramName', '')
                for ts_field, ts_type in [('InstallDate', 'Install'),
                                           ('KeyLastWriteTimestamp', 'Amcache-RegWrite')]:
                    ts = r.get(ts_field, '')
                    if ts:
                        events.append((ts, 'Amcache-Prog', name, ts_type))
        except Exception:
            pass

    # 4. Prefetch — execution timestamps
    pe_files = find_files(kape_path, '**/*PECmd_Output*.csv')
    for f in (pe_files or []):
        try:
            for r in read_csv_file(f):
                exe = r.get('ExecutableName', '') or r.get('SourceFilename', '')
                for ts_field, ts_type in [('LastRun', 'Executed'),
                                           ('PreviousRun0', 'PrevRun-0'),
                                           ('PreviousRun1', 'PrevRun-1'),
                                           ('PreviousRun2', 'PrevRun-2')]:
                    ts = r.get(ts_field, '')
                    if ts:
                        events.append((ts, 'Prefetch', exe, ts_type))
        except Exception:
            pass

    if not events:
        print("No file system timeline data found.")
        return

    # Filter by search term
    if search:
        s = search.lower()
        events = [e for e in events if s in e[2].lower() or s in e[3].lower()]

    # Sort by timestamp string (ISO-ish format sorts correctly)
    events.sort(key=lambda e: e[0])

    print("=" * 70)
    print("FILE SYSTEM TIMELINE (from LNK, Amcache, Prefetch)")
    print("=" * 70)
    if search:
        print(f"  Filter: {search}")
    print(f"  Total events: {len(events)}\n")

    print(f"  {'Timestamp':<26} {'Source':<14} {'Type':<18} {'Path/Name'}")
    print(f"  {'':->26} {'':->14} {'':->18} {'':->60}")

    limit = None if raw else 100
    for ts, source, path, detail in events[:limit]:
        if len(path) > 70:
            path = '...' + path[-67:]
        print(f"  {ts:<26} {source:<14} {detail:<18} {path}")

    if not raw and len(events) > 100:
        print(f"\n  ... ({len(events) - 100} more events, use --raw for all)")

    print(f"\n  Sources: LNK={sum(1 for e in events if e[1]=='LNK')}"
          f"  Amcache={sum(1 for e in events if 'Amcache' in e[1])}"
          f"  Prefetch={sum(1 for e in events if e[1]=='Prefetch')}")


def cmd_deleted(kape_path: Path, raw: bool = False):
    """Show deleted files from Recycle Bin (RBCmd output)."""
    print("=" * 70)
    print("DELETED FILES (RECYCLE BIN)")
    print("=" * 70)

    rb_files = find_files(kape_path, '**/*RBCmd*.csv')
    if not rb_files:
        print("\nNo Recycle Bin data found (RBCmd_Output.csv).")
        return

    all_records = []
    for rf in rb_files:
        try:
            records = read_csv_file(rf)
            all_records.extend(records)
        except Exception:
            pass

    if not all_records:
        print("\nRecycle Bin is empty — no deleted files found.")
        return

    print(f"\nTotal deleted files: {len(all_records)}\n")

    # Map RIDs to usernames from SAM
    rid_map = {}
    user_files = find_files(kape_path, '**/*UserAccounts*.csv')
    for uf in user_files:
        try:
            for r in read_csv_file(uf):
                rid = r.get('UserId', '')
                name = r.get('UserName', r.get('Name', ''))
                if rid and name:
                    rid_map[str(rid)] = name
        except Exception:
            pass

    print(f"{'Deleted On':<24} {'Size':>10} {'User':<12} {'File Name'}")
    print("-" * 90)

    for r in sorted(all_records, key=lambda x: x.get('DeletedOn', '')):
        deleted = r.get('DeletedOn', '')[:23]
        size = r.get('FileSize', '?')
        try:
            size = f"{int(size):,}"
        except (ValueError, TypeError):
            pass
        filename = r.get('FileName', 'Unknown')

        # Try to resolve user from SID RID in SourceName path
        user = '?'
        source = r.get('SourceName', '')
        # Extract RID from SID in path (e.g., S-1-5-21-...-1000 → 1000)
        import re
        sid_match = re.search(r'S-1-5-21-[\d-]+-(\d+)', source)
        if sid_match:
            rid = sid_match.group(1)
            user = rid_map.get(rid, f'RID-{rid}')
        # Fallback: extract from FileName path
        if user == '?' or user.startswith('RID-'):
            fn = r.get('FileName', '')
            user_match = re.search(r'\\Users\\([^\\]+)\\', fn)
            if user_match:
                user = user_match.group(1)

        if raw:
            print(f"{deleted:<24} {size:>10} {user:<12} {filename}")
            print(f"  Source: {source}")
            print(f"  Type: {r.get('FileType', '?')}")
        else:
            # Shorten filename for display
            name_display = filename if len(filename) <= 50 else '...' + filename[-47:]
            print(f"{deleted:<24} {size:>10} {user:<12} {name_display}")

    if not raw:
        print(f"\nUse --raw for full paths and source details.")


def cmd_recentdocs(kape_path: Path, raw: bool = False):
    """Show recent documents from registry."""
    print("=" * 70)
    print("RECENT DOCUMENTS")
    print("=" * 70)

    rd_files = find_files(kape_path, '**/*RecentDocs*.csv')

    if not rd_files:
        print("\nNo RecentDocs data found.")
        return

    all_records = []
    for rf in rd_files:
        try:
            records = read_csv_file(rf)
            all_records.extend(records)
        except:
            pass

    print(f"\nTotal entries: {len(all_records)}\n")

    # Group by extension
    by_ext = defaultdict(list)
    for r in all_records:
        ext = r.get('Extension', 'Unknown')
        by_ext[ext].append(r)

    limit = None if raw else 10
    for ext, docs in sorted(by_ext.items(), key=lambda x: -len(x[1])):
        print(f"\n### {ext} ({len(docs)}) ###")
        for r in docs[:limit]:
            name = r.get('TargetName', r.get('ValueName', 'Unknown'))
            if not raw:
                name = name[:60]
            opened = r.get('OpenedOn', r.get('ExtensionLastOpened', ''))[:19]
            print(f"  {opened:<20} {name}")
        if not raw and len(docs) > 10:
            print(f"  ... ({len(docs) - 10} more)")


def _load_userassist_timestamps(kape_path: Path) -> list:
    """Extract (datetime, program_name) from UserAssist LastExecuted column.

    Returns list of (datetime, str) tuples, filtered to entries with valid
    timestamps and non-metadata program names.
    """
    ua_files = find_files(kape_path, '**/*UserAssist*.csv')
    results = []
    for uf in ua_files:
        try:
            records = read_csv_file(uf)
            for r in records:
                name = r.get('ProgramName', '')
                ts = r.get('LastExecuted', '')
                if not name or not ts or name.startswith('UEME_'):
                    continue
                # Clean program name: strip GUID prefix, extract filename
                if '{' in name:
                    name = name.split('}')[-1].lstrip('\\')
                name = name.split('\\')[-1] if '\\' in name else name
                # Remove common suffixes for compactness
                for suffix in ['.exe', '.EXE', '.lnk', '.LNK']:
                    if name.endswith(suffix):
                        name = name[:-len(suffix)]
                try:
                    dt = datetime.strptime(ts[:19], '%Y-%m-%d %H:%M:%S')
                    results.append((dt, name))
                except (ValueError, IndexError):
                    pass
        except Exception:
            pass
    return results


def _load_all_evtx_hourly(kape_path: Path) -> dict:
    """Load all EVTX CSVs and bucket event counts by hour.

    Returns dict[log_name -> dict[hour_key -> count]] where
    hour_key is 'YYYY-MM-DD HH:00'.
    """
    result = {}
    for log_name in EVTX_TIMELINE_LOGS:
        records = _load_evtx_csv(kape_path, log_name)
        hourly = defaultdict(int)
        if records:
            for r in records:
                ts = r.get('timestamp_utc', '')
                if len(ts) >= 13:
                    hour_key = ts[:13] + ':00'
                    hourly[hour_key] += 1
        result[log_name] = dict(hourly)
    return result


def _detect_source_gaps(pf_dates: set, ua_dates: set, evtx_dates: dict) -> list:
    """Compare date-level coverage across sources. Returns list of warning strings.

    pf_dates: set of date strings (YYYY-MM-DD) with Prefetch activity
    ua_dates: set of date strings with UserAssist activity
    evtx_dates: dict[log_name -> set of date strings]
    """
    warnings = []
    # Days with UserAssist but no Prefetch
    ua_only = ua_dates - pf_dates
    if ua_only:
        warnings.append(f"ANTI-FORENSICS INDICATOR: {len(ua_only)} day(s) with UserAssist activity but NO Prefetch:")
        for d in sorted(ua_only):
            warnings.append(f"  {d}")

    # Days with EVTX but no Prefetch
    all_evtx_dates = set()
    for dates in evtx_dates.values():
        all_evtx_dates |= dates
    evtx_only = all_evtx_dates - pf_dates
    if evtx_only and evtx_only != ua_only:
        extra = evtx_only - ua_only
        if extra:
            warnings.append(f"Days with EVTX events but NO Prefetch: {sorted(extra)}")

    # Date range summary
    warnings.append("")
    warnings.append("Source date ranges:")
    if pf_dates:
        warnings.append(f"  Prefetch:   {min(pf_dates)} .. {max(pf_dates)} ({len(pf_dates)} days)")
    else:
        warnings.append("  Prefetch:   (no data)")
    if ua_dates:
        warnings.append(f"  UserAssist: {min(ua_dates)} .. {max(ua_dates)} ({len(ua_dates)} days)")
    else:
        warnings.append("  UserAssist: (no data)")
    for log_name in EVTX_TIMELINE_LOGS:
        dates = evtx_dates.get(log_name, set())
        if dates:
            warnings.append(f"  {log_name:<12} {min(dates)} .. {max(dates)} ({len(dates)} days)")

    return warnings


def cmd_timeline(kape_path: Path, raw: bool = False, summary: bool = False, compact: bool = False, unified: bool = False):
    """Show program usage timeline combining prefetch and UserAssist.

    By default, shows ALL hours including those without activity.
    Use --summary to show only hours with activity.
    Use --compact for one-row-per-hour format with comma-separated programs.
    """
    print("=" * 70)
    print("PROGRAM USAGE TIMELINE")
    print("=" * 70)

    # Load UserAssist for focus times
    ua_files = find_files(kape_path, '**/*UserAssist*.csv')
    focus_times = {}  # program -> focus time string
    run_counts = {}   # program -> run count

    for uf in ua_files:
        try:
            records = read_csv_file(uf)
            for r in records:
                name = r.get('ProgramName', '')
                if not name or name.startswith('UEME_'):
                    continue
                # Clean up name
                if '{' in name:
                    name = name.split('}')[-1].lstrip('\\')
                name = name.split('\\')[-1] if '\\' in name else name

                focus = r.get('FocusTime', '')
                count = r.get('RunCounter', '0')
                try:
                    count = int(count)
                except:
                    count = 0

                if name and count > 0:
                    focus_times[name.upper()] = focus
                    run_counts[name.upper()] = count
        except:
            pass

    # Load prefetch timeline for execution times
    pf_timeline = find_file(kape_path, '**/*PECmd*Timeline*.csv')
    executions = []  # list of (datetime, program)

    if pf_timeline:
        try:
            records = read_csv_file(pf_timeline)
            for r in records:
                runtime = r.get('RunTime', '')
                exe = r.get('ExecutableName', '')
                if runtime and exe:
                    # Extract just the exe name
                    exe_name = exe.split('\\')[-1] if '\\' in exe else exe
                    try:
                        dt = datetime.strptime(runtime[:19], '%Y-%m-%d %H:%M:%S')
                        executions.append((dt, exe_name))
                    except:
                        pass
        except:
            pass

    # --- Unified mode: multi-source hourly view ---
    if unified:
        from datetime import timedelta

        # Prefetch timestamps assume Eastern Time (UTC-5); convert to UTC
        utc_offset = timedelta(hours=5)
        pf_utc = []
        for dt, exe in executions:
            utc_dt = dt + utc_offset
            clean = exe.replace('.EXE', '').replace('.exe', '')
            pf_utc.append((utc_dt, clean))

        # Load UserAssist timestamps (already UTC)
        ua_raw = _load_userassist_timestamps(kape_path)

        # Load EVTX hourly counts
        evtx_hourly = _load_all_evtx_hourly(kape_path)

        # Bucket Prefetch by hour
        pf_by_hour = defaultdict(list)
        for dt, name in pf_utc:
            pf_by_hour[dt.strftime('%Y-%m-%d %H:00')].append(name)

        # Bucket UserAssist by hour
        ua_by_hour = defaultdict(list)
        for dt, name in ua_raw:
            ua_by_hour[dt.strftime('%Y-%m-%d %H:00')].append(name)

        # Collect all hour keys across every source
        all_hour_keys = set(pf_by_hour.keys()) | set(ua_by_hour.keys())
        for log_hourly in evtx_hourly.values():
            all_hour_keys |= set(log_hourly.keys())

        if not all_hour_keys:
            print("\nNo data found from any source.")
            return

        # Determine full hour range
        sorted_hours = sorted(all_hour_keys)
        first_dt = datetime.strptime(sorted_hours[0], '%Y-%m-%d %H:00')
        last_dt = datetime.strptime(sorted_hours[-1], '%Y-%m-%d %H:00')

        if summary:
            all_hours = sorted_hours
        else:
            all_hours = []
            current = first_dt
            while current <= last_dt:
                all_hours.append(current.strftime('%Y-%m-%d %H:00'))
                current += timedelta(hours=1)

        # Gap detection
        pf_dates = {h[:10] for h in pf_by_hour}
        ua_dates = {h[:10] for h in ua_by_hour}
        evtx_dates = {}
        for log_name, hourly in evtx_hourly.items():
            evtx_dates[log_name] = {h[:10] for h in hourly}

        gap_warnings = _detect_source_gaps(pf_dates, ua_dates, evtx_dates)

        # Print header
        print("\n### UNIFIED MULTI-SOURCE TIMELINE (UTC) ###\n")
        for w in gap_warnings:
            print(f"  *** {w}" if w and not w.startswith(' ') and not w.startswith('Source') else f"  {w}")
        print()

        # Column headers: sec sys app ps ft (short names)
        col_short = {'security': 'sec', 'system': 'sys', 'application': 'app',
                     'powershell': 'ps', 'ftdiag': 'ft'}
        hdr_cols = ''.join(f'{col_short[l]:>6}' for l in EVTX_TIMELINE_LOGS)
        print(f"{'Hour (UTC)':<16} {'PF':>4} {'UA':>4} {hdr_cols}  Programs")
        print("-" * 120)

        for hour in all_hours:
            pf_progs = pf_by_hour.get(hour, [])
            ua_progs = ua_by_hour.get(hour, [])

            # EVTX counts
            evtx_counts = []
            for log_name in EVTX_TIMELINE_LOGS:
                evtx_counts.append(evtx_hourly[log_name].get(hour, 0))

            # UA-only = programs in UserAssist but not in Prefetch this hour
            pf_set = {p.upper() for p in pf_progs}
            ua_only = [p for p in ua_progs if p.upper() not in pf_set]

            pf_count = len(set(pf_progs))
            ua_count = len(set(ua_only))
            total_evtx = sum(evtx_counts)

            # Skip empty hours in summary mode
            if summary and pf_count == 0 and ua_count == 0 and total_evtx == 0:
                continue

            # Build program list
            # Unique prefetch programs (order of first appearance)
            seen = set()
            pf_unique = []
            for p in pf_progs:
                if p.upper() not in seen:
                    seen.add(p.upper())
                    pf_unique.append(p)
            ua_unique = []
            seen_ua = set()
            for p in ua_only:
                if p.upper() not in seen_ua:
                    seen_ua.add(p.upper())
                    ua_unique.append(p)

            prog_parts = []
            if pf_unique:
                prog_parts.append(', '.join(pf_unique))
            if ua_unique:
                prog_parts.append('[UA] ' + ', '.join(ua_unique))
            prog_str = '  '.join(prog_parts)

            if not raw and len(prog_str) > 60:
                prog_str = prog_str[:57] + '...'

            # Flag: UA activity but no Prefetch
            flag = ' <<<' if ua_count > 0 and pf_count == 0 else ''

            hour_short = hour[2:]  # Drop century: "20" -> "20-11-02 18:00"
            evtx_str = ''.join(f'{c:>6}' for c in evtx_counts)
            print(f"{hour_short:<16} {pf_count:>4} {ua_count:>4} {evtx_str}  {prog_str}{flag}")

        return

    if not executions:
        print("\nNo execution timeline data found.")
        return

    # Sort by time
    executions.sort(key=lambda x: x[0])

    # Show focus time summary first
    print("\n### FOCUS TIME SUMMARY (UserAssist) ###\n")
    print(f"{'Program':<40} {'Runs':>6} {'Focus Time'}")
    print("-" * 70)

    # Sort by run count
    for prog, count in sorted(run_counts.items(), key=lambda x: -x[1])[:20 if not raw else None]:
        focus = focus_times.get(prog, '')
        # Clean up program name for display
        display = prog[:38] if not raw else prog
        print(f"{display:<40} {count:>6} {focus}")

    if not raw and len(run_counts) > 20:
        print(f"  ... ({len(run_counts) - 20} more programs)")

    # Group executions by hour
    by_hour = defaultdict(list)
    for dt, exe in executions:
        hour_key = dt.strftime('%Y-%m-%d %H:00')
        by_hour[hour_key].append((dt, exe))

    # Generate all hours between first and last execution (unless summary mode)
    if summary:
        # Summary mode: only show hours with activity
        all_hours = sorted(by_hour.keys())
    else:
        # Full mode: show all hours including empty ones
        from datetime import timedelta
        first_dt = executions[0][0].replace(minute=0, second=0, microsecond=0)
        last_dt = executions[-1][0].replace(minute=0, second=0, microsecond=0)

        all_hours = []
        current = first_dt
        while current <= last_dt:
            all_hours.append(current.strftime('%Y-%m-%d %H:00'))
            current += timedelta(hours=1)

    # Compact mode: one row per DAY with all sources, activity bar
    if compact:
        from datetime import timedelta

        # EWS-VM Prefetch is in Eastern Time (UTC-5); convert to UTC
        utc_offset = timedelta(hours=5)
        pf_utc_by_day = defaultdict(list)
        for dt, exe in executions:
            utc_dt = dt + utc_offset
            clean = exe.replace('.EXE', '').replace('.exe', '')
            pf_utc_by_day[utc_dt.strftime('%Y-%m-%d')].append(clean)

        # Load UserAssist timestamps (already UTC)
        ua_raw = _load_userassist_timestamps(kape_path)
        ua_by_day = defaultdict(list)
        for dt, name in ua_raw:
            ua_by_day[dt.strftime('%Y-%m-%d')].append(name)

        # Load EVTX hourly counts, aggregate to daily per-log and total
        evtx_hourly = _load_all_evtx_hourly(kape_path)
        evtx_by_log_day = {log: defaultdict(int) for log in EVTX_TIMELINE_LOGS}
        evtx_sum_by_day = defaultdict(int)
        for log_name in EVTX_TIMELINE_LOGS:
            for hk, cnt in evtx_hourly[log_name].items():
                day = hk[:10]
                evtx_by_log_day[log_name][day] += cnt
                evtx_sum_by_day[day] += cnt

        # Collect all day keys across every source
        all_day_keys = set(pf_utc_by_day.keys()) | set(ua_by_day.keys()) | set(evtx_sum_by_day.keys())

        if not all_day_keys:
            print("\nNo data found from any source.")
            return

        # Full day range
        sorted_keys = sorted(all_day_keys)
        first_dt = datetime.strptime(sorted_keys[0], '%Y-%m-%d')
        last_dt = datetime.strptime(sorted_keys[-1], '%Y-%m-%d')

        if summary:
            all_days = sorted_keys
        else:
            all_days = []
            current = first_dt
            while current <= last_dt:
                all_days.append(current.strftime('%Y-%m-%d'))
                current += timedelta(days=1)

        # Find max EVTX count for bar scaling
        max_evtx = max(evtx_sum_by_day.values()) if evtx_sum_by_day else 1
        bar_width = 30

        col_short = {'security': 'sec', 'system': 'sys', 'application': 'app',
                     'powershell': 'ps', 'ftdiag': 'ft'}
        hdr_cols = ''.join(f'{col_short[l]:>6}' for l in EVTX_TIMELINE_LOGS)

        print("\n\n### DAY-BY-DAY EXECUTION TIMELINE (COMPACT) ###")
        print("Note: All times UTC. Bar shows relative total EVTX volume.\n")
        print(f"{'Date (UTC)':<14} {'PF':>4} {'UA':>4} {hdr_cols} {'Bar':<{bar_width+2}} Programs")
        print("-" * 160)

        for day in all_days:
            pf_progs = pf_utc_by_day.get(day, [])
            ua_progs = ua_by_day.get(day, [])
            evtx_total = evtx_sum_by_day.get(day, 0)
            evtx_counts = [evtx_by_log_day[log].get(day, 0) for log in EVTX_TIMELINE_LOGS]

            # UA-only programs
            pf_set = {p.upper() for p in pf_progs}
            ua_only = [p for p in ua_progs if p.upper() not in pf_set]

            pf_count = len(set(pf_progs))
            ua_count = len(set(ua_only))

            # Activity bar (scaled to max)
            if evtx_total > 0:
                bar_len = max(1, int(round(evtx_total / max_evtx * bar_width)))
                bar = '\u2588' * bar_len
            else:
                bar = ''

            # Build program list (unique, sorted)
            seen = set()
            pf_unique = []
            for p in pf_progs:
                if p.upper() not in seen:
                    seen.add(p.upper())
                    pf_unique.append(p)
            ua_unique = []
            seen_ua = set()
            for p in ua_only:
                if p.upper() not in seen_ua:
                    seen_ua.add(p.upper())
                    ua_unique.append(p)

            prog_parts = []
            if pf_unique:
                prog_parts.append(', '.join(sorted(pf_unique, key=str.upper)))
            if ua_unique:
                prog_parts.append('[UA] ' + ', '.join(sorted(ua_unique, key=str.upper)))
            prog_str = '  '.join(prog_parts)

            if not raw and len(prog_str) > 70:
                prog_str = prog_str[:67] + '...'

            day_short = day[2:]  # "20-11-02"

            evtx_str = ''.join(f'{c:>6}' for c in evtx_counts)

            # Flag days with no activity at all
            if pf_count == 0 and ua_count == 0 and evtx_total == 0:
                empty_cols = ''.join(f'{"":>6}' for _ in EVTX_TIMELINE_LOGS)
                print(f"{day_short:<14} {'':>4} {'':>4} {empty_cols} {'':<{bar_width+2}} --")
                continue

            flag = ' <<<' if ua_count > 0 and pf_count == 0 else ''
            print(f"{day_short:<14} {pf_count:>4} {ua_count:>4} {evtx_str} {bar:<{bar_width+2}} {prog_str}{flag}")

        return

    # Full mode: detailed output per hour
    print("\n\n### HOUR-BY-HOUR EXECUTION TIMELINE ###\n")

    for hour in all_hours:
        items = by_hour.get(hour, [])

        if not items:
            # Empty hour - show it with no activity indicator
            print(f"\n{'='*70}")
            print(f" {hour}  (no activity)")
            print(f"{'='*70}")
            print("  ----")
            continue

        # Count unique programs this hour
        programs = defaultdict(int)
        first_seen = {}
        for dt, exe in items:
            programs[exe] += 1
            if exe not in first_seen:
                first_seen[exe] = dt

        # Create visual bar
        print(f"\n{'='*70}")
        print(f" {hour}  ({len(items)} executions, {len(programs)} unique programs)")
        print(f"{'='*70}")

        # Sort by first execution time within the hour
        for prog in sorted(programs.keys(), key=lambda x: first_seen[x]):
            count = programs[prog]
            time_str = first_seen[prog].strftime('%H:%M:%S')
            focus = focus_times.get(prog.upper(), '')

            # Visual indicator of activity level
            bar = '█' * min(count, 20) + ('→' if count > 20 else '')

            focus_info = f" ({focus})" if focus else ""
            print(f"  {time_str} {prog:<35} {bar} {count}x{focus_info}")


def cmd_jumplists(kape_path: Path, raw: bool = False):
    """Show jump lists (recent files)."""
    print("=" * 70)
    print("JUMP LISTS (RECENT FILES)")
    print("=" * 70)

    jl_files = find_files(kape_path, '**/*AutomaticDestinations*.csv')

    if not jl_files:
        print("\nNo jump list data found.")
        return

    all_records = []
    for jf in jl_files:
        try:
            records = read_csv_file(jf)
            all_records.extend(records)
        except:
            pass

    print(f"\nTotal entries: {len(all_records)}\n")

    # Group by application
    by_app = defaultdict(list)
    for r in all_records:
        app = r.get('AppIdDescription', r.get('SourceFile', 'Unknown'))
        by_app[app].append(r)

    app_limit = None if raw else 15
    entry_limit = None if raw else 5
    for app, entries in sorted(by_app.items(), key=lambda x: -len(x[1]))[:app_limit]:
        app_name = app if raw else app[:50]
        print(f"\n### {app_name} ({len(entries)}) ###")
        for r in entries[:entry_limit]:
            path = r.get('Path', r.get('TargetPath', 'Unknown'))
            if not raw:
                path = path[:60]
            modified = r.get('TargetModified', r.get('SourceModified', ''))[:19]
            print(f"  {modified:<20} {path}")
        if not raw and len(entries) > 5:
            print(f"  ... ({len(entries) - 5} more)")


# =============================================================================
# PHASE 1: OVERVIEW & DISCOVERY
# =============================================================================

def cmd_files(kape_path: Path, raw: bool = False):
    """List large files in KAPE extraction (starting point for investigation)."""
    print("=" * 70)
    print("LARGE FILES IN KAPE EXTRACTION")
    print("=" * 70)
    print(f"\nPath: {kape_path}\n")

    import subprocess

    # Find files over 100KB, sorted by size
    try:
        result = subprocess.run(
            ['find', str(kape_path), '-type', 'f', '-size', '+100k'],
            capture_output=True, text=True, timeout=60
        )
        files = result.stdout.strip().split('\n') if result.stdout.strip() else []
    except Exception as e:
        print(f"Error listing files: {e}")
        return

    # Get sizes for each file
    file_sizes = []
    for f in files:
        if f:
            try:
                size = os.path.getsize(f)
                file_sizes.append((size, f))
            except:
                pass

    # Sort by size descending
    file_sizes.sort(reverse=True)

    limit = None if raw else 40
    print(f"{'Size':>10} {'File'}")
    print("-" * 80)

    for size, filepath in file_sizes[:limit]:
        # Format size
        if size >= 1024*1024:
            size_str = f"{size/(1024*1024):.1f}M"
        else:
            size_str = f"{size/1024:.0f}K"

        # Shorten path for display
        rel_path = filepath.replace(str(kape_path) + '/', '')
        if not raw and len(rel_path) > 65:
            rel_path = '...' + rel_path[-62:]

        print(f"{size_str:>10} {rel_path}")

    if not raw and len(file_sizes) > 40:
        print(f"\n  ... ({len(file_sizes) - 40} more files over 100KB)")

    print(f"\n  Total: {len(file_sizes)} files over 100KB")


# =============================================================================
# PHASE 2: USER ACTIVITY
# =============================================================================

def cmd_activities(kape_path: Path, raw: bool = False):
    """Query Windows Timeline (ActivitiesCache.db)."""
    print("=" * 70)
    print("WINDOWS TIMELINE (ActivitiesCache.db)")
    print("=" * 70)

    import sqlite3

    # Find ActivitiesCache.db
    db_files = find_files(kape_path, '**/ActivitiesCache.db')

    if not db_files:
        print("\nNo ActivitiesCache.db found.")
        return

    for db_file in db_files:
        # Extract user from path
        path_str = str(db_file)
        user = "unknown"
        if '/L.' in path_str:
            parts = path_str.split('/L.')
            if len(parts) > 1:
                user = parts[1].split('/')[0]

        print(f"\n### User: {user} ###\n")

        try:
            conn = sqlite3.connect(f"file:{db_file}?mode=ro", uri=True)
            cursor = conn.cursor()

            # Query activities
            cursor.execute("""
                SELECT
                    datetime(StartTime, 'unixepoch') as start_time,
                    json_extract(AppId, '$[0].application') as app,
                    ActivityType
                FROM Activity
                ORDER BY StartTime DESC
                LIMIT ?
            """, (100 if raw else 30,))

            rows = cursor.fetchall()
            conn.close()

            if not rows:
                print("  No activities found.")
                continue

            print(f"{'Timestamp (UTC)':<22} {'Type':>5} {'Application'}")
            print("-" * 80)

            for start_time, app, activity_type in rows:
                # Clean up app name
                if app:
                    if '\\' in app:
                        app = app.split('\\')[-1]
                    if not raw and len(app) > 50:
                        app = app[:47] + '...'
                else:
                    app = '(unknown)'

                print(f"{start_time or '':<22} {activity_type or '':>5} {app}")

        except Exception as e:
            print(f"  Error reading database: {e}")


def cmd_browser(kape_path: Path, raw: bool = False):
    """Query browser history (Firefox and Edge)."""
    import shutil
    term_width = shutil.get_terminal_size((120, 40)).columns
    url_width = max(40, term_width - 30)

    print("=" * 70)
    print("BROWSER HISTORY")
    print("=" * 70)

    import sqlite3

    # Find Firefox places.sqlite
    firefox_dbs = find_files(kape_path, '**/places.sqlite')

    for db_file in firefox_dbs:
        print(f"\n### Firefox ###")
        print(f"File: {db_file.name}\n")

        try:
            conn = sqlite3.connect(f"file:{db_file}?mode=ro", uri=True)
            cursor = conn.cursor()

            cursor.execute("""
                SELECT
                    datetime(last_visit_date/1000000, 'unixepoch') as visit_time,
                    url,
                    title
                FROM moz_places
                WHERE last_visit_date IS NOT NULL
                ORDER BY last_visit_date DESC
                LIMIT ?
            """, (100 if raw else 30,))

            rows = cursor.fetchall()
            conn.close()

            if not rows:
                print("  No history found.")
                continue

            print(f"{'Visit Time (UTC)':<22} {'URL'}")
            print("-" * 80)

            for visit_time, url, title in rows:
                if not raw and len(url) > url_width:
                    url = url[:url_width - 3] + '...'
                print(f"{visit_time or '':<22} {url}")

        except Exception as e:
            print(f"  Error reading Firefox history: {e}")

    # Edge/IE history from WebCacheV01.dat (ESE database)
    webcache_dbs = find_files(kape_path, '**/WebCacheV01.dat')

    for db_file in webcache_dbs:
        print(f"\n### Edge/IE (WebCacheV01.dat) ###")
        print(f"File: {db_file.name}\n")

        try:
            import pyesedb
        except ImportError:
            print("  pyesedb not installed. Install with: pip install libesedb-python")
            continue

        try:
            db = pyesedb.file()
            db.open(str(db_file))

            # Get container metadata to identify history containers
            containers_table = db.get_table_by_name('Containers')
            container_cols = [containers_table.get_column(i).name
                              for i in range(containers_table.number_of_columns)]

            history_containers = []
            all_containers = []
            for i in range(containers_table.number_of_records):
                rec = containers_table.get_record(i)
                cid_data = rec.get_value_data(container_cols.index('ContainerId'))
                name_data = rec.get_value_data(container_cols.index('Name'))
                dir_data = rec.get_value_data(container_cols.index('Directory'))

                cid = int.from_bytes(cid_data, 'little') if cid_data else None
                name = name_data.decode('utf-16-le').rstrip('\x00') if name_data else ''
                directory = dir_data.decode('utf-16-le').rstrip('\x00') if dir_data else ''

                all_containers.append((cid, name, directory))
                if 'History' in name or 'MSHist' in name:
                    history_containers.append((cid, name, directory))

            def _filetime_to_utc(ft):
                """Convert Windows FILETIME (100-ns since 1601-01-01) to UTC string."""
                if not ft or ft == 0 or ft < 100000000000000:
                    return None
                from datetime import datetime, timedelta, timezone
                epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
                try:
                    dt = epoch + timedelta(microseconds=ft // 10)
                    if dt.year < 1970 or dt.year > 2100:
                        return None
                    return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
                except (OverflowError, OSError):
                    return None

            def _get_record_values(record, columns):
                """Extract values from an ESE record."""
                vals = {}
                for j, col in enumerate(columns):
                    try:
                        data = record.get_value_data(j)
                        if data is None:
                            vals[col] = None
                        elif col in ('AccessedTime', 'ModifiedTime', 'CreationTime',
                                     'ExpiryTime', 'SyncTime', 'PostCheckTime'):
                            vals[col] = _filetime_to_utc(
                                int.from_bytes(data, 'little')) if len(data) == 8 else None
                        elif col in ('Url', 'Filename', 'RedirectUrl',
                                     'RequestHeaders', 'ResponseHeaders'):
                            try:
                                vals[col] = data.decode('utf-16-le').rstrip('\x00')
                            except UnicodeDecodeError:
                                try:
                                    vals[col] = data.decode('utf-8').rstrip('\x00')
                                except UnicodeDecodeError:
                                    vals[col] = data.hex()[:80]
                        elif col in ('AccessCount', 'FileSize', 'EntryId',
                                     'SyncCount', 'UrlHash'):
                            vals[col] = int.from_bytes(
                                data, 'little') if len(data) <= 8 else None
                        else:
                            vals[col] = data
                    except Exception:
                        vals[col] = None
                return vals

            # Extract history entries from all history containers
            all_entries = []
            for cid, name, directory in history_containers:
                table_name = f'Container_{cid}'
                try:
                    table = db.get_table_by_name(table_name)
                except Exception:
                    continue

                if table.number_of_records == 0:
                    continue

                cols = [table.get_column(i).name
                        for i in range(table.number_of_columns)]

                for i in range(table.number_of_records):
                    vals = _get_record_values(table.get_record(i), cols)
                    url = vals.get('Url', '')
                    if url:
                        all_entries.append({
                            'container': name,
                            'url': url,
                            'accessed': vals.get('AccessedTime'),
                            'modified': vals.get('ModifiedTime'),
                            'created': vals.get('CreationTime'),
                            'access_count': vals.get('AccessCount', 0),
                            'response_headers': vals.get('ResponseHeaders'),
                        })

            # Also extract content entries (cached resources)
            content_entries = []
            for cid, name, directory in all_containers:
                if name != 'Content':
                    continue
                table_name = f'Container_{cid}'
                try:
                    table = db.get_table_by_name(table_name)
                except Exception:
                    continue
                if table.number_of_records == 0:
                    continue

                cols = [table.get_column(i).name
                        for i in range(table.number_of_columns)]

                for i in range(table.number_of_records):
                    vals = _get_record_values(table.get_record(i), cols)
                    url = vals.get('Url', '')
                    if url:
                        content_entries.append({
                            'container_dir': directory,
                            'url': url,
                            'accessed': vals.get('AccessedTime'),
                            'modified': vals.get('ModifiedTime'),
                            'access_count': vals.get('AccessCount', 0),
                        })

            db.close()

            # Print history
            if all_entries:
                all_entries.sort(key=lambda e: e['accessed'] or '')
                print(f"History entries: {len(all_entries)}")
                print(f"{'Accessed (UTC)':<22} {'Count':>5}  {'URL'}")
                print("-" * 90)
                for e in all_entries:
                    url = e['url']
                    if not raw and len(url) > url_width:
                        url = url[:url_width - 3] + '...'
                    print(f"{e['accessed'] or '':<22} {e['access_count'] or 0:>5}  {url}")
            else:
                print("  No history entries found.")

            # Print content/cache
            if content_entries:
                content_entries.sort(key=lambda e: e['accessed'] or '')
                print(f"\nCached resources: {len(content_entries)}")
                if not raw:
                    print("(showing last 30, use --raw for all)")
                    content_entries = content_entries[-30:]
                print(f"{'Accessed (UTC)':<22} {'Count':>5}  {'URL'}")
                print("-" * 90)
                for e in content_entries:
                    url = e['url']
                    if not raw and len(url) > url_width:
                        url = url[:url_width - 3] + '...'
                    print(f"{e['accessed'] or '':<22} {e['access_count'] or 0:>5}  {url}")

        except Exception as e:
            print(f"  Error reading WebCacheV01.dat: {e}")
            import traceback
            traceback.print_exc()


# =============================================================================
# PHASE 3: SECURITY EVENTS
#
# Uses a CSV cache for fast queries. Run `evtx-extract` once, then all
# evtx-* queries read from the CSV instantly.
# =============================================================================

# Fields extracted per event type
EVTX_DATA_FIELDS = [
    'SubjectUserName', 'SubjectDomainName',
    'TargetUserName', 'TargetDomainName',
    'LogonType', 'IpAddress', 'IpPort',
    'TargetServerName', 'ProcessName',
    'NewProcessName', 'CommandLine',
]

EVENT_NAMES = {
    '4624': 'Successful Logon',
    '4625': 'Failed Logon',
    '4634': 'Logoff',
    '4648': 'Explicit Credential Logon',
    '4672': 'Special Privileges Assigned',
    '4688': 'Process Creation',
    '4689': 'Process Termination',
    '4697': 'Service Installed',
    '4698': 'Scheduled Task Created',
    '4720': 'User Account Created',
    '4726': 'User Account Deleted',
    '4732': 'User Added to Group',
    '4776': 'Credential Validation',
    '4797': 'Blank Password Query',
    '4798': 'User Group Enumeration',
    '4799': 'Security Group Enumeration',
    '5058': 'Key File Operation',
    '5059': 'Key Migration',
    '5061': 'Cryptographic Operation',
    '5379': 'Credential Manager Read',
    '5382': 'Vault Credential Read',
}

LOGON_TYPE_MAP = {
    '2': 'Interactive',
    '3': 'Network',
    '4': 'Batch',
    '5': 'Service',
    '7': 'Unlock',
    '8': 'NetworkClear',
    '9': 'NewCreds',
    '10': 'RDP',
    '11': 'CachedInt',
}


def _get_evtx_csv(kape_path: Path, log_name: str = 'security') -> Path:
    """Return path for cached EVTX events CSV."""
    return kape_path / f'{log_name}_events.csv'


def _load_evtx_csv(kape_path: Path, log_name: str = 'security') -> list:
    """Load cached EVTX events CSV. Returns list of dicts or None."""
    csv_path = _get_evtx_csv(kape_path, log_name)
    if not csv_path.exists():
        return None
    return read_csv_file(csv_path)


def _parse_single_evtx(evtx_file: Path, csv_path: Path, raw: bool = False) -> int:
    """Parse a single EVTX file to CSV. Returns event count or -1 if skipped."""
    if csv_path.exists() and not raw:
        size_mb = csv_path.stat().st_size / (1024*1024)
        records = read_csv_file(csv_path)
        print(f"  Already cached: {csv_path.name} ({len(records)} events, {size_mb:.1f}M) -- use --raw to re-extract")
        return -1

    try:
        import Evtx.Evtx as evtx
        import xml.etree.ElementTree as ET
    except ImportError:
        print("Error: python-evtx not installed.")
        print("Install with: pip install python-evtx")
        return 0

    ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
    total = 0
    rows = []

    try:
        with evtx.Evtx(str(evtx_file)) as log:
            for record in log.records():
                total += 1
                if total % 5000 == 0:
                    print(f"    {total} events processed...")
                try:
                    root = ET.fromstring(record.xml())
                    event_id_elem = root.find('.//ns:EventID', ns)
                    if event_id_elem is None:
                        continue

                    time_created = root.find('.//ns:TimeCreated', ns)
                    timestamp = time_created.get('SystemTime')[:19] if time_created is not None else ''

                    # Get channel/provider for non-security logs
                    channel_elem = root.find('.//ns:Channel', ns)
                    provider_elem = root.find('.//ns:Provider', ns)

                    row = {
                        'timestamp_utc': timestamp,
                        'event_id': event_id_elem.text,
                        'source_file': evtx_file.name,
                        'channel': channel_elem.text if channel_elem is not None else '',
                        'provider': provider_elem.get('Name', '') if provider_elem is not None else '',
                    }

                    # Extract known data fields
                    for elem in root.findall('.//ns:Data', ns):
                        name = elem.get('Name')
                        if name and name in EVTX_DATA_FIELDS:
                            row[name] = elem.text or ''

                    rows.append(row)
                except:
                    pass
    except Exception as e:
        print(f"  Error parsing {evtx_file.name}: {e}")
        return 0

    # Write CSV
    fieldnames = ['timestamp_utc', 'event_id', 'source_file', 'channel', 'provider'] + EVTX_DATA_FIELDS
    with open(csv_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(rows)

    size_mb = csv_path.stat().st_size / (1024*1024)
    print(f"  Parsed: {total} events → {csv_path.name} ({size_mb:.1f}M)")
    return total


# Map EVTX filenames to CSV base names
EVTX_LOG_NAMES = {
    'Security.evtx': 'security',
    'System.evtx': 'system',
    'Application.evtx': 'application',
    'Windows PowerShell.evtx': 'powershell',
    'FTDiag.evtx': 'ftdiag',
}

# EVTX logs to include in unified timeline (order = column order)
EVTX_TIMELINE_LOGS = ['security', 'system', 'application', 'powershell', 'ftdiag']


def cmd_evtx_extract(kape_path: Path, raw: bool = False):
    """Parse all EVTX files and save events to CSV for fast queries."""
    print("=" * 70)
    print("EXTRACT EVENT LOGS TO CSV")
    print("=" * 70)

    evtx_files = find_files(kape_path, '**/*.evtx')

    if not evtx_files:
        print("\nNo .evtx files found.")
        return

    print(f"\nFound {len(evtx_files)} EVTX files:")
    for f in sorted(evtx_files, key=lambda x: x.stat().st_size, reverse=True):
        size_mb = f.stat().st_size / (1024*1024)
        print(f"  {f.name:30s} {size_mb:6.1f}M")
    print()

    total_all = 0
    for evtx_file in sorted(evtx_files):
        log_name = EVTX_LOG_NAMES.get(evtx_file.name, evtx_file.stem.lower().replace(' ', '_'))
        csv_path = _get_evtx_csv(kape_path, log_name)
        print(f"[{evtx_file.name}]")
        count = _parse_single_evtx(evtx_file, csv_path, raw)
        if count > 0:
            total_all += count

    # Summary
    print(f"\n{'='*70}")
    print("CSV FILES:")
    for evtx_file in sorted(evtx_files):
        log_name = EVTX_LOG_NAMES.get(evtx_file.name, evtx_file.stem.lower().replace(' ', '_'))
        csv_path = _get_evtx_csv(kape_path, log_name)
        if csv_path.exists():
            size_mb = csv_path.stat().st_size / (1024*1024)
            print(f"  {csv_path}  ({size_mb:.1f}M)")
    print(f"{'='*70}")


def cmd_evtx_summary(kape_path: Path, raw: bool = False):
    """Count events by ID in Security.evtx."""
    print("=" * 70)
    print("SECURITY EVENT LOG SUMMARY")
    print("=" * 70)

    records = _load_evtx_csv(kape_path)
    if records is None:
        print("\nNo cached CSV found. Run: just kape-evtx-extract")
        return

    from collections import Counter
    event_counts = Counter(r.get('event_id', '') for r in records)

    print(f"\nTotal events: {len(records)} (from cached CSV)\n")

    print(f"{'Event ID':>8} {'Count':>8} {'Description'}")
    print("-" * 60)

    limit = None if raw else 25
    for eid, count in event_counts.most_common(limit):
        desc = EVENT_NAMES.get(eid, '')
        print(f"{eid:>8} {count:>8} {desc}")

    if not raw and len(event_counts) > 25:
        print(f"\n  ... ({len(event_counts) - 25} more event types)")


def cmd_evtx_logons(kape_path: Path, raw: bool = False):
    """Show logon events (4624) from Security.evtx."""
    print("=" * 70)
    print("LOGON EVENTS (Event ID 4624)")
    print("=" * 70)

    records = _load_evtx_csv(kape_path)
    if records is None:
        print("\nNo cached CSV found. Run: just kape-evtx-extract")
        return

    logons = []
    for r in records:
        if r.get('event_id') != '4624':
            continue

        user = r.get('TargetUserName', '')
        ltype = r.get('LogonType', '')

        # Skip service accounts unless raw mode
        if not raw:
            if user in ['SYSTEM', 'ANONYMOUS LOGON', 'DWM-1', 'DWM-2', 'UMFD-0', 'UMFD-1', 'UMFD-2']:
                continue
            if ltype == '5':
                continue
            if user.endswith('$'):
                continue

        logons.append(r)

    logons.sort(key=lambda x: x.get('timestamp_utc', ''))

    print(f"\nTotal logon events: {len(logons)}\n")
    print(f"{'Timestamp (UTC)':<22} {'Type':<12} {'User':<15} {'Domain':<12} {'Source IP'}")
    print("-" * 85)

    limit = None if raw else 50
    for l in logons[-limit:] if limit else logons:
        ltype = LOGON_TYPE_MAP.get(l.get('LogonType', ''), f"Type{l.get('LogonType', '?')}")
        print(f"{l.get('timestamp_utc', ''):<22} {ltype:<12} {l.get('TargetUserName', ''):<15} {l.get('TargetDomainName', ''):<12} {l.get('IpAddress', '-')}")

    if not raw and len(logons) > 50:
        print(f"\n  Showing last 50 of {len(logons)} events. Use --raw for all.")


def cmd_evtx_lateral(kape_path: Path, raw: bool = False):
    """Show explicit credential logons (4648) - lateral movement indicator."""
    print("=" * 70)
    print("EXPLICIT CREDENTIAL LOGONS (Event ID 4648)")
    print("=" * 70)
    print("Note: Shows when a user uses different credentials (lateral movement indicator)\n")

    records = _load_evtx_csv(kape_path)
    if records is None:
        print("No cached CSV found. Run: just kape-evtx-extract")
        return

    events = []
    for r in records:
        if r.get('event_id') != '4648':
            continue

        subject = r.get('SubjectUserName', '')

        # Skip system/service accounts unless raw
        if not raw:
            if subject.endswith('$') or subject in ['SYSTEM']:
                continue

        events.append(r)

    events.sort(key=lambda x: x.get('timestamp_utc', ''))

    print(f"Total events: {len(events)}\n")
    print(f"{'Timestamp (UTC)':<22} {'Subject':<15} {'Target User':<15} {'Target Server'}")
    print("-" * 85)

    limit = None if raw else 50
    for e in events[-limit:] if limit else events:
        print(f"{e.get('timestamp_utc', ''):<22} {e.get('SubjectUserName', ''):<15} {e.get('TargetUserName', ''):<15} {e.get('TargetServerName', '')}")

    if not raw and len(events) > 50:
        print(f"\n  Showing last 50 of {len(events)} events. Use --raw for all.")

    # Summary of unique lateral movement patterns
    patterns = {}
    for e in events:
        key = f"{e.get('SubjectUserName', '')} → {e.get('TargetUserName', '')} @ {e.get('TargetServerName', '')}"
        patterns[key] = patterns.get(key, 0) + 1

    if patterns:
        print("\n### LATERAL MOVEMENT PATTERNS ###\n")
        for pattern, count in sorted(patterns.items(), key=lambda x: -x[1])[:20]:
            print(f"  {count:>4}x  {pattern}")


# =============================================================================
# EVTX TIMELINE
# =============================================================================

# Short aliases for log names
EVTX_ALIASES = {
    'ps': 'powershell',
    'powershell': 'powershell',
    'ftdiag': 'ftdiag',
    'ft': 'ftdiag',
    'system': 'system',
    'sys': 'system',
    'app': 'application',
    'application': 'application',
    'security': 'security',
    'sec': 'security',
}


def cmd_evtx_timeline(kape_path: Path, log_alias: str, hourly: bool = False,
                       from_date: str = None, to_date: str = None):
    """Show event count per day (or per hour) for a specific EVTX log."""
    log_name = EVTX_ALIASES.get(log_alias)
    if not log_name:
        print(f"Unknown log: {log_alias}")
        print(f"Available: {', '.join(sorted(EVTX_ALIASES.keys()))}")
        return

    records = _load_evtx_csv(kape_path, log_name)
    if not records:
        print(f"\nNo cached CSV for '{log_name}'. Run: just kape-evtx-extract")
        return

    title = f"{log_name.upper()} EVENT LOG"
    print("=" * 70)
    print(f"{title} {'(HOURLY)' if hourly else '(DAILY)'}")
    print("=" * 70)

    # Filter by date range
    if from_date:
        records = [r for r in records if r.get('timestamp_utc', '') >= from_date]
    if to_date:
        records = [r for r in records if r.get('timestamp_utc', '') <= to_date]

    if not records:
        print("\nNo events in the specified range.")
        return

    print(f"\nTotal events: {len(records)}")

    # Bucket events
    buckets = {}
    event_ids_per_bucket = {}
    for r in records:
        ts = r.get('timestamp_utc', '')
        if not ts or len(ts) < 10:
            continue
        key = ts[:13] if hourly else ts[:10]  # YYYY-MM-DD HH or YYYY-MM-DD
        buckets[key] = buckets.get(key, 0) + 1
        eid = r.get('event_id', '?')
        if key not in event_ids_per_bucket:
            event_ids_per_bucket[key] = {}
        event_ids_per_bucket[key][eid] = event_ids_per_bucket[key].get(eid, 0) + 1

    if not buckets:
        print("\nNo timestamped events found.")
        return

    # Find max for bar scaling
    max_count = max(buckets.values())
    bar_width = 40

    # Print timeline
    fmt = "hour" if hourly else "date"
    print(f"\n{'Date/Hour':<20s} {'Count':>7s}  Distribution")
    print("-" * 70)

    for key in sorted(buckets.keys()):
        count = buckets[key]
        bar_len = int((count / max_count) * bar_width) if max_count > 0 else 0
        bar = "█" * bar_len

        # Top event IDs for this bucket
        top_eids = sorted(event_ids_per_bucket[key].items(), key=lambda x: -x[1])[:3]
        eid_str = ", ".join(f"{eid}({c})" for eid, c in top_eids)

        print(f"  {key:<18s} {count:>7d}  {bar}  {eid_str}")

    # Summary: top event IDs overall
    all_eids = {}
    for r in records:
        eid = r.get('event_id', '?')
        all_eids[eid] = all_eids.get(eid, 0) + 1

    print(f"\n### TOP EVENT IDs ###\n")
    for eid, count in sorted(all_eids.items(), key=lambda x: -x[1])[:15]:
        name = EVENT_NAMES.get(eid, '')
        print(f"  {eid:>6s}  {count:>7d}  {name}")

    # Provider summary
    providers = {}
    for r in records:
        prov = r.get('provider', '') or r.get('channel', '') or '(unknown)'
        providers[prov] = providers.get(prov, 0) + 1

    if providers:
        print(f"\n### PROVIDERS ###\n")
        for prov, count in sorted(providers.items(), key=lambda x: -x[1])[:10]:
            print(f"  {count:>7d}  {prov}")


# =============================================================================
# POWERSHELL HISTORY
# =============================================================================

def cmd_ps_hist(kape_path: Path):
    """Show PowerShell console history."""
    print("=" * 70)
    print("POWERSHELL CONSOLE HISTORY")
    print("=" * 70)

    # Search for ConsoleHost_history.txt in user profiles
    hist_files = find_files(kape_path, '**/PSReadline/ConsoleHost_history.txt')

    if not hist_files:
        # Try broader search
        hist_files = find_files(kape_path, '**/ConsoleHost_history.txt')

    if not hist_files:
        print("\nNo PowerShell history found.")
        return

    for hist_file in hist_files:
        # Extract username from path
        path_str = str(hist_file)
        user = "unknown"
        if '/Users/' in path_str:
            parts = path_str.split('/Users/')
            if len(parts) > 1:
                user = parts[1].split('/')[0]

        print(f"\n### User: {user} ###")
        print(f"File: {hist_file.name}\n")

        try:
            content = read_text_file(hist_file)
            for i, line in enumerate(content.strip().split('\n'), 1):
                print(f"  {i:>3}  {line}")
        except Exception as e:
            print(f"  Error reading file: {e}")


# =============================================================================
# REGISTRY ANALYSIS COMMANDS
# =============================================================================

def cmd_mounted_devices(kape_path: Path, raw: bool = False):
    """Show mounted devices (USB/drive history)."""
    print("=" * 70)
    print("MOUNTED DEVICES")
    print("=" * 70)

    md_files = find_files(kape_path, '**/*MountedDevices*.csv')
    if not md_files:
        print("\nNo MountedDevices data found.")
        return

    all_records = []
    for mf in md_files:
        try:
            all_records.extend(read_csv_file(mf))
        except:
            pass

    print(f"\nTotal entries: {len(all_records)}\n")
    print(f"  {'Value Name':<30} {'Device Name / Data'}")
    print(f"  {'-'*30} {'-'*60}")

    for r in all_records:
        vname = r.get('BatchValueName', r.get('ValueName', ''))
        dev_name = r.get('DeviceName', '')
        dev_data = r.get('DeviceData', '')
        display = dev_name or dev_data
        if not raw and len(display) > 80:
            display = display[:77] + '...'
        print(f"  {vname:<30} {display}")


def cmd_known_networks(kape_path: Path, raw: bool = False):
    """Show known network profiles (WiFi/LAN history)."""
    print("=" * 70)
    print("KNOWN NETWORKS")
    print("=" * 70)

    kn_files = find_files(kape_path, '**/*KnownNetworks*.csv')
    if not kn_files:
        print("\nNo KnownNetworks data found.")
        return

    all_records = []
    for kf in kn_files:
        try:
            all_records.extend(read_csv_file(kf))
        except:
            pass

    print(f"\nTotal entries: {len(all_records)}\n")
    print(f"  {'Network Name':<30} {'Type':<12} {'First Connected':<22} {'Last Connected':<22} {'Gateway MAC'}")
    print(f"  {'-'*30} {'-'*12} {'-'*22} {'-'*22} {'-'*20}")

    for r in all_records:
        name = r.get('NetworkName', 'Unknown')
        ntype = r.get('NameType', '')
        first = r.get('FirstConnectLOCAL', '')[:19]
        last = r.get('LastConnectedLOCAL', '')[:19]
        gw_mac = r.get('GatewayMacAddress', '')
        dns = r.get('DNSSuffix', '')
        extra = f"  DNS: {dns}" if dns and raw else ""
        print(f"  {name:<30} {ntype:<12} {first:<22} {last:<22} {gw_mac}{extra}")


def cmd_rdp_history(kape_path: Path, raw: bool = False):
    """Show RDP connection history (TerminalServerClient)."""
    print("=" * 70)
    print("RDP CONNECTION HISTORY (TerminalServerClient)")
    print("=" * 70)

    rdp_files = find_files(kape_path, '**/*TerminalServerClient*.csv')
    if not rdp_files:
        print("\nNo TerminalServerClient data found.")
        return

    all_records = []
    for rf in rdp_files:
        try:
            records = read_csv_file(rf)
            # Tag source user from filename
            fname = str(rf)
            user = "unknown"
            if '_Users_' in fname:
                parts = fname.split('_Users_')
                if len(parts) > 1:
                    user = parts[1].split('_')[0]
            for r in records:
                r['_source_user'] = user
            all_records.extend(records)
        except:
            pass

    print(f"\nTotal entries: {len(all_records)}\n")
    print(f"  {'Source User':<15} {'Host':<25} {'Username':<20} {'MRU Pos':>8} {'Last Modified'}")
    print(f"  {'-'*15} {'-'*25} {'-'*20} {'-'*8} {'-'*22}")

    for r in sorted(all_records, key=lambda x: x.get('LastModified', '')):
        src = r.get('_source_user', '')
        host = r.get('HostName', r.get('Hostname', ''))
        user = r.get('Username', '')
        mru = r.get('MRUPosition', '')
        modified = r.get('LastModified', '')[:19]
        print(f"  {src:<15} {host:<25} {user:<20} {mru:>8} {modified}")


def cmd_opensave(kape_path: Path, raw: bool = False):
    """Show file Open/Save dialog history."""
    print("=" * 70)
    print("FILE OPEN/SAVE DIALOG HISTORY (OpenSavePidlMRU)")
    print("=" * 70)

    os_files = find_files(kape_path, '**/*OpenSavePidlMRU*.csv')
    if not os_files:
        print("\nNo OpenSavePidlMRU data found.")
        return

    all_records = []
    for of in os_files:
        try:
            all_records.extend(read_csv_file(of))
        except:
            pass

    # Sort by OpenedOn timestamp
    all_records.sort(key=lambda x: x.get('OpenedOn', ''))

    print(f"\nTotal entries: {len(all_records)}\n")
    print(f"  {'Opened On':<22} {'Ext':<8} {'MRU':>4} {'Path'}")
    print(f"  {'-'*22} {'-'*8} {'-'*4} {'-'*60}")

    for r in all_records:
        opened = r.get('OpenedOn', '')[:19]
        ext = r.get('Extension', '')
        mru = r.get('MruPosition', r.get('MRUPosition', ''))
        path = r.get('AbsolutePath', '')
        if not raw and len(path) > 80:
            path = path[:77] + '...'
        print(f"  {opened:<22} {ext:<8} {mru:>4} {path}")

    if raw:
        # Show details column too
        has_details = [r for r in all_records if r.get('Details', '').strip()]
        if has_details:
            print(f"\n  --- Entries with Details ---")
            for r in has_details:
                opened = r.get('OpenedOn', '')[:19]
                path = r.get('AbsolutePath', '')
                details = r.get('Details', '')
                print(f"  {opened}  {path}")
                print(f"    Details: {details}")


def cmd_lastvisited(kape_path: Path, raw: bool = False):
    """Show last visited folder per application."""
    print("=" * 70)
    print("LAST VISITED FOLDERS PER APPLICATION (LastVisitedPidlMRU)")
    print("=" * 70)

    lv_files = find_files(kape_path, '**/*LastVisitedPidlMRU*.csv')
    if not lv_files:
        print("\nNo LastVisitedPidlMRU data found.")
        return

    all_records = []
    for lf in lv_files:
        try:
            all_records.extend(read_csv_file(lf))
        except:
            pass

    all_records.sort(key=lambda x: x.get('OpenedOn', ''))

    print(f"\nTotal entries: {len(all_records)}\n")
    print(f"  {'Opened On':<22} {'MRU':>4} {'Executable':<25} {'Folder Path'}")
    print(f"  {'-'*22} {'-'*4} {'-'*25} {'-'*50}")

    for r in all_records:
        opened = r.get('OpenedOn', '')[:19]
        mru = r.get('MruPosition', r.get('MRUPosition', ''))
        exe = r.get('Executable', '')
        path = r.get('AbsolutePath', '')
        if not raw and len(path) > 60:
            path = path[:57] + '...'
        print(f"  {opened:<22} {mru:>4} {exe:<25} {path}")


def cmd_run_history(kape_path: Path, raw: bool = False):
    """Show Win+R run dialog history."""
    print("=" * 70)
    print("WIN+R RUN DIALOG HISTORY (RunMRU)")
    print("=" * 70)

    run_files = find_files(kape_path, '**/*RunMRU*.csv')
    if not run_files:
        print("\nNo RunMRU data found.")
        return

    all_records = []
    for rf in run_files:
        try:
            all_records.extend(read_csv_file(rf))
        except:
            pass

    all_records.sort(key=lambda x: x.get('OpenedOn', ''))

    print(f"\nTotal entries: {len(all_records)}\n")
    print(f"  {'Opened On':<22} {'MRU':>4} {'Command'}")
    print(f"  {'-'*22} {'-'*4} {'-'*50}")

    for r in all_records:
        opened = r.get('OpenedOn', '')[:19]
        mru = r.get('MruPosition', r.get('MRUPosition', ''))
        exe = r.get('Executable', r.get('ValueName', ''))
        print(f"  {opened:<22} {mru:>4} {exe}")


def cmd_shellbags(kape_path: Path, raw: bool = False):
    """Show ShellBags (folder browsing history) from raw registry hives."""
    print("=" * 70)
    print("SHELLBAGS — FOLDER BROWSING HISTORY")
    print("=" * 70)

    try:
        from regipy.registry import RegistryHive
        from regipy.plugins.ntuser.shellbags_ntuser import ShellBagNtuserPlugin
        from regipy.plugins.usrclass.shellbags_usrclass import ShellBagUsrclassPlugin
    except ImportError:
        print("\nError: regipy not installed. Run: pip install regipy")
        return

    # Find UsrClass.dat and NTUSER.DAT
    usrclass_files = find_files(kape_path, '**/Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat')
    ntuser_files = find_files(kape_path, '**/Users/*/NTUSER.DAT')
    # Exclude Default user
    ntuser_files = [f for f in ntuser_files if 'Default' not in str(f)]

    all_entries = []

    for uc_path in usrclass_files:
        user = str(uc_path).split('/Users/')[1].split('/')[0] if '/Users/' in str(uc_path) else 'unknown'
        print(f"\n  Parsing UsrClass.dat for user: {user}")
        try:
            reg = RegistryHive(str(uc_path))
            plugin = ShellBagUsrclassPlugin(reg, as_json=True)
            plugin.run()
            for entry in plugin.entries:
                entry['_source'] = f'{user}/UsrClass.dat'
                all_entries.append(entry)
        except Exception as e:
            print(f"    Error: {e}")

    for nt_path in ntuser_files:
        user = str(nt_path).split('/Users/')[1].split('/')[0] if '/Users/' in str(nt_path) else 'unknown'
        print(f"\n  Parsing NTUSER.DAT for user: {user}")
        try:
            reg = RegistryHive(str(nt_path))
            plugin = ShellBagNtuserPlugin(reg, as_json=True)
            plugin.run()
            for entry in plugin.entries:
                entry['_source'] = f'{user}/NTUSER.DAT'
                all_entries.append(entry)
        except Exception as e:
            print(f"    Error: {e}")

    if not all_entries:
        print("\n  No ShellBags entries found.")
        return

    # Sort by last_write timestamp
    def sort_key(e):
        ts = e.get('last_write', '') or ''
        return str(ts)

    all_entries.sort(key=sort_key)

    print(f"\n  Total ShellBags entries: {len(all_entries)}\n")
    print(f"  {'Last Write (UTC)':<22} {'Source':<22} {'Type':<20} {'Path'}")
    print(f"  {'-'*22} {'-'*22} {'-'*20} {'-'*50}")

    limit = None if raw else 60
    for e in all_entries[:limit]:
        ts = str(e.get('last_write', ''))[:19]
        src = e.get('_source', '')
        shell_type = e.get('shell_type', '')
        path = e.get('path', e.get('value', ''))
        if isinstance(path, dict):
            path = path.get('value', str(path))
        if not raw and len(str(path)) > 70:
            path = str(path)[:67] + '...'
        print(f"  {ts:<22} {src:<22} {shell_type:<20} {path}")

    if not raw and len(all_entries) > 60:
        print(f"\n  ... ({len(all_entries) - 60} more entries, use --raw for all)")

    # Highlight network paths (UNC shares and IP addresses in value field)
    def _is_network_entry(e):
        val = str(e.get('value', ''))
        stype = str(e.get('shell_type', ''))
        return (stype in ('Network Location', 'Users Property View')
                and ('192.168' in val or '\\\\' in val or '10.' in val))
    net_entries = [e for e in all_entries if _is_network_entry(e)]
    if net_entries:
        print(f"\n  ### NETWORK PATHS ({len(net_entries)}) ###")
        for e in net_entries:
            ts = str(e.get('last_write', ''))[:19]
            path = e.get('path', e.get('value', ''))
            if isinstance(path, dict):
                path = path.get('value', str(path))
            loc = e.get('location description', '')
            loc_str = f"  ({loc})" if loc else ''
            print(f"  {ts}  {path}{loc_str}")


def cmd_ntuser_autorun(kape_path: Path, raw: bool = False):
    """Show Run/RunOnce keys from NTUSER.DAT (persistence check)."""
    print("=" * 70)
    print("NTUSER.DAT RUN/RUNONCE KEYS (Persistence)")
    print("=" * 70)

    try:
        from regipy.registry import RegistryHive
    except ImportError:
        print("\nError: regipy not installed. Run: pip install regipy")
        return

    ntuser_files = find_files(kape_path, '**/Users/*/NTUSER.DAT')
    ntuser_files = [f for f in ntuser_files if 'Default' not in str(f)]

    run_keys = [
        '\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
        '\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
        '\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices',
        '\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce',
        '\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
    ]

    for nt_path in ntuser_files:
        user = str(nt_path).split('/Users/')[1].split('/')[0] if '/Users/' in str(nt_path) else 'unknown'
        print(f"\n  User: {user}")
        print(f"  File: {nt_path}\n")

        try:
            reg = RegistryHive(str(nt_path))
        except Exception as e:
            print(f"    Error opening hive: {e}")
            continue

        found_any = False
        for key_path in run_keys:
            try:
                key = reg.get_key(key_path)
                values = list(key.iter_values())
                if values:
                    found_any = True
                    print(f"  [{key_path}]")
                    ts = key.header.last_modified
                    print(f"    Last modified: {ts}")
                    for v in values:
                        print(f"    {v.name} = {v.value}")
                    print()
            except Exception:
                pass  # Key doesn't exist

        if not found_any:
            print(f"    No Run/RunOnce entries found (clean)")


def cmd_registry_overview(kape_path: Path, raw: bool = False):
    """Show summary of all available registry artifacts."""
    print("=" * 70)
    print("REGISTRY ARTIFACT OVERVIEW")
    print("=" * 70)
    print(f"\nKAPE Path: {kape_path}\n")

    artifacts = [
        ('Services', '*Services*SYSTEM*.csv', 'System'),
        ('MountedDevices', '*MountedDevices*.csv', 'System'),
        ('KnownNetworks', '*KnownNetworks*.csv', 'System'),
        ('TimeZoneInfo', '*TimeZoneInfo*.csv', 'System'),
        ('UserAccounts', '*UserAccounts*.csv', 'System'),
        ('TerminalServerClient', '*TerminalServerClient*.csv', 'icslab'),
        ('UserAssist', '*UserAssist*.csv', 'engineer'),
        ('OpenSavePidlMRU', '*OpenSavePidlMRU*.csv', 'engineer'),
        ('RecentDocs', '*RecentDocs*.csv', 'engineer'),
        ('LastVisitedPidlMRU', '*LastVisitedPidlMRU*.csv', 'engineer'),
        ('FileExts', '*FileExts*.csv', 'engineer'),
        ('RunMRU', '*RunMRU*.csv', 'engineer'),
        ('CIDSizeMRU', '*CIDSizeMRU*.csv', 'engineer'),
        ('FirstFolder', '*FirstFolder*.csv', 'engineer'),
        ('TypedURLs', '*TypedURLs*.csv', 'engineer'),
    ]

    print(f"  {'Artifact':<25} {'Context':<10} {'Records':>8} {'Size':>10} {'Date Range'}")
    print(f"  {'-'*25} {'-'*10} {'-'*8} {'-'*10} {'-'*30}")

    for name, pattern, context in artifacts:
        files = find_files(kape_path, f'**/{pattern}')
        if not files:
            print(f"  {name:<25} {context:<10} {'—':>8} {'—':>10} not found")
            continue

        total_size = sum(f.stat().st_size for f in files)
        total_records = 0
        dates = []
        for f in files:
            try:
                records = read_csv_file(f)
                total_records += len(records)
                for r in records:
                    for col in ['OpenedOn', 'LastModified', 'LastExecuted',
                                'ExtensionLastOpened', 'FirstConnectLOCAL',
                                'LastConnectedLOCAL', 'Timestamp0', 'LastRun']:
                        ts = r.get(col, '')
                        if ts and len(ts) >= 10:
                            dates.append(ts[:10])
            except:
                pass

        size_str = f"{total_size/1024:.1f}KB" if total_size < 1048576 else f"{total_size/1048576:.1f}MB"
        date_range = ''
        if dates:
            dates.sort()
            date_range = f"{dates[0]} .. {dates[-1]}" if dates[0] != dates[-1] else dates[0]

        print(f"  {name:<25} {context:<10} {total_records:>8} {size_str:>10} {date_range}")

    # Check for raw hive files
    print(f"\n  --- Raw Hive Files ---")
    hive_patterns = [
        ('NTUSER.DAT', '**/Users/*/NTUSER.DAT'),
        ('UsrClass.dat', '**/Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat'),
    ]
    for name, pattern in hive_patterns:
        files = find_files(kape_path, pattern)
        files = [f for f in files if 'Default' not in str(f)]
        for f in files:
            user = str(f).split('/Users/')[1].split('/')[0] if '/Users/' in str(f) else '?'
            size = f.stat().st_size
            size_str = f"{size/1024:.1f}KB" if size < 1048576 else f"{size/1048576:.1f}MB"
            print(f"  {name:<25} {user:<10} {size_str:>10} {f}")


# =============================================================================
# MAIN
# =============================================================================

def main():
    available_tiers = get_available_tiers() or ['t1', 't2', 't3']
    default_tier = 't2' if 't2' in available_tiers else available_tiers[0]

    parser = argparse.ArgumentParser(
        description='Query KAPE/triage artifacts',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Investigation Flow:
  1. files         - Start here: what files are available?
  2. ps-hist       - Check for commands run
  3. timeline      - When were programs executed?
  4. activities    - What GUI activity occurred?
  5. browser       - What sites were visited?
  6. evtx-summary  - What events are logged?
  7. evtx-logons   - Who logged in from where?
  8. evtx-lateral  - Any lateral movement?
""")
    parser.add_argument('command', nargs='?', default='files',
                        help='Command to run (default: files)')
    parser.add_argument('search', nargs='?', help='Search term (for prefetch, amcache, services)')
    parser.add_argument('--tier', default=default_tier, choices=available_tiers,
                        help=f'Artifact tier (default: {default_tier})')
    # Legacy alias
    parser.add_argument('--level', default=None, help=argparse.SUPPRESS)
    parser.add_argument('--raw', action='store_true',
                        help='Show full output without truncation')
    parser.add_argument('--summary', action='store_true',
                        help='For timeline: show only hours with activity (skip empty hours)')
    parser.add_argument('--compact', action='store_true',
                        help='For timeline: one row per hour with comma-separated programs (default in justfile)')
    parser.add_argument('--detailed', action='store_true',
                        help='For timeline: show full per-entry detail (overrides --compact)')
    parser.add_argument('--unified', action='store_true',
                        help='For timeline: unified view with Prefetch + UserAssist + EVTX columns')
    parser.add_argument('--hourly', action='store_true',
                        help='For evtx-timeline: show per-hour instead of per-day')
    parser.add_argument('--from', dest='from_date', default=None,
                        help='For evtx-timeline: start date (YYYY-MM-DD)')
    parser.add_argument('--to', dest='to_date', default=None,
                        help='For evtx-timeline: end date (YYYY-MM-DD)')
    args = parser.parse_args()

    # Support legacy --level flag
    if args.level is not None:
        args.tier = args.level

    kape_path = get_kape_path(args.tier)

    if not kape_path.exists():
        print(f"Error: KAPE path not found: {kape_path}")
        print(f"Ensure triage data is extracted for tier {args.tier}")
        sys.exit(1)

    print(f"[{args.tier.upper()} KAPE: {kape_path.name}]\n")

    commands = {
        # Phase 1: Overview & Discovery
        'files': lambda: cmd_files(kape_path, args.raw),
        'live': lambda: cmd_live(kape_path, args.raw),
        'live-process': lambda: cmd_live_process(kape_path, args.raw),
        'ps': lambda: cmd_ps(kape_path, args.raw),

        # Phase 2: User Activity
        'ps-hist': lambda: cmd_ps_hist(kape_path),
        'timeline': lambda: cmd_timeline(kape_path, args.raw, args.summary, args.compact and not args.detailed, args.unified),
        'activities': lambda: cmd_activities(kape_path, args.raw),
        'browser': lambda: cmd_browser(kape_path, args.raw),

        # Phase 3: Security Events
        'evtx-extract': lambda: cmd_evtx_extract(kape_path, args.raw),
        'evtx-summary': lambda: cmd_evtx_summary(kape_path, args.raw),
        'evtx-logons': lambda: cmd_evtx_logons(kape_path, args.raw),
        'evtx-lateral': lambda: cmd_evtx_lateral(kape_path, args.raw),
        'evtx-timeline': lambda: cmd_evtx_timeline(kape_path, args.search or 'security',
                                                     args.hourly, args.from_date, args.to_date),

        # Phase 4: Detailed Artifacts
        'prefetch': lambda: cmd_prefetch(kape_path, args.search, args.raw),
        'amcache': lambda: cmd_amcache(kape_path, args.search, args.raw),
        'amcache-hash-check': lambda: cmd_amcache_hash_check(kape_path, args.raw),
        'users': lambda: cmd_users(kape_path),
        'services': lambda: cmd_services(kape_path, args.search, args.raw),
        'userassist': lambda: cmd_userassist(kape_path, args.raw),
        'recentdocs': lambda: cmd_recentdocs(kape_path, args.raw),
        'dlls': lambda: cmd_dlls(kape_path, args.search, args.raw, args.from_date, args.to_date),
        'dll-timeline': lambda: cmd_dll_timeline(kape_path, args.hourly, args.raw, args.from_date, args.to_date),
        'fstimeline': lambda: cmd_fstimeline(kape_path, args.search, args.raw),
        'deleted': lambda: cmd_deleted(kape_path, args.raw),
        'jumplists': lambda: cmd_jumplists(kape_path, args.raw),

        # Phase 5: Registry Analysis
        'registry-overview': lambda: cmd_registry_overview(kape_path, args.raw),
        'mounted-devices': lambda: cmd_mounted_devices(kape_path, args.raw),
        'known-networks': lambda: cmd_known_networks(kape_path, args.raw),
        'rdp-history': lambda: cmd_rdp_history(kape_path, args.raw),
        'opensave': lambda: cmd_opensave(kape_path, args.raw),
        'lastvisited': lambda: cmd_lastvisited(kape_path, args.raw),
        'run-history': lambda: cmd_run_history(kape_path, args.raw),
        'shellbags': lambda: cmd_shellbags(kape_path, args.raw),
        'ntuser-autorun': lambda: cmd_ntuser_autorun(kape_path, args.raw),
    }

    if args.command in commands:
        commands[args.command]()
    else:
        print(f"Unknown command: {args.command}")
        print("\nAvailable commands:")
        print("  Phase 1: files, live, live-process, ps")
        print("  Phase 2: ps-hist, timeline, activities, browser")
        print("  Phase 3: evtx-extract, evtx-summary, evtx-timeline, evtx-logons, evtx-lateral")
        print("  Phase 4: prefetch, amcache, amcache-hash-check, users, services, userassist, recentdocs, deleted, jumplists, fstimeline, dlls, dll-timeline")
        print("  Phase 5: registry-overview, mounted-devices, known-networks, rdp-history, opensave, lastvisited, run-history, shellbags, ntuser-autorun")
        sys.exit(1)


if __name__ == '__main__':
    main()
