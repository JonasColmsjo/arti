#!/usr/bin/env python3
"""
Extract and parse disk artifacts from raw disk images.
Produces KAPE-compatible CSV output.

Usage:
    extract_disk_artifacts.py <raw_image> <output_dir> [--partition-offset N]
    extract_disk_artifacts.py prefetch <raw_image> <output_dir>
    extract_disk_artifacts.py evtx <raw_image> <output_dir>
    extract_disk_artifacts.py lnk <raw_image> <output_dir>
    extract_disk_artifacts.py registry <raw_image> <output_dir>
    extract_disk_artifacts.py all <raw_image> <output_dir>
"""

import argparse
import csv
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

# Check for required libraries
try:
    import windowsprefetch
except ImportError:
    windowsprefetch = None

try:
    import LnkParse3
except ImportError:
    LnkParse3 = None

try:
    from Evtx.Evtx import Evtx
    from Evtx.Views import evtx_file_xml_view
    import xml.etree.ElementTree as ET
except ImportError:
    Evtx = None

try:
    from regipy.registry import RegistryHive
    from regipy.plugins.system.shimcache import ShimCachePlugin
    from regipy.plugins.ntuser.user_assist import UserAssistPlugin
except ImportError:
    RegistryHive = None


def run_cmd(cmd, check=True):
    """Run shell command and return output."""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and result.returncode != 0:
        print(f"Warning: {cmd} failed: {result.stderr}", file=sys.stderr)
        return None
    return result.stdout


def find_inode(image, path, offset=0):
    """Find inode number for a path in the image."""
    # Build path components
    parts = path.strip('/').split('/')
    current_inode = None

    for i, part in enumerate(parts):
        if current_inode:
            cmd = f"fls -o {offset} '{image}' {current_inode} 2>/dev/null"
        else:
            cmd = f"fls -o {offset} '{image}' 2>/dev/null"

        output = run_cmd(cmd, check=False)
        if not output:
            return None

        # Parse fls output: "d/d 12345-128-1:  filename" or "r/r 12345:  filename"
        found = False
        for line in output.strip().split('\n'):
            # Extract filename from line (everything after the colon and whitespace)
            if ':' not in line:
                continue
            parts_line = line.split(None, 2)  # Split into: type, inode:, filename
            if len(parts_line) < 3:
                continue
            filename = parts_line[2].strip()
            # Case-insensitive exact match
            if filename.lower() == part.lower():
                inode_part = parts_line[1].rstrip(':')
                current_inode = inode_part.split('-')[0]
                found = True
                break
        if not found:
            return None

    return current_inode


def extract_file(image, inode, output_path, offset=0):
    """Extract a file from image using icat."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    cmd = f"icat -o {offset} '{image}' {inode} > '{output_path}' 2>/dev/null"
    result = subprocess.run(cmd, shell=True)
    return result.returncode == 0


def list_directory(image, path, offset=0):
    """List files in a directory, returning (name, inode) tuples."""
    inode = find_inode(image, path, offset)
    if not inode:
        return []

    cmd = f"fls -o {offset} '{image}' {inode} 2>/dev/null"
    output = run_cmd(cmd, check=False)
    if not output:
        return []

    files = []
    for line in output.strip().split('\n'):
        if not line.strip():
            continue
        # Parse: "r/r 12345-128-1:  filename"
        parts = line.split(None, 2)
        if len(parts) >= 2:
            inode_part = parts[1].rstrip(':')
            inode_num = inode_part.split('-')[0]
            name = parts[2].strip() if len(parts) > 2 else ""
            if name and not name.startswith('$'):
                files.append((name, inode_num))

    return files


def try_paths(image, paths, offset=0):
    """Try multiple path patterns (for KAPE triage vs full disk)."""
    for path in paths:
        files = list_directory(image, path, offset)
        if files:
            return files, path
    return [], None


def extract_prefetch(image, output_dir, offset=0):
    """Extract and parse Prefetch files."""
    if not windowsprefetch:
        print("windowsprefetch not installed, skipping prefetch extraction")
        return

    print("Extracting Prefetch files...")
    prefetch_dir = os.path.join(output_dir, 'ProgramExecution', 'Prefetch')
    os.makedirs(prefetch_dir, exist_ok=True)

    # Find Prefetch directory (try KAPE triage structure first, then full disk)
    files, found_path = try_paths(image, [
        'C/Windows/Prefetch',
        'Windows/Prefetch',
    ], offset)
    if not files:
        print("  No Prefetch directory found")
        return
    print(f"  Found at: {found_path}")

    records = []
    extracted_count = 0
    parse_errors = 0

    for name, inode in files:
        if not name.lower().endswith('.pf'):
            continue

        # Always extract raw file first
        raw_path = os.path.join(prefetch_dir, name)
        if extract_file(image, inode, raw_path, offset):
            extracted_count += 1

            # Try to parse (may fail on Linux for Win10 compressed prefetch)
            try:
                pf = windowsprefetch.Prefetch(raw_path)
                records.append({
                    'SourceFile': name,
                    'ExecutableName': pf.executableName,
                    'RunCount': pf.runCount,
                    'LastRunTime': pf.lastRunTime.isoformat() if pf.lastRunTime else '',
                    'PrefetchHash': pf.hash,
                    'Volume0Name': pf.volumesInformationArray[0].get('Volume Name', '') if pf.volumesInformationArray else '',
                    'Volume0Serial': pf.volumesInformationArray[0].get('Volume Serial Number', '') if pf.volumesInformationArray else '',
                })
            except (Exception, SystemExit) as e:
                parse_errors += 1
                if parse_errors == 1:  # Only show first error
                    print(f"  Note: Cannot parse Win10 prefetch on Linux (requires Windows)")
                    print(f"  Raw .pf files extracted for manual analysis")

    print(f"  Extracted {extracted_count} prefetch files")

    # Write CSV
    if records:
        csv_path = os.path.join(output_dir, 'prefetch.csv')
        with open(csv_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=records[0].keys())
            writer.writeheader()
            writer.writerows(records)
        print(f"  Wrote {len(records)} prefetch records to {csv_path}")


def extract_evtx(image, output_dir, offset=0):
    """Extract and parse EVTX event logs."""
    if not Evtx:
        print("python-evtx not installed, skipping EVTX extraction")
        return

    print("Extracting Event Logs...")
    evtx_dir = os.path.join(output_dir, 'EventLogs')
    os.makedirs(evtx_dir, exist_ok=True)

    # Key event logs to extract (try KAPE triage structure first)
    logs = [
        ('Security.evtx', 'security'),
        ('System.evtx', 'system'),
        ('Application.evtx', 'application'),
        ('Microsoft-Windows-PowerShell%4Operational.evtx', 'powershell'),
        ('Microsoft-Windows-Sysmon%4Operational.evtx', 'sysmon'),
    ]

    # Try both KAPE triage and full disk paths
    evtx_paths = [
        'C/Windows/System32/winevt/Logs',
        'Windows/System32/winevt/Logs',
    ]

    base_path = None
    for path in evtx_paths:
        if list_directory(image, path, offset):
            base_path = path
            print(f"  Found event logs at: {base_path}")
            break

    if not base_path:
        print("  No event log directory found")
        return

    for log_name, name in logs:
        log_path = f"{base_path}/{log_name}"
        inode = find_inode(image, log_path, offset)
        if not inode:
            print(f"  {name}.evtx not found")
            continue

        # Extract EVTX file
        evtx_path = os.path.join(evtx_dir, f'{name}.evtx')
        if not extract_file(image, inode, evtx_path, offset):
            continue

        # Parse to CSV
        try:
            records = []
            with Evtx(evtx_path) as evtx:
                for record in evtx.records():
                    try:
                        xml_str = record.xml()
                        root = ET.fromstring(xml_str)
                        ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}

                        system = root.find('e:System', ns)
                        if system is None:
                            continue

                        event_id_elem = system.find('e:EventID', ns)
                        time_elem = system.find('e:TimeCreated', ns)
                        computer_elem = system.find('e:Computer', ns)

                        records.append({
                            'TimeCreated': time_elem.get('SystemTime', '') if time_elem is not None else '',
                            'EventID': event_id_elem.text if event_id_elem is not None else '',
                            'Computer': computer_elem.text if computer_elem is not None else '',
                            'RecordID': record.record_num(),
                        })
                    except Exception:
                        continue

            if records:
                csv_path = os.path.join(output_dir, f'{name}_events.csv')
                with open(csv_path, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=['TimeCreated', 'EventID', 'Computer', 'RecordID'])
                    writer.writeheader()
                    writer.writerows(records)
                print(f"  Wrote {len(records)} {name} events to {csv_path}")
        except Exception as e:
            print(f"  Error parsing {name}.evtx: {e}")


def extract_lnk(image, output_dir, offset=0):
    """Extract and parse LNK (shortcut) files."""
    if not LnkParse3:
        print("LnkParse3 not installed, skipping LNK extraction")
        return

    print("Extracting LNK files...")
    lnk_dir = os.path.join(output_dir, 'FileFolderAccess', 'LNK')
    os.makedirs(lnk_dir, exist_ok=True)

    records = []

    # Get list of users (try KAPE triage structure first)
    users_path = None
    for path in ['C/Users', 'Users']:
        users = list_directory(image, path, offset)
        if users:
            users_path = path
            print(f"  Found users at: {users_path}")
            break

    if not users_path:
        print("  No Users directory found")
        return

    for username, _ in users:
        if username.lower() in ['all users', 'default', 'default user', 'public']:
            continue

        recent_path = f'{users_path}/{username}/AppData/Roaming/Microsoft/Windows/Recent'
        files = list_directory(image, recent_path, offset)

        for name, inode in files:
            if not name.lower().endswith('.lnk'):
                continue

            with tempfile.NamedTemporaryFile(suffix='.lnk', delete=False) as tmp:
                tmp_path = tmp.name

            if extract_file(image, inode, tmp_path, offset):
                try:
                    with open(tmp_path, 'rb') as f:
                        lnk = LnkParse3.lnk_file(f)
                        info = lnk.get_json()

                        records.append({
                            'SourceFile': name,
                            'User': username,
                            'TargetPath': info.get('link_info', {}).get('local_base_path', ''),
                            'WorkingDirectory': info.get('string_data', {}).get('working_dir', ''),
                            'CreationTime': info.get('header', {}).get('creation_time', ''),
                            'AccessTime': info.get('header', {}).get('access_time', ''),
                            'WriteTime': info.get('header', {}).get('write_time', ''),
                        })
                except Exception as e:
                    pass  # Skip unparseable LNK files

            os.unlink(tmp_path)

    if records:
        csv_path = os.path.join(output_dir, 'lnk.csv')
        with open(csv_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=records[0].keys())
            writer.writeheader()
            writer.writerows(records)
        print(f"  Wrote {len(records)} LNK records to {csv_path}")


def extract_registry(image, output_dir, offset=0):
    """Extract registry hives and parse with regipy."""
    if not RegistryHive:
        print("regipy not installed, skipping registry extraction")
        return

    print("Extracting Registry hives...")
    reg_dir = os.path.join(output_dir, 'Registry')
    os.makedirs(reg_dir, exist_ok=True)

    # Detect path prefix (KAPE triage vs full disk)
    prefix = ""
    for path in ['C/Windows', 'Windows']:
        if list_directory(image, path, offset):
            prefix = "C/" if path.startswith("C/") else ""
            print(f"  Detected path prefix: '{prefix}'")
            break

    # System hives
    system_hives = [
        (f'{prefix}Windows/System32/config/SYSTEM', 'SYSTEM'),
        (f'{prefix}Windows/System32/config/SOFTWARE', 'SOFTWARE'),
        (f'{prefix}Windows/System32/config/SAM', 'SAM'),
        (f'{prefix}Windows/System32/config/SECURITY', 'SECURITY'),
    ]

    for hive_path, name in system_hives:
        inode = find_inode(image, hive_path, offset)
        if not inode:
            print(f"  {name} not found")
            continue

        out_path = os.path.join(reg_dir, name)
        if extract_file(image, inode, out_path, offset):
            print(f"  Extracted {name}")

    # User hives
    users_path = f'{prefix}Users'
    users = list_directory(image, users_path, offset)
    for username, _ in users:
        if username.lower() in ['all users', 'default', 'default user', 'public']:
            continue

        user_dir = os.path.join(reg_dir, username)
        os.makedirs(user_dir, exist_ok=True)

        ntuser_path = f'{users_path}/{username}/NTUSER.DAT'
        inode = find_inode(image, ntuser_path, offset)
        if inode:
            out_path = os.path.join(user_dir, 'NTUSER.DAT')
            if extract_file(image, inode, out_path, offset):
                print(f"  Extracted {username}/NTUSER.DAT")

        usrclass_path = f'{users_path}/{username}/AppData/Local/Microsoft/Windows/UsrClass.dat'
        inode = find_inode(image, usrclass_path, offset)
        if inode:
            out_path = os.path.join(user_dir, 'UsrClass.dat')
            if extract_file(image, inode, out_path, offset):
                print(f"  Extracted {username}/UsrClass.dat")

    # Parse hives with regipy (all plugins)
    print("  Parsing registry with regipy...")
    parsed_dir = os.path.join(output_dir, 'Registry', 'parsed')
    os.makedirs(parsed_dir, exist_ok=True)

    for hive_file in Path(reg_dir).glob('*'):
        if hive_file.is_file() and hive_file.name in ['SYSTEM', 'SOFTWARE', 'SAM', 'SECURITY']:
            out_json = os.path.join(parsed_dir, f'{hive_file.name.lower()}.json')
            cmd = f"regipy-plugins-run -o '{out_json}' '{hive_file}' 2>/dev/null"
            subprocess.run(cmd, shell=True)

    for user_dir in Path(reg_dir).iterdir():
        if user_dir.is_dir() and user_dir.name not in ['parsed']:
            user_parsed = os.path.join(parsed_dir, user_dir.name)
            os.makedirs(user_parsed, exist_ok=True)

            ntuser = user_dir / 'NTUSER.DAT'
            if ntuser.exists():
                out_json = os.path.join(user_parsed, 'ntuser.json')
                cmd = f"regipy-plugins-run -o '{out_json}' '{ntuser}' 2>/dev/null"
                subprocess.run(cmd, shell=True)

            usrclass = user_dir / 'UsrClass.dat'
            if usrclass.exists():
                out_json = os.path.join(user_parsed, 'usrclass.json')
                cmd = f"regipy-plugins-run -o '{out_json}' '{usrclass}' 2>/dev/null"
                subprocess.run(cmd, shell=True)

    # Convert regipy JSON to KAPE-compatible CSVs
    print("  Converting to KAPE-compatible CSVs...")
    convert_regipy_to_kape_csv(output_dir)


def convert_regipy_to_kape_csv(output_dir):
    """Convert regipy JSON output to KAPE-compatible CSV format."""
    parsed_dir = Path(output_dir) / 'Registry' / 'parsed'
    registry_dir = Path(output_dir) / 'Registry'

    # UserAssist - combine from all users
    userassist_records = []
    for user_json in parsed_dir.glob('*/ntuser.json'):
        username = user_json.parent.name
        try:
            with open(user_json) as f:
                data = json.load(f)
            for entry in data.get('user_assist', []):
                userassist_records.append({
                    'User': username,
                    'ProgramName': entry.get('name', ''),
                    'RunCounter': entry.get('run_counter', 0),
                    'FocusCount': entry.get('focus_count', 0),
                    'FocusTime': entry.get('total_focus_time_ms', 0),
                    'LastExecuted': entry.get('timestamp', ''),
                })
        except (json.JSONDecodeError, KeyError):
            pass

    if userassist_records:
        csv_path = registry_dir / 'UserAssist.csv'
        with open(csv_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['User', 'ProgramName', 'RunCounter', 'FocusCount', 'FocusTime', 'LastExecuted'])
            writer.writeheader()
            writer.writerows(userassist_records)
        print(f"    UserAssist.csv: {len(userassist_records)} entries")

    # ShellBags - combine from all users
    shellbag_records = []
    for user_json in list(parsed_dir.glob('*/ntuser.json')) + list(parsed_dir.glob('*/usrclass.json')):
        username = user_json.parent.name
        source = 'NTUSER' if 'ntuser' in user_json.name else 'UsrClass'
        try:
            with open(user_json) as f:
                data = json.load(f)
            for plugin in ['ntuser_shellbag_plugin', 'usrclass_shellbag_plugin']:
                for entry in data.get(plugin, []):
                    shellbag_records.append({
                        'User': username,
                        'Source': source,
                        'Value': entry.get('value', ''),
                        'LastWrite': entry.get('last_write', ''),
                    })
        except (json.JSONDecodeError, KeyError):
            pass

    if shellbag_records:
        csv_path = registry_dir / 'ShellBags.csv'
        with open(csv_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['User', 'Source', 'Value', 'LastWrite'])
            writer.writeheader()
            writer.writerows(shellbag_records)
        print(f"    ShellBags.csv: {len(shellbag_records)} entries")

    # Services from SYSTEM hive (nested structure: services[controlset]['services'])
    services_records = []
    system_json = parsed_dir / 'system.json'
    if system_json.exists():
        try:
            with open(system_json) as f:
                data = json.load(f)
            services_data = data.get('services', {})
            # services is a dict with control set keys
            for controlset, controlset_data in services_data.items():
                if isinstance(controlset_data, dict) and 'services' in controlset_data:
                    for entry in controlset_data['services']:
                        services_records.append({
                            'Name': entry.get('name', ''),
                            'LastModified': entry.get('last_modified', ''),
                        })
        except (json.JSONDecodeError, KeyError, TypeError):
            pass

    if services_records:
        csv_path = registry_dir / 'Services.csv'
        with open(csv_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['Name', 'LastModified'])
            writer.writeheader()
            writer.writerows(services_records)
        print(f"    Services.csv: {len(services_records)} entries")

    # Shimcache from SYSTEM hive
    shimcache_records = []
    if system_json.exists():
        try:
            with open(system_json) as f:
                data = json.load(f)
            for entry in data.get('shimcache', []):
                shimcache_records.append({
                    'Path': entry.get('path', ''),
                    'LastModified': entry.get('last_mod_date', ''),
                })
        except (json.JSONDecodeError, KeyError):
            pass

    if shimcache_records:
        csv_path = registry_dir / 'Shimcache.csv'
        with open(csv_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['Path', 'LastModified'])
            writer.writeheader()
            writer.writerows(shimcache_records)
        print(f"    Shimcache.csv: {len(shimcache_records)} entries")

    # RDP History (Terminal Services) - from all users
    rdp_records = []
    for user_json in parsed_dir.glob('*/ntuser.json'):
        username = user_json.parent.name
        try:
            with open(user_json) as f:
                data = json.load(f)
            for entry in data.get('terminal_services_history', []):
                rdp_records.append({
                    'User': username,
                    'Server': entry.get('server', ''),
                    'LastConnection': entry.get('last_connection', ''),
                    'UsernameHint': entry.get('username_hint', ''),
                })
        except (json.JSONDecodeError, KeyError, TypeError):
            pass

    if rdp_records:
        csv_path = registry_dir / 'RDPHistory.csv'
        with open(csv_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['User', 'Server', 'LastConnection', 'UsernameHint'])
            writer.writeheader()
            writer.writerows(rdp_records)
        print(f"    RDPHistory.csv: {len(rdp_records)} entries")

    # Persistence (Run keys) - from all users
    # regipy returns nested dict: {path: {timestamp, values: [{name, value, ...}]}}
    persistence_records = []
    for user_json in parsed_dir.glob('*/ntuser.json'):
        username = user_json.parent.name
        try:
            with open(user_json) as f:
                data = json.load(f)
            persistence_data = data.get('ntuser_persistence', {})
            if isinstance(persistence_data, dict):
                for reg_path, path_data in persistence_data.items():
                    if isinstance(path_data, dict):
                        timestamp = path_data.get('timestamp', '')
                        for val in path_data.get('values', []):
                            persistence_records.append({
                                'User': username,
                                'Name': val.get('name', ''),
                                'Value': val.get('value', ''),
                                'Path': reg_path,
                                'Timestamp': timestamp,
                            })
        except (json.JSONDecodeError, KeyError, TypeError):
            pass

    if persistence_records:
        csv_path = registry_dir / 'Persistence.csv'
        with open(csv_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['User', 'Name', 'Value', 'Path', 'Timestamp'])
            writer.writeheader()
            writer.writerows(persistence_records)
        print(f"    Persistence.csv: {len(persistence_records)} entries")

    # Network List (known networks) - from SOFTWARE hive
    network_records = []
    software_json = parsed_dir / 'software.json'
    if software_json.exists():
        try:
            with open(software_json) as f:
                data = json.load(f)
            for entry in data.get('networklist', []):
                network_records.append({
                    'ProfileName': entry.get('profile_name', ''),
                    'Description': entry.get('description', ''),
                    'Category': entry.get('category', ''),
                    'NameType': entry.get('name_type', ''),
                    'DateCreated': entry.get('date_created', ''),
                    'DateLastConnected': entry.get('date_last_connected', ''),
                    'LastWrite': entry.get('last_write', ''),
                })
        except (json.JSONDecodeError, KeyError, TypeError):
            pass

    if network_records:
        csv_path = registry_dir / 'NetworkList.csv'
        with open(csv_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['ProfileName', 'Description', 'Category', 'NameType', 'DateCreated', 'DateLastConnected', 'LastWrite'])
            writer.writeheader()
            writer.writerows(network_records)
        print(f"    NetworkList.csv: {len(network_records)} entries")


def main():
    parser = argparse.ArgumentParser(description='Extract disk artifacts from raw images')
    parser.add_argument('command', choices=['all', 'prefetch', 'evtx', 'lnk', 'registry'],
                        help='What to extract')
    parser.add_argument('image', help='Path to raw disk image')
    parser.add_argument('output_dir', help='Output directory')
    parser.add_argument('--partition-offset', '-o', type=int, default=0,
                        help='Partition offset in sectors (default: 0)')

    args = parser.parse_args()

    if not os.path.exists(args.image):
        print(f"Error: Image not found: {args.image}")
        sys.exit(1)

    os.makedirs(args.output_dir, exist_ok=True)

    extractors = {
        'prefetch': extract_prefetch,
        'evtx': extract_evtx,
        'lnk': extract_lnk,
        'registry': extract_registry,
    }

    if args.command == 'all':
        for name, func in extractors.items():
            func(args.image, args.output_dir, args.partition_offset)
    else:
        extractors[args.command](args.image, args.output_dir, args.partition_offset)

    print("\nDone!")


if __name__ == '__main__':
    main()
