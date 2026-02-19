"""
Memory forensics analysis module.

Uses Volatility 3 to extract and analyze memory dump artifacts.
"""

import csv
import os
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from .base import (
    ARTIFACTS_PATH, ForensicAnalyzer, InvestigationCriteria,
    run_command, format_bytes
)


# =============================================================================
# MEMORY ANALYZER CLASS
# =============================================================================
class MemoryAnalyzer(ForensicAnalyzer):
    """Memory forensics analyzer using Volatility 3."""

    # Default path to Volatility 3 in micromamba environment
    DEFAULT_VOL3 = Path.home() / 'micromamba-volatility3' / 'bin' / 'vol'

    def __init__(self, tier: int = 1):
        super().__init__(tier, 'memory')
        self._criteria = InvestigationCriteria()
        self.vol3_path = os.environ.get('VOL3_PATH', str(self.DEFAULT_VOL3))

    def get_artifact_files(self) -> dict:
        """Get artifact files from artifacts.yaml."""
        return self._criteria.get_artifact_paths(self.tier, 'memory')

    def get_extraction_steps(self) -> list:
        return [
            ('info', 'Extract OS/system information'),
            ('pslist', 'Extract process list'),
            ('pstree', 'Extract process tree'),
            ('cmdline', 'Extract command lines'),
            ('netscan', 'Extract network connections'),
            ('malfind', 'Extract suspicious memory regions'),
            ('dlllist', 'Extract loaded DLLs'),
            ('handles', 'Extract handles (files, registry, etc.)'),
            ('svcscan', 'Extract Windows services'),
        ]

    def get_analysis_steps(self) -> list:
        return [
            ('system_info', 'Document system information'),
            ('process_analysis', 'Analyze process relationships'),
            ('network_analysis', 'Analyze network connections'),
            ('injection_analysis', 'Analyze suspicious memory regions'),
            ('execution_analysis', 'Analyze command execution'),
        ]

    def get_analysis_file_map(self) -> dict:
        """Custom file mapping for memory analysis."""
        return {
            'system_info': 'system-info.md',
            'process_analysis': 'process-analysis.md',
            'network_analysis': 'network-connections.md',
            'injection_analysis': 'injection-analysis.md',
            'execution_analysis': 'execution-analysis.md',
        }

    def _run_vol3(self, plugin, memory_file, output_file, extra_args=None):
        """Run a Volatility 3 plugin."""
        args = [self.vol3_path, '-f', str(memory_file), plugin]
        if extra_args:
            args.extend(extra_args)

        print(f"  Running: vol3 -f {memory_file.name} {plugin}")
        success, stdout, stderr = run_command(args)

        if success and stdout:
            output_file = Path(output_file)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, 'w') as f:
                f.write(stdout)
            print(f"  Written: {output_file}")
            return True

        if stderr:
            print(f"  Warning: {stderr[:200]}")
        return False

    # =========================================================================
    # EXTRACTION FUNCTIONS
    # =========================================================================
    def extract_info(self):
        """Extract OS and system information."""
        for name, mem_file in self.get_artifact_files().items():
            output = self.extractions_dir / f'{name}-info.txt'
            self._run_vol3('windows.info', mem_file, output)
        self.mark_complete('extractions', 'info')
        return True

    def extract_pslist(self):
        """Extract process list."""
        for name, mem_file in self.get_artifact_files().items():
            output = self.extractions_dir / f'{name}-pslist.txt'
            self._run_vol3('windows.pslist', mem_file, output)
        self.mark_complete('extractions', 'pslist')
        return True

    def extract_pstree(self):
        """Extract process tree."""
        for name, mem_file in self.get_artifact_files().items():
            output = self.extractions_dir / f'{name}-pstree.txt'
            self._run_vol3('windows.pstree', mem_file, output)
        self.mark_complete('extractions', 'pstree')
        return True

    def extract_cmdline(self):
        """Extract process command lines."""
        for name, mem_file in self.get_artifact_files().items():
            output = self.extractions_dir / f'{name}-cmdline.txt'
            self._run_vol3('windows.cmdline', mem_file, output)
        self.mark_complete('extractions', 'cmdline')
        return True

    def extract_netscan(self):
        """Extract network connections."""
        for name, mem_file in self.get_artifact_files().items():
            output = self.extractions_dir / f'{name}-netscan.txt'
            self._run_vol3('windows.netscan', mem_file, output)
        self.mark_complete('extractions', 'netscan')
        return True

    def extract_malfind(self):
        """Extract suspicious memory regions (RWX, injected code)."""
        for name, mem_file in self.get_artifact_files().items():
            output = self.extractions_dir / f'{name}-malfind.txt'
            self._run_vol3('windows.malfind', mem_file, output)
        self.mark_complete('extractions', 'malfind')
        return True

    def extract_dlllist(self):
        """Extract loaded DLLs."""
        for name, mem_file in self.get_artifact_files().items():
            output = self.extractions_dir / f'{name}-dlllist.txt'
            self._run_vol3('windows.dlllist', mem_file, output)
        self.mark_complete('extractions', 'dlllist')
        return True

    def extract_handles(self):
        """Extract open handles."""
        for name, mem_file in self.get_artifact_files().items():
            output = self.extractions_dir / f'{name}-handles.txt'
            self._run_vol3('windows.handles', mem_file, output)
        self.mark_complete('extractions', 'handles')
        return True

    def extract_svcscan(self):
        """Extract Windows services."""
        for name, mem_file in self.get_artifact_files().items():
            output = self.extractions_dir / f'{name}-svcscan.txt'
            self._run_vol3('windows.svcscan', mem_file, output)
        self.mark_complete('extractions', 'svcscan')
        return True

    # =========================================================================
    # ANALYSIS FUNCTIONS
    # =========================================================================
    def analyze_system_info(self):
        """Document system information from memory dump."""
        results = ["# Memory Dump System Information\n"]
        results.append(f"Generated: {datetime.now().isoformat()}\n\n")

        for name in self.get_artifact_files().keys():
            info_file = self.extractions_dir / f'{name}-info.txt'
            if info_file.exists():
                results.append(f"## {name}\n\n")
                results.append("```\n")
                with open(info_file) as f:
                    results.append(f.read())
                results.append("```\n\n")

        output = self.analysis_dir / 'system-info.md'
        with open(output, 'w') as f:
            f.writelines(results)
        print(f"  Written: {output}")
        self.mark_complete('analyses', 'system_info')
        return True

    def analyze_process_analysis(self):
        """Analyze process list and tree for anomalies and items of interest."""
        results = ["# Process Analysis\n"]
        results.append(f"Generated: {datetime.now().isoformat()}\n\n")

        # Suspicious locations for process execution
        suspicious_paths = [
            r'\\users\\', r'\\temp\\', r'\\tmp\\', r'\\downloads\\',
            r'\\appdata\\', r'\\programdata\\', r'\\public\\',
        ]

        # System processes that should have specific parents
        system_process_parents = {
            'smss.exe': ['System'],
            'csrss.exe': ['smss.exe'],
            'wininit.exe': ['smss.exe'],
            'winlogon.exe': ['smss.exe'],
            'services.exe': ['wininit.exe'],
            'lsass.exe': ['wininit.exe'],
            'svchost.exe': ['services.exe'],
        }

        for name in self.get_artifact_files().keys():
            results.append(f"## {name}\n\n")

            # Parse pslist for detailed info
            pslist_file = self.extractions_dir / f'{name}-pslist.txt'
            pstree_file = self.extractions_dir / f'{name}-pstree.txt'
            cmdline_file = self.extractions_dir / f'{name}-cmdline.txt'

            processes = []
            process_by_pid = {}
            if pslist_file.exists():
                with open(pslist_file) as f:
                    lines = f.read().strip().split('\n')
                    # Skip header lines (Volatility version, blank, column headers, blank)
                    for line in lines:
                        parts = line.split('\t')
                        # Only process lines where first field is a number (PID)
                        if len(parts) >= 3 and parts[0].strip().isdigit():
                            proc = {
                                'pid': parts[0].strip(),
                                'ppid': parts[1].strip() if len(parts) > 1 else '',
                                'name': parts[2].strip() if len(parts) > 2 else '',
                                'threads': parts[4].strip() if len(parts) > 4 else '',
                                'handles': parts[5].strip() if len(parts) > 5 else '',
                                'wow64': parts[7].strip() if len(parts) > 7 else '',
                                'createtime': parts[8].strip() if len(parts) > 8 else '',
                                'exittime': parts[9].strip() if len(parts) > 9 else '',
                            }
                            processes.append(proc)
                            process_by_pid[proc['pid']] = proc

            # Parse cmdline for path info
            cmdlines = {}
            if cmdline_file.exists():
                with open(cmdline_file) as f:
                    lines = f.read().strip().split('\n')
                    for line in lines[1:]:
                        parts = line.split('\t')
                        if len(parts) >= 3:
                            cmdlines[parts[0].strip()] = parts[2].strip() if len(parts) > 2 else ''

            # === ANOMALY DETECTION (Heuristics) ===
            results.append("### Anomaly Detection\n\n")

            # 1. Processes from suspicious locations
            results.append("#### Processes from User/Temp Directories\n\n")
            suspicious_location_procs = []
            for proc in processes:
                cmdline = cmdlines.get(proc['pid'], '').lower()
                for susp_path in suspicious_paths:
                    if re.search(susp_path, cmdline, re.IGNORECASE):
                        suspicious_location_procs.append((proc, cmdline))
                        break

            if suspicious_location_procs:
                results.append("| PID | Name | Path |\n")
                results.append("|-----|------|------|\n")
                for proc, cmdline in suspicious_location_procs:
                    path_short = cmdline[:200] + '...' if len(cmdline) > 200 else cmdline
                    results.append(f"| {proc['pid']} | {proc['name']} | `{path_short}` |\n")
            else:
                results.append("*None detected*\n")
            results.append("\n")

            # 2. Terminated processes (may indicate short-lived malicious activity)
            results.append("#### Terminated Processes (short-lived activity)\n\n")
            terminated = [p for p in processes if p.get('exittime') and p['exittime'] != 'N/A']
            if terminated:
                results.append("| PID | Name | Created | Exited |\n")
                results.append("|-----|------|---------|--------|\n")
                for proc in terminated[:20]:
                    results.append(f"| {proc['pid']} | {proc['name']} | {proc['createtime'][:19]} | {proc['exittime'][:19]} |\n")
                if len(terminated) > 20:
                    results.append(f"\n*... and {len(terminated) - 20} more*\n")
            else:
                results.append("*None detected*\n")
            results.append("\n")

            # 3. Processes with 0 threads (hidden/terminated but in list)
            results.append("#### Processes with 0 Threads (potentially hidden)\n\n")
            zero_threads = [p for p in processes if p.get('threads') == '0']
            if zero_threads:
                results.append("| PID | Name | Created |\n")
                results.append("|-----|------|--------|\n")
                for proc in zero_threads:
                    results.append(f"| {proc['pid']} | {proc['name']} | {proc['createtime'][:19] if proc.get('createtime') else 'N/A'} |\n")
            else:
                results.append("*None detected*\n")
            results.append("\n")

            # 4. Unusual parent-child relationships
            results.append("#### Unusual Parent-Child Relationships\n\n")
            unusual_parents = []
            for proc in processes:
                proc_name = proc['name'].lower()
                if proc_name in system_process_parents:
                    ppid = proc['ppid']
                    parent = process_by_pid.get(ppid, {})
                    parent_name = parent.get('name', 'Unknown').lower()
                    expected = [p.lower() for p in system_process_parents[proc_name]]
                    if parent_name not in expected and parent_name != 'unknown':
                        unusual_parents.append((proc, parent_name, expected))

            if unusual_parents:
                results.append("| Process | PID | Actual Parent | Expected Parent |\n")
                results.append("|---------|-----|---------------|----------------|\n")
                for proc, actual, expected in unusual_parents:
                    results.append(f"| {proc['name']} | {proc['pid']} | {actual} | {', '.join(expected)} |\n")
            else:
                results.append("*None detected*\n")
            results.append("\n")

            # === INVESTIGATION CRITERIA MATCHES ===
            results.append("### Matches to Investigation Criteria\n\n")
            matched = []
            for proc in processes:
                if self.criteria.matches_process(proc['name']):
                    note = self.criteria.get_note('processes', proc['name'])
                    cmdline = cmdlines.get(proc['pid'], '')
                    matched.append((proc, note, cmdline))

            if matched:
                results.append("| PID | Name | Command Line | Note |\n")
                results.append("|-----|------|--------------|------|\n")
                for proc, note, cmdline in matched:
                    cmd_short = cmdline[:200] + '...' if len(cmdline) > 200 else cmdline
                    results.append(f"| {proc['pid']} | {proc['name']} | `{cmd_short}` | {note} |\n")
            else:
                results.append("*No processes matching investigation criteria*\n")
            results.append("\n")

            # === PROCESS TREE ===
            if pstree_file.exists():
                results.append("### Process Tree (Reference)\n\n")
                results.append("```\n")
                with open(pstree_file) as f:
                    content = f.read()
                    if len(content) > 15000:
                        content = content[:15000] + "\n... (truncated)\n"
                    results.append(content)
                results.append("```\n\n")

        output = self.analysis_dir / 'process-analysis.md'
        with open(output, 'w') as f:
            f.writelines(results)
        print(f"  Written: {output}")
        self.mark_complete('analyses', 'process_analysis')
        return True

    def analyze_network_analysis(self):
        """Analyze network connections for anomalies and items of interest."""
        results = ["# Network Connections (Memory)\n"]
        results.append(f"Generated: {datetime.now().isoformat()}\n\n")

        # Suspicious ports (common for C2, exfil, tunneling)
        suspicious_ports = {
            '4444': 'Metasploit default',
            '5555': 'Common backdoor',
            '8080': 'Alt HTTP (verify process)',
            '8443': 'Alt HTTPS (verify process)',
            '1080': 'SOCKS proxy',
            '3128': 'HTTP proxy',
            '9050': 'Tor SOCKS',
            '9001': 'Tor relay',
        }

        for name in self.get_artifact_files().keys():
            results.append(f"## {name}\n\n")

            netscan_file = self.extractions_dir / f'{name}-netscan.txt'
            if not netscan_file.exists():
                results.append("*No netscan data available*\n\n")
                continue

            with open(netscan_file) as f:
                content = f.read()

            # Parse connections with more detail
            connections = []
            lines = content.strip().split('\n')
            for line in lines[1:]:  # Skip header
                parts = line.split('\t')
                if len(parts) >= 6:
                    conn = {
                        'offset': parts[0].strip(),
                        'proto': parts[1].strip(),
                        'local_addr': parts[2].strip(),
                        'local_port': parts[3].strip(),
                        'foreign_addr': parts[4].strip(),
                        'foreign_port': parts[5].strip(),
                        'state': parts[6].strip() if len(parts) > 6 else '',
                        'pid': parts[7].strip() if len(parts) > 7 else '',
                        'owner': parts[8].strip() if len(parts) > 8 else '',
                        'created': parts[9].strip() if len(parts) > 9 else '',
                        'line': line,
                    }
                    connections.append(conn)

            # === ANOMALY DETECTION (Heuristics) ===
            results.append("### Anomaly Detection\n\n")

            # 1. All external connections (critical for forensics)
            results.append("#### All External Connections\n\n")
            external = []
            for conn in connections:
                ip = conn['foreign_addr']
                if ip and not self._is_private_ip(ip) and ip not in ['0.0.0.0', '127.0.0.1', '*']:
                    external.append(conn)

            if external:
                results.append("| Local | Foreign | Port | State | Process | PID |\n")
                results.append("|-------|---------|------|-------|---------|-----|\n")
                for conn in external:
                    # Flag based on investigation criteria status
                    ip = conn['foreign_addr']
                    status = self.criteria.get_ip_status(ip)
                    if status == 'benign':
                        flag = " ✓ BENIGN"
                    elif status == 'malicious':
                        flag = " 🔴 MALICIOUS"
                    elif self.criteria.matches_ip(ip):
                        flag = " ⚠️"
                    else:
                        flag = ""
                    results.append(f"| {conn['local_addr']}:{conn['local_port']} | {ip}{flag} | {conn['foreign_port']} | {conn['state']} | {conn['owner']} | {conn['pid']} |\n")

                    # Suggest adding unknown external IPs (skip benign ones)
                    if not self.criteria.matches_ip(ip):
                        self.add_suggestion(self.criteria.suggest_ip(
                            ip,
                            f"External connection to port {conn['foreign_port']} from {conn['owner']}",
                            f"netscan - {name}"
                        ))
            else:
                results.append("*No external connections found*\n")
            results.append("\n")

            # 2. Listening ports
            results.append("#### Listening Ports\n\n")
            listening = [c for c in connections if c['state'] == 'LISTENING']
            if listening:
                results.append("| Address | Port | Process | PID |\n")
                results.append("|---------|------|---------|-----|\n")
                for conn in listening:
                    port_note = suspicious_ports.get(conn['local_port'], '')
                    flag = f" ⚠️ {port_note}" if port_note else ""
                    results.append(f"| {conn['local_addr']} | {conn['local_port']}{flag} | {conn['owner']} | {conn['pid']} |\n")
            else:
                results.append("*No listening ports found*\n")
            results.append("\n")

            # 3. Connections on suspicious ports
            results.append("#### Connections on Suspicious Ports\n\n")
            suspicious_conns = []
            for conn in connections:
                for port, note in suspicious_ports.items():
                    if conn['foreign_port'] == port or conn['local_port'] == port:
                        suspicious_conns.append((conn, port, note))
                        break

            if suspicious_conns:
                results.append("| Connection | Port | Reason | Process |\n")
                results.append("|------------|------|--------|--------|\n")
                for conn, port, note in suspicious_conns:
                    results.append(f"| {conn['local_addr']}:{conn['local_port']} → {conn['foreign_addr']}:{conn['foreign_port']} | {port} | {note} | {conn['owner']} |\n")
            else:
                results.append("*None detected*\n")
            results.append("\n")

            # 4. Established connections (active communication)
            results.append("#### Established Connections\n\n")
            established = [c for c in connections if c['state'] == 'ESTABLISHED']
            if established:
                results.append("| Local | Foreign | Process | PID |\n")
                results.append("|-------|---------|---------|-----|\n")
                for conn in established:
                    ip = conn['foreign_addr']
                    status = self.criteria.get_ip_status(ip)
                    if status == 'benign':
                        flag = " ✓ BENIGN"
                    elif status == 'malicious':
                        flag = " 🔴 MALICIOUS"
                    elif self.criteria.matches_ip(ip):
                        flag = " ⚠️"
                    else:
                        flag = ""
                    results.append(f"| {conn['local_addr']}:{conn['local_port']} | {ip}:{conn['foreign_port']}{flag} | {conn['owner']} | {conn['pid']} |\n")
            else:
                results.append("*No established connections found*\n")
            results.append("\n")

            # === INVESTIGATION CRITERIA MATCHES ===
            results.append("### Matches to Investigation Criteria\n\n")
            matched = []
            for conn in connections:
                if self.criteria.matches_ip(conn['foreign_addr']):
                    ip = conn['foreign_addr']
                    note = self.criteria.get_note('ips', ip)
                    status = self.criteria.get_ip_status(ip)
                    matched.append((conn, note, status))

            if matched:
                results.append("| Connection | IP | Process | Status | Note |\n")
                results.append("|------------|-----|---------|--------|------|\n")
                for conn, note, status in matched:
                    status_str = status.upper() if status else "INVESTIGATE"
                    results.append(f"| {conn['local_addr']}:{conn['local_port']} → {conn['foreign_addr']}:{conn['foreign_port']} | {conn['foreign_addr']} | {conn['owner']} | {status_str} | {note} |\n")
            else:
                results.append("*No connections to IPs matching investigation criteria*\n")
            results.append("\n")

        output = self.analysis_dir / 'network-connections.md'
        with open(output, 'w') as f:
            f.writelines(results)
        print(f"  Written: {output}")
        self.mark_complete('analyses', 'network_analysis')
        return True

    def analyze_injection_analysis(self):
        """Analyze malfind results for suspicious memory regions."""
        results = ["# Suspicious Memory Regions (Malfind)\n"]
        results.append(f"Generated: {datetime.now().isoformat()}\n\n")
        results.append("Malfind identifies memory regions with characteristics that\n")
        results.append("warrant further investigation (e.g., RWX permissions, PE headers).\n\n")

        for name in self.get_artifact_files().keys():
            results.append(f"## {name}\n\n")

            malfind_file = self.extractions_dir / f'{name}-malfind.txt'
            if not malfind_file.exists():
                results.append("*No malfind data available*\n\n")
                continue

            with open(malfind_file) as f:
                content = f.read()

            if not content.strip():
                results.append("*No suspicious memory regions identified*\n\n")
                continue

            # Count findings by process
            findings = defaultdict(list)
            current_process = None
            current_finding = []

            for line in content.split('\n'):
                if line.startswith('PID:') or line.startswith('Process:'):
                    if current_process and current_finding:
                        findings[current_process].append('\n'.join(current_finding))
                    current_process = line
                    current_finding = [line]
                elif current_process:
                    current_finding.append(line)

            if current_process and current_finding:
                findings[current_process].append('\n'.join(current_finding))

            # Summary table
            results.append("### Summary\n\n")
            results.append("| Process | Regions Found |\n")
            results.append("|---------|---------------|\n")
            for proc, regions in sorted(findings.items()):
                results.append(f"| {proc[:50]} | {len(regions)} |\n")
            results.append("\n")

            # Details (truncated)
            results.append("### Details\n\n")
            results.append("```\n")
            if len(content) > 15000:
                results.append(content[:15000])
                results.append("\n... (truncated, see extraction file for full output)\n")
            else:
                results.append(content)
            results.append("```\n\n")

        output = self.analysis_dir / 'injection-analysis.md'
        with open(output, 'w') as f:
            f.writelines(results)
        print(f"  Written: {output}")
        self.mark_complete('analyses', 'injection_analysis')
        return True

    def analyze_execution_analysis(self):
        """Analyze command lines and execution artifacts for anomalies."""
        results = ["# Command Line Analysis\n"]
        results.append(f"Generated: {datetime.now().isoformat()}\n\n")

        # Suspicious command patterns (LOLBins, recon, etc.)
        suspicious_patterns = {
            # Execution/Download
            r'powershell.*-e[nc]*\s': 'Encoded PowerShell',
            r'powershell.*downloadstring': 'PowerShell download',
            r'powershell.*iex': 'PowerShell invoke-expression',
            r'powershell.*bypass': 'PowerShell execution bypass',
            r'powershell.*hidden': 'Hidden PowerShell window',
            r'certutil.*-urlcache': 'Certutil download',
            r'certutil.*-decode': 'Certutil decode',
            r'bitsadmin.*/transfer': 'BITS download',
            r'mshta\s': 'MSHTA execution',
            r'rundll32.*javascript': 'Rundll32 script execution',
            r'regsvr32.*/s.*/u': 'Regsvr32 bypass',
            r'wscript|cscript': 'Script host execution',
            # Reconnaissance
            r'whoami': 'User enumeration',
            r'net\s+user': 'User enumeration',
            r'net\s+group': 'Group enumeration',
            r'net\s+localgroup': 'Local group enumeration',
            r'net\s+view': 'Network share enumeration',
            r'net\s+share': 'Share enumeration',
            r'nltest': 'Domain trust enumeration',
            r'dsquery': 'AD query',
            r'systeminfo': 'System enumeration',
            r'ipconfig\s*/all': 'Network enumeration',
            r'netstat': 'Connection enumeration',
            r'tasklist': 'Process enumeration',
            r'qprocess|qwinsta': 'Session enumeration',
            # Credential access
            r'mimikatz': 'Credential dumping',
            r'sekurlsa': 'Credential dumping',
            r'procdump.*lsass': 'LSASS dump',
            r'comsvcs.*minidump': 'Process dump',
            # Lateral movement
            r'psexec': 'Remote execution',
            r'wmic.*/node': 'Remote WMI',
            r'winrm': 'WinRM execution',
            r'schtasks.*/create': 'Scheduled task creation',
            # Persistence
            r'reg\s+add.*\\run': 'Registry run key',
            r'sc\s+create': 'Service creation',
        }

        # Suspicious paths in command lines
        suspicious_paths = [
            r'\\temp\\', r'\\tmp\\', r'\\downloads\\',
            r'\\appdata\\local\\temp', r'\\public\\',
        ]

        for name in self.get_artifact_files().keys():
            results.append(f"## {name}\n\n")

            cmdline_file = self.extractions_dir / f'{name}-cmdline.txt'
            if not cmdline_file.exists():
                results.append("*No cmdline data available*\n\n")
                continue

            with open(cmdline_file) as f:
                content = f.read()

            # Parse command lines
            cmdlines = []
            lines = content.strip().split('\n')
            for line in lines[1:]:  # Skip header
                if '\t' in line:
                    parts = line.split('\t')
                    if len(parts) >= 2:
                        cmdlines.append({
                            'pid': parts[0].strip(),
                            'process': parts[1].strip() if len(parts) > 1 else '',
                            'cmdline': parts[2].strip() if len(parts) > 2 else '',
                        })

            # === ANOMALY DETECTION (Heuristics) ===
            results.append("### Anomaly Detection\n\n")

            # 1. Suspicious command patterns
            results.append("#### Suspicious Command Patterns\n\n")
            suspicious_cmds = []
            for cmd in cmdlines:
                cmdline_lower = cmd['cmdline'].lower()
                for pattern, reason in suspicious_patterns.items():
                    if re.search(pattern, cmdline_lower, re.IGNORECASE):
                        suspicious_cmds.append((cmd, reason))
                        break

            if suspicious_cmds:
                results.append("| PID | Process | Reason | Command Line |\n")
                results.append("|-----|---------|--------|-------------|\n")
                for cmd, reason in suspicious_cmds:
                    cmdline = cmd['cmdline'][:200] + '...' if len(cmd['cmdline']) > 200 else cmd['cmdline']
                    results.append(f"| {cmd['pid']} | {cmd['process']} | {reason} | `{cmdline}` |\n")
            else:
                results.append("*None detected*\n")
            results.append("\n")

            # 2. Commands with suspicious paths
            results.append("#### Execution from Suspicious Paths\n\n")
            suspicious_path_cmds = []
            for cmd in cmdlines:
                cmdline_lower = cmd['cmdline'].lower()
                for path in suspicious_paths:
                    if re.search(path, cmdline_lower, re.IGNORECASE):
                        suspicious_path_cmds.append(cmd)
                        break

            if suspicious_path_cmds:
                results.append("| PID | Process | Command Line |\n")
                results.append("|-----|---------|-------------|\n")
                for cmd in suspicious_path_cmds[:30]:
                    cmdline = cmd['cmdline'][:200] + '...' if len(cmd['cmdline']) > 200 else cmd['cmdline']
                    results.append(f"| {cmd['pid']} | {cmd['process']} | `{cmdline}` |\n")
            else:
                results.append("*None detected*\n")
            results.append("\n")

            # 3. Long/complex command lines (may indicate obfuscation)
            results.append("#### Long Command Lines (>200 chars, potential obfuscation)\n\n")
            long_cmds = [cmd for cmd in cmdlines if len(cmd['cmdline']) > 200]
            if long_cmds:
                for cmd in long_cmds[:20]:
                    results.append(f"**PID {cmd['pid']}** - `{cmd['process']}` ({len(cmd['cmdline'])} chars)\n")
                    results.append("```\n")
                    results.append(cmd['cmdline'])
                    results.append("\n```\n\n")
            else:
                results.append("*None detected*\n")
            results.append("\n")

            # 4. cmd.exe and PowerShell instances (shells)
            results.append("#### Shell Instances (cmd.exe, powershell)\n\n")
            shells = [cmd for cmd in cmdlines if re.search(r'(cmd\.exe|powershell)', cmd['process'].lower())]
            if shells:
                results.append("| PID | Process | Command Line |\n")
                results.append("|-----|---------|-------------|\n")
                for cmd in shells:
                    cmdline = cmd['cmdline'][:200] + '...' if len(cmd['cmdline']) > 200 else cmd['cmdline']
                    results.append(f"| {cmd['pid']} | {cmd['process']} | `{cmdline}` |\n")
            else:
                results.append("*None detected*\n")
            results.append("\n")

            # === INVESTIGATION CRITERIA MATCHES ===
            results.append("### Matches to Investigation Criteria\n\n")
            matched = []
            for cmd in cmdlines:
                if self.criteria.matches_process(cmd['process']):
                    note = self.criteria.get_note('processes', cmd['process'])
                    matched.append((cmd, note))

            if matched:
                results.append("| PID | Process | Note | Command Line |\n")
                results.append("|-----|---------|------|-------------|\n")
                for cmd, note in matched:
                    cmdline = cmd['cmdline'][:200] + '...' if len(cmd['cmdline']) > 200 else cmd['cmdline']
                    results.append(f"| {cmd['pid']} | {cmd['process']} | {note} | `{cmdline}` |\n")
            else:
                results.append("*No command lines from processes of interest*\n")
            results.append("\n")

        output = self.analysis_dir / 'execution-analysis.md'
        with open(output, 'w') as f:
            f.writelines(results)
        print(f"  Written: {output}")
        self.mark_complete('analyses', 'execution_analysis')
        return True

    def _is_private_ip(self, ip):
        """Check if IP is RFC1918 private address or should be ignored."""
        # Filter out non-IPs and special values
        if not ip or ip in ['*', '::', '0.0.0.0', '127.0.0.1', '-']:
            return True  # Treat as "private" to filter out
        # Filter out header text that might slip through
        if not ip[0].isdigit() and not ip.startswith('::'):
            return True
        # IPv6 localhost
        if ip == '::1':
            return True

        parts = ip.split('.')
        if len(parts) != 4:
            return True  # Not a valid IPv4, filter out
        try:
            first = int(parts[0])
            second = int(parts[1])
            if first == 10:
                return True
            if first == 172 and 16 <= second <= 31:
                return True
            if first == 192 and second == 168:
                return True
            return False
        except ValueError:
            return True  # Can't parse, filter out


# =============================================================================
# CLI FUNCTIONS
# =============================================================================
def run_extraction(analyzer, name, force=False):
    """Run a single extraction step."""
    if not force and analyzer.is_complete('extractions', name):
        print(f"  [{name}] Already complete (use --force to re-run)")
        return True

    extract_func = getattr(analyzer, f'extract_{name}', None)
    if extract_func:
        print(f"\n[{name}]")
        return extract_func()
    else:
        print(f"  Unknown extraction: {name}")
        return False


def run_analysis(analyzer, name, force=False, show=False):
    """Run a single analysis step."""
    if not force and analyzer.is_complete('analyses', name):
        if show:
            print(f"\n[{name}] (cached)")
            show_analysis_result(analyzer, name)
        else:
            print(f"  [{name}] Already complete (use --force to re-run)")
        return True

    analyze_func = getattr(analyzer, f'analyze_{name}', None)
    if analyze_func:
        print(f"\n[{name}]")
        result = analyze_func()
        if show:
            show_analysis_result(analyzer, name)
        return result
    else:
        print(f"  Unknown analysis: {name}")
        return False


def show_analysis_result(analyzer, name):
    """Display an analysis result file."""
    file_map = analyzer.get_analysis_file_map()

    if name in file_map:
        output_file = analyzer.analysis_dir / file_map[name]
        if output_file.exists():
            print(f"\n  --- {output_file.name} ---")
            with open(output_file) as f:
                print(f.read())
            print(f"  --- end ---")


# =============================================================================
# MAIN CLI
# =============================================================================
def main():
    """Main CLI entry point for memory analysis."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Memory forensics analysis using Volatility 3'
    )
    parser.add_argument('command', choices=['status', 'extract', 'analyze', 'reset'],
                        help='Command to run')
    parser.add_argument('target', nargs='?', default='all',
                        help='Target step or "all"')
    parser.add_argument('--tier', '-t', type=int, default=1,
                        help='Artifact tier (1, 2, or 3)')
    parser.add_argument('--force', '-f', action='store_true',
                        help='Force re-run of completed steps')
    parser.add_argument('--show', '-s', action='store_true',
                        help='Show analysis output after running')

    args = parser.parse_args()
    analyzer = MemoryAnalyzer(tier=args.tier)

    if args.command == 'status':
        analyzer.show_status()
        return 0

    if args.command == 'reset':
        analyzer.reset_status()
        print("Status reset.")
        return 0

    if args.command == 'extract':
        # Check evidence files exist
        missing = analyzer.check_artifacts()
        if missing:
            print("ERROR: Missing artifact files:")
            for name, path in missing:
                print(f"  {name}: {path}")
            return 1

        steps = [s[0] for s in analyzer.get_extraction_steps()]
        if args.target == 'all':
            for step in steps:
                run_extraction(analyzer, step, args.force)
        elif args.target in steps:
            run_extraction(analyzer, args.target, args.force)
        else:
            print(f"Unknown extraction: {args.target}")
            print(f"Available: {', '.join(steps)}")
            return 1
        return 0

    if args.command == 'analyze':
        steps = [s[0] for s in analyzer.get_analysis_steps()]
        if args.target == 'all':
            for step in steps:
                run_analysis(analyzer, step, args.force, args.show)
        elif args.target in steps:
            run_analysis(analyzer, args.target, args.force, args.show)
        else:
            print(f"Unknown analysis: {args.target}")
            print(f"Available: {', '.join(steps)}")
            return 1

        # Show suggestions at the end
        analyzer.show_suggestions()
        return 0

    return 1


if __name__ == '__main__':
    import sys
    sys.exit(main())
