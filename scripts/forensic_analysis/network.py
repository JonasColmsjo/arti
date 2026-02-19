"""
Network forensics analysis module.

Analyzes PCAP files and network logs using tshark and Python parsing.
"""

import csv
import re
import subprocess
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from .base import (
    ARTIFACTS_PATH, ForensicAnalyzer, InvestigationCriteria,
    run_command, format_bytes, parse_bytes
)


# =============================================================================
# PER-PCAP EXTRACTION TEMPLATES
# =============================================================================
# Used by __getattr__ to dynamically generate extract_<pcapname>_<type> methods.
_PCAP_EXTRACTION_TEMPLATES = {
    'info': {'args': ['-q', '-z', 'io,stat,0'], 'ext': 'txt'},
    'conversations': {'args': ['-q', '-z', 'conv,ip'], 'ext': 'txt'},
    'protocols': {'args': ['-q', '-z', 'io,phs'], 'ext': 'txt'},
    'tls': {'args': ['-Y', 'tls.handshake.type == 1', '-T', 'fields',
            '-e', 'frame.number', '-e', 'frame.time_epoch',
            '-e', 'ip.src', '-e', 'ip.dst', '-e', 'tcp.dstport',
            '-e', 'tls.handshake.extensions_server_name',
            '-E', 'header=y', '-E', 'separator=,'], 'ext': 'csv'},
    'http': {'args': ['-Y', 'http.request', '-T', 'fields',
            '-e', 'frame.number', '-e', 'frame.time_epoch',
            '-e', 'ip.src', '-e', 'ip.dst',
            '-e', 'http.request.method', '-e', 'http.host',
            '-e', 'http.request.uri', '-e', 'http.user_agent',
            '-E', 'header=y', '-E', 'separator=\t'], 'ext': 'csv'},
}


# =============================================================================
# NETWORK ANALYZER CLASS
# =============================================================================
class NetworkAnalyzer(ForensicAnalyzer):
    """Network forensics analyzer using tshark."""

    def __init__(self, tier: int = 1):
        super().__init__(tier, 'network')
        self._criteria = InvestigationCriteria()

    def get_artifact_files(self) -> dict:
        """Get artifact files from artifacts.yaml."""
        return self._criteria.get_artifact_paths(self.tier, 'network')

    def __getattr__(self, name):
        """Dynamic dispatch for per-pcap extraction methods.

        Handles extract_<pcapname>_<type> calls (e.g. extract_adversary01_tls)
        by matching against _PCAP_EXTRACTION_TEMPLATES and known PCAP keys.
        """
        if name.startswith('extract_'):
            step = name[len('extract_'):]
            for suffix, template in _PCAP_EXTRACTION_TEMPLATES.items():
                if step.endswith(f'_{suffix}'):
                    pcap_name = step[:-len(f'_{suffix}')]
                    pcap_key = f'{pcap_name}_pcap'
                    if pcap_key in self.get_artifact_files():
                        def make_extractor(pk, pn, tmpl, sfx):
                            def extractor():
                                return self._extract_per_pcap(pk, pn, sfx, tmpl)
                            return extractor
                        return make_extractor(pcap_key, pcap_name, template, suffix)
        raise AttributeError(f"'{type(self).__name__}' has no attribute '{name}'")

    def _extract_per_pcap(self, pcap_key, pcap_name, extraction_type, template):
        """Run a tshark extraction on a single PCAP using a template."""
        pcap = self.get_artifact_files().get(pcap_key)
        output = self.extractions_dir / f'{self.tier_str}-{pcap_name}-{extraction_type}.{template["ext"]}'
        if not pcap or not pcap.exists():
            print(f"  ERROR: PCAP not found: {pcap}")
            return False
        success = self._run_tshark(
            ['-r', str(pcap)] + template['args'], output,
            f'{extraction_type} from {pcap.name}')
        if success:
            self.mark_complete('extractions', f'{pcap_name}_{extraction_type}')
        return success

    def get_extraction_steps(self) -> list:
        artifacts = self.get_artifact_files()
        steps = []

        # Level 1 has specific named extractions (backward compat)
        if self.tier == 1:
            steps.extend([
                ('core_conversations', 'Extract IP conversations from core PCAP'),
                ('core_protocols', 'Extract protocol hierarchy from core PCAP'),
                ('core_tls', 'Extract TLS handshakes from core PCAP'),
                ('core_syn', 'Extract SYN packets from core PCAP'),
                ('egress_conversations', 'Extract IP conversations from egress PCAP'),
                ('egress_tls', 'Extract TLS handshakes from egress PCAP'),
                ('egress_ja3', 'Extract JA3/JA4 fingerprints from egress PCAP'),
                ('egress_ftp', 'Extract FTP sessions from egress PCAP'),
                ('egress_ssh', 'Extract SSH sessions from egress PCAP'),
                ('spader_proxy', 'Extract domains from Spader proxy logs'),
                ('l1_flows', 'Extract TCP/UDP flows from Level 1 PCAPs to CSV'),
            ])

        # Dynamic per-pcap extractions for tier 2+
        pcaps = self._get_pcaps()
        if pcaps and self.tier >= 2:
            for pcap_key, pcap_path in pcaps:
                pcap_name = pcap_key.replace('_pcap', '')
                for ext_type in ['info', 'conversations', 'protocols', 'tls', 'http']:
                    steps.append((
                        f'{pcap_name}_{ext_type}',
                        f'Extract {ext_type} from {pcap_path.name}'
                    ))

        # Evidence-driven special extractions
        if 'openvpn_log' in artifacts:
            steps.append(('l2_openvpn', 'Parse OpenVPN log for connection events'))

        # Generic extractions (all levels with PCAPs)
        steps.append(('packets', 'Extract per-packet CSV with MACs from ALL PCAPs'))
        if pcaps and self.tier >= 2:
            steps.extend([
                ('mac_ip_inventory', 'Extract MAC-to-IP mappings from ARP traffic'),
                ('flows', 'Extract TCP/UDP flows to CSV'),
                ('dns', 'Extract DNS queries to CSV'),
                ('tls', 'Extract TLS/SNI/JA3 fingerprints to CSV'),
            ])

        return steps

    def get_analysis_steps(self) -> list:
        steps = [
            ('top_talkers', 'Analyze top talkers by bytes and connections'),
            ('protocol_dist', 'Analyze protocol distribution'),
            ('tls_analysis', 'Analyze TLS/SNI hostnames'),
            ('ja3_analysis', 'Analyze JA3/JA4 fingerprints'),
            ('sni_forensics', 'Identify forensically interesting SNI domains'),
            ('beacon_analysis', 'Detect periodic beacon patterns'),
            ('infrastructure', 'Document network infrastructure'),
        ]
        # Level 2-specific analyses
        if self.tier == 2:
            steps.extend([
                ('l2_overview', 'Overview of Level 2 captures (timeframes, size)'),
                ('l2_ioc_correlation', 'Correlate Level 1 IOCs with Level 2 captures'),
                ('l2_c2_traffic', 'Identify C2 traffic patterns in captures'),
                ('l2_lateral_movement', 'Analyze lateral movement indicators'),
                ('l2_vpn_analysis', 'Analyze OpenVPN connection patterns'),
            ])
        # Generic analyses (all levels with PCAPs)
        pcaps = self._get_pcaps()
        if pcaps and self.tier >= 2:
            steps.extend([
                ('router_detection', 'Auto-detect routers/gateways from traffic patterns'),
                ('router_analysis', 'Analyze routing topology for detected gateways'),
                ('file_transfers', 'Document extracted file transfers'),
                ('malware_scan', 'Scan extracted files for malware (PE analysis, YARA)'),
            ])
        return steps

    def _run_tshark(self, args, output_file, description):
        """Run tshark command and save output."""
        output_file = Path(output_file)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        print(f"  {description}")

        try:
            with open(output_file, 'w') as f:
                result = subprocess.run(
                    ['tshark'] + args,
                    stdout=f,
                    stderr=subprocess.PIPE,
                    text=True
                )
            if result.returncode != 0:
                print(f"  ERROR: {result.stderr}")
                return False
            print(f"  Written: {output_file} ({output_file.stat().st_size} bytes)")
            return True
        except Exception as e:
            print(f"  ERROR: {e}")
            return False

    def _extract_mac_ip_mapping(self, pcap_path):
        """Extract MAC-to-IP mapping from a PCAP file.

        Uses Ethernet headers and ARP to build IP-to-MAC lookup.
        Returns dict mapping IP addresses to MAC addresses.
        """
        mac_ip = {}

        if not pcap_path or not Path(pcap_path).exists():
            return mac_ip

        # Extract from Ethernet/IP headers (more comprehensive than ARP alone)
        try:
            result = subprocess.run(
                ['tshark', '-r', str(pcap_path), '-T', 'fields',
                 '-e', 'eth.src', '-e', 'ip.src',
                 '-Y', 'ip'],
                capture_output=True,
                text=True,
                timeout=120
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if '\t' in line:
                        parts = line.split('\t')
                        if len(parts) >= 2 and parts[0] and parts[1]:
                            mac, ip = parts[0].strip(), parts[1].strip()
                            if mac and ip and ':' in mac:
                                mac_ip[ip] = mac.lower()

            # Also get dst MAC-IP pairs
            result = subprocess.run(
                ['tshark', '-r', str(pcap_path), '-T', 'fields',
                 '-e', 'eth.dst', '-e', 'ip.dst',
                 '-Y', 'ip'],
                capture_output=True,
                text=True,
                timeout=120
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if '\t' in line:
                        parts = line.split('\t')
                        if len(parts) >= 2 and parts[0] and parts[1]:
                            mac, ip = parts[0].strip(), parts[1].strip()
                            if mac and ip and ':' in mac:
                                # Only add if not already present (prefer src MAC)
                                if ip not in mac_ip:
                                    mac_ip[ip] = mac.lower()

        except subprocess.TimeoutExpired:
            print(f"    WARNING: MAC extraction timed out for {pcap_path}")
        except Exception as e:
            print(f"    WARNING: MAC extraction failed: {e}")

        return mac_ip

    # =========================================================================
    # EXTRACTION FUNCTIONS
    # =========================================================================
    def extract_core_conversations(self):
        """Extract IP conversations from core PCAP."""
        pcap = self.get_artifact_files().get('core_pcap')
        output = self.extractions_dir / 'core-conversations.txt'

        if not pcap or not pcap.exists():
            print(f"  ERROR: PCAP not found: {pcap}")
            return False

        success = self._run_tshark(
            ['-r', str(pcap), '-q', '-z', 'conv,ip'],
            output,
            'IP conversations from spader-core-minimal.pcap'
        )
        if success:
            self.mark_complete('extractions', 'core_conversations')
        return success

    def extract_core_protocols(self):
        """Extract protocol hierarchy from core PCAP."""
        pcap = self.get_artifact_files().get('core_pcap')
        output = self.extractions_dir / 'core-protocols.txt'

        if not pcap or not pcap.exists():
            print(f"  ERROR: PCAP not found: {pcap}")
            return False

        success = self._run_tshark(
            ['-r', str(pcap), '-q', '-z', 'io,phs'],
            output,
            'Protocol hierarchy from spader-core-minimal.pcap'
        )
        if success:
            self.mark_complete('extractions', 'core_protocols')
        return success

    def extract_core_tls(self):
        """Extract TLS handshakes (Client Hello) from core PCAP."""
        pcap = self.get_artifact_files().get('core_pcap')
        output = self.extractions_dir / 'core-tls.csv'

        if not pcap or not pcap.exists():
            print(f"  ERROR: PCAP not found: {pcap}")
            return False

        success = self._run_tshark(
            ['-r', str(pcap), '-Y', 'tls.handshake.type == 1',
             '-T', 'fields',
             '-e', 'frame.number',
             '-e', 'frame.time_epoch',
             '-e', 'ip.src',
             '-e', 'ip.dst',
             '-e', 'tcp.dstport',
             '-e', 'tls.handshake.extensions_server_name',
             '-E', 'header=y', '-E', 'separator=,'],
            output,
            'TLS Client Hello from spader-core-minimal.pcap'
        )
        if success:
            self.mark_complete('extractions', 'core_tls')
        return success

    def extract_core_syn(self):
        """Extract SYN packets for beacon analysis."""
        pcap = self.get_artifact_files().get('core_pcap')
        output = self.extractions_dir / 'core-syn.csv'

        if not pcap or not pcap.exists():
            print(f"  ERROR: PCAP not found: {pcap}")
            return False

        success = self._run_tshark(
            ['-r', str(pcap), '-Y', 'tcp.flags.syn == 1 && tcp.flags.ack == 0',
             '-T', 'fields',
             '-e', 'frame.number',
             '-e', 'frame.time_epoch',
             '-e', 'ip.src',
             '-e', 'tcp.srcport',
             '-e', 'ip.dst',
             '-e', 'tcp.dstport',
             '-E', 'header=y', '-E', 'separator=,'],
            output,
            'SYN packets from spader-core-minimal.pcap'
        )
        if success:
            self.mark_complete('extractions', 'core_syn')
        return success

    def extract_egress_conversations(self):
        """Extract IP conversations from egress PCAP."""
        pcap = self.get_artifact_files().get('egress_pcap')
        output = self.extractions_dir / 'egress-conversations.txt'

        if not pcap or not pcap.exists():
            print(f"  ERROR: PCAP not found: {pcap}")
            return False

        success = self._run_tshark(
            ['-r', str(pcap), '-q', '-z', 'conv,ip'],
            output,
            'IP conversations from srl-egress-eth3.pcap'
        )
        if success:
            self.mark_complete('extractions', 'egress_conversations')
        return success

    def extract_egress_tls(self):
        """Extract TLS handshakes from egress PCAP."""
        pcap = self.get_artifact_files().get('egress_pcap')
        output = self.extractions_dir / 'egress-tls.csv'

        if not pcap or not pcap.exists():
            print(f"  ERROR: PCAP not found: {pcap}")
            return False

        success = self._run_tshark(
            ['-r', str(pcap), '-Y', 'tls.handshake.type == 1',
             '-T', 'fields',
             '-e', 'frame.number',
             '-e', 'frame.time_epoch',
             '-e', 'ip.src',
             '-e', 'ip.dst',
             '-e', 'tcp.dstport',
             '-e', 'tls.handshake.extensions_server_name',
             '-E', 'header=y', '-E', 'separator=,'],
            output,
            'TLS Client Hello from srl-egress-eth3.pcap'
        )
        if success:
            self.mark_complete('extractions', 'egress_tls')
        return success

    def extract_egress_ja3(self):
        """Extract JA3/JA4 fingerprints from egress PCAP."""
        pcap = self.get_artifact_files().get('egress_pcap')
        output = self.extractions_dir / 'egress-ja3.csv'

        if not pcap or not pcap.exists():
            print(f"  ERROR: PCAP not found: {pcap}")
            return False

        success = self._run_tshark(
            ['-r', str(pcap), '-Y', 'tls.handshake',
             '-T', 'fields',
             '-e', 'frame.number',
             '-e', 'frame.time_epoch',
             '-e', 'ip.src',
             '-e', 'ip.dst',
             '-e', 'tls.handshake.type',
             '-e', 'tls.handshake.extensions_server_name',
             '-e', 'tls.handshake.ja3',
             '-e', 'tls.handshake.ja4',
             '-E', 'header=y', '-E', 'separator=\t'],
            output,
            'JA3/JA4 fingerprints from srl-egress-eth3.pcap'
        )
        if success:
            self.mark_complete('extractions', 'egress_ja3')
        return success

    def extract_egress_ftp(self):
        """Extract FTP commands from egress PCAP."""
        pcap = self.get_artifact_files().get('egress_pcap')
        output = self.extractions_dir / 'egress-ftp.csv'

        if not pcap or not pcap.exists():
            print(f"  ERROR: PCAP not found: {pcap}")
            return False

        success = self._run_tshark(
            ['-r', str(pcap), '-Y', 'ftp',
             '-T', 'fields',
             '-e', 'frame.number',
             '-e', 'frame.time_epoch',
             '-e', 'ip.src',
             '-e', 'ip.dst',
             '-e', 'ftp.request.command',
             '-e', 'ftp.request.arg',
             '-e', 'ftp.response.code',
             '-e', 'ftp.response.arg',
             '-E', 'header=y', '-E', 'separator=,'],
            output,
            'FTP sessions from srl-egress-eth3.pcap'
        )
        if success:
            self.mark_complete('extractions', 'egress_ftp')
        return success

    def extract_egress_ssh(self):
        """Extract SSH sessions from egress PCAP."""
        pcap = self.get_artifact_files().get('egress_pcap')
        output = self.extractions_dir / 'egress-ssh.csv'

        if not pcap or not pcap.exists():
            print(f"  ERROR: PCAP not found: {pcap}")
            return False

        success = self._run_tshark(
            ['-r', str(pcap), '-Y', 'ssh',
             '-T', 'fields',
             '-e', 'frame.number',
             '-e', 'frame.time_epoch',
             '-e', 'ip.src',
             '-e', 'ip.dst',
             '-e', 'tcp.srcport',
             '-e', 'tcp.dstport',
             '-E', 'header=y', '-E', 'separator=,'],
            output,
            'SSH sessions from srl-egress-eth3.pcap'
        )
        if success:
            self.mark_complete('extractions', 'egress_ssh')
        return success

    def extract_spader_proxy(self):
        """Extract domains from Spader proxy logs (HTTP traffic)."""
        log_dir = self.get_artifact_files().get('firewall_logs')
        output = self.extractions_dir / 'spader-proxy-domains.csv'
        output.parent.mkdir(parents=True, exist_ok=True)

        if not log_dir or not log_dir.is_dir():
            print(f"  ERROR: Log directory not found: {log_dir}")
            return False

        print(f"  Parsing proxy logs from: {log_dir}")

        url_pattern = re.compile(r'"(?:GET|POST|CONNECT)\s+(?:https?://)?([^/\s:]+)')
        domains = defaultdict(lambda: {'count': 0, 'sources': set(), 'methods': set(), 'timestamps': []})

        proxy_files = sorted(log_dir.glob('st-proxy-*.log'))
        if not proxy_files:
            print(f"  ERROR: No proxy log files found in {log_dir}")
            return False

        for log_file in proxy_files:
            print(f"  Processing: {log_file.name}")
            with open(log_file, 'r', errors='ignore') as f:
                for line in f:
                    match = url_pattern.search(line)
                    if match:
                        domain = match.group(1).lower()
                        parts = line.split()
                        src_ip = None
                        for i, part in enumerate(parts):
                            if 'squid' in part and i + 1 < len(parts):
                                src_ip = parts[i + 1]
                                break
                        ts_match = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', line)
                        timestamp = ts_match.group(1) if ts_match else None
                        method_match = re.search(r'"(GET|POST|CONNECT)\s', line)
                        method = method_match.group(1) if method_match else None

                        domains[domain]['count'] += 1
                        if src_ip:
                            domains[domain]['sources'].add(src_ip)
                        if method:
                            domains[domain]['methods'].add(method)
                        if timestamp and len(domains[domain]['timestamps']) < 5:
                            domains[domain]['timestamps'].append(timestamp)

        with open(output, 'w') as f:
            f.write("domain\tcount\tsources\tmethods\tfirst_seen\n")
            for domain, data in sorted(domains.items(), key=lambda x: x[1]['count'], reverse=True):
                sources = ','.join(sorted(data['sources']))
                methods = ','.join(sorted(data['methods']))
                first_seen = min(data['timestamps']) if data['timestamps'] else ''
                f.write(f"{domain}\t{data['count']}\t{sources}\t{methods}\t{first_seen}\n")

        print(f"  Written: {output} ({len(domains)} unique domains)")
        self.mark_complete('extractions', 'spader_proxy')
        return True

    def extract_l1_flows(self):
        """Extract TCP/UDP flows from Level 1 PCAPs to CSV for fast querying.

        Processes both spader-core-minimal.pcap and srl-egress-eth3.pcap.
        """
        from datetime import datetime, timedelta

        output = self.extractions_dir / 'l1-flows.csv'
        output.parent.mkdir(parents=True, exist_ok=True)

        print("  Extracting flows from Level 1 captures...")

        all_flows = []

        for pcap_key, pcap_name in [('core_pcap', 'spader-core'),
                                     ('egress_pcap', 'stark-egress')]:
            pcap = self.get_artifact_files().get(pcap_key)
            if not pcap or not pcap.exists():
                print(f"  WARNING: PCAP not found: {pcap_key}")
                continue

            print(f"  Processing: {pcap.name}")

            # Get capture start time
            capture_start = None
            try:
                result = subprocess.run(
                    ['tshark', '-r', str(pcap), '-c', '1', '-T', 'fields', '-e', 'frame.time_epoch'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if result.returncode == 0 and result.stdout.strip():
                    epoch = float(result.stdout.strip())
                    capture_start = datetime.utcfromtimestamp(epoch)
                    print(f"    Capture start: {capture_start.isoformat()}")
            except Exception as e:
                print(f"    WARNING: Could not get capture start time: {e}")

            # Extract MAC-IP mapping for this PCAP
            print(f"    Extracting MAC-IP mappings...")
            mac_ip_map = self._extract_mac_ip_mapping(pcap)
            print(f"    Found {len(mac_ip_map)} MAC-IP pairs")

            # Extract TCP flows
            try:
                result = subprocess.run(
                    ['tshark', '-r', str(pcap), '-q', '-z', 'conv,tcp'],
                    capture_output=True,
                    text=True,
                    timeout=600  # 10 min timeout for large PCAPs
                )

                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if '<->' not in line:
                            continue
                        try:
                            parts = line.split()
                            if len(parts) < 10:
                                continue

                            sep_idx = parts.index('<->')
                            src = parts[sep_idx - 1]
                            dst = parts[sep_idx + 1]

                            if ':' in src:
                                src_ip, src_port = src.rsplit(':', 1)
                            else:
                                src_ip, src_port = src, ''

                            if ':' in dst:
                                dst_ip, dst_port = dst.rsplit(':', 1)
                            else:
                                dst_ip, dst_port = dst, ''

                            stats = parts[sep_idx + 2:]
                            if len(stats) >= 11:
                                frames_total = stats[6].replace(',', '')
                                bytes_num = stats[7].replace(',', '')
                                bytes_unit = stats[8] if len(stats) > 8 else 'bytes'
                                rel_start = stats[9]
                                duration = stats[10]

                                try:
                                    bytes_val = float(bytes_num)
                                    if bytes_unit == 'kB':
                                        bytes_total = int(bytes_val * 1024)
                                    elif bytes_unit == 'MB':
                                        bytes_total = int(bytes_val * 1024 * 1024)
                                    elif bytes_unit == 'GB':
                                        bytes_total = int(bytes_val * 1024 * 1024 * 1024)
                                    else:
                                        bytes_total = int(bytes_val)
                                except ValueError:
                                    bytes_total = 0

                                timestamp_utc = ''
                                if capture_start:
                                    try:
                                        rel_seconds = float(rel_start)
                                        abs_time = capture_start + timedelta(seconds=rel_seconds)
                                        timestamp_utc = abs_time.strftime('%Y-%m-%dT%H:%M:%S')
                                    except ValueError:
                                        pass

                                all_flows.append({
                                    'timestamp_utc': timestamp_utc,
                                    'capture': pcap_name,
                                    'proto': 'TCP',
                                    'src_mac': mac_ip_map.get(src_ip, ''),
                                    'src_ip': src_ip,
                                    'src_port': src_port,
                                    'dst_mac': mac_ip_map.get(dst_ip, ''),
                                    'dst_ip': dst_ip,
                                    'dst_port': dst_port,
                                    'frames': frames_total,
                                    'bytes': bytes_total,
                                    'duration': duration,
                                })
                        except (ValueError, IndexError):
                            continue

            except subprocess.TimeoutExpired:
                print(f"  WARNING: Timeout extracting TCP flows from {pcap.name}")
            except Exception as e:
                print(f"  ERROR: {e}")

            # Extract UDP flows
            try:
                result = subprocess.run(
                    ['tshark', '-r', str(pcap), '-q', '-z', 'conv,udp'],
                    capture_output=True,
                    text=True,
                    timeout=600
                )

                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if '<->' not in line:
                            continue
                        try:
                            parts = line.split()
                            if len(parts) < 10:
                                continue

                            sep_idx = parts.index('<->')
                            src = parts[sep_idx - 1]
                            dst = parts[sep_idx + 1]

                            if ':' in src:
                                src_ip, src_port = src.rsplit(':', 1)
                            else:
                                src_ip, src_port = src, ''

                            if ':' in dst:
                                dst_ip, dst_port = dst.rsplit(':', 1)
                            else:
                                dst_ip, dst_port = dst, ''

                            stats = parts[sep_idx + 2:]
                            if len(stats) >= 11:
                                frames_total = stats[6].replace(',', '')
                                bytes_num = stats[7].replace(',', '')
                                bytes_unit = stats[8] if len(stats) > 8 else 'bytes'
                                rel_start = stats[9]
                                duration = stats[10]

                                try:
                                    bytes_val = float(bytes_num)
                                    if bytes_unit == 'kB':
                                        bytes_total = int(bytes_val * 1024)
                                    elif bytes_unit == 'MB':
                                        bytes_total = int(bytes_val * 1024 * 1024)
                                    elif bytes_unit == 'GB':
                                        bytes_total = int(bytes_val * 1024 * 1024 * 1024)
                                    else:
                                        bytes_total = int(bytes_val)
                                except ValueError:
                                    bytes_total = 0

                                timestamp_utc = ''
                                if capture_start:
                                    try:
                                        rel_seconds = float(rel_start)
                                        abs_time = capture_start + timedelta(seconds=rel_seconds)
                                        timestamp_utc = abs_time.strftime('%Y-%m-%dT%H:%M:%S')
                                    except ValueError:
                                        pass

                                all_flows.append({
                                    'timestamp_utc': timestamp_utc,
                                    'capture': pcap_name,
                                    'proto': 'UDP',
                                    'src_mac': mac_ip_map.get(src_ip, ''),
                                    'src_ip': src_ip,
                                    'src_port': src_port,
                                    'dst_mac': mac_ip_map.get(dst_ip, ''),
                                    'dst_ip': dst_ip,
                                    'dst_port': dst_port,
                                    'frames': frames_total,
                                    'bytes': bytes_total,
                                    'duration': duration,
                                })
                        except (ValueError, IndexError):
                            continue

            except subprocess.TimeoutExpired:
                print(f"  WARNING: Timeout extracting UDP flows from {pcap.name}")
            except Exception as e:
                print(f"  ERROR: {e}")

        # Sort by timestamp
        all_flows.sort(key=lambda x: x.get('timestamp_utc', '') or 'zzzz')

        # Write combined flow CSV
        with open(output, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=[
                'timestamp_utc', 'capture', 'proto', 'src_mac', 'src_ip', 'src_port', 'dst_mac', 'dst_ip', 'dst_port', 'frames', 'bytes', 'duration'
            ])
            writer.writeheader()
            writer.writerows(all_flows)

        print(f"  Written: {output} ({len(all_flows)} flows)")
        self.mark_complete('extractions', 'l1_flows')
        return True

    # =========================================================================
    # LEVEL 2 EXTRACTION FUNCTIONS
    # =========================================================================
    def extract_l2_capture1_info(self):
        """Extract capture1.pcap metadata and timeframe."""
        pcap = self.get_artifact_files().get('capture1_pcap')
        output = self.extractions_dir / 'l2-capture1-info.txt'

        if not pcap or not pcap.exists():
            print(f"  ERROR: PCAP not found: {pcap}")
            return False

        success = self._run_tshark(
            ['-r', str(pcap), '-q', '-z', 'io,stat,0'],
            output,
            'Capture1 statistics'
        )
        if success:
            self.mark_complete('extractions', 'l2_capture1_info')
        return success

    def extract_l2_capture1_conversations(self):
        """Extract IP conversations from capture1."""
        pcap = self.get_artifact_files().get('capture1_pcap')
        output = self.extractions_dir / 'l2-capture1-conversations.txt'

        if not pcap or not pcap.exists():
            print(f"  ERROR: PCAP not found: {pcap}")
            return False

        success = self._run_tshark(
            ['-r', str(pcap), '-q', '-z', 'conv,ip'],
            output,
            'IP conversations from capture1.pcap'
        )
        if success:
            self.mark_complete('extractions', 'l2_capture1_conversations')
        return success

    def extract_l2_capture1_protocols(self):
        """Extract protocol hierarchy from capture1."""
        pcap = self.get_artifact_files().get('capture1_pcap')
        output = self.extractions_dir / 'l2-capture1-protocols.txt'

        if not pcap or not pcap.exists():
            print(f"  ERROR: PCAP not found: {pcap}")
            return False

        success = self._run_tshark(
            ['-r', str(pcap), '-q', '-z', 'io,phs'],
            output,
            'Protocol hierarchy from capture1.pcap'
        )
        if success:
            self.mark_complete('extractions', 'l2_capture1_protocols')
        return success

    def extract_l2_capture1_tls(self):
        """Extract TLS handshakes from capture1."""
        pcap = self.get_artifact_files().get('capture1_pcap')
        output = self.extractions_dir / 'l2-capture1-tls.csv'

        if not pcap or not pcap.exists():
            print(f"  ERROR: PCAP not found: {pcap}")
            return False

        success = self._run_tshark(
            ['-r', str(pcap), '-Y', 'tls.handshake.type == 1',
             '-T', 'fields',
             '-e', 'frame.number',
             '-e', 'frame.time_epoch',
             '-e', 'ip.src',
             '-e', 'ip.dst',
             '-e', 'tcp.dstport',
             '-e', 'tls.handshake.extensions_server_name',
             '-E', 'header=y', '-E', 'separator=,'],
            output,
            'TLS Client Hello from capture1.pcap'
        )
        if success:
            self.mark_complete('extractions', 'l2_capture1_tls')
        return success

    def extract_l2_capture1_http(self):
        """Extract HTTP requests from capture1."""
        pcap = self.get_artifact_files().get('capture1_pcap')
        output = self.extractions_dir / 'l2-capture1-http.csv'

        if not pcap or not pcap.exists():
            print(f"  ERROR: PCAP not found: {pcap}")
            return False

        success = self._run_tshark(
            ['-r', str(pcap), '-Y', 'http.request',
             '-T', 'fields',
             '-e', 'frame.number',
             '-e', 'frame.time_epoch',
             '-e', 'ip.src',
             '-e', 'ip.dst',
             '-e', 'http.request.method',
             '-e', 'http.host',
             '-e', 'http.request.uri',
             '-e', 'http.user_agent',
             '-E', 'header=y', '-E', 'separator=\t'],
            output,
            'HTTP requests from capture1.pcap'
        )
        if success:
            self.mark_complete('extractions', 'l2_capture1_http')
        return success

    def extract_l2_capture2_info(self):
        """Extract capture2.pcap metadata and timeframe."""
        pcap = self.get_artifact_files().get('capture2_pcap')
        output = self.extractions_dir / 'l2-capture2-info.txt'

        if not pcap or not pcap.exists():
            print(f"  ERROR: PCAP not found: {pcap}")
            return False

        success = self._run_tshark(
            ['-r', str(pcap), '-q', '-z', 'io,stat,0'],
            output,
            'Capture2 statistics'
        )
        if success:
            self.mark_complete('extractions', 'l2_capture2_info')
        return success

    def extract_l2_capture2_conversations(self):
        """Extract IP conversations from capture2."""
        pcap = self.get_artifact_files().get('capture2_pcap')
        output = self.extractions_dir / 'l2-capture2-conversations.txt'

        if not pcap or not pcap.exists():
            print(f"  ERROR: PCAP not found: {pcap}")
            return False

        success = self._run_tshark(
            ['-r', str(pcap), '-q', '-z', 'conv,ip'],
            output,
            'IP conversations from capture2.pcap'
        )
        if success:
            self.mark_complete('extractions', 'l2_capture2_conversations')
        return success

    def extract_l2_capture2_protocols(self):
        """Extract protocol hierarchy from capture2."""
        pcap = self.get_artifact_files().get('capture2_pcap')
        output = self.extractions_dir / 'l2-capture2-protocols.txt'

        if not pcap or not pcap.exists():
            print(f"  ERROR: PCAP not found: {pcap}")
            return False

        success = self._run_tshark(
            ['-r', str(pcap), '-q', '-z', 'io,phs'],
            output,
            'Protocol hierarchy from capture2.pcap'
        )
        if success:
            self.mark_complete('extractions', 'l2_capture2_protocols')
        return success

    def extract_l2_capture2_tls(self):
        """Extract TLS handshakes from capture2."""
        pcap = self.get_artifact_files().get('capture2_pcap')
        output = self.extractions_dir / 'l2-capture2-tls.csv'

        if not pcap or not pcap.exists():
            print(f"  ERROR: PCAP not found: {pcap}")
            return False

        success = self._run_tshark(
            ['-r', str(pcap), '-Y', 'tls.handshake.type == 1',
             '-T', 'fields',
             '-e', 'frame.number',
             '-e', 'frame.time_epoch',
             '-e', 'ip.src',
             '-e', 'ip.dst',
             '-e', 'tcp.dstport',
             '-e', 'tls.handshake.extensions_server_name',
             '-E', 'header=y', '-E', 'separator=,'],
            output,
            'TLS Client Hello from capture2.pcap'
        )
        if success:
            self.mark_complete('extractions', 'l2_capture2_tls')
        return success

    def extract_l2_capture2_http(self):
        """Extract HTTP requests from capture2."""
        pcap = self.get_artifact_files().get('capture2_pcap')
        output = self.extractions_dir / 'l2-capture2-http.csv'

        if not pcap or not pcap.exists():
            print(f"  ERROR: PCAP not found: {pcap}")
            return False

        success = self._run_tshark(
            ['-r', str(pcap), '-Y', 'http.request',
             '-T', 'fields',
             '-e', 'frame.number',
             '-e', 'frame.time_epoch',
             '-e', 'ip.src',
             '-e', 'ip.dst',
             '-e', 'http.request.method',
             '-e', 'http.host',
             '-e', 'http.request.uri',
             '-e', 'http.user_agent',
             '-E', 'header=y', '-E', 'separator=\t'],
            output,
            'HTTP requests from capture2.pcap'
        )
        if success:
            self.mark_complete('extractions', 'l2_capture2_http')
        return success

    def extract_l2_openvpn(self):
        """Parse OpenVPN log for connection events."""
        log_file = self.get_artifact_files().get('openvpn_log')
        output = self.extractions_dir / 'l2-openvpn-events.csv'
        output.parent.mkdir(parents=True, exist_ok=True)

        if not log_file or not log_file.exists():
            print(f"  ERROR: OpenVPN log not found: {log_file}")
            return False

        print(f"  Parsing OpenVPN log: {log_file}")

        events = []
        with open(log_file, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                # Parse OpenVPN log format: timestamp event details
                # Example: Mon Aug 17 12:34:56 2020 VERIFY OK: ...
                parts = line.split()
                if len(parts) < 5:
                    continue

                # Try to extract timestamp (Mon Aug 17 12:34:56 2020)
                try:
                    ts_str = ' '.join(parts[:5])
                    ts = datetime.strptime(ts_str, '%a %b %d %H:%M:%S %Y')
                    event_type = parts[5] if len(parts) > 5 else ''
                    details = ' '.join(parts[5:]) if len(parts) > 5 else ''

                    events.append({
                        'timestamp': ts.strftime('%Y-%m-%d %H:%M:%S'),
                        'timestamp_utc': ts.strftime('%Y-%m-%dT%H:%M:%SZ'),
                        'event_type': event_type,
                        'details': details[:200],  # Truncate long details
                    })
                except (ValueError, IndexError):
                    # Try alternative format or skip
                    continue

        with open(output, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['timestamp', 'timestamp_utc', 'event_type', 'details'])
            writer.writeheader()
            writer.writerows(events)

        print(f"  Written: {output} ({len(events)} events)")
        self.mark_complete('extractions', 'l2_openvpn')
        return True

    def extract_packets(self):
        """Extract per-packet CSV with MAC addresses from PCAPs for this tier.

        Creates a single per-packet export from PCAP files for the current
        level only. Can be queried instantly with grep/awk instead of
        re-reading multi-GB PCAPs with tshark.

        Includes src/dst MAC addresses for host identification and a 'source'
        column identifying which PCAP each packet came from.
        """
        from datetime import datetime

        output = self.extractions_dir / 'packets.csv'
        output.parent.mkdir(parents=True, exist_ok=True)

        print(f"  Extracting per-packet CSV from L{self.tier} PCAPs (this may take several minutes)...")

        fieldnames = [
            'timestamp_utc', 'level', 'source', 'frame_num', 'src_mac', 'src_ip',
            'dst_mac', 'dst_ip', 'tcp_srcport', 'tcp_dstport',
            'udp_srcport', 'udp_dstport', 'protocol'
        ]

        total_packets = 0

        # Collect PCAPs for this tier only
        pcaps_to_process = []
        level_paths = self._criteria.get_artifact_paths(self.tier, 'network')
        for key, path in level_paths.items():
            if key.endswith('_pcap') and path and path.exists():
                pcaps_to_process.append((self.tier, key, path))

        if not pcaps_to_process:
            print("  WARNING: No PCAP files found")
            return False

        print(f"  Found {len(pcaps_to_process)} PCAP files to process")

        with open(output, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for lvl, pcap_key, pcap in pcaps_to_process:
                # Use PCAP filename (without extension) as source identifier
                source_name = pcap.stem

                print(f"  Processing L{lvl}: {pcap.name} ...")

                # Use tshark -T fields for fast per-packet export
                cmd = [
                    'tshark', '-r', str(pcap), '-T', 'fields',
                    '-E', 'separator=\t', '-E', 'occurrence=f',
                    '-e', 'frame.number',
                    '-e', 'frame.time_epoch',
                    '-e', 'eth.src',
                    '-e', 'ip.src',
                    '-e', 'eth.dst',
                    '-e', 'ip.dst',
                    '-e', 'tcp.srcport',
                    '-e', 'tcp.dstport',
                    '-e', 'udp.srcport',
                    '-e', 'udp.dstport',
                    '-e', '_ws.col.Protocol',
                ]

                try:
                    proc = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        bufsize=1
                    )

                    count = 0
                    for line in proc.stdout:
                        line = line.rstrip('\n')
                        if not line:
                            continue
                        parts = line.split('\t')
                        if len(parts) < 11:
                            parts.extend([''] * (11 - len(parts)))

                        # Convert epoch to human-readable UTC
                        timestamp_utc = ''
                        try:
                            epoch = float(parts[1])
                            dt = datetime.utcfromtimestamp(epoch)
                            timestamp_utc = dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]
                        except (ValueError, IndexError):
                            pass

                        writer.writerow({
                            'timestamp_utc': timestamp_utc,
                            'level': lvl,
                            'source': source_name,
                            'frame_num': parts[0],
                            'src_mac': parts[2],
                            'src_ip': parts[3],
                            'dst_mac': parts[4],
                            'dst_ip': parts[5],
                            'tcp_srcport': parts[6],
                            'tcp_dstport': parts[7],
                            'udp_srcport': parts[8],
                            'udp_dstport': parts[9],
                            'protocol': parts[10],
                        })
                        count += 1
                        if count % 100000 == 0:
                            print(f"    {count:,} packets processed...")

                    proc.wait()
                    if proc.returncode != 0:
                        stderr = proc.stderr.read()
                        print(f"  WARNING: tshark stderr: {stderr[:200]}")

                    total_packets += count
                    print(f"    {pcap.name}: {count:,} packets")

                except Exception as e:
                    print(f"  ERROR processing {pcap.name}: {e}")

        print(f"  Written: {output} ({total_packets:,} packets)")
        self.mark_complete('extractions', 'packets')
        return True

    # Backwards compatibility alias
    def extract_l2_packets(self):
        """Alias for extract_packets() for backwards compatibility."""
        return self.extract_packets()

    # =========================================================================
    # GENERIC EXTRACTION METHODS (work for any tier via _get_pcaps())
    # =========================================================================

    def extract_dns(self):
        """Extract DNS queries from all PCAPs to CSV (any tier)."""
        from datetime import datetime

        output = self.extractions_dir / f'{self.tier_str}-dns.csv'
        output.parent.mkdir(parents=True, exist_ok=True)

        print("  Extracting DNS queries from captures...")

        all_dns = []

        for pcap_key, pcap_path in self._get_pcaps():
            pcap_name = pcap_key.replace('_pcap', '')
            print(f"  Processing: {pcap_path.name}")

            try:
                result = subprocess.run(
                    ['tshark', '-r', str(pcap_path),
                     '-Y', 'dns',
                     '-T', 'fields',
                     '-e', 'frame.time_epoch',
                     '-e', 'ip.src',
                     '-e', 'ip.dst',
                     '-e', 'dns.qry.name',
                     '-e', 'dns.qry.type',
                     '-e', 'dns.flags.rcode',
                     '-e', 'dns.a',
                     '-e', 'dns.aaaa',
                     '-e', 'dns.cname',
                     '-E', 'header=n',
                     '-E', 'separator=\t'],
                    capture_output=True,
                    text=True,
                    timeout=300
                )

                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if not line.strip():
                            continue
                        parts = line.split('\t')
                        if len(parts) < 6:
                            continue

                        try:
                            epoch = float(parts[0])
                            timestamp = datetime.utcfromtimestamp(epoch).strftime('%Y-%m-%dT%H:%M:%S')
                        except (ValueError, IndexError):
                            timestamp = ''

                        src_ip = parts[1] if len(parts) > 1 else ''
                        dst_ip = parts[2] if len(parts) > 2 else ''
                        query_name = parts[3] if len(parts) > 3 else ''
                        query_type = parts[4] if len(parts) > 4 else ''
                        rcode = parts[5] if len(parts) > 5 else ''
                        answer_a = parts[6] if len(parts) > 6 else ''
                        answer_aaaa = parts[7] if len(parts) > 7 else ''
                        answer_cname = parts[8] if len(parts) > 8 else ''

                        if not query_name:
                            continue

                        answers = [a for a in [answer_a, answer_aaaa, answer_cname] if a]
                        answer = ','.join(answers) if answers else ''

                        rcode_names = {'0': 'NOERROR', '1': 'FORMERR', '2': 'SERVFAIL',
                                       '3': 'NXDOMAIN', '4': 'NOTIMP', '5': 'REFUSED'}
                        rcode_name = rcode_names.get(rcode, rcode)

                        qtype_names = {'1': 'A', '2': 'NS', '5': 'CNAME', '6': 'SOA',
                                       '12': 'PTR', '15': 'MX', '16': 'TXT', '28': 'AAAA',
                                       '33': 'SRV', '255': 'ANY', '65': 'HTTPS'}
                        qtype_name = qtype_names.get(query_type, query_type)

                        all_dns.append({
                            'timestamp_utc': timestamp,
                            'capture': pcap_name,
                            'client_ip': src_ip,
                            'server_ip': dst_ip,
                            'query_name': query_name,
                            'query_type': qtype_name,
                            'response_code': rcode_name,
                            'answer': answer
                        })

            except subprocess.TimeoutExpired:
                print(f"  WARNING: Timeout extracting DNS from {pcap_path.name}")
            except Exception as e:
                print(f"  ERROR: {e}")

        all_dns.sort(key=lambda x: x.get('timestamp_utc', '') or 'zzzz')

        with open(output, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=[
                'timestamp_utc', 'capture', 'client_ip', 'server_ip',
                'query_name', 'query_type', 'response_code', 'answer'
            ])
            writer.writeheader()
            writer.writerows(all_dns)

        print(f"  Written: {output} ({len(all_dns)} DNS records)")
        self.mark_complete('extractions', 'dns')
        return True

    def extract_tls(self):
        """Extract TLS handshakes with SNI and JA3 fingerprints from all PCAPs (any tier)."""
        from datetime import datetime

        output = self.extractions_dir / f'{self.tier_str}-tls.csv'
        output.parent.mkdir(parents=True, exist_ok=True)

        print("  Extracting TLS fingerprints from captures...")

        all_tls = []

        for pcap_key, pcap_path in self._get_pcaps():
            pcap_name = pcap_key.replace('_pcap', '')
            print(f"  Processing: {pcap_path.name}")

            try:
                result = subprocess.run(
                    ['tshark', '-r', str(pcap_path),
                     '-Y', 'tls.handshake.type == 1',
                     '-T', 'fields',
                     '-e', 'frame.time_epoch',
                     '-e', 'ip.src',
                     '-e', 'ip.dst',
                     '-e', 'tcp.dstport',
                     '-e', 'tls.handshake.extensions_server_name',
                     '-e', 'tls.handshake.ja3',
                     '-e', 'tls.handshake.ja3_full',
                     '-E', 'header=n',
                     '-E', 'separator=\t'],
                    capture_output=True,
                    text=True,
                    timeout=300
                )

                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if not line.strip():
                            continue
                        parts = line.split('\t')
                        if len(parts) < 4:
                            continue

                        try:
                            epoch = float(parts[0])
                            timestamp = datetime.utcfromtimestamp(epoch).strftime('%Y-%m-%dT%H:%M:%S')
                        except (ValueError, IndexError):
                            timestamp = ''

                        all_tls.append({
                            'timestamp_utc': timestamp,
                            'capture': pcap_name,
                            'client_ip': parts[1] if len(parts) > 1 else '',
                            'server_ip': parts[2] if len(parts) > 2 else '',
                            'server_port': parts[3] if len(parts) > 3 else '',
                            'sni': parts[4] if len(parts) > 4 else '',
                            'ja3': parts[5] if len(parts) > 5 else '',
                            'ja3_full': parts[6] if len(parts) > 6 else ''
                        })

            except subprocess.TimeoutExpired:
                print(f"  WARNING: Timeout extracting TLS from {pcap_path.name}")
            except Exception as e:
                print(f"  ERROR: {e}")

        all_tls.sort(key=lambda x: x.get('timestamp_utc', '') or 'zzzz')

        with open(output, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=[
                'timestamp_utc', 'capture', 'client_ip', 'server_ip',
                'server_port', 'sni', 'ja3', 'ja3_full'
            ])
            writer.writeheader()
            writer.writerows(all_tls)

        print(f"  Written: {output} ({len(all_tls)} TLS handshakes)")
        self.mark_complete('extractions', 'tls')
        return True

    def extract_mac_ip_inventory(self):
        """Extract MAC-to-IP mappings from ARP traffic in all PCAPs (any tier)."""
        output = self.extractions_dir / f'{self.tier_str}-mac-ip-inventory.csv'
        output.parent.mkdir(parents=True, exist_ok=True)

        MAC_VENDORS = {
            "00:00:bc": "Rockwell Automation",
            "00:0c:29": "VMware",
            "00:a0:45": "Phoenix Contact",
            "2c:73:a0": "Cisco",
            "8c:ae:4c": "Sony",
            "c0:3e:ba": "Dell",
            "e4:90:69": "Rockwell Automation",
            "f4:54:33": "Rockwell Automation",
        }

        def get_vendor(mac):
            prefix = mac[:8].lower()
            return MAC_VENDORS.get(prefix, "Unknown")

        def get_device_type(vendor, ip):
            if vendor == "VMware":
                if ip.endswith(".2"):
                    return "OPNsense Router (VM)"
                elif ip.endswith(".100"):
                    return "EWS-VM (Engineering Workstation)"
                return "VMware VM"
            elif vendor == "Dell":
                return "VMware Host"
            elif vendor == "Rockwell Automation":
                return "PLC/HMI"
            elif vendor == "Phoenix Contact":
                return "Industrial I/O"
            elif vendor == "Cisco":
                return "Gateway Router"
            elif vendor == "Sony":
                return "Engineer Laptop/PC"
            return "Unknown"

        print("  Extracting MAC-IP mappings from ARP traffic")

        mac_ip_pairs = {}

        for pcap_key, pcap_path in self._get_pcaps():
            print(f"  Processing: {pcap_path.name}")

            try:
                result = subprocess.run(
                    ['tshark', '-r', str(pcap_path), '-Y', 'arp',
                     '-T', 'fields', '-e', 'eth.src', '-e', 'arp.src.proto_ipv4'],
                    capture_output=True,
                    text=True
                )

                if result.returncode != 0:
                    print(f"  ERROR: tshark failed: {result.stderr}")
                    continue

                for line in result.stdout.strip().split('\n'):
                    if not line or '\t' not in line:
                        continue
                    parts = line.split('\t')
                    if len(parts) >= 2:
                        mac, ip = parts[0], parts[1]
                        if ip and ip != "0.0.0.0":
                            mac_ip_pairs[mac] = ip

            except Exception as e:
                print(f"  ERROR: {e}")
                continue

        if not mac_ip_pairs:
            print("  ERROR: No MAC-IP pairs extracted")
            return False

        def ip_sort_key(pair):
            mac, ip = pair
            parts = ip.split('.')
            return tuple(int(p) for p in parts)

        sorted_pairs = sorted(mac_ip_pairs.items(), key=ip_sort_key)

        with open(output, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['mac', 'ip', 'vendor', 'device_type'])
            for mac, ip in sorted_pairs:
                vendor = get_vendor(mac)
                device_type = get_device_type(vendor, ip)
                writer.writerow([mac, ip, vendor, device_type])

        print(f"  Written: {output} ({len(sorted_pairs)} devices)")
        self.mark_complete('extractions', 'mac_ip_inventory')
        return True

    def extract_flows(self):
        """Extract TCP/UDP flows to CSV from all PCAPs (any tier)."""
        from datetime import datetime, timedelta

        output = self.extractions_dir / f'{self.tier_str}-flows.csv'
        output.parent.mkdir(parents=True, exist_ok=True)

        print("  Extracting flows from captures (this may take a minute)...")

        all_flows = []

        for pcap_key, pcap_path in self._get_pcaps():
            pcap_name = pcap_key.replace('_pcap', '')
            print(f"  Processing: {pcap_path.name}")

            # Get capture start time
            capture_start = None
            try:
                result = subprocess.run(
                    ['tshark', '-r', str(pcap_path), '-c', '1', '-T', 'fields', '-e', 'frame.time_epoch'],
                    capture_output=True, text=True, timeout=30
                )
                if result.returncode == 0 and result.stdout.strip():
                    epoch = float(result.stdout.strip())
                    capture_start = datetime.utcfromtimestamp(epoch)
                    print(f"    Capture start: {capture_start.isoformat()}")
            except Exception as e:
                print(f"    WARNING: Could not get capture start time: {e}")

            mac_ip_map = self._extract_mac_ip_mapping(pcap_path)

            # Extract TCP and UDP flows
            for proto in ['tcp', 'udp']:
                try:
                    result = subprocess.run(
                        ['tshark', '-r', str(pcap_path), '-q', '-z', f'conv,{proto}'],
                        capture_output=True, text=True, timeout=300
                    )

                    if result.returncode == 0:
                        for line in result.stdout.split('\n'):
                            if '<->' not in line:
                                continue
                            try:
                                parts = line.split()
                                if len(parts) < 10:
                                    continue

                                sep_idx = parts.index('<->')
                                src = parts[sep_idx - 1]
                                dst = parts[sep_idx + 1]

                                if ':' in src:
                                    src_ip, src_port = src.rsplit(':', 1)
                                else:
                                    src_ip, src_port = src, ''

                                if ':' in dst:
                                    dst_ip, dst_port = dst.rsplit(':', 1)
                                else:
                                    dst_ip, dst_port = dst, ''

                                stats = parts[sep_idx + 2:]
                                if len(stats) >= 11:
                                    frames_total = stats[6].replace(',', '')
                                    bytes_num = stats[7].replace(',', '')
                                    bytes_unit = stats[8] if len(stats) > 8 else 'bytes'
                                    rel_start = stats[9]
                                    duration = stats[10]

                                    try:
                                        bytes_val = float(bytes_num)
                                        if bytes_unit == 'kB':
                                            bytes_total = int(bytes_val * 1024)
                                        elif bytes_unit == 'MB':
                                            bytes_total = int(bytes_val * 1024 * 1024)
                                        elif bytes_unit == 'GB':
                                            bytes_total = int(bytes_val * 1024 * 1024 * 1024)
                                        else:
                                            bytes_total = int(bytes_val)
                                    except ValueError:
                                        bytes_total = 0

                                    timestamp_utc = ''
                                    if capture_start:
                                        try:
                                            rel_seconds = float(rel_start)
                                            abs_time = capture_start + timedelta(seconds=rel_seconds)
                                            timestamp_utc = abs_time.strftime('%Y-%m-%dT%H:%M:%S')
                                        except ValueError:
                                            pass

                                    all_flows.append({
                                        'timestamp_utc': timestamp_utc,
                                        'capture': pcap_name,
                                        'proto': proto.upper(),
                                        'src_mac': mac_ip_map.get(src_ip, ''),
                                        'src_ip': src_ip,
                                        'src_port': src_port,
                                        'dst_mac': mac_ip_map.get(dst_ip, ''),
                                        'dst_ip': dst_ip,
                                        'dst_port': dst_port,
                                        'frames': frames_total,
                                        'bytes': bytes_total,
                                        'duration': duration,
                                    })
                            except (ValueError, IndexError):
                                continue

                except subprocess.TimeoutExpired:
                    print(f"  WARNING: Timeout extracting {proto.upper()} flows from {pcap_path.name}")
                except Exception as e:
                    print(f"  ERROR: {e}")

        all_flows.sort(key=lambda x: x.get('timestamp_utc', '') or 'zzzz')

        with open(output, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=[
                'timestamp_utc', 'capture', 'proto', 'src_mac', 'src_ip', 'src_port',
                'dst_mac', 'dst_ip', 'dst_port', 'frames', 'bytes', 'duration'
            ])
            writer.writeheader()
            writer.writerows(all_flows)

        print(f"  Written: {output} ({len(all_flows)} flows)")
        self.mark_complete('extractions', 'flows')
        return True

    # =========================================================================
    # BACKWARD-COMPATIBLE ALIASES
    # =========================================================================

    def extract_l2_dns(self):
        """Alias: delegates to generic extract_dns()."""
        return self.extract_dns()

    def extract_l2_tls(self):
        """Alias: delegates to generic extract_tls()."""
        return self.extract_tls()

    def extract_l2_mac_ip_inventory(self):
        """Alias: delegates to generic extract_mac_ip_inventory()."""
        return self.extract_mac_ip_inventory()

    def extract_l2_flows(self):
        """Alias: delegates to generic extract_flows()."""
        return self.extract_flows()

    def extract_l2_file_objects(self):
        """Extract transferred files from Level 2 captures (FTP, HTTP, SMB)."""
        import hashlib

        output_dir = self.extractions_dir / 'extracted-files'
        output_dir.mkdir(parents=True, exist_ok=True)
        manifest_file = self.extractions_dir / 'extracted-files-manifest.csv'

        # Protocols supported by tshark --export-objects
        protocols = ['ftp-data', 'http', 'smb']

        all_files = []

        for pcap_key in ['capture1_pcap', 'capture2_pcap']:
            pcap = self.get_artifact_files().get(pcap_key)
            if not pcap or not pcap.exists():
                print(f"  WARNING: PCAP not found: {pcap}")
                continue

            pcap_name = pcap.stem  # capture1 or capture2

            for protocol in protocols:
                proto_dir = output_dir / pcap_name / protocol
                proto_dir.mkdir(parents=True, exist_ok=True)

                print(f"  Extracting {protocol} from {pcap.name}...")

                try:
                    result = subprocess.run(
                        ['tshark', '-r', str(pcap), '-q',
                         '--export-objects', f'{protocol},{proto_dir}'],
                        capture_output=True,
                        text=True,
                        timeout=300  # 5 minute timeout for large files
                    )

                    if result.returncode != 0 and result.stderr:
                        # Only warn if actual error, not just "no objects found"
                        if 'error' in result.stderr.lower():
                            print(f"    WARNING: {result.stderr.strip()}")

                    # List extracted files
                    extracted = list(proto_dir.glob('*'))
                    if extracted:
                        print(f"    Extracted {len(extracted)} files")
                        for f in extracted:
                            # Calculate hash
                            sha256 = hashlib.sha256()
                            with open(f, 'rb') as fh:
                                for chunk in iter(lambda: fh.read(8192), b''):
                                    sha256.update(chunk)

                            all_files.append({
                                'pcap': pcap_name,
                                'protocol': protocol,
                                'filename': f.name,
                                'size': f.stat().st_size,
                                'sha256': sha256.hexdigest(),
                                'path': str(f.relative_to(self.extractions_dir))
                            })
                    else:
                        print(f"    No files found")

                except subprocess.TimeoutExpired:
                    print(f"    WARNING: Extraction timed out for {protocol}")
                except Exception as e:
                    print(f"    ERROR: {e}")

        # Write manifest
        if all_files:
            with open(manifest_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['pcap', 'protocol', 'filename', 'size', 'sha256', 'path'])
                writer.writeheader()
                writer.writerows(all_files)
            print(f"  Written manifest: {manifest_file} ({len(all_files)} files)")
        else:
            print("  No files extracted from any capture")

        self.mark_complete('extractions', 'l2_file_objects')
        return True

    # =========================================================================
    # ANALYSIS FUNCTIONS
    # =========================================================================
    def _parse_bytes(self, value, unit=None):
        """Parse bytes with unit (e.g., '13 MB', '7,066 kB', '0 bytes')."""
        value = value.replace(',', '')
        try:
            num = float(value)
        except ValueError:
            return 0

        if unit:
            unit = unit.lower()
            if unit == 'mb':
                return int(num * 1024 * 1024)
            elif unit == 'kb':
                return int(num * 1024)
            elif unit == 'bytes':
                return int(num)
        return int(num)

    def analyze_top_talkers(self):
        """Analyze top talkers from conversation extracts."""
        output = self.analysis_dir / 'top-talkers.md'
        output.parent.mkdir(parents=True, exist_ok=True)

        results = []
        results.append("# Top Talkers Analysis\n")
        results.append(f"Generated: {datetime.now().isoformat()}\n\n")

        for name, conv_file in [('Spader Core', self.extractions_dir / 'core-conversations.txt'),
                                ('Stark Egress', self.extractions_dir / 'egress-conversations.txt')]:
            results.append(f"## {name}\n\n")

            if not conv_file.exists():
                results.append(f"*Extraction not complete: {conv_file}*\n\n")
                continue

            conversations = []
            with open(conv_file) as f:
                for line in f:
                    if '<->' not in line:
                        continue

                    parts = line.split('<->')
                    if len(parts) != 2:
                        continue

                    ip1 = parts[0].strip()
                    rest = parts[1].strip().split()

                    if len(rest) < 10:
                        continue

                    ip2 = rest[0]

                    try:
                        frames_total = int(rest[7].replace(',', ''))
                        bytes_val = rest[8]
                        bytes_unit = rest[9] if len(rest) > 9 else 'bytes'
                        bytes_total = self._parse_bytes(bytes_val, bytes_unit)

                        conversations.append({
                            'ip1': ip1,
                            'ip2': ip2,
                            'bytes': bytes_total,
                            'frames': frames_total,
                            'bytes_str': f"{bytes_val} {bytes_unit}"
                        })
                    except (ValueError, IndexError):
                        continue

            conversations.sort(key=lambda x: x['bytes'], reverse=True)
            total_bytes = sum(c['bytes'] for c in conversations)

            results.append("### By Bytes Transferred (Top 20)\n\n")
            results.append("| Rank | IP 1 | IP 2 | Bytes | % | Frames |\n")
            results.append("|------|------|------|------:|--:|-------:|\n")
            for i, conv in enumerate(conversations[:20], 1):
                frames_fmt = f"{conv['frames']:,}"
                pct = (conv['bytes'] / total_bytes * 100) if total_bytes > 0 else 0
                # Check if IPs match investigation criteria
                ip1_match = "**" if self.criteria.matches_ip(conv['ip1']) else ""
                ip2_match = "**" if self.criteria.matches_ip(conv['ip2']) else ""
                results.append(f"| {i} | {ip1_match}{conv['ip1']}{ip1_match} | {ip2_match}{conv['ip2']}{ip2_match} | {conv['bytes_str']} | {pct:.1f}% | {frames_fmt} |\n")

            top20_bytes = sum(c['bytes'] for c in conversations[:20])
            top20_pct = (top20_bytes / total_bytes * 100) if total_bytes > 0 else 0

            results.append(f"\nTotal conversations: {len(conversations)}\n")
            results.append(f"Top 20 accounts for: {top20_pct:.1f}% of total traffic\n\n")

            # Traffic per individual IP
            ip_traffic = defaultdict(int)
            for conv in conversations:
                ip_traffic[conv['ip1']] += conv['bytes']
                ip_traffic[conv['ip2']] += conv['bytes']

            sorted_ips = sorted(ip_traffic.items(), key=lambda x: x[1], reverse=True)

            results.append("### Traffic by Individual IP (Top 20)\n\n")
            results.append("| Rank | IP | Traffic | % |\n")
            results.append("|------|-------|-------:|--:|\n")
            for i, (ip, bytes_val) in enumerate(sorted_ips[:20], 1):
                pct = (bytes_val / total_bytes * 100) if total_bytes > 0 else 0
                bytes_str = format_bytes(bytes_val)
                ip_match = "**" if self.criteria.matches_ip(ip) else ""
                results.append(f"| {i} | {ip_match}{ip}{ip_match} | {bytes_str} | {pct:.1f}% |\n")

            results.append("\n")

        with open(output, 'w') as f:
            f.writelines(results)

        print(f"  Written: {output}")
        self.mark_complete('analyses', 'top_talkers')
        return True

    def analyze_protocol_dist(self):
        """Analyze protocol distribution from hierarchy extract."""
        output = self.analysis_dir / 'protocol-distribution.md'
        output.parent.mkdir(parents=True, exist_ok=True)

        results = []
        results.append("# Protocol Distribution Analysis\n")
        results.append(f"Generated: {datetime.now().isoformat()}\n\n")

        proto_file = self.extractions_dir / 'core-protocols.txt'
        if not proto_file.exists():
            results.append(f"*Extraction not complete: {proto_file}*\n")
            with open(output, 'w') as f:
                f.writelines(results)
            return False

        results.append("## Spader Core PCAP\n\n")
        results.append("```\n")
        with open(proto_file) as f:
            results.append(f.read())
        results.append("```\n")

        with open(output, 'w') as f:
            f.writelines(results)

        print(f"  Written: {output}")
        self.mark_complete('analyses', 'protocol_dist')
        return True

    def analyze_tls_analysis(self):
        """Analyze TLS SNI hostnames."""
        output = self.analysis_dir / 'tls-analysis.md'
        output.parent.mkdir(parents=True, exist_ok=True)

        results = []
        results.append("# TLS/SNI Analysis\n")
        results.append(f"Generated: {datetime.now().isoformat()}\n\n")

        for name, tls_file in [('Spader Core', self.extractions_dir / 'core-tls.csv'),
                               ('Stark Egress', self.extractions_dir / 'egress-tls.csv')]:
            results.append(f"## {name}\n\n")

            if not tls_file.exists():
                results.append(f"*Extraction not complete: {tls_file}*\n\n")
                continue

            sni_counts = defaultdict(int)
            total = 0
            with open(tls_file) as f:
                reader = csv.DictReader(f)
                for row in reader:
                    total += 1
                    sni = row.get('tls.handshake.extensions_server_name', '')
                    if sni:
                        sni_counts[sni] += 1
                    else:
                        sni_counts['(no SNI)'] += 1

            sorted_sni = sorted(sni_counts.items(), key=lambda x: x[1], reverse=True)

            results.append(f"Total TLS handshakes: {total}\n\n")
            results.append("### Top SNI Hostnames (Top 30)\n\n")
            results.append("| Rank | SNI Hostname | Count |\n")
            results.append("|------|--------------|------:|\n")
            for i, (sni, count) in enumerate(sorted_sni[:30], 1):
                # Check against investigation criteria
                match = "**" if self.criteria.matches_domain(sni) else ""
                results.append(f"| {i} | {match}{sni}{match} | {count} |\n")

            results.append("\n")

        with open(output, 'w') as f:
            f.writelines(results)

        print(f"  Written: {output}")
        self.mark_complete('analyses', 'tls_analysis')
        return True

    def analyze_ja3_analysis(self):
        """Analyze JA3/JA4 fingerprints from egress PCAP."""
        output = self.analysis_dir / 'ja3-analysis.md'
        output.parent.mkdir(parents=True, exist_ok=True)

        results = []
        results.append("# JA3/JA4 Fingerprint Analysis\n")
        results.append(f"Generated: {datetime.now().isoformat()}\n\n")

        ja3_file = self.extractions_dir / 'egress-ja3.csv'
        if not ja3_file.exists():
            results.append(f"*Extraction not complete: {ja3_file}*\n")
            with open(output, 'w') as f:
                f.writelines(results)
            return False

        results.append("## About JA3/JA4\n\n")
        results.append("- **JA3**: MD5 hash of TLS Client Hello parameters (version, ciphers, extensions)\n")
        results.append("- **JA4**: Improved fingerprint format with better stability across sessions\n")
        results.append("- Only available from TLS handshakes (Client Hello packets)\n\n")

        ja3_counts = defaultdict(lambda: {'count': 0, 'sources': set(), 'sni': set()})
        total_handshakes = 0

        with open(ja3_file) as f:
            header = f.readline()
            for line in f:
                parts = line.strip().split('\t')
                if len(parts) >= 8:
                    frame, ts, src, dst, hs_type, sni, ja3, ja4 = parts[:8]
                    if hs_type == '1' and ja3:
                        total_handshakes += 1
                        key = (ja3, ja4)
                        ja3_counts[key]['count'] += 1
                        ja3_counts[key]['sources'].add(src)
                        if sni:
                            ja3_counts[key]['sni'].add(sni)

        sorted_ja3 = sorted(ja3_counts.items(), key=lambda x: x[1]['count'], reverse=True)

        results.append(f"## Stark Egress - Client Hello Fingerprints\n\n")
        results.append(f"Total TLS Client Hello packets with JA3: {total_handshakes}\n")
        results.append(f"Unique JA3/JA4 fingerprint pairs: {len(sorted_ja3)}\n\n")

        results.append("### Fingerprint Distribution\n\n")
        results.append("| Rank | Count | % | JA3 | JA4 | Sources | Sample SNI |\n")
        results.append("|------|------:|--:|-----|-----|---------|------------|\n")

        for i, ((ja3, ja4), data) in enumerate(sorted_ja3[:15], 1):
            pct = (data['count'] / total_handshakes * 100) if total_handshakes > 0 else 0
            sources = ', '.join(sorted(data['sources'])[:3])
            if len(data['sources']) > 3:
                sources += f" (+{len(data['sources'])-3})"
            sample_sni = ', '.join(sorted(data['sni'])[:2])
            if len(data['sni']) > 2:
                sample_sni += '...'
            ja3_short = ja3[:16] + '...' if len(ja3) > 16 else ja3
            ja4_short = ja4[:20] + '...' if len(ja4) > 20 else ja4
            results.append(f"| {i} | {data['count']} | {pct:.1f}% | `{ja3_short}` | `{ja4_short}` | {sources} | {sample_sni} |\n")

        with open(output, 'w') as f:
            f.writelines(results)

        print(f"  Written: {output}")
        self.mark_complete('analyses', 'ja3_analysis')
        return True

    def analyze_sni_forensics(self):
        """Identify forensically interesting domains from SNI and proxy logs."""
        output = self.analysis_dir / 'sni-forensics.md'
        output.parent.mkdir(parents=True, exist_ok=True)

        results = []
        results.append("# Domain Forensic Analysis\n")
        results.append(f"Generated: {datetime.now().isoformat()}\n\n")
        results.append("Sources: TLS SNI (egress PCAP) + HTTP proxy logs (Spader)\n\n")

        # Known legitimate domains to filter out
        KNOWN_LEGITIMATE = {
            'microsoft.com', 'windows.com', 'live.com', 'office.com', 'msedge.net',
            'azure.com', 'bing.com', 'skype.com', 'teams.microsoft.com',
            'google.com', 'googleapis.com', 'gstatic.com', 'youtube.com',
            'mozilla.org', 'firefox.com',
            'amazon.com', 'amazonaws.com', 'cloudfront.net',
            'akamai.net', 'akamaiedge.net', 'akadns.net',
            'symantec.com', 'norton.com', 'symantecliveupdate.com',
            'dropbox.com',
        }

        # Cross-organization indicators
        CROSS_ORG_PATTERNS = ['spadertech', 'starkresearch']

        # Parse SNI data from egress JA3
        sni_data = defaultdict(lambda: {'count': 0, 'sources': set(), 'ips': set(), 'source_type': set()})

        ja3_file = self.extractions_dir / 'egress-ja3.csv'
        if ja3_file.exists():
            with open(ja3_file) as f:
                header = f.readline()
                for line in f:
                    parts = line.strip().split('\t')
                    if len(parts) >= 6:
                        frame, ts, src, dst, hs_type, sni = parts[:6]
                        if hs_type == '1' and sni:
                            sni_data[sni]['count'] += 1
                            sni_data[sni]['sources'].add(src)
                            sni_data[sni]['ips'].add(dst)
                            sni_data[sni]['source_type'].add('TLS/SNI')

        # Parse proxy domains
        proxy_file = self.extractions_dir / 'spader-proxy-domains.csv'
        if proxy_file.exists():
            with open(proxy_file) as f:
                header = f.readline()
                for line in f:
                    parts = line.strip().split('\t')
                    if len(parts) >= 4:
                        domain, count, sources, methods = parts[:4]
                        sni_data[domain]['count'] += int(count)
                        for src in sources.split(','):
                            if src:
                                sni_data[domain]['sources'].add(src)
                        sni_data[domain]['source_type'].add('HTTP/Proxy')

        if not sni_data:
            results.append("*No domain data available. Run extractions first.*\n")
            with open(output, 'w') as f:
                f.writelines(results)
            return False

        # Categorize domains
        suspicious = []
        cross_org = []
        unusual = []

        for domain, data in sni_data.items():
            is_legitimate = any(domain.endswith(legit) or legit in domain for legit in KNOWN_LEGITIMATE)
            is_cross_org = any(pattern in domain.lower() for pattern in CROSS_ORG_PATTERNS)
            is_known_ioc = self.criteria.matches_domain(domain)

            is_unusual = (
                len(domain.split('.')[0]) > 20 or
                any(c.isdigit() for c in domain.split('.')[0] if len(domain.split('.')[0]) > 10) or
                domain.count('.') > 4
            )

            if is_known_ioc:
                note = self.criteria.get_note('domains', domain) or 'Known IOC'
                suspicious.append((domain, data, note))
            elif is_cross_org:
                cross_org.append((domain, data))
            elif not is_legitimate and is_unusual:
                unusual.append((domain, data))
                # Suggest adding to investigation criteria
                suggestion = self.criteria.suggest_domain(
                    domain,
                    f"Unusual domain structure (count: {data['count']})",
                    source='network-sni'
                )
                self.add_suggestion(suggestion)

        # Low-frequency uncommon domains
        uncommon = []
        for domain, data in sni_data.items():
            is_legitimate = any(domain.endswith(legit) or legit in domain for legit in KNOWN_LEGITIMATE)
            if not is_legitimate and data['count'] <= 10:
                already_flagged = any(domain == s[0] for s in suspicious + cross_org + unusual)
                if not already_flagged and not self.criteria.is_excluded_domain(domain):
                    uncommon.append((domain, data))

        results.append("## Forensically Interesting Domains\n\n")

        # Known IOCs
        results.append("### Known IOCs or Suspicious Domains\n\n")
        if suspicious:
            results.append("| Domain | Count | Source | Type | Reason |\n")
            results.append("|--------|------:|--------|------|--------|\n")
            for domain, data, reason in sorted(suspicious, key=lambda x: x[1]['count'], reverse=True):
                sources = ', '.join(sorted(data['sources'])[:2])
                src_type = ', '.join(sorted(data.get('source_type', {'?'})))
                results.append(f"| **`{domain}`** | {data['count']} | {sources} | {src_type} | {reason} |\n")
        else:
            results.append("*No known IOCs found*\n")
        results.append("\n")

        # Cross-organization
        results.append("### Cross-Organization Access\n\n")
        if cross_org:
            results.append("| Domain | Count | Source | Type |\n")
            results.append("|--------|------:|--------|------|\n")
            for domain, data in sorted(cross_org, key=lambda x: x[1]['count'], reverse=True):
                sources = ', '.join(sorted(data['sources'])[:3])
                src_type = ', '.join(sorted(data.get('source_type', {'?'})))
                results.append(f"| `{domain}` | {data['count']} | {sources} | {src_type} |\n")
        else:
            results.append("*No cross-organization traffic detected*\n")
        results.append("\n")

        # Unusual domains
        results.append("### Unusual or Low-Frequency Domains\n\n")
        uncommon_sorted = sorted(uncommon, key=lambda x: x[1]['count'], reverse=True)[:25]
        if uncommon_sorted:
            results.append("| Domain | Count | Source | Type |\n")
            results.append("|--------|------:|--------|------|\n")
            for domain, data in uncommon_sorted:
                sources = ', '.join(sorted(data['sources'])[:2])
                src_type = ', '.join(sorted(data.get('source_type', {'?'})))
                results.append(f"| `{domain}` | {data['count']} | {sources} | {src_type} |\n")
        else:
            results.append("*No unusual domains flagged*\n")
        results.append("\n")

        # Summary
        results.append("## Summary Statistics\n\n")
        results.append(f"- Total unique domains: {len(sni_data)}\n")
        results.append(f"- Known IOCs found: {len(suspicious)}\n")
        results.append(f"- Cross-org domains: {len(cross_org)}\n")
        results.append(f"- Unusual/uncommon domains: {len(uncommon)}\n")

        with open(output, 'w') as f:
            f.writelines(results)

        print(f"  Written: {output}")
        self.mark_complete('analyses', 'sni_forensics')
        return True

    def analyze_beacon_analysis(self):
        """Detect periodic beacon patterns in SYN packets."""
        output = self.analysis_dir / 'beacon-analysis.md'
        output.parent.mkdir(parents=True, exist_ok=True)

        results = []
        results.append("# Beacon Detection Analysis\n")
        results.append(f"Generated: {datetime.now().isoformat()}\n\n")

        syn_file = self.extractions_dir / 'core-syn.csv'
        if not syn_file.exists():
            results.append(f"*Extraction not complete: {syn_file}*\n")
            with open(output, 'w') as f:
                f.writelines(results)
            return False

        connections = defaultdict(list)
        with open(syn_file) as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    dst = f"{row['ip.dst']}:{row['tcp.dstport']}"
                    ts = float(row['frame.time_epoch'])
                    src = row['ip.src']
                    connections[(src, dst)].append(ts)
                except (KeyError, ValueError):
                    continue

        results.append("## Potential Beacons (Regular Intervals)\n\n")
        results.append("Looking for connections with consistent intervals (30-120 second range, >5 occurrences)\n\n")

        beacons_found = []
        for (src, dst), timestamps in connections.items():
            if len(timestamps) < 5:
                continue

            timestamps.sort()
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]

            if not intervals:
                continue

            avg_interval = sum(intervals) / len(intervals)

            if 30 <= avg_interval <= 120:
                variance = sum((i - avg_interval)**2 for i in intervals) / len(intervals)
                std_dev = variance ** 0.5

                if std_dev < avg_interval * 0.2:
                    beacons_found.append({
                        'src': src,
                        'dst': dst,
                        'count': len(timestamps),
                        'avg_interval': avg_interval,
                        'std_dev': std_dev
                    })
                    # Suggest adding beacon destination IP
                    dst_ip = dst.split(':')[0]
                    if not self.criteria.matches_ip(dst_ip):
                        suggestion = self.criteria.suggest_ip(
                            dst_ip,
                            f"Potential beacon destination (interval: {avg_interval:.0f}s)",
                            source='network-beacon'
                        )
                        self.add_suggestion(suggestion)

        if beacons_found:
            beacons_found.sort(key=lambda x: x['count'], reverse=True)
            results.append("| Source | Destination | Connections | Avg Interval (s) | Std Dev |\n")
            results.append("|--------|-------------|------------:|----------------:|---------:|\n")
            for b in beacons_found[:20]:
                results.append(f"| {b['src']} | {b['dst']} | {b['count']} | {b['avg_interval']:.1f} | {b['std_dev']:.1f} |\n")
        else:
            results.append("*No clear beacon patterns detected in 30-120 second range*\n")

        results.append("\n## Connection Frequency Summary\n\n")
        results.append("Top destinations by connection count:\n\n")

        dst_counts = defaultdict(int)
        for (src, dst), timestamps in connections.items():
            dst_counts[dst] += len(timestamps)

        sorted_dsts = sorted(dst_counts.items(), key=lambda x: x[1], reverse=True)
        results.append("| Destination | SYN Count |\n")
        results.append("|-------------|----------:|\n")
        for dst, count in sorted_dsts[:20]:
            results.append(f"| {dst} | {count} |\n")

        with open(output, 'w') as f:
            f.writelines(results)

        print(f"  Written: {output}")
        self.mark_complete('analyses', 'beacon_analysis')
        return True

    def analyze_infrastructure(self):
        """Document network infrastructure from all sources."""
        output = self.analysis_dir / 'infrastructure.md'
        output.parent.mkdir(parents=True, exist_ok=True)

        results = []
        results.append("# Network Infrastructure Analysis\n")
        results.append(f"Generated: {datetime.now().isoformat()}\n\n")

        results.append("## IP Ranges Observed\n\n")
        results.append("| Range | Organization | Purpose |\n")
        results.append("|-------|--------------|--------|\n")
        results.append("| 192.168.1.x | Spader Technologies | Servers (DNS, proxy, SEP) |\n")
        results.append("| 192.168.2.x | Spader Technologies | Workstations |\n")
        results.append("| 10.0.1.x | Spader Technologies | Domain controllers |\n")
        results.append("| 10.0.2.x | Spader Technologies | Internal servers |\n")
        results.append("| 10.10.x.x | Spader/Stark | AWS VPC (shared infrastructure) |\n")
        results.append("| 172.16.1.x | Stark Research Labs | Firewall |\n")
        results.append("| 172.16.4.x | Stark Research Labs | Workstations/Proxy |\n")
        results.append("| 172.16.5.x | Stark Research Labs | Servers |\n")
        results.append("| 172.16.10.x | Stark Research Labs | DMZ |\n")
        results.append("| 192.168.30.x | Stark Research Labs | VPN/RDP segment |\n")
        results.append("| 70.39.165.200 | Spader Technologies | External IP |\n")
        results.append("| 174.79.40.221 | Alset Energy | VPN endpoint |\n")

        # Add IPs from investigation criteria
        results.append("\n## IPs of Interest (from investigation.yaml)\n\n")
        results.append("| IP | Note |\n")
        results.append("|-------|------|\n")
        for ip in self.criteria.get_ips():
            note = self.criteria.get_note('ips', ip)
            results.append(f"| **{ip}** | {note} |\n")

        results.append("\n## Key Hosts\n\n")
        results.append("| IP | Hostname | Role |\n")
        results.append("|----|----------|------|\n")
        results.append("| 192.168.1.2 | - | Spader DNS resolver |\n")
        results.append("| 192.168.1.6 | stsep01.spadertech.com | Symantec EP server |\n")
        results.append("| 192.168.2.10 | stsupport10 | Compromised workstation (t.johnson) |\n")
        results.append("| 10.10.200.207 | LARIAT-C2 | Cyber range control server |\n")
        results.append("| 10.10.254.1 | Puppet | Configuration management |\n")
        results.append("| 172.16.1.20 | base-fw | Stark firewall |\n")
        results.append("| 172.16.4.10 | - | Stark web proxy |\n")
        results.append("| 172.16.5.26 | base-admin | Stark admin workstation (rsydow) |\n")

        with open(output, 'w') as f:
            f.writelines(results)

        print(f"  Written: {output}")
        self.mark_complete('analyses', 'infrastructure')
        return True

    # =========================================================================
    # LEVEL 2 ANALYSIS FUNCTIONS
    # =========================================================================
    def analyze_l2_overview(self):
        """Generate overview of Level 2 captures."""
        output = self.analysis_dir / 'l2-overview.md'
        output.parent.mkdir(parents=True, exist_ok=True)

        results = []
        results.append("# Level 2 Network Captures - Overview\n")
        results.append(f"Generated: {datetime.now().isoformat()}\n\n")

        # Read capture info files
        for name, info_file in [('capture1', self.extractions_dir / 'l2-capture1-info.txt'),
                                ('capture2', self.extractions_dir / 'l2-capture2-info.txt')]:
            results.append(f"## {name}.pcap\n\n")

            pcap_path = self.get_artifact_files().get(f'{name}_pcap')
            if pcap_path and pcap_path.exists():
                size_mb = pcap_path.stat().st_size / (1024 * 1024)
                results.append(f"- **File size**: {size_mb:.1f} MB\n")

            if info_file.exists():
                results.append("```\n")
                with open(info_file) as f:
                    results.append(f.read())
                results.append("```\n\n")
            else:
                results.append(f"*Extraction not complete: {info_file.name}*\n\n")

            # Protocol summary
            proto_file = self.extractions_dir / f'l2-{name}-protocols.txt'
            if proto_file.exists():
                results.append("### Protocol Hierarchy\n\n```\n")
                with open(proto_file) as f:
                    # Only include first 50 lines
                    for i, line in enumerate(f):
                        if i >= 50:
                            results.append("... (truncated)\n")
                            break
                        results.append(line)
                results.append("```\n\n")

        # OpenVPN summary
        openvpn_file = self.extractions_dir / 'l2-openvpn-events.csv'
        if openvpn_file.exists():
            results.append("## OpenVPN Log Summary\n\n")
            event_counts = defaultdict(int)
            first_ts = None
            last_ts = None

            with open(openvpn_file) as f:
                reader = csv.DictReader(f)
                for row in reader:
                    event_counts[row['event_type']] += 1
                    ts = row['timestamp']
                    if not first_ts or ts < first_ts:
                        first_ts = ts
                    if not last_ts or ts > last_ts:
                        last_ts = ts

            results.append(f"- **Timeframe**: {first_ts} to {last_ts}\n")
            results.append(f"- **Total events**: {sum(event_counts.values())}\n\n")
            results.append("| Event Type | Count |\n")
            results.append("|------------|------:|\n")
            for event_type, count in sorted(event_counts.items(), key=lambda x: x[1], reverse=True)[:15]:
                results.append(f"| {event_type} | {count} |\n")
            results.append("\n")

        with open(output, 'w') as f:
            f.writelines(results)

        print(f"  Written: {output}")
        self.mark_complete('analyses', 'l2_overview')
        return True

    def analyze_l2_ioc_correlation(self):
        """Correlate Level 1 IOCs with Level 2 captures."""
        output = self.analysis_dir / 'l2-ioc-correlation.md'
        output.parent.mkdir(parents=True, exist_ok=True)

        results = []
        results.append("# Level 2 IOC Correlation\n")
        results.append(f"Generated: {datetime.now().isoformat()}\n\n")
        results.append("Searching for Level 1 IOCs in Level 2 network captures.\n\n")

        # Get IOCs from investigation criteria
        known_ips = self.criteria.get_ips()
        known_domains = self.criteria.get_domains()

        results.append("## Known IOCs from Level 1\n\n")
        results.append("### IPs\n")
        for ip in known_ips:
            note = self.criteria.get_note('ips', ip)
            results.append(f"- `{ip}` - {note}\n")
        results.append("\n### Domains\n")
        for domain in known_domains:
            note = self.criteria.get_note('domains', domain)
            results.append(f"- `{domain}` - {note}\n")
        results.append("\n")

        # Search in conversation files
        results.append("## IP Correlation Results\n\n")

        for name in ['capture1', 'capture2']:
            conv_file = self.extractions_dir / f'l2-{name}-conversations.txt'
            results.append(f"### {name}.pcap\n\n")

            if not conv_file.exists():
                results.append(f"*Extraction not complete: {conv_file.name}*\n\n")
                continue

            matches = []
            with open(conv_file) as f:
                for line in f:
                    for ip in known_ips:
                        if ip in line:
                            matches.append((ip, line.strip()))

            if matches:
                results.append("| IOC IP | Conversation |\n")
                results.append("|--------|-------------|\n")
                for ip, line in matches[:50]:  # Limit to 50 matches
                    line_short = line[:80] + '...' if len(line) > 80 else line
                    results.append(f"| **{ip}** | `{line_short}` |\n")
                if len(matches) > 50:
                    results.append(f"\n*... and {len(matches) - 50} more matches*\n")
            else:
                results.append("*No known IOC IPs found in this capture*\n")
            results.append("\n")

        # Search in TLS SNI
        results.append("## Domain Correlation Results\n\n")

        for name in ['capture1', 'capture2']:
            tls_file = self.extractions_dir / f'l2-{name}-tls.csv'
            results.append(f"### {name}.pcap TLS/SNI\n\n")

            if not tls_file.exists():
                results.append(f"*Extraction not complete: {tls_file.name}*\n\n")
                continue

            matches = []
            with open(tls_file) as f:
                reader = csv.DictReader(f)
                for row in reader:
                    sni = row.get('tls.handshake.extensions_server_name', '')
                    for domain in known_domains:
                        if domain.lower() in sni.lower():
                            matches.append({
                                'domain': domain,
                                'sni': sni,
                                'src': row.get('ip.src', ''),
                                'dst': row.get('ip.dst', ''),
                                'frame': row.get('frame.number', ''),
                            })

            if matches:
                results.append("| IOC Domain | SNI | Source | Dest | Frame |\n")
                results.append("|------------|-----|--------|------|------:|\n")
                for m in matches[:30]:
                    results.append(f"| **{m['domain']}** | {m['sni']} | {m['src']} | {m['dst']} | {m['frame']} |\n")
                if len(matches) > 30:
                    results.append(f"\n*... and {len(matches) - 30} more matches*\n")
            else:
                results.append("*No known IOC domains found in TLS SNI*\n")
            results.append("\n")

        # Search in HTTP
        results.append("## HTTP Host Correlation\n\n")

        for name in ['capture1', 'capture2']:
            http_file = self.extractions_dir / f'l2-{name}-http.csv'
            results.append(f"### {name}.pcap HTTP\n\n")

            if not http_file.exists():
                results.append(f"*Extraction not complete: {http_file.name}*\n\n")
                continue

            matches = []
            with open(http_file) as f:
                reader = csv.DictReader(f, delimiter='\t')
                for row in reader:
                    host = row.get('http.host', '')
                    for domain in known_domains:
                        if domain.lower() in host.lower():
                            matches.append({
                                'domain': domain,
                                'host': host,
                                'method': row.get('http.request.method', ''),
                                'uri': row.get('http.request.uri', '')[:50],
                                'src': row.get('ip.src', ''),
                            })

            if matches:
                results.append("| IOC Domain | Host | Method | URI | Source |\n")
                results.append("|------------|------|--------|-----|--------|\n")
                for m in matches[:30]:
                    results.append(f"| **{m['domain']}** | {m['host']} | {m['method']} | {m['uri']} | {m['src']} |\n")
            else:
                results.append("*No known IOC domains found in HTTP hosts*\n")
            results.append("\n")

        with open(output, 'w') as f:
            f.writelines(results)

        print(f"  Written: {output}")
        self.mark_complete('analyses', 'l2_ioc_correlation')
        return True

    def analyze_l2_c2_traffic(self):
        """Identify potential C2 traffic patterns in Level 2 captures."""
        output = self.analysis_dir / 'l2-c2-traffic.md'
        output.parent.mkdir(parents=True, exist_ok=True)

        results = []
        results.append("# Level 2 C2 Traffic Analysis\n")
        results.append(f"Generated: {datetime.now().isoformat()}\n\n")

        # Known C2 indicators from Level 1
        c2_ports = [8443, 443, 4444, 5555]  # Common C2 ports
        c2_ips = [ip for ip in self.criteria.get_ips()
                  if 'c2' in self.criteria.get_note('ips', ip).lower()]

        results.append("## C2 Indicators from Level 1\n\n")
        results.append(f"- Known C2 IPs: {', '.join(c2_ips) if c2_ips else 'None identified'}\n")
        results.append(f"- Suspicious ports: {', '.join(map(str, c2_ports))}\n\n")

        # Analyze each capture
        for name in ['capture1', 'capture2']:
            results.append(f"## {name}.pcap C2 Analysis\n\n")

            # Check TLS on suspicious ports
            tls_file = self.extractions_dir / f'l2-{name}-tls.csv'
            if tls_file.exists():
                suspicious_tls = []
                with open(tls_file) as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        port = int(row.get('tcp.dstport', 0) or 0)
                        dst_ip = row.get('ip.dst', '')
                        sni = row.get('tls.handshake.extensions_server_name', '')

                        is_suspicious = (
                            port in c2_ports or
                            dst_ip in c2_ips or
                            not sni  # TLS without SNI can indicate C2
                        )

                        if is_suspicious:
                            suspicious_tls.append({
                                'frame': row.get('frame.number', ''),
                                'src': row.get('ip.src', ''),
                                'dst': dst_ip,
                                'port': port,
                                'sni': sni or '(no SNI)',
                            })

                if suspicious_tls:
                    results.append("### Suspicious TLS Connections\n\n")
                    results.append("| Frame | Source | Destination | Port | SNI |\n")
                    results.append("|------:|--------|-------------|-----:|-----|\n")
                    for conn in suspicious_tls[:50]:
                        results.append(f"| {conn['frame']} | {conn['src']} | {conn['dst']} | {conn['port']} | {conn['sni']} |\n")
                    results.append("\n")
                else:
                    results.append("*No suspicious TLS connections detected*\n\n")
            else:
                results.append(f"*TLS extraction not complete*\n\n")

            # High-frequency destinations (potential beacons)
            conv_file = self.extractions_dir / f'l2-{name}-conversations.txt'
            if conv_file.exists():
                results.append("### High-Frequency Destinations\n\n")
                # This will be populated during beacon analysis
                results.append("*See beacon_analysis for periodic connection patterns*\n\n")

        with open(output, 'w') as f:
            f.writelines(results)

        print(f"  Written: {output}")
        self.mark_complete('analyses', 'l2_c2_traffic')
        return True

    def analyze_l2_lateral_movement(self):
        """Analyze lateral movement indicators in Level 2 captures."""
        output = self.analysis_dir / 'l2-lateral-movement.md'
        output.parent.mkdir(parents=True, exist_ok=True)

        results = []
        results.append("# Level 2 Lateral Movement Analysis\n")
        results.append(f"Generated: {datetime.now().isoformat()}\n\n")

        # Lateral movement indicators
        lateral_ports = {
            22: 'SSH',
            23: 'Telnet',
            135: 'RPC',
            139: 'NetBIOS',
            445: 'SMB',
            3389: 'RDP',
            5985: 'WinRM HTTP',
            5986: 'WinRM HTTPS',
        }

        results.append("## Lateral Movement Indicators\n\n")
        results.append("Searching for traffic on common lateral movement ports:\n")
        for port, proto in lateral_ports.items():
            results.append(f"- Port {port}: {proto}\n")
        results.append("\n")

        for name in ['capture1', 'capture2']:
            results.append(f"## {name}.pcap\n\n")

            conv_file = self.extractions_dir / f'l2-{name}-conversations.txt'
            if not conv_file.exists():
                results.append(f"*Extraction not complete*\n\n")
                continue

            # We need to look at TCP conversations for port info
            # The conversation extract doesn't include ports, so we note this
            results.append("*Note: Detailed port analysis requires running tshark with port filters*\n\n")

            # Check if there are any internal-to-internal connections
            results.append("### Internal Network Traffic\n\n")
            internal_prefixes = ['192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.',
                                '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
                                '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.']

            internal_convs = []
            with open(conv_file) as f:
                for line in f:
                    if '<->' not in line:
                        continue

                    parts = line.split('<->')
                    if len(parts) != 2:
                        continue

                    ip1 = parts[0].strip()
                    ip2 = parts[1].strip().split()[0]

                    is_ip1_internal = any(ip1.startswith(p) for p in internal_prefixes)
                    is_ip2_internal = any(ip2.startswith(p) for p in internal_prefixes)

                    if is_ip1_internal and is_ip2_internal:
                        internal_convs.append(line.strip())

            if internal_convs:
                results.append(f"Found {len(internal_convs)} internal-to-internal conversations:\n\n")
                results.append("```\n")
                for conv in internal_convs[:30]:
                    results.append(f"{conv}\n")
                if len(internal_convs) > 30:
                    results.append(f"... and {len(internal_convs) - 30} more\n")
                results.append("```\n\n")
            else:
                results.append("*No internal-to-internal traffic detected*\n\n")

        with open(output, 'w') as f:
            f.writelines(results)

        print(f"  Written: {output}")
        self.mark_complete('analyses', 'l2_lateral_movement')
        return True

    def analyze_l2_vpn_analysis(self):
        """Analyze OpenVPN connection patterns."""
        output = self.analysis_dir / 'l2-vpn-analysis.md'
        output.parent.mkdir(parents=True, exist_ok=True)

        results = []
        results.append("# Level 2 VPN Analysis\n")
        results.append(f"Generated: {datetime.now().isoformat()}\n\n")

        openvpn_file = self.extractions_dir / 'l2-openvpn-events.csv'
        if not openvpn_file.exists():
            results.append("*OpenVPN extraction not complete*\n")
            with open(output, 'w') as f:
                f.writelines(results)
            self.mark_complete('analyses', 'l2_vpn_analysis')
            return True

        # Parse events
        events = []
        with open(openvpn_file) as f:
            reader = csv.DictReader(f)
            for row in reader:
                events.append(row)

        if not events:
            results.append("*No OpenVPN events found*\n")
            with open(output, 'w') as f:
                f.writelines(results)
            self.mark_complete('analyses', 'l2_vpn_analysis')
            return True

        results.append(f"## Overview\n\n")
        results.append(f"- Total events: {len(events)}\n")
        results.append(f"- First event: {events[0]['timestamp']}\n")
        results.append(f"- Last event: {events[-1]['timestamp']}\n\n")

        # Event type distribution
        event_types = defaultdict(int)
        for e in events:
            event_types[e['event_type']] += 1

        results.append("## Event Types\n\n")
        results.append("| Event Type | Count |\n")
        results.append("|------------|------:|\n")
        for etype, count in sorted(event_types.items(), key=lambda x: x[1], reverse=True):
            results.append(f"| {etype} | {count} |\n")
        results.append("\n")

        # Look for interesting events
        interesting_keywords = ['VERIFY', 'AUTH', 'CONNECT', 'DISCONNECT', 'ERROR', 'WARNING', 'FAIL']
        interesting_events = []
        for e in events:
            for keyword in interesting_keywords:
                if keyword in e['event_type'].upper() or keyword in e['details'].upper():
                    interesting_events.append(e)
                    break

        if interesting_events:
            results.append("## Notable Events\n\n")
            results.append("| Timestamp | Event | Details |\n")
            results.append("|-----------|-------|--------|\n")
            for e in interesting_events[:50]:
                details_short = e['details'][:60] + '...' if len(e['details']) > 60 else e['details']
                results.append(f"| {e['timestamp']} | {e['event_type']} | {details_short} |\n")
            results.append("\n")

        # Correlation with investigation timeframe
        results.append("## Timeframe Correlation\n\n")
        start_ts, end_ts = self.criteria.get_timeframe()
        if start_ts and end_ts:
            results.append(f"Investigation timeframe: {start_ts.date()} to {end_ts.date()}\n\n")

            in_timeframe = []
            for e in events:
                try:
                    event_ts = datetime.strptime(e['timestamp'], '%Y-%m-%d %H:%M:%S')
                    if start_ts <= event_ts <= end_ts:
                        in_timeframe.append(e)
                except ValueError:
                    continue

            results.append(f"Events within investigation timeframe: {len(in_timeframe)}\n\n")
        else:
            results.append("*No investigation timeframe defined*\n\n")

        with open(output, 'w') as f:
            f.writelines(results)

        print(f"  Written: {output}")
        self.mark_complete('analyses', 'l2_vpn_analysis')
        return True

    def _get_pcaps(self):
        """Discover all PCAPs from artifact files (keys ending in _pcap)."""
        artifacts = self.get_artifact_files()
        pcaps = []
        for key, path in sorted(artifacts.items()):
            if key.endswith('_pcap') and path and path.exists():
                pcaps.append((key, path))
        return pcaps

    def _build_mac_ip_inventory(self, pcaps):
        """Build MAC-IP inventory from ARP traffic in given PCAPs.

        First tries to load existing inventory CSV, then supplements
        with ARP extraction from PCAPs.
        """
        mac_to_ip = {}
        ip_to_mac = {}

        # Try loading existing inventory CSV
        inventory_file = self.extractions_dir / f'{self.tier_str}-mac-ip-inventory.csv'
        if not inventory_file.exists():
            # Fall back to l2 inventory (backwards compat)
            inventory_file = self.extractions_dir / 'l2-mac-ip-inventory.csv'

        if inventory_file.exists():
            with open(inventory_file) as f:
                reader = csv.DictReader(f)
                for row in reader:
                    mac = row['mac'].lower()
                    ip = row['ip']
                    mac_to_ip[mac] = ip
                    ip_to_mac[ip] = mac
            print(f"  Loaded {len(mac_to_ip)} entries from {inventory_file.name}")

        # Supplement with ARP from PCAPs
        arp_count = 0
        for pcap_key, pcap in pcaps:
            try:
                result = subprocess.run(
                    ['tshark', '-r', str(pcap), '-Y', 'arp',
                     '-T', 'fields', '-e', 'arp.src.hw_mac', '-e', 'arp.src.proto_ipv4'],
                    capture_output=True, text=True, timeout=120
                )
                if result.returncode != 0:
                    continue
                for line in result.stdout.strip().split('\n'):
                    if not line or '\t' not in line:
                        continue
                    parts = line.split('\t')
                    if len(parts) >= 2 and parts[0] and parts[1]:
                        mac = parts[0].lower()
                        ip = parts[1]
                        if ip != '0.0.0.0' and mac not in mac_to_ip:
                            mac_to_ip[mac] = ip
                            ip_to_mac[ip] = mac
                            arp_count += 1
            except Exception as e:
                print(f"  ERROR (ARP {pcap.name}): {e}")

        if arp_count:
            print(f"  Added {arp_count} new entries from ARP")

        return mac_to_ip, ip_to_mac

    def analyze_router_detection(self):
        """Auto-detect routers/gateways by analyzing traffic patterns.

        Generic method that works for any tier by discovering PCAPs
        from artifact files and building MAC-IP inventory from ARP.

        A router is detected when a MAC address forwards packets where
        src_ip or dst_ip doesn't match any IP associated with that MAC.
        """
        prefix = self.tier_str
        output = self.analysis_dir / f'{prefix}-router-detection.md'
        output.parent.mkdir(parents=True, exist_ok=True)

        results = []
        results.append(f"# Router/Gateway Detection (Level {self.tier})\n")
        results.append(f"Generated: {datetime.now().isoformat()}\n\n")
        results.append("Detecting devices that route traffic (forward packets for other IPs).\n\n")

        pcaps = self._get_pcaps()
        if not pcaps:
            results.append("*No PCAPs found in artifact files.*\n")
            with open(output, 'w') as f:
                f.writelines(results)
            return False

        pcap_names = [p.name for _, p in pcaps]
        results.append(f"Scanning {len(pcaps)} captures: {', '.join(pcap_names)}\n\n")

        # Build MAC-IP inventory
        mac_to_ip, ip_to_mac = self._build_mac_ip_inventory(pcaps)

        if not mac_to_ip:
            results.append("*No MAC-IP mappings found (no inventory CSV and no ARP traffic).*\n")
            with open(output, 'w') as f:
                f.writelines(results)
            print(f"  Written: {output}")
            self.mark_complete('analyses', 'router_detection')
            return True

        results.append(f"## MAC-IP Inventory\n\n")
        results.append(f"Using {len(mac_to_ip)} MAC-IP mappings.\n\n")
        results.append("| MAC | IP |\n")
        results.append("|-----|----|\n")
        for mac, ip in sorted(mac_to_ip.items(), key=lambda x: x[1]):
            results.append(f"| `{mac}` | {ip} |\n")
        results.append("\n")

        # Detect routing behavior
        router_stats = defaultdict(lambda: {
            'forwarded_packets': 0,
            'dst_networks': defaultdict(int),
            'src_networks': defaultdict(int),
            'own_ip': None,
            'pcaps_seen': set(),
        })

        for pcap_key, pcap in pcaps:
            print(f"  Routing scan: {pcap.name}")
            try:
                result = subprocess.run(
                    ['tshark', '-r', str(pcap), '-Y', 'ip',
                     '-T', 'fields', '-e', 'eth.src', '-e', 'eth.dst',
                     '-e', 'ip.src', '-e', 'ip.dst'],
                    capture_output=True, text=True, timeout=300
                )
                if result.returncode != 0:
                    continue

                for line in result.stdout.strip().split('\n'):
                    if not line or '\t' not in line:
                        continue
                    parts = line.split('\t')
                    if len(parts) < 4:
                        continue

                    eth_src, eth_dst, ip_src, ip_dst = parts[:4]
                    eth_src = eth_src.lower()
                    eth_dst = eth_dst.lower()

                    if eth_src in mac_to_ip:
                        own_ip = mac_to_ip[eth_src]
                        router_stats[eth_src]['own_ip'] = own_ip
                        if ip_src != own_ip:
                            router_stats[eth_src]['forwarded_packets'] += 1
                            src_net = '.'.join(ip_src.split('.')[:3]) + '.0/24'
                            router_stats[eth_src]['src_networks'][src_net] += 1
                            router_stats[eth_src]['pcaps_seen'].add(pcap.name)

                    if eth_dst in mac_to_ip:
                        own_ip = mac_to_ip[eth_dst]
                        router_stats[eth_dst]['own_ip'] = own_ip
                        if ip_dst != own_ip:
                            router_stats[eth_dst]['forwarded_packets'] += 1
                            dst_net = '.'.join(ip_dst.split('.')[:3]) + '.0/24'
                            router_stats[eth_dst]['dst_networks'][dst_net] += 1
                            router_stats[eth_dst]['pcaps_seen'].add(pcap.name)

            except Exception as e:
                print(f"  ERROR: {e}")

        # Filter to devices forwarding significant traffic
        routers = [(mac, stats) for mac, stats in router_stats.items()
                   if stats['forwarded_packets'] > 100]
        routers.sort(key=lambda x: x[1]['forwarded_packets'], reverse=True)

        if routers:
            results.append("## Detected Routers/Gateways\n\n")
            results.append("| MAC | Own IP | Forwarded Packets | PCAPs | Networks Routed |\n")
            results.append("|-----|--------|------------------:|-------|----------------|\n")

            for mac, stats in routers:
                own_ip = stats['own_ip'] or 'Unknown'
                fwd = stats['forwarded_packets']
                pcap_list = ', '.join(sorted(stats['pcaps_seen']))
                all_nets = set(stats['dst_networks'].keys()) | set(stats['src_networks'].keys())
                nets_str = ', '.join(sorted(all_nets)[:5])
                if len(all_nets) > 5:
                    nets_str += f" (+{len(all_nets)-5} more)"
                results.append(f"| `{mac}` | {own_ip} | {fwd:,} | {pcap_list} | {nets_str} |\n")

            results.append("\n## Detailed Router Analysis\n\n")

            for mac, stats in routers:
                own_ip = stats['own_ip'] or 'Unknown'
                results.append(f"### Router: {mac} ({own_ip})\n\n")

                results.append("**Traffic routed TO (destination networks):**\n\n")
                results.append("| Network | Packets |\n")
                results.append("|---------|--------:|\n")
                for net, count in sorted(stats['dst_networks'].items(),
                                        key=lambda x: x[1], reverse=True)[:10]:
                    results.append(f"| {net} | {count:,} |\n")

                results.append("\n**Traffic routed FROM (source networks):**\n\n")
                results.append("| Network | Packets |\n")
                results.append("|---------|--------:|\n")
                for net, count in sorted(stats['src_networks'].items(),
                                        key=lambda x: x[1], reverse=True)[:10]:
                    results.append(f"| {net} | {count:,} |\n")
                results.append("\n")

            # Save router list for use by router_analysis
            router_file = self.extractions_dir / f'{prefix}-detected-routers.csv'
            with open(router_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['mac', 'ip', 'forwarded_packets'])
                for mac, stats in routers:
                    writer.writerow([mac, stats['own_ip'] or '', stats['forwarded_packets']])
            results.append(f"\n*Router list saved to: {router_file.name}*\n")

        else:
            results.append("*No routers detected (no devices forwarding >100 packets)*\n")

        with open(output, 'w') as f:
            f.writelines(results)

        print(f"  Written: {output}")
        self.mark_complete('analyses', 'router_detection')
        return True

    def analyze_router_analysis(self):
        """Detailed routing topology analysis for detected gateways.

        Generic method that reads router list from router_detection output
        and analyzes traffic through each router across all tier PCAPs.
        """
        prefix = self.tier_str
        output = self.analysis_dir / f'{prefix}-router-analysis.md'
        output.parent.mkdir(parents=True, exist_ok=True)

        results = []
        results.append(f"# Router Topology Analysis (Level {self.tier})\n")
        results.append(f"Generated: {datetime.now().isoformat()}\n\n")

        # Load detected routers
        router_file = self.extractions_dir / f'{prefix}-detected-routers.csv'
        if not router_file.exists():
            results.append(f"*Run router_detection first to identify routers.*\n")
            with open(output, 'w') as f:
                f.writelines(results)
            return False

        routers = []
        with open(router_file) as f:
            reader = csv.DictReader(f)
            for row in reader:
                routers.append(row)

        if not routers:
            results.append("*No routers detected.*\n")
            with open(output, 'w') as f:
                f.writelines(results)
            self.mark_complete('analyses', 'router_analysis')
            return True

        pcaps = self._get_pcaps()

        results.append("## Network Topology\n\n")
        results.append("Based on traffic analysis of detected routers.\n\n")

        for router in routers:
            mac = router['mac']
            ip = router['ip']

            results.append(f"### {ip} ({mac})\n\n")

            outbound = defaultdict(lambda: {'packets': 0, 'ips': set()})
            inbound = defaultdict(lambda: {'packets': 0, 'ips': set()})

            for pcap_key, pcap in pcaps:
                try:
                    # Outbound: dst MAC = router
                    result = subprocess.run(
                        ['tshark', '-r', str(pcap),
                         '-Y', f'eth.dst == {mac} && ip',
                         '-T', 'fields', '-e', 'ip.src', '-e', 'ip.dst'],
                        capture_output=True, text=True, timeout=300
                    )

                    if result.returncode == 0:
                        for line in result.stdout.strip().split('\n'):
                            if not line:
                                continue
                            parts = line.split('\t')
                            if len(parts) >= 2:
                                ip_src, ip_dst = parts[:2]
                                dst_net = '.'.join(ip_dst.split('.')[:3]) + '.0/24'
                                outbound[dst_net]['packets'] += 1
                                outbound[dst_net]['ips'].add(ip_dst)

                    # Inbound: src MAC = router
                    result = subprocess.run(
                        ['tshark', '-r', str(pcap),
                         '-Y', f'eth.src == {mac} && ip',
                         '-T', 'fields', '-e', 'ip.src', '-e', 'ip.dst'],
                        capture_output=True, text=True, timeout=300
                    )

                    if result.returncode == 0:
                        for line in result.stdout.strip().split('\n'):
                            if not line:
                                continue
                            parts = line.split('\t')
                            if len(parts) >= 2:
                                ip_src, ip_dst = parts[:2]
                                src_net = '.'.join(ip_src.split('.')[:3]) + '.0/24'
                                inbound[src_net]['packets'] += 1
                                inbound[src_net]['ips'].add(ip_src)

                except Exception as e:
                    print(f"  ERROR analyzing {pcap.name}: {e}")

            results.append("**Outbound (traffic leaving through this router):**\n\n")
            results.append("| Destination Network | Packets | Unique IPs | Sample IPs |\n")
            results.append("|---------------------|--------:|-----------:|------------|\n")
            for net, data in sorted(outbound.items(), key=lambda x: x[1]['packets'], reverse=True)[:15]:
                sample_ips = ', '.join(sorted(data['ips'])[:3])
                if len(data['ips']) > 3:
                    sample_ips += '...'
                results.append(f"| {net} | {data['packets']:,} | {len(data['ips'])} | {sample_ips} |\n")

            results.append("\n**Inbound (traffic arriving through this router):**\n\n")
            results.append("| Source Network | Packets | Unique IPs | Sample IPs |\n")
            results.append("|----------------|--------:|-----------:|------------|\n")
            for net, data in sorted(inbound.items(), key=lambda x: x[1]['packets'], reverse=True)[:15]:
                sample_ips = ', '.join(sorted(data['ips'])[:3])
                if len(data['ips']) > 3:
                    sample_ips += '...'
                results.append(f"| {net} | {data['packets']:,} | {len(data['ips'])} | {sample_ips} |\n")

            results.append("\n")

        # Generate ASCII topology diagram
        results.append("## Network Topology Diagram\n\n")
        results.append("```\n")

        if routers:
            r = routers[0]
            results.append(f"                    ┌─────────────────┐\n")
            results.append(f"                    │  External/WAN   │\n")
            results.append(f"                    └────────┬────────┘\n")
            results.append(f"                             │\n")
            results.append(f"                    ┌────────┴────────┐\n")
            results.append(f"                    │  Gateway/Router │\n")
            results.append(f"                    │  {r['ip']:^15} │\n")
            results.append(f"                    │  {r['mac']}│\n")
            results.append(f"                    └────────┬────────┘\n")
            results.append(f"                             │\n")
            results.append(f"              ┌──────────────┼──────────────┐\n")
            results.append(f"              │              │              │\n")
            results.append(f"         ┌────┴────┐   ┌─────┴────┐   ┌─────┴────┐\n")
            results.append(f"         │ Network │   │ Network  │   │ Network  │\n")
            results.append(f"         │   A     │   │    B     │   │    C     │\n")
            results.append(f"         └─────────┘   └──────────┘   └──────────┘\n")

        results.append("```\n")
        results.append("\n*Note: This is a simplified diagram. See tables above for actual networks.*\n")

        with open(output, 'w') as f:
            f.writelines(results)

        print(f"  Written: {output}")
        self.mark_complete('analyses', 'router_analysis')
        return True

    def analyze_file_transfers(self):
        """Document extracted file transfers from FTP, HTTP, SMB (any tier)."""
        output = self.analysis_dir / f'{self.tier_str}-file-transfers.md'
        output.parent.mkdir(parents=True, exist_ok=True)
        manifest_file = self.extractions_dir / 'extracted-files-manifest.csv'

        results = []
        results.append(f"# Extracted File Transfers - Level {self.tier}\n\n")
        results.append(f"Generated: {datetime.now().isoformat()}\n\n")

        if not manifest_file.exists():
            results.append("*No manifest found. Run file object extraction first.*\n")
            with open(output, 'w') as f:
                f.writelines(results)
            return False

        # Read manifest
        files = []
        with open(manifest_file, 'r') as f:
            reader = csv.DictReader(f)
            files = list(reader)

        if not files:
            results.append("*No files were extracted from the captures.*\n")
            with open(output, 'w') as f:
                f.writelines(results)
            self.mark_complete('analyses', 'file_transfers')
            return True

        results.append(f"**Total files extracted: {len(files)}**\n\n")

        # Group by pcap and protocol
        by_pcap = {}
        for f in files:
            pcap = f['pcap']
            if pcap not in by_pcap:
                by_pcap[pcap] = {}
            proto = f['protocol']
            if proto not in by_pcap[pcap]:
                by_pcap[pcap][proto] = []
            by_pcap[pcap][proto].append(f)

        for pcap in sorted(by_pcap.keys()):
            results.append(f"## {pcap}.pcap\n\n")

            for proto in sorted(by_pcap[pcap].keys()):
                proto_files = by_pcap[pcap][proto]
                results.append(f"### {proto.upper()} ({len(proto_files)} files)\n\n")

                results.append("| Filename | Size | SHA256 |\n")
                results.append("|----------|-----:|--------|\n")

                for f in sorted(proto_files, key=lambda x: x['filename']):
                    size = int(f['size'])
                    if size >= 1024*1024:
                        size_str = f"{size/1024/1024:.1f} MB"
                    elif size >= 1024:
                        size_str = f"{size/1024:.1f} KB"
                    else:
                        size_str = f"{size} B"
                    sha_short = f['sha256'][:16] + '...'
                    results.append(f"| {f['filename']} | {size_str} | `{sha_short}` |\n")

                results.append("\n")

        # Highlight forensically interesting files
        results.append("## Forensic Highlights\n\n")
        interesting = []
        for f in files:
            fname = f['filename'].lower()
            size = int(f['size'])
            # Flag large files, zip/archive, specific protocols
            if size > 1024*1024:  # > 1MB
                interesting.append((f, f"Large file ({size/1024/1024:.1f} MB)"))
            elif fname.endswith(('.zip', '.rar', '.7z', '.tar', '.gz')):
                interesting.append((f, "Archive file - potential exfiltration"))
            elif fname.endswith(('.exe', '.dll', '.ps1', '.bat', '.vbs')):
                interesting.append((f, "Executable - potential malware"))
            elif fname.endswith(('.pdf', '.doc', '.docx', '.xls', '.xlsx')):
                interesting.append((f, "Document - potential sensitive data"))

        if interesting:
            results.append("| File | Protocol | Reason | SHA256 |\n")
            results.append("|------|----------|--------|--------|\n")
            for f, reason in interesting:
                results.append(f"| {f['filename']} | {f['protocol']} | {reason} | `{f['sha256'][:16]}...` |\n")
        else:
            results.append("*No obviously suspicious files detected.*\n")

        results.append("\n## Full SHA256 Hashes\n\n")
        results.append("```\n")
        for f in files:
            results.append(f"{f['sha256']}  {f['path']}\n")
        results.append("```\n")

        with open(output, 'w') as f:
            f.writelines(results)

        print(f"  Written: {output}")
        self.mark_complete('analyses', 'file_transfers')
        return True

    def analyze_l2_file_transfers(self):
        """Alias: delegates to generic analyze_file_transfers()."""
        return self.analyze_file_transfers()

    def analyze_malware_scan(self):
        """Scan extracted files for malware indicators using PE analysis and YARA (any tier)."""
        output = self.analysis_dir / f'{self.tier_str}-malware-scan.md'
        output.parent.mkdir(parents=True, exist_ok=True)
        extracted_dir = self.extractions_dir / 'extracted-files'
        manifest_file = self.extractions_dir / 'extracted-files-manifest.csv'

        results = []
        results.append(f"# Malware Scan - Extracted Files (Level {self.tier})\n\n")
        results.append(f"Generated: {datetime.now().isoformat()}\n\n")

        if not extracted_dir.exists():
            results.append("*No extracted files found. Run `l2_file_objects` extraction first.*\n")
            with open(output, 'w') as f:
                f.writelines(results)
            return False

        # Try to import optional libraries
        try:
            import pefile
            HAS_PEFILE = True
        except ImportError:
            HAS_PEFILE = False
            results.append("*Warning: pefile not installed - PE analysis disabled*\n\n")

        try:
            import yara
            HAS_YARA = True
        except ImportError:
            HAS_YARA = False
            results.append("*Warning: yara-python not installed - YARA scanning disabled*\n\n")

        # Basic YARA rules for common malware indicators
        YARA_RULES = '''
rule Suspicious_Strings {
    strings:
        $ps1 = "powershell" nocase
        $ps2 = "invoke-expression" nocase
        $ps3 = "downloadstring" nocase
        $ps4 = "iex(" nocase
        $cmd1 = "cmd.exe /c" nocase
        $cmd2 = "wscript.shell" nocase
        $net1 = "webclient" nocase
        $net2 = "net.webrequest" nocase
        $enc1 = "frombase64string" nocase
        $enc2 = "-enc " nocase
        $enc3 = "-encodedcommand" nocase
        $reg1 = "currentversion\\\\run" nocase
        $reg2 = "hkey_current_user" nocase
        $shell1 = "/bin/sh" nocase
        $shell2 = "/bin/bash" nocase
        $c2_1 = "user-agent:" nocase
        $c2_2 = "POST /"
    condition:
        3 of them
}

rule Packed_Executable {
    strings:
        $upx = "UPX!"
        $aspack = ".aspack"
        $petite = ".petite"
        $themida = "Themida"
    condition:
        any of them
}

rule Potential_Backdoor {
    strings:
        $bd1 = "reverse" nocase
        $bd2 = "shell" nocase
        $bd3 = "bind" nocase
        $bd4 = "connect" nocase
        $bd5 = "socket" nocase
        $port1 = "4444"
        $port2 = "5555"
        $port3 = "1337"
    condition:
        ($bd1 and $bd2) or ($bd3 and $bd5) or ($bd4 and $bd5 and any of ($port*))
}

rule Suspicious_PE_Imports {
    strings:
        $imp1 = "VirtualAlloc"
        $imp2 = "VirtualProtect"
        $imp3 = "WriteProcessMemory"
        $imp4 = "CreateRemoteThread"
        $imp5 = "NtUnmapViewOfSection"
        $imp6 = "SetWindowsHookEx"
    condition:
        3 of them
}
'''

        # Compile YARA rules
        yara_compiled = None
        if HAS_YARA:
            try:
                yara_compiled = yara.compile(source=YARA_RULES)
            except Exception as e:
                results.append(f"*Warning: YARA compilation failed: {e}*\n\n")

        # Find all executable files to scan
        scan_results = []
        pe_analysis = []
        yara_matches = []

        # Get list of files from manifest or scan directory
        files_to_scan = []
        if manifest_file.exists():
            with open(manifest_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    fpath = self.extractions_dir / row['path']
                    if fpath.exists():
                        files_to_scan.append((fpath, row))
        else:
            for fpath in extracted_dir.rglob('*'):
                if fpath.is_file():
                    files_to_scan.append((fpath, {'filename': fpath.name, 'path': str(fpath)}))

        results.append(f"**Scanning {len(files_to_scan)} files**\n\n")

        # Scan each file
        for fpath, meta in files_to_scan:
            if not fpath.exists() or fpath.stat().st_size == 0:
                continue

            fname = meta.get('filename', fpath.name)
            findings = []

            # Get file type using file command
            try:
                file_result = subprocess.run(
                    ['file', '-b', str(fpath)],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                file_type = file_result.stdout.strip() if file_result.returncode == 0 else "unknown"
            except Exception:
                file_type = "unknown"

            # PE Analysis for Windows executables
            is_pe = 'PE32' in file_type or 'executable' in file_type.lower() or \
                    fname.lower().endswith(('.exe', '.dll', '.sys', '.scr'))

            if is_pe and HAS_PEFILE:
                try:
                    pe = pefile.PE(str(fpath), fast_load=True)
                    pe.parse_data_directories()

                    pe_info = {
                        'file': fname,
                        'path': str(fpath.relative_to(self.extractions_dir)),
                        'machine': hex(pe.FILE_HEADER.Machine),
                        'timestamp': datetime.utcfromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat(),
                        'sections': [],
                        'imports': [],
                        'suspicious': []
                    }

                    # Check sections
                    for section in pe.sections:
                        sec_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
                        entropy = section.get_entropy()
                        pe_info['sections'].append({
                            'name': sec_name,
                            'entropy': round(entropy, 2),
                            'size': section.SizeOfRawData
                        })
                        if entropy > 7.0:
                            pe_info['suspicious'].append(f"High entropy section: {sec_name} ({entropy:.2f})")

                        # SwollenFile detection: large sections with very low entropy = null padding for AV evasion
                        if section.SizeOfRawData > 1_000_000 and entropy < 1.0:
                            pe_info['suspicious'].append(
                                f"SwollenFile (AV evasion): {sec_name} is {section.SizeOfRawData:,} bytes with entropy {entropy:.2f} (null padding)"
                            )

                    # Check imports
                    suspicious_imports = [
                        # Process injection
                        'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect', 'WriteProcessMemory',
                        'CreateRemoteThread', 'NtUnmapViewOfSection', 'QueueUserAPC',
                        # Keylogging/hooking
                        'SetWindowsHookEx', 'GetAsyncKeyState', 'SetWindowsHookExA', 'SetWindowsHookExW',
                        # Code execution
                        'CreateProcess', 'CreateProcessA', 'CreateProcessW',
                        'ShellExecute', 'ShellExecuteA', 'ShellExecuteW', 'ShellExecuteEx',
                        'WinExec', 'system',
                        # Download/network
                        'URLDownloadToFile', 'URLDownloadToFileA', 'URLDownloadToFileW',
                        'URLDownloadToCacheFile', 'URLDownloadToCacheFileA', 'URLDownloadToCacheFileW',
                        'InternetOpenUrl', 'HttpOpenRequest',
                        # Encryption/decryption (potential ransomware or payload decryption)
                        'CryptEncrypt', 'CryptDecrypt', 'DecryptFile', 'DecryptFileA', 'DecryptFileW',
                        'CryptAcquireContext', 'CryptGenKey',
                        # MSI abuse (persistence/installation)
                        'MsiInstallProduct', 'MsiOpenPackage', 'MsiViewExecute',
                        # Anti-analysis
                        'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess',
                    ]
                    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                        for entry in pe.DIRECTORY_ENTRY_IMPORT:
                            dll_name = entry.dll.decode('utf-8', errors='ignore')
                            for imp in entry.imports:
                                if imp.name:
                                    imp_name = imp.name.decode('utf-8', errors='ignore')
                                    pe_info['imports'].append(f"{dll_name}:{imp_name}")
                                    if imp_name in suspicious_imports:
                                        pe_info['suspicious'].append(f"Suspicious import: {imp_name}")

                    # Check for no imports (possible packer)
                    if not pe_info['imports']:
                        pe_info['suspicious'].append("No imports detected (possible packer)")

                    pe_analysis.append(pe_info)
                    pe.close()

                except Exception as e:
                    findings.append(f"PE parse error: {str(e)[:50]}")

            # YARA scanning
            if yara_compiled and fpath.stat().st_size < 100 * 1024 * 1024:  # Skip files > 100MB
                try:
                    matches = yara_compiled.match(str(fpath), timeout=30)
                    if matches:
                        yara_matches.append({
                            'file': fname,
                            'path': str(fpath.relative_to(self.extractions_dir)),
                            'rules': [m.rule for m in matches]
                        })
                except Exception as e:
                    pass  # Skip YARA errors silently

        # Generate report
        results.append("## PE Analysis Results\n\n")
        if pe_analysis:
            suspicious_pes = [p for p in pe_analysis if p['suspicious']]
            results.append(f"**Analyzed {len(pe_analysis)} PE files, {len(suspicious_pes)} with suspicious indicators**\n\n")

            if suspicious_pes:
                results.append("### Suspicious PE Files\n\n")
                for pe_info in suspicious_pes:
                    results.append(f"#### {pe_info['file']}\n\n")
                    results.append(f"- **Path**: `{pe_info['path']}`\n")
                    results.append(f"- **Compile Time**: {pe_info['timestamp']}\n")
                    results.append(f"- **Machine**: {pe_info['machine']}\n")
                    results.append("\n**Suspicious Indicators:**\n")
                    for susp in pe_info['suspicious']:
                        results.append(f"- {susp}\n")
                    results.append("\n**Sections:**\n")
                    results.append("| Name | Entropy | Size |\n")
                    results.append("|------|--------:|-----:|\n")
                    for sec in pe_info['sections']:
                        # Flag both high entropy (packed/encrypted) and SwollenFile (low entropy + large)
                        if sec['entropy'] > 7.0:
                            entropy_flag = " ⚠️ HIGH"
                        elif sec['size'] > 1_000_000 and sec['entropy'] < 1.0:
                            entropy_flag = " ⚠️ SWOLLEN"
                        else:
                            entropy_flag = ""
                        results.append(f"| {sec['name']} | {sec['entropy']}{entropy_flag} | {sec['size']:,} |\n")
                    results.append("\n")
        else:
            results.append("*No PE files found or pefile not available.*\n\n")

        results.append("## YARA Scan Results\n\n")
        if yara_matches:
            results.append(f"**{len(yara_matches)} files matched YARA rules**\n\n")
            results.append("| File | Rules Matched |\n")
            results.append("|------|---------------|\n")
            for match in yara_matches:
                rules_str = ', '.join(match['rules'])
                results.append(f"| {match['file']} | {rules_str} |\n")
            results.append("\n")

            results.append("### Detailed YARA Matches\n\n")
            for match in yara_matches:
                results.append(f"**{match['file']}** (`{match['path']}`)\n")
                results.append(f"- Rules: {', '.join(match['rules'])}\n\n")
        else:
            results.append("*No YARA matches found.*\n\n")

        # Summary
        results.append("## Summary\n\n")
        total_suspicious = len([p for p in pe_analysis if p['suspicious']]) + len(yara_matches)
        if total_suspicious > 0:
            results.append(f"⚠️ **{total_suspicious} files require further investigation**\n\n")
        else:
            results.append("✅ **No obvious malware indicators detected**\n\n")

        results.append("*Note: This is automated scanning with basic rules. ")
        results.append("Manual analysis and VirusTotal lookup recommended for suspicious files.*\n")

        with open(output, 'w') as f:
            f.writelines(results)

        print(f"  Written: {output}")
        self.mark_complete('analyses', 'malware_scan')
        return True

    def analyze_l2_malware_scan(self):
        """Alias: delegates to generic analyze_malware_scan()."""
        return self.analyze_malware_scan()


# =============================================================================
# HELPER FUNCTIONS FOR CLI
# =============================================================================
def run_extraction(analyzer, step, force=False):
    """Run a single extraction step."""
    print(f"\n[{step}]")
    if not force and analyzer.is_complete('extractions', step):
        print("  Skipping (already complete, use --force to re-run)")
        return True

    method = getattr(analyzer, f'extract_{step}', None)
    if method:
        return method()
    else:
        print(f"  ERROR: No extraction method for {step}")
        return False


def run_analysis(analyzer, step, force=False, show=False):
    """Run a single analysis step."""
    print(f"\n[{step}]")
    if not force and analyzer.is_complete('analyses', step):
        print("  Already complete (use --force to re-run)")
        if show:
            _show_result(analyzer, step)
        return True

    method = getattr(analyzer, f'analyze_{step}', None)
    if method:
        success = method()
        if success and show:
            _show_result(analyzer, step)
        return success
    else:
        print(f"  ERROR: No analysis method for {step}")
        return False


def _show_result(analyzer, step):
    """Display the result file for an analysis."""
    file_map = analyzer.get_analysis_file_map()
    filename = file_map.get(step, f'{step.replace("_", "-")}.md')
    output = analyzer.analysis_dir / filename
    if output.exists():
        print(f"\n  --- {output.name} ---")
        with open(output) as f:
            for line in f.read().split('\n'):
                print(f"  {line}")
        print(f"  --- end ---\n")
