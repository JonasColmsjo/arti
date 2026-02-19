"""
Binary/malware analysis module.

Performs static analysis on PE files using radare2 and Python libraries.
Designed for investigating suspicious executables extracted from network captures.
"""

import csv
import hashlib
import json
import os
import re
import subprocess
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from .base import REPO_DIR, ForensicAnalyzer


# =============================================================================
# BINARY ANALYZER CLASS
# =============================================================================
class BinaryAnalyzer:
    """Static binary analysis using radare2 and pefile."""

    def __init__(self, output_dir: Path = None):
        self.output_dir = output_dir or REPO_DIR / 'work' / 'binary-analysis'
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.r2_path = self._find_radare2()

        # Try to import optional libraries
        try:
            import pefile
            self.pefile = pefile
        except ImportError:
            self.pefile = None

    def _find_radare2(self) -> str:
        """Find radare2 binary."""
        for cmd in ['r2', 'radare2']:
            try:
                result = subprocess.run([cmd, '-v'], capture_output=True, text=True)
                if result.returncode == 0:
                    return cmd
            except FileNotFoundError:
                continue
        return None

    def _run_r2(self, file_path: Path, commands: list[str], timeout: int = 30) -> str:
        """Run radare2 commands on a file."""
        if not self.r2_path:
            return "ERROR: radare2 not found"

        # Join commands with newlines for -c
        cmd_str = ';'.join(commands)

        try:
            result = subprocess.run(
                [self.r2_path, '-q', '-c', cmd_str, str(file_path)],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            return "ERROR: radare2 timed out"
        except Exception as e:
            return f"ERROR: {e}"

    def _calculate_hashes(self, file_path: Path) -> dict:
        """Calculate file hashes."""
        hashes = {'md5': '', 'sha1': '', 'sha256': ''}

        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                hashes['md5'] = hashlib.md5(data).hexdigest()
                hashes['sha1'] = hashlib.sha1(data).hexdigest()
                hashes['sha256'] = hashlib.sha256(data).hexdigest()
        except Exception as e:
            hashes['error'] = str(e)

        return hashes

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0

        from collections import Counter
        import math

        counter = Counter(data)
        length = len(data)
        entropy = 0.0

        for count in counter.values():
            if count > 0:
                freq = count / length
                entropy -= freq * math.log2(freq)

        return round(entropy, 2)

    def analyze_file(self, file_path: Path, output_name: str = None) -> dict:
        """Perform comprehensive analysis on a binary file.

        Args:
            file_path: Path to the file to analyze
            output_name: Optional name for output files (defaults to filename)

        Returns:
            Dict containing analysis results
        """
        file_path = Path(file_path)
        if not file_path.exists():
            return {'error': f'File not found: {file_path}'}

        output_name = output_name or file_path.stem
        results = {
            'file': str(file_path),
            'filename': file_path.name,
            'size': file_path.stat().st_size,
            'analyzed': datetime.now().isoformat(),
            'hashes': {},
            'file_type': '',
            'pe_info': {},
            'sections': [],
            'imports': [],
            'exports': [],
            'strings': [],
            'suspicious_indicators': [],
            'entropy_analysis': {},
            'verdict': 'unknown',
            'confidence': 'low',
        }

        print(f"Analyzing: {file_path.name}")

        # Phase 1: Basic file info and hashes
        print("  [1/6] Calculating hashes...")
        results['hashes'] = self._calculate_hashes(file_path)

        # Get file type
        try:
            file_result = subprocess.run(['file', '-b', str(file_path)],
                                         capture_output=True, text=True, timeout=10)
            results['file_type'] = file_result.stdout.strip()
        except Exception:
            results['file_type'] = 'unknown'

        # Check if PE file
        is_pe = 'PE32' in results['file_type'] or file_path.suffix.lower() in ['.exe', '.dll', '.sys']

        # Phase 2: PE Analysis (if applicable)
        if is_pe and self.pefile:
            print("  [2/6] PE analysis...")
            results['pe_info'], results['sections'], results['imports'], results['exports'] = \
                self._analyze_pe(file_path)
        elif is_pe:
            print("  [2/6] PE analysis (radare2 fallback)...")
            results['pe_info'], results['sections'], results['imports'], results['exports'] = \
                self._analyze_pe_r2(file_path)
        else:
            print("  [2/6] Skipping PE analysis (not a PE file)")

        # Phase 3: Entropy analysis
        print("  [3/6] Entropy analysis...")
        results['entropy_analysis'] = self._analyze_entropy(file_path, results.get('sections', []))

        # Phase 4: String extraction
        print("  [4/6] String extraction...")
        results['strings'] = self._extract_strings(file_path)

        # Phase 5: Suspicious indicator detection
        print("  [5/6] Detecting suspicious indicators...")
        results['suspicious_indicators'] = self._detect_suspicious(results)

        # Phase 6: Verdict
        print("  [6/6] Generating verdict...")
        results['verdict'], results['confidence'] = self._generate_verdict(results)

        # Generate report
        report_path = self.output_dir / f'{output_name}-analysis.md'
        self._generate_report(results, report_path)
        print(f"  Report: {report_path}")

        return results

    def _analyze_pe(self, file_path: Path) -> tuple:
        """Analyze PE file using pefile library."""
        pe_info = {}
        sections = []
        imports = []
        exports = []

        try:
            pe = self.pefile.PE(str(file_path))

            # Basic info
            pe_info = {
                'machine': hex(pe.FILE_HEADER.Machine),
                'compile_time': datetime.utcfromtimestamp(
                    pe.FILE_HEADER.TimeDateStamp).isoformat(),
                'subsystem': pe.OPTIONAL_HEADER.Subsystem,
                'dll': pe.FILE_HEADER.IMAGE_FILE_DLL,
                'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            }

            # Sections
            for section in pe.sections:
                sec_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
                entropy = section.get_entropy()
                sections.append({
                    'name': sec_name,
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData,
                    'entropy': round(entropy, 2),
                    'characteristics': hex(section.Characteristics),
                    'executable': bool(section.Characteristics & 0x20000000),
                    'writable': bool(section.Characteristics & 0x80000000),
                })

            # Imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    for imp in entry.imports:
                        if imp.name:
                            imports.append({
                                'dll': dll_name,
                                'function': imp.name.decode('utf-8', errors='ignore'),
                                'ordinal': imp.ordinal,
                            })

            # Exports
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        exports.append({
                            'name': exp.name.decode('utf-8', errors='ignore'),
                            'ordinal': exp.ordinal,
                            'address': hex(exp.address),
                        })

            pe.close()

        except Exception as e:
            pe_info['error'] = str(e)

        return pe_info, sections, imports, exports

    def _analyze_pe_r2(self, file_path: Path) -> tuple:
        """Analyze PE file using radare2 (fallback if pefile not available)."""
        pe_info = {}
        sections = []
        imports = []
        exports = []

        # Get basic info
        info_output = self._run_r2(file_path, ['iIj'])
        try:
            info = json.loads(info_output)
            pe_info = {
                'machine': info.get('machine', 'unknown'),
                'compile_time': info.get('compiled', 'unknown'),
                'subsystem': info.get('subsys', 'unknown'),
                'entry_point': info.get('baddr', 'unknown'),
            }
        except json.JSONDecodeError:
            pe_info['raw'] = info_output[:500]

        # Get sections
        sections_output = self._run_r2(file_path, ['iSj'])
        try:
            secs = json.loads(sections_output)
            for s in secs:
                sections.append({
                    'name': s.get('name', ''),
                    'virtual_size': s.get('vsize', 0),
                    'raw_size': s.get('size', 0),
                    'entropy': s.get('entropy', 0),
                    'characteristics': s.get('perm', ''),
                    'executable': 'x' in s.get('perm', ''),
                    'writable': 'w' in s.get('perm', ''),
                })
        except json.JSONDecodeError:
            pass

        # Get imports
        imports_output = self._run_r2(file_path, ['iij'])
        try:
            imps = json.loads(imports_output)
            for i in imps:
                imports.append({
                    'dll': i.get('libname', ''),
                    'function': i.get('name', ''),
                    'ordinal': i.get('ordinal', 0),
                })
        except json.JSONDecodeError:
            pass

        return pe_info, sections, imports, exports

    def _analyze_entropy(self, file_path: Path, sections: list) -> dict:
        """Analyze file entropy."""
        result = {
            'overall': 0.0,
            'sections': {},
            'high_entropy_sections': [],
            'swollen_sections': [],  # Large sections with low entropy (AV evasion via null padding)
        }

        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                result['overall'] = self._calculate_entropy(data)
        except Exception as e:
            result['error'] = str(e)
            return result

        # Check sections for high entropy
        for section in sections:
            entropy = section.get('entropy', 0)
            result['sections'][section['name']] = entropy
            if entropy > 7.0:
                result['high_entropy_sections'].append({
                    'name': section['name'],
                    'entropy': entropy,
                    'size': section.get('raw_size', 0),
                })

            # SwollenFile detection: large sections with very low entropy = null padding for AV evasion
            raw_size = section.get('raw_size', 0)
            if raw_size > 1_000_000 and entropy < 1.0:
                result['swollen_sections'].append({
                    'name': section['name'],
                    'entropy': entropy,
                    'size': raw_size,
                })

        return result

    def _extract_strings(self, file_path: Path, min_length: int = 6) -> list:
        """Extract interesting strings from file."""
        strings = []

        # Use radare2 for string extraction
        output = self._run_r2(file_path, ['izj'], timeout=60)

        try:
            raw_strings = json.loads(output)

            # Interesting patterns
            patterns = {
                'url': re.compile(r'https?://|ftp://|\\\\\\\\', re.I),
                'ip': re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'),
                'registry': re.compile(r'HKEY_|CurrentVersion|\\Run|\\Services', re.I),
                'file_ops': re.compile(r'cmd\.exe|powershell|CreateFile|WriteFile|DeleteFile', re.I),
                'network': re.compile(r'socket|connect|recv|send|WSA|InternetOpen', re.I),
                'crypto': re.compile(r'crypt|aes|rsa|base64|decode|encrypt|decrypt', re.I),
                'suspicious': re.compile(r'shell|inject|hook|keylog|capture|dump|password', re.I),
            }

            for s in raw_strings:
                string = s.get('string', '')
                if len(string) < min_length:
                    continue

                # Check against patterns
                for category, pattern in patterns.items():
                    if pattern.search(string):
                        strings.append({
                            'string': string[:200],  # Truncate long strings
                            'category': category,
                            'offset': s.get('vaddr', 0),
                            'section': s.get('section', ''),
                        })
                        break

        except json.JSONDecodeError:
            # Fallback to strings command
            try:
                result = subprocess.run(['strings', '-n', str(min_length), str(file_path)],
                                       capture_output=True, text=True, timeout=30)
                for line in result.stdout.split('\n')[:100]:
                    strings.append({'string': line, 'category': 'raw'})
            except Exception:
                pass

        return strings[:500]  # Limit to 500 strings

    def _detect_suspicious(self, results: dict) -> list:
        """Detect suspicious indicators from analysis results."""
        indicators = []

        # Check compile time
        compile_time = results.get('pe_info', {}).get('compile_time', '')
        if compile_time:
            try:
                ct = datetime.fromisoformat(compile_time)
                if ct.year < 2000:
                    indicators.append({
                        'type': 'timestamp_anomaly',
                        'severity': 'medium',
                        'description': f'Suspicious compile time: {compile_time} (possible timestomping)',
                    })
                elif ct > datetime.now():
                    indicators.append({
                        'type': 'timestamp_anomaly',
                        'severity': 'high',
                        'description': f'Future compile time: {compile_time}',
                    })
            except Exception:
                pass

        # Check for high entropy sections
        for section in results.get('entropy_analysis', {}).get('high_entropy_sections', []):
            indicators.append({
                'type': 'high_entropy',
                'severity': 'medium',
                'description': f"High entropy section: {section['name']} ({section['entropy']})",
            })

        # Check for SwollenFile (AV evasion via null padding)
        for section in results.get('entropy_analysis', {}).get('swollen_sections', []):
            indicators.append({
                'type': 'swollen_file',
                'severity': 'high',
                'description': f"SwollenFile (AV evasion): {section['name']} is {section['size']:,} bytes with entropy {section['entropy']} (null padding)",
            })

        # Check for executable + writable sections
        for section in results.get('sections', []):
            if section.get('executable') and section.get('writable'):
                indicators.append({
                    'type': 'rwx_section',
                    'severity': 'high',
                    'description': f"RWX section: {section['name']} (self-modifying code)",
                })

        # Check for suspicious imports
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

        for imp in results.get('imports', []):
            func = imp.get('function', '')
            if func in suspicious_imports:
                indicators.append({
                    'type': 'suspicious_import',
                    'severity': 'medium',
                    'description': f"Suspicious API: {imp['dll']}:{func}",
                })

        # Check for suspicious strings
        high_risk_categories = ['suspicious', 'crypto']
        for s in results.get('strings', []):
            if s.get('category') in high_risk_categories:
                indicators.append({
                    'type': 'suspicious_string',
                    'severity': 'low',
                    'description': f"Suspicious string ({s['category']}): {s['string'][:50]}",
                })

        # Check for no imports (possible packer)
        if results.get('pe_info') and not results.get('imports'):
            indicators.append({
                'type': 'no_imports',
                'severity': 'high',
                'description': 'No imports detected (likely packed or obfuscated)',
            })

        return indicators

    def _generate_verdict(self, results: dict) -> tuple:
        """Generate verdict based on analysis results."""
        indicators = results.get('suspicious_indicators', [])

        if not indicators:
            return 'clean', 'medium'

        # Count by severity
        high = sum(1 for i in indicators if i['severity'] == 'high')
        medium = sum(1 for i in indicators if i['severity'] == 'medium')
        low = sum(1 for i in indicators if i['severity'] == 'low')

        # Score: high=3, medium=2, low=1
        score = high * 3 + medium * 2 + low

        if score >= 6 or high >= 2:
            return 'malicious', 'high' if high >= 2 else 'medium'
        elif score >= 3 or high >= 1:
            return 'suspicious', 'medium'
        elif score >= 1:
            return 'likely_benign', 'low'
        else:
            return 'clean', 'medium'

    def _generate_report(self, results: dict, output_path: Path):
        """Generate markdown report from analysis results."""
        lines = []

        # Header
        lines.append(f"# Binary Analysis Report: {results['filename']}\n")
        lines.append(f"**Analyzed:** {results['analyzed']}\n")
        lines.append(f"**Verdict:** {results['verdict'].upper()} (confidence: {results['confidence']})\n\n")

        # Summary box
        verdict_emoji = {
            'clean': '✅',
            'likely_benign': '✅',
            'suspicious': '⚠️',
            'malicious': '🚨',
            'unknown': '❓',
        }
        lines.append(f"## {verdict_emoji.get(results['verdict'], '❓')} Summary\n\n")
        lines.append(f"| Property | Value |\n")
        lines.append(f"|----------|-------|\n")
        lines.append(f"| File | `{results['filename']}` |\n")
        lines.append(f"| Size | {results['size']:,} bytes |\n")
        lines.append(f"| Type | {results['file_type'][:60]} |\n")
        lines.append(f"| SHA256 | `{results['hashes'].get('sha256', 'N/A')}` |\n")
        lines.append(f"| Verdict | **{results['verdict'].upper()}** |\n")
        lines.append(f"| Suspicious Indicators | {len(results['suspicious_indicators'])} |\n\n")

        # Hashes
        lines.append("## File Hashes\n\n")
        lines.append("```\n")
        for algo, hash_val in results['hashes'].items():
            if algo != 'error':
                lines.append(f"{algo.upper()}: {hash_val}\n")
        lines.append("```\n\n")

        # PE Info
        if results.get('pe_info'):
            lines.append("## PE Information\n\n")
            lines.append("| Property | Value |\n")
            lines.append("|----------|-------|\n")
            for key, value in results['pe_info'].items():
                lines.append(f"| {key} | `{value}` |\n")
            lines.append("\n")

        # Sections
        if results.get('sections'):
            lines.append("## Sections\n\n")
            lines.append("| Name | Raw Size | Entropy | Executable | Writable |\n")
            lines.append("|------|----------|---------|------------|----------|\n")
            for sec in results['sections']:
                entropy = sec.get('entropy', 0)
                raw_size = sec.get('raw_size', 0)
                # Flag both high entropy (packed/encrypted) and SwollenFile (low entropy + large)
                if entropy > 7.0:
                    entropy_flag = " ⚠️ HIGH"
                elif raw_size > 1_000_000 and entropy < 1.0:
                    entropy_flag = " ⚠️ SWOLLEN"
                else:
                    entropy_flag = ""
                rwx_flag = " 🚨" if sec.get('executable') and sec.get('writable') else ""
                lines.append(f"| {sec['name']} | {raw_size:,} | "
                           f"{entropy}{entropy_flag} | "
                           f"{sec.get('executable', False)}{rwx_flag} | "
                           f"{sec.get('writable', False)} |\n")
            lines.append("\n")

        # Entropy Analysis
        if results.get('entropy_analysis', {}).get('high_entropy_sections'):
            lines.append("## ⚠️ High Entropy Sections\n\n")
            for sec in results['entropy_analysis']['high_entropy_sections']:
                lines.append(f"- **{sec['name']}**: entropy {sec['entropy']} "
                           f"(size: {sec['size']:,} bytes)\n")
            lines.append("\n")

        # SwollenFile Analysis (AV evasion via null padding)
        if results.get('entropy_analysis', {}).get('swollen_sections'):
            lines.append("## ⚠️ SwollenFile Sections (AV Evasion)\n\n")
            lines.append("Large sections with very low entropy indicate null-byte padding to evade AV scanners.\n\n")
            for sec in results['entropy_analysis']['swollen_sections']:
                lines.append(f"- **{sec['name']}**: {sec['size']:,} bytes with entropy {sec['entropy']} "
                           f"(expected >4.0 for real data)\n")
            lines.append("\n")

        # Suspicious Indicators
        if results.get('suspicious_indicators'):
            lines.append("## Suspicious Indicators\n\n")
            lines.append("| Severity | Type | Description |\n")
            lines.append("|----------|------|-------------|\n")
            for ind in sorted(results['suspicious_indicators'],
                            key=lambda x: {'high': 0, 'medium': 1, 'low': 2}.get(x['severity'], 3)):
                sev_emoji = {'high': '🔴', 'medium': '🟡', 'low': '🟢'}.get(ind['severity'], '⚪')
                lines.append(f"| {sev_emoji} {ind['severity']} | {ind['type']} | {ind['description']} |\n")
            lines.append("\n")

        # Interesting Strings
        interesting_strings = [s for s in results.get('strings', [])
                              if s.get('category') in ['url', 'ip', 'suspicious', 'crypto']]
        if interesting_strings:
            lines.append("## Interesting Strings\n\n")
            lines.append("| Category | String |\n")
            lines.append("|----------|--------|\n")
            for s in interesting_strings[:30]:
                safe_string = s['string'].replace('|', '\\|').replace('\n', ' ')[:80]
                lines.append(f"| {s['category']} | `{safe_string}` |\n")
            if len(interesting_strings) > 30:
                lines.append(f"\n*... and {len(interesting_strings) - 30} more*\n")
            lines.append("\n")

        # Imports (suspicious only)
        suspicious_imports = [i for i in results.get('imports', [])
                            if any(ind['type'] == 'suspicious_import' and i['function'] in ind['description']
                                  for ind in results.get('suspicious_indicators', []))]
        if suspicious_imports:
            lines.append("## Suspicious Imports\n\n")
            for imp in suspicious_imports:
                lines.append(f"- `{imp['dll']}:{imp['function']}`\n")
            lines.append("\n")

        # Recommendations
        lines.append("## Recommendations\n\n")
        if results['verdict'] == 'malicious':
            lines.append("1. **Do not execute** this file\n")
            lines.append("2. Submit to VirusTotal for additional analysis\n")
            lines.append("3. Extract and analyze any embedded payloads\n")
            lines.append("4. Add file hash to IOC blocklist\n")
        elif results['verdict'] == 'suspicious':
            lines.append("1. Submit to VirusTotal for reputation check\n")
            lines.append("2. Analyze in isolated sandbox environment\n")
            lines.append("3. Compare against known-good version if available\n")
        else:
            lines.append("1. File appears benign based on static analysis\n")
            lines.append("2. Consider VirusTotal check for additional confidence\n")

        # Write report
        with open(output_path, 'w') as f:
            f.writelines(lines)

    def compare_files(self, file1: Path, file2: Path) -> dict:
        """Compare two binary files for differences."""
        file1, file2 = Path(file1), Path(file2)

        result = {
            'file1': str(file1),
            'file2': str(file2),
            'identical': False,
            'size_match': False,
            'hash_match': False,
            'differences': [],
        }

        # Size comparison
        size1 = file1.stat().st_size
        size2 = file2.stat().st_size
        result['size_match'] = size1 == size2
        result['size1'] = size1
        result['size2'] = size2

        # Hash comparison
        hash1 = self._calculate_hashes(file1)['sha256']
        hash2 = self._calculate_hashes(file2)['sha256']
        result['hash_match'] = hash1 == hash2
        result['hash1'] = hash1
        result['hash2'] = hash2

        result['identical'] = result['size_match'] and result['hash_match']

        if not result['identical']:
            # Find differences using radiff2
            try:
                diff_result = subprocess.run(
                    ['radiff2', '-s', str(file1), str(file2)],
                    capture_output=True, text=True, timeout=30
                )
                result['diff_output'] = diff_result.stdout[:2000]
            except Exception as e:
                result['diff_error'] = str(e)

        return result


# =============================================================================
# CLI FUNCTIONS
# =============================================================================
def analyze_file(file_path: str, output_dir: str = None):
    """Analyze a single binary file."""
    analyzer = BinaryAnalyzer(Path(output_dir) if output_dir else None)
    return analyzer.analyze_file(Path(file_path))


def compare_files(file1: str, file2: str):
    """Compare two binary files."""
    analyzer = BinaryAnalyzer()
    return analyzer.compare_files(Path(file1), Path(file2))


def main():
    """CLI entry point for binary analysis."""
    import argparse

    parser = argparse.ArgumentParser(description='Binary/malware analysis tool')
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze a binary file')
    analyze_parser.add_argument('file', help='Path to file to analyze')
    analyze_parser.add_argument('-o', '--output', help='Output directory')
    analyze_parser.add_argument('-n', '--name', help='Output file name prefix')

    # Compare command
    compare_parser = subparsers.add_parser('compare', help='Compare two binary files')
    compare_parser.add_argument('file1', help='First file')
    compare_parser.add_argument('file2', help='Second file')

    args = parser.parse_args()

    if args.command == 'analyze':
        analyzer = BinaryAnalyzer(Path(args.output) if args.output else None)
        results = analyzer.analyze_file(Path(args.file), args.name)
        print(f"\nVerdict: {results['verdict'].upper()} (confidence: {results['confidence']})")
        print(f"Suspicious indicators: {len(results['suspicious_indicators'])}")

    elif args.command == 'compare':
        analyzer = BinaryAnalyzer()
        results = analyzer.compare_files(Path(args.file1), Path(args.file2))
        if results['identical']:
            print("Files are IDENTICAL")
        else:
            print("Files DIFFER")
            print(f"  Size: {results['size1']} vs {results['size2']}")
            print(f"  Hash match: {results['hash_match']}")

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
