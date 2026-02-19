"""
Disk forensics analysis module.

Analyzes disk artifacts from Plaso timelines, domain controller logs,
and triage images (VHDX files).
"""

import csv
import json
import os
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import pandas as pd

from .base import (
    ARTIFACTS_PATH, REPO_DIR, ForensicAnalyzer, InvestigationCriteria,
    run_command, format_bytes
)


# Suspicious patterns for heuristic detection
SUSPICIOUS_PATHS = [
    r'\\temp\\', r'\\tmp\\', r'\\downloads\\',
    r'\\appdata\\local\\temp', r'\\public\\',
    r'\\users\\.*\\desktop\\', r'\\programdata\\',
]

SUSPICIOUS_EXES = [
    'vncviewer', 'whoami', 'net.exe', 'net1.exe', 'ipconfig',
    'nslookup', 'systeminfo', 'tasklist', 'qwinsta',
    'psexec', 'mimikatz', 'procdump', 'rundll32', 'mshta',
    'certutil', 'bitsadmin', 'wmic', 'powershell',
]

PERSISTENCE_KEYS = [
    r'Software\\Microsoft\\Windows\\CurrentVersion\\Run',
    r'Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
    r'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders',
    r'CurrentVersion\\Services',
    r'ControlSet.*\\Services',
]

# Interesting Event IDs for DC logs
INTERESTING_EVENT_IDS = {
    4624: 'Logon',
    4625: 'Failed logon',
    4634: 'Logoff',
    4648: 'Explicit credential logon',
    4672: 'Special privileges assigned',
    4720: 'User account created',
    4722: 'User account enabled',
    4724: 'Password reset attempt',
    4728: 'Member added to global group',
    4732: 'Member added to local group',
    4738: 'User account changed',
    4768: 'Kerberos TGT requested',
    4769: 'Kerberos service ticket requested',
    4771: 'Kerberos pre-auth failed',
    4776: 'NTLM authentication',
}


# =============================================================================
# DISK ANALYZER CLASS
# =============================================================================
class DiskAnalyzer(ForensicAnalyzer):
    """Disk forensics analyzer for triage images and timelines."""

    def __init__(self, tier: int = 1):
        super().__init__(tier, 'disk')
        self._criteria = InvestigationCriteria()
        # Get timeframe from investigation.yaml (optional)
        self.attack_start, self.attack_end = self.criteria.get_timeframe()
        # If no timeframe configured, analyze all data
        if not self.attack_start:
            print("  Note: No timeframe configured - analyzing all data")

    def get_artifact_files(self) -> dict:
        """Return flat dict of artifact file paths for status display."""
        nested = self._criteria.get_artifact_paths(self.tier, 'disk')
        flat = {}
        for name, files in nested.items():
            if isinstance(files, dict):
                for file_type, path in files.items():
                    flat[f'{name}-{file_type}'] = path
            else:
                flat[name] = files
        return flat

    def get_artifacts_by_host(self) -> dict:
        """Return nested artifact dict by host for extraction methods."""
        return self._criteria.get_artifact_paths(self.tier, 'disk')

    def get_extraction_steps(self) -> list:
        steps = []
        # Level 1 only: Plaso and DC log extractions
        if self.tier == 1:
            steps = [
                ('plaso', 'Parse Plaso timeline CSV'),
                ('dclog', 'Parse domain controller logs'),
                ('prefetch', 'Extract prefetch execution data from Plaso'),
                ('registry', 'Extract registry artifacts from Plaso'),
                ('browser', 'Extract browser history from Plaso'),
                ('events', 'Extract Windows events from Plaso'),
                ('timeline', 'Build consolidated timeline'),
            ]
        # Level 2+: EWS-VM triage extractions only
        if self.tier >= 2:
            steps = [
                ('ews_prefetch', 'Extract EWS-VM prefetch/execution data'),
                ('ews_registry', 'Extract EWS-VM registry artifacts'),
                ('ews_lnk', 'Extract EWS-VM LNK/shortcut files'),
                ('ews_amcache', 'Extract EWS-VM Amcache data'),
                ('ews_shellbags', 'Extract EWS-VM shellbags'),
            ]
        return steps

    def get_analysis_steps(self) -> list:
        steps = []
        # Level 1 only: Plaso-based analyses
        if self.tier == 1:
            steps = [
                ('timeline_analysis', 'Attack timeline reconstruction'),
                ('execution_analysis', 'Program execution analysis'),
                ('persistence_analysis', 'Registry persistence analysis'),
                ('user_analysis', 'User account and logon analysis'),
                ('file_analysis', 'File system anomaly analysis'),
                ('ioc_analysis', 'IOC matching and suggestions'),
            ]
        # Level 2+: EWS-VM specific analyses only
        if self.tier >= 2:
            steps = [
                ('ews_overview', 'EWS-VM triage overview'),
                ('ews_execution', 'EWS-VM program execution analysis'),
                ('ews_user_activity', 'EWS-VM user activity analysis'),
                ('ews_ioc_correlation', 'Correlate Level 1 IOCs with EWS-VM'),
            ]
        return steps

    def get_analysis_file_map(self) -> dict:
        """Custom file mapping for disk analysis."""
        return {
            'timeline_analysis': 'timeline-analysis.md',
            'execution_analysis': 'execution-analysis.md',
            'persistence_analysis': 'persistence-analysis.md',
            'user_analysis': 'user-analysis.md',
            'file_analysis': 'file-analysis.md',
            'ioc_analysis': 'ioc-analysis.md',
        }

    def _parse_plaso_datetime(self, date_str, time_str):
        """Parse Plaso date/time format to datetime."""
        try:
            dt_str = f"{date_str} {time_str}"
            # Format: MM/DD/YYYY HH:MM:SS
            return datetime.strptime(dt_str, "%m/%d/%Y %H:%M:%S")
        except (ValueError, TypeError):
            return None

    def _parse_dclog_datetime(self, time_str):
        """Parse DC log timestamp to datetime."""
        try:
            # Format: 2020-08-15 20:00:04.8122362
            return datetime.strptime(time_str[:19], "%Y-%m-%d %H:%M:%S")
        except (ValueError, TypeError):
            return None

    def _is_in_attack_window(self, dt):
        """Check if datetime is within attack timeframe."""
        if dt is None:
            return False
        return self.attack_start <= dt <= self.attack_end

    # =========================================================================
    # EXTRACTION FUNCTIONS
    # =========================================================================
    def extract_plaso(self):
        """Parse and filter Plaso timeline CSV."""
        evidence = self.get_artifacts_by_host()

        for name, files in evidence.items():
            if 'plaso' not in files:
                continue

            plaso_file = files['plaso']
            if not plaso_file.exists():
                print(f"  WARNING: Plaso file not found: {plaso_file}")
                continue

            output = self.extractions_dir / f'{name}-plaso.csv'
            print(f"  Parsing {plaso_file.name}...")

            # Read with pandas for efficiency
            try:
                df = pd.read_csv(plaso_file, low_memory=False)
                print(f"  Loaded {len(df):,} rows")

                # Convert date/time to datetime
                df['datetime'] = pd.to_datetime(
                    df['date'] + ' ' + df['time'],
                    format='%m/%d/%Y %H:%M:%S',
                    errors='coerce'
                )

                # Filter to attack window if configured
                if self.attack_start and self.attack_end:
                    mask = (df['datetime'] >= self.attack_start) & (df['datetime'] <= self.attack_end)
                    filtered = df[mask].copy()
                    print(f"  Timeframe filter: {len(filtered):,} rows ({self.attack_start.date()} to {self.attack_end.date()})")
                else:
                    filtered = df.copy()
                    print(f"  No timeframe filter: {len(filtered):,} rows (all data)")

                # Save filtered data
                filtered.to_csv(output, index=False)
                print(f"  Written: {output}")

            except Exception as e:
                print(f"  ERROR parsing Plaso: {e}")
                continue

        self.mark_complete('extractions', 'plaso')
        return True

    def extract_dclog(self):
        """Parse domain controller logs."""
        evidence = self.get_artifacts_by_host()

        for name, files in evidence.items():
            if 'dclog' not in files:
                continue

            dclog_file = files['dclog']
            if not dclog_file.exists():
                print(f"  WARNING: DC log file not found: {dclog_file}")
                continue

            output = self.extractions_dir / f'{name}-dclog.csv'
            print(f"  Parsing {dclog_file.name}...")

            try:
                df = pd.read_csv(dclog_file, low_memory=False)
                print(f"  Loaded {len(df):,} rows")

                # Parse timestamp
                df['datetime'] = pd.to_datetime(
                    df['TimeCreated'].str[:19],
                    format='%Y-%m-%d %H:%M:%S',
                    errors='coerce'
                )

                # Filter to attack window if configured
                if self.attack_start and self.attack_end:
                    mask = (df['datetime'] >= self.attack_start) & (df['datetime'] <= self.attack_end)
                    filtered = df[mask].copy()
                    print(f"  Timeframe filter: {len(filtered):,} rows")
                else:
                    filtered = df.copy()
                    print(f"  No timeframe filter: {len(filtered):,} rows (all data)")

                # Save filtered data
                filtered.to_csv(output, index=False)
                print(f"  Written: {output}")

            except Exception as e:
                print(f"  ERROR parsing DC logs: {e}")
                continue

        self.mark_complete('extractions', 'dclog')
        return True

    def extract_prefetch(self):
        """Extract prefetch execution data from Plaso timeline."""
        plaso_file = self.extractions_dir / 'stsupport10-plaso.csv'
        if not plaso_file.exists():
            print("  ERROR: Run 'extract plaso' first")
            return False

        output = self.extractions_dir / 'stsupport10-prefetch.csv'
        print(f"  Extracting prefetch from {plaso_file.name}...")

        try:
            df = pd.read_csv(plaso_file, low_memory=False)

            # Filter for PE sources (includes prefetch) and prefetch mentions
            mask = (
                (df['source'] == 'PE') |
                (df['sourcetype'].str.contains('Prefetch', case=False, na=False)) |
                (df['desc'].str.contains('prefetch', case=False, na=False))
            )
            prefetch = df[mask].copy()
            print(f"  Found {len(prefetch):,} prefetch-related entries")

            prefetch.to_csv(output, index=False)
            print(f"  Written: {output}")

        except Exception as e:
            print(f"  ERROR: {e}")
            return False

        self.mark_complete('extractions', 'prefetch')
        return True

    def extract_registry(self):
        """Extract registry artifacts from Plaso timeline."""
        plaso_file = self.extractions_dir / 'stsupport10-plaso.csv'
        if not plaso_file.exists():
            print("  ERROR: Run 'extract plaso' first")
            return False

        output = self.extractions_dir / 'stsupport10-registry.csv'
        print(f"  Extracting registry from {plaso_file.name}...")

        try:
            df = pd.read_csv(plaso_file, low_memory=False)

            # Filter for REG source
            mask = df['source'] == 'REG'
            registry = df[mask].copy()
            print(f"  Found {len(registry):,} registry entries")

            registry.to_csv(output, index=False)
            print(f"  Written: {output}")

        except Exception as e:
            print(f"  ERROR: {e}")
            return False

        self.mark_complete('extractions', 'registry')
        return True

    def extract_browser(self):
        """Extract browser history from Plaso timeline."""
        plaso_file = self.extractions_dir / 'stsupport10-plaso.csv'
        if not plaso_file.exists():
            print("  ERROR: Run 'extract plaso' first")
            return False

        output = self.extractions_dir / 'stsupport10-browser.csv'
        print(f"  Extracting browser history from {plaso_file.name}...")

        try:
            df = pd.read_csv(plaso_file, low_memory=False)

            # Filter for WEBHIST source
            mask = df['source'] == 'WEBHIST'
            browser = df[mask].copy()
            print(f"  Found {len(browser):,} browser history entries")

            browser.to_csv(output, index=False)
            print(f"  Written: {output}")

        except Exception as e:
            print(f"  ERROR: {e}")
            return False

        self.mark_complete('extractions', 'browser')
        return True

    def extract_events(self):
        """Extract Windows events from Plaso timeline."""
        plaso_file = self.extractions_dir / 'stsupport10-plaso.csv'
        if not plaso_file.exists():
            print("  ERROR: Run 'extract plaso' first")
            return False

        output = self.extractions_dir / 'stsupport10-events.csv'
        print(f"  Extracting Windows events from {plaso_file.name}...")

        try:
            df = pd.read_csv(plaso_file, low_memory=False)

            # Filter for EVT source
            mask = df['source'] == 'EVT'
            events = df[mask].copy()
            print(f"  Found {len(events):,} Windows event entries")

            events.to_csv(output, index=False)
            print(f"  Written: {output}")

        except Exception as e:
            print(f"  ERROR: {e}")
            return False

        self.mark_complete('extractions', 'events')
        return True

    def extract_timeline(self):
        """Build consolidated timeline from all sources."""
        output = self.extractions_dir / 'consolidated-timeline.csv'
        print("  Building consolidated timeline...")

        timeline_rows = []

        # Load existing extracted disk CSVs if available
        spader_disk = REPO_DIR / 'work' / 'level1' / 'data' / 'spader-disk.csv'
        stark_disk = REPO_DIR / 'work' / 'level1' / 'data' / 'stark-disk.csv'

        for csv_file, source in [(spader_disk, 'spader-disk'), (stark_disk, 'stark-disk')]:
            if csv_file.exists():
                try:
                    df = pd.read_csv(csv_file)
                    df['evidence_source'] = source
                    timeline_rows.append(df)
                    print(f"  Loaded {len(df)} rows from {source}")
                except Exception as e:
                    print(f"  WARNING: Could not load {csv_file}: {e}")

        # Load key events from DC logs
        dclog_file = self.extractions_dir / 'base-rd-02-dclog.csv'
        if dclog_file.exists():
            try:
                df = pd.read_csv(dclog_file, low_memory=False)
                # Extract interesting events
                df['EventId'] = pd.to_numeric(df['EventId'], errors='coerce')
                interesting = df[df['EventId'].isin(INTERESTING_EVENT_IDS.keys())].copy()

                if len(interesting) > 0:
                    # Convert to timeline format
                    timeline_df = pd.DataFrame({
                        'datetime_utc': interesting['datetime'],
                        'category': 'DC Log',
                        'severity': 'info',
                        'artifact': interesting['EventId'].map(INTERESTING_EVENT_IDS),
                        'description': interesting['MapDescription'],
                        'evidence_source': 'srl-domain-controller-logs'
                    })
                    timeline_rows.append(timeline_df)
                    print(f"  Loaded {len(timeline_df)} interesting DC log events")

            except Exception as e:
                print(f"  WARNING: Could not load DC logs: {e}")

        # Combine all
        if timeline_rows:
            combined = pd.concat(timeline_rows, ignore_index=True)
            # Sort by datetime
            if 'datetime_utc' in combined.columns:
                combined = combined.sort_values('datetime_utc')
            combined.to_csv(output, index=False)
            print(f"  Written consolidated timeline: {len(combined)} rows to {output}")
        else:
            print("  WARNING: No timeline data to consolidate")

        self.mark_complete('extractions', 'timeline')
        return True

    # =========================================================================
    # LEVEL 2: EWS-VM EXTRACTION FUNCTIONS
    # =========================================================================
    def extract_ews_prefetch(self):
        """Extract EWS-VM prefetch/execution data."""
        evidence = self.get_artifacts_by_host()
        ews = evidence.get('ews-vm', {})
        prog_exec_dir = ews.get('program_execution')

        if not prog_exec_dir or not prog_exec_dir.exists():
            print(f"  ERROR: EWS-VM ProgramExecution not found: {prog_exec_dir}")
            return False

        output = self.extractions_dir / 'ews-vm-prefetch.csv'
        print(f"  Extracting prefetch from {prog_exec_dir}...")

        # Look for PECmd output files
        prefetch_files = list(prog_exec_dir.glob('*PECmd*.csv'))
        if not prefetch_files:
            print("  WARNING: No PECmd output files found")
            self.mark_complete('extractions', 'ews_prefetch')
            return True

        all_rows = []
        for pf in prefetch_files:
            try:
                df = pd.read_csv(pf, low_memory=False)
                df['source_file'] = pf.name
                all_rows.append(df)
                print(f"  Loaded {len(df)} rows from {pf.name}")
            except Exception as e:
                print(f"  WARNING: Could not read {pf.name}: {e}")

        if all_rows:
            combined = pd.concat(all_rows, ignore_index=True)
            combined.to_csv(output, index=False)
            print(f"  Written: {output} ({len(combined)} rows)")

        self.mark_complete('extractions', 'ews_prefetch')
        return True

    def extract_ews_registry(self):
        """Extract EWS-VM registry artifacts."""
        evidence = self.get_artifacts_by_host()
        ews = evidence.get('ews-vm', {})
        registry_dir = ews.get('registry')

        if not registry_dir or not registry_dir.exists():
            print(f"  ERROR: EWS-VM Registry not found: {registry_dir}")
            return False

        output = self.extractions_dir / 'ews-vm-registry.csv'
        print(f"  Extracting registry from {registry_dir}...")

        # Look for registry CSV exports
        reg_files = list(registry_dir.glob('*.csv'))
        if not reg_files:
            print("  WARNING: No registry CSV files found")
            self.mark_complete('extractions', 'ews_registry')
            return True

        all_rows = []
        for rf in reg_files:
            try:
                df = pd.read_csv(rf, low_memory=False)
                df['source_file'] = rf.name
                all_rows.append(df)
                print(f"  Loaded {len(df)} rows from {rf.name}")
            except Exception as e:
                print(f"  WARNING: Could not read {rf.name}: {e}")

        if all_rows:
            combined = pd.concat(all_rows, ignore_index=True)
            combined.to_csv(output, index=False)
            print(f"  Written: {output} ({len(combined)} rows)")

        self.mark_complete('extractions', 'ews_registry')
        return True

    def extract_ews_lnk(self):
        """Extract EWS-VM LNK/shortcut files."""
        evidence = self.get_artifacts_by_host()
        ews = evidence.get('ews-vm', {})
        ffa_dir = ews.get('file_folder_access')

        if not ffa_dir or not ffa_dir.exists():
            print(f"  ERROR: EWS-VM FileFolderAccess not found: {ffa_dir}")
            return False

        output = self.extractions_dir / 'ews-vm-lnk.csv'
        print(f"  Extracting LNK files from {ffa_dir}...")

        # Look for LECmd output
        lnk_files = list(ffa_dir.glob('*LECmd*.csv'))
        if not lnk_files:
            print("  WARNING: No LECmd output files found")
            self.mark_complete('extractions', 'ews_lnk')
            return True

        all_rows = []
        for lf in lnk_files:
            try:
                df = pd.read_csv(lf, low_memory=False)
                df['source_file'] = lf.name
                all_rows.append(df)
                print(f"  Loaded {len(df)} rows from {lf.name}")
            except Exception as e:
                print(f"  WARNING: Could not read {lf.name}: {e}")

        if all_rows:
            combined = pd.concat(all_rows, ignore_index=True)
            combined.to_csv(output, index=False)
            print(f"  Written: {output} ({len(combined)} rows)")

        self.mark_complete('extractions', 'ews_lnk')
        return True

    def extract_ews_amcache(self):
        """Extract EWS-VM Amcache data."""
        evidence = self.get_artifacts_by_host()
        ews = evidence.get('ews-vm', {})
        prog_exec_dir = ews.get('program_execution')

        if not prog_exec_dir or not prog_exec_dir.exists():
            print(f"  ERROR: EWS-VM ProgramExecution not found: {prog_exec_dir}")
            return False

        output = self.extractions_dir / 'ews-vm-amcache.csv'
        print(f"  Extracting Amcache from {prog_exec_dir}...")

        # Look for Amcache output
        amcache_files = list(prog_exec_dir.glob('*Amcache*.csv'))
        if not amcache_files:
            print("  WARNING: No Amcache output files found")
            self.mark_complete('extractions', 'ews_amcache')
            return True

        all_rows = []
        for af in amcache_files:
            try:
                df = pd.read_csv(af, low_memory=False)
                df['source_file'] = af.name
                all_rows.append(df)
                print(f"  Loaded {len(df)} rows from {af.name}")
            except Exception as e:
                print(f"  WARNING: Could not read {af.name}: {e}")

        if all_rows:
            combined = pd.concat(all_rows, ignore_index=True)
            combined.to_csv(output, index=False)
            print(f"  Written: {output} ({len(combined)} rows)")

        self.mark_complete('extractions', 'ews_amcache')
        return True

    def extract_ews_shellbags(self):
        """Extract EWS-VM shellbags."""
        evidence = self.get_artifacts_by_host()
        ews = evidence.get('ews-vm', {})
        ffa_dir = ews.get('file_folder_access')

        if not ffa_dir or not ffa_dir.exists():
            print(f"  ERROR: EWS-VM FileFolderAccess not found: {ffa_dir}")
            return False

        output = self.extractions_dir / 'ews-vm-shellbags.csv'
        print(f"  Extracting shellbags from {ffa_dir}...")

        # Look for SBECmd or shellbag output
        shellbag_files = list(ffa_dir.glob('*SBE*.csv')) + list(ffa_dir.glob('*shellbag*.csv'))
        # Also check for NTUSER.DAT and UsrClass.dat CSV exports
        shellbag_files += [f for f in ffa_dir.glob('*.csv') if 'NTUSER' in f.name or 'UsrClass' in f.name]

        if not shellbag_files:
            print("  WARNING: No shellbag-related files found")
            self.mark_complete('extractions', 'ews_shellbags')
            return True

        all_rows = []
        for sf in shellbag_files:
            try:
                df = pd.read_csv(sf, low_memory=False)
                df['source_file'] = sf.name
                all_rows.append(df)
                print(f"  Loaded {len(df)} rows from {sf.name}")
            except Exception as e:
                print(f"  WARNING: Could not read {sf.name}: {e}")

        if all_rows:
            combined = pd.concat(all_rows, ignore_index=True)
            combined.to_csv(output, index=False)
            print(f"  Written: {output} ({len(combined)} rows)")

        self.mark_complete('extractions', 'ews_shellbags')
        return True

    # =========================================================================
    # ANALYSIS FUNCTIONS
    # =========================================================================
    def analyze_timeline_analysis(self):
        """Analyze attack timeline reconstruction."""
        results = ["# Disk Timeline Analysis\n"]
        results.append(f"Generated: {datetime.now().isoformat()}\n\n")
        if self.attack_start and self.attack_end:
            results.append(f"Timeframe: {self.attack_start.date()} to {self.attack_end.date()}\n\n")

        # Load consolidated timeline
        timeline_file = self.extractions_dir / 'consolidated-timeline.csv'
        if timeline_file.exists():
            try:
                df = pd.read_csv(timeline_file)
                results.append(f"Total timeline events: {len(df):,}\n\n")

                # Group by category
                if 'category' in df.columns:
                    results.append("## Events by Category\n\n")
                    category_counts = df['category'].value_counts()
                    results.append("| Category | Count |\n")
                    results.append("|----------|-------|\n")
                    for cat, count in category_counts.items():
                        results.append(f"| {cat} | {count:,} |\n")
                    results.append("\n")

                # Show malicious/notable events
                if 'severity' in df.columns:
                    results.append("## Events by Severity\n\n")
                    sev_counts = df['severity'].value_counts()
                    results.append("| Severity | Count |\n")
                    results.append("|----------|-------|\n")
                    for sev, count in sev_counts.items():
                        results.append(f"| {sev} | {count:,} |\n")
                    results.append("\n")

                    # Detail malicious events
                    malicious = df[df['severity'].isin(['malicious', 'critical'])]
                    if len(malicious) > 0:
                        results.append("## Malicious/Critical Events\n\n")
                        results.append("| Timestamp | Category | Artifact | Description |\n")
                        results.append("|-----------|----------|----------|-------------|\n")
                        for _, row in malicious.iterrows():
                            desc = str(row.get('description', ''))[:300]
                            results.append(f"| {row.get('datetime_utc', '')} | {row.get('category', '')} | {row.get('artifact', '')} | {desc} |\n")
                        results.append("\n")

            except Exception as e:
                results.append(f"ERROR loading timeline: {e}\n")
        else:
            results.append("*No consolidated timeline found. Run 'extract timeline' first.*\n")

        output = self.analysis_dir / 'timeline-analysis.md'
        with open(output, 'w') as f:
            f.writelines(results)
        print(f"  Written: {output}")
        self.mark_complete('analyses', 'timeline_analysis')
        return True

    def analyze_execution_analysis(self):
        """Analyze program execution artifacts (prefetch, amcache)."""
        results = ["# Program Execution Analysis\n"]
        results.append(f"Generated: {datetime.now().isoformat()}\n\n")

        # Load prefetch data
        prefetch_file = self.extractions_dir / 'stsupport10-prefetch.csv'
        if prefetch_file.exists():
            try:
                df = pd.read_csv(prefetch_file, low_memory=False)
                results.append(f"## Prefetch/PE Entries ({len(df):,} total)\n\n")

                # Look for suspicious executables
                results.append("### Suspicious Executables\n\n")
                suspicious_found = []
                for _, row in df.iterrows():
                    desc = str(row.get('desc', '')).lower()
                    short = str(row.get('short', '')).lower()
                    for exe in SUSPICIOUS_EXES:
                        if exe in desc or exe in short:
                            suspicious_found.append({
                                'datetime': row.get('datetime', row.get('date', '')),
                                'exe': exe,
                                'description': str(row.get('short', ''))[:300],
                            })
                            # Suggest adding to investigation criteria
                            if not self.criteria.matches_process(exe):
                                self.add_suggestion({
                                    'category': 'processes',
                                    'value': exe,
                                    'note': f"Suspicious executable found in prefetch",
                                    'source': "disk prefetch analysis",
                                    'added': datetime.now().strftime('%Y-%m-%d'),
                                })
                            break

                if suspicious_found:
                    results.append("| Timestamp | Executable | Description |\n")
                    results.append("|-----------|------------|-------------|\n")
                    for item in suspicious_found[:50]:
                        results.append(f"| {item['datetime']} | {item['exe']} | {item['description']} |\n")
                else:
                    results.append("*No suspicious executables detected in prefetch.*\n")
                results.append("\n")

                # Look for suspicious paths
                results.append("### Execution from Suspicious Paths\n\n")
                path_matches = []
                for _, row in df.iterrows():
                    desc = str(row.get('desc', '')).lower()
                    filename = str(row.get('filename', '')).lower()
                    for path_pattern in SUSPICIOUS_PATHS:
                        if re.search(path_pattern, desc, re.IGNORECASE) or \
                           re.search(path_pattern, filename, re.IGNORECASE):
                            path_matches.append({
                                'datetime': row.get('datetime', row.get('date', '')),
                                'path': path_pattern,
                                'description': str(row.get('short', ''))[:300],
                            })
                            break

                if path_matches:
                    results.append("| Timestamp | Pattern | Description |\n")
                    results.append("|-----------|---------|-------------|\n")
                    for item in path_matches[:30]:
                        results.append(f"| {item['datetime']} | `{item['path']}` | {item['description']} |\n")
                else:
                    results.append("*No execution from suspicious paths detected.*\n")
                results.append("\n")

                # Investigation criteria matches
                results.append("### Matches to Investigation Criteria\n\n")
                matched = []
                for _, row in df.iterrows():
                    desc = str(row.get('desc', '')).lower()
                    short = str(row.get('short', '')).lower()
                    for proc in self.criteria.get_processes():
                        if proc.lower() in desc or proc.lower() in short:
                            note = self.criteria.get_note('processes', proc)
                            matched.append({
                                'datetime': row.get('datetime', row.get('date', '')),
                                'process': proc,
                                'note': note,
                                'description': str(row.get('short', ''))[:300],
                            })
                            break

                if matched:
                    results.append("| Timestamp | Process | Note | Description |\n")
                    results.append("|-----------|---------|------|-------------|\n")
                    for item in matched[:30]:
                        results.append(f"| {item['datetime']} | {item['process']} | {item['note']} | {item['description']} |\n")
                else:
                    results.append("*No processes matching investigation criteria.*\n")
                results.append("\n")

            except Exception as e:
                results.append(f"ERROR loading prefetch: {e}\n")
        else:
            results.append("*No prefetch data found. Run 'extract prefetch' first.*\n")

        output = self.analysis_dir / 'execution-analysis.md'
        with open(output, 'w') as f:
            f.writelines(results)
        print(f"  Written: {output}")
        self.mark_complete('analyses', 'execution_analysis')
        return True

    def analyze_persistence_analysis(self):
        """Analyze registry persistence mechanisms."""
        results = ["# Persistence Analysis (Registry)\n"]
        results.append(f"Generated: {datetime.now().isoformat()}\n\n")

        # Load registry data
        registry_file = self.extractions_dir / 'stsupport10-registry.csv'
        if registry_file.exists():
            try:
                df = pd.read_csv(registry_file, low_memory=False)
                results.append(f"## Registry Entries ({len(df):,} total in attack window)\n\n")

                # Look for persistence keys
                results.append("### Known Persistence Locations\n\n")
                persistence_found = []
                for _, row in df.iterrows():
                    desc = str(row.get('desc', ''))
                    filename = str(row.get('filename', ''))
                    for key_pattern in PERSISTENCE_KEYS:
                        if re.search(key_pattern, desc, re.IGNORECASE) or \
                           re.search(key_pattern, filename, re.IGNORECASE):
                            persistence_found.append({
                                'datetime': row.get('datetime', row.get('date', '')),
                                'key': key_pattern,
                                'description': str(row.get('desc', ''))[:500],
                            })
                            break

                if persistence_found:
                    results.append("| Timestamp | Key Pattern | Description |\n")
                    results.append("|-----------|-------------|-------------|\n")
                    for item in persistence_found[:50]:
                        results.append(f"| {item['datetime']} | `{item['key']}` | {item['description']} |\n")
                else:
                    results.append("*No persistence key modifications detected.*\n")
                results.append("\n")

                # Services modifications
                results.append("### Service-Related Registry Activity\n\n")
                service_entries = df[
                    df['desc'].str.contains('Services', case=False, na=False) |
                    df['filename'].str.contains('Services', case=False, na=False)
                ]
                if len(service_entries) > 0:
                    results.append(f"Found {len(service_entries)} service-related entries.\n\n")
                    results.append("| Timestamp | Description |\n")
                    results.append("|-----------|-------------|\n")
                    for _, row in service_entries.head(20).iterrows():
                        desc = str(row.get('desc', ''))[:500]
                        results.append(f"| {row.get('datetime', '')} | {desc} |\n")
                else:
                    results.append("*No service registry modifications detected.*\n")
                results.append("\n")

            except Exception as e:
                results.append(f"ERROR loading registry: {e}\n")
        else:
            results.append("*No registry data found. Run 'extract registry' first.*\n")

        output = self.analysis_dir / 'persistence-analysis.md'
        with open(output, 'w') as f:
            f.writelines(results)
        print(f"  Written: {output}")
        self.mark_complete('analyses', 'persistence_analysis')
        return True

    def analyze_user_analysis(self):
        """Analyze user accounts and logon activity."""
        results = ["# User Account Analysis\n"]
        results.append(f"Generated: {datetime.now().isoformat()}\n\n")

        # Load DC logs
        dclog_file = self.extractions_dir / 'base-rd-02-dclog.csv'
        if dclog_file.exists():
            try:
                df = pd.read_csv(dclog_file, low_memory=False)
                df['EventId'] = pd.to_numeric(df['EventId'], errors='coerce')
                results.append(f"## Domain Controller Events ({len(df):,} in attack window)\n\n")

                # Group by event type
                results.append("### Event Type Distribution\n\n")
                event_counts = df['EventId'].value_counts().head(20)
                results.append("| Event ID | Description | Count |\n")
                results.append("|----------|-------------|-------|\n")
                for event_id, count in event_counts.items():
                    desc = INTERESTING_EVENT_IDS.get(int(event_id), 'Other')
                    results.append(f"| {int(event_id)} | {desc} | {count:,} |\n")
                results.append("\n")

                # Account modifications
                results.append("### Account Modifications\n\n")
                account_events = [4720, 4722, 4724, 4728, 4732, 4738]
                account_df = df[df['EventId'].isin(account_events)]
                if len(account_df) > 0:
                    results.append("| Timestamp | Event | Description |\n")
                    results.append("|-----------|-------|-------------|\n")
                    for _, row in account_df.head(30).iterrows():
                        event_id = int(row['EventId'])
                        event_desc = INTERESTING_EVENT_IDS.get(event_id, 'Unknown')
                        map_desc = str(row.get('MapDescription', ''))[:300]
                        results.append(f"| {row.get('datetime', '')} | {event_id} - {event_desc} | {map_desc} |\n")

                        # Check for known accounts
                        payload = str(row.get('PayloadData1', ''))
                        for account in self.criteria.get_accounts():
                            if account.lower() in payload.lower():
                                note = self.criteria.get_note('accounts', account)
                                results.append(f"| | **MATCHED: {account}** | {note} |\n")
                else:
                    results.append("*No account modification events found.*\n")
                results.append("\n")

                # Failed logons
                results.append("### Failed Logon Attempts (4625)\n\n")
                failed = df[df['EventId'] == 4625]
                if len(failed) > 0:
                    results.append(f"Found {len(failed)} failed logon attempts.\n\n")
                    # Group by source if available
                    if 'RemoteHost' in failed.columns:
                        by_host = failed['RemoteHost'].value_counts().head(10)
                        results.append("| Source Host | Count |\n")
                        results.append("|-------------|-------|\n")
                        for host, count in by_host.items():
                            results.append(f"| {host} | {count} |\n")
                else:
                    results.append("*No failed logon attempts found.*\n")
                results.append("\n")

            except Exception as e:
                results.append(f"ERROR loading DC logs: {e}\n")
        else:
            results.append("*No DC log data found. Run 'extract dclog' first.*\n")

        # Add investigation criteria matches
        results.append("## Matched Accounts from Investigation Criteria\n\n")
        accounts = self.criteria.get_accounts()
        if accounts:
            results.append("| Account | Note |\n")
            results.append("|---------|------|\n")
            for account in accounts:
                note = self.criteria.get_note('accounts', account)
                results.append(f"| {account} | {note} |\n")
        else:
            results.append("*No accounts in investigation criteria.*\n")

        output = self.analysis_dir / 'user-analysis.md'
        with open(output, 'w') as f:
            f.writelines(results)
        print(f"  Written: {output}")
        self.mark_complete('analyses', 'user_analysis')
        return True

    def analyze_file_analysis(self):
        """Analyze file system anomalies."""
        results = ["# File System Anomaly Analysis\n"]
        results.append(f"Generated: {datetime.now().isoformat()}\n\n")

        # Load Plaso data
        plaso_file = self.extractions_dir / 'stsupport10-plaso.csv'
        if plaso_file.exists():
            try:
                df = pd.read_csv(plaso_file, low_memory=False)

                # Filter for FILE source
                file_df = df[df['source'] == 'FILE']
                results.append(f"## File System Events ({len(file_df):,} entries)\n\n")

                # Look for suspicious file activity
                results.append("### Files in Suspicious Locations\n\n")
                suspicious_files = []
                for _, row in file_df.iterrows():
                    filename = str(row.get('filename', ''))
                    desc = str(row.get('desc', ''))
                    for path_pattern in SUSPICIOUS_PATHS:
                        if re.search(path_pattern, filename, re.IGNORECASE) or \
                           re.search(path_pattern, desc, re.IGNORECASE):
                            suspicious_files.append({
                                'datetime': row.get('datetime', row.get('date', '')),
                                'pattern': path_pattern,
                                'filename': filename[:300],
                                'type': row.get('type', ''),
                            })
                            break

                if suspicious_files:
                    results.append("| Timestamp | Type | Path Pattern | Filename |\n")
                    results.append("|-----------|------|--------------|----------|\n")
                    for item in suspicious_files[:50]:
                        results.append(f"| {item['datetime']} | {item['type']} | `{item['pattern']}` | {item['filename']} |\n")
                else:
                    results.append("*No files in suspicious locations detected.*\n")
                results.append("\n")

                # Executable files
                results.append("### Executable File Activity\n\n")
                exe_df = file_df[
                    file_df['filename'].str.contains(r'\.(?:exe|dll|bat|cmd|ps1|vbs|js)$', case=False, na=False, regex=True)
                ]
                if len(exe_df) > 0:
                    results.append(f"Found {len(exe_df)} executable-related entries.\n\n")
                    results.append("| Timestamp | Type | Filename |\n")
                    results.append("|-----------|------|----------|\n")
                    for _, row in exe_df.head(30).iterrows():
                        filename = str(row.get('filename', ''))
                        # Extract just filename from path
                        if '\\' in filename:
                            filename = filename.split('\\')[-1]
                        elif '/' in filename:
                            filename = filename.split('/')[-1]
                        results.append(f"| {row.get('datetime', '')} | {row.get('type', '')} | {filename[:200]} |\n")
                else:
                    results.append("*No executable file activity detected.*\n")
                results.append("\n")

            except Exception as e:
                results.append(f"ERROR loading Plaso: {e}\n")
        else:
            results.append("*No Plaso data found. Run 'extract plaso' first.*\n")

        output = self.analysis_dir / 'file-analysis.md'
        with open(output, 'w') as f:
            f.writelines(results)
        print(f"  Written: {output}")
        self.mark_complete('analyses', 'file_analysis')
        return True

    def analyze_ioc_analysis(self):
        """Match IOCs and generate suggestions for investigation.yaml."""
        results = ["# IOC Analysis and Suggestions\n"]
        results.append(f"Generated: {datetime.now().isoformat()}\n\n")

        # Summary of current investigation criteria
        results.append("## Current Investigation Criteria\n\n")

        results.append("### IPs\n")
        for ip in self.criteria.get_ips():
            note = self.criteria.get_note('ips', ip)
            results.append(f"- `{ip}`: {note}\n")
        results.append("\n")

        results.append("### Domains\n")
        for domain in self.criteria.get_domains():
            note = self.criteria.get_note('domains', domain)
            results.append(f"- `{domain}`: {note}\n")
        results.append("\n")

        results.append("### Processes\n")
        for proc in self.criteria.get_processes():
            note = self.criteria.get_note('processes', proc)
            results.append(f"- `{proc}`: {note}\n")
        results.append("\n")

        results.append("### Accounts\n")
        for account in self.criteria.get_accounts():
            note = self.criteria.get_note('accounts', account)
            results.append(f"- `{account}`: {note}\n")
        results.append("\n")

        # Search for IOCs in browser history
        results.append("## Browser History IOC Matches\n\n")
        browser_file = self.extractions_dir / 'stsupport10-browser.csv'
        if browser_file.exists():
            try:
                df = pd.read_csv(browser_file, low_memory=False)
                matched_domains = []

                for _, row in df.iterrows():
                    desc = str(row.get('desc', ''))
                    for domain in self.criteria.get_domains():
                        if domain.lower() in desc.lower():
                            matched_domains.append({
                                'datetime': row.get('datetime', ''),
                                'domain': domain,
                                'url': desc[:300],
                            })
                            break

                if matched_domains:
                    results.append("| Timestamp | Domain | URL |\n")
                    results.append("|-----------|--------|-----|\n")
                    for item in matched_domains[:30]:
                        results.append(f"| {item['datetime']} | {item['domain']} | {item['url']} |\n")
                else:
                    results.append("*No domain IOCs found in browser history.*\n")

            except Exception as e:
                results.append(f"ERROR: {e}\n")
        else:
            results.append("*No browser history data.*\n")
        results.append("\n")

        # New domain suggestions from browser history
        results.append("## Suggested New Domains\n\n")
        if browser_file.exists():
            try:
                df = pd.read_csv(browser_file, low_memory=False)
                # Extract domains from URLs
                domain_pattern = r'https?://([^/]+)'
                domains_seen = defaultdict(int)

                for _, row in df.iterrows():
                    desc = str(row.get('desc', ''))
                    matches = re.findall(domain_pattern, desc)
                    for domain in matches:
                        # Filter out common/benign domains
                        if not any(safe in domain.lower() for safe in [
                            'google', 'microsoft', 'windows', 'bing', 'office',
                            'live.com', 'msn.com', 'mozilla', 'adobe', 'localhost'
                        ]):
                            domains_seen[domain] += 1

                # Suggest uncommon domains (exclude already tracked and excluded)
                suspicious_domains = [(d, c) for d, c in domains_seen.items()
                                     if not self.criteria.matches_domain(d)
                                     and not self.criteria.is_excluded_domain(d)]

                if suspicious_domains:
                    results.append("| Domain | Visits | Status |\n")
                    results.append("|--------|--------|--------|\n")
                    for domain, count in sorted(suspicious_domains, key=lambda x: -x[1])[:20]:
                        results.append(f"| {domain} | {count} | *Review* |\n")
                        # Add suggestion
                        self.add_suggestion(self.criteria.suggest_domain(
                            domain,
                            f"Found in browser history ({count} visits)",
                            "disk browser analysis"
                        ))
                else:
                    results.append("*No new domains to suggest.*\n")

            except Exception as e:
                results.append(f"ERROR: {e}\n")
        results.append("\n")

        output = self.analysis_dir / 'ioc-analysis.md'
        with open(output, 'w') as f:
            f.writelines(results)
        print(f"  Written: {output}")
        self.mark_complete('analyses', 'ioc_analysis')
        return True

    # =========================================================================
    # LEVEL 2: EWS-VM ANALYSIS FUNCTIONS
    # =========================================================================
    def analyze_ews_overview(self):
        """Generate EWS-VM triage overview."""
        results = ["# EWS-VM (Engineering Workstation) Triage Overview\n"]
        results.append(f"Generated: {datetime.now().isoformat()}\n\n")

        evidence = self.get_artifacts_by_host()
        ews = evidence.get('ews-vm', {})
        triage_dir = ews.get('triage_dir')

        if not triage_dir or not triage_dir.exists():
            results.append("*EWS-VM triage data not found*\n")
        else:
            results.append(f"Triage directory: `{triage_dir}`\n\n")

            # List available data
            results.append("## Available Data\n\n")
            for subdir in sorted(triage_dir.iterdir()):
                if subdir.is_dir():
                    file_count = len(list(subdir.glob('*')))
                    results.append(f"- **{subdir.name}/**: {file_count} files\n")
                elif subdir.is_file():
                    size = subdir.stat().st_size
                    results.append(f"- **{subdir.name}**: {format_bytes(size)}\n")

        # Extraction status
        results.append("\n## Extraction Status\n\n")
        extractions = [
            ('ews_prefetch', self.extractions_dir / 'ews-vm-prefetch.csv'),
            ('ews_registry', self.extractions_dir / 'ews-vm-registry.csv'),
            ('ews_lnk', self.extractions_dir / 'ews-vm-lnk.csv'),
            ('ews_amcache', self.extractions_dir / 'ews-vm-amcache.csv'),
            ('ews_shellbags', self.extractions_dir / 'ews-vm-shellbags.csv'),
        ]

        results.append("| Extraction | File | Rows |\n")
        results.append("|------------|------|-----:|\n")
        for name, path in extractions:
            if path.exists():
                try:
                    df = pd.read_csv(path, low_memory=False)
                    results.append(f"| {name} | ✅ {path.name} | {len(df):,} |\n")
                except:
                    results.append(f"| {name} | ✅ {path.name} | ? |\n")
            else:
                results.append(f"| {name} | ❌ Not extracted | - |\n")

        # Check qwinsta.txt for RDP info
        qwinsta_file = triage_dir / 'qwinsta.txt' if triage_dir else None
        if qwinsta_file and qwinsta_file.exists():
            results.append("\n## RDP Sessions (qwinsta.txt)\n\n")
            results.append("```\n")
            # Windows command output is typically UTF-16 LE
            with open(qwinsta_file, encoding='utf-16-le', errors='replace') as f:
                results.append(f.read())
            results.append("```\n")

        output = self.analysis_dir / 'ews-overview.md'
        with open(output, 'w') as f:
            f.writelines(results)
        print(f"  Written: {output}")
        self.mark_complete('analyses', 'ews_overview')
        return True

    def analyze_ews_execution(self):
        """Analyze EWS-VM program execution."""
        results = ["# EWS-VM Program Execution Analysis\n"]
        results.append(f"Generated: {datetime.now().isoformat()}\n\n")

        # Load prefetch data
        prefetch_file = self.extractions_dir / 'ews-vm-prefetch.csv'
        if prefetch_file.exists():
            try:
                df = pd.read_csv(prefetch_file, low_memory=False)
                results.append(f"## Prefetch Data ({len(df):,} entries)\n\n")

                # Look for suspicious executables
                results.append("### Suspicious Executables\n\n")
                suspicious_found = []

                # Check column names - KAPE tools use different formats
                exec_col = None
                for col in ['ExecutableName', 'SourceFilename', 'Executable', 'Name']:
                    if col in df.columns:
                        exec_col = col
                        break

                if exec_col:
                    for _, row in df.iterrows():
                        exe_name = str(row.get(exec_col, '')).lower()
                        for sus_exe in SUSPICIOUS_EXES:
                            if sus_exe in exe_name:
                                suspicious_found.append({
                                    'executable': row.get(exec_col, ''),
                                    'matched': sus_exe,
                                    'source': row.get('source_file', ''),
                                })
                                break

                    if suspicious_found:
                        results.append("| Executable | Matched Pattern | Source |\n")
                        results.append("|------------|-----------------|--------|\n")
                        seen = set()
                        for item in suspicious_found:
                            key = item['executable']
                            if key not in seen:
                                seen.add(key)
                                results.append(f"| {item['executable']} | {item['matched']} | {item['source']} |\n")
                    else:
                        results.append("*No suspicious executables found in prefetch.*\n")
                else:
                    results.append("*Could not identify executable column in prefetch data.*\n")
                    results.append(f"Available columns: {list(df.columns)}\n")

            except Exception as e:
                results.append(f"ERROR loading prefetch: {e}\n")
        else:
            results.append("*No prefetch data. Run 'extract ews_prefetch' first.*\n")

        # Load Amcache data
        results.append("\n## Amcache Data\n\n")
        amcache_file = self.extractions_dir / 'ews-vm-amcache.csv'
        if amcache_file.exists():
            try:
                df = pd.read_csv(amcache_file, low_memory=False)
                results.append(f"Total Amcache entries: {len(df):,}\n\n")

                # Show column overview
                results.append(f"Available columns: {', '.join(df.columns[:10])}\n\n")

            except Exception as e:
                results.append(f"ERROR loading Amcache: {e}\n")
        else:
            results.append("*No Amcache data. Run 'extract ews_amcache' first.*\n")

        output = self.analysis_dir / 'ews-execution.md'
        with open(output, 'w') as f:
            f.writelines(results)
        print(f"  Written: {output}")
        self.mark_complete('analyses', 'ews_execution')
        return True

    def analyze_ews_user_activity(self):
        """Analyze EWS-VM user activity (LNK files, shellbags)."""
        results = ["# EWS-VM User Activity Analysis\n"]
        results.append(f"Generated: {datetime.now().isoformat()}\n\n")

        # Load LNK data
        results.append("## Recent Files (LNK Shortcuts)\n\n")
        lnk_file = self.extractions_dir / 'ews-vm-lnk.csv'
        if lnk_file.exists():
            try:
                df = pd.read_csv(lnk_file, low_memory=False)
                results.append(f"Total LNK entries: {len(df):,}\n\n")

                # Show recent files accessed
                if 'TargetPath' in df.columns or 'LocalPath' in df.columns:
                    path_col = 'TargetPath' if 'TargetPath' in df.columns else 'LocalPath'
                    results.append(f"### Target Paths (first 30)\n\n")
                    results.append("| Target Path |\n")
                    results.append("|-------------|\n")
                    for path in df[path_col].dropna().unique()[:30]:
                        results.append(f"| {path} |\n")
                else:
                    results.append(f"Available columns: {', '.join(df.columns[:15])}\n")

            except Exception as e:
                results.append(f"ERROR loading LNK data: {e}\n")
        else:
            results.append("*No LNK data. Run 'extract ews_lnk' first.*\n")

        # Load shellbags
        results.append("\n## Shellbags (Folder Access History)\n\n")
        shellbag_file = self.extractions_dir / 'ews-vm-shellbags.csv'
        if shellbag_file.exists():
            try:
                df = pd.read_csv(shellbag_file, low_memory=False)
                results.append(f"Total shellbag entries: {len(df):,}\n\n")

                # Group by source file type
                if 'source_file' in df.columns:
                    results.append("### By Source\n\n")
                    for src, count in df['source_file'].value_counts().items():
                        results.append(f"- {src}: {count:,} entries\n")

            except Exception as e:
                results.append(f"ERROR loading shellbag data: {e}\n")
        else:
            results.append("*No shellbag data. Run 'extract ews_shellbags' first.*\n")

        output = self.analysis_dir / 'ews-user-activity.md'
        with open(output, 'w') as f:
            f.writelines(results)
        print(f"  Written: {output}")
        self.mark_complete('analyses', 'ews_user_activity')
        return True

    def analyze_ews_ioc_correlation(self):
        """Correlate Level 1 IOCs with EWS-VM artifacts."""
        results = ["# EWS-VM IOC Correlation\n"]
        results.append(f"Generated: {datetime.now().isoformat()}\n\n")
        results.append("Searching for Level 1 IOCs in EWS-VM triage data.\n\n")

        # Get IOCs
        known_domains = self.criteria.get_domains()
        known_processes = self.criteria.get_processes()
        known_ips = self.criteria.get_ips()

        results.append("## Known IOCs from Level 1\n\n")
        results.append(f"- Domains: {len(known_domains)}\n")
        results.append(f"- Processes: {len(known_processes)}\n")
        results.append(f"- IPs: {len(known_ips)}\n\n")

        # Search in all extracted CSVs
        matches = []
        for csv_file in self.extractions_dir.glob('ews-vm-*.csv'):
            try:
                df = pd.read_csv(csv_file, low_memory=False)
                # Convert all columns to string and search
                for col in df.columns:
                    for _, row in df.iterrows():
                        val = str(row[col]).lower()
                        # Check processes
                        for proc in known_processes:
                            if proc.lower() in val:
                                matches.append({
                                    'type': 'Process',
                                    'ioc': proc,
                                    'file': csv_file.name,
                                    'column': col,
                                    'value': str(row[col])[:100],
                                })
                        # Check domains
                        for domain in known_domains:
                            if domain.lower() in val:
                                matches.append({
                                    'type': 'Domain',
                                    'ioc': domain,
                                    'file': csv_file.name,
                                    'column': col,
                                    'value': str(row[col])[:100],
                                })
            except Exception as e:
                results.append(f"*Warning: Could not search {csv_file.name}: {e}*\n")

        results.append("## IOC Matches\n\n")
        if matches:
            # Deduplicate
            seen = set()
            unique_matches = []
            for m in matches:
                key = (m['type'], m['ioc'], m['file'])
                if key not in seen:
                    seen.add(key)
                    unique_matches.append(m)

            results.append(f"Found {len(unique_matches)} unique matches:\n\n")
            results.append("| Type | IOC | File | Column | Sample Value |\n")
            results.append("|------|-----|------|--------|-------------|\n")
            for m in unique_matches[:50]:
                results.append(f"| {m['type']} | {m['ioc']} | {m['file']} | {m['column']} | {m['value']} |\n")
        else:
            results.append("*No IOC matches found in EWS-VM data.*\n")

        output = self.analysis_dir / 'ews-level1-ioc-correlation.md'
        with open(output, 'w') as f:
            f.writelines(results)
        print(f"  Written: {output}")
        self.mark_complete('analyses', 'ews_ioc_correlation')
        return True


# =============================================================================
# CLI HELPERS
# =============================================================================
def run_extraction(analyzer: DiskAnalyzer, step: str, force: bool = False):
    """Run a single extraction step."""
    print(f"[{step}]")
    if analyzer.is_complete('extractions', step) and not force:
        print("  Already complete (use --force to re-run)")
        return

    method_name = f"extract_{step}"
    method = getattr(analyzer, method_name, None)
    if method:
        method()
    else:
        print(f"  ERROR: No method {method_name}")


def run_analysis(analyzer: DiskAnalyzer, step: str, force: bool = False, show: bool = False):
    """Run a single analysis step."""
    print(f"[{step}]")
    if analyzer.is_complete('analyses', step) and not force:
        print("  Already complete (use --force to re-run)")
        if show:
            _show_analysis_output(analyzer, step)
        return

    method_name = f"analyze_{step}"
    method = getattr(analyzer, method_name, None)
    if method:
        method()
        if show:
            _show_analysis_output(analyzer, step)
    else:
        print(f"  ERROR: No method {method_name}")


def _show_analysis_output(analyzer: DiskAnalyzer, step: str):
    """Display the output file for an analysis step."""
    file_map = analyzer.get_analysis_file_map()
    filename = file_map.get(step, f"{step.replace('_', '-')}.md")
    output_file = analyzer.analysis_dir / filename
    if output_file.exists():
        print(f"\n  --- {filename} ---")
        with open(output_file) as f:
            print(f.read())
    else:
        print(f"  Output file not found: {output_file}")


# =============================================================================
# CLI HELPER (for standalone testing)
# =============================================================================
def main():
    """Main CLI entry point for disk analysis (for standalone testing)."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Disk forensics analysis'
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
    analyzer = DiskAnalyzer(tier=args.tier)

    if args.command == 'status':
        analyzer.show_status()
        return 0

    if args.command == 'reset':
        analyzer.reset_status()
        print("Status reset.")
        return 0

    if args.command == 'extract':
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

        analyzer.show_suggestions()
        return 0

    return 1


if __name__ == '__main__':
    import sys
    sys.exit(main())
