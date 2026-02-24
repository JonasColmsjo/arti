"""
Base module for forensic analysis framework.

Provides common functionality for network, memory, and disk analysis modules.
Designed to be portable across projects via PYTHONPATH configuration.
"""

import json
import os
import subprocess
import yaml
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path


# =============================================================================
# PATHS - Configured via environment variables for portability
# =============================================================================
# PROJECT_ROOT: The root directory of the consuming project
# ARTIFACTS_PATH: Where the artifact files are stored
# Both can be set in .envrc or exported manually

PROJECT_ROOT = Path(os.environ.get('PROJECT_ROOT', Path.cwd()))
ARTIFACTS_PATH = Path(os.environ.get('ARTIFACTS_PATH', PROJECT_ROOT / 'artifacts'))
CONFIG_DIR = PROJECT_ROOT / 'config'

# Legacy alias for backwards compatibility
REPO_DIR = PROJECT_ROOT

# Config files - relative to PROJECT_ROOT
FINDINGS_FILE = CONFIG_DIR / 'findings.yaml'
SETTINGS_FILE = CONFIG_DIR / 'settings.yaml'
ARTIFACTS_FILE = CONFIG_DIR / 'artifacts.yaml'
IOCS_FILE = CONFIG_DIR / 'iocs.yaml'

# Legacy alias for backwards compatibility
INVESTIGATION_FILE = FINDINGS_FILE


# =============================================================================
# INVESTIGATION CRITERIA
# =============================================================================
class InvestigationCriteria:
    """Manages investigation criteria from config YAML files."""

    def __init__(self, config_dir=None):
        self.config_dir = Path(config_dir) if config_dir else CONFIG_DIR
        self.data = self._load()

    def _load(self):
        """Load criteria from multiple config YAML files."""
        data = {'ips': [], 'domains': [], 'processes': [], 'accounts': [],
                'thresholds': {}, 'exclude_domains': [], 'timeframe': {}, 'artifacts': {}}

        # Load findings (ips, domains, processes, accounts)
        findings_file = self.config_dir / 'findings.yaml'
        if findings_file.exists():
            with open(findings_file) as f:
                findings = yaml.safe_load(f) or {}
                data['ips'] = findings.get('ips', [])
                data['domains'] = findings.get('domains', [])
                data['processes'] = findings.get('processes', [])
                data['accounts'] = findings.get('accounts', [])

        # Load settings (thresholds, timeframe, exclude_domains)
        settings_file = self.config_dir / 'settings.yaml'
        if settings_file.exists():
            with open(settings_file) as f:
                settings = yaml.safe_load(f) or {}
                data['thresholds'] = settings.get('thresholds', {})
                data['timeframe'] = settings.get('timeframe', {})
                data['exclude_domains'] = settings.get('exclude_domains', [])

        # Load artifact paths
        artifacts_file = self.config_dir / 'artifacts.yaml'
        if artifacts_file.exists():
            with open(artifacts_file) as f:
                artifacts = yaml.safe_load(f) or {}
                # Map tier keys (t1/t2/t3 or l1/l2/l3) to tier1/tier2/tier3
                tiers_cfg = get_tiers_config()
                if tiers_cfg:
                    data['artifacts'] = {
                        f'tier{i+1}': artifacts.get(k, {})
                        for i, k in enumerate(sorted(tiers_cfg.keys()))
                    }
                else:
                    data['artifacts'] = {
                        f'tier{i+1}': artifacts.get(k, {})
                        for i, k in enumerate(['t1', 't2', 't3']) if k in artifacts
                    }

        return data

    def save(self):
        """Save findings back to findings.yaml."""
        findings_file = self.config_dir / 'findings.yaml'
        findings_data = {
            'ips': self.data.get('ips', []),
            'domains': self.data.get('domains', []),
            'processes': self.data.get('processes', []),
            'accounts': self.data.get('accounts', []),
        }
        with open(findings_file, 'w') as f:
            yaml.dump(findings_data, f, default_flow_style=False, sort_keys=False)

    def get_ips(self):
        """Get list of IPs of interest."""
        return [item['value'] for item in self.data.get('ips', [])]

    def get_domains(self):
        """Get list of domains of interest."""
        return [item['value'] for item in self.data.get('domains', [])]

    def get_processes(self):
        """Get list of processes of interest."""
        return [item['value'] for item in self.data.get('processes', [])]

    def get_accounts(self):
        """Get list of accounts of interest."""
        return [item['value'] for item in self.data.get('accounts', [])]

    def get_exclude_domains(self):
        """Get list of domains to exclude from suggestions."""
        return self.data.get('exclude_domains', [])

    def is_excluded_domain(self, domain):
        """Check if domain is in exclusion list."""
        domain_lower = domain.lower()
        for excluded in self.get_exclude_domains():
            if excluded.lower() in domain_lower or domain_lower in excluded.lower():
                return True
        return False

    def get_threshold(self, name, default=None):
        """Get a threshold value."""
        return self.data.get('thresholds', {}).get(name, default)

    def get_timeframe(self, level=None):
        """Get investigation timeframe as (start, end) datetime tuple.

        Args:
            level: Optional tier (1, 2, 3 or 't1', 't2', 't3'). If None, returns t1 timeframe.
        """
        from datetime import datetime
        tf = self.data.get('timeframe', {})

        # Handle level/tier parameter
        if level is not None:
            tier_key = f't{level}' if isinstance(level, int) else level
            tf = tf.get(tier_key, {})

        start = tf.get('start')
        end = tf.get('end')
        if start and end:
            return (
                datetime.strptime(start, '%Y-%m-%d'),
                datetime.strptime(end, '%Y-%m-%d').replace(hour=23, minute=59, second=59)
            )
        return None, None

    def get_note(self, category, value):
        """Get the note for a specific item."""
        for item in self.data.get(category, []):
            if item['value'].lower() == value.lower():
                return item.get('note', '')
        return ''

    def matches_ip(self, ip):
        """Check if IP matches any criteria."""
        return ip in self.get_ips()

    def is_benign_ip(self, ip):
        """Check if IP is marked as benign in criteria."""
        for item in self.data.get('ips', []):
            if item['value'] == ip:
                return item.get('status', '').lower() == 'benign'
        return False

    def get_ip_status(self, ip):
        """Get the status of an IP (benign, suspicious, or None)."""
        for item in self.data.get('ips', []):
            if item['value'] == ip:
                return item.get('status', None)
        return None

    def matches_domain(self, domain):
        """Check if domain matches any criteria (substring match)."""
        domain_lower = domain.lower()
        for d in self.get_domains():
            if d.lower() in domain_lower:
                return True
        return False

    def matches_process(self, process):
        """Check if process matches any criteria (substring match)."""
        process_lower = process.lower()
        for p in self.get_processes():
            if p.lower() in process_lower:
                return True
        return False

    def matches_account(self, account):
        """Check if account matches any criteria."""
        account_lower = account.lower()
        for a in self.get_accounts():
            if a.lower() == account_lower:
                return True
        return False

    def suggest_ip(self, ip, note, source):
        """Suggest adding an IP to investigation criteria."""
        if not self.matches_ip(ip):
            return {
                'category': 'ips',
                'value': ip,
                'note': note,
                'source': source,
                'added': datetime.now().strftime('%Y-%m-%d'),
            }
        return None

    def suggest_domain(self, domain, note, source):
        """Suggest adding a domain to investigation criteria."""
        # Check if already tracked or excluded
        if self.matches_domain(domain):
            return None
        # Check exclusion list
        for excluded in self.get_exclude_domains():
            if excluded.lower() in domain.lower() or domain.lower() in excluded.lower():
                return None
        return {
            'category': 'domains',
            'value': domain,
            'note': note,
            'source': source,
            'added': datetime.now().strftime('%Y-%m-%d'),
        }

    def add_suggestion(self, suggestion):
        """Add a suggestion to the criteria file."""
        if suggestion:
            category = suggestion.pop('category')
            if category not in self.data:
                self.data[category] = []
            self.data[category].append(suggestion)
            self.save()

    def get_artifact_paths(self, tier: int, module: str) -> dict:
        """Get artifact paths for a specific tier and module.

        Args:
            tier: Artifact tier (1, 2, or 3)
            module: Module name ('network', 'disk', or 'memory')

        Returns:
            Dict mapping artifact keys to resolved Path objects
        """
        artifacts = self.data.get('artifacts', {})
        tier_key = f'tier{tier}'

        if tier_key not in artifacts:
            return {}

        module_data = artifacts[tier_key].get(module, {})
        return self._resolve_paths(module_data)

    def get_all_artifact_paths(self, tier: int, module: str) -> dict:
        """Get cumulative artifact paths up to and including the specified tier.

        For tier 2, returns tier 1 + tier 2 paths.
        For tier 3, returns tier 1 + tier 2 + tier 3 paths.

        WARNING: Only use this for explicit cross-tier correlation (e.g.
        mac-correlate). For per-tier extraction and analysis, use
        get_artifact_paths() instead to avoid mixing artifacts across tiers.
        """
        all_paths = {}
        for t in range(1, tier + 1):
            all_paths.update(self.get_artifact_paths(t, module))
        return all_paths

    def _resolve_paths(self, data, base_path=None) -> dict:
        """Recursively resolve relative paths to absolute Path objects.

        Args:
            data: Dict or string containing relative paths
            base_path: Base path for resolution (defaults to ARTIFACTS_PATH/artifacts-unpacked)

        Returns:
            Dict with same structure but Path objects instead of strings
        """
        if base_path is None:
            base_path = ARTIFACTS_PATH / 'artifacts-unpacked'

        if isinstance(data, str):
            return base_path / data
        elif isinstance(data, dict):
            result = {}
            for key, value in data.items():
                if isinstance(value, dict):
                    # Nested dict (like disk.stsupport10.plaso)
                    result[key] = self._resolve_paths(value, base_path)
                elif isinstance(value, str):
                    result[key] = base_path / value
                else:
                    result[key] = value
            return result
        return data


# =============================================================================
# TIER CONFIGURATION HELPERS
# =============================================================================
def get_tiers_config() -> dict:
    """Get all tier configurations from settings.yaml."""
    settings_file = CONFIG_DIR / 'settings.yaml'
    if settings_file.exists():
        with open(settings_file) as f:
            settings = yaml.safe_load(f) or {}
            return settings.get('tiers', settings.get('levels', {}))
    return {}


def get_tier_config(tier: str) -> dict:
    """Get configuration for a specific tier.

    Args:
        tier: Tier identifier (e.g., 't1', 't2', 't3' or custom names)

    Returns:
        Dict with keys: artifacts_folder, work_folder, display_name, description

    Raises:
        ValueError: If tier is not defined in settings.yaml
    """
    tiers = get_tiers_config()
    if tier not in tiers:
        available = ', '.join(tiers.keys()) if tiers else 'none defined'
        raise ValueError(f"Unknown tier: {tier}. Available tiers: {available}")
    return tiers[tier]


def get_available_tiers() -> list:
    """Get list of available tier identifiers."""
    return list(get_tiers_config().keys())


def get_artifact_path(tier: str) -> Path:
    """Get artifact folder path for a tier.

    Args:
        tier: Tier identifier (e.g., 't1', 't2')

    Returns:
        Path to artifact folder (e.g., $ARTIFACTS_PATH/artifacts/Tier_1_Artifacts)
    """
    config = get_tier_config(tier)
    return ARTIFACTS_PATH / 'artifacts' / config['artifacts_folder']


def get_work_path(tier: str) -> Path:
    """Get work folder path for a tier.

    Args:
        tier: Tier identifier (e.g., 't1', 't2')

    Returns:
        Path to work folder (e.g., $PROJECT_ROOT/work/tier1)
    """
    config = get_tier_config(tier)
    return PROJECT_ROOT / 'work' / config['work_folder']


def get_extractions_path(tier: str, module: str) -> Path:
    """Get extractions folder path for a tier and module.

    Args:
        tier: Tier identifier (e.g., 't1', 't2')
        module: Module name ('network', 'disk', 'memory')

    Returns:
        Path to extractions folder
    """
    return get_work_path(tier) / 'automated' / module / 'extractions'


def tier_to_int(tier: str) -> int:
    """Convert tier string to integer.

    Args:
        tier: Tier identifier (e.g., 't1', 't2')

    Returns:
        Integer tier (1, 2, 3, etc.)
    """
    # Extract number from tier string (t1 -> 1, t2 -> 2, etc.)
    import re
    match = re.search(r'\d+', tier)
    if match:
        return int(match.group())
    # Fallback: try to get position in available tiers
    tiers = get_available_tiers()
    if tier in tiers:
        return tiers.index(tier) + 1
    return 1


# =============================================================================
# BASE ANALYZER CLASS
# =============================================================================
class ForensicAnalyzer(ABC):
    """Base class for forensic analysis modules."""

    def __init__(self, tier, module_name: str):
        """Initialize analyzer for a specific tier and module.

        Args:
            tier: Tier identifier (str like 't1', 't2' or int like 1, 2 for backwards compat)
            module_name: Module name ('network', 'disk', 'memory')
        """
        # Handle both string ('t1', 'l2') and int (1, 2) tier identifiers
        if isinstance(tier, int):
            # Look up actual tier name from config (e.g., int 1 → 'l1' or 't1')
            available = get_available_tiers()
            if available and tier <= len(available):
                self.tier_str = sorted(available)[tier - 1]
            else:
                self.tier_str = f't{tier}'
            self.tier = tier
        else:
            self.tier_str = tier
            self.tier = tier_to_int(tier)

        self.module = module_name
        self.tier_dir = get_work_path(self.tier_str)

        # Separate automated (script output) from manual (investigator notes) at tier folder
        self.automated_dir = self.tier_dir / 'automated'
        self.manual_dir = self.tier_dir / 'manual'

        # Script outputs go in automated/<module>/
        self.work_dir = self.automated_dir / module_name
        self.extractions_dir = self.work_dir / 'extractions'
        self.analysis_dir = self.work_dir / 'analysis'
        self.status_file = self.work_dir / '.analysis_status.json'

        self.criteria = InvestigationCriteria()
        self.suggestions = []  # Collected during analysis

        # Ensure directories exist
        self.extractions_dir.mkdir(parents=True, exist_ok=True)
        self.analysis_dir.mkdir(parents=True, exist_ok=True)
        self.manual_dir.mkdir(parents=True, exist_ok=True)

    def load_status(self):
        """Load analysis status from file."""
        if self.status_file.exists():
            with open(self.status_file) as f:
                return json.load(f)
        return {'extractions': {}, 'analyses': {}}

    def save_status(self, status):
        """Save analysis status to file."""
        with open(self.status_file, 'w') as f:
            json.dump(status, f, indent=2)

    def mark_complete(self, category: str, step: str):
        """Mark a step as complete."""
        status = self.load_status()
        if category not in status:
            status[category] = {}
        status[category][step] = True
        self.save_status(status)

    def is_complete(self, category: str, step: str) -> bool:
        """Check if a step is complete."""
        status = self.load_status()
        return status.get(category, {}).get(step, False)

    def reset_status(self):
        """Reset all status."""
        self.save_status({'extractions': {}, 'analyses': {}})

    def add_suggestion(self, suggestion):
        """Add a suggestion for investigation criteria."""
        if suggestion:
            self.suggestions.append(suggestion)

    def show_suggestions(self, interactive=True):
        """Display collected suggestions (deduplicated) and optionally add them."""
        if not self.suggestions:
            return

        # Deduplicate by (category, value)
        seen = {}
        for s in self.suggestions:
            key = (s['category'], s['value'])
            if key not in seen:
                seen[key] = s
            else:
                # Merge sources
                existing_source = seen[key]['source']
                new_source = s['source']
                if new_source not in existing_source:
                    seen[key]['source'] = f"{existing_source}, {new_source}"

        unique = list(seen.values())

        print("\n" + "=" * 70)
        print("SUGGESTED ADDITIONS TO investigation.yaml")
        print("=" * 70)
        print(f"\n{len(unique)} unique items flagged during analysis:\n")

        for i, s in enumerate(unique, 1):
            print(f"  [{i}] {s['category']}: {s['value']}")
            print(f"      {s['note']}")
            print(f"      (source: {s['source']})")
            print()

        if interactive and unique:
            print("-" * 70)
            response = input("Add these to investigation.yaml? [y/N/numbers]: ").strip().lower()

            if response == 'y':
                for s in unique:
                    self.criteria.add_suggestion(s.copy())
                print(f"Added {len(unique)} items to {INVESTIGATION_FILE}")
            elif response and response != 'n':
                # Parse numbers like "1,3,5" or "1 3 5"
                try:
                    indices = [int(x.strip()) for x in response.replace(',', ' ').split()]
                    added = 0
                    for idx in indices:
                        if 1 <= idx <= len(unique):
                            self.criteria.add_suggestion(unique[idx-1].copy())
                            added += 1
                    print(f"Added {added} items to {INVESTIGATION_FILE}")
                except ValueError:
                    print("Invalid input, nothing added")

    @abstractmethod
    def get_artifact_files(self) -> dict:
        """Return dict of artifact file paths."""
        pass

    @abstractmethod
    def get_extraction_steps(self) -> list:
        """Return list of (name, description) tuples for extraction steps."""
        pass

    @abstractmethod
    def get_analysis_steps(self) -> list:
        """Return list of (name, description) tuples for analysis steps."""
        pass

    def get_analysis_file_map(self) -> dict:
        """Return mapping of analysis names to output filenames.

        Default implementation converts underscores to hyphens.
        Override if custom mapping is needed.
        """
        return {name: f"{name.replace('_', '-')}.md"
                for name, _ in self.get_analysis_steps()}

    def check_artifacts(self):
        """Check that all artifact files exist."""
        missing = []
        for name, path in self.get_artifact_files().items():
            if not Path(path).exists():
                missing.append((name, path))
        return missing

    def show_status(self):
        """Display current analysis status."""
        print("=" * 70)
        print(f"{self.module.upper()} ANALYSIS STATUS - TIER {self.tier}")
        print("=" * 70)

        # Artifact files
        print("\n## Artifact Files\n")
        for name, path in self.get_artifact_files().items():
            exists = Path(path).exists()
            status = "OK" if exists else "MISSING"
            print(f"  [{status:7}] {name}: {path}")

        # Extractions
        print("\n## Extractions\n")
        for name, desc in self.get_extraction_steps():
            done = self.is_complete('extractions', name)
            status = "DONE" if done else "PENDING"
            print(f"  [{status:7}] {name}: {desc}")

        # Analyses
        print("\n## Analyses\n")
        for name, desc in self.get_analysis_steps():
            done = self.is_complete('analyses', name)
            status = "DONE" if done else "PENDING"
            print(f"  [{status:7}] {name}: {desc}")

        print("\n" + "=" * 70)
        print(f"Tier directory: {self.tier_dir}")
        print(f"  Automated:   {self.automated_dir}")
        print(f"  Manual:      {self.manual_dir}")
        print(f"Module output: {self.work_dir}")
        print(f"Investigation criteria: {INVESTIGATION_FILE}")
        print("=" * 70)


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================
def run_command(args, output_file=None, description=None, capture_output=True):
    """Run a command and optionally save output to file."""
    if description:
        print(f"  {description}")

    try:
        result = subprocess.run(
            args,
            capture_output=capture_output,
            text=True,
            timeout=600  # 10 minute timeout
        )

        if output_file and result.stdout:
            output_file = Path(output_file)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, 'w') as f:
                f.write(result.stdout)
            print(f"  Written: {output_file}")

        return result.returncode == 0, result.stdout, result.stderr

    except subprocess.TimeoutExpired:
        print(f"  ERROR: Command timed out")
        return False, '', 'Timeout'
    except Exception as e:
        print(f"  ERROR: {e}")
        return False, '', str(e)


def parse_bytes(value, unit=None):
    """Parse byte values with optional unit suffix."""
    if isinstance(value, (int, float)):
        return int(value)

    value = str(value).strip()
    multipliers = {
        'B': 1, 'K': 1024, 'KB': 1024,
        'M': 1024**2, 'MB': 1024**2,
        'G': 1024**3, 'GB': 1024**3,
    }

    for suffix, mult in multipliers.items():
        if value.upper().endswith(suffix):
            return int(float(value[:-len(suffix)].strip()) * mult)

    if unit and unit.upper() in multipliers:
        return int(float(value) * multipliers[unit.upper()])

    try:
        return int(float(value))
    except ValueError:
        return 0


def format_bytes(n):
    """Format bytes as human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if abs(n) < 1024:
            return f"{n:.0f} {unit}" if unit == 'B' else f"{n:,.0f} {unit}"
        n /= 1024
    return f"{n:,.1f} TB"
