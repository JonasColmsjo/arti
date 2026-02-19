#!/usr/bin/env python3
"""Helper to read config/artifacts.yaml and output paths for justfile targets.

Usage:
    artifacts_helper.py config [module]            # Show project config (optionally for a module)
    artifacts_helper.py pcaps <tier>               # Print PCAP paths (one per line)
    artifacts_helper.py work-path <tier> <key>     # Print a work_paths value
    artifacts_helper.py artifact-path <tier> <module> <key>  # Print resolved artifact path
    artifacts_helper.py artifact-dirs <tier>        # Print top-level artifact directories for a tier

Environment:
    PROJECT_ROOT  - project root directory (default: cwd)
    ARTIFACTS_PATH - artifact base path (for resolving artifact paths)
"""

import os
import sys
from pathlib import Path

import yaml


def load_artifacts():
    """Load config/artifacts.yaml from PROJECT_ROOT."""
    project_root = Path(os.environ.get('PROJECT_ROOT', Path.cwd()))
    artifacts_file = project_root / 'config' / 'artifacts.yaml'
    if not artifacts_file.exists():
        print(f"Error: {artifacts_file} not found", file=sys.stderr)
        sys.exit(1)
    with open(artifacts_file) as f:
        return yaml.safe_load(f) or {}


def load_settings():
    """Load config/settings.yaml from PROJECT_ROOT."""
    project_root = Path(os.environ.get('PROJECT_ROOT', Path.cwd()))
    settings_file = project_root / 'config' / 'settings.yaml'
    if settings_file.exists():
        with open(settings_file) as f:
            return yaml.safe_load(f) or {}
    return {}


def cmd_config(tier=None, module=None):
    """Show project configuration, optionally filtered to a tier and/or module."""
    project_root = Path(os.environ.get('PROJECT_ROOT', Path.cwd()))
    artifacts_path = Path(os.environ.get('ARTIFACTS_PATH', ''))
    artifacts_base = artifacts_path / 'artifacts-unpacked'
    data = load_artifacts()
    settings = load_settings()
    tiers = settings.get('tiers', {})
    timeframes = settings.get('timeframe', {})

    print(f"PROJECT_ROOT:   {project_root}")
    print(f"ARTIFACTS_PATH: {artifacts_path}")
    print(f"Config dir:     {project_root / 'config'}")
    print()

    show_tiers = [tier] if tier else sorted(tiers.keys())

    for tier_key in show_tiers:
        if tier_key not in tiers:
            print(f"Unknown tier: {tier_key}. Available: {', '.join(sorted(tiers.keys()))}")
            continue

        tc = tiers[tier_key]
        tf = timeframes.get(tier_key, {})
        print(f"=== {tc.get('display_name', tier_key)} ===")
        print(f"  {tc.get('description', '')}")
        if tf.get('start'):
            print(f"  Timeframe: {tf['start']} to {tf.get('end', '?')}")
            if tf.get('note'):
                print(f"  Note: {tf['note']}")
        print()

        tier_data = data.get(tier_key, {})
        modules = [module] if module else [m for m in ('network', 'disk', 'memory', 'docs') if m in tier_data]

        for mod in modules:
            mod_data = tier_data.get(mod, {})
            if not mod_data:
                if module:
                    print(f"  [{mod}] (no artifacts configured)")
                continue

            print(f"  [{mod}]")
            _print_artifact_tree(mod_data, artifacts_base, indent=4)
            print()


def _print_artifact_tree(data, base_path, indent=4):
    """Recursively print artifact paths with existence check."""
    pad = ' ' * indent
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, dict):
                print(f"{pad}{key}/")
                _print_artifact_tree(value, base_path, indent + 2)
            elif isinstance(value, str):
                resolved = base_path / value
                exists = resolved.exists()
                marker = '' if exists else ' [MISSING]'
                print(f"{pad}{key}: {value}{marker}")
            else:
                print(f"{pad}{key}: {value}")
    elif isinstance(data, str):
        resolved = base_path / data
        exists = resolved.exists()
        marker = '' if exists else ' [MISSING]'
        print(f"{pad}{data}{marker}")


def cmd_pcaps(tier):
    """Print all PCAP file paths for a single tier (resolved to absolute paths)."""
    data = load_artifacts()
    artifacts_base = Path(os.environ.get('ARTIFACTS_PATH', '')) / 'artifacts-unpacked'

    network = data.get(tier, {}).get('network', {})
    for key, path in network.items():
        if key.endswith('_pcap'):
            resolved = artifacts_base / path
            if resolved.exists():
                print(resolved)
            else:
                # Try glob for directory-based pcaps
                parent = resolved.parent
                if parent.exists():
                    for pcap in sorted(parent.glob('*.pcap')):
                        print(pcap)


def cmd_work_path(tier, key):
    """Print work_paths value(s) for a tier. Supports string or list."""
    data = load_artifacts()
    project_root = Path(os.environ.get('PROJECT_ROOT', Path.cwd()))
    work_paths = data.get('work_paths', {}).get(tier, {})
    if key not in work_paths:
        print(f"Error: work_paths.{tier}.{key} not found in artifacts.yaml", file=sys.stderr)
        sys.exit(1)
    value = work_paths[key]
    if isinstance(value, list):
        for v in value:
            print(project_root / v)
    else:
        print(project_root / value)


def cmd_artifact_path(tier, module, key):
    """Print a resolved artifact path."""
    data = load_artifacts()
    artifacts_base = Path(os.environ.get('ARTIFACTS_PATH', '')) / 'artifacts-unpacked'
    module_data = data.get(tier, {}).get(module, {})
    if key not in module_data:
        print(f"Error: {tier}.{module}.{key} not found in artifacts.yaml", file=sys.stderr)
        sys.exit(1)
    value = module_data[key]
    # Handle nested dicts (e.g. disk.stsupport10.plaso)
    if isinstance(value, dict):
        for k, v in value.items():
            print(f"{k}={artifacts_base / v}")
    else:
        print(artifacts_base / value)


def _collect_paths(obj):
    """Recursively collect all string values from a nested dict."""
    paths = []
    if isinstance(obj, dict):
        for v in obj.values():
            paths.extend(_collect_paths(v))
    elif isinstance(obj, str) and obj:
        paths.append(obj)
    return paths


def cmd_artifact_dirs(tier):
    """Print unique top-level artifact directories for a tier.

    Scans all artifact paths in the tier config and finds the common
    top-level directories (e.g. Tier_1_Artifacts/Spader_Technologies).
    Prints one absolute path per line, deduplicated.
    """
    data = load_artifacts()
    artifacts_base = Path(os.environ.get('ARTIFACTS_PATH', '')) / 'artifacts-unpacked'
    tier_data = data.get(tier, {})

    # Collect all relative paths from network, disk, memory
    all_paths = []
    for module in ('network', 'disk', 'memory'):
        module_data = tier_data.get(module, {})
        all_paths.extend(_collect_paths(module_data))

    if not all_paths:
        print(f"Error: no artifact paths configured for {tier}", file=sys.stderr)
        sys.exit(1)

    # Find unique top-level directories (first path component)
    top_dirs = set()
    for p in all_paths:
        parts = Path(p).parts
        if parts:
            top_dirs.add(parts[0])

    for d in sorted(top_dirs):
        resolved = artifacts_base / d
        if resolved.exists():
            print(resolved)
        else:
            print(f"Warning: {resolved} does not exist", file=sys.stderr)
            print(resolved)


def main():
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == 'config':
        # Parse optional tier (tN) and module args in any order
        tier = None
        module = None
        for arg in sys.argv[2:]:
            if arg.startswith('t') and arg[1:].isdigit():
                tier = arg
            else:
                module = arg
        cmd_config(tier=tier, module=module)
    elif cmd == 'pcaps':
        if len(sys.argv) < 3:
            print("Usage: artifacts_helper.py pcaps <tier>", file=sys.stderr)
            sys.exit(1)
        cmd_pcaps(sys.argv[2])
    elif cmd == 'work-path':
        if len(sys.argv) < 4:
            print("Usage: artifacts_helper.py work-path <tier> <key>", file=sys.stderr)
            sys.exit(1)
        cmd_work_path(sys.argv[2], sys.argv[3])
    elif cmd == 'artifact-path':
        if len(sys.argv) < 5:
            print("Usage: artifacts_helper.py artifact-path <tier> <module> <key>", file=sys.stderr)
            sys.exit(1)
        cmd_artifact_path(sys.argv[2], sys.argv[3], sys.argv[4])
    elif cmd == 'artifact-dirs':
        if len(sys.argv) < 3:
            print("Usage: artifacts_helper.py artifact-dirs <tier>", file=sys.stderr)
            sys.exit(1)
        cmd_artifact_dirs(sys.argv[2])
    # Legacy aliases for backwards compatibility
    elif cmd == 'evidence-path':
        if len(sys.argv) < 5:
            print("Usage: artifacts_helper.py artifact-path <tier> <module> <key>", file=sys.stderr)
            sys.exit(1)
        cmd_artifact_path(sys.argv[2], sys.argv[3], sys.argv[4])
    elif cmd == 'evidence-dirs':
        if len(sys.argv) < 3:
            print("Usage: artifacts_helper.py artifact-dirs <tier>", file=sys.stderr)
            sys.exit(1)
        cmd_artifact_dirs(sys.argv[2])
    else:
        print(f"Unknown command: {cmd}", file=sys.stderr)
        print(__doc__, file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
