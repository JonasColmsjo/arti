#!/usr/bin/env python3
"""
Unified forensic analysis CLI.

Usage:
    python forensic_analysis.py memory status
    python forensic_analysis.py memory extract all
    python forensic_analysis.py memory analyze all --show

    python forensic_analysis.py network status
    python forensic_analysis.py network extract all
    python forensic_analysis.py network analyze all --show

    python forensic_analysis.py disk status
    python forensic_analysis.py disk extract all
    python forensic_analysis.py disk analyze all --show
"""

import argparse
import sys


def cmd_status(analyzer):
    """Show analysis status."""
    analyzer.show_status()
    return 0


def cmd_reset(analyzer):
    """Reset analysis status."""
    analyzer.reset_status()
    print("Status reset.")
    return 0


def cmd_extract(analyzer, target, force, run_extraction_func):
    """Run extraction steps."""
    missing = analyzer.check_artifacts()
    if missing:
        print("ERROR: Missing artifact files:")
        for name, path in missing:
            print(f"  {name}: {path}")
        return 1

    steps = [s[0] for s in analyzer.get_extraction_steps()]
    if target == 'all':
        for step in steps:
            run_extraction_func(analyzer, step, force)
    elif target in steps:
        run_extraction_func(analyzer, target, force)
    else:
        print(f"Unknown extraction: {target}")
        print(f"Available: {', '.join(steps)}")
        return 1
    return 0


def cmd_analyze(analyzer, target, force, show, interactive, run_analysis_func):
    """Run analysis steps."""
    steps = [s[0] for s in analyzer.get_analysis_steps()]
    if target == 'all':
        for step in steps:
            run_analysis_func(analyzer, step, force, show)
    elif target in steps:
        run_analysis_func(analyzer, target, force, show)
    else:
        print(f"Unknown analysis: {target}")
        print(f"Available: {', '.join(steps)}")
        return 1

    analyzer.show_suggestions(interactive=interactive)
    return 0


def main():
    parser = argparse.ArgumentParser(
        description='Unified forensic analysis CLI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python forensic_analysis.py memory status           # Show memory analysis status
    python forensic_analysis.py memory extract all      # Run all memory extractions
    python forensic_analysis.py memory analyze all -s   # Run all analyses, show output
    python forensic_analysis.py network status          # Show network analysis status
    python forensic_analysis.py network extract all     # Run all network extractions
    python forensic_analysis.py network analyze all -s  # Run all analyses, show output
    python forensic_analysis.py disk status             # Show disk analysis status
"""
    )

    parser.add_argument('module', choices=['memory', 'network', 'disk'],
                        help='Analysis module')
    parser.add_argument('command', choices=['status', 'extract', 'analyze', 'reset'],
                        help='Command to run')
    parser.add_argument('target', nargs='?', default='all',
                        help='Target step or "all"')
    parser.add_argument('--tier', '-t', default='t1',
                        help='Artifact tier (t1, t2, or t3)')
    # Legacy alias
    parser.add_argument('--level', '-l', default=None,
                        help=argparse.SUPPRESS)
    parser.add_argument('--force', '-f', action='store_true',
                        help='Force re-run of completed steps')
    parser.add_argument('--show', '-s', action='store_true',
                        help='Show analysis output after running')
    parser.add_argument('--no-interactive', '-n', action='store_true',
                        help='Disable interactive prompts for suggestions')

    args = parser.parse_args()

    # Support legacy --level flag
    tier_str = args.level if args.level is not None else args.tier

    # Convert tier format: t1/t2/t3/... -> 1/2/3/... (accept tN, lN, or N)
    if tier_str.startswith('t') and tier_str[1:].isdigit():
        tier = int(tier_str[1:])
    elif tier_str.startswith('l') and tier_str[1:].isdigit():
        tier = int(tier_str[1:])
    elif tier_str.isdigit():
        tier = int(tier_str)
    else:
        print(f"Invalid tier: {tier_str}. Use t1, t2, t3, ...")
        return 1

    # Create appropriate analyzer and get module-specific functions
    try:
        if args.module == 'memory':
            from forensic_analysis.memory import MemoryAnalyzer, run_extraction, run_analysis
            analyzer = MemoryAnalyzer(tier=tier)
        elif args.module == 'network':
            from forensic_analysis.network import NetworkAnalyzer, run_extraction, run_analysis
            analyzer = NetworkAnalyzer(tier=tier)
        elif args.module == 'disk':
            from forensic_analysis.disk import DiskAnalyzer, run_extraction, run_analysis
            analyzer = DiskAnalyzer(tier=tier)
        else:
            print(f"Unknown module: {args.module}")
            return 1
    except ValueError as e:
        print(f"Error: {e}")
        return 1

    # Run command
    if args.command == 'status':
        return cmd_status(analyzer)
    elif args.command == 'reset':
        return cmd_reset(analyzer)
    elif args.command == 'extract':
        return cmd_extract(analyzer, args.target, args.force, run_extraction)
    elif args.command == 'analyze':
        return cmd_analyze(analyzer, args.target, args.force, args.show,
                          not args.no_interactive, run_analysis)

    return 1


if __name__ == '__main__':
    sys.exit(main())
