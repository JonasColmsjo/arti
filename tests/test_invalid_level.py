"""Tests that invalid tier arguments are rejected cleanly (no tracebacks)."""

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

from forensic_analysis.base import get_tier_config

# Load main() from scripts/forensic_analysis.py (the CLI script, not the package)
_script_path = Path(__file__).parent.parent / "scripts" / "forensic_analysis.py"
_spec = importlib.util.spec_from_file_location("forensic_analysis_cli", _script_path)
_cli_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_cli_mod)
_forensic_main = _cli_mod.main

# =============================================================================
# 1. get_tier_config rejects invalid tiers
# =============================================================================
class TestGetTierConfigRejectsInvalid:
    @pytest.mark.parametrize("tier", ["t99", "t0", "t999", "nonexistent", "T1"])
    def test_raises_value_error(self, config_dir, tier):
        with pytest.raises(ValueError, match="Unknown tier"):
            get_tier_config(tier)


# =============================================================================
# 2. Analyzer construction rejects invalid tiers
# =============================================================================
class TestAnalyzerConstructionRejectsInvalid:
    def test_network_analyzer(self, config_dir):
        from forensic_analysis.network import NetworkAnalyzer
        with pytest.raises(ValueError, match="Unknown tier"):
            NetworkAnalyzer(tier=99)

    def test_memory_analyzer(self, config_dir):
        from forensic_analysis.memory import MemoryAnalyzer
        with pytest.raises(ValueError, match="Unknown tier"):
            MemoryAnalyzer(tier=99)

    def test_disk_analyzer(self, config_dir):
        from forensic_analysis.disk import DiskAnalyzer
        with pytest.raises(ValueError, match="Unknown tier"):
            DiskAnalyzer(tier=99)


# =============================================================================
# 3. CLI entry points reject invalid tier
# =============================================================================
class TestCLIEntryPointsRejectInvalid:
    """Test that Python main() functions handle invalid tiers gracefully."""

    def test_query_flows_rejects_t99(self, config_dir, monkeypatch):
        """argparse choices= rejects t99 with SystemExit(2)."""
        monkeypatch.setattr(sys, "argv", ["query_flows.py", "--tier", "t99", "summary"])
        from query_flows import main
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 2

    def test_query_dns_rejects_t99(self, config_dir, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["query_dns.py", "--tier", "t99", "summary"])
        from query_dns import main
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 2

    def test_query_tls_rejects_t99(self, config_dir, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["query_tls.py", "--tier", "t99", "summary"])
        from query_tls import main
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 2

    def test_query_kape_rejects_t99(self, config_dir, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["query_kape.py", "--tier", "t99", "files"])
        from query_kape import main
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 2

    def test_forensic_analysis_network_rejects_t99(self, config_dir, monkeypatch, capsys):
        """forensic_analysis.py catches ValueError and returns non-zero."""
        monkeypatch.setattr(sys, "argv", [
            "forensic_analysis.py", "network", "status", "--tier", "t99",
        ])
        rc = _forensic_main()
        assert rc != 0
        captured = capsys.readouterr()
        assert "Traceback" not in captured.out
        assert "Traceback" not in captured.err

    def test_forensic_analysis_memory_rejects_t99(self, config_dir, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", [
            "forensic_analysis.py", "memory", "status", "--tier", "t99",
        ])
        rc = _forensic_main()
        assert rc != 0
        captured = capsys.readouterr()
        assert "Traceback" not in captured.out
        assert "Traceback" not in captured.err

    def test_forensic_analysis_disk_rejects_t99(self, config_dir, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", [
            "forensic_analysis.py", "disk", "status", "--tier", "t99",
        ])
        rc = _forensic_main()
        assert rc != 0
        captured = capsys.readouterr()
        assert "Traceback" not in captured.out
        assert "Traceback" not in captured.err


# =============================================================================
# 4. Subprocess integration tests (slow)
# =============================================================================
GIZUR_ARTI_DIR = str(subprocess.run(
    ["git", "rev-parse", "--show-toplevel"],
    capture_output=True, text=True, cwd=__file__.rsplit("/", 1)[0],
).stdout.strip()) if subprocess.run(
    ["git", "rev-parse", "--show-toplevel"],
    capture_output=True, text=True, cwd=__file__.rsplit("/", 1)[0],
).returncode == 0 else None

# Representative targets covering validation patterns:
#   forensic_analysis.py:  project-status, network-extract-all, disk-extract
#   argparse choices:      network-flows, network-dns-nxdomain, network-tls-sni
SUBPROCESS_TARGETS = [
    # (target + args, description)
    ("project-status network t99", "forensic_analysis.py pass-through (status)"),
    ("network-extract-all t99", "forensic_analysis.py pass-through (extract)"),
    ("disk-extract t99", "forensic_analysis.py pass-through (disk)"),
    ("network-flows summary t99", "argparse choices (query_flows)"),
    ("network-dns-nxdomain t99", "argparse choices (query_dns)"),
    ("network-tls-sni t99", "bash guard + argparse (query_tls)"),
]


@pytest.mark.slow
class TestSubprocessInvalidTier:
    """Run just targets with t99 and verify clean failure."""

    @pytest.mark.parametrize(
        "target_args,desc",
        SUBPROCESS_TARGETS,
        ids=[t[1] for t in SUBPROCESS_TARGETS],
    )
    def test_just_target_rejects_t99(self, target_args, desc):
        if GIZUR_ARTI_DIR is None:
            pytest.skip("Not inside a git repo")
        result = subprocess.run(
            ["just", *target_args.split()],
            capture_output=True, text=True,
            cwd=GIZUR_ARTI_DIR,
            timeout=30,
        )
        output = result.stdout + result.stderr
        assert result.returncode != 0, (
            f"`just {target_args}` exited 0 — expected non-zero for invalid tier\n"
            f"Output: {output[:500]}"
        )
        assert "Traceback" not in output, (
            f"`just {target_args}` produced a Python traceback:\n{output[:1000]}"
        )
