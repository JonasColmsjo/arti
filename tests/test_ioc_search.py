"""Tests for scripts/ioc_search.py — IOC search functions."""

import types
from pathlib import Path
from unittest import mock

import pytest
import yaml

from ioc_search import get_iocs_for_tier


# =============================================================================
# get_iocs_for_tier
# =============================================================================
class TestGetIocsForTier:
    @pytest.fixture
    def ioc_data(self):
        return {
            "t1": {
                "ips": ["10.10.200.207", "10.10.2.10"],
                "domains": ["evil-corp.example.com"],
                "hashes": ["d41d8cd98f00b204e9800998ecf8427e"],
            },
            "t2": {
                "ips": ["83.136.254.57", "83.136.254.199"],
                "domains": ["topenergysupport.com"],
                "ports": [8443],
            },
            "t3": {},
        }

    def test_valid_tier(self, ioc_data):
        iocs = get_iocs_for_tier(ioc_data, "t1")
        assert "ips" in iocs
        assert len(iocs["ips"]) == 2
        assert "10.10.200.207" in iocs["ips"]

    def test_t2_tier(self, ioc_data):
        iocs = get_iocs_for_tier(ioc_data, "t2")
        assert "domains" in iocs
        assert "topenergysupport.com" in iocs["domains"]

    def test_empty_tier(self, ioc_data):
        iocs = get_iocs_for_tier(ioc_data, "t3")
        assert iocs == {}

    def test_missing_tier(self, ioc_data):
        iocs = get_iocs_for_tier(ioc_data, "t99")
        assert iocs == {}


# =============================================================================
# cmd_list (stdout capture)
# =============================================================================
class TestCmdList:
    def test_cmd_list_output(self, config_dir, capsys):
        from ioc_search import cmd_list, IOCS_FILE
        import ioc_search

        # Monkeypatch the IOCS_FILE to use fixture
        iocs_file = config_dir / "iocs.yaml"
        with mock.patch.object(ioc_search, "IOCS_FILE", iocs_file):
            args = types.SimpleNamespace(tier="t2")
            cmd_list(args)

        output = capsys.readouterr().out
        assert "IOCs for T2" in output
        assert "83.136.254.57" in output

    def test_cmd_list_empty_tier(self, config_dir, capsys):
        from ioc_search import cmd_list
        import ioc_search

        iocs_file = config_dir / "iocs.yaml"
        with mock.patch.object(ioc_search, "IOCS_FILE", iocs_file):
            args = types.SimpleNamespace(tier="t3")
            cmd_list(args)

        output = capsys.readouterr().out
        assert "Total: " in output


# =============================================================================
# cmd_overlap (stdout capture)
# =============================================================================
class TestCmdOverlap:
    def test_overlaps_exist(self, config_dir, capsys):
        from ioc_search import cmd_overlap
        import ioc_search

        iocs_file = config_dir / "iocs.yaml"
        with mock.patch.object(ioc_search, "IOCS_FILE", iocs_file):
            # Also need to mock get_available_tiers
            with mock.patch.object(ioc_search, "get_available_tiers", return_value=["t1", "t2", "t3"]):
                args = types.SimpleNamespace()
                cmd_overlap(args)

        output = capsys.readouterr().out
        # 83.136.254.57 and topenergysupport.com appear in both t2 and t3
        assert "83.136.254.57" in output or "topenergysupport.com" in output

    def test_no_overlaps(self, tmp_path, capsys):
        from ioc_search import cmd_overlap
        import ioc_search

        # Create IOC file with no overlaps
        ioc_data = {
            "t1": {"ips": ["1.1.1.1"]},
            "t2": {"ips": ["2.2.2.2"]},
        }
        iocs_file = tmp_path / "iocs.yaml"
        iocs_file.write_text(yaml.dump(ioc_data))

        with mock.patch.object(ioc_search, "IOCS_FILE", iocs_file):
            with mock.patch.object(ioc_search, "get_available_tiers", return_value=["t1", "t2"]):
                args = types.SimpleNamespace()
                cmd_overlap(args)

        output = capsys.readouterr().out
        assert "No overlapping" in output
