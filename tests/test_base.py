"""Tests for forensic_analysis/base.py — utility functions and InvestigationCriteria."""

import yaml
from datetime import datetime
from pathlib import Path

import pytest

from forensic_analysis.base import (
    InvestigationCriteria,
    format_bytes,
    get_available_tiers,
    get_artifact_path,
    get_extractions_path,
    get_tier_config,
    get_tiers_config,
    get_work_path,
    tier_to_int,
    parse_bytes,
)


# =============================================================================
# parse_bytes
# =============================================================================
class TestParseBytes:
    def test_int_passthrough(self):
        assert parse_bytes(1024) == 1024

    def test_float_passthrough(self):
        assert parse_bytes(2.5) == 2

    def test_string_int(self):
        assert parse_bytes("1024") == 1024

    def test_k_suffix(self):
        assert parse_bytes("10K") == 10 * 1024

    def test_m_suffix(self):
        assert parse_bytes("2M") == 2 * 1024 ** 2

    def test_g_suffix(self):
        assert parse_bytes("1G") == 1024 ** 3

    def test_b_suffix(self):
        assert parse_bytes("1024B") == 1024

    def test_b_suffix(self):
        assert parse_bytes("512B") == 512

    def test_fractional_m(self):
        assert parse_bytes("2.5M") == int(2.5 * 1024 ** 2)

    def test_unit_param(self):
        assert parse_bytes("10", unit="KB") == 10 * 1024

    def test_invalid_returns_zero(self):
        assert parse_bytes("not_a_number") == 0

    def test_empty_string_returns_zero(self):
        assert parse_bytes("") == 0


# =============================================================================
# format_bytes
# =============================================================================
class TestFormatBytes:
    def test_zero(self):
        assert format_bytes(0) == "0 B"

    def test_bytes_range(self):
        assert format_bytes(512) == "512 B"

    def test_kb_range(self):
        result = format_bytes(15360)
        assert "KB" in result
        assert "15" in result

    def test_mb_range(self):
        result = format_bytes(5 * 1024 * 1024)
        assert "MB" in result

    def test_gb_range(self):
        result = format_bytes(2 * 1024 ** 3)
        assert "GB" in result

    def test_tb_range(self):
        result = format_bytes(2 * 1024 ** 4)
        assert "TB" in result


# =============================================================================
# tier_to_int
# =============================================================================
class TestTierToInt:
    def test_t1(self, config_dir):
        assert tier_to_int("t1") == 1

    def test_t2(self, config_dir):
        assert tier_to_int("t2") == 2

    def test_t3(self, config_dir):
        assert tier_to_int("t3") == 3

    def test_no_digits_fallback(self, config_dir):
        # If tier is in available_tiers but has no digit, uses index+1
        result = tier_to_int("xyz")
        assert isinstance(result, int)


# =============================================================================
# Level config helpers
# =============================================================================
class TestTierConfig:
    def test_get_tiers_config(self, config_dir):
        config = get_tiers_config()
        assert "t1" in config
        assert "t2" in config

    def test_get_available_tiers(self, config_dir):
        tiers = get_available_tiers()
        assert "t1" in tiers
        assert "t2" in tiers
        assert "t3" in tiers

    def test_get_tier_config_valid(self, config_dir):
        cfg = get_tier_config("t1")
        assert cfg["artifacts_folder"] == "Tier_1_Artifacts"
        assert cfg["work_folder"] == "tier1"

    def test_get_tier_config_invalid(self, config_dir):
        with pytest.raises(ValueError, match="Unknown tier"):
            get_tier_config("nonexistent")

    def test_get_work_path(self, config_dir):
        path = get_work_path("t1")
        assert path == config_dir / "work" / "tier1"

    def test_get_extractions_path(self, config_dir):
        path = get_extractions_path("t2", "network")
        assert path == config_dir / "work" / "tier2" / "automated" / "network" / "extractions"

    def test_get_artifact_path(self, config_dir):
        path = get_artifact_path("t1")
        assert "Tier_1_Artifacts" in str(path)

    def test_get_tiers_config_missing_file(self, tmp_path, monkeypatch):
        import forensic_analysis.base as base_mod
        monkeypatch.setattr(base_mod, "CONFIG_DIR", tmp_path / "nonexistent")
        assert get_tiers_config() == {}

    def test_get_available_tiers_empty(self, tmp_path, monkeypatch):
        import forensic_analysis.base as base_mod
        monkeypatch.setattr(base_mod, "CONFIG_DIR", tmp_path / "nonexistent")
        assert get_available_tiers() == []


# =============================================================================
# InvestigationCriteria
# =============================================================================
class TestInvestigationCriteria:
    def test_load_from_config_dir(self, config_dir):
        ic = InvestigationCriteria(config_dir=str(config_dir))
        assert len(ic.get_ips()) > 0

    def test_get_ips(self, config_dir):
        ic = InvestigationCriteria(config_dir=str(config_dir))
        ips = ic.get_ips()
        assert "83.136.254.57" in ips
        assert "192.168.24.100" in ips

    def test_get_domains(self, config_dir):
        ic = InvestigationCriteria(config_dir=str(config_dir))
        domains = ic.get_domains()
        assert "topenergysupport.com" in domains

    def test_get_processes(self, config_dir):
        ic = InvestigationCriteria(config_dir=str(config_dir))
        procs = ic.get_processes()
        assert "mimikatz.exe" in procs

    def test_get_accounts(self, config_dir):
        ic = InvestigationCriteria(config_dir=str(config_dir))
        accts = ic.get_accounts()
        assert "admin" in accts

    def test_matches_ip_true(self, config_dir):
        ic = InvestigationCriteria(config_dir=str(config_dir))
        assert ic.matches_ip("83.136.254.57") is True

    def test_matches_ip_false(self, config_dir):
        ic = InvestigationCriteria(config_dir=str(config_dir))
        assert ic.matches_ip("1.2.3.4") is False

    def test_is_benign_ip(self, config_dir):
        ic = InvestigationCriteria(config_dir=str(config_dir))
        assert ic.is_benign_ip("192.168.24.100") is True
        assert ic.is_benign_ip("83.136.254.57") is False

    def test_get_ip_status(self, config_dir):
        ic = InvestigationCriteria(config_dir=str(config_dir))
        assert ic.get_ip_status("83.136.254.57") == "suspicious"
        assert ic.get_ip_status("192.168.24.100") == "benign"
        assert ic.get_ip_status("1.2.3.4") is None

    def test_matches_domain_substring(self, config_dir):
        ic = InvestigationCriteria(config_dir=str(config_dir))
        assert ic.matches_domain("www.topenergysupport.com") is True
        assert ic.matches_domain("safe-domain.org") is False

    def test_matches_process_substring(self, config_dir):
        ic = InvestigationCriteria(config_dir=str(config_dir))
        assert ic.matches_process("C:\\Windows\\mimikatz.exe") is True
        assert ic.matches_process("notepad.exe") is False

    def test_matches_account_case_insensitive(self, config_dir):
        ic = InvestigationCriteria(config_dir=str(config_dir))
        assert ic.matches_account("ADMIN") is True
        assert ic.matches_account("Admin") is True
        assert ic.matches_account("unknown_user") is False

    def test_get_exclude_domains(self, config_dir):
        ic = InvestigationCriteria(config_dir=str(config_dir))
        excluded = ic.get_exclude_domains()
        assert "microsoft.com" in excluded

    def test_is_excluded_domain(self, config_dir):
        ic = InvestigationCriteria(config_dir=str(config_dir))
        assert ic.is_excluded_domain("update.microsoft.com") is True
        assert ic.is_excluded_domain("topenergysupport.com") is False

    def test_get_threshold(self, config_dir):
        ic = InvestigationCriteria(config_dir=str(config_dir))
        assert ic.get_threshold("min_bytes") == 1024
        assert ic.get_threshold("nonexistent", default=42) == 42

    def test_get_timeframe_t2(self, config_dir):
        ic = InvestigationCriteria(config_dir=str(config_dir))
        start, end = ic.get_timeframe(level="t2")
        assert start == datetime(2020, 8, 17)
        assert end.year == 2020 and end.month == 8 and end.day == 18

    def test_get_timeframe_none_returns_none(self, config_dir):
        ic = InvestigationCriteria(config_dir=str(config_dir))
        start, end = ic.get_timeframe(level="nonexistent")
        assert start is None
        assert end is None

    def test_get_note(self, config_dir):
        ic = InvestigationCriteria(config_dir=str(config_dir))
        assert ic.get_note("ips", "83.136.254.57") == "C2 server"
        assert ic.get_note("ips", "1.2.3.4") == ""

    def test_suggest_ip_new(self, config_dir):
        ic = InvestigationCriteria(config_dir=str(config_dir))
        suggestion = ic.suggest_ip("1.2.3.4", "test ip", "test")
        assert suggestion is not None
        assert suggestion["value"] == "1.2.3.4"

    def test_suggest_ip_existing_returns_none(self, config_dir):
        ic = InvestigationCriteria(config_dir=str(config_dir))
        assert ic.suggest_ip("83.136.254.57", "existing", "test") is None

    def test_suggest_domain_new(self, config_dir):
        ic = InvestigationCriteria(config_dir=str(config_dir))
        suggestion = ic.suggest_domain("new-domain.com", "test", "test")
        assert suggestion is not None

    def test_suggest_domain_excluded_returns_none(self, config_dir):
        ic = InvestigationCriteria(config_dir=str(config_dir))
        assert ic.suggest_domain("update.microsoft.com", "test", "test") is None

    def test_suggest_domain_existing_returns_none(self, config_dir):
        ic = InvestigationCriteria(config_dir=str(config_dir))
        assert ic.suggest_domain("topenergysupport.com", "test", "test") is None

    def test_add_suggestion(self, config_dir):
        ic = InvestigationCriteria(config_dir=str(config_dir))
        suggestion = {"category": "ips", "value": "9.9.9.9", "note": "test", "source": "test"}
        ic.add_suggestion(suggestion)
        assert "9.9.9.9" in [item["value"] for item in ic.data["ips"]]

    def test_add_suggestion_none_is_noop(self, config_dir):
        ic = InvestigationCriteria(config_dir=str(config_dir))
        count_before = len(ic.data["ips"])
        ic.add_suggestion(None)
        assert len(ic.data["ips"]) == count_before

    def test_save_and_reload(self, config_dir):
        ic = InvestigationCriteria(config_dir=str(config_dir))
        ic.data["ips"].append({"value": "5.5.5.5", "note": "saved"})
        ic.save()
        ic2 = InvestigationCriteria(config_dir=str(config_dir))
        assert "5.5.5.5" in ic2.get_ips()

    def test_get_artifact_paths(self, config_dir):
        ic = InvestigationCriteria(config_dir=str(config_dir))
        paths = ic.get_artifact_paths(2, "network")
        # Should resolve paths from artifacts.yaml
        assert isinstance(paths, dict)

    def test_get_all_artifact_paths(self, config_dir):
        ic = InvestigationCriteria(config_dir=str(config_dir))
        paths = ic.get_all_artifact_paths(2, "network")
        assert isinstance(paths, dict)


# =============================================================================
# Config edge cases
# =============================================================================
class TestConfigEdgeCases:
    def test_empty_findings_yaml(self, tmp_path, monkeypatch):
        import forensic_analysis.base as base_mod
        monkeypatch.setattr(base_mod, "CONFIG_DIR", tmp_path)
        (tmp_path / "findings.yaml").write_text("")
        (tmp_path / "settings.yaml").write_text("")
        ic = InvestigationCriteria(config_dir=str(tmp_path))
        assert ic.get_ips() == []
        assert ic.get_domains() == []

    def test_missing_all_config_files(self, tmp_path):
        ic = InvestigationCriteria(config_dir=str(tmp_path))
        assert ic.get_ips() == []
        assert ic.get_domains() == []
        assert ic.get_exclude_domains() == []

    def test_partial_settings(self, tmp_path, monkeypatch):
        import forensic_analysis.base as base_mod
        monkeypatch.setattr(base_mod, "CONFIG_DIR", tmp_path)
        (tmp_path / "settings.yaml").write_text(yaml.dump({"thresholds": {"x": 1}}))
        ic = InvestigationCriteria(config_dir=str(tmp_path))
        assert ic.get_threshold("x") == 1
        assert ic.get_exclude_domains() == []

    def test_resolve_paths_string(self, config_dir):
        ic = InvestigationCriteria(config_dir=str(config_dir))
        result = ic._resolve_paths("some/path")
        assert isinstance(result, Path)

    def test_resolve_paths_non_dict_non_str(self, config_dir):
        ic = InvestigationCriteria(config_dir=str(config_dir))
        assert ic._resolve_paths(42) == 42

    def test_timeframe_with_int_level(self, config_dir):
        ic = InvestigationCriteria(config_dir=str(config_dir))
        start, end = ic.get_timeframe(level=2)
        assert start is not None

    def test_timeframe_no_level(self, config_dir):
        ic = InvestigationCriteria(config_dir=str(config_dir))
        # No level returns top-level timeframe (which has nested l1/l2 keys, not start/end)
        start, end = ic.get_timeframe()
        # Top-level has l1/l2 as keys, not start/end — so returns None, None
        assert start is None and end is None

    def test_get_timeframe_t1(self, config_dir):
        ic = InvestigationCriteria(config_dir=str(config_dir))
        start, end = ic.get_timeframe(level="t1")
        assert start == datetime(2020, 11, 5)
