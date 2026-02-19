"""Tests for pure utility functions from scripts/query_kape.py."""

import csv
import io
from pathlib import Path

import pytest

from query_kape import (
    _parse_wmi_datetime,
    find_file,
    find_files,
    read_csv_file,
    read_text_file,
)


# =============================================================================
# _parse_wmi_datetime
# =============================================================================
class TestParseWmiDatetime:
    def test_utc_negative_offset(self):
        # 20201102101533.452742-240 => -240 minutes offset (UTC-4)
        result = _parse_wmi_datetime("20201102101533.452742-240", utc=True)
        assert "UTC" in result
        # -240 min = UTC-4, so 10:15:33 local at UTC-4 = 14:15:33 UTC
        assert "2020-11-02 14:15:33 UTC" == result

    def test_utc_positive_offset(self):
        # +60 means UTC+1
        result = _parse_wmi_datetime("20201102101533.452742+60", utc=True)
        assert "UTC" in result
        # +60 min = UTC+1, so 10:15:33 local = 09:15:33 UTC
        assert "2020-11-02 09:15:33 UTC" == result

    def test_local_time(self):
        result = _parse_wmi_datetime("20201102101533.452742-240", utc=False)
        assert result == "2020-11-02 10:15:33"

    def test_zero_offset(self):
        result = _parse_wmi_datetime("20201102101533.452742+0", utc=True)
        assert "2020-11-02 10:15:33 UTC" == result

    def test_invalid_format_returns_original(self):
        assert _parse_wmi_datetime("not-a-wmi-datetime") == "not-a-wmi-datetime"

    def test_empty_string_returns_original(self):
        assert _parse_wmi_datetime("") == ""


# =============================================================================
# read_text_file
# =============================================================================
class TestReadTextFile:
    def test_utf8(self, tmp_path):
        path = tmp_path / "test.txt"
        path.write_text("Hello UTF-8 world", encoding="utf-8")
        assert read_text_file(path) == "Hello UTF-8 world"

    def test_utf16_le(self, tmp_path):
        path = tmp_path / "test.txt"
        path.write_bytes(b"\xff\xfeH\x00e\x00l\x00l\x00o\x00")
        result = read_text_file(path)
        assert "Hello" in result

    def test_latin1_fallback(self, tmp_path):
        path = tmp_path / "test.txt"
        # Write bytes that are valid Latin-1 but not valid UTF-8
        path.write_bytes(b"\xe9\xe0\xf1")  # éàñ in Latin-1
        result = read_text_file(path)
        assert len(result) == 3


# =============================================================================
# read_csv_file
# =============================================================================
class TestReadCsvFile:
    def test_basic_csv(self, tmp_path):
        path = tmp_path / "test.csv"
        path.write_text("name,value\nfoo,1\nbar,2", encoding="utf-8")
        rows = read_csv_file(path)
        assert len(rows) == 2
        assert rows[0]["name"] == "foo"

    def test_bom_csv(self, tmp_path):
        path = tmp_path / "test.csv"
        # Write CSV with UTF-8 BOM
        path.write_bytes(b"\xef\xbb\xbfname,value\nfoo,1\n")
        rows = read_csv_file(path)
        assert len(rows) == 1
        assert rows[0]["name"] == "foo"


# =============================================================================
# find_file / find_files
# =============================================================================
class TestFindFiles:
    def test_find_file_exists(self, tmp_path):
        (tmp_path / "subdir").mkdir()
        (tmp_path / "subdir" / "test.csv").write_text("data")
        result = find_file(tmp_path, "**/test.csv")
        assert result is not None
        assert result.name == "test.csv"

    def test_find_file_not_exists(self, tmp_path):
        assert find_file(tmp_path, "**/nonexistent.csv") is None

    def test_find_files_multiple(self, tmp_path):
        (tmp_path / "a.csv").write_text("data")
        (tmp_path / "b.csv").write_text("data")
        results = find_files(tmp_path, "*.csv")
        assert len(results) == 2

    def test_find_files_empty(self, tmp_path):
        results = find_files(tmp_path, "*.xyz")
        assert results == []


# =============================================================================
# _detect_source_gaps (needs EVTX_TIMELINE_LOGS constant)
# =============================================================================
class TestDetectSourceGaps:
    def test_gaps_present(self):
        from query_kape import _detect_source_gaps
        pf_dates = {"2020-11-05", "2020-11-06"}
        ua_dates = {"2020-11-05", "2020-11-06", "2020-11-07"}
        evtx_dates = {"security": {"2020-11-05", "2020-11-06"}}

        warnings = _detect_source_gaps(pf_dates, ua_dates, evtx_dates)
        # Should warn about 2020-11-07 (UserAssist but no Prefetch)
        combined = "\n".join(warnings)
        assert "ANTI-FORENSICS" in combined
        assert "2020-11-07" in combined

    def test_no_gaps(self):
        from query_kape import _detect_source_gaps
        pf_dates = {"2020-11-05", "2020-11-06"}
        ua_dates = {"2020-11-05", "2020-11-06"}
        evtx_dates = {"security": {"2020-11-05", "2020-11-06"}}

        warnings = _detect_source_gaps(pf_dates, ua_dates, evtx_dates)
        combined = "\n".join(warnings)
        assert "ANTI-FORENSICS" not in combined

    def test_empty_sources(self):
        from query_kape import _detect_source_gaps
        warnings = _detect_source_gaps(set(), set(), {})
        combined = "\n".join(warnings)
        assert "(no data)" in combined
