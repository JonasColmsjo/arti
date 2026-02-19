"""Tests for scripts/show-timeline-csv.py — timeline display functions.

Note: This script has a hyphen in its name, so we use importlib to import it.
The module has top-level execution code that calls sys.exit(1) when no CSV data
is provided, so we must mock sys.exit during import.
"""

import csv
import importlib
import sys
from pathlib import Path
from unittest import mock

import pytest

# Import module with hyphen in name — mock sys.exit to prevent crash from
# module-level execution (calls sys.exit(1) when CSV env var is empty).
with mock.patch.object(sys, "exit"):
    stl = importlib.import_module("show-timeline-csv")

trunc = stl.trunc
detect_format = stl.detect_format
read_csvs = stl.read_csvs


# =============================================================================
# trunc
# =============================================================================
class TestTrunc:
    def test_short_string_unchanged(self):
        assert trunc("hello", 10) == "hello"

    def test_exact_length_unchanged(self):
        assert trunc("hello", 5) == "hello"

    def test_long_string_truncated(self):
        result = trunc("hello world", 8)
        assert len(result) == 8
        assert result.endswith("…")
        assert result == "hello w…"

    def test_width_one(self):
        result = trunc("hello", 1)
        assert result == "…"


# =============================================================================
# detect_format
# =============================================================================
class TestDetectFormat:
    def test_t2_format(self):
        rows = [{"phase": "Initial Access", "timestamp_utc": "2020-08-17", "event": "test"}]
        assert detect_format(rows) == "t2"

    def test_t1_format(self):
        rows = [{"seq": "1", "timestamp_utc": "2020-11-06", "event": "test"}]
        assert detect_format(rows) == "t1"

    def test_unknown_empty(self):
        assert detect_format([]) == "unknown"


# =============================================================================
# read_csvs
# =============================================================================
class TestReadCsvs:
    def test_single_file(self, tmp_path):
        csv_path = tmp_path / "timeline.csv"
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["seq", "timestamp_utc", "event"])
            writer.writeheader()
            writer.writerow({"seq": "1", "timestamp_utc": "2020-11-06T10:00:00", "event": "Test event"})
            writer.writerow({"seq": "2", "timestamp_utc": "2020-11-06T10:05:00", "event": "Another event"})

        rows = read_csvs([str(csv_path)])
        assert len(rows) == 2
        assert rows[0]["event"] == "Test event"

    def test_multiple_files(self, tmp_path):
        for i, name in enumerate(["a.csv", "b.csv"]):
            csv_path = tmp_path / name
            with open(csv_path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=["seq", "timestamp_utc", "event"])
                writer.writeheader()
                writer.writerow({"seq": str(i + 1), "timestamp_utc": f"2020-11-0{i+6}T10:00:00", "event": f"Event {name}"})

        rows = read_csvs([str(tmp_path / "a.csv"), str(tmp_path / "b.csv")])
        assert len(rows) == 2

    def test_empty_paths_skipped(self, tmp_path):
        csv_path = tmp_path / "timeline.csv"
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["seq", "event"])
            writer.writeheader()
            writer.writerow({"seq": "1", "event": "Test"})

        rows = read_csvs(["", str(csv_path), "  "])
        assert len(rows) == 1
