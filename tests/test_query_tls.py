"""Tests for scripts/query_tls.py — TLS query functions."""

import pytest

from query_tls import (
    KNOWN_MALICIOUS_JA3,
    cmd_external,
    cmd_ip,
    cmd_ja3,
    cmd_sni,
    cmd_summary,
    load_tls,
)


# =============================================================================
# load_tls
# =============================================================================
class TestLoadTls:
    def test_basic_load(self, tls_csv):
        records = load_tls(tls_csv)
        assert len(records) == 5
        assert records[0]["client_ip"] == "192.168.24.100"


# =============================================================================
# cmd_summary
# =============================================================================
class TestCmdSummary:
    def test_summary_output(self, sample_tls_records, capsys):
        cmd_summary(sample_tls_records)
        output = capsys.readouterr().out
        assert "Total TLS handshakes: 5" in output
        assert "Unique clients:" in output
        assert "UNIQUE JA3 FINGERPRINTS" in output

    def test_malicious_ja3_detected(self, sample_tls_records, capsys):
        cmd_summary(sample_tls_records)
        output = capsys.readouterr().out
        # Our sample data has Cobalt Strike JA3 hashes
        assert "MALICIOUS JA3" in output or "Cobalt Strike" in output

    def test_summary_empty(self, capsys):
        cmd_summary([])
        output = capsys.readouterr().out
        assert "Total TLS handshakes: 0" in output


# =============================================================================
# cmd_ip
# =============================================================================
class TestCmdIp:
    def test_filter_by_ip(self, sample_tls_records, capsys):
        cmd_ip(sample_tls_records, "192.168.24.100")
        output = capsys.readouterr().out
        assert "192.168.24.100" in output

    def test_malicious_ja3_warning(self, sample_tls_records, capsys):
        cmd_ip(sample_tls_records, "192.168.24.100")
        output = capsys.readouterr().out
        assert "MALICIOUS JA3" in output

    def test_no_matches(self, sample_tls_records, capsys):
        cmd_ip(sample_tls_records, "1.2.3.4")
        output = capsys.readouterr().out
        assert "TLS connections from 1.2.3.4: 0" in output


# =============================================================================
# cmd_sni
# =============================================================================
class TestCmdSni:
    def test_sni_output(self, sample_tls_records, capsys):
        cmd_sni(sample_tls_records)
        output = capsys.readouterr().out
        assert "topenergysupport.com" in output
        assert "google.com" in output
        assert "Unique SNI" in output

    def test_no_sni_shows_placeholder(self, capsys):
        records = [
            {"timestamp_utc": "2020-01-01", "client_ip": "1.2.3.4",
             "server_ip": "5.6.7.8", "server_port": "443", "ja3": "abc", "sni": ""},
        ]
        cmd_sni(records)
        output = capsys.readouterr().out
        assert "(no SNI)" in output


# =============================================================================
# cmd_ja3
# =============================================================================
class TestCmdJa3:
    def test_ja3_search(self, sample_tls_records, capsys):
        cmd_ja3(sample_tls_records, "a0e9f5d64349fb13191bc781f81f42e1")
        output = capsys.readouterr().out
        assert "192.168.24.100" in output
        assert "Cobalt Strike" in output

    def test_ja3_no_match(self, sample_tls_records, capsys):
        cmd_ja3(sample_tls_records, "nonexistent_hash")
        output = capsys.readouterr().out
        assert "0" in output

    def test_ja3_substring_match(self, sample_tls_records, capsys):
        # Use partial hash
        cmd_ja3(sample_tls_records, "a0e9f5d6")
        output = capsys.readouterr().out
        assert "192.168.24.100" in output


# =============================================================================
# cmd_external
# =============================================================================
class TestCmdExternal:
    def test_external_servers(self, sample_tls_records, capsys):
        cmd_external(sample_tls_records)
        output = capsys.readouterr().out
        assert "83.136.254.57" in output or "142.250.80.46" in output
        assert "external servers" in output.lower()

    def test_private_servers_excluded(self, capsys):
        records = [
            {"timestamp_utc": "2020-01-01", "client_ip": "192.168.24.100",
             "server_ip": "10.0.0.1", "server_port": "443", "ja3": "abc", "sni": "internal"},
        ]
        cmd_external(records)
        output = capsys.readouterr().out
        assert "TLS connections to external servers: 0" in output


# =============================================================================
# KNOWN_MALICIOUS_JA3
# =============================================================================
class TestKnownMaliciousJa3:
    def test_cobalt_strike_present(self):
        assert "a0e9f5d64349fb13191bc781f81f42e1" in KNOWN_MALICIOUS_JA3
        assert KNOWN_MALICIOUS_JA3["a0e9f5d64349fb13191bc781f81f42e1"] == "Cobalt Strike"

    def test_metasploit_present(self):
        assert "51c64c77e60f3980eea90869b68c58a8" in KNOWN_MALICIOUS_JA3
