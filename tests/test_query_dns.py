"""Tests for scripts/query_dns.py — DNS query functions."""

import pytest

from query_dns import (
    cmd_domain,
    cmd_external,
    cmd_ip,
    cmd_nxdomain,
    cmd_summary,
    load_dns,
)


# =============================================================================
# load_dns
# =============================================================================
class TestLoadDns:
    def test_basic_load(self, dns_csv):
        records = load_dns(dns_csv)
        assert len(records) == 8
        assert records[0]["query_name"] == "topenergysupport.com."


# =============================================================================
# cmd_summary
# =============================================================================
class TestCmdSummary:
    def test_summary_output(self, sample_dns_records, capsys):
        cmd_summary(sample_dns_records)
        output = capsys.readouterr().out
        assert "Total DNS records: 8" in output
        assert "Unique domains:" in output
        assert "topenergysupport.com" in output

    def test_summary_empty(self, capsys):
        cmd_summary([])
        output = capsys.readouterr().out
        assert "Total DNS records: 0" in output


# =============================================================================
# cmd_ip
# =============================================================================
class TestCmdIp:
    def test_filter_by_ip(self, sample_dns_records, capsys):
        cmd_ip(sample_dns_records, "192.168.24.100")
        output = capsys.readouterr().out
        assert "192.168.24.100" in output
        assert "topenergysupport.com" in output

    def test_no_matches(self, sample_dns_records, capsys):
        cmd_ip(sample_dns_records, "1.2.3.4")
        output = capsys.readouterr().out
        assert "DNS queries from 1.2.3.4: 0" in output


# =============================================================================
# cmd_nxdomain
# =============================================================================
class TestCmdNxdomain:
    def test_nxdomain_found(self, sample_dns_records, capsys):
        cmd_nxdomain(sample_dns_records)
        output = capsys.readouterr().out
        assert "NXDOMAIN responses: 2" in output
        assert "xyzabc123random.evil.tld" in output

    def test_nxdomain_empty(self, capsys):
        records = [
            {"timestamp_utc": "2020-01-01", "client_ip": "1.2.3.4",
             "query_name": "google.com.", "response_code": "NOERROR", "answer": "1.2.3.4"},
        ]
        cmd_nxdomain(records)
        output = capsys.readouterr().out
        assert "No NXDOMAIN" in output

    def test_dga_analysis_section(self, sample_dns_records, capsys):
        cmd_nxdomain(sample_dns_records)
        output = capsys.readouterr().out
        assert "DGA ANALYSIS" in output


# =============================================================================
# cmd_domain
# =============================================================================
class TestCmdDomain:
    def test_domain_search(self, sample_dns_records, capsys):
        cmd_domain(sample_dns_records, "topenergy")
        output = capsys.readouterr().out
        assert "topenergysupport.com" in output
        assert "Domains matching" in output

    def test_domain_no_match(self, sample_dns_records, capsys):
        cmd_domain(sample_dns_records, "nonexistent.xyz")
        output = capsys.readouterr().out
        assert "Domains matching 'nonexistent.xyz': 0" in output

    def test_case_insensitive(self, sample_dns_records, capsys):
        cmd_domain(sample_dns_records, "TOPENERGY")
        output = capsys.readouterr().out
        assert "topenergysupport.com" in output


# =============================================================================
# cmd_external
# =============================================================================
class TestCmdExternal:
    def test_external_domains(self, sample_dns_records, capsys):
        cmd_external(sample_dns_records)
        output = capsys.readouterr().out
        assert "External domain queries:" in output
        # External domains should be present
        assert "topenergysupport.com" in output or "google.com" in output

    def test_local_domain_filtered(self, capsys):
        """Domains without trailing dots are filtered by local_suffixes."""
        records = [
            {"timestamp_utc": "2020-01-01", "client_ip": "1.2.3.4",
             "query_name": "dc01.corp.local", "response_code": "NOERROR", "answer": "10.0.0.1"},
            {"timestamp_utc": "2020-01-01", "client_ip": "1.2.3.4",
             "query_name": "host.in-addr.arpa", "response_code": "NOERROR", "answer": ""},
        ]
        cmd_external(records)
        output = capsys.readouterr().out
        assert "External domain queries: 0" in output
