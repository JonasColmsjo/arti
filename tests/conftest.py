"""Shared fixtures for gizur-arti forensic framework tests."""

import csv
import io
import os
import sys
from pathlib import Path

import pytest
import yaml

# Add scripts directory to path so modules can be imported
scripts_dir = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(scripts_dir))


@pytest.fixture
def config_dir(tmp_path, monkeypatch):
    """Create a temporary config directory with fixture YAMLs and monkeypatch base module paths."""
    fixtures_dir = Path(__file__).parent / "fixtures"

    # Copy fixture YAMLs to tmp_path
    for name in ("settings.yaml", "artifacts.yaml", "iocs.yaml"):
        src = fixtures_dir / name
        if src.exists():
            (tmp_path / name).write_text(src.read_text())

    # Create a minimal findings.yaml
    findings = {
        "ips": [
            {"value": "83.136.254.57", "note": "C2 server", "status": "suspicious"},
            {"value": "192.168.24.100", "note": "EWS-VM", "status": "benign"},
        ],
        "domains": [
            {"value": "topenergysupport.com", "note": "C2 domain"},
            {"value": "evil.example.com", "note": "test malicious domain"},
        ],
        "processes": [
            {"value": "mimikatz.exe", "note": "credential tool"},
            {"value": "powershell.exe", "note": "scripting engine"},
        ],
        "accounts": [
            {"value": "admin", "note": "admin account"},
            {"value": "SYSTEM", "note": "system account"},
        ],
    }
    (tmp_path / "findings.yaml").write_text(yaml.dump(findings, default_flow_style=False))

    # Monkeypatch the base module globals
    import forensic_analysis.base as base_mod

    monkeypatch.setattr(base_mod, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(base_mod, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(base_mod, "ARTIFACTS_PATH", tmp_path / "artifacts")
    monkeypatch.setattr(base_mod, "FINDINGS_FILE", tmp_path / "findings.yaml")
    monkeypatch.setattr(base_mod, "SETTINGS_FILE", tmp_path / "settings.yaml")
    monkeypatch.setattr(base_mod, "ARTIFACTS_FILE", tmp_path / "artifacts.yaml")
    monkeypatch.setattr(base_mod, "IOCS_FILE", tmp_path / "iocs.yaml")

    return tmp_path


# ---------------------------------------------------------------------------
# Inline sample data fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_flows():
    """Sample flow records as list of dicts."""
    return [
        {
            "timestamp_utc": "2020-08-17T10:00:00",
            "proto": "TCP",
            "src_ip": "192.168.24.100",
            "src_port": "50908",
            "dst_ip": "192.168.24.144",
            "dst_port": "445",
            "frames": 120,
            "bytes": "15360",
            "bytes_num": 15360,
            "capture": "capture1.pcap",
        },
        {
            "timestamp_utc": "2020-08-17T10:05:00",
            "proto": "UDP",
            "src_ip": "192.168.24.100",
            "src_port": "12345",
            "dst_ip": "83.136.254.57",
            "dst_port": "8443",
            "frames": 45,
            "bytes": "5120",
            "bytes_num": 5120,
            "capture": "capture1.pcap",
        },
        {
            "timestamp_utc": "2020-08-17T10:10:00",
            "proto": "TCP",
            "src_ip": "192.168.24.10",
            "src_port": "44818",
            "dst_ip": "192.168.24.100",
            "dst_port": "44818",
            "frames": 200,
            "bytes": "25600",
            "bytes_num": 25600,
            "capture": "capture2.pcap",
        },
        {
            "timestamp_utc": "2020-08-17T10:15:00",
            "proto": "TCP",
            "src_ip": "10.0.0.1",
            "src_port": "443",
            "dst_ip": "192.168.24.100",
            "dst_port": "54321",
            "frames": 80,
            "bytes": "10240",
            "bytes_num": 10240,
            "capture": "capture1.pcap",
        },
    ]


@pytest.fixture
def sample_dns_records():
    """Sample DNS records as list of dicts."""
    return [
        {"timestamp_utc": "2020-08-17T10:00:00", "client_ip": "192.168.24.100", "query_name": "topenergysupport.com.", "response_code": "NOERROR", "answer": "83.136.254.57"},
        {"timestamp_utc": "2020-08-17T10:01:00", "client_ip": "192.168.24.100", "query_name": "google.com.", "response_code": "NOERROR", "answer": "142.250.80.46"},
        {"timestamp_utc": "2020-08-17T10:02:00", "client_ip": "192.168.24.144", "query_name": "xyzabc123random.evil.tld.", "response_code": "NXDOMAIN", "answer": ""},
        {"timestamp_utc": "2020-08-17T10:03:00", "client_ip": "192.168.24.100", "query_name": "dc01.corp.local.", "response_code": "NOERROR", "answer": "10.0.0.1"},
        {"timestamp_utc": "2020-08-17T10:04:00", "client_ip": "192.168.24.144", "query_name": "topenergysupport.com.", "response_code": "NOERROR", "answer": "83.136.254.57"},
        {"timestamp_utc": "2020-08-17T10:05:00", "client_ip": "192.168.24.100", "query_name": "updates.corp.local.", "response_code": "NOERROR", "answer": "10.0.0.5"},
        {"timestamp_utc": "2020-08-17T10:06:00", "client_ip": "192.168.24.100", "query_name": "bxkqtrwpmlnj.suspect.tld.", "response_code": "NXDOMAIN", "answer": ""},
        {"timestamp_utc": "2020-08-17T10:07:00", "client_ip": "192.168.24.10", "query_name": "ntp.ubuntu.com.", "response_code": "NOERROR", "answer": "91.189.89.198"},
    ]


@pytest.fixture
def sample_tls_records():
    """Sample TLS records as list of dicts."""
    return [
        {"timestamp_utc": "2020-08-17T10:00:00", "client_ip": "192.168.24.100", "server_ip": "83.136.254.57", "server_port": "8443", "ja3": "a0e9f5d64349fb13191bc781f81f42e1", "sni": "topenergysupport.com"},
        {"timestamp_utc": "2020-08-17T10:01:00", "client_ip": "192.168.24.100", "server_ip": "142.250.80.46", "server_port": "443", "ja3": "e4f26e13aa0e40bab91d4ffe4bb19cce", "sni": "google.com"},
        {"timestamp_utc": "2020-08-17T10:02:00", "client_ip": "192.168.24.144", "server_ip": "83.136.254.199", "server_port": "8443", "ja3": "72a589da586844d7f0818ce684948eea", "sni": ""},
        {"timestamp_utc": "2020-08-17T10:03:00", "client_ip": "192.168.24.100", "server_ip": "10.0.0.1", "server_port": "443", "ja3": "e4f26e13aa0e40bab91d4ffe4bb19cce", "sni": "dc01.corp.local"},
        {"timestamp_utc": "2020-08-17T10:04:00", "client_ip": "192.168.24.100", "server_ip": "83.136.254.57", "server_port": "8443", "ja3": "a0e9f5d64349fb13191bc781f81f42e1", "sni": "topenergysupport.com"},
    ]


# ---------------------------------------------------------------------------
# CSV file fixtures (write sample data to tmp files)
# ---------------------------------------------------------------------------

@pytest.fixture
def flows_csv(tmp_path, sample_flows):
    """Write sample flows to a CSV file and return the path."""
    path = tmp_path / "flows.csv"
    fieldnames = ["timestamp_utc", "proto", "src_ip", "src_port", "dst_ip", "dst_port", "frames", "bytes", "capture"]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for flow in sample_flows:
            row = {k: flow[k] for k in fieldnames}
            writer.writerow(row)
    return path


@pytest.fixture
def dns_csv(tmp_path, sample_dns_records):
    """Write sample DNS records to a CSV file and return the path."""
    path = tmp_path / "dns.csv"
    fieldnames = ["timestamp_utc", "client_ip", "query_name", "response_code", "answer"]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for rec in sample_dns_records:
            writer.writerow(rec)
    return path


@pytest.fixture
def tls_csv(tmp_path, sample_tls_records):
    """Write sample TLS records to a CSV file and return the path."""
    path = tmp_path / "tls.csv"
    fieldnames = ["timestamp_utc", "client_ip", "server_ip", "server_port", "ja3", "sni"]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for rec in sample_tls_records:
            writer.writerow(rec)
    return path
