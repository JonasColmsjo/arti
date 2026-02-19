"""Tests for scripts/query_flows.py — pure-logic flow query functions."""

import csv
from pathlib import Path

import pytest

from query_flows import (
    cmd_beacon,
    cmd_summary,
    cmd_top_ips,
    cmd_top_ports,
    get_port_protocol,
    hex_dump_formatted,
    ip_matches,
    is_private_ip,
    load_flows,
)


# =============================================================================
# get_port_protocol
# =============================================================================
class TestGetPortProtocol:
    def test_known_ftp(self):
        assert get_port_protocol(21) == "FTP"

    def test_known_https(self):
        assert get_port_protocol(443) == "HTTPS"

    def test_known_ssh_str(self):
        assert get_port_protocol("22") == "SSH"

    def test_known_smb(self):
        assert get_port_protocol(445) == "SMB"

    def test_known_rdp(self):
        assert get_port_protocol(3389) == "RDP"

    def test_known_enip(self):
        assert get_port_protocol(44818) == "ENIP/CIP"

    def test_known_modbus(self):
        assert get_port_protocol(502) == "MODBUS"

    def test_unknown_returns_empty(self):
        assert get_port_protocol(99999) == ""


# =============================================================================
# is_private_ip
# =============================================================================
class TestIsPrivateIp:
    def test_192_168(self):
        assert is_private_ip("192.168.1.1") is True

    def test_10_x(self):
        assert is_private_ip("10.0.0.1") is True

    def test_172_16(self):
        assert is_private_ip("172.16.0.1") is True

    def test_172_24(self):
        assert is_private_ip("172.24.0.1") is True

    def test_172_31(self):
        assert is_private_ip("172.31.0.1") is True

    def test_multicast_224(self):
        assert is_private_ip("224.0.0.1") is True

    def test_multicast_239(self):
        assert is_private_ip("239.255.255.250") is True

    def test_public_ip(self):
        assert is_private_ip("83.136.254.57") is False

    def test_public_8_8_8_8(self):
        assert is_private_ip("8.8.8.8") is False

    def test_link_local_ipv6(self):
        assert is_private_ip("fe80::1") is True


# =============================================================================
# ip_matches
# =============================================================================
class TestIpMatches:
    def test_exact_match(self):
        assert ip_matches("192.168.24.100", "192.168.24.100") is True

    def test_exact_no_match(self):
        assert ip_matches("192.168.24.100", "192.168.24.200") is False

    def test_wildcard_x(self):
        assert ip_matches("192.168.24.100", "192.168.24.x") is True

    def test_wildcard_star(self):
        assert ip_matches("192.168.24.100", "192.168.24.*") is True

    def test_wildcard_no_match(self):
        assert ip_matches("192.168.25.100", "192.168.24.x") is False

    def test_subnet_prefix_match(self):
        assert ip_matches("192.168.24.100", "192.168.24") is True

    def test_substring_match(self):
        assert ip_matches("192.168.24.100", "168.24") is True

    def test_no_match(self):
        assert ip_matches("10.0.0.1", "192.168") is False


# =============================================================================
# load_flows
# =============================================================================
class TestLoadFlows:
    def test_basic_load(self, flows_csv):
        flows = load_flows(flows_csv)
        assert len(flows) == 4
        assert flows[0]["src_ip"] == "192.168.24.100"

    def test_frames_parsed_as_int(self, flows_csv):
        flows = load_flows(flows_csv)
        assert isinstance(flows[0]["frames"], int)
        assert flows[0]["frames"] == 120

    def test_bytes_num_parsed(self, flows_csv):
        flows = load_flows(flows_csv)
        assert flows[0]["bytes_num"] == 15360

    def test_kb_suffix_parsing(self, tmp_path):
        csv_path = tmp_path / "test.csv"
        with open(csv_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp_utc", "proto", "src_ip", "src_port", "dst_ip", "dst_port", "frames", "bytes", "capture"])
            writer.writerow(["2020-08-17T10:00:00", "TCP", "1.2.3.4", "80", "5.6.7.8", "443", "10", "1.5kB", "test.pcap"])
        flows = load_flows(csv_path)
        assert flows[0]["bytes_num"] == int(1.5 * 1024)

    def test_mb_suffix_parsing(self, tmp_path):
        csv_path = tmp_path / "test.csv"
        with open(csv_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp_utc", "proto", "src_ip", "src_port", "dst_ip", "dst_port", "frames", "bytes", "capture"])
            writer.writerow(["2020-08-17T10:00:00", "TCP", "1.2.3.4", "80", "5.6.7.8", "443", "10", "2MB", "test.pcap"])
        flows = load_flows(csv_path)
        assert flows[0]["bytes_num"] == 2 * 1024 * 1024

    def test_bytes_suffix_parsing(self, tmp_path):
        csv_path = tmp_path / "test.csv"
        with open(csv_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp_utc", "proto", "src_ip", "src_port", "dst_ip", "dst_port", "frames", "bytes", "capture"])
            writer.writerow(["2020-08-17T10:00:00", "TCP", "1.2.3.4", "80", "5.6.7.8", "443", "10", "1024 bytes", "test.pcap"])
        flows = load_flows(csv_path)
        assert flows[0]["bytes_num"] == 1024


# =============================================================================
# hex_dump_formatted
# =============================================================================
class TestHexDumpFormatted:
    def test_small_data(self, capsys):
        hex_dump_formatted(b"\x48\x65\x6c\x6c\x6f")
        output = capsys.readouterr().out
        assert "48 65 6c 6c 6f" in output
        assert "Hello" in output

    def test_multiline(self, capsys):
        data = bytes(range(32))
        hex_dump_formatted(data)
        output = capsys.readouterr().out
        lines = output.strip().split("\n")
        assert len(lines) == 2  # 32 bytes / 16 per line

    def test_non_printable_shows_dot(self, capsys):
        hex_dump_formatted(b"\x00\x01\x02")
        output = capsys.readouterr().out
        assert "..." in output


# =============================================================================
# cmd_summary
# =============================================================================
class TestCmdSummary:
    def test_prints_summary(self, sample_flows, capsys):
        cmd_summary(sample_flows)
        output = capsys.readouterr().out
        assert "Total flows: 4" in output
        assert "Total frames:" in output
        assert "TCP" in output
        assert "UDP" in output

    def test_empty_flows(self, capsys):
        cmd_summary([])
        output = capsys.readouterr().out
        assert "Total flows: 0" in output


# =============================================================================
# cmd_top_ips
# =============================================================================
class TestCmdTopIps:
    def test_top_ips(self, sample_flows, capsys):
        cmd_top_ips(sample_flows, 5)
        output = capsys.readouterr().out
        assert "192.168.24.100" in output
        assert "Top 5 IPs" in output

    def test_aggregation(self, sample_flows, capsys):
        cmd_top_ips(sample_flows, 10)
        output = capsys.readouterr().out
        # 192.168.24.100 appears in all 4 flows (src or dst)
        assert "192.168.24.100" in output


# =============================================================================
# cmd_top_ports
# =============================================================================
class TestCmdTopPorts:
    def test_top_ports(self, sample_flows, capsys):
        cmd_top_ports(sample_flows, 5)
        output = capsys.readouterr().out
        assert "445" in output or "8443" in output
        assert "Top 5 ports" in output

    def test_shows_service_name(self, sample_flows, capsys):
        cmd_top_ports(sample_flows, 20)
        output = capsys.readouterr().out
        assert "SMB" in output or "HTTPS-ALT" in output


# =============================================================================
# cmd_beacon
# =============================================================================
class TestCmdBeacon:
    def test_no_beacons_with_few_flows(self, sample_flows, capsys):
        cmd_beacon(sample_flows)
        output = capsys.readouterr().out
        assert "No significant beacon" in output or "Potential beacons" in output

    def test_regular_intervals_detected(self, capsys):
        """Create flows with regular intervals that should score as beacons."""
        from datetime import datetime, timedelta

        flows = []
        base_time = datetime(2020, 8, 17, 10, 0, 0)
        for i in range(25):
            flows.append({
                "timestamp_utc": (base_time + timedelta(seconds=60 * i)).isoformat(),
                "proto": "TCP",
                "src_ip": "192.168.24.100",
                "src_port": "12345",
                "dst_ip": "83.136.254.57",
                "dst_port": "8443",
                "frames": 10,
                "bytes_num": 1024,
                "capture": "test.pcap",
            })
        cmd_beacon(flows)
        output = capsys.readouterr().out
        assert "Potential beacons" in output or "BEACON" in output

    def test_random_intervals_not_detected(self, capsys):
        """Random intervals should not trigger beacon detection."""
        import random
        from datetime import datetime, timedelta

        random.seed(42)
        flows = []
        base_time = datetime(2020, 8, 17, 10, 0, 0)
        t = base_time
        for i in range(10):
            t += timedelta(seconds=random.randint(1, 3600))
            flows.append({
                "timestamp_utc": t.isoformat(),
                "proto": "TCP",
                "src_ip": "192.168.24.100",
                "src_port": str(random.randint(1024, 65535)),
                "dst_ip": "10.0.0.1",
                "dst_port": "80",
                "frames": random.randint(1, 100),
                "bytes_num": random.randint(100, 100000),
                "capture": "test.pcap",
            })
        cmd_beacon(flows)
        output = capsys.readouterr().out
        # With random intervals and only 10 connections, should not find strong beacons
        assert "No significant beacon" in output or "LOW" in output or "Potential" in output

    def test_flows_without_timestamps(self, capsys):
        """Flows without timestamps should not crash."""
        flows = [
            {"proto": "TCP", "src_ip": "1.2.3.4", "src_port": "80",
             "dst_ip": "5.6.7.8", "dst_port": "443", "frames": 10, "bytes_num": 100, "capture": "x"},
        ]
        cmd_beacon(flows)
        output = capsys.readouterr().out
        assert "No significant beacon" in output
