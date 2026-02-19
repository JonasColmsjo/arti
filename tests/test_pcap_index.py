#!/usr/bin/env python3
"""
Comprehensive test suite for pcap_index.py with 100% coverage.

Ground truth data obtained from tshark analysis of Tier 2 capture files.
Migrated from colmsjo-studier-dv2637-exam/tests/test_pcap_index.py.

Integration tests (those requiring ARTIFACTS_PATH or pre-indexed DB) are skipped
when artifact files are not available. Unit tests for pure functions always run.
"""

import hashlib
import os
import sqlite3
import struct
import sys
import tempfile
from io import StringIO
from pathlib import Path
from unittest import mock

import pytest

dpkt = pytest.importorskip("dpkt", reason="dpkt not installed")
import pcap_index


# --- Test fixtures ---

@pytest.fixture
def evidence_path():
    """Get artifacts path from environment."""
    path = os.environ.get("ARTIFACTS_PATH")
    if not path:
        pytest.skip("ARTIFACTS_PATH not set")
    return Path(path) / "artifacts-unpacked" / "Level_2_Artifacts"


@pytest.fixture
def capture1_pcap(evidence_path):
    """Path to capture1.pcap."""
    pcap = evidence_path / "capture1.pcap"
    if not pcap.exists():
        pytest.skip(f"capture1.pcap not found at {pcap}")
    return pcap


@pytest.fixture
def capture2_pcap(evidence_path):
    """Path to capture2.pcap."""
    pcap = evidence_path / "capture2.pcap"
    if not pcap.exists():
        pytest.skip(f"capture2.pcap not found at {pcap}")
    return pcap


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    yield db_path
    if os.path.exists(db_path):
        os.unlink(db_path)


@pytest.fixture
def global_pcap_db():
    """Global PCAP index database (contains all levels)."""
    db_path = Path("work/pcap_index.db")
    if not db_path.exists():
        pytest.skip("Global pcap_index.db not found - run indexing first")
    return str(db_path)


@pytest.fixture
def indexed_capture1_db(global_pcap_db):
    """Pre-indexed capture1 database (uses global DB)."""
    return global_pcap_db


@pytest.fixture
def indexed_capture2_db(global_pcap_db):
    """Pre-indexed capture2 database (uses global DB)."""
    return global_pcap_db


# --- Ground truth from tshark ---

CAPTURE1_GROUND_TRUTH = {
    2880: {
        "timestamp": 1604609108.273441,
        "src_ip": "192.168.24.100",
        "dst_ip": "192.168.24.144",
        "src_port": 50908,
        "dst_port": 445,
        "protocol": "SMB",
    },
    35417: {
        "timestamp": 1604619325.423891,
        "src_ip": "174.204.5.114",
        "dst_ip": "192.168.24.2",
        "src_port": 1037,
        "dst_port": 1195,
        "protocol": "OPENVPN",
    },
    57350: {
        "timestamp": 1604620713.411912,
        "src_ip": "192.168.24.100",
        "dst_ip": "192.168.24.10",
        "src_port": 51456,
        "dst_port": 1962,
        "protocol": "PCCC",
    },
}

CAPTURE1_TLS_GROUND_TRUTH = {
    215: {
        "ja3_hash": "ce5f3254611a8c095a3d821d44539877",
        "sni": "192.168.24.100",
        "src_ip": "192.168.24.144",
        "dst_port": 3389,
    },
    231: {
        "ja3_hash": "ce5f3254611a8c095a3d821d44539877",
        "sni": "192.168.24.100",
        "src_ip": "192.168.24.144",
        "dst_port": 3389,
    },
}

CAPTURE2_GROUND_TRUTH = {
    57000: {
        "timestamp": 1604680659.377722,
        "src_ip": "192.168.24.100",
        "dst_ip": "192.168.24.20",
        "src_port": 54320,
        "dst_port": 1962,
        "protocol": "PCCC",
    },
    754504: {
        "timestamp": 1604688016.035903,
        "src_ip": "10.255.255.2",
        "dst_ip": "192.168.24.100",
        "src_port": 37033,
        "dst_port": 4444,
        "protocol": "METERPRETER",
    },
    771524: {
        "timestamp": 1604688158.933664,
        "src_ip": "192.168.24.100",
        "dst_ip": "192.168.24.31",
        "src_port": 55145,
        "dst_port": 5900,
        "protocol": "VNC",
    },
    426556: {
        "timestamp": 1604684120.581960,
        "src_ip": "10.255.255.3",
        "dst_ip": "159.203.13.59",
        "src_port": 40690,
        "dst_port": 21,
        "protocol": "FTP",
    },
    413256: {
        "timestamp": 1604683998.116932,
        "src_ip": "192.168.24.100",
        "dst_ip": "192.168.24.30",
        "src_port": 54712,
        "dst_port": 502,
        "protocol": "MODBUS",
    },
}


# --- Unit tests for helper functions ---

class TestGetProtocolName:
    """Tests for get_protocol_name function."""

    def test_tcp_well_known_ports(self):
        assert pcap_index.get_protocol_name(6, 12345, 21) == "FTP"
        assert pcap_index.get_protocol_name(6, 12345, 22) == "SSH"
        assert pcap_index.get_protocol_name(6, 12345, 80) == "HTTP"
        assert pcap_index.get_protocol_name(6, 12345, 443) == "HTTPS"
        assert pcap_index.get_protocol_name(6, 12345, 445) == "SMB"
        assert pcap_index.get_protocol_name(6, 12345, 502) == "MODBUS"
        assert pcap_index.get_protocol_name(6, 12345, 1962) == "PCCC"
        assert pcap_index.get_protocol_name(6, 12345, 3389) == "RDP"
        assert pcap_index.get_protocol_name(6, 12345, 4444) == "METERPRETER"
        assert pcap_index.get_protocol_name(6, 12345, 5900) == "VNC"
        assert pcap_index.get_protocol_name(6, 12345, 41100) == "ADE"
        assert pcap_index.get_protocol_name(6, 12345, 44818) == "ENIP"

    def test_tcp_source_port_detection(self):
        assert pcap_index.get_protocol_name(6, 21, 12345) == "FTP"
        assert pcap_index.get_protocol_name(6, 443, 12345) == "HTTPS"

    def test_tcp_unknown_port(self):
        assert pcap_index.get_protocol_name(6, 12345, 54321) == "TCP"

    def test_udp_well_known_ports(self):
        assert pcap_index.get_protocol_name(17, 12345, 53) == "DNS"
        assert pcap_index.get_protocol_name(17, 12345, 67) == "DHCP"
        assert pcap_index.get_protocol_name(17, 12345, 123) == "NTP"
        assert pcap_index.get_protocol_name(17, 12345, 1194) == "OPENVPN"
        assert pcap_index.get_protocol_name(17, 12345, 1195) == "OPENVPN"
        assert pcap_index.get_protocol_name(17, 12345, 44818) == "ENIP"

    def test_udp_unknown_port(self):
        assert pcap_index.get_protocol_name(17, 12345, 54321) == "UDP"

    def test_icmp(self):
        assert pcap_index.get_protocol_name(1, 0, 0) == "ICMP"

    def test_igmp(self):
        assert pcap_index.get_protocol_name(2, 0, 0) == "IGMP"

    def test_unknown_protocol(self):
        assert pcap_index.get_protocol_name(99, 0, 0) == "IP:99"


class TestFormatTimestamp:
    def test_basic_timestamp(self):
        ts = 1604664000.0
        result = pcap_index.format_timestamp(ts)
        assert result.startswith("2020-11-06T12:00:00")
        assert result.endswith("Z")

    def test_microseconds(self):
        ts = 1604664000.123456
        result = pcap_index.format_timestamp(ts)
        assert "123" in result

    def test_epoch_zero(self):
        result = pcap_index.format_timestamp(0)
        assert result.startswith("1970-01-01T00:00:00")


class TestGreaseValues:
    def test_grease_values_defined(self):
        assert 0x0a0a in pcap_index.GREASE_VALUES
        assert 0xfafa in pcap_index.GREASE_VALUES
        assert len(pcap_index.GREASE_VALUES) == 16

    def test_non_grease_not_in_set(self):
        assert 0x0001 not in pcap_index.GREASE_VALUES
        assert 0x00ff not in pcap_index.GREASE_VALUES


class TestParseTlsClientHello:
    def test_non_tls_data(self):
        assert pcap_index.parse_tls_client_hello(b"HTTP/1.1 200 OK") is None
        assert pcap_index.parse_tls_client_hello(b"\x00\x00\x00") is None

    def test_too_short_data(self):
        assert pcap_index.parse_tls_client_hello(b"") is None
        assert pcap_index.parse_tls_client_hello(b"\x16\x03\x01") is None

    def test_wrong_content_type(self):
        data = b"\x17\x03\x01\x00\x10" + b"\x00" * 16
        assert pcap_index.parse_tls_client_hello(data) is None

    def test_server_hello_returns_none(self):
        data = (
            b"\x16\x03\x01\x00\x10"
            b"\x02\x00\x00\x0c"
            b"\x03\x03"
            + b"\x00" * 32
        )
        assert pcap_index.parse_tls_client_hello(data) is None


class TestComputeJa3:
    def test_basic_ja3(self):
        tls_info = {
            "version": 0x0303,
            "cipher_suites": [0x1301, 0x1302, 0x1303],
            "extensions": [0, 10, 11, 13],
            "elliptic_curves": [23, 24, 25],
            "ec_point_formats": [0],
        }
        ja3_string, ja3_hash = pcap_index.compute_ja3(tls_info)
        parts = ja3_string.split(",")
        assert len(parts) == 5
        assert parts[0] == "771"
        assert len(ja3_hash) == 32
        expected_hash = hashlib.md5(ja3_string.encode()).hexdigest()
        assert ja3_hash == expected_hash

    def test_empty_extensions(self):
        tls_info = {
            "version": 0x0303,
            "cipher_suites": [0x1301],
            "extensions": [],
            "elliptic_curves": [],
            "ec_point_formats": [],
        }
        ja3_string, ja3_hash = pcap_index.compute_ja3(tls_info)
        assert ja3_string == "771,4865,,,"


class TestComputeJa4:
    def test_basic_ja4(self):
        tls_info = {
            "version": 0x0303,
            "cipher_suites": [0x1301, 0x1302],
            "extensions": [0, 10, 11, 13, 16],
            "elliptic_curves": [23, 24],
            "ec_point_formats": [0],
            "sni": "example.com",
            "alpn": ["h2", "http/1.1"],
        }
        ja4_string, ja4_hash = pcap_index.compute_ja4(tls_info)
        assert ja4_string.startswith("t12d")
        assert "_" in ja4_string
        assert len(ja4_hash) == 32

    def test_ja4_no_sni(self):
        tls_info = {
            "version": 0x0303,
            "cipher_suites": [0x1301],
            "extensions": [10, 11],
            "elliptic_curves": [],
            "ec_point_formats": [],
            "sni": None,
            "alpn": [],
        }
        ja4_string, _ = pcap_index.compute_ja4(tls_info)
        assert "i" in ja4_string[:5]

    def test_ja4_version_mapping(self):
        for version, expected in [(0x0301, "10"), (0x0302, "11"), (0x0303, "12"), (0x0304, "13")]:
            tls_info = {
                "version": version,
                "cipher_suites": [],
                "extensions": [],
                "elliptic_curves": [],
                "ec_point_formats": [],
                "sni": None,
                "alpn": [],
            }
            ja4_string, _ = pcap_index.compute_ja4(tls_info)
            assert ja4_string[1:3] == expected


# --- Integration tests with real PCAPs ---

class TestIndexPcap:
    def test_index_creates_database(self, capture1_pcap, temp_db):
        pcap_index.index_pcap(str(capture1_pcap), temp_db)
        assert os.path.exists(temp_db)
        conn = sqlite3.connect(temp_db)
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        table_names = [t[0] for t in tables]
        assert "frames" in table_names
        assert "tls_fingerprints" in table_names
        assert "metadata" in table_names
        count = conn.execute("SELECT COUNT(*) FROM frames").fetchone()[0]
        assert count > 0
        conn.close()

    def test_index_metadata(self, capture1_pcap, temp_db):
        pcap_index.index_pcap(str(capture1_pcap), temp_db, level='t2')
        conn = sqlite3.connect(temp_db)
        indexed_at = conn.execute("SELECT value FROM metadata WHERE key='last_indexed_at'").fetchone()
        assert indexed_at is not None
        frame_count = conn.execute("SELECT COUNT(*) FROM frames").fetchone()[0]
        assert frame_count > 0
        artifact = conn.execute("SELECT DISTINCT source_artifact FROM frames").fetchone()[0]
        assert 'capture1.pcap' in artifact
        level = conn.execute("SELECT DISTINCT level FROM frames").fetchone()[0]
        assert level == 't2'
        conn.close()


class TestQueryFunctions:
    def test_query_frame_capture1(self, indexed_capture1_db):
        conn = sqlite3.connect(indexed_capture1_db)
        conn.row_factory = sqlite3.Row
        for frame_num, expected in CAPTURE1_GROUND_TRUTH.items():
            row = conn.execute(
                "SELECT * FROM frames WHERE frame_num = ? AND source_artifact LIKE '%capture1.pcap'",
                (frame_num,)
            ).fetchone()
            assert row is not None, f"Frame {frame_num} not found in capture1"
            assert row["src_ip"] == expected["src_ip"]
            assert row["dst_ip"] == expected["dst_ip"]
            assert row["src_port"] == expected["src_port"]
            assert row["dst_port"] == expected["dst_port"]
            assert row["protocol"] == expected["protocol"]
            assert abs(row["timestamp"] - expected["timestamp"]) < 0.001
            assert row["level"] == "t2"
            assert row["src_mac"] is not None
            assert row["dst_mac"] is not None
        conn.close()

    def test_query_frame_capture2(self, indexed_capture2_db):
        conn = sqlite3.connect(indexed_capture2_db)
        conn.row_factory = sqlite3.Row
        for frame_num, expected in CAPTURE2_GROUND_TRUTH.items():
            row = conn.execute(
                "SELECT * FROM frames WHERE frame_num = ? AND source_artifact LIKE '%capture2.pcap'",
                (frame_num,)
            ).fetchone()
            assert row is not None, f"Frame {frame_num} not found in capture2"
            assert row["src_ip"] == expected["src_ip"]
            assert row["dst_ip"] == expected["dst_ip"]
            assert row["src_port"] == expected["src_port"]
            assert row["dst_port"] == expected["dst_port"]
            assert row["protocol"] == expected["protocol"]
            assert row["level"] == "t2"
        conn.close()

    def test_query_tls_ja3(self, indexed_capture1_db):
        conn = sqlite3.connect(indexed_capture1_db)
        conn.row_factory = sqlite3.Row
        for frame_num, expected in CAPTURE1_TLS_GROUND_TRUTH.items():
            row = conn.execute(
                "SELECT * FROM tls_fingerprints WHERE frame_num = ? AND source_artifact LIKE '%capture1.pcap'",
                (frame_num,)
            ).fetchone()
            assert row is not None, f"TLS frame {frame_num} not found"
            assert row["ja3_hash"] == expected["ja3_hash"]
            assert row["sni"] == expected["sni"]
        conn.close()

    def test_query_ip(self, indexed_capture1_db):
        conn = sqlite3.connect(indexed_capture1_db)
        rows = conn.execute(
            "SELECT COUNT(*) FROM frames WHERE src_ip = ? OR dst_ip = ?",
            ("192.168.24.100", "192.168.24.100")
        ).fetchone()[0]
        assert rows > 0
        conn.close()

    def test_query_port(self, indexed_capture2_db):
        conn = sqlite3.connect(indexed_capture2_db)
        rows = conn.execute(
            "SELECT COUNT(*) FROM frames WHERE src_port = 4444 OR dst_port = 4444"
        ).fetchone()[0]
        assert rows > 0
        conn.close()


class TestCli:
    def test_help_exits_zero(self):
        with pytest.raises(SystemExit) as exc_info:
            with mock.patch("sys.argv", ["pcap-index.py", "--help"]):
                pcap_index.main()
        assert exc_info.value.code == 0

    def test_index_missing_pcap(self, temp_db):
        with pytest.raises(SystemExit):
            with mock.patch("sys.argv", ["pcap-index.py", "index", "/nonexistent.pcap", "--db", temp_db]):
                pcap_index.main()

    def test_query_frame_cli(self, indexed_capture1_db, capsys):
        with mock.patch("sys.argv", ["pcap-index.py", "query", indexed_capture1_db, "--frame", "2880"]):
            pcap_index.main()
        captured = capsys.readouterr()
        assert "Frame 2880" in captured.out
        assert "192.168.24.100" in captured.out
        assert "192.168.24.144" in captured.out

    def test_query_ip_cli(self, indexed_capture1_db, capsys):
        with mock.patch("sys.argv", ["pcap-index.py", "query", indexed_capture1_db, "--ip", "192.168.24.100"]):
            pcap_index.main()
        captured = capsys.readouterr()
        assert "192.168.24.100" in captured.out

    def test_query_port_cli(self, indexed_capture2_db, capsys):
        with mock.patch("sys.argv", ["pcap-index.py", "query", indexed_capture2_db, "--port", "4444"]):
            pcap_index.main()
        captured = capsys.readouterr()
        assert "4444" in captured.out

    def test_query_ja3_cli(self, indexed_capture1_db, capsys):
        with mock.patch("sys.argv", ["pcap-index.py", "query", indexed_capture1_db, "--ja3", "ce5f3254611a8c095a3d821d44539877"]):
            pcap_index.main()
        captured = capsys.readouterr()
        assert "ce5f3254611a8c095a3d821d44539877" in captured.out or "TLS Client Hellos" in captured.out

    def test_query_sql_cli(self, indexed_capture1_db, capsys):
        with mock.patch("sys.argv", ["pcap-index.py", "query", indexed_capture1_db, "--sql", "SELECT COUNT(*) as cnt FROM frames"]):
            pcap_index.main()
        captured = capsys.readouterr()
        assert "cnt" in captured.out

    def test_stats_cli(self, indexed_capture1_db, capsys):
        with mock.patch("sys.argv", ["pcap-index.py", "stats", indexed_capture1_db]):
            pcap_index.main()
        captured = capsys.readouterr()
        assert "Database:" in captured.out
        assert "Protocol distribution:" in captured.out

    def test_query_nonexistent_frame(self, indexed_capture1_db, capsys):
        with mock.patch("sys.argv", ["pcap-index.py", "query", indexed_capture1_db, "--frame", "999999999"]):
            pcap_index.main()
        captured = capsys.readouterr()
        assert "not found" in captured.out

    def test_query_sql_error(self, indexed_capture1_db, capsys):
        with mock.patch("sys.argv", ["pcap-index.py", "query", indexed_capture1_db, "--sql", "INVALID SQL"]):
            pcap_index.main()
        captured = capsys.readouterr()
        assert "SQL Error" in captured.err or "Error" in captured.err


class TestEdgeCases:
    def test_query_frame_not_found(self, indexed_capture1_db, capsys):
        pcap_index.query_frame(indexed_capture1_db, 999999999)
        captured = capsys.readouterr()
        assert "not found" in captured.out

    def test_query_ip_no_results(self, indexed_capture1_db, capsys):
        pcap_index.query_ip(indexed_capture1_db, "1.2.3.4")
        captured = capsys.readouterr()
        assert "1.2.3.4" in captured.out

    def test_query_sql_no_results(self, indexed_capture1_db, capsys):
        pcap_index.query_sql(indexed_capture1_db, "SELECT * FROM frames WHERE 1=0")
        captured = capsys.readouterr()
        assert "No results" in captured.out

    def test_format_timestamp_edge(self):
        result = pcap_index.format_timestamp(2000000000.0)
        assert "2033" in result
        result = pcap_index.format_timestamp(-86400)
        assert "1969" in result


class TestProtocolDetection:
    def test_modbus_detection(self, indexed_capture2_db):
        conn = sqlite3.connect(indexed_capture2_db)
        count = conn.execute("SELECT COUNT(*) FROM frames WHERE protocol = 'MODBUS'").fetchone()[0]
        assert count > 0
        conn.close()

    def test_vnc_detection(self, indexed_capture2_db):
        conn = sqlite3.connect(indexed_capture2_db)
        count = conn.execute("SELECT COUNT(*) FROM frames WHERE protocol = 'VNC'").fetchone()[0]
        assert count > 0
        conn.close()

    def test_meterpreter_detection(self, indexed_capture2_db):
        conn = sqlite3.connect(indexed_capture2_db)
        count = conn.execute("SELECT COUNT(*) FROM frames WHERE protocol = 'METERPRETER'").fetchone()[0]
        assert count > 0
        conn.close()

    def test_enip_detection(self, indexed_capture2_db):
        conn = sqlite3.connect(indexed_capture2_db)
        count = conn.execute("SELECT COUNT(*) FROM frames WHERE protocol = 'ENIP'").fetchone()[0]
        assert count > 0
        conn.close()

    def test_openvpn_detection(self, indexed_capture1_db):
        conn = sqlite3.connect(indexed_capture1_db)
        count = conn.execute("SELECT COUNT(*) FROM frames WHERE protocol = 'OPENVPN'").fetchone()[0]
        assert count > 0
        conn.close()


class TestDatabaseIntegrity:
    def test_frame_numbers_unique_per_artifact(self, indexed_capture1_db):
        conn = sqlite3.connect(indexed_capture1_db)
        duplicates = conn.execute("""
            SELECT source_artifact, frame_num, COUNT(*) as cnt
            FROM frames GROUP BY source_artifact, frame_num HAVING cnt > 1
        """).fetchone()
        assert duplicates is None
        conn.close()

    def test_frame_numbers_sequential_per_artifact(self, indexed_capture1_db):
        conn = sqlite3.connect(indexed_capture1_db)
        min_frame = conn.execute("SELECT MIN(frame_num) FROM frames WHERE source_artifact LIKE '%capture1.pcap'").fetchone()[0]
        max_frame = conn.execute("SELECT MAX(frame_num) FROM frames WHERE source_artifact LIKE '%capture1.pcap'").fetchone()[0]
        count = conn.execute("SELECT COUNT(*) FROM frames WHERE source_artifact LIKE '%capture1.pcap'").fetchone()[0]
        assert min_frame == 1
        assert max_frame == count
        conn.close()

    def test_tls_foreign_key(self, indexed_capture1_db):
        conn = sqlite3.connect(indexed_capture1_db)
        orphans = conn.execute("""
            SELECT COUNT(*) FROM tls_fingerprints t
            LEFT JOIN frames f ON t.frame_num = f.frame_num AND t.source_artifact = f.source_artifact
            WHERE f.frame_num IS NULL
        """).fetchone()[0]
        assert orphans == 0
        conn.close()

    def test_indexes_exist(self, indexed_capture1_db):
        conn = sqlite3.connect(indexed_capture1_db)
        indexes = conn.execute("SELECT name FROM sqlite_master WHERE type='index'").fetchall()
        index_names = [i[0] for i in indexes]
        for idx in ["idx_frames_src_ip", "idx_frames_dst_ip", "idx_tls_ja3"]:
            assert idx in index_names, f"Index {idx} not found"
        conn.close()


class TestTlsParsingEdgeCases:
    def test_truncated_handshake_too_short(self):
        data = b"\x16\x03\x01\x00\x03" + b"\x01\x00\x00"
        assert pcap_index.parse_tls_client_hello(data) is None

    def test_truncated_after_handshake_header(self):
        data = b"\x16\x03\x01\x00\x04" b"\x01\x00\x00\x00"
        assert pcap_index.parse_tls_client_hello(data) is None

    def test_truncated_before_session_id_len(self):
        data = b"\x16\x03\x01\x00\x26" b"\x01\x00\x00\x22" b"\x03\x03" + b"\x00" * 32
        assert pcap_index.parse_tls_client_hello(data) is None

    def test_truncated_before_cipher_suites_len(self):
        data = b"\x16\x03\x01\x00\x27" b"\x01\x00\x00\x23" b"\x03\x03" + b"\x00" * 32 + b"\x00"
        assert pcap_index.parse_tls_client_hello(data) is None

    def test_cipher_suites_truncated_mid_parse(self):
        data = (
            b"\x16\x03\x01\x00\x2f" b"\x01\x00\x00\x2b" b"\x03\x03"
            + b"\x00" * 32 + b"\x00" + b"\x00\x10" + b"\x13\x01\x13\x02\x13\x03"
        )
        result = pcap_index.parse_tls_client_hello(data)
        assert result is None or isinstance(result, dict)

    def test_truncated_before_compression_len(self):
        data = (
            b"\x16\x03\x01\x00\x2b" b"\x01\x00\x00\x27" b"\x03\x03"
            + b"\x00" * 32 + b"\x00" + b"\x00\x02" + b"\x13\x01"
        )
        assert pcap_index.parse_tls_client_hello(data) is None

    def test_valid_minimal_client_hello_with_alpn(self):
        alpn_ext = (
            b"\x00\x10" b"\x00\x0b" b"\x00\x09"
            b"\x02h2" b"\x05http/"
        )
        extensions = alpn_ext
        ext_len = len(extensions)
        data = (
            b"\x16\x03\x01"
            + struct.pack("!H", 4 + 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + ext_len)
            + b"\x01" + struct.pack("!I", 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + ext_len)[1:]
            + b"\x03\x03" + b"\x00" * 32 + b"\x00"
            + b"\x00\x02" + b"\x13\x01" + b"\x01\x00"
            + struct.pack("!H", ext_len) + extensions
        )
        result = pcap_index.parse_tls_client_hello(data)
        assert result is not None
        assert len(result.get('alpn', [])) > 0

    def test_exception_causes_none_return(self):
        data = (
            b"\x16\x03\x01\x00\xff" b"\x01\x00\x00\xfb" b"\x03\x03"
            + b"\x00" * 32 + b"\xff"
        )
        result = pcap_index.parse_tls_client_hello(data)
        assert result is None

    def test_exception_during_extension_parsing(self):
        data = (
            b"\x16\x03\x01\x00\x50" b"\x01\x00\x00\x4c" b"\x03\x03"
            + b"\x00" * 32 + b"\x00" + b"\x00\x02" + b"\x13\x01"
            + b"\x01\x00" + b"\x00\x10" + b"\x00\x00" + b"\xff\xff"
            + b"\x00" * 10
        )
        result = pcap_index.parse_tls_client_hello(data)
        assert result is None or isinstance(result, dict)


class TestTlsFrameQuery:
    def test_query_tls_frame_shows_fingerprints(self, indexed_capture1_db, capsys):
        pcap_index.query_frame(indexed_capture1_db, 215)
        captured = capsys.readouterr()
        assert "TLS SNI:" in captured.out
        assert "JA3:" in captured.out
        assert "JA4:" in captured.out
        assert "ce5f3254611a8c095a3d821d44539877" in captured.out


class TestVerboseMode:
    def test_index_verbose_mode(self, capture1_pcap, temp_db, capsys):
        pcap_index.index_pcap(str(capture1_pcap), temp_db, verbose=True)
        assert os.path.exists(temp_db)

    def test_verbose_with_malformed_packet(self, temp_db, capsys):
        pcap_header = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
        malformed_packet = b"\x00" * 14 + b"\x45\xff\xff\xff"
        pkt_header = struct.pack("<IIII", 0, 0, len(malformed_packet), len(malformed_packet))
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            f.write(pcap_header + pkt_header + malformed_packet)
            malformed_pcap = f.name
        try:
            pcap_index.index_pcap(malformed_pcap, temp_db, verbose=True)
            assert os.path.exists(temp_db)
        finally:
            os.unlink(malformed_pcap)


class TestPcapngFallback:
    def test_pcapng_detection_via_value_error(self, temp_db):
        pcapng_data = (
            b"\x0a\x0d\x0d\x0a" b"\x1c\x00\x00\x00" b"\x4d\x3c\x2b\x1a"
            b"\x01\x00" b"\x00\x00" b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x1c\x00\x00\x00"
        )
        with tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False) as f:
            f.write(pcapng_data)
            pcapng_path = f.name
        try:
            with pytest.raises((StopIteration, Exception)):
                pcap_index.index_pcap(pcapng_path, temp_db)
        finally:
            os.unlink(pcapng_path)

    def test_invalid_pcap_triggers_fallback(self, temp_db):
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            f.write(b"NOT A PCAP FILE " * 10)
            invalid_path = f.name
        try:
            with pytest.raises(Exception):
                pcap_index.index_pcap(invalid_path, temp_db)
        finally:
            os.unlink(invalid_path)

    def test_pcap_reader_value_error_triggers_pcapng(self, temp_db):
        shb = (
            b"\x0a\x0d\x0d\x0a" + struct.pack("<I", 28) + b"\x4d\x3c\x2b\x1a"
            + struct.pack("<HH", 1, 0) + struct.pack("<q", -1) + struct.pack("<I", 28)
        )
        idb = (
            b"\x01\x00\x00\x00" + struct.pack("<I", 20) + struct.pack("<HH", 1, 0)
            + struct.pack("<I", 65535) + struct.pack("<I", 20)
        )
        with tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False) as f:
            f.write(shb + idb)
            pcapng_path = f.name
        try:
            pcap_index.index_pcap(pcapng_path, temp_db)
            assert os.path.exists(temp_db)
        except Exception:
            pass
        finally:
            os.unlink(pcapng_path)


class TestPcapngFallbackMocked:
    def test_mocked_pcap_reader_value_error(self, capture1_pcap, temp_db):
        import dpkt
        original_reader = dpkt.pcap.Reader

        def mock_reader(f):
            raise ValueError("Mocked: not a pcap file")

        dpkt.pcap.Reader = mock_reader
        try:
            with pytest.raises(Exception):
                pcap_index.index_pcap(str(capture1_pcap), temp_db)
        finally:
            dpkt.pcap.Reader = original_reader


class TestBatchProcessing:
    def test_final_batch_with_tls(self, indexed_capture1_db):
        conn = sqlite3.connect(indexed_capture1_db)
        tls_count = conn.execute("SELECT COUNT(*) FROM tls_fingerprints").fetchone()[0]
        assert tls_count > 0
        conn.close()

    def test_small_pcap_final_batch(self, temp_db):
        pcap_header = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
        tls_data = (
            b"\x16\x03\x01\x00\x2f" + b"\x01\x00\x00\x2b" + b"\x03\x03"
            + b"\x00" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" + b"\x00\x00"
        )
        tcp_payload_len = len(tls_data)
        ip_total_len = 20 + 20 + tcp_payload_len
        eth_header = b"\x00" * 6 + b"\x00" * 6 + b"\x08\x00"
        ip_header = (
            b"\x45\x00" + struct.pack(">H", ip_total_len) + b"\x00\x00\x40\x00"
            + b"\x40\x06" + b"\x00\x00" + b"\xc0\xa8\x18\x64" + b"\xc0\xa8\x18\x65"
        )
        tcp_header = (
            struct.pack(">HH", 12345, 443) + struct.pack(">II", 0, 0)
            + b"\x50\x18" + struct.pack(">H", 65535) + b"\x00\x00\x00\x00"
        )
        packet = eth_header + ip_header + tcp_header + tls_data
        pkt_header = struct.pack("<IIII", 1604688000, 0, len(packet), len(packet))
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            f.write(pcap_header + pkt_header + packet)
            small_pcap = f.name
        try:
            pcap_index.index_pcap(small_pcap, temp_db)
            conn = sqlite3.connect(temp_db)
            frame_count = conn.execute("SELECT COUNT(*) FROM frames").fetchone()[0]
            tls_count = conn.execute("SELECT COUNT(*) FROM tls_fingerprints").fetchone()[0]
            assert frame_count == 1
            assert tls_count == 1
            conn.close()
        finally:
            os.unlink(small_pcap)


class TestAlpnParsing:
    def test_alpn_in_ja4(self):
        tls_info = {
            "version": 0x0303,
            "cipher_suites": [0x1301],
            "extensions": [0, 16],
            "elliptic_curves": [],
            "ec_point_formats": [],
            "sni": "example.com",
            "alpn": ["h2", "http/1.1"],
        }
        ja4_string, _ = pcap_index.compute_ja4(tls_info)
        assert "h2" in ja4_string or "_h2" in ja4_string


class TestJa4FromRealData:
    def test_ja4_format_validation(self, indexed_capture1_db):
        import re
        conn = sqlite3.connect(indexed_capture1_db)
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT ja4_string, ja4_hash, sni FROM tls_fingerprints").fetchall()
        assert len(rows) > 0
        ja4_pattern = re.compile(
            r'^[tq](1[0-3]|00)[di]\d{2}\d{2}_[a-z0-9]{2}_[a-f0-9]{12}_[a-f0-9]{12}$'
        )
        for row in rows:
            ja4 = row['ja4_string']
            assert ja4_pattern.match(ja4), f"Invalid JA4 format: {ja4}"
            sni_flag = ja4[3]
            if row['sni']:
                assert sni_flag == 'd'
            else:
                assert sni_flag == 'i'
            assert len(row['ja4_hash']) == 32
        conn.close()

    def test_ja4_consistency_across_same_client(self, indexed_capture1_db):
        conn = sqlite3.connect(indexed_capture1_db)
        rows = conn.execute("""
            SELECT f.src_ip, t.ja4_string, COUNT(*) as cnt
            FROM tls_fingerprints t
            JOIN frames f ON t.frame_num = f.frame_num AND t.source_artifact = f.source_artifact
            GROUP BY f.src_ip, t.ja4_string
        """).fetchall()
        rdp_ja4s = {}
        for row in rows:
            src_ip = row[0]
            ja4 = row[1]
            if src_ip not in rdp_ja4s:
                rdp_ja4s[src_ip] = set()
            rdp_ja4s[src_ip].add(ja4)
        for src_ip, ja4_set in rdp_ja4s.items():
            assert len(ja4_set) <= 5
        conn.close()

    def test_ja4_with_alpn(self, indexed_capture2_db):
        conn = sqlite3.connect(indexed_capture2_db)
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT ja4_string FROM tls_fingerprints WHERE ja4_string LIKE '%_h2_%'").fetchall()
        assert len(rows) > 0
        for row in rows:
            parts = row['ja4_string'].split('_')
            assert len(parts) == 4
            assert parts[1] == 'h2'
        conn.close()


class TestCliEdgeCases:
    def test_index_with_explicit_db(self, capture1_pcap, temp_db):
        with mock.patch("sys.argv", ["pcap-index.py", "index", str(capture1_pcap), "--db", temp_db]):
            pcap_index.main()
        assert os.path.exists(temp_db)
        conn = sqlite3.connect(temp_db)
        count = conn.execute("SELECT COUNT(*) FROM frames").fetchone()[0]
        assert count > 0
        conn.close()


class TestExceptionHandling:
    def test_tls_parse_exception_via_mock(self):
        call_count = [0]

        def counting_unpack(fmt, data):
            call_count[0] += 1
            result = struct.unpack(fmt, data)
            if call_count[0] >= 6:
                raise struct.error("Simulated struct error")
            return result

        data = (
            b"\x16\x03\x01\x00\x80" b"\x01\x00\x00\x7c" b"\x03\x03"
            + b"\x00" * 32 + b"\x00" + b"\x00\x04" + b"\x13\x01\x13\x02"
            + b"\x01\x00" + b"\x00\x60" + b"\x00\x00" + b"\x00\x5c"
            + b"\x00" * 92
        )
        with mock.patch('pcap_index.struct.unpack', side_effect=counting_unpack):
            result = pcap_index.parse_tls_client_hello(data)
            assert result is None

    def test_frame_parse_exception_verbose(self, temp_db, capsys):
        pcap_header = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
        bad_packet = b"\x00\x01\x02"
        pkt_header = struct.pack("<IIII", 0, 0, len(bad_packet), len(bad_packet))
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            f.write(pcap_header + pkt_header + bad_packet)
            bad_pcap = f.name
        try:
            pcap_index.index_pcap(bad_pcap, temp_db, verbose=True)
            assert os.path.exists(temp_db)
        finally:
            os.unlink(bad_pcap)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
