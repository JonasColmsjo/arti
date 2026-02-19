"""Tests for scripts/ascii_flows.py — ASCII flow visualization helpers."""

import pytest

from ascii_flows import (
    get_dst_id,
    get_host_label,
    get_src_id,
    get_timestamp_column,
    has_mac_columns,
    has_timestamps,
    get_time_str,
    ip_in_subnet,
    is_broadcast_or_multicast,
    is_mac_address,
    normalize_mac,
    render_matrix_ascii,
    render_sankey_ascii,
)


# =============================================================================
# normalize_mac
# =============================================================================
class TestNormalizeMac:
    def test_colon_format(self):
        assert normalize_mac("00:0C:29:AB:C1:C9") == "00:0c:29:ab:c1:c9"

    def test_dash_format(self):
        assert normalize_mac("00-0C-29-AB-C1-C9") == "00:0c:29:ab:c1:c9"

    def test_dot_format(self):
        assert normalize_mac("000C.29AB.C1C9") == "00:0c:29:ab:c1:c9"

    def test_raw_format(self):
        assert normalize_mac("000C29ABC1C9") == "00:0c:29:ab:c1:c9"

    def test_empty_string(self):
        assert normalize_mac("") == ""

    def test_invalid_short(self):
        # Not 12 hex chars after cleaning — returns lowercased original
        result = normalize_mac("ABCD")
        assert result == "abcd"


# =============================================================================
# is_mac_address
# =============================================================================
class TestIsMacAddress:
    def test_colon_format_valid(self):
        assert is_mac_address("00:0c:29:ab:c1:c9") is True

    def test_dash_format_valid(self):
        assert is_mac_address("00-0C-29-AB-C1-C9") is True

    def test_ip_address_not_mac(self):
        assert is_mac_address("192.168.1.1") is False

    def test_hostname_not_mac(self):
        assert is_mac_address("server01") is False

    def test_empty_string(self):
        assert is_mac_address("") is False


# =============================================================================
# is_broadcast_or_multicast
# =============================================================================
class TestIsBroadcastOrMulticast:
    def test_broadcast_mac(self):
        assert is_broadcast_or_multicast("ff:ff:ff:ff:ff:ff") is True

    def test_multicast_mac(self):
        # 01:00:5e:xx is multicast (first byte LSB set)
        assert is_broadcast_or_multicast("01:00:5e:00:00:01") is True

    def test_unicast_mac(self):
        assert is_broadcast_or_multicast("00:0c:29:ab:c1:c9") is False

    def test_multicast_ip(self):
        assert is_broadcast_or_multicast("224.0.0.1") is True

    def test_broadcast_ip(self):
        assert is_broadcast_or_multicast("192.168.1.255") is True

    def test_unicast_ip(self):
        assert is_broadcast_or_multicast("192.168.1.100") is False

    def test_wildcard_star(self):
        assert is_broadcast_or_multicast("*") is True

    def test_dash(self):
        assert is_broadcast_or_multicast("-") is True

    def test_empty(self):
        assert is_broadcast_or_multicast("") is True

    def test_239_multicast(self):
        assert is_broadcast_or_multicast("239.255.255.250") is True


# =============================================================================
# ip_in_subnet
# =============================================================================
class TestIpInSubnet:
    def test_slash_24_match(self):
        assert ip_in_subnet("192.168.24.100", "192.168.24.0/24") is True

    def test_slash_24_no_match(self):
        assert ip_in_subnet("192.168.25.100", "192.168.24.0/24") is False

    def test_slash_16_match(self):
        assert ip_in_subnet("172.16.5.10", "172.16.0.0/16") is True

    def test_slash_16_no_match(self):
        assert ip_in_subnet("172.17.5.10", "172.16.0.0/16") is False

    def test_slash_8_match(self):
        assert ip_in_subnet("10.0.0.1", "10.0.0.0/8") is True

    def test_slash_8_no_match(self):
        assert ip_in_subnet("11.0.0.1", "10.0.0.0/8") is False

    def test_exact_ip_no_cidr(self):
        assert ip_in_subnet("10.0.0.1", "10.0.0.1") is True
        assert ip_in_subnet("10.0.0.2", "10.0.0.1") is False

    def test_unsupported_prefix_returns_false(self):
        assert ip_in_subnet("10.0.0.1", "10.0.0.0/12") is False

    def test_invalid_ip(self):
        assert ip_in_subnet("not.an.ip", "10.0.0.0/24") is False


# =============================================================================
# get_timestamp_column
# =============================================================================
class TestGetTimestampColumn:
    def test_timestamp_utc(self):
        flows = [{"timestamp_utc": "2020-08-17T10:00:00", "src_ip": "1.2.3.4"}]
        assert get_timestamp_column(flows) == "timestamp_utc"

    def test_datetime_utc(self):
        flows = [{"datetime_utc": "2020-08-17T10:00:00", "src_ip": "1.2.3.4"}]
        assert get_timestamp_column(flows) == "datetime_utc"

    def test_no_timestamp(self):
        flows = [{"src_ip": "1.2.3.4", "dst_ip": "5.6.7.8"}]
        assert get_timestamp_column(flows) is None

    def test_empty_flows(self):
        assert get_timestamp_column([]) is None


# =============================================================================
# get_src_id / get_dst_id
# =============================================================================
class TestGetSrcDstId:
    def test_src_prefers_mac(self):
        flow = {"src_mac": "00:0C:29:AB:C1:C9", "src_ip": "192.168.24.100"}
        assert get_src_id(flow) == "00:0c:29:ab:c1:c9"

    def test_src_fallback_to_ip(self):
        flow = {"src_ip": "192.168.24.100"}
        assert get_src_id(flow) == "192.168.24.100"

    def test_src_mac_dash_uses_ip(self):
        flow = {"src_mac": "-", "src_ip": "192.168.24.100"}
        assert get_src_id(flow) == "192.168.24.100"

    def test_src_mac_empty_uses_ip(self):
        flow = {"src_mac": "", "src_ip": "192.168.24.100"}
        assert get_src_id(flow) == "192.168.24.100"

    def test_dst_prefers_mac(self):
        flow = {"dst_mac": "00:0C:29:AB:C1:C9", "dst_ip": "192.168.24.144"}
        assert get_dst_id(flow) == "00:0c:29:ab:c1:c9"

    def test_dst_fallback_to_ip(self):
        flow = {"dst_ip": "192.168.24.144"}
        assert get_dst_id(flow) == "192.168.24.144"

    def test_dst_mac_star_uses_ip(self):
        flow = {"dst_mac": "*", "dst_ip": "192.168.24.144"}
        assert get_dst_id(flow) == "192.168.24.144"

    def test_no_mac_no_ip(self):
        flow = {}
        assert get_src_id(flow) == "?"
        assert get_dst_id(flow) == "?"


# =============================================================================
# get_host_label
# =============================================================================
class TestGetHostLabel:
    def test_label_found(self):
        labels = {"192.168.24.100": "EWS-VM"}
        assert get_host_label("192.168.24.100", labels) == "EWS-VM"

    def test_label_not_found_returns_identifier(self):
        assert get_host_label("192.168.24.100", {}) == "192.168.24.100"

    def test_long_label_truncated(self):
        labels = {"192.168.24.100": "very-long-hostname-label"}
        result = get_host_label("192.168.24.100", labels, max_len=10)
        assert len(result) == 10
        assert result.endswith("…")

    def test_mac_label_lookup(self):
        labels = {"00:0c:29:ab:c1:c9": "EWS-VM"}
        assert get_host_label("00:0C:29:AB:C1:C9", labels) == "EWS-VM"


# =============================================================================
# has_mac_columns / has_timestamps / get_time_str
# =============================================================================
class TestMiscHelpers:
    def test_has_mac_columns_true(self):
        flows = [{"src_mac": "00:0c:29:ab:c1:c9", "src_ip": "1.2.3.4"}]
        assert has_mac_columns(flows) is True

    def test_has_mac_columns_false(self):
        flows = [{"src_ip": "1.2.3.4", "dst_ip": "5.6.7.8"}]
        assert has_mac_columns(flows) is False

    def test_has_mac_columns_empty(self):
        assert has_mac_columns([]) is False

    def test_has_timestamps_true(self):
        flows = [{"timestamp_utc": "2020-08-17T10:00:00"}]
        assert has_timestamps(flows) is True

    def test_has_timestamps_false_no_col(self):
        flows = [{"src_ip": "1.2.3.4"}]
        assert has_timestamps(flows) is False

    def test_has_timestamps_false_empty_values(self):
        flows = [{"timestamp_utc": ""}]
        assert has_timestamps(flows) is False

    def test_get_time_str_full(self):
        flow = {"timestamp_utc": "2020-08-17T10:05:30.123"}
        assert get_time_str(flow, full=True) == "2020-08-17T10:05:30"

    def test_get_time_str_short(self):
        flow = {"timestamp_utc": "2020-08-17T10:05:30.123"}
        assert get_time_str(flow) == "10:05:30"

    def test_get_time_str_empty(self):
        flow = {"timestamp_utc": ""}
        assert get_time_str(flow) == ""

    def test_get_time_str_datetime_utc(self):
        flow = {"datetime_utc": "2020-08-17T10:05:30"}
        assert get_time_str(flow) == "10:05:30"


# =============================================================================
# render_sankey_ascii / render_matrix_ascii
# =============================================================================
class TestRenderers:
    def test_render_sankey_returns_string(self):
        flows = [
            {"src_ip": "1.2.3.4", "dst_ip": "5.6.7.8", "dst_port": "443",
             "protocol": "TLS", "explanation": "test", "timestamp_utc": "2020-01-01T00:00:00"},
        ]
        result = render_sankey_ascii(flows, {})
        assert isinstance(result, str)
        assert "1.2.3.4" in result
        assert "5.6.7.8" in result

    def test_render_matrix_returns_string(self):
        flows = [
            {"src_ip": "1.2.3.4", "dst_ip": "5.6.7.8", "protocol": "TCP"},
        ]
        result = render_matrix_ascii(flows, {})
        assert isinstance(result, str)
        assert "CONNECTION MATRIX" in result

    def test_render_matrix_no_unicast(self):
        flows = [
            {"src_ip": "224.0.0.1", "dst_ip": "ff:ff:ff:ff:ff:ff", "protocol": "IGMP"},
        ]
        result = render_matrix_ascii(flows, {})
        assert "No unicast" in result

    def test_render_sankey_without_timestamps(self):
        flows = [
            {"src_ip": "1.2.3.4", "dst_ip": "5.6.7.8", "dst_port": "80",
             "protocol": "HTTP", "explanation": ""},
        ]
        result = render_sankey_ascii(flows, {})
        assert "CHRONOLOGICAL" not in result
