#!/usr/bin/env python3
"""
PCAP Indexer with SQLite storage and JA3/JA4 TLS fingerprinting.

Usage:
    pcap-index.py index <pcap_file> [--db <database>]
    pcap-index.py query <database> --frame <num>
    pcap-index.py query <database> --ip <ip>
    pcap-index.py query <database> --port <port>
    pcap-index.py query <database> --ja3 <hash>
    pcap-index.py query <database> --sql <query>
    pcap-index.py stats <database>

Dependencies:
    pip install dpkt

JA3/JA4 fingerprinting based on Salesforce implementation.
"""

import argparse
import hashlib
import socket
import sqlite3
import struct
import sys
import time
from pathlib import Path

import dpkt


# --- Database Schema ---

SCHEMA = """
CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS frames (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    level TEXT,
    source_artifact TEXT,
    frame_num INTEGER,
    timestamp REAL,
    timestamp_utc TEXT,
    src_mac TEXT,
    dst_mac TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT,
    ip_proto INTEGER,
    payload_len INTEGER,
    info TEXT
);

CREATE TABLE IF NOT EXISTS tls_fingerprints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    frame_id INTEGER,
    source_artifact TEXT,
    frame_num INTEGER,
    ja3_string TEXT,
    ja3_hash TEXT,
    ja4_string TEXT,
    ja4_hash TEXT,
    sni TEXT,
    FOREIGN KEY (frame_id) REFERENCES frames(id)
);

CREATE INDEX IF NOT EXISTS idx_frames_level ON frames(level);
CREATE INDEX IF NOT EXISTS idx_frames_source_artifact ON frames(source_artifact);
CREATE INDEX IF NOT EXISTS idx_frames_artifact_frame ON frames(source_artifact, frame_num);
CREATE INDEX IF NOT EXISTS idx_frames_src_mac ON frames(src_mac);
CREATE INDEX IF NOT EXISTS idx_frames_dst_mac ON frames(dst_mac);
CREATE INDEX IF NOT EXISTS idx_frames_src_ip ON frames(src_ip);
CREATE INDEX IF NOT EXISTS idx_frames_dst_ip ON frames(dst_ip);
CREATE INDEX IF NOT EXISTS idx_frames_src_port ON frames(src_port);
CREATE INDEX IF NOT EXISTS idx_frames_dst_port ON frames(dst_port);
CREATE INDEX IF NOT EXISTS idx_frames_timestamp ON frames(timestamp);
CREATE INDEX IF NOT EXISTS idx_tls_ja3 ON tls_fingerprints(ja3_hash);
CREATE INDEX IF NOT EXISTS idx_tls_ja4 ON tls_fingerprints(ja4_hash);
CREATE INDEX IF NOT EXISTS idx_tls_sni ON tls_fingerprints(sni);
"""


# --- JA3 Implementation (based on Salesforce ja3) ---

GREASE_VALUES = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
}


def parse_tls_client_hello(tcp_data: bytes) -> dict | None:
    """Parse TLS Client Hello and extract JA3 components."""
    try:
        if len(tcp_data) < 6:
            return None

        # Check for TLS handshake
        content_type = tcp_data[0]
        if content_type != 0x16:  # Handshake
            return None

        tls_version = struct.unpack('!H', tcp_data[1:3])[0]
        record_len = struct.unpack('!H', tcp_data[3:5])[0]

        if len(tcp_data) < 5 + record_len:
            return None

        handshake = tcp_data[5:5 + record_len]

        if len(handshake) < 4:
            return None

        handshake_type = handshake[0]
        if handshake_type != 0x01:  # Client Hello
            return None

        # Parse Client Hello
        hs_len = struct.unpack('!I', b'\x00' + handshake[1:4])[0]
        pos = 4

        if len(handshake) < pos + 2:
            return None

        client_version = struct.unpack('!H', handshake[pos:pos+2])[0]
        pos += 2

        # Skip random (32 bytes)
        pos += 32

        if len(handshake) < pos + 1:
            return None

        # Session ID
        session_id_len = handshake[pos]
        pos += 1 + session_id_len

        if len(handshake) < pos + 2:
            return None

        # Cipher suites
        cipher_suites_len = struct.unpack('!H', handshake[pos:pos+2])[0]
        pos += 2

        cipher_suites = []
        for i in range(0, cipher_suites_len, 2):
            if pos + i + 2 > len(handshake):
                break
            cs = struct.unpack('!H', handshake[pos+i:pos+i+2])[0]
            if cs not in GREASE_VALUES:
                cipher_suites.append(cs)
        pos += cipher_suites_len

        if len(handshake) < pos + 1:
            return None

        # Compression methods
        comp_len = handshake[pos]
        pos += 1 + comp_len

        # Extensions
        extensions = []
        elliptic_curves = []
        ec_point_formats = []
        sni = None
        signature_algorithms = []
        alpn = []

        if pos + 2 <= len(handshake):
            ext_len = struct.unpack('!H', handshake[pos:pos+2])[0]
            pos += 2
            ext_end = pos + ext_len

            while pos + 4 <= ext_end and pos + 4 <= len(handshake):
                ext_type = struct.unpack('!H', handshake[pos:pos+2])[0]
                ext_data_len = struct.unpack('!H', handshake[pos+2:pos+4])[0]
                ext_data = handshake[pos+4:pos+4+ext_data_len]
                pos += 4 + ext_data_len

                if ext_type not in GREASE_VALUES:
                    extensions.append(ext_type)

                # SNI (ext type 0)
                if ext_type == 0 and len(ext_data) > 5:
                    sni_len = struct.unpack('!H', ext_data[3:5])[0]
                    if len(ext_data) >= 5 + sni_len:
                        sni = ext_data[5:5+sni_len].decode('utf-8', errors='ignore')

                # Supported Groups / Elliptic Curves (ext type 10)
                elif ext_type == 10 and len(ext_data) >= 2:
                    ec_len = struct.unpack('!H', ext_data[0:2])[0]
                    for i in range(2, min(2 + ec_len, len(ext_data)), 2):
                        if i + 2 <= len(ext_data):
                            curve = struct.unpack('!H', ext_data[i:i+2])[0]
                            if curve not in GREASE_VALUES:
                                elliptic_curves.append(curve)

                # EC Point Formats (ext type 11)
                elif ext_type == 11 and len(ext_data) >= 1:
                    fmt_len = ext_data[0]
                    for i in range(1, min(1 + fmt_len, len(ext_data))):
                        ec_point_formats.append(ext_data[i])

                # Signature Algorithms (ext type 13)
                elif ext_type == 13 and len(ext_data) >= 2:
                    sig_len = struct.unpack('!H', ext_data[0:2])[0]
                    for i in range(2, min(2 + sig_len, len(ext_data)), 2):
                        if i + 2 <= len(ext_data):
                            sig = struct.unpack('!H', ext_data[i:i+2])[0]
                            signature_algorithms.append(sig)

                # ALPN (ext type 16)
                elif ext_type == 16 and len(ext_data) >= 2:
                    alpn_len = struct.unpack('!H', ext_data[0:2])[0]
                    alpn_pos = 2
                    while alpn_pos < min(2 + alpn_len, len(ext_data)):
                        proto_len = ext_data[alpn_pos]
                        if alpn_pos + 1 + proto_len <= len(ext_data):
                            proto = ext_data[alpn_pos+1:alpn_pos+1+proto_len].decode('utf-8', errors='ignore')
                            alpn.append(proto)
                        alpn_pos += 1 + proto_len

        return {
            'version': client_version,
            'cipher_suites': cipher_suites,
            'extensions': extensions,
            'elliptic_curves': elliptic_curves,
            'ec_point_formats': ec_point_formats,
            'sni': sni,
            'signature_algorithms': signature_algorithms,
            'alpn': alpn,
        }

    except Exception:
        return None


def compute_ja3(tls_info: dict) -> tuple[str, str]:
    """Compute JA3 string and hash from parsed TLS Client Hello."""
    ja3_parts = [
        str(tls_info['version']),
        '-'.join(str(x) for x in tls_info['cipher_suites']),
        '-'.join(str(x) for x in tls_info['extensions']),
        '-'.join(str(x) for x in tls_info['elliptic_curves']),
        '-'.join(str(x) for x in tls_info['ec_point_formats']),
    ]
    ja3_string = ','.join(ja3_parts)
    ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()
    return ja3_string, ja3_hash


def compute_ja4(tls_info: dict) -> tuple[str, str]:
    """
    Compute JA4 fingerprint (simplified version).

    JA4 format: t{TLS_version}{SNI}{cipher_count}{ext_count}_{cipher_hash}_{ext_hash}
    """
    # Protocol (t=TCP TLS, q=QUIC)
    proto = 't'

    # TLS version mapping
    version_map = {
        0x0301: '10',  # TLS 1.0
        0x0302: '11',  # TLS 1.1
        0x0303: '12',  # TLS 1.2
        0x0304: '13',  # TLS 1.3
    }
    version = version_map.get(tls_info['version'], '00')

    # SNI: d=domain present, i=IP or no SNI
    sni_flag = 'd' if tls_info.get('sni') else 'i'

    # Counts (2 digits each)
    cipher_count = min(len(tls_info['cipher_suites']), 99)
    ext_count = min(len(tls_info['extensions']), 99)

    # ALPN first value (first char, or 00)
    alpn = tls_info.get('alpn', [])
    alpn_flag = alpn[0][:2] if alpn else '00'

    # Part a: type + version + sni + cipher_count + ext_count + alpn
    part_a = f"{proto}{version}{sni_flag}{cipher_count:02d}{ext_count:02d}_{alpn_flag}"

    # Part b: sorted cipher suites hash (first 12 chars of sha256)
    sorted_ciphers = sorted(tls_info['cipher_suites'])
    cipher_str = ','.join(f"{c:04x}" for c in sorted_ciphers)
    part_b = hashlib.sha256(cipher_str.encode()).hexdigest()[:12]

    # Part c: sorted extensions hash (first 12 chars of sha256)
    # Exclude SNI (0) and ALPN (16) from hash per JA4 spec
    filtered_exts = [e for e in tls_info['extensions'] if e not in (0, 16)]
    sorted_exts = sorted(filtered_exts)
    ext_str = ','.join(f"{e:04x}" for e in sorted_exts)
    part_c = hashlib.sha256(ext_str.encode()).hexdigest()[:12]

    ja4_string = f"{part_a}_{part_b}_{part_c}"
    ja4_hash = hashlib.sha256(ja4_string.encode()).hexdigest()[:32]

    return ja4_string, ja4_hash


# --- PCAP Parsing ---

def get_protocol_name(ip_proto: int, sport: int, dport: int) -> str:
    """Get protocol name from IP protocol number and ports."""
    if ip_proto == 6:  # TCP
        well_known = {
            20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET',
            25: 'SMTP', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 502: 'MODBUS', 993: 'IMAPS',
            995: 'POP3S', 1962: 'PCCC', 3389: 'RDP', 4444: 'METERPRETER',
            5900: 'VNC', 41100: 'ADE', 44818: 'ENIP',
        }
        for port in (dport, sport):
            if port in well_known:
                return well_known[port]
        return 'TCP'
    elif ip_proto == 17:  # UDP
        well_known = {
            53: 'DNS', 67: 'DHCP', 68: 'DHCP', 69: 'TFTP',
            123: 'NTP', 161: 'SNMP', 500: 'ISAKMP', 514: 'SYSLOG',
            1194: 'OPENVPN', 1195: 'OPENVPN', 1196: 'OPENVPN',
            2222: 'ENIP', 44818: 'ENIP',
        }
        for port in (dport, sport):
            if port in well_known:
                return well_known[port]
        return 'UDP'
    elif ip_proto == 1:
        return 'ICMP'
    elif ip_proto == 2:
        return 'IGMP'
    else:
        return f'IP:{ip_proto}'


def format_timestamp(ts: float) -> str:
    """Format timestamp as ISO 8601 UTC."""
    from datetime import datetime, timezone
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'


def format_mac(mac_bytes: bytes) -> str:
    """Format MAC address bytes as colon-separated hex string."""
    return ':'.join(f'{b:02x}' for b in mac_bytes)


def index_pcap(pcap_path: str, db_path: str, level: str = None, artifact_path: str = None, verbose: bool = False) -> None:
    """Index a PCAP file into SQLite database.

    Args:
        pcap_path: Path to PCAP file
        db_path: Path to SQLite database (shared across all levels)
        level: Artifact tier (e.g., 't1', 't2', 't3')
        artifact_path: Meaningful path for source_artifact (e.g., 'Tier_2_Artifacts/capture1.pcap')
        verbose: Show verbose output
    """
    pcap_path = Path(pcap_path)
    db_path = Path(db_path)

    if not pcap_path.exists():
        print(f"Error: PCAP file not found: {pcap_path}", file=sys.stderr)
        sys.exit(1)

    # Source artifact: use provided path or derive from pcap_path
    if artifact_path:
        source_artifact = artifact_path
    else:
        # Try to extract relative path from evidence structure
        path_str = str(pcap_path)
        if 'Tier_1_Artifacts' in path_str or 'Level_1_Artifacts' in path_str:
            source_artifact = pcap_path.parts[-2] + '/' + pcap_path.name
            level = level or 't1'
        elif 'Tier_2_Artifacts' in path_str or 'Level_2_Artifacts' in path_str:
            source_artifact = pcap_path.parts[-2] + '/' + pcap_path.name
            level = level or 't2'
        elif 'Tier_3_Artifacts' in path_str or 'Level_3_Artifacts' in path_str:
            source_artifact = pcap_path.parts[-2] + '/' + pcap_path.name
            level = level or 't3'
        else:
            source_artifact = pcap_path.name

    level = level or 'unknown'

    print(f"Indexing {pcap_path} -> {db_path}")
    print(f"  Level: {level}, Artifact: {source_artifact}")
    start_time = time.time()

    # Create/connect to database
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(SCHEMA)

    # Check if this artifact is already indexed
    existing = conn.execute(
        "SELECT COUNT(*) FROM frames WHERE source_artifact = ?", (source_artifact,)
    ).fetchone()[0]
    if existing > 0:
        print(f"  Warning: {source_artifact} already has {existing:,} frames indexed. Skipping.")
        print(f"  Use --force to re-index (will delete existing frames first).")
        conn.close()
        return

    # Store metadata (append to list of indexed files)
    conn.execute("INSERT OR REPLACE INTO metadata VALUES ('last_indexed_at', ?)", (format_timestamp(time.time()),))

    # Open PCAP
    with open(pcap_path, 'rb') as f:
        try:
            pcap = dpkt.pcap.Reader(f)
            pcap_type = 'pcap'
        except ValueError:
            f.seek(0)
            pcap = dpkt.pcapng.Reader(f)
            pcap_type = 'pcapng'

        frame_count = 0
        tls_count = 0
        batch_frames = []
        batch_tls = []
        batch_size = 10000

        for ts, buf in pcap:
            frame_count += 1

            src_mac = dst_mac = None
            src_ip = dst_ip = None
            src_port = dst_port = None
            ip_proto = 0
            payload_len = 0
            info = ''
            tls_info = None

            try:
                eth = dpkt.ethernet.Ethernet(buf)

                # Extract MAC addresses
                src_mac = format_mac(eth.src)
                dst_mac = format_mac(eth.dst)

                if isinstance(eth.data, dpkt.ip.IP):
                    ip = eth.data
                    src_ip = socket.inet_ntoa(ip.src)
                    dst_ip = socket.inet_ntoa(ip.dst)
                    ip_proto = ip.p
                    payload_len = len(ip.data) if hasattr(ip, 'data') else 0

                    if isinstance(ip.data, dpkt.tcp.TCP):
                        tcp = ip.data
                        src_port = tcp.sport
                        dst_port = tcp.dport
                        payload_len = len(tcp.data) if tcp.data else 0

                        # Check for TLS Client Hello
                        if tcp.data and len(tcp.data) > 5:
                            tls_info = parse_tls_client_hello(bytes(tcp.data))

                        # Basic info
                        flags = []
                        if tcp.flags & dpkt.tcp.TH_SYN:
                            flags.append('SYN')
                        if tcp.flags & dpkt.tcp.TH_ACK:
                            flags.append('ACK')
                        if tcp.flags & dpkt.tcp.TH_FIN:
                            flags.append('FIN')
                        if tcp.flags & dpkt.tcp.TH_RST:
                            flags.append('RST')
                        info = f"{src_port} -> {dst_port} [{','.join(flags)}]"

                    elif isinstance(ip.data, dpkt.udp.UDP):
                        udp = ip.data
                        src_port = udp.sport
                        dst_port = udp.dport
                        payload_len = len(udp.data) if udp.data else 0
                        info = f"{src_port} -> {dst_port}"

                    elif isinstance(ip.data, dpkt.icmp.ICMP):
                        info = 'ICMP'

                elif isinstance(eth.data, dpkt.ip6.IP6):
                    ip6 = eth.data
                    src_ip = socket.inet_ntop(socket.AF_INET6, ip6.src)
                    dst_ip = socket.inet_ntop(socket.AF_INET6, ip6.dst)
                    ip_proto = ip6.nxt

                elif isinstance(eth.data, dpkt.arp.ARP):
                    info = 'ARP'
                    ip_proto = -1  # ARP marker

            except Exception as e:
                if verbose:
                    print(f"  Frame {frame_count}: parse error: {e}", file=sys.stderr)

            protocol = get_protocol_name(ip_proto, src_port or 0, dst_port or 0)

            batch_frames.append((
                level,
                source_artifact,
                frame_count,
                ts,
                format_timestamp(ts),
                src_mac,
                dst_mac,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                protocol,
                ip_proto,
                payload_len,
                info,
            ))

            if tls_info:
                ja3_string, ja3_hash = compute_ja3(tls_info)
                ja4_string, ja4_hash = compute_ja4(tls_info)
                batch_tls.append((
                    source_artifact,
                    frame_count,
                    ja3_string,
                    ja3_hash,
                    ja4_string,
                    ja4_hash,
                    tls_info.get('sni'),
                ))
                tls_count += 1

            # Batch insert
            if len(batch_frames) >= batch_size:
                conn.executemany(
                    """INSERT INTO frames (level, source_artifact, frame_num, timestamp, timestamp_utc,
                       src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, protocol, ip_proto, payload_len, info)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    batch_frames
                )
                if batch_tls:
                    conn.executemany(
                        """INSERT INTO tls_fingerprints (source_artifact, frame_num, ja3_string, ja3_hash, ja4_string, ja4_hash, sni)
                           VALUES (?,?,?,?,?,?,?)""",
                        batch_tls
                    )
                conn.commit()
                print(f"  Indexed {frame_count:,} frames, {tls_count:,} TLS handshakes...", end='\r')
                batch_frames = []
                batch_tls = []

        # Final batch
        if batch_frames:
            conn.executemany(
                """INSERT INTO frames (level, source_artifact, frame_num, timestamp, timestamp_utc,
                   src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, protocol, ip_proto, payload_len, info)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                batch_frames
            )
        if batch_tls:
            conn.executemany(
                """INSERT INTO tls_fingerprints (source_artifact, frame_num, ja3_string, ja3_hash, ja4_string, ja4_hash, sni)
                   VALUES (?,?,?,?,?,?,?)""",
                batch_tls
            )
        conn.commit()

    # Store final count
    conn.execute("INSERT OR REPLACE INTO metadata VALUES ('frame_count', ?)", (str(frame_count),))
    conn.execute("INSERT OR REPLACE INTO metadata VALUES ('tls_count', ?)", (str(tls_count),))
    conn.commit()
    conn.close()

    elapsed = time.time() - start_time
    print(f"\nIndexed {frame_count:,} frames ({tls_count:,} TLS) in {elapsed:.1f}s")
    print(f"Database: {db_path} ({db_path.stat().st_size / 1024 / 1024:.1f} MB)")


def query_frame(db_path: str, frame_num: int, artifact: str = None) -> None:
    """Query a specific frame by number and optionally artifact."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    if artifact:
        # Match artifact by suffix (e.g., "capture1.pcap" matches "Level_2_Artifacts/capture1.pcap")
        row = conn.execute(
            "SELECT * FROM frames WHERE frame_num = ? AND source_artifact LIKE ?",
            (frame_num, f"%{artifact}")
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT * FROM frames WHERE frame_num = ?", (frame_num,)
        ).fetchone()

    if not row:
        print(f"Frame {frame_num} not found" + (f" in {artifact}" if artifact else ""))
        return

    print(f"Frame {row['frame_num']} [{row['source_artifact']}]:")
    print(f"  Level:     {row['level']}")
    print(f"  Timestamp: {row['timestamp_utc']}")
    print(f"  Src MAC:   {row['src_mac']}")
    print(f"  Dst MAC:   {row['dst_mac']}")
    print(f"  Source:    {row['src_ip']}:{row['src_port']}")
    print(f"  Dest:      {row['dst_ip']}:{row['dst_port']}")
    print(f"  Protocol:  {row['protocol']}")
    print(f"  Payload:   {row['payload_len']} bytes")
    print(f"  Info:      {row['info']}")

    # Check for TLS
    if artifact:
        tls = conn.execute(
            "SELECT * FROM tls_fingerprints WHERE frame_num = ? AND source_artifact LIKE ?",
            (frame_num, f"%{artifact}")
        ).fetchone()
    else:
        tls = conn.execute(
            "SELECT * FROM tls_fingerprints WHERE frame_num = ?", (frame_num,)
        ).fetchone()

    if tls:
        print(f"  TLS SNI:   {tls['sni']}")
        print(f"  JA3:       {tls['ja3_hash']}")
        print(f"  JA4:       {tls['ja4_string']}")

    conn.close()


def query_ip(db_path: str, ip: str) -> None:
    """Query frames by IP address."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    rows = conn.execute("""
        SELECT frame_num, timestamp_utc, src_ip, src_port, dst_ip, dst_port, protocol
        FROM frames
        WHERE src_ip = ? OR dst_ip = ?
        ORDER BY timestamp
        LIMIT 100
    """, (ip, ip)).fetchall()

    print(f"Frames involving {ip} (showing first 100):")
    print(f"{'Frame':>8} {'Timestamp':^24} {'Source':^22} {'Dest':^22} {'Proto':<10}")
    print("-" * 90)

    for row in rows:
        src = f"{row['src_ip']}:{row['src_port']}" if row['src_port'] else row['src_ip'] or '-'
        dst = f"{row['dst_ip']}:{row['dst_port']}" if row['dst_port'] else row['dst_ip'] or '-'
        print(f"{row['frame_num']:>8} {row['timestamp_utc']:<24} {src:<22} {dst:<22} {row['protocol']:<10}")

    conn.close()


def query_port(db_path: str, port: int) -> None:
    """Query frames by port number."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    rows = conn.execute("""
        SELECT frame_num, timestamp_utc, src_ip, src_port, dst_ip, dst_port, protocol
        FROM frames
        WHERE src_port = ? OR dst_port = ?
        ORDER BY timestamp
        LIMIT 100
    """, (port, port)).fetchall()

    print(f"Frames involving port {port} (showing first 100):")
    print(f"{'Frame':>8} {'Timestamp':^24} {'Source':^22} {'Dest':^22} {'Proto':<10}")
    print("-" * 90)

    for row in rows:
        src = f"{row['src_ip']}:{row['src_port']}" if row['src_port'] else row['src_ip'] or '-'
        dst = f"{row['dst_ip']}:{row['dst_port']}" if row['dst_port'] else row['dst_ip'] or '-'
        print(f"{row['frame_num']:>8} {row['timestamp_utc']:<24} {src:<22} {dst:<22} {row['protocol']:<10}")

    conn.close()


def query_mac(db_path: str, mac: str) -> None:
    """Query frames by MAC address."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    # Normalize MAC address format (lowercase, colon-separated)
    mac = mac.lower().replace('-', ':')

    rows = conn.execute("""
        SELECT frame_num, timestamp_utc, src_mac, dst_mac, src_ip, dst_ip, protocol
        FROM frames
        WHERE src_mac = ? OR dst_mac = ?
        ORDER BY timestamp
        LIMIT 100
    """, (mac, mac)).fetchall()

    print(f"Frames involving MAC {mac} (showing first 100):")
    print(f"{'Frame':>8} {'Timestamp':^24} {'Src MAC':^18} {'Dst MAC':^18} {'Proto':<10}")
    print("-" * 90)

    for row in rows:
        print(f"{row['frame_num']:>8} {row['timestamp_utc']:<24} {row['src_mac'] or '-':<18} {row['dst_mac'] or '-':<18} {row['protocol']:<10}")

    conn.close()


def query_ja3(db_path: str, ja3_hash: str) -> None:
    """Query frames by JA3 hash."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    rows = conn.execute("""
        SELECT f.frame_num, f.timestamp_utc, f.src_ip, f.src_port, f.dst_ip, f.dst_port,
               t.ja3_hash, t.sni
        FROM tls_fingerprints t
        JOIN frames f ON f.frame_num = t.frame_num
        WHERE t.ja3_hash = ?
        ORDER BY f.timestamp
        LIMIT 100
    """, (ja3_hash,)).fetchall()

    print(f"TLS Client Hellos with JA3 {ja3_hash} (showing first 100):")
    print(f"{'Frame':>8} {'Timestamp':^24} {'Source':^22} {'SNI':<30}")
    print("-" * 90)

    for row in rows:
        src = f"{row['src_ip']}:{row['src_port']}"
        print(f"{row['frame_num']:>8} {row['timestamp_utc']:<24} {src:<22} {row['sni'] or '-':<30}")

    conn.close()


def query_sql(db_path: str, sql: str) -> None:
    """Execute arbitrary SQL query."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    try:
        rows = conn.execute(sql).fetchall()

        if not rows:
            print("No results")
            return

        # Print header
        cols = rows[0].keys()
        print('\t'.join(cols))
        print('-' * 80)

        for row in rows:
            print('\t'.join(str(row[c]) if row[c] is not None else '-' for c in cols))

    except sqlite3.Error as e:
        print(f"SQL Error: {e}", file=sys.stderr)

    conn.close()


def show_stats(db_path: str) -> None:
    """Show database statistics."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    print(f"Database: {db_path}")
    print()

    # Metadata
    print("Metadata:")
    for row in conn.execute("SELECT * FROM metadata"):
        print(f"  {row['key']}: {row['value']}")
    print()

    # Protocol distribution
    print("Protocol distribution:")
    for row in conn.execute("""
        SELECT protocol, COUNT(*) as count
        FROM frames
        GROUP BY protocol
        ORDER BY count DESC
        LIMIT 15
    """):
        print(f"  {row['protocol']:<15} {row['count']:>10,}")
    print()

    # Top source IPs
    print("Top source IPs:")
    for row in conn.execute("""
        SELECT src_ip, COUNT(*) as count
        FROM frames
        WHERE src_ip IS NOT NULL
        GROUP BY src_ip
        ORDER BY count DESC
        LIMIT 10
    """):
        print(f"  {row['src_ip']:<18} {row['count']:>10,}")
    print()

    # Top destination IPs
    print("Top destination IPs:")
    for row in conn.execute("""
        SELECT dst_ip, COUNT(*) as count
        FROM frames
        WHERE dst_ip IS NOT NULL
        GROUP BY dst_ip
        ORDER BY count DESC
        LIMIT 10
    """):
        print(f"  {row['dst_ip']:<18} {row['count']:>10,}")
    print()

    # JA3 fingerprints
    tls_count = conn.execute("SELECT COUNT(*) FROM tls_fingerprints").fetchone()[0]
    if tls_count > 0:
        print(f"TLS Client Hellos: {tls_count:,}")
        print("Top JA3 hashes:")
        for row in conn.execute("""
            SELECT ja3_hash, COUNT(*) as count, GROUP_CONCAT(DISTINCT sni) as snis
            FROM tls_fingerprints
            GROUP BY ja3_hash
            ORDER BY count DESC
            LIMIT 10
        """):
            snis = row['snis'][:50] + '...' if row['snis'] and len(row['snis']) > 50 else row['snis']
            print(f"  {row['ja3_hash']} ({row['count']:>5}) {snis or ''}")

    conn.close()


def main():
    parser = argparse.ArgumentParser(
        description='PCAP Indexer with SQLite storage and JA3/JA4 fingerprinting'
    )
    subparsers = parser.add_subparsers(dest='command', required=True)

    # Dynamic tier choices from project config
    try:
        from forensic_analysis.base import get_available_tiers
        _tiers = get_available_tiers() or ['t1', 't2', 't3']
    except Exception:
        _tiers = ['t1', 't2', 't3']

    # Index command
    index_parser = subparsers.add_parser('index', help='Index a PCAP file')
    index_parser.add_argument('pcap', help='PCAP file to index')
    index_parser.add_argument('--db', help='Output database path (default: pcap_index.db)')
    index_parser.add_argument('--tier', '--level', choices=_tiers, help='Artifact tier')
    index_parser.add_argument('--artifact', help='Source artifact path (e.g., Tier_2_Artifacts/capture1.pcap)')
    index_parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    # Query command
    query_parser = subparsers.add_parser('query', help='Query the index')
    query_parser.add_argument('db', help='Database file')
    query_parser.add_argument('--artifact', '-a', help='Filter by source artifact (e.g., capture1.pcap)')
    query_parser.add_argument('--tier', '--level', '-t', choices=_tiers, help='Filter by artifact tier')
    query_group = query_parser.add_mutually_exclusive_group(required=True)
    query_group.add_argument('--frame', type=int, help='Query by frame number')
    query_group.add_argument('--ip', help='Query by IP address')
    query_group.add_argument('--mac', help='Query by MAC address')
    query_group.add_argument('--port', type=int, help='Query by port number')
    query_group.add_argument('--ja3', help='Query by JA3 hash')
    query_group.add_argument('--sql', help='Execute SQL query')

    # Stats command
    stats_parser = subparsers.add_parser('stats', help='Show database statistics')
    stats_parser.add_argument('db', help='Database file')

    args = parser.parse_args()

    if args.command == 'index':
        db_path = args.db or "pcap_index.db"
        index_pcap(args.pcap, db_path, level=args.tier, artifact_path=args.artifact, verbose=args.verbose)

    elif args.command == 'query':
        if args.frame:
            query_frame(args.db, args.frame, artifact=args.artifact)
        elif args.ip:
            query_ip(args.db, args.ip)
        elif args.mac:
            query_mac(args.db, args.mac)
        elif args.port:
            query_port(args.db, args.port)
        elif args.ja3:
            query_ja3(args.db, args.ja3)
        elif args.sql:
            query_sql(args.db, args.sql)

    elif args.command == 'stats':
        show_stats(args.db)


if __name__ == '__main__':
    main()
