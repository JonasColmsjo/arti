#!/usr/bin/env python3
"""Fast packet queries using Polars.

Query the pre-extracted packets.csv file with various filters.
Much faster than tshark for repeated queries on large PCAPs.

Usage:
    query_packets.py --tier 2 ip 192.168.24.144
    query_packets.py --tier 2 mac 8c:ae:4c:e1:37:94
    query_packets.py --tier 2 port 3389
    query_packets.py --tier 2 stats
"""

import os
import sys
from pathlib import Path

import click
import polars as pl

PROJECT_ROOT = Path(os.environ.get('PROJECT_ROOT', Path.cwd()))


def get_packets_csv(tier: int) -> Path:
    """Get path to packets.csv for the specified tier."""
    return PROJECT_ROOT / f'work/tier{tier}/automated/network/extractions/packets.csv'


def load_packets(csv_path: Path, lazy: bool = True) -> pl.LazyFrame | pl.DataFrame:
    """Load packets CSV, optionally as lazy frame for efficiency."""
    if not csv_path.exists():
        click.echo(f"Error: {csv_path} not found. Run: just packets-extract t{csv_path.parent.parent.parent.name[-1]}", err=True)
        sys.exit(1)

    if lazy:
        return pl.scan_csv(csv_path)
    return pl.read_csv(csv_path)


def output_results(df: pl.LazyFrame | pl.DataFrame, count: bool, head: int, csv_out: bool, tail: int = 0):
    """Output query results in requested format."""
    # Collect if lazy
    if isinstance(df, pl.LazyFrame):
        if count:
            result = df.select(pl.len()).collect()
            click.echo(f"{result.item():,} packets")
            return
        df = df.collect()

    if count:
        click.echo(f"{len(df):,} packets")
        return

    if head > 0:
        df = df.head(head)
    elif tail > 0:
        df = df.tail(tail)

    if csv_out:
        click.echo(df.write_csv())
    else:
        # Pretty print with limited width
        with pl.Config(tbl_cols=12, tbl_width_chars=200, tbl_rows=100):
            click.echo(df)


@click.group()
@click.option('--tier', '-t', default=2, type=int, help='Artifact tier (1, 2, or 3)')
@click.pass_context
def cli(ctx, tier):
    """Fast packet queries using Polars."""
    ctx.ensure_object(dict)
    ctx.obj['tier'] = tier
    ctx.obj['csv'] = get_packets_csv(tier)


@cli.command()
@click.argument('address')
@click.option('--count', '-c', is_flag=True, help='Only show count')
@click.option('--head', '-n', default=0, help='Show first N rows')
@click.option('--tail', '-t', default=0, help='Show last N rows')
@click.option('--csv', 'csv_out', is_flag=True, help='Output as CSV')
@click.option('--src', is_flag=True, help='Match source IP only')
@click.option('--dst', is_flag=True, help='Match destination IP only')
@click.pass_context
def ip(ctx, address, count, head, tail, csv_out, src, dst):
    """Filter packets by IP address (src or dst)."""
    df = load_packets(ctx.obj['csv'])

    if src:
        df = df.filter(pl.col('src_ip') == address)
    elif dst:
        df = df.filter(pl.col('dst_ip') == address)
    else:
        df = df.filter((pl.col('src_ip') == address) | (pl.col('dst_ip') == address))

    output_results(df, count, head, csv_out, tail)


@cli.command()
@click.argument('address')
@click.option('--count', '-c', is_flag=True, help='Only show count')
@click.option('--head', '-n', default=0, help='Show first N rows')
@click.option('--tail', '-t', default=0, help='Show last N rows')
@click.option('--csv', 'csv_out', is_flag=True, help='Output as CSV')
@click.pass_context
def mac(ctx, address, count, head, tail, csv_out):
    """Filter packets by MAC address (src or dst)."""
    df = load_packets(ctx.obj['csv'])
    address_lower = address.lower()

    df = df.filter(
        (pl.col('src_mac').str.to_lowercase() == address_lower) |
        (pl.col('dst_mac').str.to_lowercase() == address_lower)
    )

    output_results(df, count, head, csv_out, tail)


@cli.command()
@click.argument('port_num', type=str)
@click.option('--count', '-c', is_flag=True, help='Only show count')
@click.option('--head', '-n', default=0, help='Show first N rows')
@click.option('--tail', '-t', default=0, help='Show last N rows')
@click.option('--csv', 'csv_out', is_flag=True, help='Output as CSV')
@click.option('--tcp', is_flag=True, help='TCP ports only')
@click.option('--udp', is_flag=True, help='UDP ports only')
@click.pass_context
def port(ctx, port_num, count, head, tail, csv_out, tcp, udp):
    """Filter packets by port number (src or dst, TCP or UDP)."""
    df = load_packets(ctx.obj['csv'])

    conditions = []
    if tcp or not udp:
        conditions.extend([
            pl.col('tcp_srcport').cast(pl.Utf8) == port_num,
            pl.col('tcp_dstport').cast(pl.Utf8) == port_num,
        ])
    if udp or not tcp:
        conditions.extend([
            pl.col('udp_srcport').cast(pl.Utf8) == port_num,
            pl.col('udp_dstport').cast(pl.Utf8) == port_num,
        ])

    df = df.filter(pl.any_horizontal(conditions))
    output_results(df, count, head, csv_out, tail)


@cli.command()
@click.argument('protocol')
@click.option('--count', '-c', is_flag=True, help='Only show count')
@click.option('--head', '-n', default=0, help='Show first N rows')
@click.option('--tail', '-t', default=0, help='Show last N rows')
@click.option('--csv', 'csv_out', is_flag=True, help='Output as CSV')
@click.pass_context
def proto(ctx, protocol, count, head, tail, csv_out):
    """Filter packets by protocol (TCP, UDP, ARP, etc.)."""
    df = load_packets(ctx.obj['csv'])
    df = df.filter(pl.col('protocol').str.to_uppercase() == protocol.upper())
    output_results(df, count, head, csv_out, tail)


@cli.command()
@click.argument('pcap_source')
@click.option('--count', '-c', is_flag=True, help='Only show count')
@click.option('--head', '-n', default=0, help='Show first N rows')
@click.option('--tail', '-t', default=0, help='Show last N rows')
@click.option('--csv', 'csv_out', is_flag=True, help='Output as CSV')
@click.pass_context
def source(ctx, pcap_source, count, head, tail, csv_out):
    """Filter packets by source PCAP name."""
    df = load_packets(ctx.obj['csv'])
    df = df.filter(pl.col('source') == pcap_source)
    output_results(df, count, head, csv_out, tail)


@cli.command()
@click.argument('src_tier', type=int)
@click.option('--count', '-c', is_flag=True, help='Only show count')
@click.option('--head', '-n', default=0, help='Show first N rows')
@click.option('--tail', '-t', default=0, help='Show last N rows')
@click.option('--csv', 'csv_out', is_flag=True, help='Output as CSV')
@click.pass_context
def tier(ctx, src_tier, count, head, tail, csv_out):
    """Filter packets by artifact tier (1, 2, or 3)."""
    df = load_packets(ctx.obj['csv'])
    # CSV column is named 'level' for backwards compatibility
    df = df.filter(pl.col('level') == src_tier)
    output_results(df, count, head, csv_out, tail)


@cli.command()
@click.argument('pattern')
@click.option('--count', '-c', is_flag=True, help='Only show count')
@click.option('--head', '-n', default=0, help='Show first N rows')
@click.option('--tail', '-t', default=0, help='Show last N rows')
@click.option('--csv', 'csv_out', is_flag=True, help='Output as CSV')
@click.pass_context
def search(ctx, pattern, count, head, tail, csv_out):
    """Search packets with regex pattern across all string columns."""
    df = load_packets(ctx.obj['csv'])

    # Search across all string columns
    string_cols = ['timestamp_utc', 'source', 'src_mac', 'src_ip', 'dst_mac', 'dst_ip', 'protocol']
    conditions = [pl.col(c).cast(pl.Utf8).str.contains(pattern, literal=False) for c in string_cols]

    df = df.filter(pl.any_horizontal(conditions))
    output_results(df, count, head, csv_out, tail)


@cli.command()
@click.pass_context
def stats(ctx):
    """Show packet statistics by source PCAP."""
    df = load_packets(ctx.obj['csv'], lazy=False)

    click.echo(f"Total packets: {len(df):,}\n")
    click.echo("Packets per source:")

    stats = df.group_by('level', 'source').agg(
        pl.len().alias('packets')
    ).sort('level', 'source')

    with pl.Config(tbl_rows=50):
        click.echo(stats)


@cli.command('top-ips')
@click.argument('n', default=10, type=int)
@click.option('--src', is_flag=True, help='Source IPs only')
@click.option('--dst', is_flag=True, help='Destination IPs only')
@click.pass_context
def top_ips(ctx, n, src, dst):
    """Show top N IP addresses by packet count."""
    df = load_packets(ctx.obj['csv'], lazy=False)

    if src:
        click.echo(f"Top {n} source IPs:")
        result = df.filter(pl.col('src_ip') != '').group_by('src_ip').agg(
            pl.len().alias('packets')
        ).sort('packets', descending=True).head(n)
        click.echo(result)
    elif dst:
        click.echo(f"Top {n} destination IPs:")
        result = df.filter(pl.col('dst_ip') != '').group_by('dst_ip').agg(
            pl.len().alias('packets')
        ).sort('packets', descending=True).head(n)
        click.echo(result)
    else:
        # Combine src and dst
        click.echo(f"Top {n} IPs (src + dst combined):")
        src_counts = df.filter(pl.col('src_ip') != '').select(
            pl.col('src_ip').alias('ip')
        )
        dst_counts = df.filter(pl.col('dst_ip') != '').select(
            pl.col('dst_ip').alias('ip')
        )
        combined = pl.concat([src_counts, dst_counts])
        result = combined.group_by('ip').agg(
            pl.len().alias('packets')
        ).sort('packets', descending=True).head(n)
        click.echo(result)


@cli.command('top-macs')
@click.argument('n', default=10, type=int)
@click.pass_context
def top_macs(ctx, n):
    """Show top N MAC addresses by packet count."""
    df = load_packets(ctx.obj['csv'], lazy=False)

    click.echo(f"Top {n} MACs (src + dst combined):")
    src_counts = df.filter(pl.col('src_mac') != '').select(
        pl.col('src_mac').alias('mac')
    )
    dst_counts = df.filter(pl.col('dst_mac') != '').select(
        pl.col('dst_mac').alias('mac')
    )
    combined = pl.concat([src_counts, dst_counts])
    result = combined.group_by('mac').agg(
        pl.len().alias('packets')
    ).sort('packets', descending=True).head(n)
    click.echo(result)


@cli.command('top-ports')
@click.argument('n', default=10, type=int)
@click.option('--tcp', is_flag=True, help='TCP ports only')
@click.option('--udp', is_flag=True, help='UDP ports only')
@click.pass_context
def top_ports(ctx, n, tcp, udp):
    """Show top N ports by packet count."""
    df = load_packets(ctx.obj['csv'], lazy=False)

    all_ports = []

    if tcp or not udp:
        tcp_src = df.filter(pl.col('tcp_srcport') != '').select(
            pl.col('tcp_srcport').alias('port'), pl.lit('TCP').alias('proto')
        )
        tcp_dst = df.filter(pl.col('tcp_dstport') != '').select(
            pl.col('tcp_dstport').alias('port'), pl.lit('TCP').alias('proto')
        )
        all_ports.extend([tcp_src, tcp_dst])

    if udp or not tcp:
        udp_src = df.filter(pl.col('udp_srcport') != '').select(
            pl.col('udp_srcport').alias('port'), pl.lit('UDP').alias('proto')
        )
        udp_dst = df.filter(pl.col('udp_dstport') != '').select(
            pl.col('udp_dstport').alias('port'), pl.lit('UDP').alias('proto')
        )
        all_ports.extend([udp_src, udp_dst])

    if not all_ports:
        click.echo("No ports found")
        return

    combined = pl.concat(all_ports)
    result = combined.group_by('proto', 'port').agg(
        pl.len().alias('packets')
    ).sort('packets', descending=True).head(n)

    click.echo(f"Top {n} ports:")
    click.echo(result)


@cli.command()
@click.pass_context
def protocols(ctx):
    """Show protocol distribution."""
    df = load_packets(ctx.obj['csv'], lazy=False)

    result = df.group_by('protocol').agg(
        pl.len().alias('packets')
    ).sort('packets', descending=True)

    click.echo("Protocol distribution:")
    with pl.Config(tbl_rows=50):
        click.echo(result)


@cli.command()
@click.argument('start_time')
@click.argument('end_time', required=False)
@click.option('--count', '-c', is_flag=True, help='Only show count')
@click.option('--head', '-n', default=0, help='Show first N rows')
@click.option('--tail', '-t', default=0, help='Show last N rows')
@click.option('--csv', 'csv_out', is_flag=True, help='Output as CSV')
@click.pass_context
def timerange(ctx, start_time, end_time, count, head, tail, csv_out):
    """Filter packets by time range.

    Examples:
        timerange 2020-11-05                    # All packets on Nov 5
        timerange 2020-11-05T10:00 2020-11-05T11:00  # Between 10:00-11:00
        timerange "2020-11-05 10:00"            # Prefix match
    """
    df = load_packets(ctx.obj['csv'])

    if end_time:
        df = df.filter(
            (pl.col('timestamp_utc') >= start_time) &
            (pl.col('timestamp_utc') <= end_time)
        )
    else:
        # Prefix match
        df = df.filter(pl.col('timestamp_utc').str.starts_with(start_time))

    output_results(df, count, head, csv_out, tail)


@cli.command()
@click.argument('ip1')
@click.argument('ip2')
@click.option('--count', '-c', is_flag=True, help='Only show count')
@click.option('--head', '-n', default=0, help='Show first N rows')
@click.option('--tail', '-t', default=0, help='Show last N rows')
@click.option('--csv', 'csv_out', is_flag=True, help='Output as CSV')
@click.pass_context
def conversation(ctx, ip1, ip2, count, head, tail, csv_out):
    """Show packets between two IP addresses (bidirectional)."""
    df = load_packets(ctx.obj['csv'])

    df = df.filter(
        ((pl.col('src_ip') == ip1) & (pl.col('dst_ip') == ip2)) |
        ((pl.col('src_ip') == ip2) & (pl.col('dst_ip') == ip1))
    )

    output_results(df, count, head, csv_out, tail)


if __name__ == '__main__':
    cli()
