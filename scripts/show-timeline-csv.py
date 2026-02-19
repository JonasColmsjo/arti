#!/usr/bin/env python3
"""Render attack timeline CSVs as colored terminal tables.

Supports two CSV formats:
  - T2: timestamp_utc, phase, event, source_ip, dest_ip, user, severity, ...
  - T1: seq, timestamp_utc, event, source_dest, evidence_type, ...

Usage (via justfile):
    just attack-tl-csv t2 [phase-filter]
    just attack-tl-csv t1 [p|s]
    just attack-tl-csv all [phase-filter]   # Integrated cross-tier view

Environment variables:
    CSV           - path to the CSV file (or comma-separated list)
    PHASE_FILTER  - optional substring to filter phases (T2 / integrated)
    INTEGRATED    - set to "1" for cross-tier integrated view
    TIER_FILTER   - optional: T1, T2, T3 to show only one tier (integrated mode)
"""

import csv
import os
import sys

phase_filter = os.environ.get("PHASE_FILTER", "").strip()
csv_paths = os.environ.get("CSV", "").split(",")
term_w = os.get_terminal_size().columns if sys.stdout.isatty() else 200

# ANSI codes
COLORS = {
    "critical": "\033[91m",
    "suspicious": "\033[33m",
    "notable": "\033[93m",
    "info": "\033[37m",
}
RST = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"


def trunc(s, w):
    return s[: w - 1] + "…" if len(s) > w else s


def read_csvs(paths):
    rows = []
    for p in paths:
        p = p.strip()
        if not p:
            continue
        with open(p) as f:
            rows.extend(csv.DictReader(f))
    return rows


def detect_format(rows):
    if not rows:
        return "unknown"
    return "t2" if "phase" in rows[0] else "t1"


def render_l2(rows):
    if phase_filter:
        rows = [r for r in rows if phase_filter.lower() in r["phase"].lower()]

    W = {"ts": 19, "phase": 20, "src": 16, "dst": 16, "user": 10, "sev": 8}
    fixed = sum(W.values())
    seps = 7 * 3
    w_ev = max(30, term_w - fixed - seps)

    def sep_line(style=""):
        parts = ["─" * W["ts"], "─" * W["phase"], "─" * w_ev,
                 "─" * W["src"], "─" * W["dst"], "─" * W["user"], "─" * W["sev"]]
        return style + "─┼─".join(parts) + RST

    def fmt(ts, phase, event, src, dst, user, sev, color="", row_color=""):
        return (f"{row_color}{ts:<{W['ts']}} │ {phase:<{W['phase']}} │ "
                f"{event:<{w_ev}} │ {src:<{W['src']}} │ {dst:<{W['dst']}} │ "
                f"{user:<{W['user']}} │ {RST}{color}{sev:<{W['sev']}}{RST}")

    print(fmt("TIME (UTC)", "PHASE", "EVENT", "SOURCE", "DEST", "USER", "SEV", row_color=BOLD))
    print(sep_line())

    prev_phase = ""
    for r in rows:
        ts = r["timestamp_utc"].replace("T", " ")[:W["ts"]]
        phase = trunc(r["phase"], W["phase"])
        event = trunc(r["event"], w_ev)
        src = trunc(r.get("source_ip", ""), W["src"])
        dst = trunc(r.get("dest_ip", ""), W["dst"])
        user = trunc(r.get("user", ""), W["user"])
        sev = r.get("severity", "")
        color = COLORS.get(sev, "")

        if r["phase"] != prev_phase and prev_phase:
            print(sep_line(DIM))
        prev_phase = r["phase"]

        print(fmt(ts, phase, event, src, dst, user, sev, color=color))

    footer = f"\n{DIM}{len(rows)} events"
    if phase_filter:
        footer += f" (filtered: {phase_filter})"
    legend = (f"  │  {COLORS['critical']}■ critical{RST}"
              f"  {COLORS['suspicious']}■ suspicious{RST}"
              f"  {COLORS['notable']}■ notable{RST}"
              f"  {COLORS['info']}■ info{RST}")
    print(footer + legend + RST)


LEVEL_COLORS = {
    "L1": "\033[96m",   # cyan
    "L2": "\033[95m",   # magenta
    "L3": "\033[92m",   # green
}


def normalize_l1_row(row, level_label):
    """Convert L1 format row to L2 format for integrated display."""
    src_dst = row.get("source_dest", "")
    src, dst = "", ""
    if " → " in src_dst:
        src, dst = src_dst.split(" → ", 1)
    elif " -> " in src_dst:
        src, dst = src_dst.split(" -> ", 1)
    return {
        "timestamp_utc": row["timestamp_utc"],
        "timestamp_cet": "",
        "phase": row.get("evidence_type", "L1"),
        "event": row["event"],
        "source_ip": src.strip(),
        "dest_ip": dst.strip(),
        "user": "",
        "evidence": row.get("evidence_file", ""),
        "mitre": "",
        "severity": "",
        "notes": "",
        "level": level_label,
    }


def read_csvs_with_tier(paths):
    """Read CSVs and tag each row with its tier (derived from path)."""
    rows = []
    for p in paths:
        p = p.strip()
        if not p:
            continue
        level_label = "??"
        if "/tier1/" in p or "/t1" in p.lower():
            level_label = "L1"
        elif "/tier2/" in p or "/t2" in p.lower():
            level_label = "L2"
        elif "/tier3/" in p or "/t3" in p.lower():
            level_label = "L3"
        with open(p) as f:
            for row in csv.DictReader(f):
                if "phase" not in row:
                    row = normalize_l1_row(row, level_label)
                else:
                    row["level"] = level_label
                rows.append(row)
    return rows


def render_integrated(rows):
    """Render multi-tier timeline sorted chronologically."""
    level_filter = os.environ.get("TIER_FILTER", os.environ.get("LEVEL_FILTER", "")).strip().upper()
    if phase_filter:
        rows = [r for r in rows if phase_filter.lower() in r.get("phase", "").lower()]
    if level_filter:
        rows = [r for r in rows if level_filter in r.get("level", "").upper()]

    rows.sort(key=lambda r: r.get("timestamp_utc", ""))

    W = {"lvl": 3, "ts": 19, "phase": 18, "src": 16, "dst": 16, "sev": 8}
    fixed = sum(W.values())
    seps = 7 * 3
    w_ev = max(30, term_w - fixed - seps)

    def sep_line(style=""):
        parts = ["─" * W["lvl"], "─" * W["ts"], "─" * W["phase"], "─" * w_ev,
                 "─" * W["src"], "─" * W["dst"], "─" * W["sev"]]
        return style + "─┼─".join(parts) + RST

    def fmt(lvl, ts, phase, event, src, dst, sev, color="", lvl_color=""):
        return (f"{lvl_color}{lvl:<{W['lvl']}}{RST} │ {ts:<{W['ts']}} │ {phase:<{W['phase']}} │ "
                f"{event:<{w_ev}} │ {src:<{W['src']}} │ {dst:<{W['dst']}} │ "
                f"{RST}{color}{sev:<{W['sev']}}{RST}")

    print(fmt("LVL", "TIME (UTC)", "PHASE", "EVENT", "SOURCE", "DEST", "SEV",
              lvl_color=BOLD))
    print(sep_line())

    prev_level = ""
    for r in rows:
        lvl = r.get("level", "??")
        ts = r["timestamp_utc"].replace("T", " ")[:W["ts"]]
        phase = trunc(r.get("phase", ""), W["phase"])
        event = trunc(r["event"], w_ev)
        src = trunc(r.get("source_ip", ""), W["src"])
        dst = trunc(r.get("dest_ip", ""), W["dst"])
        sev = r.get("severity", "")
        color = COLORS.get(sev, "")
        lvl_color = LEVEL_COLORS.get(lvl, "")

        if lvl != prev_level and prev_level:
            print(sep_line(DIM))
        prev_level = lvl

        print(fmt(lvl, ts, phase, event, src, dst, sev, color=color, lvl_color=lvl_color))

    footer = f"\n{DIM}{len(rows)} events"
    if phase_filter:
        footer += f" (phase: {phase_filter})"
    if level_filter:
        footer += f" (tier: {level_filter})"
    legend = (f"  │  {LEVEL_COLORS['L1']}■ L1{RST}"
              f"  {LEVEL_COLORS['L2']}■ L2{RST}"
              f"  {LEVEL_COLORS['L3']}■ L3{RST}"
              f"  │  {COLORS['critical']}■ critical{RST}"
              f"  {COLORS['suspicious']}■ suspicious{RST}"
              f"  {COLORS['notable']}■ notable{RST}"
              f"  {COLORS['info']}■ info{RST}")
    print(footer + legend + RST)


def render_l1(rows):
    W = {"seq": 4, "ts": 16, "src_dst": 30, "ev_type": 8}
    fixed = sum(W.values())
    seps = 5 * 3
    w_ev = max(30, term_w - fixed - seps)

    def sep_line(style=""):
        parts = ["─" * W["seq"], "─" * W["ts"], "─" * w_ev,
                 "─" * W["src_dst"], "─" * W["ev_type"]]
        return style + "─┼─".join(parts) + RST

    def fmt(seq, ts, event, src_dst, ev_type, color=""):
        return (f"{color}{seq:>{W['seq']}} │ {ts:<{W['ts']}} │ "
                f"{event:<{w_ev}} │ {src_dst:<{W['src_dst']}} │ "
                f"{ev_type:<{W['ev_type']}}{RST}")

    print(fmt("#", "TIME (UTC)", "EVENT", "SOURCE → DEST", "EVIDENCE", BOLD))
    print(sep_line())

    for r in rows:
        seq = r.get("seq", "")
        ts = r["timestamp_utc"][:W["ts"]]
        event = trunc(r["event"], w_ev)
        src_dst = trunc(r.get("source_dest", ""), W["src_dst"])
        ev_type = trunc(r.get("evidence_type", ""), W["ev_type"])
        print(fmt(seq, ts, event, src_dst, ev_type))

    print(f"\n{DIM}{len(rows)} events{RST}")


integrated = os.environ.get("INTEGRATED", "").strip()

if integrated:
    rows = read_csvs_with_tier(csv_paths)
    render_integrated(rows)
else:
    rows = read_csvs(csv_paths)
    fmt = detect_format(rows)
    if fmt == "t2":
        render_l2(rows)
    elif fmt == "t1":
        render_l1(rows)
    else:
        print("No data or unrecognized CSV format.", file=sys.stderr)
        sys.exit(1)
