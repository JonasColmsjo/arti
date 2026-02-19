#!/usr/bin/env python3
"""
Visualization Generator for Forensic Artifacts

Generates charts with multiple output formats and time aggregations.

Usage:
    python visualize_ascii.py plaso                    # ASCII, daily (default)
    python visualize_ascii.py plaso --hourly --plotly  # Plotly, hourly
    python visualize_ascii.py firewall --monthly --png # PNG, monthly

Environment:
    ARTIFACTS_PATH  Base path for artifact files
    WORK_PATH      Base path for work/output files (defaults to ./work)
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from dataclasses import dataclass
from typing import Optional

import pandas as pd
import yaml

# =============================================================================
# Configuration
# =============================================================================

SCRIPT_DIR = Path(__file__).parent

# Use environment variables for portability
ARTIFACTS_PATH = Path(os.environ.get('ARTIFACTS_PATH', '/home/me/data/bth-kurs'))
WORK_PATH = Path(os.environ.get('WORK_PATH', Path.cwd() / 'work'))

# Artifact locations (can be overridden with --source-file)
ARTIFACT_DIR = ARTIFACTS_PATH / "artifacts-unpacked/Tier_1_Artifacts"
WORK_DIR = WORK_PATH / "level1"
DEFAULT_OUTPUT_DIR = WORK_DIR / "ascii-charts"

# Global settings (set by args)
OUTPUT_DIR = DEFAULT_OUTPUT_DIR
OUTPUT_FORMAT = 'ascii'  # ascii, png, plotly
TIME_AGG = 'daily'  # daily, monthly, hourly
TIME_START = None  # Optional start date filter
TIME_END = None    # Optional end date filter
NO_ANNOTATIONS = False  # Disable annotations/markers
BY_USER = False  # Group by user instead of total count
USERS = []  # Users to track (set via --users flag)

# NOTE: Keep this script GENERIC - no hardcoding of source-specific values.
# Use command-line arguments for source-specific filtering (e.g., --users)


# =============================================================================
# Standardized Data Structure
# =============================================================================

@dataclass
class TimeSeriesData:
    """Standardized time series data for plotting."""
    df: pd.DataFrame          # Must have 'date' and 'count' columns
    title: str
    subtitle: str
    markers: dict             # {date_str: label} for annotations
    date_col: str = 'date'
    count_col: str = 'count'


@dataclass
class MultiSeriesData:
    """Time series data with multiple series (e.g., by user)."""
    df: pd.DataFrame          # Must have 'date' column and one column per series
    title: str
    subtitle: str
    markers: dict             # {date_str: label} for annotations
    series_cols: list         # List of column names for each series
    date_col: str = 'date'


# =============================================================================
# Utilities
# =============================================================================

def ascii_bar(value: int, max_value: int, width: int = 50, char: str = "█") -> str:
    """Generate an ASCII bar of proportional length."""
    if max_value == 0:
        return ""
    bar_len = int((value / max_value) * width)
    return char * bar_len


def load_markers(marker_file: str, date_values: list[str]) -> dict:
    """
    Load markers from YAML file and filter to only those matching dates in data.

    Args:
        marker_file: YAML file name in OUTPUT_DIR
        date_values: List of date strings present in the data (for filtering)

    Returns:
        Dict of {date_str: label} filtered to matching dates
    """
    marker_path = OUTPUT_DIR / marker_file
    if not marker_path.exists():
        # Try in work dir
        marker_path = WORK_DIR / marker_file
        if not marker_path.exists():
            return {}

    with open(marker_path, 'r') as f:
        all_markers = yaml.safe_load(f) or {}

    # Convert all marker keys to strings
    all_markers = {str(k): v for k, v in all_markers.items()}

    # Filter to only markers that match dates in the data
    filtered = {}
    for date_str in date_values:
        if date_str in all_markers:
            filtered[date_str] = all_markers[date_str]

    return filtered


def format_date(dt: pd.Timestamp, agg: str) -> str:
    """Format datetime based on aggregation level."""
    if agg == 'hourly':
        return dt.strftime('%Y-%m-%d %H:%M')
    elif agg == 'monthly':
        return dt.strftime('%Y-%m')
    else:  # daily
        return dt.strftime('%Y-%m-%d')


# =============================================================================
# Generic Plotter Functions
# =============================================================================

def plot_ascii(data: TimeSeriesData):
    """Plot time series data as ASCII bar chart."""
    df = data.df
    max_count = df[data.count_col].max()

    print(f"\n{'=' * 100}")
    print(f"  {data.title}")
    print(f"  {data.subtitle}")
    print(f"{'=' * 100}\n")

    for _, row in df.iterrows():
        label = str(row[data.date_col])
        count = row[data.count_col]
        bar = ascii_bar(count, max_count, width=50)

        marker = data.markers.get(label, "")
        marker_str = f" ← ★ {marker}" if marker else ""

        print(f"{label} │ {bar} {count:>7,}{marker_str}")

    print()


def plot_png(data: TimeSeriesData, filename: str):
    """Plot time series data as PNG using Plotly (same as HTML but exported to PNG)."""
    import plotly.graph_objects as go

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    df = data.df
    dates = pd.to_datetime(df[data.date_col])
    counts = df[data.count_col]

    # Create colors array
    colors = []
    for i, date in enumerate(dates):
        date_str = str(df.iloc[i][data.date_col])
        if date_str in data.markers:
            colors.append('crimson')
        else:
            colors.append('steelblue')

    # Create hover text
    hover_text = []
    for i, (date, count) in enumerate(zip(dates, counts)):
        date_str = str(df.iloc[i][data.date_col])
        if date_str in data.markers:
            hover_text.append(f"<b>{date_str}</b><br>Events: {count:,}<br><b>★ {data.markers[date_str]}</b>")
        else:
            hover_text.append(f"<b>{date_str}</b><br>Events: {count:,}")

    # Create figure
    fig = go.Figure()

    fig.add_trace(go.Bar(
        x=dates,
        y=counts,
        marker_color=colors,
        marker_line_color='navy',
        marker_line_width=1,
        hovertext=hover_text,
        hoverinfo='text',
        name='Events'
    ))

    # Add annotations for marked dates
    annotations = []
    for i, (date, count) in enumerate(zip(dates, counts)):
        date_str = str(df.iloc[i][data.date_col])
        if date_str in data.markers:
            annotations.append(dict(
                x=date,
                y=count,
                text=f"<b>{data.markers[date_str]}</b>",
                showarrow=True,
                arrowhead=2,
                arrowsize=1,
                arrowwidth=2,
                arrowcolor='darkred',
                ax=0,
                ay=-40,
                font=dict(size=10, color='darkred'),
                bgcolor='rgba(255,255,255,0.8)',
                bordercolor='darkred',
                borderwidth=1
            ))

    # Configure x-axis based on time aggregation
    if TIME_AGG == 'hourly':
        xaxis_config = dict(
            tickformat='%b %d %H:%M',
            tickangle=45,
            tickfont=dict(size=10),
            showgrid=True,
            gridcolor='lightgray'
        )
    elif TIME_AGG == 'monthly':
        xaxis_config = dict(
            tickformat='%b %Y',
            tickangle=0,
            dtick='M1',
            tickfont=dict(size=12),
            showgrid=True,
            gridcolor='lightgray'
        )
    else:  # daily
        xaxis_config = dict(
            tickformat='%b %d',
            tickangle=45,
            tickfont=dict(size=10),
            showgrid=True,
            gridcolor='lightgray'
        )

    fig.update_layout(
        title=dict(
            text=f'<b>{data.title}</b><br><sup>{data.subtitle}</sup>',
            x=0.5,
            font=dict(size=18)
        ),
        xaxis_title='Date',
        yaxis_title='Event Count',
        template='plotly_white',
        hovermode='x unified',
        annotations=annotations,
        xaxis=xaxis_config,
        yaxis=dict(
            tickformat=',',
            gridcolor='lightgray'
        ),
        height=600,
        width=1200,
        margin=dict(t=100, b=120)
    )

    png_path = OUTPUT_DIR / filename
    fig.write_image(str(png_path), scale=2)

    print(f"\nSaved: {png_path}")
    subprocess.run(['xdg-open', str(png_path)], check=False)


def plot_plotly(data: TimeSeriesData, filename: str):
    """Plot time series data as interactive HTML using Plotly."""
    import plotly.graph_objects as go

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    df = data.df
    dates = pd.to_datetime(df[data.date_col])
    counts = df[data.count_col]

    # Create colors array
    colors = []
    for i, date in enumerate(dates):
        date_str = str(df.iloc[i][data.date_col])
        if date_str in data.markers:
            colors.append('crimson')
        else:
            colors.append('steelblue')

    # Create hover text
    hover_text = []
    for i, (date, count) in enumerate(zip(dates, counts)):
        date_str = str(df.iloc[i][data.date_col])
        if date_str in data.markers:
            hover_text.append(f"<b>{date_str}</b><br>Events: {count:,}<br><b>★ {data.markers[date_str]}</b>")
        else:
            hover_text.append(f"<b>{date_str}</b><br>Events: {count:,}")

    # Create figure
    fig = go.Figure()

    fig.add_trace(go.Bar(
        x=dates,
        y=counts,
        marker_color=colors,
        marker_line_color='navy',
        marker_line_width=1,
        hovertext=hover_text,
        hoverinfo='text',
        name='Events'
    ))

    # Add annotations for marked dates
    annotations = []
    for i, (date, count) in enumerate(zip(dates, counts)):
        date_str = str(df.iloc[i][data.date_col])
        if date_str in data.markers:
            annotations.append(dict(
                x=date,
                y=count,
                text=f"<b>{data.markers[date_str]}</b>",
                showarrow=True,
                arrowhead=2,
                arrowsize=1,
                arrowwidth=2,
                arrowcolor='darkred',
                ax=0,
                ay=-40,
                font=dict(size=10, color='darkred'),
                bgcolor='rgba(255,255,255,0.8)',
                bordercolor='darkred',
                borderwidth=1
            ))

    # Configure x-axis based on time aggregation
    if TIME_AGG == 'hourly':
        xaxis_config = dict(
            tickformat='%b %d %H:%M',
            tickangle=45,
            tickfont=dict(size=10),
            showgrid=True,
            gridcolor='lightgray'
        )
    elif TIME_AGG == 'monthly':
        xaxis_config = dict(
            tickformat='%b %Y',
            tickangle=0,
            dtick='M1',
            tickfont=dict(size=12),
            showgrid=True,
            gridcolor='lightgray'
        )
    else:  # daily
        xaxis_config = dict(
            tickformat='%b %d',
            tickangle=45,
            tickfont=dict(size=10),
            showgrid=True,
            gridcolor='lightgray'
        )

    fig.update_layout(
        title=dict(
            text=f'<b>{data.title}</b><br><sup>{data.subtitle}</sup>',
            x=0.5,
            font=dict(size=18)
        ),
        xaxis_title='Date',
        yaxis_title='Event Count',
        template='plotly_white',
        hovermode='x unified',
        annotations=annotations,
        xaxis=xaxis_config,
        yaxis=dict(
            tickformat=',',
            gridcolor='lightgray'
        ),
        height=600,
        margin=dict(t=100, b=120)
    )

    html_path = OUTPUT_DIR / filename
    fig.write_html(str(html_path))

    print(f"\nSaved: {html_path}")
    subprocess.run(['xdg-open', str(html_path)], check=False)


def plot_data(data: TimeSeriesData, base_filename: str):
    """Plot data using the selected output mode."""
    if OUTPUT_FORMAT == 'plotly':
        plot_plotly(data, f"{base_filename}.html")
    elif OUTPUT_FORMAT == 'png':
        plot_png(data, f"{base_filename}.png")
    else:
        plot_ascii(data)


# =============================================================================
# Multi-Series Plotter Functions (by user)
# =============================================================================

def plot_ascii_multi(data: MultiSeriesData):
    """Plot multi-series data as ASCII bar chart with columns per user."""
    df = data.df

    # Find max across all series for scaling
    max_count = max(df[col].max() for col in data.series_cols)

    # Column widths
    col_width = 15

    print(f"\n{'=' * 120}")
    print(f"  {data.title}")
    print(f"  {data.subtitle}")
    print(f"{'=' * 120}\n")

    # Header
    header = f"{'Date':<20} │"
    for col in data.series_cols:
        header += f" {col:^{col_width}} │"
    print(header)
    print("─" * len(header))

    for _, row in df.iterrows():
        label = str(row[data.date_col])
        line = f"{label:<20} │"

        for col in data.series_cols:
            count = row[col]
            bar_len = int((count / max_count) * 8) if max_count > 0 else 0
            bar = "█" * bar_len
            line += f" {bar:<8} {count:>5,} │"

        marker = data.markers.get(label, "")
        marker_str = f" ← ★ {marker}" if marker else ""

        print(f"{line}{marker_str}")

    print()


def plot_plotly_multi(data: MultiSeriesData, filename: str):
    """Plot multi-series data as stacked subplots (one row per user) using Plotly."""
    from plotly.subplots import make_subplots
    import plotly.graph_objects as go

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    df = data.df
    dates = pd.to_datetime(df[data.date_col])
    n_series = len(data.series_cols)

    # Color palette for users
    colors = {
        't.johnson': '#e74c3c',      # Red - human user (key)
        'systemprofile': '#3498db',   # Blue - system
        'LocalService': '#2ecc71',    # Green - service
        'NetworkService': '#9b59b6',  # Purple - network
    }

    # Create subplots: annotations row + one row per user
    n_rows = n_series + 1  # +1 for annotations row
    row_heights = [0.15] + [0.85 / n_series] * n_series  # Small top row for annotations

    fig = make_subplots(
        rows=n_rows,
        cols=1,
        shared_xaxes=True,
        vertical_spacing=0.08,  # Increased spacing between subplots
        subplot_titles=['Events'] + data.series_cols,
        row_heights=row_heights
    )

    # Row 1: Annotations row (markers only, with alternating y-positions)
    marker_dates = []
    marker_labels = []
    marker_y = []
    for i, date in enumerate(dates):
        date_str = str(df.iloc[i][data.date_col])
        if date_str in data.markers:
            marker_dates.append(date)
            marker_labels.append(data.markers[date_str])
            # Alternate y-position: 1, 2, 3, 1, 2, 3...
            marker_y.append((len(marker_dates) % 3) + 1)

    if marker_dates:
        fig.add_trace(
            go.Scatter(
                x=marker_dates,
                y=marker_y,
                mode='markers+text',
                marker=dict(symbol='star', size=12, color='darkred'),
                text=marker_labels,
                textposition='middle right',
                textfont=dict(size=9, color='darkred'),
                hovertemplate="<b>%{text}</b><br>%{x}<extra></extra>",
                showlegend=False
            ),
            row=1,
            col=1
        )

    # Rows 2+: User data
    for idx, col in enumerate(data.series_cols, 2):  # Start at row 2
        counts = df[col]
        color = colors.get(col, '#95a5a6')

        fig.add_trace(
            go.Bar(
                x=dates,
                y=counts,
                name=col,
                marker_color=color,
                hovertemplate=f"<b>{col}</b><br>%{{x}}<br>Events: %{{y:,}}<extra></extra>",
                showlegend=False
            ),
            row=idx,
            col=1
        )

    # Configure x-axis based on time aggregation
    if TIME_AGG == 'hourly':
        tickformat = '%b %d %H:%M'
        tickangle = 45
    elif TIME_AGG == 'monthly':
        tickformat = '%b %Y'
        tickangle = 0
    else:  # daily
        tickformat = '%b %d'
        tickangle = 45

    fig.update_layout(
        title=dict(
            text=f'<b>{data.title}</b><br><sup>{data.subtitle}</sup>',
            x=0.5,
            font=dict(size=18)
        ),
        template='plotly_white',
        hovermode='x unified',
        height=200 * n_series + 200,
        margin=dict(t=100, b=80)
    )

    # Update all x-axes
    fig.update_xaxes(
        tickformat=tickformat,
        tickangle=tickangle,
        showgrid=True,
        gridcolor='lightgray'
    )

    # Hide y-axis for annotations row
    fig.update_yaxes(visible=False, row=1, col=1)

    # Update y-axes for data rows
    for idx in range(2, n_rows + 1):
        fig.update_yaxes(
            tickformat=',',
            gridcolor='lightgray',
            row=idx,
            col=1
        )

    # Update bottom x-axis label
    fig.update_xaxes(title_text='Date', row=n_rows, col=1)

    html_path = OUTPUT_DIR / filename
    fig.write_html(str(html_path))

    print(f"\nSaved: {html_path}")
    subprocess.run(['xdg-open', str(html_path)], check=False)


def plot_png_multi(data: MultiSeriesData, filename: str):
    """Plot multi-series data as PNG using Plotly (same as HTML but exported to PNG)."""
    from plotly.subplots import make_subplots
    import plotly.graph_objects as go

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    df = data.df
    dates = pd.to_datetime(df[data.date_col])
    n_series = len(data.series_cols)

    # Color palette for users
    colors = {
        't.johnson': '#e74c3c',      # Red - human user (key)
        'systemprofile': '#3498db',   # Blue - system
        'LocalService': '#2ecc71',    # Green - service
        'NetworkService': '#9b59b6',  # Purple - network
    }

    # Create subplots: annotations row + one row per user
    n_rows = n_series + 1  # +1 for annotations row
    row_heights = [0.15] + [0.85 / n_series] * n_series

    fig = make_subplots(
        rows=n_rows,
        cols=1,
        shared_xaxes=True,
        vertical_spacing=0.08,
        subplot_titles=['Events'] + data.series_cols,
        row_heights=row_heights
    )

    # Row 1: Annotations row (markers only, with alternating y-positions)
    marker_dates = []
    marker_labels = []
    marker_y = []
    for i, date in enumerate(dates):
        date_str = str(df.iloc[i][data.date_col])
        if date_str in data.markers:
            marker_dates.append(date)
            marker_labels.append(data.markers[date_str])
            marker_y.append((len(marker_dates) % 3) + 1)

    if marker_dates:
        fig.add_trace(
            go.Scatter(
                x=marker_dates,
                y=marker_y,
                mode='markers+text',
                marker=dict(symbol='star', size=12, color='darkred'),
                text=marker_labels,
                textposition='middle right',
                textfont=dict(size=9, color='darkred'),
                hovertemplate="<b>%{text}</b><br>%{x}<extra></extra>",
                showlegend=False
            ),
            row=1,
            col=1
        )

    # Rows 2+: User data
    for idx, col in enumerate(data.series_cols, 2):
        counts = df[col]
        color = colors.get(col, '#95a5a6')

        fig.add_trace(
            go.Bar(
                x=dates,
                y=counts,
                name=col,
                marker_color=color,
                hovertemplate=f"<b>{col}</b><br>%{{x}}<br>Events: %{{y:,}}<extra></extra>",
                showlegend=False
            ),
            row=idx,
            col=1
        )

    # Configure x-axis based on time aggregation
    if TIME_AGG == 'hourly':
        tickformat = '%b %d %H:%M'
        tickangle = 45
    elif TIME_AGG == 'monthly':
        tickformat = '%b %Y'
        tickangle = 0
    else:  # daily
        tickformat = '%b %d'
        tickangle = 45

    fig.update_layout(
        title=dict(
            text=f'<b>{data.title}</b><br><sup>{data.subtitle}</sup>',
            x=0.5,
            font=dict(size=18)
        ),
        template='plotly_white',
        hovermode='x unified',
        height=200 * n_series + 200,
        width=1200,
        margin=dict(t=100, b=80)
    )

    # Update all x-axes
    fig.update_xaxes(
        tickformat=tickformat,
        tickangle=tickangle,
        showgrid=True,
        gridcolor='lightgray'
    )

    # Hide y-axis for annotations row
    fig.update_yaxes(visible=False, row=1, col=1)

    # Update y-axes for data rows
    for idx in range(2, n_rows + 1):
        fig.update_yaxes(
            tickformat=',',
            gridcolor='lightgray',
            row=idx,
            col=1
        )

    # Update bottom x-axis label
    fig.update_xaxes(title_text='Date', row=n_rows, col=1)

    png_path = OUTPUT_DIR / filename
    fig.write_image(str(png_path), scale=2)

    print(f"\nSaved: {png_path}")
    subprocess.run(['xdg-open', str(png_path)], check=False)


def plot_data_multi(data: MultiSeriesData, base_filename: str):
    """Plot multi-series data using the selected output mode."""
    if OUTPUT_FORMAT == 'plotly':
        plot_plotly_multi(data, f"{base_filename}.html")
    elif OUTPUT_FORMAT == 'png':
        plot_png_multi(data, f"{base_filename}.png")
    else:
        plot_ascii_multi(data)


# =============================================================================
# Parser: Plaso Timeline
# =============================================================================

def parse_plaso(source_file: Optional[Path] = None) -> TimeSeriesData:
    """Parse Plaso timeline and aggregate by selected time period."""
    if source_file:
        csv_file = source_file
    else:
        csv_file = ARTIFACT_DIR / "Spader_Technologies/stsupport10-plaso-timeline/stsupport10-plaso-timeline.csv"

    print(f"Loading {csv_file.name}...")
    df = pd.read_csv(csv_file, low_memory=False)

    # Parse datetime
    df['datetime'] = pd.to_datetime(df['date'] + ' ' + df['time'], format='%m/%d/%Y %H:%M:%S', errors='coerce')
    df = df.dropna(subset=['datetime'])

    # Filter to reasonable date range to exclude bogus timestamps
    df = df[(df['datetime'] >= '1990-01-01') & (df['datetime'] <= '2030-12-31')]

    total_events = len(df)
    print(f"Total events (valid dates): {total_events:,}")

    # Apply optional time filters
    time_filter_desc = ""
    if TIME_START:
        df = df[df['datetime'] >= TIME_START]
        time_filter_desc = f" from {TIME_START}"
    if TIME_END:
        df = df[df['datetime'] <= TIME_END]
        time_filter_desc += f" to {TIME_END}"

    if TIME_START or TIME_END:
        print(f"Filtered to {len(df):,} events{time_filter_desc}")

    # Aggregate based on TIME_AGG
    if TIME_AGG == 'hourly':
        df['period'] = df['datetime'].dt.floor('h')
        title_suffix = "Hourly"
    elif TIME_AGG == 'monthly':
        df['period'] = df['datetime'].dt.to_period('M').dt.to_timestamp()
        title_suffix = "Monthly"
    else:  # daily
        df['period'] = df['datetime'].dt.floor('D')
        title_suffix = "Daily"

    agg = df.groupby('period').size().reset_index(name='count')
    agg = agg.sort_values('period')
    agg['date'] = agg['period'].apply(lambda x: format_date(x, TIME_AGG))

    # Load markers from external file (auto-filtered to dates in data)
    markers = {} if NO_ANNOTATIONS else load_markers("plaso-markers.yaml", agg['date'].tolist())

    # Build title
    title = f"Plaso Timeline - {title_suffix}"
    if time_filter_desc:
        title += f" ({time_filter_desc.strip()})"

    return TimeSeriesData(
        df=agg,
        title=title,
        subtitle=f"Total: {total_events:,} events",
        markers=markers,
        date_col='date',
        count_col='count'
    )


def parse_plaso_by_user(source_file: Optional[Path] = None) -> MultiSeriesData:
    """Parse Plaso timeline and aggregate by user and time period."""
    if source_file:
        csv_file = source_file
    else:
        csv_file = ARTIFACT_DIR / "Spader_Technologies/stsupport10-plaso-timeline/stsupport10-plaso-timeline.csv"

    print(f"Loading {csv_file.name}...")
    df = pd.read_csv(csv_file, low_memory=False)

    # Parse datetime
    df['datetime'] = pd.to_datetime(df['date'] + ' ' + df['time'], format='%m/%d/%Y %H:%M:%S', errors='coerce')
    df = df.dropna(subset=['datetime'])

    # Filter to reasonable date range
    df = df[(df['datetime'] >= '1990-01-01') & (df['datetime'] <= '2030-12-31')]

    total_events = len(df)
    print(f"Total events (valid dates): {total_events:,}")

    # Apply optional time filters
    time_filter_desc = ""
    if TIME_START:
        df = df[df['datetime'] >= TIME_START]
        time_filter_desc = f" from {TIME_START}"
    if TIME_END:
        df = df[df['datetime'] <= TIME_END]
        time_filter_desc += f" to {TIME_END}"

    if TIME_START or TIME_END:
        print(f"Filtered to {len(df):,} events{time_filter_desc}")

    # Aggregate based on TIME_AGG
    if TIME_AGG == 'hourly':
        df['period'] = df['datetime'].dt.floor('h')
        title_suffix = "Hourly"
    elif TIME_AGG == 'monthly':
        df['period'] = df['datetime'].dt.to_period('M').dt.to_timestamp()
        title_suffix = "Monthly"
    else:  # daily
        df['period'] = df['datetime'].dt.floor('D')
        title_suffix = "Daily"

    # Get unique periods
    periods = sorted(df['period'].unique())

    # Build aggregation by user
    result_data = []
    for period in periods:
        period_df = df[df['period'] == period]
        row = {'period': period}
        for user in USERS:
            row[user] = len(period_df[period_df['user'] == user])
        result_data.append(row)

    agg = pd.DataFrame(result_data)
    agg['date'] = agg['period'].apply(lambda x: format_date(x, TIME_AGG))

    # Print user totals
    for user in USERS:
        total = agg[user].sum()
        print(f"  {user}: {total:,} events")

    # Load markers
    markers = {} if NO_ANNOTATIONS else load_markers("plaso-markers.yaml", agg['date'].tolist())

    # Build title
    title = f"Plaso Timeline by User - {title_suffix}"
    if time_filter_desc:
        title += f" ({time_filter_desc.strip()})"

    return MultiSeriesData(
        df=agg,
        title=title,
        subtitle=f"Total: {total_events:,} events | Users: {', '.join(USERS)}",
        markers=markers,
        series_cols=USERS,
        date_col='date'
    )


# =============================================================================
# Parser: Firewall Logs
# =============================================================================

def parse_firewall(source_file: Optional[Path] = None) -> TimeSeriesData:
    """Parse firewall logs and aggregate by selected time period."""
    if source_file:
        csv_file = source_file
    else:
        csv_file = WORK_DIR / "data/spader-firewall.csv"

    print(f"Loading {csv_file.name}...")
    df = pd.read_csv(csv_file, low_memory=False)

    # Parse datetime
    df['datetime'] = pd.to_datetime(df['timestamp_utc'], errors='coerce')
    df = df.dropna(subset=['datetime'])

    total_events = len(df)
    print(f"Total firewall events: {total_events:,}")

    # Apply optional time filters
    time_filter_desc = ""
    if TIME_START:
        df = df[df['datetime'] >= TIME_START]
        time_filter_desc = f" from {TIME_START}"
    if TIME_END:
        df = df[df['datetime'] <= TIME_END]
        time_filter_desc += f" to {TIME_END}"

    if TIME_START or TIME_END:
        print(f"Filtered to {len(df):,} events{time_filter_desc}")

    # Aggregate based on TIME_AGG
    if TIME_AGG == 'hourly':
        df['period'] = df['datetime'].dt.floor('h')
        title_suffix = "Hourly"
    elif TIME_AGG == 'monthly':
        df['period'] = df['datetime'].dt.to_period('M').dt.to_timestamp()
        title_suffix = "Monthly"
    else:  # daily
        df['period'] = df['datetime'].dt.floor('D')
        title_suffix = "Daily"

    agg = df.groupby('period').size().reset_index(name='count')
    agg = agg.sort_values('period')
    agg['date'] = agg['period'].apply(lambda x: format_date(x, TIME_AGG))

    # Load markers from external file (auto-filtered to dates in data)
    markers = {} if NO_ANNOTATIONS else load_markers("firewall-markers.yaml", agg['date'].tolist())

    # Build title
    title = f"Firewall Timeline - {title_suffix}"
    if time_filter_desc:
        title += f" ({time_filter_desc.strip()})"

    return TimeSeriesData(
        df=agg,
        title=title,
        subtitle=f"Total: {total_events:,} events",
        markers=markers,
        date_col='date',
        count_col='count'
    )


# =============================================================================
# Parser: Proxy Logs
# =============================================================================

def parse_proxy(source_file: Optional[Path] = None) -> TimeSeriesData:
    """Parse proxy logs and aggregate by selected time period."""
    if source_file:
        csv_file = source_file
    else:
        csv_file = WORK_DIR / "data/spader-proxy.csv"

    print(f"Loading {csv_file.name}...")
    df = pd.read_csv(csv_file, low_memory=False)

    # Parse datetime
    df['datetime'] = pd.to_datetime(df['timestamp_utc'], errors='coerce')
    df = df.dropna(subset=['datetime'])

    total_events = len(df)
    print(f"Total proxy events: {total_events:,}")

    # Apply optional time filters
    time_filter_desc = ""
    if TIME_START:
        df = df[df['datetime'] >= TIME_START]
        time_filter_desc = f" from {TIME_START}"
    if TIME_END:
        df = df[df['datetime'] <= TIME_END]
        time_filter_desc += f" to {TIME_END}"

    if TIME_START or TIME_END:
        print(f"Filtered to {len(df):,} events{time_filter_desc}")

    # Aggregate based on TIME_AGG
    if TIME_AGG == 'hourly':
        df['period'] = df['datetime'].dt.floor('h')
        title_suffix = "Hourly"
    elif TIME_AGG == 'monthly':
        df['period'] = df['datetime'].dt.to_period('M').dt.to_timestamp()
        title_suffix = "Monthly"
    else:  # daily
        df['period'] = df['datetime'].dt.floor('D')
        title_suffix = "Daily"

    agg = df.groupby('period').size().reset_index(name='count')
    agg = agg.sort_values('period')
    agg['date'] = agg['period'].apply(lambda x: format_date(x, TIME_AGG))

    # Load markers from external file (auto-filtered to dates in data)
    markers = {} if NO_ANNOTATIONS else load_markers("proxy-markers.yaml", agg['date'].tolist())

    # Build title
    title = f"Proxy Timeline - {title_suffix}"
    if time_filter_desc:
        title += f" ({time_filter_desc.strip()})"

    return TimeSeriesData(
        df=agg,
        title=title,
        subtitle=f"Total: {total_events:,} events",
        markers=markers,
        date_col='date',
        count_col='count'
    )


# =============================================================================
# Chart Definitions
# =============================================================================

SOURCES = {
    'plaso': ('Plaso Timeline', parse_plaso),
    'firewall': ('Firewall Logs', parse_firewall),
    'proxy': ('Proxy Logs', parse_proxy),
}


def list_sources():
    """List available data sources."""
    print("\nAvailable sources:")
    print("-" * 50)
    for name, (desc, _) in SOURCES.items():
        print(f"  {name:20} {desc}")
    print("\nTime aggregation:")
    print("  --daily    Aggregate by day (default)")
    print("  --hourly   Aggregate by hour")
    print("  --monthly  Aggregate by month")
    print("\nOutput format:")
    print("  --png      Generate PNG (matplotlib)")
    print("  --plotly   Generate interactive HTML (Plotly)")
    print("  (default)  ASCII output")
    print("\nTime range filter (optional):")
    print("  --start    Start date (YYYY-MM-DD or YYYY-MM-DD HH:MM)")
    print("  --end      End date (YYYY-MM-DD or YYYY-MM-DD HH:MM)")
    print("\nGrouping:")
    print("  --by-user          Group by user (requires --users)")
    print("  --users            Comma-separated list of users (e.g., t.johnson,systemprofile)")
    print("\nOther options:")
    print("  --source-file      Path to source CSV file")
    print("  --output           Output directory for charts")
    print("  --no-annotations   Disable annotations/markers")
    print("\nEnvironment variables:")
    print("  ARTIFACTS_PATH      Base path for artifact files")
    print("  WORK_PATH          Base path for work/output files")
    print()


# =============================================================================
# Main
# =============================================================================

def main():
    global OUTPUT_DIR, OUTPUT_FORMAT, TIME_AGG, TIME_START, TIME_END, NO_ANNOTATIONS, BY_USER, USERS

    parser = argparse.ArgumentParser(
        description='Visualization Generator for Forensic Artifacts',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python visualize_ascii.py plaso                     # ASCII, daily
  python visualize_ascii.py plaso --hourly --plotly   # Plotly, hourly
  python visualize_ascii.py firewall --monthly --png  # PNG, monthly
  python visualize_ascii.py plaso --source-file /path/to/file.csv

Environment:
  ARTIFACTS_PATH  Base path for artifact files
  WORK_PATH      Base path for work/output files
        """
    )
    parser.add_argument('source', nargs='?', help='Data source name (plaso, firewall)')
    parser.add_argument('--list', action='store_true', help='List available sources')

    # Time aggregation (mutually exclusive)
    time_group = parser.add_mutually_exclusive_group()
    time_group.add_argument('--daily', action='store_true', help='Aggregate by day (default)')
    time_group.add_argument('--hourly', action='store_true', help='Aggregate by hour')
    time_group.add_argument('--monthly', action='store_true', help='Aggregate by month')

    # Output format (mutually exclusive)
    format_group = parser.add_mutually_exclusive_group()
    format_group.add_argument('--png', action='store_true', help='Generate PNG (matplotlib)')
    format_group.add_argument('--plotly', action='store_true', help='Generate interactive HTML (Plotly)')

    # Time range filter
    parser.add_argument('--start', type=str, help='Start date (YYYY-MM-DD or YYYY-MM-DD HH:MM)')
    parser.add_argument('--end', type=str, help='End date (YYYY-MM-DD or YYYY-MM-DD HH:MM)')

    # File options
    parser.add_argument('--source-file', type=Path, help='Path to source CSV file')
    parser.add_argument('--output', type=Path, help='Output directory for charts')
    parser.add_argument('--no-annotations', action='store_true', help='Disable annotations/markers')
    parser.add_argument('--by-user', action='store_true', help='Group by user (plaso only)')
    parser.add_argument('--users', type=str, help='Comma-separated list of users to track (e.g., t.johnson,systemprofile)')

    args = parser.parse_args()

    if args.list:
        list_sources()
        return

    if not args.source:
        list_sources()
        return

    if args.source not in SOURCES:
        print(f"Unknown source: {args.source}")
        list_sources()
        return

    # Set time aggregation
    if args.hourly:
        TIME_AGG = 'hourly'
    elif args.monthly:
        TIME_AGG = 'monthly'
    else:
        TIME_AGG = 'daily'

    # Set time range filter
    TIME_START = args.start
    TIME_END = args.end

    # Set output format
    if args.png:
        OUTPUT_FORMAT = 'png'
    elif args.plotly:
        OUTPUT_FORMAT = 'plotly'
    else:
        OUTPUT_FORMAT = 'ascii'

    # Set output directory
    if args.output:
        OUTPUT_DIR = args.output
    else:
        OUTPUT_DIR = DEFAULT_OUTPUT_DIR

    # Set annotations flag
    NO_ANNOTATIONS = args.no_annotations

    # Set by-user flag
    BY_USER = args.by_user

    # Set users list
    if args.users:
        USERS = [u.strip() for u in args.users.split(',')]
    else:
        USERS = []

    # Parse and plot
    if BY_USER and args.source == 'plaso':
        data = parse_plaso_by_user(args.source_file)
        base_filename = f"{args.source}-by-user-{TIME_AGG}"
        plot_data_multi(data, base_filename)
    else:
        _, parser_func = SOURCES[args.source]
        data = parser_func(args.source_file)
        base_filename = f"{args.source}-{TIME_AGG}"
        plot_data(data, base_filename)


if __name__ == '__main__':
    main()
