#!/bin/bash
#
# investigation-log.sh - Manage daily investigation log files with append-only enforcement
#
# Purpose: Split investigation logs into daily files (YYYY-MM-DD.md) with automatic
#          locking of previous days' files (chmod 400) to enforce append-only discipline.
#
# Usage: investigation-log.sh <subcommand> [args]
#   add "Title"              Append entry to today's log (body via stdin)
#   add --edit "Title"       Append entry to today's log (opens $EDITOR)
#   show [YYYY-MM-DD]        Display a day's log (default: today)
#   list                     List all daily files with entry counts and lock status
#   lock                     chmod 400 all files older than today
#   migrate [source.md]      Split monolithic log into daily files
#   init                     Create investigation-log/ directory with README.md
#
# Author: Jonas Colmsjö
# Date: 2026-02-19
#

set -e
set -u

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
LOG_DIR="${PROJECT_ROOT:-.}/investigation-log"

# Usage function
usage() {
    echo "Usage: $(basename "$0") <subcommand> [args]"
    echo ""
    echo "Subcommands:"
    echo "  add \"Title\"              Append entry (body via stdin)"
    echo "  add --edit \"Title\"       Append entry (opens \$EDITOR)"
    echo "  show [YYYY-MM-DD]        Display a day's log (default: today)"
    echo "  list                     List all daily files with entry counts"
    echo "  lock                     Lock all files older than today (chmod 400)"
    echo "  migrate [source.md]      Split monolithic log into daily files"
    echo "  init                     Create investigation-log/ with README.md"
    exit 1
}

# Ensure log directory exists (auto-init)
ensure_log_dir() {
    if [ ! -d "$LOG_DIR" ]; then
        do_init
    fi
}

# ─── Subcommand: init ────────────────────────────────────────────────────────

do_init() {
    if [ -d "$LOG_DIR" ]; then
        echo -e "${YELLOW}investigation-log/ already exists — skipping init${NC}"
        return 0
    fi
    mkdir -p "$LOG_DIR"
    cat > "$LOG_DIR/README.md" << 'EOF'
# Investigation Log

Daily investigation log files — one file per day (`YYYY-MM-DD.md`).

## Rules

- **APPEND-ONLY**: Previous days' files are automatically locked (chmod 400).
- Never modify locked files. If a previous entry contains an error, add a correction entry today.
- Log in real-time, not batched.

## Usage

```bash
# Add entry (pipe body via stdin)
just inv-log add "Entry Title" <<'ENTRY'
**Action**: What was done
**Evidence**: Which artifacts were examined
**Key Finding**: Summary of discoveries
**Output**: Files created or modified
ENTRY

# Add entry interactively (opens $EDITOR)
just inv-log add --edit "Entry Title"

# Show today's log
just inv-log show

# Show a specific day
just inv-log show 2026-01-15

# List all daily files
just inv-log list

# Lock old files manually
just inv-log lock
```
EOF
    echo -e "${GREEN}Created investigation-log/ with README.md${NC}"
}

# ─── Subcommand: add ─────────────────────────────────────────────────────────

do_add() {
    local edit_mode=false
    local title=""

    # Parse args
    while [ $# -gt 0 ]; do
        case "$1" in
            --edit)
                edit_mode=true
                shift
                ;;
            *)
                title="$1"
                shift
                ;;
        esac
    done

    if [ -z "$title" ]; then
        echo -e "${RED}Error: Title is required${NC}"
        echo "Usage: $(basename "$0") add \"Entry Title\""
        exit 1
    fi

    ensure_log_dir

    local today
    today=$(date -u +%Y-%m-%d)
    local timestamp
    timestamp=$(date -u +"%Y-%m-%d %H:%M UTC")
    local today_file="$LOG_DIR/$today.md"

    # Create today's file with header if new
    if [ ! -f "$today_file" ]; then
        echo "# Investigation Log — $today" > "$today_file"
    fi

    local body=""

    if [ "$edit_mode" = true ]; then
        # Create temp file with template
        local tmpfile
        tmpfile=$(mktemp /tmp/inv-log-XXXXXX.md)
        cat > "$tmpfile" << EOF
**Action**:
**Evidence**:
**Key Finding**:
**Output**:
EOF
        # Open editor
        "${EDITOR:-vi}" "$tmpfile"
        body=$(cat "$tmpfile")
        rm -f "$tmpfile"
    else
        # Read body from stdin
        if [ -t 0 ]; then
            echo -e "${YELLOW}Enter log entry body (Ctrl-D when done):${NC}"
        fi
        body=$(cat)
    fi

    if [ -z "$body" ]; then
        echo -e "${RED}Error: Empty entry body — aborting${NC}"
        exit 1
    fi

    # Append entry
    {
        echo ""
        echo "---"
        echo ""
        echo "### $timestamp - $title"
        echo ""
        echo "$body"
    } >> "$today_file"

    # Lock previous days
    do_lock_quiet

    echo -e "${GREEN}✓ Entry added to $today.md${NC}"
}

# ─── Subcommand: show ────────────────────────────────────────────────────────

do_show() {
    ensure_log_dir

    local date_str="${1:-$(date -u +%Y-%m-%d)}"
    local file="$LOG_DIR/$date_str.md"

    if [ ! -f "$file" ]; then
        echo -e "${YELLOW}No log file for $date_str${NC}"
        exit 0
    fi

    cat "$file"
}

# ─── Subcommand: list ────────────────────────────────────────────────────────

do_list() {
    ensure_log_dir

    local today
    today=$(date -u +%Y-%m-%d)

    echo -e "${BLUE}Investigation Log Files${NC}"
    echo -e "${BLUE}═══════════════════════${NC}"
    echo ""

    local count=0
    for file in "$LOG_DIR"/????-??-??.md; do
        [ -f "$file" ] || continue
        local basename
        basename=$(basename "$file" .md)
        local entries
        entries=$(grep -c '^### ' "$file" 2>/dev/null || true)
        local lock_status

        if [ ! -w "$file" ]; then
            lock_status="${RED}locked${NC}"
        elif [ "$basename" = "$today" ]; then
            lock_status="${GREEN}active${NC}"
        else
            lock_status="${YELLOW}unlocked${NC}"
        fi

        echo -e "  $basename  $(printf '%2d' "$entries") entries  [$lock_status]"
        ((++count))
    done

    if [ $count -eq 0 ]; then
        echo -e "  ${YELLOW}(no log files yet)${NC}"
    fi
    echo ""
    echo -e "Total: $count files"
}

# ─── Subcommand: lock ────────────────────────────────────────────────────────

do_lock() {
    ensure_log_dir
    do_lock_quiet
    echo -e "${GREEN}✓ Locked all files older than today${NC}"
}

do_lock_quiet() {
    local today
    today=$(date -u +%Y-%m-%d)
    # Lock all daily files except today's
    for file in "$LOG_DIR"/????-??-??.md; do
        [ -f "$file" ] || continue
        local basename
        basename=$(basename "$file" .md)
        if [ "$basename" != "$today" ] && [ -w "$file" ]; then
            chmod 400 "$file"
        fi
    done
}

# ─── Subcommand: migrate ─────────────────────────────────────────────────────

do_migrate() {
    local source_file="${1:-${PROJECT_ROOT:-.}/INVESTIGATION-LOG.md}"

    if [ ! -f "$source_file" ]; then
        echo -e "${RED}Error: Source file not found: $source_file${NC}"
        exit 1
    fi

    ensure_log_dir

    echo -e "${BLUE}Migrating: $source_file → $LOG_DIR/${NC}"
    echo ""

    local current_date=""
    local current_file=""
    local preamble_file="$LOG_DIR/README-migrated-preamble.md"
    local in_preamble=true
    local file_count=0
    local entry_count=0

    while IFS= read -r line; do
        # Check for dated heading: ### YYYY-MM-DD ...
        if [[ "$line" =~ ^###[[:space:]]([0-9]{4}-[0-9]{2}-[0-9]{2}) ]]; then
            in_preamble=false
            local new_date="${BASH_REMATCH[1]}"
            if [ "$new_date" != "$current_date" ]; then
                current_date="$new_date"
                current_file="$LOG_DIR/$current_date.md"
                if [ ! -f "$current_file" ]; then
                    echo "# Investigation Log — $current_date" > "$current_file"
                    ((++file_count))
                fi
            fi
            # Append separator and the heading line
            echo "" >> "$current_file"
            echo "---" >> "$current_file"
            echo "" >> "$current_file"
            echo "$line" >> "$current_file"
            ((++entry_count))
            continue
        fi

        # Check for undated heading with **Date**: YYYY-MM-DD in subsequent lines
        # This is handled by routing lines to current_file — the date context carries forward.

        if [ "$in_preamble" = true ]; then
            echo "$line" >> "$preamble_file"
        elif [ -n "$current_file" ]; then
            echo "$line" >> "$current_file"
        fi
    done < "$source_file"

    # Rename source file
    mv "$source_file" "${source_file%.md}.migrated"

    # Create stub pointing to new directory
    cat > "$source_file" << EOF
# Investigation Log

**MIGRATED**: This log has been split into daily files.

See \`investigation-log/\` directory for all entries.

Use \`just inv-log list\` to see all daily files.
EOF

    # Lock all past-day files
    do_lock_quiet

    echo -e "${GREEN}Migration complete:${NC}"
    echo -e "  Files created: $file_count"
    echo -e "  Entries migrated: $entry_count"
    echo -e "  Source renamed: ${source_file%.md}.migrated"
    echo -e "  Stub created: $source_file"
}

# ─── Main dispatch ────────────────────────────────────────────────────────────

if [ $# -lt 1 ]; then
    usage
fi

SUBCOMMAND="$1"
shift

case "$SUBCOMMAND" in
    add)
        do_add "$@"
        ;;
    show)
        do_show "$@"
        ;;
    list)
        do_list
        ;;
    lock)
        do_lock
        ;;
    migrate)
        do_migrate "$@"
        ;;
    init)
        do_init
        ;;
    *)
        echo -e "${RED}Error: Unknown subcommand '$SUBCOMMAND'${NC}"
        usage
        ;;
esac
