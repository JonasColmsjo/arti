#!/bin/bash
#
# hash-folder.sh - Generate and verify hashes for any folder structure
#
# Purpose: Create cryptographic hashes (MD5 & SHA256) for all files in a directory
# Output: Creates hash manifests in specified output directory
# Usage: ./scripts/hash-folder.sh <folder> [-o <output-dir>]
#        ./scripts/hash-folder.sh <folder> [-o <output-dir>] --verify
#
# Author: Jonas Colmsjö
# Date: 2026-01-14
#

set -e
set -u

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Usage function
usage() {
    echo "Usage: $0 <folder> [-o <output-dir>] [--verify]"
    echo ""
    echo "Generate hashes:"
    echo "  $0 <folder>"
    echo "  $0 <folder> -o ./evidence-intake/hashes"
    echo ""
    echo "Verify hashes:"
    echo "  $0 <folder> --verify"
    echo "  $0 <folder> -o ./evidence-intake/hashes --verify"
    echo ""
    echo "Options:"
    echo "  <folder>           Directory to hash or verify"
    echo "  -o <output-dir>    Output directory for hash manifests (default: <folder>-hashes/)"
    echo "  --verify           Verify existing hashes instead of generating new ones"
    exit 1
}

# Check arguments
if [ $# -lt 1 ]; then
    usage
fi

INPUT_FOLDER="$1"
shift
VERIFY_MODE=false
OUTPUT_DIR=""

# Parse remaining arguments
while [ $# -gt 0 ]; do
    case "$1" in
        -o|--output)
            if [ $# -lt 2 ]; then
                echo -e "${RED}Error: -o requires an argument${NC}"
                usage
            fi
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --verify)
            VERIFY_MODE=true
            shift
            ;;
        *)
            echo -e "${RED}Error: Unknown option '$1'${NC}"
            usage
            ;;
    esac
done

# Remove trailing slash if present
INPUT_FOLDER="${INPUT_FOLDER%/}"

# Check if input folder exists
if [ ! -d "$INPUT_FOLDER" ]; then
    echo -e "${RED}Error: Directory not found: $INPUT_FOLDER${NC}"
    exit 1
fi

# Set hash directory and manifest file
if [ -n "$OUTPUT_DIR" ]; then
    HASH_DIR="$OUTPUT_DIR"
else
    HASH_DIR="${INPUT_FOLDER}-hashes"
fi
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
TIMESTAMP_FILE=$(date -u +"%Y%m%d-%H%M%S")
MANIFEST_FILE="$HASH_DIR/hash-manifest-${TIMESTAMP_FILE}.txt"

# Function to hash a single file
hash_file() {
    local filepath="$1"
    local relative_path="${filepath#$INPUT_FOLDER/}"

    # Generate hashes
    if [[ "$OSTYPE" == "darwin"* ]]; then
        local md5hash=$(md5 -q "$filepath" 2>/dev/null)
        local sha256hash=$(shasum -a 256 "$filepath" 2>/dev/null | awk '{print $1}')
    else
        local md5hash=$(md5sum "$filepath" 2>/dev/null | awk '{print $1}')
        local sha256hash=$(sha256sum "$filepath" 2>/dev/null | awk '{print $1}')
    fi

    # Return: relative_path|md5|sha256
    echo "$relative_path|$md5hash|$sha256hash"
}

# Function to verify a single file
verify_file() {
    local relative_path="$1"
    local expected_md5="$2"
    local expected_sha256="$3"
    local filepath="$INPUT_FOLDER/$relative_path"

    # Check if file exists
    if [ ! -f "$filepath" ]; then
        echo -e "${RED}✗ MISSING${NC} - $relative_path"
        return 1
    fi

    # Calculate current hashes
    if [[ "$OSTYPE" == "darwin"* ]]; then
        local current_md5=$(md5 -q "$filepath" 2>/dev/null)
        local current_sha256=$(shasum -a 256 "$filepath" 2>/dev/null | awk '{print $1}')
    else
        local current_md5=$(md5sum "$filepath" 2>/dev/null | awk '{print $1}')
        local current_sha256=$(sha256sum "$filepath" 2>/dev/null | awk '{print $1}')
    fi

    # Verify both hashes
    if [ "$current_md5" = "$expected_md5" ] && [ "$current_sha256" = "$expected_sha256" ]; then
        echo -e "${GREEN}✓ VALID${NC} - $relative_path"
        return 0
    else
        echo -e "${RED}✗ FAILED${NC} - $relative_path"
        if [ "$current_md5" != "$expected_md5" ]; then
            echo -e "  ${RED}MD5 mismatch:${NC}"
            echo -e "    Expected: $expected_md5"
            echo -e "    Current:  $current_md5"
        fi
        if [ "$current_sha256" != "$expected_sha256" ]; then
            echo -e "  ${RED}SHA256 mismatch:${NC}"
            echo -e "    Expected: $expected_sha256"
            echo -e "    Current:  $current_sha256"
        fi
        return 1
    fi
}

# Function to compare hashes across all manifests
compare_manifests() {
    echo
    echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}Cross-Manifest Comparison${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}Checking if file hashes are consistent across all manifests...${NC}"
    echo

    # Find all manifest files (sorted by time, newest first)
    local manifests=($(ls -t "$HASH_DIR"/hash-manifest-*.txt 2>/dev/null))
    local manifest_count=${#manifests[@]}

    if [ $manifest_count -lt 2 ]; then
        echo -e "${YELLOW}Only one manifest found - skipping cross-manifest comparison${NC}"
        echo
        return 0
    fi

    echo -e "Found ${GREEN}$manifest_count${NC} manifests to compare:"
    for manifest in "${manifests[@]}"; do
        echo -e "  - $(basename "$manifest")"
    done
    echo

    local inconsistent_files=0
    local consistent_files=0
    local temp_dir="/tmp/hash-compare-$$"
    mkdir -p "$temp_dir"

    # Extract unique file list from first manifest
    grep -v '^#' "${manifests[0]}" | grep -v '^$' | cut -d'|' -f1 | sort > "$temp_dir/files.txt"

    # Check each file across all manifests
    while IFS= read -r relative_path; do
        local first_hash=""
        local is_consistent=true
        local manifest_hashes="$temp_dir/manifest_hashes_$$.txt"
        > "$manifest_hashes"

        # Collect hashes from all manifests
        for manifest in "${manifests[@]}"; do
            local hash_line=$(grep "^${relative_path}|" "$manifest" 2>/dev/null | head -1)
            if [ -n "$hash_line" ]; then
                local md5hash=$(echo "$hash_line" | cut -d'|' -f2)
                local sha256hash=$(echo "$hash_line" | cut -d'|' -f3)
                local hash_pair="${md5hash}|${sha256hash}"
                echo "$(basename "$manifest")|$hash_pair" >> "$manifest_hashes"

                if [ -z "$first_hash" ]; then
                    first_hash="$hash_pair"
                elif [ "$first_hash" != "$hash_pair" ]; then
                    is_consistent=false
                fi
            fi
        done

        if [ "$is_consistent" = true ]; then
            ((++consistent_files))
            echo -e "${GREEN}✓ CONSISTENT${NC} - $relative_path"
        else
            ((++inconsistent_files))
            echo -e "${RED}✗ INCONSISTENT${NC} - $relative_path"
            echo -e "  ${YELLOW}Hash changed between manifests:${NC}"
            while IFS='|' read -r manifest_name hash_pair; do
                local md5="${hash_pair%%|*}"
                local sha256="${hash_pair##*|}"
                echo -e "    $manifest_name:"
                echo -e "      MD5:    $md5"
                echo -e "      SHA256: $sha256"
            done < "$manifest_hashes"
        fi

        rm -f "$manifest_hashes"
    done < "$temp_dir/files.txt"

    # Cleanup
    rm -rf "$temp_dir"

    echo
    echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}Cross-Manifest Summary${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
    echo -e "Manifests compared: $manifest_count"
    echo -e "Consistent files:   ${GREEN}$consistent_files${NC}"
    echo -e "Inconsistent files: ${RED}$inconsistent_files${NC}"
    echo

    if [ $inconsistent_files -gt 0 ]; then
        echo -e "${RED}⚠ WARNING: Files have been modified between hash snapshots!${NC}"
        echo -e "${RED}This may indicate tampering or unauthorized changes.${NC}"
        return 1
    else
        echo -e "${GREEN}✓ All files have consistent hashes across all manifests${NC}"
        echo -e "${GREEN}No evidence of tampering between snapshots${NC}"
        return 0
    fi
}

# VERIFY MODE
if [ "$VERIFY_MODE" = true ]; then
    echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║  Hash Verification Mode                                ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "Folder: ${YELLOW}$INPUT_FOLDER${NC}"

    # Check if hash directory exists
    if [ ! -d "$HASH_DIR" ]; then
        echo -e "${RED}Error: Hash directory not found: $HASH_DIR${NC}"
        echo -e "${YELLOW}Hint: Generate hashes first by running without --verify${NC}"
        exit 1
    fi

    # Find the most recent manifest file
    MANIFEST_FILE=$(ls -t "$HASH_DIR"/hash-manifest-*.txt 2>/dev/null | head -1)

    if [ -z "$MANIFEST_FILE" ]; then
        echo -e "${RED}Error: No hash manifest files found in $HASH_DIR${NC}"
        echo -e "${YELLOW}Hint: Generate hashes first by running without --verify${NC}"
        exit 1
    fi

    echo -e "Manifest: ${YELLOW}$MANIFEST_FILE${NC}"
    echo -e "Using most recent manifest: ${GREEN}$(basename "$MANIFEST_FILE")${NC}"
    echo

    echo -e "${GREEN}Verifying files...${NC}"
    echo

    total_files=0
    valid_files=0
    failed_files=0

    # Read manifest and verify each file
    while IFS='|' read -r relative_path md5hash sha256hash; do
        # Skip empty lines and comments
        if [[ -z "$relative_path" ]] || [[ "$relative_path" == \#* ]]; then
            continue
        fi

        ((++total_files))

        if verify_file "$relative_path" "$md5hash" "$sha256hash"; then
            ((++valid_files))
        else
            ((++failed_files))
        fi
    done < "$MANIFEST_FILE"

    echo
    echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}Verification Summary${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
    echo -e "Total files: $total_files"
    echo -e "Valid:       ${GREEN}$valid_files${NC}"
    echo -e "Failed:      ${RED}$failed_files${NC}"
    echo

    if [ $failed_files -eq 0 ]; then
        echo -e "${GREEN}✓ ALL FILES VERIFIED${NC}"
        echo -e "${GREEN}File integrity maintained - no corruption detected${NC}"
    else
        echo -e "${RED}✗ VERIFICATION FAILED${NC}"
        echo -e "${RED}$failed_files file(s) failed integrity check${NC}"
    fi

    # Check file permissions (should be 400 for read-only evidence)
    echo
    echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}Permission Verification${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"

    fs_type=$(df -T "$INPUT_FOLDER" 2>/dev/null | tail -1 | awk '{print $2}')
    if [ "$fs_type" = "exfat" ] || [ "$fs_type" = "vfat" ] || [ "$fs_type" = "fuseblk" ]; then
        echo -e "${YELLOW}Filesystem ($fs_type) does not support Unix permissions - skipping check${NC}"
    else
        writable_files=0
        while IFS='|' read -r relative_path md5hash sha256hash; do
            if [[ -z "$relative_path" ]] || [[ "$relative_path" == \#* ]]; then
                continue
            fi
            filepath="$INPUT_FOLDER/$relative_path"
            if [ -f "$filepath" ]; then
                perms=$(stat -c "%a" "$filepath" 2>/dev/null)
                if [ "$perms" != "400" ]; then
                    echo -e "${RED}⚠ WARNING${NC} - $relative_path (mode $perms, expected 400)"
                    ((++writable_files))
                fi
            fi
        done < "$MANIFEST_FILE"

        if [ $writable_files -eq 0 ]; then
            echo -e "${GREEN}✓ All files have correct permissions (mode 400)${NC}"
        else
            echo -e "${RED}⚠ $writable_files file(s) are not read-only${NC}"
            echo -e "${YELLOW}Run without --verify to reset permissions${NC}"
        fi
    fi

    # Perform cross-manifest comparison
    compare_manifests
    comparison_result=$?

    # Final exit code based on both verifications
    if [ $failed_files -eq 0 ] && [ $comparison_result -eq 0 ]; then
        exit 0
    else
        exit 1
    fi
fi

# GENERATION MODE
echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Hash Generation Mode                                  ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
echo
echo -e "Input folder: ${YELLOW}$INPUT_FOLDER${NC}"
echo -e "Output directory: ${YELLOW}$HASH_DIR${NC}"
echo -e "Timestamp: ${YELLOW}$TIMESTAMP${NC}"
echo

# Create hash directory
mkdir -p "$HASH_DIR"

# Create manifest header
cat > "$MANIFEST_FILE" << EOF
# Hash Manifest for: $INPUT_FOLDER
# Generated: $TIMESTAMP
# Format: RELATIVE_PATH|MD5|SHA256
# ========================================
EOF

echo -e "${GREEN}Generating hashes for all files...${NC}"
echo

total_files=0
total_bytes=0

# Find all files and hash them
while IFS= read -r -d '' file; do
    # Skip macOS metadata files
    if [[ $(basename "$file") == ._* ]]; then
        continue
    fi

    # Get file info
    if [[ "$OSTYPE" == "darwin"* ]]; then
        filesize=$(stat -f%z "$file" 2>/dev/null || echo 0)
    else
        filesize=$(stat -c%s "$file" 2>/dev/null || echo 0)
    fi

    relative_path="${file#$INPUT_FOLDER/}"

    echo -e "${YELLOW}Hashing:${NC} $relative_path"

    # Hash the file
    result=$(hash_file "$file")
    rel_path=$(echo "$result" | cut -d'|' -f1)
    md5hash=$(echo "$result" | cut -d'|' -f2)
    sha256hash=$(echo "$result" | cut -d'|' -f3)

    # Write to manifest
    echo "$rel_path|$md5hash|$sha256hash" >> "$MANIFEST_FILE"

    ((++total_files))
    total_bytes=$((total_bytes + filesize))
done < <(find "$INPUT_FOLDER" -type f -print0 | sort -z)

# Format total size
if [ $total_bytes -lt 1048576 ]; then
    size_display="$((total_bytes / 1024)) KB"
elif [ $total_bytes -lt 1073741824 ]; then
    size_display="$((total_bytes / 1048576)) MB"
else
    size_display="$((total_bytes / 1073741824)) GB"
fi

# Set read-only permissions if filesystem supports it (not exFAT)
fs_type=$(df -T "$INPUT_FOLDER" 2>/dev/null | tail -1 | awk '{print $2}')
if [ "$fs_type" != "exfat" ] && [ "$fs_type" != "vfat" ] && [ "$fs_type" != "fuseblk" ]; then
    echo
    echo -e "${YELLOW}Setting evidence files to read-only (mode 400)...${NC}"
    protected_count=0
    while IFS= read -r -d '' file; do
        if [[ $(basename "$file") == ._* ]]; then
            continue
        fi
        chmod 400 "$file" 2>/dev/null && ((++protected_count))
    done < <(find "$INPUT_FOLDER" -type f -print0)
    echo -e "${GREEN}✓ Protected $protected_count files${NC}"
else
    echo
    echo -e "${YELLOW}Filesystem ($fs_type) does not support Unix permissions - skipping chmod${NC}"
fi

echo
echo -e "${GREEN}════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Hash Generation Complete${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════${NC}"
echo -e "Total files hashed: ${GREEN}$total_files${NC}"
echo -e "Total size: ${GREEN}$size_display${NC} ($total_bytes bytes)"
echo
echo -e "Output:"
echo -e "  Manifest: ${YELLOW}$(basename "$MANIFEST_FILE")${NC}"
echo -e "  Full path: ${YELLOW}$MANIFEST_FILE${NC}"
echo
echo -e "${BLUE}To verify integrity later:${NC}"
echo -e "  ${YELLOW}$0 $INPUT_FOLDER --verify${NC}"
echo -e "  (Will use most recent manifest automatically)"
echo
echo -e "${GREEN}✓ Hashes saved successfully${NC}"
echo
