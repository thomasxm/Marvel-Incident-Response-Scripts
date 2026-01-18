#!/bin/bash
#
# File Anomaly Detection - Pure Bash Implementation
# No external dependencies - uses find, stat, sha256sum
#
# Monitors suspicious directories for unauthorized files:
# - /tmp, /var/tmp, /dev/shm (world-writable)
# - /etc/cron.*, crontabs (persistence)
# - User home directories
#
# Usage:
#   ./file_anomaly.sh baseline -o file_baseline.json
#   ./file_anomaly.sh scan -b file_baseline.json
#

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Output functions
print_header() { echo -e "\n${CYAN}════════════════════════════════════════════════════════════${NC}"; echo -e "${CYAN}  $1${NC}"; echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}\n"; }
print_info() { echo -e "${BLUE}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[+]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error() { echo -e "${RED}[-]${NC} $1"; }
print_new() { echo -e "${RED}[NEW]${NC} $1"; }
print_missing() { echo -e "${YELLOW}[MISSING]${NC} $1"; }
print_modified() { echo -e "${MAGENTA}[MODIFIED]${NC} $1"; }

# Suspicious directories to monitor
SUSPICIOUS_PATHS=(
    "/tmp"
    "/var/tmp"
    "/dev/shm"
    "/etc/cron.d"
    "/etc/cron.daily"
    "/etc/cron.hourly"
    "/etc/cron.weekly"
    "/etc/cron.monthly"
    "/var/spool/cron"
    "/var/spool/cron/crontabs"
    "/var/spool/at"
    "/root"
)

# Suspicious file extensions
SUSPICIOUS_EXTENSIONS=(
    "exe" "elf" "bin" "sh" "bash" "py" "pl" "rb" "php"
    "ps1" "bat" "cmd" "vbs" "js" "jar" "war"
    "so" "dll" "dylib"
)

# Check if extension is suspicious
is_suspicious_extension() {
    local filename="$1"
    local ext="${filename##*.}"
    ext="${ext,,}"  # lowercase

    for s_ext in "${SUSPICIOUS_EXTENSIONS[@]}"; do
        [[ "$ext" == "$s_ext" ]] && return 0
    done
    return 1
}

# Compute SHA256 hash
compute_hash() {
    local filepath="$1"

    if [[ -f "$filepath" && -r "$filepath" ]]; then
        sha256sum "$filepath" 2>/dev/null | cut -d' ' -f1
    else
        echo "null"
    fi
}

# Get file info
get_file_info() {
    local filepath="$1"

    [[ ! -e "$filepath" ]] && return 1

    local filename
    filename=$(basename "$filepath")

    local size permissions owner group mtime
    read -r permissions _ owner group size _ _ _ _ < <(ls -la "$filepath" 2>/dev/null)

    mtime=$(stat -c %Y "$filepath" 2>/dev/null)

    local filetype="file"
    [[ -d "$filepath" ]] && filetype="directory"
    [[ -L "$filepath" ]] && filetype="symlink"
    [[ -x "$filepath" ]] && filetype="executable"

    local is_hidden="false"
    [[ "$filename" == .* ]] && is_hidden="true"

    local hash="null"
    if [[ -f "$filepath" && -r "$filepath" ]]; then
        hash=$(compute_hash "$filepath")
    fi

    # Escape special characters for JSON
    local safe_path
    safe_path=$(echo "$filepath" | sed 's/"/\\"/g')

    echo "{\"path\":\"$safe_path\",\"name\":\"$filename\",\"size\":$size,\"permissions\":\"$permissions\",\"owner\":\"$owner\",\"group\":\"$group\",\"mtime\":$mtime,\"type\":\"$filetype\",\"hidden\":$is_hidden,\"hash\":\"$hash\"}"
}

# Scan a directory
scan_directory() {
    local dir="$1"
    local max_depth="${2:-3}"

    [[ ! -d "$dir" ]] && return

    find "$dir" -maxdepth "$max_depth" -type f 2>/dev/null || true
}

# Create baseline
create_baseline() {
    local output_file="$1"

    print_header "Creating File Baseline"

    local hostname
    hostname=$(hostname)
    local timestamp
    timestamp=$(date -Iseconds)

    print_info "Hostname: $hostname"
    print_info "Timestamp: $timestamp"

    # Start JSON
    echo "{" > "$output_file"
    echo "  \"timestamp\": \"$timestamp\"," >> "$output_file"
    echo "  \"hostname\": \"$hostname\"," >> "$output_file"
    echo "  \"platform\": \"Linux\"," >> "$output_file"
    echo "  \"monitored_paths\": [" >> "$output_file"

    local first_path=true
    for path in "${SUSPICIOUS_PATHS[@]}"; do
        if [[ "$first_path" == "true" ]]; then
            first_path=false
        else
            echo "," >> "$output_file"
        fi
        echo -n "    \"$path\"" >> "$output_file"
    done
    echo "" >> "$output_file"
    echo "  ]," >> "$output_file"
    echo "  \"files\": [" >> "$output_file"

    local count=0
    local first=true

    for dir in "${SUSPICIOUS_PATHS[@]}"; do
        [[ ! -d "$dir" ]] && continue

        print_info "Scanning: $dir"

        while IFS= read -r filepath; do
            [[ -z "$filepath" ]] && continue

            local file_json
            file_json=$(get_file_info "$filepath") || continue

            if [[ "$first" == "true" ]]; then
                first=false
            else
                echo "," >> "$output_file"
            fi

            echo -n "    $file_json" >> "$output_file"
            ((count++)) || true

            if ((count % 100 == 0)); then
                echo -ne "\r${BLUE}[*]${NC} Processed $count files..."
            fi
        done < <(scan_directory "$dir" 3)
    done

    # Also add user home directories
    for home_dir in /home/*; do
        [[ ! -d "$home_dir" ]] && continue

        print_info "Scanning: $home_dir"

        # Scan common persistence locations in home
        for subdir in "" ".ssh" ".config" ".local/bin" ".bashrc" ".profile"; do
            local target="$home_dir/$subdir"
            [[ ! -e "$target" ]] && continue

            if [[ -f "$target" ]]; then
                local file_json
                file_json=$(get_file_info "$target") || continue

                if [[ "$first" == "true" ]]; then
                    first=false
                else
                    echo "," >> "$output_file"
                fi
                echo -n "    $file_json" >> "$output_file"
                ((count++)) || true
            elif [[ -d "$target" ]]; then
                while IFS= read -r filepath; do
                    [[ -z "$filepath" ]] && continue

                    local file_json
                    file_json=$(get_file_info "$filepath") || continue

                    if [[ "$first" == "true" ]]; then
                        first=false
                    else
                        echo "," >> "$output_file"
                    fi
                    echo -n "    $file_json" >> "$output_file"
                    ((count++)) || true
                done < <(find "$target" -maxdepth 1 -type f 2>/dev/null)
            fi
        done
    done

    echo "" >> "$output_file"
    echo "  ]" >> "$output_file"
    echo "}" >> "$output_file"

    echo ""
    print_success "Baseline created: $output_file"
    print_info "Total files: $count"
}

# Run scan
run_scan() {
    local baseline_file="$1"
    local output_file="${2:-}"

    print_header "File Anomaly Scan"

    if [[ ! -f "$baseline_file" ]]; then
        print_error "Baseline file not found: $baseline_file"
        exit 1
    fi

    print_info "Loading baseline: $baseline_file"

    # Build associative arrays for baseline (initialize to avoid unbound variable)
    declare -A baseline_files=()
    declare -A baseline_hashes=()

    # Regex patterns (stored in variables for proper bash handling)
    local re_path='"path":"([^"]+)"'
    local re_hash='"hash":"([^"]+)"'

    # Parse baseline
    while IFS= read -r line; do
        if [[ "$line" =~ $re_path ]]; then
            local path="${BASH_REMATCH[1]}"
            local hash=""
            if [[ "$line" =~ $re_hash ]]; then
                hash="${BASH_REMATCH[1]}"
            fi
            baseline_files["$path"]="$line"
            baseline_hashes["$path"]="$hash"
        fi
    done < "$baseline_file"

    local baseline_count=${#baseline_files[@]}
    print_info "Baseline files: $baseline_count"

    declare -A current_files=()
    local new_count=0
    local missing_count=0
    local modified_count=0

    # Arrays to collect results for JSON output
    local -a new_files_json=()
    local -a modified_files_json=()
    local -a missing_files_json=()

    echo ""
    print_header "Scanning for New/Modified Files"

    for dir in "${SUSPICIOUS_PATHS[@]}"; do
        [[ ! -d "$dir" ]] && continue

        while IFS= read -r filepath; do
            [[ -z "$filepath" ]] && continue

            current_files["$filepath"]=1

            if [[ -z "${baseline_files[$filepath]:-}" ]]; then
                # New file
                ((new_count++)) || true

                local filename
                filename=$(basename "$filepath")
                local size
                size=$(stat -c %s "$filepath" 2>/dev/null || echo "0")
                local mtime
                mtime=$(stat -c %Y "$filepath" 2>/dev/null)
                local mtime_human
                mtime_human=$(date -d "@$mtime" 2>/dev/null || echo "unknown")
                local permissions
                permissions=$(stat -c %a "$filepath" 2>/dev/null)
                local owner
                owner=$(stat -c %U "$filepath" 2>/dev/null)
                local hash
                hash=$(compute_hash "$filepath")

                # Collect risk indicators
                local -a risk_indicators=()
                if [[ "$filename" == .* ]]; then
                    risk_indicators+=("Hidden file")
                fi
                if is_suspicious_extension "$filename"; then
                    risk_indicators+=("Executable extension")
                fi
                if [[ -x "$filepath" ]]; then
                    risk_indicators+=("Executable permissions")
                fi
                if [[ "$filepath" =~ /cron ]]; then
                    risk_indicators+=("Cron persistence location")
                fi
                if [[ "$filepath" =~ /tmp/ ]] || [[ "$filepath" =~ /dev/shm/ ]]; then
                    risk_indicators+=("World-writable directory")
                fi
                if [[ "$filepath" =~ \.ssh/ ]] && [[ ! "$filename" =~ ^(authorized_keys|known_hosts|config)$ ]]; then
                    risk_indicators+=("Unusual SSH file")
                fi

                echo ""
                print_new "$filepath"
                echo -e "    ${CYAN}Size:${NC}        $size bytes"
                echo -e "    ${CYAN}Permissions:${NC} $permissions"
                echo -e "    ${CYAN}Owner:${NC}       $owner"
                echo -e "    ${CYAN}Modified:${NC}    $mtime_human"

                # Show risk indicators
                for indicator in "${risk_indicators[@]}"; do
                    echo -e "    ${RED}[!] SUSPICIOUS: $indicator${NC}"
                done

                # Build JSON for this new file
                local risk_json=""
                if [[ ${#risk_indicators[@]} -gt 0 ]]; then
                    risk_json=$(printf ',"%s"' "${risk_indicators[@]}")
                    risk_json="[${risk_json:1}]"
                else
                    risk_json="[]"
                fi
                local safe_path
                safe_path=$(echo "$filepath" | sed 's/\\/\\\\/g; s/"/\\"/g')
                new_files_json+=("{\"category\":\"new\",\"path\":\"$safe_path\",\"name\":\"$filename\",\"size\":$size,\"permissions\":\"$permissions\",\"owner\":\"$owner\",\"mtime\":$mtime,\"hash\":\"$hash\",\"risk_indicators\":$risk_json}")

            else
                # Check for modification
                local current_hash
                current_hash=$(compute_hash "$filepath")
                local baseline_hash="${baseline_hashes[$filepath]}"

                if [[ "$current_hash" != "null" && "$baseline_hash" != "null" && "$current_hash" != "$baseline_hash" ]]; then
                    ((modified_count++)) || true

                    echo ""
                    print_modified "$filepath"
                    echo -e "    ${CYAN}Baseline Hash:${NC} $baseline_hash"
                    echo -e "    ${CYAN}Current Hash:${NC}  ${RED}$current_hash${NC}"

                    # Build JSON for modified file
                    local safe_path
                    safe_path=$(echo "$filepath" | sed 's/\\/\\\\/g; s/"/\\"/g')
                    modified_files_json+=("{\"category\":\"modified\",\"path\":\"$safe_path\",\"baseline_hash\":\"$baseline_hash\",\"current_hash\":\"$current_hash\",\"risk_indicators\":[\"File hash changed\"]}")
                fi
            fi
        done < <(scan_directory "$dir" 3)
    done

    # Also scan home directories
    for home_dir in /home/*; do
        [[ ! -d "$home_dir" ]] && continue

        for subdir in "" ".ssh" ".config" ".local/bin"; do
            local target="$home_dir/$subdir"
            [[ ! -d "$target" ]] && continue

            while IFS= read -r filepath; do
                [[ -z "$filepath" ]] && continue

                current_files["$filepath"]=1

                if [[ -z "${baseline_files[$filepath]:-}" ]]; then
                    ((new_count++)) || true
                    print_new "$filepath"

                    local filename
                    filename=$(basename "$filepath")
                    local -a risk_indicators=()

                    if [[ "$filename" == .* ]]; then
                        echo -e "    ${RED}[!] SUSPICIOUS: Hidden file${NC}"
                        risk_indicators+=("Hidden file")
                    fi
                    if [[ "$filepath" =~ \.ssh/ ]] && [[ ! "$filename" =~ ^(authorized_keys|known_hosts|config)$ ]]; then
                        echo -e "    ${RED}[!] SUSPICIOUS: Unusual SSH file${NC}"
                        risk_indicators+=("Unusual SSH file")
                    fi

                    # Build JSON
                    local size permissions owner mtime hash
                    size=$(stat -c %s "$filepath" 2>/dev/null || echo "0")
                    permissions=$(stat -c %a "$filepath" 2>/dev/null)
                    owner=$(stat -c %U "$filepath" 2>/dev/null)
                    mtime=$(stat -c %Y "$filepath" 2>/dev/null)
                    hash=$(compute_hash "$filepath")

                    local risk_json=""
                    if [[ ${#risk_indicators[@]} -gt 0 ]]; then
                        risk_json=$(printf ',"%s"' "${risk_indicators[@]}")
                        risk_json="[${risk_json:1}]"
                    else
                        risk_json="[]"
                    fi
                    local safe_path
                    safe_path=$(echo "$filepath" | sed 's/\\/\\\\/g; s/"/\\"/g')
                    new_files_json+=("{\"category\":\"new\",\"path\":\"$safe_path\",\"name\":\"$filename\",\"size\":$size,\"permissions\":\"$permissions\",\"owner\":\"$owner\",\"mtime\":$mtime,\"hash\":\"$hash\",\"risk_indicators\":$risk_json}")
                fi
            done < <(find "$target" -maxdepth 1 -type f 2>/dev/null)
        done
    done

    # Check for missing files
    echo ""
    print_header "Checking for Missing Files"

    for path in "${!baseline_files[@]}"; do
        if [[ -z "${current_files[$path]:-}" ]]; then
            ((missing_count++)) || true
            print_missing "$path"

            local safe_path
            safe_path=$(echo "$path" | sed 's/\\/\\\\/g; s/"/\\"/g')
            missing_files_json+=("{\"category\":\"missing\",\"path\":\"$safe_path\",\"risk_indicators\":[\"File no longer exists\"]}")
        fi
    done

    # Summary
    echo ""
    print_header "Scan Summary"

    if [[ $new_count -gt 0 ]]; then
        echo -e "${RED}[!] New files:      $new_count${NC}"
    else
        echo -e "${GREEN}[+] New files:      $new_count${NC}"
    fi

    if [[ $missing_count -gt 0 ]]; then
        echo -e "${YELLOW}[!] Missing files:  $missing_count${NC}"
    else
        echo -e "${GREEN}[+] Missing files:  $missing_count${NC}"
    fi

    if [[ $modified_count -gt 0 ]]; then
        echo -e "${MAGENTA}[!] Modified files: $modified_count${NC}"
    else
        echo -e "${GREEN}[+] Modified files: $modified_count${NC}"
    fi

    local total=$((new_count + missing_count + modified_count))
    echo ""
    if [[ $total -gt 0 ]]; then
        print_warning "Total anomalies: $total"
    else
        print_success "No anomalies detected"
    fi

    # Save results to JSON if output file specified
    if [[ -n "$output_file" ]]; then
        local timestamp hostname
        timestamp=$(date -Iseconds)
        hostname=$(hostname)

        {
            echo "{"
            echo "  \"scan_type\": \"file_anomaly\","
            echo "  \"timestamp\": \"$timestamp\","
            echo "  \"hostname\": \"$hostname\","
            echo "  \"platform\": \"Linux\","
            echo "  \"baseline_file\": \"$baseline_file\","
            echo "  \"summary\": {"
            echo "    \"new_count\": $new_count,"
            echo "    \"modified_count\": $modified_count,"
            echo "    \"missing_count\": $missing_count,"
            echo "    \"total_anomalies\": $total"
            echo "  },"
            echo "  \"anomalies\": ["

            local first=true
            for item in "${new_files_json[@]}"; do
                if [[ "$first" == "true" ]]; then
                    first=false
                else
                    echo ","
                fi
                echo -n "    $item"
            done
            for item in "${modified_files_json[@]}"; do
                if [[ "$first" == "true" ]]; then
                    first=false
                else
                    echo ","
                fi
                echo -n "    $item"
            done
            for item in "${missing_files_json[@]}"; do
                if [[ "$first" == "true" ]]; then
                    first=false
                else
                    echo ","
                fi
                echo -n "    $item"
            done

            echo ""
            echo "  ]"
            echo "}"
        } > "$output_file"

        echo ""
        print_success "Scan results saved to: $output_file"
    fi
}

# Display baseline or scan results in formatted table
show_results() {
    local file="$1"
    local show_all="${2:-false}"
    local show_limit="${3:-5}"

    if [[ ! -f "$file" ]]; then
        print_error "File not found: $file"
        exit 1
    fi

    print_header "File Analysis Report"

    # Detect file type
    local is_scan=false
    if grep -q '"scan_type"' "$file" 2>/dev/null; then
        is_scan=true
    fi

    # Extract metadata
    local timestamp hostname platform
    timestamp=$(grep -oP '"timestamp":\s*"[^"]*"' "$file" | head -1 | cut -d'"' -f4)
    hostname=$(grep -oP '"hostname":\s*"[^"]*"' "$file" | head -1 | cut -d'"' -f4)
    platform=$(grep -oP '"platform":\s*"[^"]*"' "$file" | head -1 | cut -d'"' -f4)

    echo -e "${CYAN}File:${NC}      $file"
    echo -e "${CYAN}Timestamp:${NC} $timestamp"
    echo -e "${CYAN}Hostname:${NC}  $hostname"
    [[ -n "$platform" ]] && echo -e "${CYAN}Platform:${NC} $platform"
    echo ""

    if [[ "$is_scan" == "true" ]]; then
        show_scan_results "$file" "$show_all" "$show_limit"
    else
        show_baseline_results "$file" "$show_all" "$show_limit"
    fi
}

# Display baseline in formatted table
show_baseline_results() {
    local file="$1"
    local show_all="${2:-false}"
    local show_limit="${3:-5}"

    print_header "File Baseline Summary"

    # Count files
    local total_count
    total_count=$(grep -c '"path":' "$file" 2>/dev/null) || total_count=0

    echo -e "${GREEN}Total Files Monitored:${NC} $total_count"
    if [[ "$show_all" == "true" ]]; then
        echo -e "${YELLOW}Showing all entries${NC}"
    else
        echo -e "${CYAN}Showing up to $show_limit entries per group (use -a/--all for full output)${NC}"
    fi
    echo ""

    # Use Python for detailed display with grouping by directory
    python3 << PYEOF
import json
import os
from datetime import datetime
from collections import defaultdict

# ANSI colors
CYAN = '\033[0;36m'
BLUE = '\033[0;34m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
RED = '\033[0;31m'
WHITE = '\033[1;37m'
NC = '\033[0m'

# Control flags from bash
SHOW_ALL = "$show_all" == "true"
SHOW_LIMIT = int("$show_limit") if "$show_limit".isdigit() else 5

def print_header(text):
    print(f"\n{CYAN}{'='*60}{NC}")
    print(f"{CYAN}  {text}{NC}")
    print(f"{CYAN}{'='*60}{NC}\n")

def format_size(size):
    if size is None:
        return "N/A"
    size = int(size)
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size}{unit}"
        size //= 1024
    return f"{size}TB"

def format_time(mtime):
    if mtime:
        try:
            return datetime.fromtimestamp(int(mtime)).strftime('%Y-%m-%d %H:%M')
        except:
            return str(mtime)
    return "N/A"

try:
    with open("$file", 'r') as f:
        data = json.load(f)

    entries = data.get('entries', data.get('files', []))

    # Group by directory
    by_dir = defaultdict(list)
    for entry in entries:
        path = entry.get('path', '')
        dirname = os.path.dirname(path)
        by_dir[dirname].append(entry)

    # Sort directories by file count (descending)
    sorted_dirs = sorted(by_dir.items(), key=lambda x: len(x[1]), reverse=True)

    for dirname, files in sorted_dirs:
        print_header(f"{dirname} ({len(files)} files)")

        # Sort files by name, apply limit unless show_all
        sorted_files = sorted(files, key=lambda x: x.get('path', ''))
        display_files = sorted_files if SHOW_ALL else sorted_files[:SHOW_LIMIT]

        for i, entry in enumerate(display_files, 1):
            path = entry.get('path', '')
            name = os.path.basename(path)
            owner = entry.get('owner', 'N/A')
            perms = entry.get('permissions', 'N/A')
            size = entry.get('size')
            mtime = entry.get('mtime')
            hash_val = entry.get('hash', entry.get('content_hash', ''))

            print(f"{WHITE}[{i}]{NC} {CYAN}{name}{NC}")
            print(f"    {BLUE}Path:{NC}     {path}")
            print(f"    {BLUE}Size:{NC}     {format_size(size)}")
            print(f"    {BLUE}Owner:{NC}    {owner}")
            print(f"    {BLUE}Perms:{NC}    {perms}")
            print(f"    {BLUE}Modified:{NC} {format_time(mtime)}")
            if hash_val:
                print(f"    {BLUE}SHA256:{NC}   {hash_val[:16]}...")
            print()

        remaining = len(files) - len(display_files)
        if remaining > 0:
            print(f"    {YELLOW}... and {remaining} more files in this directory (use -a to show all){NC}\n")

except Exception as e:
    print(f"Error: {e}")
PYEOF

    # Show statistics by directory
    echo ""
    print_header "Statistics Summary"

    for dir in "${SUSPICIOUS_PATHS[@]}"; do
        local dir_count
        dir_count=$(grep -c "\"$dir" "$file" 2>/dev/null) || dir_count=0
        [[ $dir_count -gt 0 ]] && printf "  %-40s %d files\n" "$dir" "$dir_count"
    done
}

# Display scan results in formatted table
show_scan_results() {
    local file="$1"
    local show_all="${2:-false}"
    local show_limit="${3:-5}"

    # Extract counts
    local new_count modified_count missing_count total_anomalies
    new_count=$(grep -oP '"new_count":\s*\d+' "$file" | grep -oP '\d+') || new_count=0
    modified_count=$(grep -oP '"modified_count":\s*\d+' "$file" | grep -oP '\d+') || modified_count=0
    missing_count=$(grep -oP '"missing_count":\s*\d+' "$file" | grep -oP '\d+') || missing_count=0
    total_anomalies=$((new_count + modified_count + missing_count))

    print_header "Scan Results Summary"

    # Risk assessment
    local risk_level="LOW"
    local risk_color="$GREEN"
    if [[ $total_anomalies -gt 10 ]]; then
        risk_level="CRITICAL"
        risk_color="$RED"
    elif [[ $total_anomalies -gt 5 ]]; then
        risk_level="HIGH"
        risk_color="$RED"
    elif [[ $total_anomalies -gt 0 ]]; then
        risk_level="MEDIUM"
        risk_color="$YELLOW"
    fi

    echo -e "${CYAN}Risk Level:${NC} ${risk_color}${risk_level}${NC}"
    echo ""

    echo -e "${CYAN}┌────────────────────────────────────┬────────┐${NC}"
    printf "${CYAN}│${NC} %-34s ${CYAN}│${NC} %6s ${CYAN}│${NC}\n" "CATEGORY" "COUNT"
    echo -e "${CYAN}├────────────────────────────────────┼────────┤${NC}"

    if [[ $new_count -gt 0 ]]; then
        printf "${CYAN}│${NC} ${RED}%-34s${NC} ${CYAN}│${NC} ${RED}%6d${NC} ${CYAN}│${NC}\n" "New Files" "$new_count"
    else
        printf "${CYAN}│${NC} ${GREEN}%-34s${NC} ${CYAN}│${NC} ${GREEN}%6d${NC} ${CYAN}│${NC}\n" "New Files" "$new_count"
    fi

    if [[ $modified_count -gt 0 ]]; then
        printf "${CYAN}│${NC} ${MAGENTA}%-34s${NC} ${CYAN}│${NC} ${MAGENTA}%6d${NC} ${CYAN}│${NC}\n" "Modified Files" "$modified_count"
    else
        printf "${CYAN}│${NC} ${GREEN}%-34s${NC} ${CYAN}│${NC} ${GREEN}%6d${NC} ${CYAN}│${NC}\n" "Modified Files" "$modified_count"
    fi

    if [[ $missing_count -gt 0 ]]; then
        printf "${CYAN}│${NC} ${YELLOW}%-34s${NC} ${CYAN}│${NC} ${YELLOW}%6d${NC} ${CYAN}│${NC}\n" "Missing Files" "$missing_count"
    else
        printf "${CYAN}│${NC} ${GREEN}%-34s${NC} ${CYAN}│${NC} ${GREEN}%6d${NC} ${CYAN}│${NC}\n" "Missing Files" "$missing_count"
    fi

    echo -e "${CYAN}├────────────────────────────────────┼────────┤${NC}"
    printf "${CYAN}│${NC} ${risk_color}%-34s${NC} ${CYAN}│${NC} ${risk_color}%6d${NC} ${CYAN}│${NC}\n" "TOTAL ANOMALIES" "$total_anomalies"
    echo -e "${CYAN}└────────────────────────────────────┴────────┘${NC}"

    # Show detailed anomalies
    if [[ $total_anomalies -gt 0 ]]; then
        echo ""
        print_header "Anomaly Details"

        local re_path='"path":"([^"]*)"'
        local re_cat='"category":"([^"]*)"'
        local re_risk='"risk_indicators":\[([^\]]*)\]'

        echo -e "${CYAN}┌──────────┬──────────────────────────────────────────────────────────────────────┐${NC}"
        printf "${CYAN}│${NC} %-8s ${CYAN}│${NC} %-68s ${CYAN}│${NC}\n" "TYPE" "FILE PATH / INDICATOR"
        echo -e "${CYAN}├──────────┼──────────────────────────────────────────────────────────────────────┤${NC}"

        while IFS= read -r line; do
            [[ ! "$line" =~ $re_cat ]] && continue

            local category="${BASH_REMATCH[1]}"
            local path=""

            [[ "$line" =~ $re_path ]] && path="${BASH_REMATCH[1]}"

            # Determine color based on category
            local cat_color="$NC"
            local cat_label=""
            case "$category" in
                new) cat_color="$RED"; cat_label="NEW" ;;
                modified) cat_color="$MAGENTA"; cat_label="MODIFIED" ;;
                missing) cat_color="$YELLOW"; cat_label="MISSING" ;;
            esac

            # Truncate
            [[ ${#path} -gt 67 ]] && path="...${path: -64}"

            printf "${CYAN}│${NC} ${cat_color}%-8s${NC} ${CYAN}│${NC} %-68s ${CYAN}│${NC}\n" "$cat_label" "$path"

            # Show risk indicators
            if [[ "$line" =~ $re_risk ]]; then
                local indicators="${BASH_REMATCH[1]}"
                indicators=$(echo "$indicators" | tr ',' '\n' | tr -d '"' | head -3)
                while IFS= read -r ind; do
                    [[ -z "$ind" ]] && continue
                    [[ ${#ind} -gt 66 ]] && ind="${ind:0:63}..."
                    printf "${CYAN}│${NC} %-8s ${CYAN}│${NC} ${RED}⚠ %-66s${NC} ${CYAN}│${NC}\n" "" "$ind"
                done <<< "$indicators"
            fi
        done < "$file"

        echo -e "${CYAN}└──────────┴──────────────────────────────────────────────────────────────────────┘${NC}"
    fi

    # Recommendations
    echo ""
    print_header "Recommendations"

    if [[ $total_anomalies -eq 0 ]]; then
        echo -e "${GREEN}✓ No anomalies detected. File system appears clean.${NC}"
    else
        if [[ $new_count -gt 0 ]]; then
            echo -e "${RED}• Investigate new files - verify legitimacy${NC}"
            echo -e "  - Check file contents: file <path> && cat <path>"
            echo -e "  - Look for suspicious strings: strings <path> | grep -E '(bash|sh|/dev/tcp)'"
            echo -e "  - Review file hashes against threat intel"
        fi
        if [[ $modified_count -gt 0 ]]; then
            echo -e "${MAGENTA}• Verify modified files - possible tampering${NC}"
            echo -e "  - Compare with backup or known-good versions"
            echo -e "  - Check modification timestamps"
            echo -e "  - Consider reinstalling affected packages"
        fi
        if [[ $missing_count -gt 0 ]]; then
            echo -e "${YELLOW}• Review missing files - possible anti-forensics${NC}"
            echo -e "  - Check if files were intentionally removed"
            echo -e "  - Look for evidence of file deletion attempts"
        fi
    fi
}

# Usage
usage() {
    echo "File Anomaly Detection - Pure Bash"
    echo ""
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  baseline    Create baseline of files in suspicious directories"
    echo "  scan        Scan for anomalies against baseline"
    echo "  show        Display baseline or scan results in formatted table"
    echo ""
    echo "Options:"
    echo "  -o, --output FILE    Output file for baseline/scan results"
    echo "  -b, --baseline FILE  Baseline file for scan"
    echo "  -f, --file FILE      File to display (for show command)"
    echo "  -a, --all            Show all entries (no limit, for show command)"
    echo "  -n, --limit NUM      Limit entries per group (default: 5, for show command)"
    echo "  -h, --help           Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 baseline -o /tmp/file_baseline.json"
    echo "  $0 scan -b /tmp/file_baseline.json -o /tmp/results.json"
    echo "  $0 show -f /tmp/file_baseline.json"
    echo "  $0 show -f /tmp/results.json"
    echo ""
    echo "Monitored directories:"
    for dir in "${SUSPICIOUS_PATHS[@]}"; do
        echo "  - $dir"
    done
}

# Main
main() {
    if [[ $# -lt 1 ]]; then
        usage
        exit 1
    fi

    local command="$1"
    shift

    local output_file=""
    local baseline_file=""
    local show_file=""
    local show_all=false
    local show_limit=5

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -o|--output)
                output_file="$2"
                shift 2
                ;;
            -b|--baseline)
                baseline_file="$2"
                shift 2
                ;;
            -f|--file)
                show_file="$2"
                shift 2
                ;;
            -a|--all)
                show_all=true
                shift
                ;;
            -n|--limit)
                show_limit="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    case "$command" in
        baseline)
            [[ -z "$output_file" ]] && output_file="file_baseline.json"
            create_baseline "$output_file"
            ;;
        scan)
            if [[ -z "$baseline_file" ]]; then
                print_error "Baseline file required for scan (-b)"
                exit 1
            fi
            run_scan "$baseline_file" "$output_file"
            ;;
        show)
            if [[ -z "$show_file" ]]; then
                print_error "File required for show command (-f)"
                exit 1
            fi
            show_results "$show_file" "$show_all" "$show_limit"
            ;;
        *)
            print_error "Unknown command: $command"
            usage
            exit 1
            ;;
    esac
}

main "$@"
