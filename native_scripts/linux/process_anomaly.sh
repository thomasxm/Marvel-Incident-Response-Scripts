#!/bin/bash
#
# Process Anomaly Detection - Pure Bash Implementation
# No external dependencies - uses /proc, ps, sha256sum
#
# Usage:
#   ./process_anomaly.sh baseline -o baseline.json
#   ./process_anomaly.sh scan -b baseline.json
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

# Kernel process patterns to whitelist (cannot be injected)
KERNEL_PROCESSES=(
    "kthreadd"
    "kworker/*"
    "ksoftirqd/*"
    "kswapd*"
    "migration/*"
    "rcu_sched"
    "rcu_bh"
    "watchdog/*"
    "cpuhp/*"
    "kauditd"
    "khungtaskd"
    "oom_reaper"
    "writeback"
    "kcompactd*"
    "khugepaged"
    "kintegrityd"
    "kblockd"
    "kthrotld"
    "irq/*"
    "scsi_*"
    "md*_*"
    "edac-poller"
    "ipv6_addrconf"
    "netns"
)

# Auto-updating/dynamic processes to skip hash comparison
# These legitimately change their executables frequently
DYNAMIC_HASH_SKIP=(
    # Browsers (auto-update)
    "chrome"
    "chrome_crashpad"
    "chromium"
    "firefox"
    "brave"
    # Electron apps (auto-update)
    "code"               # VS Code
    "claude"             # Claude desktop app
    "slack"
    "discord"
    "spotify"
    "teams"
    "zoom"
    "electron"
    "signal-desktop"
    # Development tools
    "node"               # Node.js apps often update
    "npm"
    "npx"
    # Package managers
    "snapd"
    "flatpak"
    "gnome-software"
    "packagekitd"
    "apt"
    "dpkg"
    "rpm"
    "yum"
    "dnf"
    # Desktop portals (dynamically load extensions)
    "xdg-desktop-por"    # xdg-desktop-portal (truncated in /proc)
    "xdg-document-por"
    "xdg-permission-s"
    # GNOME/KDE services that load plugins
    "gnome-shell"
    "plasmashell"
    "kwin"
)

# Paths that indicate auto-updating applications
DYNAMIC_PATH_PATTERNS=(
    "*/versions/*"       # Version directories (Claude, Electron apps)
    "*/app-*/resources/*"  # Electron apps
    "*/.local/share/*/versions/*"
    "*/snap/*"
    "*/flatpak/*"
    "*/.cache/*"
    # Python version managers
    "*/.local/share/uv/*"     # UV Python manager
    "*/.pyenv/*"              # pyenv
    "*/.asdf/*"               # asdf version manager
    "*/virtualenv/*"
    "*/venv/*"
    "*/.conda/*"              # Conda
    # Node version managers
    "*/.nvm/*"                # Node Version Manager
    "*/.volta/*"              # Volta
    # Ruby version managers
    "*/.rbenv/*"
    "*/.rvm/*"
)

# Check if process should skip hash comparison
should_skip_hash_check() {
    local name="$1"
    local exe="$2"

    # In strict mode, never skip
    [[ "$STRICT_MODE" == "true" ]] && return 1

    # Check process name whitelist
    for pattern in "${DYNAMIC_HASH_SKIP[@]}"; do
        if [[ "$name" == "$pattern" ]] || [[ "$name" == "${pattern}_"* ]]; then
            return 0
        fi
    done

    # Check exe path patterns
    for pattern in "${DYNAMIC_PATH_PATTERNS[@]}"; do
        if [[ "$exe" == $pattern ]]; then
            return 0
        fi
    done

    return 1
}

# Check if process is a kernel thread
is_kernel_process() {
    local name="$1"
    local pid="$2"

    # PID 2 is always kthreadd
    [[ "$pid" == "2" ]] && return 0

    # Check /proc/[pid]/exe - kernel threads have no exe
    [[ ! -e "/proc/$pid/exe" ]] && return 0

    # Check against patterns
    for pattern in "${KERNEL_PROCESSES[@]}"; do
        if [[ "$name" == $pattern ]]; then
            return 0
        fi
    done

    # Bracketed names are kernel threads
    [[ "$name" =~ ^\[.*\]$ ]] && return 0

    return 1
}

# Compute SHA256 hash of executable
compute_hash() {
    local exe_path="$1"

    if [[ -f "$exe_path" && -r "$exe_path" ]]; then
        sha256sum "$exe_path" 2>/dev/null | cut -d' ' -f1
    else
        echo "null"
    fi
}

# Get process info from /proc
get_process_info() {
    local pid="$1"
    local proc_dir="/proc/$pid"

    [[ ! -d "$proc_dir" ]] && return 1

    # Get basic info
    local name="" ppid="" uid="" state=""
    if [[ -r "$proc_dir/status" ]]; then
        name=$(grep -m1 "^Name:" "$proc_dir/status" 2>/dev/null | awk '{print $2}')
        ppid=$(grep -m1 "^PPid:" "$proc_dir/status" 2>/dev/null | awk '{print $2}')
        uid=$(grep -m1 "^Uid:" "$proc_dir/status" 2>/dev/null | awk '{print $2}')
        state=$(grep -m1 "^State:" "$proc_dir/status" 2>/dev/null | awk '{print $2}')
    fi

    # Get username from UID
    local username
    username=$(getent passwd "$uid" 2>/dev/null | cut -d: -f1)
    [[ -z "$username" ]] && username="$uid"

    # Get exe path
    local exe=""
    if [[ -L "$proc_dir/exe" ]]; then
        exe=$(readlink -f "$proc_dir/exe" 2>/dev/null) || exe=""
    fi

    # Get cmdline
    local cmdline=""
    if [[ -r "$proc_dir/cmdline" ]]; then
        cmdline=$(tr '\0' ' ' < "$proc_dir/cmdline" 2>/dev/null | sed 's/ $//')
    fi

    # Get cwd
    local cwd=""
    if [[ -L "$proc_dir/cwd" ]]; then
        cwd=$(readlink -f "$proc_dir/cwd" 2>/dev/null) || cwd=""
    fi

    # Get create time (stat of /proc/pid)
    local create_time=""
    create_time=$(stat -c %Y "$proc_dir" 2>/dev/null)

    # Compute hash
    local exe_hash="null"
    if [[ -n "$exe" && ! "$exe" =~ \(deleted\)$ ]]; then
        exe_hash=$(compute_hash "$exe")
    fi

    # Output JSON
    echo "{\"pid\":$pid,\"name\":\"$name\",\"ppid\":$ppid,\"username\":\"$username\",\"exe\":\"$exe\",\"cmdline\":\"$(echo "$cmdline" | sed 's/"/\\"/g' | head -c 500)\",\"cwd\":\"$cwd\",\"state\":\"$state\",\"create_time\":$create_time,\"exe_hash\":\"$exe_hash\"}"
}

# Create baseline
create_baseline() {
    local output_file="$1"

    print_header "Creating Process Baseline"

    local hostname
    hostname=$(hostname)
    local timestamp
    timestamp=$(date -Iseconds)
    local kernel
    kernel=$(uname -r)

    print_info "Hostname: $hostname"
    print_info "Timestamp: $timestamp"
    print_info "Kernel: $kernel"

    # Start JSON
    echo "{" > "$output_file"
    echo "  \"timestamp\": \"$timestamp\"," >> "$output_file"
    echo "  \"hostname\": \"$hostname\"," >> "$output_file"
    echo "  \"kernel\": \"$kernel\"," >> "$output_file"
    echo "  \"platform\": \"Linux\"," >> "$output_file"
    echo "  \"processes\": [" >> "$output_file"

    local count=0
    local first=true

    # Iterate through /proc
    for pid_dir in /proc/[0-9]*; do
        local pid
        pid=$(basename "$pid_dir")

        # Skip kernel threads
        local name
        name=$(grep -m1 "^Name:" "$pid_dir/status" 2>/dev/null | awk '{print $2}') || continue

        if is_kernel_process "$name" "$pid"; then
            continue
        fi

        # Get process info
        local proc_json
        proc_json=$(get_process_info "$pid") || continue

        if [[ "$first" == "true" ]]; then
            first=false
        else
            echo "," >> "$output_file"
        fi

        echo -n "    $proc_json" >> "$output_file"
        ((count++)) || true

        # Progress
        if ((count % 50 == 0)); then
            echo -ne "\r${BLUE}[*]${NC} Processed $count processes..."
        fi
    done

    echo "" >> "$output_file"
    echo "  ]" >> "$output_file"
    echo "}" >> "$output_file"

    echo ""
    print_success "Baseline created: $output_file"
    print_info "Total processes: $count"
}

# Load baseline from JSON
load_baseline() {
    local baseline_file="$1"

    if [[ ! -f "$baseline_file" ]]; then
        print_error "Baseline file not found: $baseline_file"
        exit 1
    fi

    # Extract processes - simple parsing without jq
    grep -oP '"pid":\d+' "$baseline_file" | grep -oP '\d+' | sort -n
}

# Get baseline process by PID
get_baseline_process() {
    local baseline_file="$1"
    local pid="$2"

    # Extract the JSON object for this PID
    # This is a simplified extraction - works for our format
    awk -v pid="$pid" '
        /"pid":'"$pid"'[,}]/ {
            # Find the start of this object
            gsub(/^[ \t]+/, "")
            print
            exit
        }
    ' "$baseline_file"
}

# Run anomaly scan
run_scan() {
    local baseline_file="$1"
    local output_file="${2:-}"

    print_header "Process Anomaly Scan"

    if [[ ! -f "$baseline_file" ]]; then
        print_error "Baseline file not found: $baseline_file"
        exit 1
    fi

    print_info "Loading baseline: $baseline_file"

    # Build associative arrays for baseline (initialize with dummy to avoid unbound variable)
    declare -A baseline_names=()
    declare -A baseline_hashes=()
    declare -A baseline_pids=()
    declare -A baseline_exe=()

    # Regex patterns (stored in variables for proper bash handling)
    local re_pid='"pid":([0-9]+)'
    local re_name='"name":"([^"]+)"'
    local re_hash='"exe_hash":"([^"]+)"'
    local re_exe='"exe":"([^"]*)"'

    # Parse baseline (simplified - extracts key fields)
    while IFS= read -r line; do
        if [[ "$line" =~ $re_pid ]]; then
            local pid="${BASH_REMATCH[1]}"
            local name="" hash="" exe_path=""

            if [[ "$line" =~ $re_name ]]; then
                name="${BASH_REMATCH[1]}"
            fi
            if [[ "$line" =~ $re_hash ]]; then
                hash="${BASH_REMATCH[1]}"
            fi
            if [[ "$line" =~ $re_exe ]]; then
                exe_path="${BASH_REMATCH[1]}"
            fi

            baseline_names["$name:$pid"]="$line"
            baseline_hashes["$name"]="$hash"
            baseline_pids["$pid"]="$name"
            baseline_exe["$name"]="$exe_path"
        fi
    done < "$baseline_file"

    local baseline_count=${#baseline_pids[@]}
    print_info "Baseline processes: $baseline_count"

    # Track current processes
    declare -A current_pids=()
    declare -A current_names=()

    local new_count=0
    local missing_count=0
    local modified_count=0
    local skipped_count=0

    # Arrays to collect results for JSON output
    local -a new_processes_json=()
    local -a modified_processes_json=()
    local -a missing_processes_json=()

    # Show mode info
    if [[ "$STRICT_MODE" == "true" ]]; then
        print_warning "Strict mode: all hash changes will be reported"
    else
        print_info "Normal mode: auto-updating apps excluded from hash comparison"
    fi

    echo ""
    print_header "Scanning Current Processes"

    # Check current processes
    for pid_dir in /proc/[0-9]*; do
        local pid
        pid=$(basename "$pid_dir")

        local name
        name=$(grep -m1 "^Name:" "$pid_dir/status" 2>/dev/null | awk '{print $2}') || continue

        # Skip kernel threads
        if is_kernel_process "$name" "$pid"; then
            continue
        fi

        current_pids["$pid"]="$name"
        current_names["$name"]=1

        # Check if this is a new process (by name, since PIDs change)
        if [[ -z "${baseline_hashes[$name]:-}" ]]; then
            # New process
            ((new_count++)) || true

            local exe=""
            [[ -L "$pid_dir/exe" ]] && exe=$(readlink -f "$pid_dir/exe" 2>/dev/null)
            local cmdline=""
            [[ -r "$pid_dir/cmdline" ]] && cmdline=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null | head -c 200)
            local username
            local uid
            uid=$(grep -m1 "^Uid:" "$pid_dir/status" 2>/dev/null | awk '{print $2}')
            username=$(getent passwd "$uid" 2>/dev/null | cut -d: -f1)
            [[ -z "$username" ]] && username="$uid"

            # Collect risk indicators
            local -a risk_indicators=()
            if [[ "$exe" =~ ^/tmp/ ]] || [[ "$exe" =~ ^/dev/shm/ ]] || [[ "$exe" =~ ^/var/tmp/ ]]; then
                risk_indicators+=("Executable in temp directory")
            fi
            if [[ "$cmdline" =~ /dev/tcp/ ]] || [[ "$cmdline" =~ "bash -i" ]]; then
                risk_indicators+=("Possible reverse shell")
            fi
            if [[ "$name" =~ ^(nc|ncat|netcat|socat)$ ]]; then
                risk_indicators+=("Network tool")
            fi
            if [[ "$name" =~ ^(python|perl|ruby|php|bash|sh)$ && "$cmdline" =~ -(c|e)\ .*\; ]]; then
                risk_indicators+=("Scripting with inline code")
            fi

            echo ""
            print_new "Process: $name (PID: $pid)"
            echo -e "    ${CYAN}User:${NC}    $username"
            echo -e "    ${CYAN}Exe:${NC}     $exe"
            echo -e "    ${CYAN}Cmdline:${NC} $cmdline"

            # Show risk indicators
            for indicator in "${risk_indicators[@]}"; do
                echo -e "    ${RED}[!] SUSPICIOUS: $indicator${NC}"
            done

            # Build JSON for this new process
            local risk_json=""
            if [[ ${#risk_indicators[@]} -gt 0 ]]; then
                risk_json=$(printf ',"%s"' "${risk_indicators[@]}")
                risk_json="[${risk_json:1}]"
            else
                risk_json="[]"
            fi
            local escaped_cmdline
            escaped_cmdline=$(echo "$cmdline" | sed 's/\\/\\\\/g; s/"/\\"/g')
            new_processes_json+=("{\"category\":\"new\",\"pid\":$pid,\"name\":\"$name\",\"username\":\"$username\",\"exe\":\"$exe\",\"cmdline\":\"$escaped_cmdline\",\"risk_indicators\":$risk_json}")
        else
            # Check for hash modification
            local current_hash="null"
            local exe=""
            if [[ -L "$pid_dir/exe" ]]; then
                exe=$(readlink -f "$pid_dir/exe" 2>/dev/null) || exe=""
            fi

            # Skip hash check for auto-updating/dynamic applications
            if should_skip_hash_check "$name" "$exe"; then
                ((skipped_count++)) || true
                continue
            fi

            if [[ -n "$exe" && ! "$exe" =~ \(deleted\)$ && -f "$exe" ]]; then
                current_hash=$(compute_hash "$exe")
            fi

            local baseline_hash="${baseline_hashes[$name]}"

            if [[ "$current_hash" != "null" && "$baseline_hash" != "null" && "$current_hash" != "$baseline_hash" ]]; then
                ((modified_count++)) || true
                echo ""
                print_modified "Process: $name (PID: $pid)"
                echo -e "    ${CYAN}Exe:${NC}           $exe"
                echo -e "    ${CYAN}Baseline Hash:${NC} $baseline_hash"
                echo -e "    ${CYAN}Current Hash:${NC}  ${RED}$current_hash${NC}"

                # Build JSON for modified process
                modified_processes_json+=("{\"category\":\"modified\",\"pid\":$pid,\"name\":\"$name\",\"exe\":\"$exe\",\"baseline_hash\":\"$baseline_hash\",\"current_hash\":\"$current_hash\",\"risk_indicators\":[\"Executable hash changed\"]}")
            fi
        fi
    done

    # Check for missing processes
    echo ""
    print_header "Checking for Missing Processes"

    for name in "${!baseline_hashes[@]}"; do
        if [[ -z "${current_names[$name]:-}" ]]; then
            ((missing_count++)) || true
            print_missing "Process no longer running: $name"

            local baseline_exe_path="${baseline_exe[$name]:-unknown}"
            missing_processes_json+=("{\"category\":\"missing\",\"name\":\"$name\",\"exe\":\"$baseline_exe_path\",\"risk_indicators\":[\"Process no longer running\"]}")
        fi
    done

    # Summary
    echo ""
    print_header "Scan Summary"

    if [[ $new_count -gt 0 ]]; then
        echo -e "${RED}[!] New processes:      $new_count${NC}"
    else
        echo -e "${GREEN}[+] New processes:      $new_count${NC}"
    fi

    if [[ $missing_count -gt 0 ]]; then
        echo -e "${YELLOW}[!] Missing processes:  $missing_count${NC}"
    else
        echo -e "${GREEN}[+] Missing processes:  $missing_count${NC}"
    fi

    if [[ $modified_count -gt 0 ]]; then
        echo -e "${MAGENTA}[!] Modified processes: $modified_count${NC}"
    else
        echo -e "${GREEN}[+] Modified processes: $modified_count${NC}"
    fi

    if [[ $skipped_count -gt 0 && "$STRICT_MODE" != "true" ]]; then
        echo -e "${BLUE}[*] Skipped (dynamic):  $skipped_count${NC} (use --strict to include)"
    fi

    local total_anomalies=$((new_count + missing_count + modified_count))
    echo ""
    if [[ $total_anomalies -gt 0 ]]; then
        print_warning "Total anomalies detected: $total_anomalies"
    else
        print_success "No anomalies detected"
    fi

    # Save results to JSON if output file specified
    if [[ -n "$output_file" ]]; then
        local timestamp hostname kernel
        timestamp=$(date -Iseconds)
        hostname=$(hostname)
        kernel=$(uname -r)

        {
            echo "{"
            echo "  \"scan_type\": \"process_anomaly\","
            echo "  \"timestamp\": \"$timestamp\","
            echo "  \"hostname\": \"$hostname\","
            echo "  \"kernel\": \"$kernel\","
            echo "  \"platform\": \"Linux\","
            echo "  \"baseline_file\": \"$baseline_file\","
            echo "  \"strict_mode\": $STRICT_MODE,"
            echo "  \"summary\": {"
            echo "    \"new_count\": $new_count,"
            echo "    \"modified_count\": $modified_count,"
            echo "    \"missing_count\": $missing_count,"
            echo "    \"skipped_count\": $skipped_count,"
            echo "    \"total_anomalies\": $total_anomalies"
            echo "  },"
            echo "  \"anomalies\": ["

            local first=true
            for item in "${new_processes_json[@]}"; do
                if [[ "$first" == "true" ]]; then
                    first=false
                else
                    echo ","
                fi
                echo -n "    $item"
            done
            for item in "${modified_processes_json[@]}"; do
                if [[ "$first" == "true" ]]; then
                    first=false
                else
                    echo ","
                fi
                echo -n "    $item"
            done
            for item in "${missing_processes_json[@]}"; do
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

# Global flag for strict mode
STRICT_MODE=false

# Global arrays for scan results (for JSON output)
declare -a SCAN_NEW_PROCESSES=()
declare -a SCAN_MISSING_PROCESSES=()
declare -a SCAN_MODIFIED_PROCESSES=()

# Display baseline or scan results in formatted table
show_results() {
    local file="$1"
    local show_all="${2:-false}"
    local show_limit="${3:-5}"

    if [[ ! -f "$file" ]]; then
        print_error "File not found: $file"
        exit 1
    fi

    print_header "Process Analysis Report"

    # Detect file type
    local is_scan=false
    if grep -q '"scan_type"' "$file" 2>/dev/null; then
        is_scan=true
    fi

    # Extract metadata
    local timestamp hostname kernel platform
    timestamp=$(grep -oP '"timestamp":\s*"[^"]*"' "$file" | head -1 | cut -d'"' -f4)
    hostname=$(grep -oP '"hostname":\s*"[^"]*"' "$file" | head -1 | cut -d'"' -f4)
    kernel=$(grep -oP '"kernel":\s*"[^"]*"' "$file" | head -1 | cut -d'"' -f4)
    platform=$(grep -oP '"platform":\s*"[^"]*"' "$file" | head -1 | cut -d'"' -f4)

    echo -e "${CYAN}File:${NC}      $file"
    echo -e "${CYAN}Timestamp:${NC} $timestamp"
    echo -e "${CYAN}Hostname:${NC}  $hostname"
    [[ -n "$kernel" ]] && echo -e "${CYAN}Kernel:${NC}    $kernel"
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

    print_header "Process Baseline Summary"

    # Count processes
    local total_count
    total_count=$(grep -c '"pid":' "$file" 2>/dev/null) || total_count=0

    echo -e "${GREEN}Total Processes:${NC} $total_count"
    if [[ "$show_all" == "true" ]]; then
        echo -e "${YELLOW}Showing all entries${NC}"
    else
        echo -e "${CYAN}Showing up to $show_limit entries per group (use -a/--all for full output)${NC}"
    fi
    echo ""

    # Use Python for detailed display
    python3 << PYEOF
import json
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

def format_time(create_time):
    if create_time:
        try:
            return datetime.fromtimestamp(float(create_time)).strftime('%Y-%m-%d %H:%M:%S')
        except:
            return str(create_time)
    return "N/A"

try:
    with open("$file", 'r') as f:
        data = json.load(f)

    processes = data.get('processes', data.get('entries', []))

    # Group by user
    by_user = defaultdict(list)
    for proc in processes:
        user = proc.get('username', 'unknown')
        by_user[user].append(proc)

    # Sort users by process count
    sorted_users = sorted(by_user.items(), key=lambda x: len(x[1]), reverse=True)

    for user, procs in sorted_users:
        print_header(f"User: {user} ({len(procs)} processes)")

        # Sort by process name, apply limit unless show_all
        sorted_procs = sorted(procs, key=lambda x: x.get('name', ''))
        display_procs = sorted_procs if SHOW_ALL else sorted_procs[:SHOW_LIMIT]

        for i, proc in enumerate(display_procs, 1):
            name = proc.get('name', 'N/A')
            pid = proc.get('pid', 'N/A')
            exe = proc.get('exe', 'N/A')
            cmdline = proc.get('cmdline', '')
            ppid = proc.get('ppid', 'N/A')
            create_time = proc.get('create_time')
            status = proc.get('status', 'N/A')
            hash_val = proc.get('exe_hash', proc.get('hash', ''))

            # Truncate long command lines
            if cmdline and len(cmdline) > 80:
                cmdline = cmdline[:77] + '...'

            print(f"{WHITE}[{i}]{NC} {CYAN}{name}{NC} (PID: {pid})")
            print(f"    {BLUE}Executable:{NC} {exe}")
            if cmdline:
                print(f"    {BLUE}Command:{NC}    {cmdline}")
            print(f"    {BLUE}PPID:{NC}       {ppid}")
            print(f"    {BLUE}Status:{NC}     {status}")
            if create_time:
                print(f"    {BLUE}Started:{NC}    {format_time(create_time)}")
            if hash_val:
                print(f"    {BLUE}Exe Hash:{NC}   {hash_val[:16]}...")
            print()

        remaining = len(procs) - len(display_procs)
        if remaining > 0:
            print(f"    {YELLOW}... and {remaining} more processes for this user (use -a to show all){NC}\n")

    # Summary statistics
    print_header("Summary Statistics")

    # Count by user
    print(f"{CYAN}Processes by User:{NC}")
    for user, procs in sorted_users[:10]:
        print(f"  {user:20s} {len(procs)} processes")

    # Suspicious locations
    tmp_procs = [p for p in processes if '/tmp/' in str(p.get('exe', ''))]
    shm_procs = [p for p in processes if '/dev/shm/' in str(p.get('exe', ''))]

    if tmp_procs or shm_procs:
        print(f"\n{RED}Suspicious Executable Locations:{NC}")
        if tmp_procs:
            print(f"  {YELLOW}/tmp:{NC} {len(tmp_procs)} processes")
            display_tmp = tmp_procs if SHOW_ALL else tmp_procs[:SHOW_LIMIT]
            for p in display_tmp:
                print(f"    - {p.get('name', 'N/A')} ({p.get('exe', 'N/A')})")
            if not SHOW_ALL and len(tmp_procs) > SHOW_LIMIT:
                print(f"    ... and {len(tmp_procs) - SHOW_LIMIT} more")
        if shm_procs:
            print(f"  {YELLOW}/dev/shm:{NC} {len(shm_procs)} processes")
            display_shm = shm_procs if SHOW_ALL else shm_procs[:SHOW_LIMIT]
            for p in display_shm:
                print(f"    - {p.get('name', 'N/A')} ({p.get('exe', 'N/A')})")
            if not SHOW_ALL and len(shm_procs) > SHOW_LIMIT:
                print(f"    ... and {len(shm_procs) - SHOW_LIMIT} more")

except Exception as e:
    print(f"Error: {e}")
PYEOF
}

# Display scan results in formatted table
show_scan_results() {
    local file="$1"
    local show_all="${2:-false}"
    local show_limit="${3:-5}"

    # Extract counts from summary section first (most reliable)
    local new_count modified_count missing_count total_anomalies
    new_count=$(grep -oP '"new_count":\s*\d+' "$file" | grep -oP '\d+' | head -1) || new_count=0
    modified_count=$(grep -oP '"modified_count":\s*\d+' "$file" | grep -oP '\d+' | head -1) || modified_count=0
    missing_count=$(grep -oP '"missing_count":\s*\d+' "$file" | grep -oP '\d+' | head -1) || missing_count=0

    # Fallback to counting categories if summary not found
    if [[ -z "$new_count" || "$new_count" == "0" ]]; then
        new_count=$(grep -c '"category":"new"' "$file" 2>/dev/null) || new_count=0
    fi
    if [[ -z "$modified_count" || "$modified_count" == "0" ]]; then
        modified_count=$(grep -c '"category":"modified"' "$file" 2>/dev/null) || modified_count=0
    fi
    if [[ -z "$missing_count" || "$missing_count" == "0" ]]; then
        missing_count=$(grep -c '"category":"missing"' "$file" 2>/dev/null) || missing_count=0
    fi

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
        printf "${CYAN}│${NC} ${RED}%-34s${NC} ${CYAN}│${NC} ${RED}%6d${NC} ${CYAN}│${NC}\n" "New Processes" "$new_count"
    else
        printf "${CYAN}│${NC} ${GREEN}%-34s${NC} ${CYAN}│${NC} ${GREEN}%6d${NC} ${CYAN}│${NC}\n" "New Processes" "$new_count"
    fi

    if [[ $modified_count -gt 0 ]]; then
        printf "${CYAN}│${NC} ${MAGENTA}%-34s${NC} ${CYAN}│${NC} ${MAGENTA}%6d${NC} ${CYAN}│${NC}\n" "Modified Processes" "$modified_count"
    else
        printf "${CYAN}│${NC} ${GREEN}%-34s${NC} ${CYAN}│${NC} ${GREEN}%6d${NC} ${CYAN}│${NC}\n" "Modified Processes" "$modified_count"
    fi

    if [[ $missing_count -gt 0 ]]; then
        printf "${CYAN}│${NC} ${YELLOW}%-34s${NC} ${CYAN}│${NC} ${YELLOW}%6d${NC} ${CYAN}│${NC}\n" "Missing Processes" "$missing_count"
    else
        printf "${CYAN}│${NC} ${GREEN}%-34s${NC} ${CYAN}│${NC} ${GREEN}%6d${NC} ${CYAN}│${NC}\n" "Missing Processes" "$missing_count"
    fi

    echo -e "${CYAN}├────────────────────────────────────┼────────┤${NC}"
    printf "${CYAN}│${NC} ${risk_color}%-34s${NC} ${CYAN}│${NC} ${risk_color}%6d${NC} ${CYAN}│${NC}\n" "TOTAL ANOMALIES" "$total_anomalies"
    echo -e "${CYAN}└────────────────────────────────────┴────────┘${NC}"

    # Show detailed anomalies
    if [[ $total_anomalies -gt 0 ]]; then
        echo ""
        print_header "Anomaly Details"

        # Parse and display each anomaly
        local re_name='"name":"([^"]*)"'
        local re_cat='"category":"([^"]*)"'
        local re_exe='"exe":"([^"]*)"'
        local re_user='"username":"([^"]*)"'
        local re_cmdline='"cmdline":"([^"]*)"'
        local re_risk='"risk_indicators":\[([^\]]*)\]'

        echo -e "${CYAN}┌──────────┬────────────────────────┬──────────┬─────────────────────────────────────────────────┐${NC}"
        printf "${CYAN}│${NC} %-8s ${CYAN}│${NC} %-22s ${CYAN}│${NC} %-8s ${CYAN}│${NC} %-47s ${CYAN}│${NC}\n" "TYPE" "PROCESS" "USER" "EXECUTABLE/INDICATOR"
        echo -e "${CYAN}├──────────┼────────────────────────┼──────────┼─────────────────────────────────────────────────┤${NC}"

        while IFS= read -r line; do
            [[ ! "$line" =~ $re_cat ]] && continue

            local category="${BASH_REMATCH[1]}"
            local name="" user="" exe="" indicator=""

            [[ "$line" =~ $re_name ]] && name="${BASH_REMATCH[1]}"
            [[ "$line" =~ $re_user ]] && user="${BASH_REMATCH[1]}"
            [[ "$line" =~ $re_exe ]] && exe="${BASH_REMATCH[1]}"

            # Determine color based on category
            local cat_color="$NC"
            local cat_label=""
            case "$category" in
                new) cat_color="$RED"; cat_label="NEW" ;;
                modified) cat_color="$MAGENTA"; cat_label="MODIFIED" ;;
                missing) cat_color="$YELLOW"; cat_label="MISSING" ;;
            esac

            # Truncate
            [[ ${#name} -gt 21 ]] && name="${name:0:18}..."
            [[ ${#user} -gt 8 ]] && user="${user:0:8}"
            [[ ${#exe} -gt 46 ]] && exe="...${exe: -43}"

            printf "${CYAN}│${NC} ${cat_color}%-8s${NC} ${CYAN}│${NC} %-22s ${CYAN}│${NC} %-8s ${CYAN}│${NC} %-47s ${CYAN}│${NC}\n" "$cat_label" "$name" "$user" "$exe"

            # Show risk indicators if present
            if [[ "$line" =~ $re_risk ]]; then
                local indicators="${BASH_REMATCH[1]}"
                indicators=$(echo "$indicators" | tr ',' '\n' | tr -d '"' | head -3)
                while IFS= read -r ind; do
                    [[ -z "$ind" ]] && continue
                    [[ ${#ind} -gt 46 ]] && ind="${ind:0:43}..."
                    printf "${CYAN}│${NC} %-8s ${CYAN}│${NC} %-22s ${CYAN}│${NC} %-8s ${CYAN}│${NC} ${RED}⚠ %-45s${NC} ${CYAN}│${NC}\n" "" "" "" "$ind"
                done <<< "$indicators"
            fi
        done < "$file"

        echo -e "${CYAN}└──────────┴────────────────────────┴──────────┴─────────────────────────────────────────────────┘${NC}"
    fi

    # Recommendations
    echo ""
    print_header "Recommendations"

    if [[ $total_anomalies -eq 0 ]]; then
        echo -e "${GREEN}✓ No anomalies detected. System appears clean.${NC}"
    else
        if [[ $new_count -gt 0 ]]; then
            echo -e "${RED}• Investigate new processes - verify legitimacy${NC}"
            echo -e "  - Check process ancestry: ps -ef | grep <PID>"
            echo -e "  - Examine network connections: ss -tulpn | grep <PID>"
            echo -e "  - Review file hashes against threat intel"
        fi
        if [[ $modified_count -gt 0 ]]; then
            echo -e "${MAGENTA}• Verify modified executables - possible tampering${NC}"
            echo -e "  - Compare with known-good hashes"
            echo -e "  - Check file timestamps and permissions"
            echo -e "  - Consider reinstalling affected packages"
        fi
        if [[ $missing_count -gt 0 ]]; then
            echo -e "${YELLOW}• Review missing processes - possible service disruption${NC}"
            echo -e "  - Check if services were intentionally stopped"
            echo -e "  - Look for signs of anti-forensics activity"
        fi
    fi
}

# Usage
usage() {
    echo "Process Anomaly Detection - Pure Bash"
    echo ""
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  baseline    Create a baseline of current processes"
    echo "  scan        Scan for anomalies against baseline"
    echo "  show        Display baseline or scan results in formatted table"
    echo ""
    echo "Options:"
    echo "  -o, --output FILE    Output file for baseline/scan results"
    echo "  -b, --baseline FILE  Baseline file for scan"
    echo "  -f, --file FILE      File to display (for show command)"
    echo "  -a, --all            Show all entries (no limit, for show command)"
    echo "  -n, --limit NUM      Limit entries per group (default: 5, for show command)"
    echo "  -s, --strict         Strict mode: report all hash changes (no whitelist)"
    echo "  -h, --help           Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 baseline -o /tmp/baseline.json"
    echo "  $0 scan -b /tmp/baseline.json -o /tmp/results.json"
    echo "  $0 scan -b /tmp/baseline.json --strict"
    echo "  $0 show -f /tmp/baseline.json"
    echo "  $0 show -f /tmp/results.json"
    echo ""
    echo "Note: By default, auto-updating applications (Chrome, Claude, VS Code, etc.)"
    echo "      are excluded from hash comparison to reduce false positives."
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
            -s|--strict)
                STRICT_MODE=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    case "$command" in
        baseline)
            [[ -z "$output_file" ]] && output_file="process_baseline.json"
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
