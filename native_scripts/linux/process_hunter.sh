#!/bin/bash
#
# Process Hunter - Pure Bash Implementation
# No external dependencies - uses ps, /proc, grep, kill
#
# Search for processes by regex pattern and optionally kill them
#
# Usage:
#   ./process_hunter.sh "pattern"
#   ./process_hunter.sh "nc|netcat" -k
#   ./process_hunter.sh "python.*socket" -c -o results.json
#

set -uo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

# Output functions
print_header() { echo -e "\n${CYAN}════════════════════════════════════════════════════════════${NC}"; echo -e "${CYAN}  $1${NC}"; echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}\n"; }
print_info() { echo -e "${BLUE}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[+]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error() { echo -e "${RED}[-]${NC} $1"; }

# Suspicious path patterns
SUSPICIOUS_PATHS=(
    "/tmp/"
    "/var/tmp/"
    "/dev/shm/"
    "/dev/shm/."
    "/.*/\\."  # hidden directories
)

# Suspicious process names
SUSPICIOUS_NAMES=(
    "nc"
    "ncat"
    "netcat"
    "socat"
    "curl"
    "wget"
    "python"
    "python2"
    "python3"
    "perl"
    "ruby"
    "php"
    "telnet"
)

# Suspicious cmdline patterns
SUSPICIOUS_CMDLINE_PATTERNS=(
    "/dev/tcp/"
    "bash -i"
    "bash -c.*socket"
    "base64.*-d"
    "base64.*--decode"
    "| bash"
    "| sh"
    "eval("
    "exec("
    "-e /bin/sh"
    "-e /bin/bash"
    "mkfifo"
    "nc.*-e"
    "ncat.*-e"
)

# Check for suspicious indicators
check_suspicious() {
    local name="$1"
    local exe="$2"
    local cmdline="$3"
    local indicators=()

    # Check paths
    for pattern in "${SUSPICIOUS_PATHS[@]}"; do
        if [[ "$exe" =~ $pattern ]]; then
            indicators+=("Suspicious path: $pattern")
            break
        fi
    done

    # Check process names
    local name_lower="${name,,}"
    for s_name in "${SUSPICIOUS_NAMES[@]}"; do
        if [[ "$name_lower" == "$s_name" ]]; then
            indicators+=("Network/scripting tool: $name")
            break
        fi
    done

    # Check cmdline patterns
    for pattern in "${SUSPICIOUS_CMDLINE_PATTERNS[@]}"; do
        if [[ "$cmdline" =~ $pattern ]]; then
            indicators+=("Suspicious cmdline pattern: $pattern")
            break
        fi
    done

    # Check for network connections
    local pid="$4"
    if [[ -d "/proc/$pid/fd" ]]; then
        local socket_count
        socket_count=$(ls -la "/proc/$pid/fd" 2>/dev/null | grep -c "socket:" || echo "0")
        if [[ "$socket_count" -gt 0 ]]; then
            indicators+=("Has $socket_count network socket(s)")
        fi
    fi

    # Check for deleted executable
    if [[ "$exe" =~ \(deleted\)$ ]]; then
        indicators+=("Executable has been deleted")
    fi

    # Return indicators
    printf '%s\n' "${indicators[@]}"
}

# Get detailed process info
get_process_details() {
    local pid="$1"
    local proc_dir="/proc/$pid"

    [[ ! -d "$proc_dir" ]] && return 1

    # Get basic info from /proc/[pid]/status
    local name="" ppid="" uid="" state="" threads=""
    if [[ -r "$proc_dir/status" ]]; then
        name=$(grep -m1 "^Name:" "$proc_dir/status" 2>/dev/null | awk '{print $2}')
        ppid=$(grep -m1 "^PPid:" "$proc_dir/status" 2>/dev/null | awk '{print $2}')
        uid=$(grep -m1 "^Uid:" "$proc_dir/status" 2>/dev/null | awk '{print $2}')
        state=$(grep -m1 "^State:" "$proc_dir/status" 2>/dev/null | cut -f2)
        threads=$(grep -m1 "^Threads:" "$proc_dir/status" 2>/dev/null | awk '{print $2}')
    fi

    # Get username
    local username
    username=$(getent passwd "$uid" 2>/dev/null | cut -d: -f1)
    [[ -z "$username" ]] && username="$uid"

    # Get exe
    local exe=""
    [[ -L "$proc_dir/exe" ]] && exe=$(readlink -f "$proc_dir/exe" 2>/dev/null)

    # Get cmdline
    local cmdline=""
    [[ -r "$proc_dir/cmdline" ]] && cmdline=$(tr '\0' ' ' < "$proc_dir/cmdline" 2>/dev/null | head -c 500)

    # Get cwd
    local cwd=""
    [[ -L "$proc_dir/cwd" ]] && cwd=$(readlink -f "$proc_dir/cwd" 2>/dev/null)

    # Get create time
    local create_time=""
    local start_time
    start_time=$(stat -c %Y "$proc_dir" 2>/dev/null)
    [[ -n "$start_time" ]] && create_time=$(date -d "@$start_time" "+%Y-%m-%d %H:%M:%S" 2>/dev/null)

    # Get memory/CPU (from ps)
    local cpu_mem
    cpu_mem=$(ps -p "$pid" -o %cpu,%mem --no-headers 2>/dev/null)
    local cpu_percent mem_percent
    read -r cpu_percent mem_percent <<< "$cpu_mem"

    # Get hash if exe exists
    local exe_hash="N/A"
    if [[ -f "$exe" && -r "$exe" && ! "$exe" =~ \(deleted\)$ ]]; then
        exe_hash=$(sha256sum "$exe" 2>/dev/null | cut -d' ' -f1 | head -c 16)...
    fi

    # Get network connections
    local connections=""
    if [[ -d "$proc_dir/fd" ]]; then
        while IFS= read -r line; do
            if [[ "$line" =~ socket:\[([0-9]+)\] ]]; then
                local inode="${BASH_REMATCH[1]}"
                local conn
                conn=$(grep -h "$inode" /proc/net/tcp /proc/net/tcp6 2>/dev/null | head -1)
                if [[ -n "$conn" ]]; then
                    connections+="  socket:$inode "
                fi
            fi
        done < <(ls -la "$proc_dir/fd" 2>/dev/null | grep socket)
    fi

    # Check suspicious indicators
    local -a indicators
    while IFS= read -r ind; do
        [[ -n "$ind" ]] && indicators+=("$ind")
    done < <(check_suspicious "$name" "$exe" "$cmdline" "$pid")

    local has_indicators="false"
    [[ ${#indicators[@]} -gt 0 ]] && has_indicators="true"

    # Print details
    local marker="${GREEN}[*]${NC}"
    [[ "$has_indicators" == "true" ]] && marker="${RED}[!]${NC}"

    echo -e "\n$marker ${BOLD}════════════════════════════════════════════════════${NC}"
    echo -e "  ${CYAN}PID:${NC}         $pid"
    echo -e "  ${CYAN}Name:${NC}        $name"
    echo -e "  ${CYAN}PPID:${NC}        $ppid"
    echo -e "  ${CYAN}User:${NC}        $username"
    echo -e "  ${CYAN}State:${NC}       $state"
    echo -e "  ${CYAN}Exe:${NC}         $exe"
    echo -e "  ${CYAN}Cmdline:${NC}     ${cmdline:0:100}"
    [[ ${#cmdline} -gt 100 ]] && echo -e "               ${cmdline:100:100}..."
    echo -e "  ${CYAN}CWD:${NC}         $cwd"
    echo -e "  ${CYAN}Started:${NC}     $create_time"
    echo -e "  ${CYAN}CPU%:${NC}        ${cpu_percent:-N/A}"
    echo -e "  ${CYAN}MEM%:${NC}        ${mem_percent:-N/A}"
    echo -e "  ${CYAN}Threads:${NC}     ${threads:-N/A}"
    echo -e "  ${CYAN}Hash:${NC}        $exe_hash"

    if [[ -n "$connections" ]]; then
        echo -e "  ${CYAN}Sockets:${NC}    $connections"
    fi

    if [[ "$has_indicators" == "true" ]]; then
        echo -e "  ${RED}SUSPICIOUS:${NC}"
        for ind in "${indicators[@]}"; do
            echo -e "    ${RED}! $ind${NC}"
        done
    fi

    # Return for JSON output
    echo "JSON:$pid|$name|$exe|$cmdline|$username|$has_indicators"
}

# Search processes
search_processes() {
    local pattern="$1"
    local search_cmdline="$2"
    local results=()

    print_info "Searching for pattern: $pattern"
    [[ "$search_cmdline" == "true" ]] && print_info "Searching in cmdline as well"

    for pid_dir in /proc/[0-9]*; do
        local pid
        pid=$(basename "$pid_dir")
        [[ ! -d "$pid_dir" ]] && continue

        local name=""
        [[ -r "$pid_dir/status" ]] && name=$(grep -m1 "^Name:" "$pid_dir/status" 2>/dev/null | awk '{print $2}')
        [[ -z "$name" ]] && continue

        local cmdline=""
        [[ -r "$pid_dir/cmdline" ]] && cmdline=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null)

        local match="false"

        # Match against name
        if echo "$name" | grep -qiE "$pattern" 2>/dev/null; then
            match="true"
        fi

        # Match against cmdline if enabled
        if [[ "$search_cmdline" == "true" && "$match" == "false" ]]; then
            if echo "$cmdline" | grep -qiE "$pattern" 2>/dev/null; then
                match="true"
            fi
        fi

        if [[ "$match" == "true" ]]; then
            results+=("$pid")
        fi
    done

    echo "${results[@]}"
}

# Interactive kill mode
interactive_kill() {
    local pids=("$@")

    echo ""
    print_warning "Kill mode enabled"
    echo -e "${YELLOW}Enter PID to kill, 'all' to kill all, or 'q' to quit${NC}"

    while true; do
        echo -ne "${CYAN}> ${NC}"
        read -r choice

        case "$choice" in
            q|quit|exit)
                print_info "Exiting kill mode"
                break
                ;;
            all)
                echo -ne "${RED}Kill ALL ${#pids[@]} processes? Type 'yes' to confirm: ${NC}"
                read -r confirm
                if [[ "$confirm" == "yes" ]]; then
                    for pid in "${pids[@]}"; do
                        if kill -9 "$pid" 2>/dev/null; then
                            print_success "Killed PID $pid"
                        else
                            print_error "Failed to kill PID $pid"
                        fi
                    done
                else
                    print_info "Cancelled"
                fi
                break
                ;;
            *)
                if [[ "$choice" =~ ^[0-9]+$ ]]; then
                    local found="false"
                    for pid in "${pids[@]}"; do
                        if [[ "$pid" == "$choice" ]]; then
                            found="true"
                            break
                        fi
                    done

                    if [[ "$found" == "true" ]]; then
                        echo -ne "Signal (15=TERM, 9=KILL) [15]: "
                        read -r sig
                        [[ -z "$sig" ]] && sig=15

                        if kill "-$sig" "$choice" 2>/dev/null; then
                            print_success "Sent signal $sig to PID $choice"
                        else
                            print_error "Failed to kill PID $choice"
                        fi
                    else
                        print_warning "PID $choice not in search results"
                    fi
                else
                    print_error "Invalid input"
                fi
                ;;
        esac
    done
}

# Save results to JSON
save_results() {
    local output_file="$1"
    shift
    local results=("$@")

    echo "{" > "$output_file"
    echo "  \"timestamp\": \"$(date -Iseconds)\"," >> "$output_file"
    echo "  \"hostname\": \"$(hostname)\"," >> "$output_file"
    echo "  \"results\": [" >> "$output_file"

    local first=true
    for result in "${results[@]}"; do
        # Parse JSON line from get_process_details
        if [[ "$result" =~ ^JSON: ]]; then
            local data="${result#JSON:}"
            IFS='|' read -r pid name exe cmdline username suspicious <<< "$data"

            if [[ "$first" == "true" ]]; then
                first=false
            else
                echo "," >> "$output_file"
            fi

            # Escape special chars
            cmdline=$(echo "$cmdline" | sed 's/"/\\"/g' | head -c 200)

            echo -n "    {\"pid\":$pid,\"name\":\"$name\",\"exe\":\"$exe\",\"cmdline\":\"$cmdline\",\"username\":\"$username\",\"suspicious\":$suspicious}" >> "$output_file"
        fi
    done

    echo "" >> "$output_file"
    echo "  ]" >> "$output_file"
    echo "}" >> "$output_file"

    print_success "Results saved to: $output_file"
}

# Usage
usage() {
    echo "Process Hunter - Pure Bash"
    echo ""
    echo "Usage: $0 <pattern> [options]"
    echo ""
    echo "Arguments:"
    echo "  pattern              Regex pattern to search (required)"
    echo ""
    echo "Options:"
    echo "  -c, --cmdline        Also search in command line"
    echo "  -k, --kill           Enable interactive kill mode"
    echo "  -o, --output FILE    Save results to JSON file"
    echo "  -h, --help           Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 'nc|netcat'                   # Find netcat processes"
    echo "  $0 'python.*socket' -c           # Find python with socket in cmdline"
    echo "  $0 'suspicious' -k               # Find and optionally kill"
    echo "  $0 'miner' -c -o results.json    # Save results to file"
    echo ""
    echo "Suspicious indicators detected:"
    echo "  - Executables in /tmp, /dev/shm, /var/tmp"
    echo "  - Network tools: nc, netcat, socat, curl, wget"
    echo "  - Scripting: python, perl, ruby, php"
    echo "  - Reverse shell patterns: /dev/tcp, bash -i, base64 decode"
    echo "  - Deleted executables"
    echo "  - Active network sockets"
}

# Main
main() {
    if [[ $# -lt 1 ]]; then
        usage
        exit 1
    fi

    local pattern=""
    local search_cmdline="false"
    local kill_mode="false"
    local output_file=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -c|--cmdline)
                search_cmdline="true"
                shift
                ;;
            -k|--kill)
                kill_mode="true"
                shift
                ;;
            -o|--output)
                output_file="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            -*)
                print_error "Unknown option: $1"
                exit 1
                ;;
            *)
                if [[ -z "$pattern" ]]; then
                    pattern="$1"
                else
                    print_error "Multiple patterns not supported"
                    exit 1
                fi
                shift
                ;;
        esac
    done

    if [[ -z "$pattern" ]]; then
        print_error "Pattern required"
        usage
        exit 1
    fi

    # Validate regex
    if ! echo "test" | grep -qE "$pattern" 2>/dev/null; then
        # Try anyway, might just not match
        true
    fi

    print_header "Process Hunter - Searching: $pattern"

    # Search
    local pids
    read -ra pids <<< "$(search_processes "$pattern" "$search_cmdline")"

    if [[ ${#pids[@]} -eq 0 ]]; then
        print_info "No matching processes found"
        exit 0
    fi

    print_success "Found ${#pids[@]} matching process(es)"

    # Display details and collect JSON data
    local json_results=()
    local suspicious_count=0

    for pid in "${pids[@]}"; do
        local output
        output=$(get_process_details "$pid" 2>/dev/null)

        if [[ -n "$output" ]]; then
            # Print the visual output (non-JSON lines)
            echo "$output" | grep -v "^JSON:"

            # Capture JSON line
            local json_line
            json_line=$(echo "$output" | grep "^JSON:")
            [[ -n "$json_line" ]] && json_results+=("$json_line")

            # Count suspicious
            local re_suspicious='"suspicious":true'
            if [[ "$json_line" =~ $re_suspicious ]]; then
                ((suspicious_count++)) || true
            fi
        fi
    done

    # Summary
    echo ""
    print_header "Summary"
    print_info "Total matches: ${#pids[@]}"
    if [[ $suspicious_count -gt 0 ]]; then
        echo -e "${RED}[!] Suspicious processes: $suspicious_count${NC}"
    fi

    # Save to file
    if [[ -n "$output_file" ]]; then
        save_results "$output_file" "${json_results[@]}"
    fi

    # Kill mode
    if [[ "$kill_mode" == "true" ]]; then
        interactive_kill "${pids[@]}"
    fi
}

main "$@"
