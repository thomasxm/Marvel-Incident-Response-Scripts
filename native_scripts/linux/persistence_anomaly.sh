#!/bin/bash
#
# Persistence Anomaly Detection - Pure Bash Implementation
# Author: Medjed
# Monitors persistence mechanisms: cron, systemd, shell configs, SSH keys, etc.
#
# Usage:
#   ./persistence_anomaly.sh baseline -o baseline.json
#   ./persistence_anomaly.sh scan -b baseline.json -o results.json
#   ./persistence_anomaly.sh show -f results.json
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

# Global variables
SCAN_LEVEL=2
SELECTED_CATEGORIES=()

# Category definitions with MITRE ATT&CK mappings
# Format: "level:mitre_id:description"
declare -A CATEGORY_INFO=(
    ["cron"]="1:T1053.003:Cron Jobs"
    ["systemd-services"]="1:T1543.002:Systemd Services"
    ["shell-rc"]="1:T1546.004:Shell Configuration"
    ["ssh-keys"]="1:T1098.004:SSH Authorized Keys"
    ["systemd-timers"]="2:T1053.006:Systemd Timers"
    ["at-jobs"]="2:T1053.002:At Jobs"
    ["init-scripts"]="2:T1037.004:Init Scripts"
    ["xdg-autostart"]="2:T1547.013:XDG Autostart"
    ["ld-preload"]="3:T1574.006:LD_PRELOAD Hijacking"
    ["kernel-modules"]="3:T1547.006:Kernel Modules"
    ["udev-rules"]="3:T1546.012:Udev Rules"
    ["motd-scripts"]="3:T1546:MOTD Scripts"
)

# Get categories for a given level (includes all lower levels)
get_categories_for_level() {
    local level="$1"
    local categories=()
    for cat in "${!CATEGORY_INFO[@]}"; do
        local cat_level="${CATEGORY_INFO[$cat]%%:*}"
        if [[ "$cat_level" -le "$level" ]]; then
            categories+=("$cat")
        fi
    done
    echo "${categories[@]}"
}

# Get MITRE technique for category
get_mitre_technique() {
    local category="$1"
    local info="${CATEGORY_INFO[$category]:-}"
    if [[ -n "$info" ]]; then
        echo "$info" | cut -d: -f2
    else
        echo "Unknown"
    fi
}

# Get category description
get_category_description() {
    local category="$1"
    local info="${CATEGORY_INFO[$category]:-}"
    if [[ -n "$info" ]]; then
        echo "$info" | cut -d: -f3
    else
        echo "$category"
    fi
}

# Suspicious patterns for risk detection
SUSPICIOUS_PATHS=(
    "/tmp/"
    "/dev/shm/"
    "/var/tmp/"
    "/run/user/"
)

NETWORK_COMMANDS=(
    "curl" "wget" "nc" "ncat" "netcat" "socat"
    "/dev/tcp/" "/dev/udp/"
    "python -c" "python3 -c" "perl -e" "ruby -e"
)

ENCODED_PATTERNS=(
    "base64" "eval" "exec("
)

# Check if content contains suspicious indicators
detect_risk_indicators() {
    local content="$1"
    local filepath="$2"
    local mtime="${3:-0}"
    local indicators=()

    # Check suspicious paths
    for pattern in "${SUSPICIOUS_PATHS[@]}"; do
        if [[ "$content" == *"$pattern"* ]] || [[ "$filepath" == *"$pattern"* ]]; then
            indicators+=("Suspicious path: $pattern")
            break
        fi
    done

    # Check network commands
    for cmd in "${NETWORK_COMMANDS[@]}"; do
        if [[ "$content" == *"$cmd"* ]]; then
            indicators+=("Network command: $cmd")
            break
        fi
    done

    # Check for piped shell execution
    if [[ "$content" =~ \|[[:space:]]*(ba)?sh ]] || [[ "$content" =~ \|[[:space:]]*bash ]]; then
        indicators+=("Piped to shell execution")
    fi

    # Check encoded/obfuscated content
    for pattern in "${ENCODED_PATTERNS[@]}"; do
        if [[ "$content" == *"$pattern"* ]]; then
            indicators+=("Encoded/obfuscated content")
            break
        fi
    done

    # Check if recently modified (within 24 hours)
    if [[ "$mtime" -gt 0 ]]; then
        local now
        now=$(date +%s)
        local age=$((now - mtime))
        if [[ "$age" -lt 86400 ]]; then
            indicators+=("Modified within last 24 hours")
        fi
    fi

    # Check for hidden files (excluding standard shell configs)
    local filename
    filename=$(basename "$filepath")
    if [[ "$filename" == .* ]] && [[ "$filename" != ".bashrc" ]] && [[ "$filename" != ".profile" ]] && [[ "$filename" != ".bash_profile" ]] && [[ "$filename" != ".zshrc" ]] && [[ "$filename" != ".zprofile" ]]; then
        indicators+=("Hidden file")
    fi

    # Return indicators
    printf '%s\n' "${indicators[@]}"
}

# Calculate risk score based on indicators
calculate_risk_score() {
    local -a indicators=("$@")
    local count=${#indicators[@]}

    # Handle empty array
    [[ $count -eq 0 ]] && echo "LOW" && return

    # Check for critical combinations
    local has_network=false
    local has_shell_pipe=false
    local has_temp_path=false

    for ind in "${indicators[@]}"; do
        [[ "$ind" == *"Network command"* ]] && has_network=true
        [[ "$ind" == *"Piped to shell"* ]] && has_shell_pipe=true
        [[ "$ind" == *"Suspicious path"* ]] && has_temp_path=true
    done

    # Critical: network + shell pipe, or temp path execution, or 3+ indicators
    if { [[ "$has_network" == "true" ]] && [[ "$has_shell_pipe" == "true" ]]; } || \
       { [[ "$has_temp_path" == "true" ]] && [[ "$has_network" == "true" ]]; } || \
       [[ "$count" -ge 3 ]]; then
        echo "CRITICAL"
    elif [[ "$count" -ge 2 ]]; then
        echo "HIGH"
    elif [[ "$count" -ge 1 ]]; then
        echo "MEDIUM"
    else
        echo "LOW"
    fi
}

# Compute SHA256 hash of file content
compute_hash() {
    local filepath="$1"
    if [[ -f "$filepath" && -r "$filepath" ]]; then
        sha256sum "$filepath" 2>/dev/null | cut -d' ' -f1
    else
        echo "null"
    fi
}

# Escape string for JSON
escape_json() {
    local str="$1"
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    str="${str//$'\n'/ }"
    str="${str//$'\r'/}"
    str="${str//$'\t'/ }"
    echo "$str"
}

# Scan cron jobs
scan_cron() {
    local mitre
    mitre=$(get_mitre_technique "cron")

    # System crontab
    if [[ -f "/etc/crontab" ]]; then
        local hash owner perms mtime content_preview
        hash=$(compute_hash "/etc/crontab")
        owner=$(stat -c %U "/etc/crontab" 2>/dev/null || echo "unknown")
        perms=$(stat -c %a "/etc/crontab" 2>/dev/null || echo "000")
        mtime=$(stat -c %Y "/etc/crontab" 2>/dev/null || echo "0")
        content_preview=$(escape_json "$(head -c 200 "/etc/crontab" 2>/dev/null | tr '\n' ' ')")
        echo "{\"category\":\"cron\",\"path\":\"/etc/crontab\",\"content_hash\":\"$hash\",\"owner\":\"$owner\",\"permissions\":\"$perms\",\"mtime\":$mtime,\"mitre_technique\":\"$mitre\",\"command_preview\":\"$content_preview\"}"
    fi

    # /etc/cron.d/
    if [[ -d "/etc/cron.d" ]]; then
        for f in /etc/cron.d/*; do
            [[ -f "$f" ]] || continue
            local hash owner perms mtime content_preview
            hash=$(compute_hash "$f")
            owner=$(stat -c %U "$f" 2>/dev/null || echo "unknown")
            perms=$(stat -c %a "$f" 2>/dev/null || echo "000")
            mtime=$(stat -c %Y "$f" 2>/dev/null || echo "0")
            content_preview=$(escape_json "$(head -c 200 "$f" 2>/dev/null | tr '\n' ' ')")
            echo "{\"category\":\"cron\",\"path\":\"$f\",\"content_hash\":\"$hash\",\"owner\":\"$owner\",\"permissions\":\"$perms\",\"mtime\":$mtime,\"mitre_technique\":\"$mitre\",\"command_preview\":\"$content_preview\"}"
        done
    fi

    # /etc/cron.{hourly,daily,weekly,monthly}/
    for period in hourly daily weekly monthly; do
        local dir="/etc/cron.$period"
        [[ -d "$dir" ]] || continue
        for f in "$dir"/*; do
            [[ -f "$f" ]] || continue
            local hash owner perms mtime content_preview
            hash=$(compute_hash "$f")
            owner=$(stat -c %U "$f" 2>/dev/null || echo "unknown")
            perms=$(stat -c %a "$f" 2>/dev/null || echo "000")
            mtime=$(stat -c %Y "$f" 2>/dev/null || echo "0")
            content_preview=$(escape_json "$(head -c 200 "$f" 2>/dev/null | tr '\n' ' ')")
            echo "{\"category\":\"cron\",\"path\":\"$f\",\"content_hash\":\"$hash\",\"owner\":\"$owner\",\"permissions\":\"$perms\",\"mtime\":$mtime,\"mitre_technique\":\"$mitre\",\"command_preview\":\"$content_preview\"}"
        done
    done

    # User crontabs
    for crontab_dir in /var/spool/cron/crontabs /var/spool/cron; do
        [[ -d "$crontab_dir" ]] || continue
        for f in "$crontab_dir"/*; do
            [[ -f "$f" ]] || continue
            local hash owner perms mtime content_preview
            hash=$(compute_hash "$f")
            owner=$(stat -c %U "$f" 2>/dev/null || echo "unknown")
            perms=$(stat -c %a "$f" 2>/dev/null || echo "000")
            mtime=$(stat -c %Y "$f" 2>/dev/null || echo "0")
            content_preview=$(escape_json "$(head -c 200 "$f" 2>/dev/null | tr '\n' ' ')")
            echo "{\"category\":\"cron\",\"path\":\"$f\",\"content_hash\":\"$hash\",\"owner\":\"$owner\",\"permissions\":\"$perms\",\"mtime\":$mtime,\"mitre_technique\":\"$mitre\",\"command_preview\":\"$content_preview\"}"
        done
    done
}

# Scan systemd services
scan_systemd_services() {
    local mitre
    mitre=$(get_mitre_technique "systemd-services")

    # System service directories
    for dir in /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system; do
        [[ -d "$dir" ]] || continue
        for f in "$dir"/*.service; do
            [[ -f "$f" ]] || continue
            local hash owner perms mtime content_preview
            hash=$(compute_hash "$f")
            owner=$(stat -c %U "$f" 2>/dev/null || echo "unknown")
            perms=$(stat -c %a "$f" 2>/dev/null || echo "000")
            mtime=$(stat -c %Y "$f" 2>/dev/null || echo "0")
            content_preview=$(escape_json "$(grep -E "^(ExecStart|ExecStartPre|ExecStartPost)=" "$f" 2>/dev/null | head -1 | cut -c1-200)")
            echo "{\"category\":\"systemd-services\",\"path\":\"$f\",\"content_hash\":\"$hash\",\"owner\":\"$owner\",\"permissions\":\"$perms\",\"mtime\":$mtime,\"mitre_technique\":\"$mitre\",\"command_preview\":\"$content_preview\"}"
        done
    done

    # User services
    for home in /home/* /root; do
        local user_dir="$home/.config/systemd/user"
        [[ -d "$user_dir" ]] || continue
        for f in "$user_dir"/*.service; do
            [[ -f "$f" ]] || continue
            local hash owner perms mtime content_preview
            hash=$(compute_hash "$f")
            owner=$(stat -c %U "$f" 2>/dev/null || echo "unknown")
            perms=$(stat -c %a "$f" 2>/dev/null || echo "000")
            mtime=$(stat -c %Y "$f" 2>/dev/null || echo "0")
            content_preview=$(escape_json "$(grep -E "^(ExecStart|ExecStartPre|ExecStartPost)=" "$f" 2>/dev/null | head -1 | cut -c1-200)")
            echo "{\"category\":\"systemd-services\",\"path\":\"$f\",\"content_hash\":\"$hash\",\"owner\":\"$owner\",\"permissions\":\"$perms\",\"mtime\":$mtime,\"mitre_technique\":\"$mitre\",\"command_preview\":\"$content_preview\"}"
        done
    done
}

# Scan systemd timers
scan_systemd_timers() {
    local mitre
    mitre=$(get_mitre_technique "systemd-timers")

    for dir in /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system; do
        [[ -d "$dir" ]] || continue
        for f in "$dir"/*.timer; do
            [[ -f "$f" ]] || continue
            local hash owner perms mtime content_preview
            hash=$(compute_hash "$f")
            owner=$(stat -c %U "$f" 2>/dev/null || echo "unknown")
            perms=$(stat -c %a "$f" 2>/dev/null || echo "000")
            mtime=$(stat -c %Y "$f" 2>/dev/null || echo "0")
            content_preview=$(escape_json "$(grep -E "^(OnCalendar|OnBootSec|OnUnitActiveSec)=" "$f" 2>/dev/null | head -1 | cut -c1-200)")
            echo "{\"category\":\"systemd-timers\",\"path\":\"$f\",\"content_hash\":\"$hash\",\"owner\":\"$owner\",\"permissions\":\"$perms\",\"mtime\":$mtime,\"mitre_technique\":\"$mitre\",\"command_preview\":\"$content_preview\"}"
        done
    done
}

# Scan shell configuration files
scan_shell_rc() {
    local mitre
    mitre=$(get_mitre_technique "shell-rc")

    # System-wide
    for f in /etc/profile /etc/bash.bashrc /etc/bashrc /etc/zsh/zshrc; do
        [[ -f "$f" ]] || continue
        local hash owner perms mtime content_preview
        hash=$(compute_hash "$f")
        owner=$(stat -c %U "$f" 2>/dev/null || echo "unknown")
        perms=$(stat -c %a "$f" 2>/dev/null || echo "000")
        mtime=$(stat -c %Y "$f" 2>/dev/null || echo "0")
        content_preview=$(escape_json "$(head -c 200 "$f" 2>/dev/null | tr '\n' ' ')")
        echo "{\"category\":\"shell-rc\",\"path\":\"$f\",\"content_hash\":\"$hash\",\"owner\":\"$owner\",\"permissions\":\"$perms\",\"mtime\":$mtime,\"mitre_technique\":\"$mitre\",\"command_preview\":\"$content_preview\"}"
    done

    # /etc/profile.d/
    if [[ -d "/etc/profile.d" ]]; then
        for f in /etc/profile.d/*; do
            [[ -f "$f" ]] || continue
            local hash owner perms mtime content_preview
            hash=$(compute_hash "$f")
            owner=$(stat -c %U "$f" 2>/dev/null || echo "unknown")
            perms=$(stat -c %a "$f" 2>/dev/null || echo "000")
            mtime=$(stat -c %Y "$f" 2>/dev/null || echo "0")
            content_preview=$(escape_json "$(head -c 200 "$f" 2>/dev/null | tr '\n' ' ')")
            echo "{\"category\":\"shell-rc\",\"path\":\"$f\",\"content_hash\":\"$hash\",\"owner\":\"$owner\",\"permissions\":\"$perms\",\"mtime\":$mtime,\"mitre_technique\":\"$mitre\",\"command_preview\":\"$content_preview\"}"
        done
    fi

    # User shell configs
    for home in /home/* /root; do
        [[ -d "$home" ]] || continue
        for rc in .bashrc .bash_profile .profile .zshrc .zprofile; do
            local f="$home/$rc"
            [[ -f "$f" ]] || continue
            local hash owner perms mtime content_preview
            hash=$(compute_hash "$f")
            owner=$(stat -c %U "$f" 2>/dev/null || echo "unknown")
            perms=$(stat -c %a "$f" 2>/dev/null || echo "000")
            mtime=$(stat -c %Y "$f" 2>/dev/null || echo "0")
            content_preview=$(escape_json "$(head -c 200 "$f" 2>/dev/null | tr '\n' ' ')")
            echo "{\"category\":\"shell-rc\",\"path\":\"$f\",\"content_hash\":\"$hash\",\"owner\":\"$owner\",\"permissions\":\"$perms\",\"mtime\":$mtime,\"mitre_technique\":\"$mitre\",\"command_preview\":\"$content_preview\"}"
        done
    done
}

# Scan SSH authorized_keys
scan_ssh_keys() {
    local mitre
    mitre=$(get_mitre_technique "ssh-keys")

    for home in /home/* /root; do
        local f="$home/.ssh/authorized_keys"
        [[ -f "$f" ]] || continue
        local hash owner perms mtime content_preview key_count
        hash=$(compute_hash "$f")
        owner=$(stat -c %U "$f" 2>/dev/null || echo "unknown")
        perms=$(stat -c %a "$f" 2>/dev/null || echo "000")
        mtime=$(stat -c %Y "$f" 2>/dev/null || echo "0")
        key_count=$(grep -c "^ssh-" "$f" 2>/dev/null || echo "0")
        content_preview="$key_count SSH keys"
        echo "{\"category\":\"ssh-keys\",\"path\":\"$f\",\"content_hash\":\"$hash\",\"owner\":\"$owner\",\"permissions\":\"$perms\",\"mtime\":$mtime,\"mitre_technique\":\"$mitre\",\"command_preview\":\"$content_preview\"}"
    done
}

# Scan at jobs
scan_at_jobs() {
    local mitre
    mitre=$(get_mitre_technique "at-jobs")

    for dir in /var/spool/at /var/spool/atjobs; do
        [[ -d "$dir" ]] || continue
        for f in "$dir"/*; do
            [[ -f "$f" ]] || continue
            [[ "$(basename "$f")" == ".SEQ" ]] && continue
            local hash owner perms mtime content_preview
            hash=$(compute_hash "$f")
            owner=$(stat -c %U "$f" 2>/dev/null || echo "unknown")
            perms=$(stat -c %a "$f" 2>/dev/null || echo "000")
            mtime=$(stat -c %Y "$f" 2>/dev/null || echo "0")
            content_preview=$(escape_json "$(head -c 200 "$f" 2>/dev/null | tr '\n' ' ')")
            echo "{\"category\":\"at-jobs\",\"path\":\"$f\",\"content_hash\":\"$hash\",\"owner\":\"$owner\",\"permissions\":\"$perms\",\"mtime\":$mtime,\"mitre_technique\":\"$mitre\",\"command_preview\":\"$content_preview\"}"
        done
    done
}

# Scan init scripts
scan_init_scripts() {
    local mitre
    mitre=$(get_mitre_technique "init-scripts")

    # /etc/init.d/
    if [[ -d "/etc/init.d" ]]; then
        for f in /etc/init.d/*; do
            [[ -f "$f" ]] || continue
            local hash owner perms mtime content_preview
            hash=$(compute_hash "$f")
            owner=$(stat -c %U "$f" 2>/dev/null || echo "unknown")
            perms=$(stat -c %a "$f" 2>/dev/null || echo "000")
            mtime=$(stat -c %Y "$f" 2>/dev/null || echo "0")
            content_preview=$(escape_json "$(head -c 200 "$f" 2>/dev/null | tr '\n' ' ')")
            echo "{\"category\":\"init-scripts\",\"path\":\"$f\",\"content_hash\":\"$hash\",\"owner\":\"$owner\",\"permissions\":\"$perms\",\"mtime\":$mtime,\"mitre_technique\":\"$mitre\",\"command_preview\":\"$content_preview\"}"
        done
    fi

    # /etc/rc.local
    if [[ -f "/etc/rc.local" ]]; then
        local hash owner perms mtime content_preview
        hash=$(compute_hash "/etc/rc.local")
        owner=$(stat -c %U "/etc/rc.local" 2>/dev/null || echo "unknown")
        perms=$(stat -c %a "/etc/rc.local" 2>/dev/null || echo "000")
        mtime=$(stat -c %Y "/etc/rc.local" 2>/dev/null || echo "0")
        content_preview=$(escape_json "$(head -c 200 "/etc/rc.local" 2>/dev/null | tr '\n' ' ')")
        echo "{\"category\":\"init-scripts\",\"path\":\"/etc/rc.local\",\"content_hash\":\"$hash\",\"owner\":\"$owner\",\"permissions\":\"$perms\",\"mtime\":$mtime,\"mitre_technique\":\"$mitre\",\"command_preview\":\"$content_preview\"}"
    fi
}

# Scan XDG autostart
scan_xdg_autostart() {
    local mitre
    mitre=$(get_mitre_technique "xdg-autostart")

    # System autostart
    if [[ -d "/etc/xdg/autostart" ]]; then
        for f in /etc/xdg/autostart/*.desktop; do
            [[ -f "$f" ]] || continue
            local hash owner perms mtime content_preview
            hash=$(compute_hash "$f")
            owner=$(stat -c %U "$f" 2>/dev/null || echo "unknown")
            perms=$(stat -c %a "$f" 2>/dev/null || echo "000")
            mtime=$(stat -c %Y "$f" 2>/dev/null || echo "0")
            content_preview=$(escape_json "$(grep -E "^Exec=" "$f" 2>/dev/null | head -1 | cut -c1-200)")
            echo "{\"category\":\"xdg-autostart\",\"path\":\"$f\",\"content_hash\":\"$hash\",\"owner\":\"$owner\",\"permissions\":\"$perms\",\"mtime\":$mtime,\"mitre_technique\":\"$mitre\",\"command_preview\":\"$content_preview\"}"
        done
    fi

    # User autostart
    for home in /home/*; do
        local dir="$home/.config/autostart"
        [[ -d "$dir" ]] || continue
        for f in "$dir"/*.desktop; do
            [[ -f "$f" ]] || continue
            local hash owner perms mtime content_preview
            hash=$(compute_hash "$f")
            owner=$(stat -c %U "$f" 2>/dev/null || echo "unknown")
            perms=$(stat -c %a "$f" 2>/dev/null || echo "000")
            mtime=$(stat -c %Y "$f" 2>/dev/null || echo "0")
            content_preview=$(escape_json "$(grep -E "^Exec=" "$f" 2>/dev/null | head -1 | cut -c1-200)")
            echo "{\"category\":\"xdg-autostart\",\"path\":\"$f\",\"content_hash\":\"$hash\",\"owner\":\"$owner\",\"permissions\":\"$perms\",\"mtime\":$mtime,\"mitre_technique\":\"$mitre\",\"command_preview\":\"$content_preview\"}"
        done
    done
}

# Scan ld.so.preload
scan_ld_preload() {
    local mitre
    mitre=$(get_mitre_technique "ld-preload")

    if [[ -f "/etc/ld.so.preload" ]]; then
        local hash owner perms mtime content_preview
        hash=$(compute_hash "/etc/ld.so.preload")
        owner=$(stat -c %U "/etc/ld.so.preload" 2>/dev/null || echo "unknown")
        perms=$(stat -c %a "/etc/ld.so.preload" 2>/dev/null || echo "000")
        mtime=$(stat -c %Y "/etc/ld.so.preload" 2>/dev/null || echo "0")
        content_preview=$(escape_json "$(head -c 200 "/etc/ld.so.preload" 2>/dev/null | tr '\n' ' ')")
        echo "{\"category\":\"ld-preload\",\"path\":\"/etc/ld.so.preload\",\"content_hash\":\"$hash\",\"owner\":\"$owner\",\"permissions\":\"$perms\",\"mtime\":$mtime,\"mitre_technique\":\"$mitre\",\"command_preview\":\"$content_preview\"}"
    fi
}

# Scan kernel modules configuration
scan_kernel_modules() {
    local mitre
    mitre=$(get_mitre_technique "kernel-modules")

    # /etc/modules
    if [[ -f "/etc/modules" ]]; then
        local hash owner perms mtime content_preview
        hash=$(compute_hash "/etc/modules")
        owner=$(stat -c %U "/etc/modules" 2>/dev/null || echo "unknown")
        perms=$(stat -c %a "/etc/modules" 2>/dev/null || echo "000")
        mtime=$(stat -c %Y "/etc/modules" 2>/dev/null || echo "0")
        content_preview=$(escape_json "$(head -c 200 "/etc/modules" 2>/dev/null | tr '\n' ' ')")
        echo "{\"category\":\"kernel-modules\",\"path\":\"/etc/modules\",\"content_hash\":\"$hash\",\"owner\":\"$owner\",\"permissions\":\"$perms\",\"mtime\":$mtime,\"mitre_technique\":\"$mitre\",\"command_preview\":\"$content_preview\"}"
    fi

    # /etc/modules-load.d/
    if [[ -d "/etc/modules-load.d" ]]; then
        for f in /etc/modules-load.d/*.conf; do
            [[ -f "$f" ]] || continue
            local hash owner perms mtime content_preview
            hash=$(compute_hash "$f")
            owner=$(stat -c %U "$f" 2>/dev/null || echo "unknown")
            perms=$(stat -c %a "$f" 2>/dev/null || echo "000")
            mtime=$(stat -c %Y "$f" 2>/dev/null || echo "0")
            content_preview=$(escape_json "$(head -c 200 "$f" 2>/dev/null | tr '\n' ' ')")
            echo "{\"category\":\"kernel-modules\",\"path\":\"$f\",\"content_hash\":\"$hash\",\"owner\":\"$owner\",\"permissions\":\"$perms\",\"mtime\":$mtime,\"mitre_technique\":\"$mitre\",\"command_preview\":\"$content_preview\"}"
        done
    fi
}

# Scan udev rules
scan_udev_rules() {
    local mitre
    mitre=$(get_mitre_technique "udev-rules")

    for dir in /etc/udev/rules.d /lib/udev/rules.d; do
        [[ -d "$dir" ]] || continue
        for f in "$dir"/*.rules; do
            [[ -f "$f" ]] || continue
            local hash owner perms mtime content_preview
            hash=$(compute_hash "$f")
            owner=$(stat -c %U "$f" 2>/dev/null || echo "unknown")
            perms=$(stat -c %a "$f" 2>/dev/null || echo "000")
            mtime=$(stat -c %Y "$f" 2>/dev/null || echo "0")
            content_preview=$(escape_json "$(grep -E "RUN\+?=" "$f" 2>/dev/null | head -1 | cut -c1-200)")
            echo "{\"category\":\"udev-rules\",\"path\":\"$f\",\"content_hash\":\"$hash\",\"owner\":\"$owner\",\"permissions\":\"$perms\",\"mtime\":$mtime,\"mitre_technique\":\"$mitre\",\"command_preview\":\"$content_preview\"}"
        done
    done
}

# Scan MOTD scripts
scan_motd_scripts() {
    local mitre
    mitre=$(get_mitre_technique "motd-scripts")

    if [[ -d "/etc/update-motd.d" ]]; then
        for f in /etc/update-motd.d/*; do
            [[ -f "$f" ]] || continue
            local hash owner perms mtime content_preview
            hash=$(compute_hash "$f")
            owner=$(stat -c %U "$f" 2>/dev/null || echo "unknown")
            perms=$(stat -c %a "$f" 2>/dev/null || echo "000")
            mtime=$(stat -c %Y "$f" 2>/dev/null || echo "0")
            content_preview=$(escape_json "$(head -c 200 "$f" 2>/dev/null | tr '\n' ' ')")
            echo "{\"category\":\"motd-scripts\",\"path\":\"$f\",\"content_hash\":\"$hash\",\"owner\":\"$owner\",\"permissions\":\"$perms\",\"mtime\":$mtime,\"mitre_technique\":\"$mitre\",\"command_preview\":\"$content_preview\"}"
        done
    fi
}

# Main scanning dispatcher
scan_category() {
    local category="$1"
    case "$category" in
        cron) scan_cron ;;
        systemd-services) scan_systemd_services ;;
        systemd-timers) scan_systemd_timers ;;
        shell-rc) scan_shell_rc ;;
        ssh-keys) scan_ssh_keys ;;
        at-jobs) scan_at_jobs ;;
        init-scripts) scan_init_scripts ;;
        xdg-autostart) scan_xdg_autostart ;;
        ld-preload) scan_ld_preload ;;
        kernel-modules) scan_kernel_modules ;;
        udev-rules) scan_udev_rules ;;
        motd-scripts) scan_motd_scripts ;;
        *) print_warning "Unknown category: $category" ;;
    esac
}

# Create baseline
create_baseline() {
    local output_file="$1"

    print_header "Creating Persistence Baseline"

    local hostname timestamp
    hostname=$(hostname)
    timestamp=$(date -Iseconds)

    print_info "Hostname: $hostname"
    print_info "Timestamp: $timestamp"
    print_info "Scan Level: $SCAN_LEVEL"

    # Determine categories to scan
    local -a categories_to_scan
    if [[ ${#SELECTED_CATEGORIES[@]} -gt 0 ]]; then
        categories_to_scan=("${SELECTED_CATEGORIES[@]}")
    else
        IFS=' ' read -ra categories_to_scan <<< "$(get_categories_for_level "$SCAN_LEVEL")"
    fi

    print_info "Categories: ${categories_to_scan[*]}"

    # Build JSON header
    {
        echo "{"
        echo "  \"timestamp\": \"$timestamp\","
        echo "  \"hostname\": \"$hostname\","
        echo "  \"platform\": \"Linux\","
        echo "  \"scan_level\": $SCAN_LEVEL,"
        printf '  "categories_scanned": ['
        local first_cat=true
        for cat in "${categories_to_scan[@]}"; do
            [[ "$first_cat" == "true" ]] && first_cat=false || printf ','
            printf '"%s"' "$cat"
        done
        echo '],'
        echo "  \"entries\": ["
    } > "$output_file"

    local first=true
    local count=0

    for category in "${categories_to_scan[@]}"; do
        print_info "Scanning: $(get_category_description "$category")"

        while IFS= read -r entry; do
            [[ -z "$entry" ]] && continue
            if [[ "$first" == "true" ]]; then
                first=false
            else
                echo "," >> "$output_file"
            fi
            echo -n "    $entry" >> "$output_file"
            ((count++)) || true
        done < <(scan_category "$category")
    done

    {
        echo ""
        echo "  ]"
        echo "}"
    } >> "$output_file"

    echo ""
    print_success "Baseline created: $output_file"
    print_info "Total entries: $count"
}

# Run scan and compare against baseline
run_scan() {
    local baseline_file="$1"
    local output_file="${2:-}"

    print_header "Persistence Anomaly Scan"

    if [[ ! -f "$baseline_file" ]]; then
        print_error "Baseline file not found: $baseline_file"
        exit 1
    fi

    print_info "Loading baseline: $baseline_file"

    # Build associative arrays for baseline
    declare -A baseline_entries=()
    declare -A baseline_hashes=()
    declare -A baseline_categories=()

    local re_path='"path":"([^"]+)"'
    local re_hash='"content_hash":"([^"]+)"'
    local re_category='"category":"([^"]+)"'

    while IFS= read -r line; do
        if [[ "$line" =~ $re_path ]]; then
            local path="${BASH_REMATCH[1]}"
            local hash="" cat=""
            [[ "$line" =~ $re_hash ]] && hash="${BASH_REMATCH[1]}"
            [[ "$line" =~ $re_category ]] && cat="${BASH_REMATCH[1]}"
            baseline_entries["$path"]="$line"
            baseline_hashes["$path"]="$hash"
            baseline_categories["$path"]="$cat"
        fi
    done < "$baseline_file"

    local baseline_count=${#baseline_entries[@]}
    print_info "Baseline entries: $baseline_count"
    print_info "Scan Level: $SCAN_LEVEL"

    # Determine categories to scan
    local -a categories_to_scan
    if [[ ${#SELECTED_CATEGORIES[@]} -gt 0 ]]; then
        categories_to_scan=("${SELECTED_CATEGORIES[@]}")
    else
        IFS=' ' read -ra categories_to_scan <<< "$(get_categories_for_level "$SCAN_LEVEL")"
    fi

    # Track current entries and anomalies
    declare -A current_entries=()
    local -a new_entries_json=()
    local -a modified_entries_json=()
    local -a missing_entries_json=()

    local new_count=0
    local modified_count=0
    local missing_count=0

    echo ""
    print_header "Scanning Current Persistence Mechanisms"

    for category in "${categories_to_scan[@]}"; do
        print_info "Scanning: $(get_category_description "$category")"

        while IFS= read -r entry; do
            [[ -z "$entry" ]] && continue

            local path="" hash="" mtime="0" content=""
            [[ "$entry" =~ $re_path ]] && path="${BASH_REMATCH[1]}"
            [[ "$entry" =~ $re_hash ]] && hash="${BASH_REMATCH[1]}"

            # Extract mtime and command_preview for risk analysis
            local re_mtime='"mtime":([0-9]+)'
            local re_preview='"command_preview":"([^"]*)"'
            [[ "$entry" =~ $re_mtime ]] && mtime="${BASH_REMATCH[1]}"
            [[ "$entry" =~ $re_preview ]] && content="${BASH_REMATCH[1]}"

            current_entries["$path"]=1

            if [[ -z "${baseline_entries[$path]:-}" ]]; then
                # New entry
                ((new_count++)) || true

                # Detect risk indicators
                local -a risk_indicators=()
                while IFS= read -r indicator; do
                    [[ -n "$indicator" ]] && risk_indicators+=("$indicator")
                done < <(detect_risk_indicators "$content" "$path" "$mtime")

                local risk_score
                risk_score=$(calculate_risk_score "${risk_indicators[@]}")

                local mitre
                mitre=$(get_mitre_technique "$category")

                echo ""
                print_new "[$risk_score] $path"
                echo -e "    ${CYAN}Category:${NC}  $category ($(get_category_description "$category"))"
                echo -e "    ${CYAN}MITRE:${NC}     $mitre"
                if [[ -n "$content" ]]; then
                    echo -e "    ${CYAN}Preview:${NC}   ${content:0:80}"
                fi
                for indicator in "${risk_indicators[@]}"; do
                    echo -e "    ${RED}⚠ $indicator${NC}"
                done

                # Build JSON
                local risk_json="[]"
                if [[ ${#risk_indicators[@]} -gt 0 ]]; then
                    risk_json=$(printf ',"%s"' "${risk_indicators[@]}")
                    risk_json="[${risk_json:1}]"
                fi
                new_entries_json+=("{\"anomaly_type\":\"new\",\"entry_type\":\"$category\",\"path\":\"$path\",\"mitre_technique\":\"$mitre\",\"content_hash\":\"$hash\",\"risk_score\":\"$risk_score\",\"risk_indicators\":$risk_json}")

            else
                # Check for modification
                local baseline_hash="${baseline_hashes[$path]}"
                if [[ "$hash" != "null" && "$baseline_hash" != "null" && "$hash" != "$baseline_hash" ]]; then
                    ((modified_count++)) || true

                    local mitre
                    mitre=$(get_mitre_technique "$category")

                    echo ""
                    print_modified "[HIGH] $path"
                    echo -e "    ${CYAN}Category:${NC}      $category"
                    echo -e "    ${CYAN}MITRE:${NC}         $mitre"
                    echo -e "    ${CYAN}Baseline Hash:${NC} $baseline_hash"
                    echo -e "    ${CYAN}Current Hash:${NC}  ${RED}$hash${NC}"

                    modified_entries_json+=("{\"anomaly_type\":\"modified\",\"entry_type\":\"$category\",\"path\":\"$path\",\"mitre_technique\":\"$mitre\",\"baseline_hash\":\"$baseline_hash\",\"current_hash\":\"$hash\",\"risk_score\":\"HIGH\",\"risk_indicators\":[\"Content hash changed\"]}")
                fi
            fi
        done < <(scan_category "$category")
    done

    # Check for missing entries
    echo ""
    print_header "Checking for Missing Entries"

    for path in "${!baseline_entries[@]}"; do
        if [[ -z "${current_entries[$path]:-}" ]]; then
            ((missing_count++)) || true

            local cat="${baseline_categories[$path]:-unknown}"
            local mitre
            mitre=$(get_mitre_technique "$cat")

            print_missing "$path"
            echo -e "    ${CYAN}Was:${NC} $cat ($mitre)"

            missing_entries_json+=("{\"anomaly_type\":\"missing\",\"entry_type\":\"$cat\",\"path\":\"$path\",\"mitre_technique\":\"$mitre\",\"risk_score\":\"MEDIUM\",\"risk_indicators\":[\"Entry no longer exists\"]}")
        fi
    done

    # Summary
    echo ""
    print_header "Scan Summary"

    if [[ $new_count -gt 0 ]]; then
        echo -e "${RED}[!] New entries:      $new_count${NC}"
    else
        echo -e "${GREEN}[+] New entries:      $new_count${NC}"
    fi

    if [[ $modified_count -gt 0 ]]; then
        echo -e "${MAGENTA}[!] Modified entries: $modified_count${NC}"
    else
        echo -e "${GREEN}[+] Modified entries: $modified_count${NC}"
    fi

    if [[ $missing_count -gt 0 ]]; then
        echo -e "${YELLOW}[!] Missing entries:  $missing_count${NC}"
    else
        echo -e "${GREEN}[+] Missing entries:  $missing_count${NC}"
    fi

    local total_anomalies=$((new_count + modified_count + missing_count))
    echo ""
    if [[ $total_anomalies -gt 0 ]]; then
        print_warning "Total anomalies detected: $total_anomalies"
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
            echo "  \"scan_type\": \"persistence_anomaly\","
            echo "  \"timestamp\": \"$timestamp\","
            echo "  \"hostname\": \"$hostname\","
            echo "  \"platform\": \"Linux\","
            echo "  \"baseline_file\": \"$baseline_file\","
            echo "  \"scan_level\": $SCAN_LEVEL,"
            echo "  \"summary\": {"
            echo "    \"new_count\": $new_count,"
            echo "    \"modified_count\": $modified_count,"
            echo "    \"missing_count\": $missing_count,"
            echo "    \"total_anomalies\": $total_anomalies"
            echo "  },"
            echo "  \"anomalies\": ["

            local first=true
            for item in "${new_entries_json[@]}"; do
                if [[ "$first" == "true" ]]; then
                    first=false
                else
                    echo ","
                fi
                echo -n "    $item"
            done
            for item in "${modified_entries_json[@]}"; do
                if [[ "$first" == "true" ]]; then
                    first=false
                else
                    echo ","
                fi
                echo -n "    $item"
            done
            for item in "${missing_entries_json[@]}"; do
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

# Display results in formatted table
show_results() {
    local file="$1"
    local show_all="${2:-false}"
    local show_limit="${3:-5}"

    if [[ ! -f "$file" ]]; then
        print_error "File not found: $file"
        exit 1
    fi

    print_header "Persistence Analysis Report"

    # Detect file type
    local is_scan=false
    grep -q '"scan_type"' "$file" 2>/dev/null && is_scan=true

    # Extract metadata
    local timestamp hostname platform scan_level
    timestamp=$(grep -oP '"timestamp":\s*"[^"]*"' "$file" | head -1 | cut -d'"' -f4)
    hostname=$(grep -oP '"hostname":\s*"[^"]*"' "$file" | head -1 | cut -d'"' -f4)
    platform=$(grep -oP '"platform":\s*"[^"]*"' "$file" | head -1 | cut -d'"' -f4)
    scan_level=$(grep -oP '"scan_level":\s*\d+' "$file" | head -1 | grep -oP '\d+') || scan_level="N/A"

    echo -e "${CYAN}File:${NC}       $file"
    echo -e "${CYAN}Timestamp:${NC}  $timestamp"
    echo -e "${CYAN}Hostname:${NC}   $hostname"
    echo -e "${CYAN}Platform:${NC}   $platform"
    echo -e "${CYAN}Scan Level:${NC} $scan_level"
    echo ""

    if [[ "$is_scan" == "true" ]]; then
        show_scan_results "$file" "$show_all" "$show_limit"
    else
        show_baseline_results "$file" "$show_all" "$show_limit"
    fi
}

show_baseline_results() {
    local file="$1"
    local show_all="${2:-false}"
    local show_limit="${3:-5}"

    print_header "Persistence Baseline Summary"

    local total_count
    total_count=$(/bin/grep -c '"path":' "$file" 2>/dev/null) || total_count=0

    echo -e "${GREEN}Total Entries:${NC} $total_count"
    if [[ "$show_all" == "true" ]]; then
        echo -e "${CYAN}Output Mode:${NC}  Showing all entries"
    else
        echo -e "${CYAN}Output Mode:${NC}  Showing up to $show_limit entries per category (use -a/--all for full output)"
    fi
    echo ""

    # Use Python for reliable JSON parsing and formatting
    python3 << PYEOF
import json
import sys
from datetime import datetime

# Output control from bash
SHOW_ALL = "$show_all" == "true"
SHOW_LIMIT = int("$show_limit") if "$show_limit".isdigit() else 5

# ANSI colors
CYAN = '\033[0;36m'
BLUE = '\033[0;34m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
RED = '\033[0;31m'
WHITE = '\033[1;37m'
NC = '\033[0m'

def print_header(text):
    print(f"\n{CYAN}{'='*60}{NC}")
    print(f"{CYAN}  {text}{NC}")
    print(f"{CYAN}{'='*60}{NC}\n")

def format_time(mtime):
    if mtime:
        try:
            return datetime.fromtimestamp(int(mtime)).strftime('%Y-%m-%d %H:%M:%S')
        except:
            return str(mtime)
    return ""

# MITRE mappings
mitre_map = {
    "cron": "T1053.003", "systemd-services": "T1543.002", "shell-rc": "T1546.004",
    "ssh-keys": "T1098.004", "systemd-timers": "T1053.006", "at-jobs": "T1053.002",
    "init-scripts": "T1037.004", "xdg-autostart": "T1547.013", "ld-preload": "T1574.006",
    "kernel-modules": "T1547.006", "udev-rules": "T1546.012", "motd-scripts": "T1546"
}

desc_map = {
    "cron": "Cron Jobs", "systemd-services": "Systemd Services", "shell-rc": "Shell Configuration",
    "ssh-keys": "SSH Authorized Keys", "systemd-timers": "Systemd Timers", "at-jobs": "At Jobs",
    "init-scripts": "Init Scripts", "xdg-autostart": "XDG Autostart", "ld-preload": "LD_PRELOAD",
    "kernel-modules": "Kernel Modules", "udev-rules": "Udev Rules", "motd-scripts": "MOTD Scripts"
}

try:
    # Use errors='replace' to handle non-UTF-8 bytes
    with open("$file", 'r', encoding='utf-8', errors='replace') as f:
        data = json.load(f)

    # Group entries by category first
    entries_by_cat = {}
    for entry in data.get('entries', []):
        cat = entry.get('category', '')
        if cat:
            if cat not in entries_by_cat:
                entries_by_cat[cat] = []
            entries_by_cat[cat].append(entry)

    # Process each category
    for cat, entries in entries_by_cat.items():
        mitre = mitre_map.get(cat, "Unknown")
        desc = desc_map.get(cat, cat)
        total_in_cat = len(entries)

        print_header(f"{desc} ({cat}) - {mitre} [{total_in_cat} entries]")

        # Apply limit
        display_entries = entries if SHOW_ALL else entries[:SHOW_LIMIT]
        skipped = total_in_cat - len(display_entries)

        cat_count = 0
        for entry in display_entries:
            cat_count += 1
            path = entry.get('path', '')
            owner = entry.get('owner', '')
            perm = entry.get('permissions', '')
            mtime = entry.get('mtime', '')
            preview = entry.get('command_preview', '')
            name = path.split('/')[-1] if path else ''

            # Display based on category
            if cat == 'cron':
                print(f"{WHITE}[{cat_count}]{NC} {CYAN}{name}{NC}")
                print(f"    {BLUE}Path:{NC}     {path}")
                if owner: print(f"    {BLUE}Owner:{NC}    {owner}")
                if perm: print(f"    {BLUE}Perms:{NC}    {perm}")
                if mtime: print(f"    {BLUE}Modified:{NC} {format_time(mtime)}")
                if preview:
                    # Extract cron job lines
                    import re
                    cron_lines = re.findall(r'[0-9*/,-]+\s+[0-9*/,-]+\s+[0-9*/,-]+\s+[0-9*/,-]+\s+[0-9*/,-]+\s+\S+\s+\S.*', preview)
                    if cron_lines:
                        print(f"    {YELLOW}Jobs:{NC}")
                        for line in cron_lines[:3]:
                            print(f"      {GREEN}>{NC} {line[:80]}")
                    else:
                        print(f"    {YELLOW}Content:{NC}  {preview[:100]}")
                print()

            elif cat in ['systemd-services', 'systemd-timers']:
                print(f"{WHITE}[{cat_count}]{NC} {CYAN}{name}{NC}")
                print(f"    {BLUE}Path:{NC}     {path}")
                if owner: print(f"    {BLUE}Owner:{NC}    {owner}")
                if mtime: print(f"    {BLUE}Modified:{NC} {format_time(mtime)}")
                if preview:
                    import re
                    exec_match = re.search(r'ExecStart=(\S+)', preview)
                    desc_match = re.search(r'Description=([^#\n]+)', preview)
                    if desc_match: print(f"    {YELLOW}Description={desc_match.group(1)[:60]}{NC}")
                    if exec_match: print(f"    {YELLOW}ExecStart={exec_match.group(1)}{NC}")
                print()

            elif cat == 'shell-rc':
                print(f"{WHITE}[{cat_count}]{NC} {CYAN}{name}{NC}")
                print(f"    {BLUE}Path:{NC}     {path}")
                if owner: print(f"    {BLUE}Owner:{NC}    {owner}")
                if perm: print(f"    {BLUE}Perms:{NC}    {perm}")
                if mtime: print(f"    {BLUE}Modified:{NC} {format_time(mtime)}")
                if preview: print(f"    {YELLOW}Preview:{NC}  {preview[:100]}...")
                print()

            elif cat == 'ssh-keys':
                print(f"{WHITE}[{cat_count}]{NC} {CYAN}{name}{NC}")
                print(f"    {BLUE}Path:{NC}     {path}")
                if owner: print(f"    {BLUE}Owner:{NC}    {owner}")
                if perm: print(f"    {BLUE}Perms:{NC}    {perm}")
                if mtime: print(f"    {BLUE}Modified:{NC} {format_time(mtime)}")
                if preview:
                    key_count = preview.count('ssh-')
                    print(f"    {YELLOW}Keys:{NC}     {key_count} authorized key(s)")
                    import re
                    key_types = set(re.findall(r'ssh-[a-z0-9-]+', preview))
                    if key_types: print(f"    {YELLOW}Types:{NC}    {' '.join(key_types)}")
                print()

            elif cat == 'init-scripts':
                print(f"{WHITE}[{cat_count}]{NC} {CYAN}{name}{NC}")
                print(f"    {BLUE}Path:{NC}     {path}")
                if owner: print(f"    {BLUE}Owner:{NC}    {owner}")
                if perm: print(f"    {BLUE}Perms:{NC}    {perm}")
                if mtime: print(f"    {BLUE}Modified:{NC} {format_time(mtime)}")
                if preview:
                    import re
                    desc_match = re.search(r'(Short-Description|Description):\s*([^#\n]+)', preview)
                    if desc_match: print(f"    {YELLOW}{desc_match.group(0)[:60]}{NC}")
                print()

            elif cat == 'xdg-autostart':
                app_name = name.replace('.desktop', '') if name.endswith('.desktop') else name
                print(f"{WHITE}[{cat_count}]{NC} {CYAN}{app_name}{NC}")
                print(f"    {BLUE}Path:{NC}     {path}")
                if owner: print(f"    {BLUE}Owner:{NC}    {owner}")
                if preview:
                    import re
                    name_match = re.search(r'Name=([^\n]+)', preview)
                    exec_match = re.search(r'Exec=(\S+)', preview)
                    if name_match: print(f"    {YELLOW}Name={name_match.group(1)}{NC}")
                    if exec_match: print(f"    {YELLOW}Exec={exec_match.group(1)}{NC}")
                print()

            elif cat == 'ld-preload':
                print(f"{WHITE}[{cat_count}]{NC} {RED}{path}{NC} [HIGH RISK]")
                if owner: print(f"    {BLUE}Owner:{NC}    {owner}")
                if perm: print(f"    {BLUE}Perms:{NC}    {perm}")
                if mtime: print(f"    {BLUE}Modified:{NC} {format_time(mtime)}")
                if preview: print(f"    {YELLOW}Libraries:{NC} {preview[:100]}")
                print()

            else:
                # Generic display
                print(f"{WHITE}[{cat_count}]{NC} {CYAN}{name}{NC}")
                print(f"    {BLUE}Path:{NC}     {path}")
                if owner: print(f"    {BLUE}Owner:{NC}    {owner}")
                if perm: print(f"    {BLUE}Perms:{NC}    {perm}")
                if mtime: print(f"    {BLUE}Modified:{NC} {format_time(mtime)}")
                if preview: print(f"    {YELLOW}Preview:{NC}  {preview[:80]}")
                print()

        # Show skipped count after processing entries for this category
        if skipped > 0:
            print(f"    {YELLOW}... and {skipped} more entries in this category (use -a/--all to see all){NC}")
            print()

except Exception as e:
    print(f"Error parsing JSON: {e}", file=sys.stderr)
    sys.exit(1)
PYEOF
}

show_scan_results() {
    local file="$1"
    local show_all="${2:-false}"
    local show_limit="${3:-5}"

    # Extract counts
    local new_count modified_count missing_count total_anomalies
    new_count=$(grep -oP '"new_count":\s*\d+' "$file" | grep -oP '\d+' | head -1) || new_count=0
    modified_count=$(grep -oP '"modified_count":\s*\d+' "$file" | grep -oP '\d+' | head -1) || modified_count=0
    missing_count=$(grep -oP '"missing_count":\s*\d+' "$file" | grep -oP '\d+' | head -1) || missing_count=0
    total_anomalies=$((new_count + modified_count + missing_count))

    print_header "Scan Results Summary"

    # Risk assessment
    local risk_level="LOW" risk_color="$GREEN"
    if [[ $total_anomalies -gt 10 ]]; then
        risk_level="CRITICAL"; risk_color="$RED"
    elif [[ $total_anomalies -gt 5 ]]; then
        risk_level="HIGH"; risk_color="$RED"
    elif [[ $total_anomalies -gt 0 ]]; then
        risk_level="MEDIUM"; risk_color="$YELLOW"
    fi

    echo -e "${CYAN}Risk Level:${NC} ${risk_color}${risk_level}${NC}"
    echo ""

    echo -e "${CYAN}┌────────────────────────────────────┬────────┐${NC}"
    printf "${CYAN}│${NC} %-34s ${CYAN}│${NC} %6s ${CYAN}│${NC}\n" "CATEGORY" "COUNT"
    echo -e "${CYAN}├────────────────────────────────────┼────────┤${NC}"

    if [[ $new_count -gt 0 ]]; then
        printf "${CYAN}│${NC} ${RED}%-34s${NC} ${CYAN}│${NC} ${RED}%6d${NC} ${CYAN}│${NC}\n" "New Entries" "$new_count"
    else
        printf "${CYAN}│${NC} ${GREEN}%-34s${NC} ${CYAN}│${NC} ${GREEN}%6d${NC} ${CYAN}│${NC}\n" "New Entries" "$new_count"
    fi

    if [[ $modified_count -gt 0 ]]; then
        printf "${CYAN}│${NC} ${MAGENTA}%-34s${NC} ${CYAN}│${NC} ${MAGENTA}%6d${NC} ${CYAN}│${NC}\n" "Modified Entries" "$modified_count"
    else
        printf "${CYAN}│${NC} ${GREEN}%-34s${NC} ${CYAN}│${NC} ${GREEN}%6d${NC} ${CYAN}│${NC}\n" "Modified Entries" "$modified_count"
    fi

    if [[ $missing_count -gt 0 ]]; then
        printf "${CYAN}│${NC} ${YELLOW}%-34s${NC} ${CYAN}│${NC} ${YELLOW}%6d${NC} ${CYAN}│${NC}\n" "Missing Entries" "$missing_count"
    else
        printf "${CYAN}│${NC} ${GREEN}%-34s${NC} ${CYAN}│${NC} ${GREEN}%6d${NC} ${CYAN}│${NC}\n" "Missing Entries" "$missing_count"
    fi

    echo -e "${CYAN}├────────────────────────────────────┼────────┤${NC}"
    printf "${CYAN}│${NC} ${risk_color}%-34s${NC} ${CYAN}│${NC} ${risk_color}%6d${NC} ${CYAN}│${NC}\n" "TOTAL ANOMALIES" "$total_anomalies"
    echo -e "${CYAN}└────────────────────────────────────┴────────┘${NC}"

    # Show detailed anomalies if any
    if [[ $total_anomalies -gt 0 ]]; then
        echo ""
        print_header "Anomaly Details"

        if [[ "$show_all" == "true" ]]; then
            echo -e "${CYAN}Output Mode:${NC}  Showing all $total_anomalies anomalies"
        else
            echo -e "${CYAN}Output Mode:${NC}  Showing up to $show_limit anomalies (use -a/--all for full output)"
        fi
        echo ""

        echo -e "${CYAN}┌──────────┬──────────┬────────────────────┬──────────────────────────────────────────┐${NC}"
        printf "${CYAN}│${NC} %-8s ${CYAN}│${NC} %-8s ${CYAN}│${NC} %-18s ${CYAN}│${NC} %-40s ${CYAN}│${NC}\n" "RISK" "TYPE" "CATEGORY" "PATH"
        echo -e "${CYAN}├──────────┼──────────┼────────────────────┼──────────────────────────────────────────┤${NC}"

        local re_type='"anomaly_type":"([^"]*)"'
        local re_path='"path":"([^"]*)"'
        local re_entry='"entry_type":"([^"]*)"'
        local re_risk='"risk_score":"([^"]*)"'
        local re_mitre='"mitre_technique":"([^"]*)"'

        local anomaly_count=0
        while IFS= read -r line; do
            [[ ! "$line" =~ $re_type ]] && continue

            # Apply limit unless show_all is true
            if [[ "$show_all" != "true" ]] && [[ $anomaly_count -ge $show_limit ]]; then
                continue
            fi

            local atype="${BASH_REMATCH[1]}" path="" entry="" risk="" mitre=""
            [[ "$line" =~ $re_path ]] && path="${BASH_REMATCH[1]}"
            [[ "$line" =~ $re_entry ]] && entry="${BASH_REMATCH[1]}"
            [[ "$line" =~ $re_risk ]] && risk="${BASH_REMATCH[1]}"
            [[ "$line" =~ $re_mitre ]] && mitre="${BASH_REMATCH[1]}"

            local risk_color="$NC" type_color="$NC"
            case "$risk" in
                CRITICAL) risk_color="$RED" ;;
                HIGH) risk_color="$RED" ;;
                MEDIUM) risk_color="$YELLOW" ;;
                LOW) risk_color="$GREEN" ;;
            esac
            case "$atype" in
                new) type_color="$RED" ;;
                modified) type_color="$MAGENTA" ;;
                missing) type_color="$YELLOW" ;;
            esac

            [[ ${#path} -gt 39 ]] && path="...${path: -36}"

            printf "${CYAN}│${NC} ${risk_color}%-8s${NC} ${CYAN}│${NC} ${type_color}%-8s${NC} ${CYAN}│${NC} %-18s ${CYAN}│${NC} %-40s ${CYAN}│${NC}\n" "$risk" "${atype^^}" "$entry" "$path"
            printf "${CYAN}│${NC} %-8s ${CYAN}│${NC} %-8s ${CYAN}│${NC} %-18s ${CYAN}│${NC} ${BLUE}%-40s${NC} ${CYAN}│${NC}\n" "" "" "" "$mitre"
            ((anomaly_count++))
        done < "$file"

        echo -e "${CYAN}└──────────┴──────────┴────────────────────┴──────────────────────────────────────────┘${NC}"

        # Show skipped count
        if [[ "$show_all" != "true" ]] && [[ $total_anomalies -gt $show_limit ]]; then
            local skipped=$((total_anomalies - show_limit))
            echo ""
            echo -e "${YELLOW}    ... and $skipped more anomalies (use -a/--all to see all)${NC}"
        fi
    fi

    # Recommendations
    echo ""
    print_header "Recommendations"

    if [[ $total_anomalies -eq 0 ]]; then
        echo -e "${GREEN}✓ No anomalies detected. Persistence mechanisms appear unchanged.${NC}"
    else
        if [[ $new_count -gt 0 ]]; then
            echo -e "${RED}• Investigate new persistence entries immediately${NC}"
            echo -e "  - Review content of new entries"
            echo -e "  - Check creation timestamps"
            echo -e "  - Correlate with user activity logs"
        fi
        if [[ $modified_count -gt 0 ]]; then
            echo -e "${MAGENTA}• Verify modified entries - possible tampering${NC}"
            echo -e "  - Compare with backup or known-good baseline"
            echo -e "  - Check for unauthorized changes"
        fi
        if [[ $missing_count -gt 0 ]]; then
            echo -e "${YELLOW}• Review missing entries - possible anti-forensics${NC}"
            echo -e "  - Verify if removal was authorized"
            echo -e "  - Check for signs of cleanup activity"
        fi
    fi
}

# Usage
usage() {
    echo "Persistence Anomaly Detection - Pure Bash"
    echo "Author: Medjed"
    echo ""
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  baseline    Create baseline of persistence mechanisms"
    echo "  scan        Scan and compare against baseline"
    echo "  show        Display baseline or scan results"
    echo ""
    echo "Options:"
    echo "  -o, --output FILE      Output file for baseline/scan results"
    echo "  -b, --baseline FILE    Baseline file for comparison (scan command)"
    echo "  -f, --file FILE        File to display (show command)"
    echo "  -a, --all              Show all entries (no limit, for show command)"
    echo "  -n, --limit NUM        Limit entries per group (default: 5, for show command)"
    echo "  -l, --level 1|2|3      Scan level (default: 2)"
    echo "                           1 = Essential (cron, systemd, shell-rc, ssh-keys)"
    echo "                           2 = Comprehensive (+ timers, at-jobs, init, xdg)"
    echo "                           3 = Exhaustive (+ ld-preload, modules, udev, motd)"
    echo "  -c, --category LIST    Specific categories (comma-separated)"
    echo "  -h, --help             Show this help"
    echo ""
    echo "Categories:"
    echo "  Level 1: cron, systemd-services, shell-rc, ssh-keys"
    echo "  Level 2: systemd-timers, at-jobs, init-scripts, xdg-autostart"
    echo "  Level 3: ld-preload, kernel-modules, udev-rules, motd-scripts"
    echo ""
    echo "Examples:"
    echo "  $0 baseline -l 1 -o baseline.json"
    echo "  $0 scan -b baseline.json -l 3 -o results.json"
    echo "  $0 scan -b baseline.json -c cron,ssh-keys"
    echo "  $0 show -f results.json"
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
            -l|--level)
                SCAN_LEVEL="$2"
                if [[ ! "$SCAN_LEVEL" =~ ^[123]$ ]]; then
                    print_error "Invalid level: $SCAN_LEVEL (must be 1, 2, or 3)"
                    exit 1
                fi
                shift 2
                ;;
            -c|--category)
                IFS=',' read -ra SELECTED_CATEGORIES <<< "$2"
                shift 2
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
            [[ -z "$output_file" ]] && output_file="persistence_baseline.json"
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
