#!/bin/bash
#
# Network Isolation Script using UFW (Uncomplicated Firewall)
# Part of Incident Response Toolkit
#
# This script provides an interactive menu and CLI interface for network isolation
# during incident response activities using UFW.
#
# Usage:
#   Interactive mode: sudo ./network_isolate_ufw.sh
#   CLI mode:         sudo ./network_isolate_ufw.sh [OPTIONS]
#
# CLI Options:
#   --allow-port-from <port> <ip>         Allow port from specific IP
#   --block-port-except-from <port> <ips> Block port except from IPs (comma-separated)
#   --allow-port-to <port> <ip>           Allow outbound to port on specific IP
#   --block-port-except-to <port> <ips>   Block outbound port except to IPs (comma-separated)
#   --block-port-in <port>                Block inbound port
#   --block-port-out <port>               Block outbound port
#   --restrict-dns <ips>                  Restrict outbound DNS to resolvers (comma-separated)
#   --restrict-smtp <ips>                 Restrict outbound SMTP to mail servers (comma-separated)
#   --enable-logging                      Enable firewall logging
#   --disable-logging                     Disable firewall logging
#   --help                                Show this help message
#

set -e

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Script mode
INTERACTIVE_MODE=true

# ============================================================================
# Helper Functions
# ============================================================================

print_header() {
    echo -e "\n${BLUE}============================================================${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}============================================================${NC}\n"
}

print_info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root!"
        print_info "Please run with: sudo $0"
        exit 1
    fi
}

check_ufw() {
    if ! command -v ufw &>/dev/null; then
        print_error "UFW is not installed!"
        print_info "Install it with: sudo apt-get install ufw"
        exit 1
    fi
}

pause() {
    if [[ "$INTERACTIVE_MODE" == true ]]; then
        echo ""
        read -rp "Press Enter to continue..."
    fi
}

confirm_action() {
    local message="$1"
    print_warning "$message"
    echo ""
    read -rp "Are you sure you want to proceed? (yes/no): " confirm
    if [[ "$confirm" == "yes" ]]; then
        return 0
    else
        print_info "Operation cancelled."
        return 1
    fi
}

# ============================================================================
# Validation Functions
# ============================================================================

validate_port() {
    local port="$1"
    if [[ ! "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        print_error "Invalid port number. Must be between 1 and 65535."
        return 1
    fi
    return 0
}

validate_ip() {
    local ip="$1"
    # Basic IPv4 validation
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        # Check each octet
        IFS='.' read -ra octets <<< "$ip"
        for octet in "${octets[@]}"; do
            if [ "$octet" -gt 255 ]; then
                print_error "Invalid IP address. Octets must be 0-255."
                return 1
            fi
        done
        return 0
    # IPv4 CIDR notation
    elif [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        local ip_part="${ip%/*}"
        local cidr="${ip##*/}"
        if [ "$cidr" -gt 32 ]; then
            print_error "Invalid CIDR notation. Must be /0 to /32."
            return 1
        fi
        IFS='.' read -ra octets <<< "$ip_part"
        for octet in "${octets[@]}"; do
            if [ "$octet" -gt 255 ]; then
                print_error "Invalid IP address in CIDR."
                return 1
            fi
        done
        return 0
    else
        print_error "Invalid IP address format. Use x.x.x.x or x.x.x.x/xx"
        return 1
    fi
}

validate_ip_list() {
    local ip_list="$1"
    if [[ -z "$ip_list" ]]; then
        print_error "IP list cannot be empty."
        return 1
    fi

    IFS=',' read -ra ips <<< "$ip_list"
    for ip in "${ips[@]}"; do
        # Trim whitespace
        ip=$(echo "$ip" | xargs)
        if ! validate_ip "$ip"; then
            return 1
        fi
    done
    return 0
}

validate_interface() {
    local iface="$1"
    if ! ip link show "$iface" &>/dev/null; then
        print_error "Interface '$iface' does not exist."
        return 1
    fi
    return 0
}

validate_rule_number() {
    local rule_num="$1"
    if [[ ! "$rule_num" =~ ^[0-9]+$ ]] || [ "$rule_num" -lt 1 ]; then
        print_error "Invalid rule number. Must be a positive integer."
        return 1
    fi
    return 0
}

get_protocol() {
    echo ""
    echo "Select protocol:"
    echo "  1) TCP"
    echo "  2) UDP"
    echo "  3) Both (TCP and UDP)"
    read -rp "Enter choice [1-3]: " proto_choice

    case $proto_choice in
        1) echo "tcp" ;;
        2) echo "udp" ;;
        3) echo "both" ;;
        *)
            print_warning "Invalid choice, defaulting to TCP"
            echo "tcp"
            ;;
    esac
}

get_direction() {
    echo ""
    echo "Select direction:"
    echo "  1) Incoming (in)"
    echo "  2) Outgoing (out)"
    echo "  3) Both (in and out)"
    read -rp "Enter choice [1-3]: " dir_choice

    case $dir_choice in
        1) echo "in" ;;
        2) echo "out" ;;
        3) echo "both" ;;
        *)
            print_warning "Invalid choice, defaulting to Incoming"
            echo "in"
            ;;
    esac
}

# ============================================================================
# Original Menu Option Functions
# ============================================================================

show_ufw_status() {
    print_header "UFW Status and Rules"

    print_info "UFW Status:"
    echo ""
    ufw status verbose
    echo ""

    print_info "Numbered rules (for deletion):"
    echo ""
    ufw status numbered

    pause
}

show_open_ports() {
    print_header "Open Ports and Services"

    print_info "Listening TCP ports:"
    echo ""
    ss -tlnp

    echo ""
    print_info "Listening UDP ports:"
    echo ""
    ss -ulnp

    echo ""
    print_info "Established connections:"
    echo ""
    ss -tnp state established

    pause
}

enable_ufw() {
    print_header "Enable UFW"

    print_info "Current UFW status:"
    ufw status | head -1
    echo ""

    if confirm_action "This will enable UFW and activate firewall rules."; then
        print_info "Enabling UFW..."
        # Use --force to avoid interactive prompt
        ufw --force enable
        print_success "UFW is now enabled."
    fi

    pause
}

disable_ufw() {
    print_header "Disable UFW"

    print_info "Current UFW status:"
    ufw status | head -1
    echo ""

    if confirm_action "This will disable UFW and deactivate all firewall rules!"; then
        print_info "Disabling UFW..."
        ufw disable
        print_success "UFW is now disabled."
    fi

    pause
}

block_port() {
    print_header "Block a Specific Port"

    read -rp "Enter port number to block: " port
    if ! validate_port "$port"; then
        pause
        return
    fi

    protocol=$(get_protocol)
    direction=$(get_direction)

    echo ""
    print_info "Blocking port $port ($protocol, $direction)..."

    block_port_cmd() {
        local proto="$1"
        local dir="$2"
        local prt="$3"

        case $dir in
            in)
                ufw deny in proto "$proto" to any port "$prt"
                print_success "Blocked incoming $proto port $prt"
                ;;
            out)
                ufw deny out proto "$proto" to any port "$prt"
                print_success "Blocked outgoing $proto port $prt"
                ;;
            both)
                ufw deny in proto "$proto" to any port "$prt"
                ufw deny out proto "$proto" to any port "$prt"
                print_success "Blocked incoming and outgoing $proto port $prt"
                ;;
        esac
    }

    case $protocol in
        tcp)
            block_port_cmd "tcp" "$direction" "$port"
            ;;
        udp)
            block_port_cmd "udp" "$direction" "$port"
            ;;
        both)
            block_port_cmd "tcp" "$direction" "$port"
            block_port_cmd "udp" "$direction" "$port"
            ;;
    esac

    pause
}

block_ip() {
    print_header "Block a Specific IP Address"

    read -rp "Enter IP address to block (e.g., 192.168.1.100 or 10.0.0.0/8): " ip
    if ! validate_ip "$ip"; then
        pause
        return
    fi

    direction=$(get_direction)

    echo ""
    print_info "Blocking IP $ip ($direction)..."

    case $direction in
        in)
            ufw deny in from "$ip"
            print_success "Blocked incoming traffic from $ip"
            ;;
        out)
            ufw deny out to "$ip"
            print_success "Blocked outgoing traffic to $ip"
            ;;
        both)
            ufw deny in from "$ip"
            ufw deny out to "$ip"
            print_success "Blocked all traffic to/from $ip"
            ;;
    esac

    pause
}

allow_port() {
    print_header "Allow a Specific Port"

    read -rp "Enter port number to allow: " port
    if ! validate_port "$port"; then
        pause
        return
    fi

    protocol=$(get_protocol)
    direction=$(get_direction)

    echo ""
    print_info "Allowing port $port ($protocol, $direction)..."

    allow_port_cmd() {
        local proto="$1"
        local dir="$2"
        local prt="$3"

        case $dir in
            in)
                ufw allow in proto "$proto" to any port "$prt"
                print_success "Allowed incoming $proto port $prt"
                ;;
            out)
                ufw allow out proto "$proto" to any port "$prt"
                print_success "Allowed outgoing $proto port $prt"
                ;;
            both)
                ufw allow in proto "$proto" to any port "$prt"
                ufw allow out proto "$proto" to any port "$prt"
                print_success "Allowed incoming and outgoing $proto port $prt"
                ;;
        esac
    }

    case $protocol in
        tcp)
            allow_port_cmd "tcp" "$direction" "$port"
            ;;
        udp)
            allow_port_cmd "udp" "$direction" "$port"
            ;;
        both)
            allow_port_cmd "tcp" "$direction" "$port"
            allow_port_cmd "udp" "$direction" "$port"
            ;;
    esac

    pause
}

allow_ip() {
    print_header "Allow a Specific IP Address"

    read -rp "Enter IP address to allow (e.g., 192.168.1.100 or 10.0.0.0/8): " ip
    if ! validate_ip "$ip"; then
        pause
        return
    fi

    direction=$(get_direction)

    echo ""
    print_info "Allowing IP $ip ($direction)..."

    case $direction in
        in)
            ufw allow in from "$ip"
            print_success "Allowed incoming traffic from $ip"
            ;;
        out)
            ufw allow out to "$ip"
            print_success "Allowed outgoing traffic to $ip"
            ;;
        both)
            ufw allow in from "$ip"
            ufw allow out to "$ip"
            print_success "Allowed all traffic to/from $ip"
            ;;
    esac

    pause
}

delete_rule() {
    print_header "Delete a Rule by Number"

    print_info "Current numbered rules:"
    echo ""
    ufw status numbered
    echo ""

    read -rp "Enter rule number to delete: " rule_num
    if ! validate_rule_number "$rule_num"; then
        pause
        return
    fi

    if confirm_action "This will delete rule number $rule_num."; then
        print_info "Deleting rule $rule_num..."
        # Use --force to avoid interactive prompt
        if ufw --force delete "$rule_num"; then
            print_success "Rule $rule_num has been deleted."
        else
            print_error "Failed to delete rule $rule_num. Check the rule number."
        fi
    fi

    pause
}

reset_ufw() {
    print_header "Reset UFW (Remove All Rules)"

    if confirm_action "This will remove ALL UFW rules and disable the firewall!"; then
        print_info "Resetting UFW..."
        # Use --force to avoid interactive prompt
        ufw --force reset
        print_success "UFW has been reset. All rules removed and firewall disabled."
        print_info "You will need to re-enable UFW and add new rules."
    fi

    pause
}

default_deny_incoming() {
    print_header "Enable Default Deny Incoming"

    print_warning "This will set the default policy to deny ALL incoming traffic!"
    print_warning "Only explicitly allowed connections will be permitted."
    echo ""

    if confirm_action "This may block remote access if not configured properly!"; then
        print_info "Setting default deny incoming..."
        ufw default deny incoming
        print_success "Default incoming policy is now DENY."
        print_info "Add allow rules for services you need access to."
    fi

    pause
}

default_deny_outgoing() {
    print_header "Enable Default Deny Outgoing"

    print_warning "This will set the default policy to deny ALL outgoing traffic!"
    print_warning "This system will not be able to initiate any connections!"
    echo ""

    if confirm_action "This is a highly restrictive setting!"; then
        print_info "Setting default deny outgoing..."
        ufw default deny outgoing
        print_success "Default outgoing policy is now DENY."
        print_info "Add allow rules for services this system needs to reach."
    fi

    pause
}

take_down_interface() {
    print_header "Take Down Network Interface"

    print_info "Available network interfaces:"
    echo ""
    ip -br link show
    echo ""

    read -rp "Enter interface name to take down: " iface
    if ! validate_interface "$iface"; then
        pause
        return
    fi

    if confirm_action "This will disable network interface '$iface'!"; then
        print_info "Taking down interface $iface..."
        ip link set "$iface" down
        print_success "Interface $iface is now DOWN."
    fi

    pause
}

bring_up_interface() {
    print_header "Bring Up Network Interface"

    print_info "Available network interfaces:"
    echo ""
    ip -br link show
    echo ""

    read -rp "Enter interface name to bring up: " iface
    if ! validate_interface "$iface"; then
        pause
        return
    fi

    print_info "Bringing up interface $iface..."
    ip link set "$iface" up
    print_success "Interface $iface is now UP."

    pause
}

show_interfaces() {
    print_header "Network Interfaces"

    print_info "Interface summary:"
    echo ""
    ip -br link show

    echo ""
    print_info "Detailed interface information:"
    echo ""
    ip -br addr show

    echo ""
    print_info "Routing table:"
    echo ""
    ip route show

    pause
}

# ============================================================================
# NEW: Combined IP+Port Functions
# ============================================================================

allow_port_from_ip() {
    if [[ "$INTERACTIVE_MODE" == true ]]; then
        print_header "Allow Port from Specific IP (Admin Access Control)"

        read -rp "Enter port number: " port
        if ! validate_port "$port"; then
            pause
            return
        fi

        read -rp "Enter source IP address (e.g., 10.1.2.3 or 10.1.2.0/24): " ip
        if ! validate_ip "$ip"; then
            pause
            return
        fi

        protocol=$(get_protocol)
    else
        local port="$1"
        local ip="$2"
        local protocol="${3:-tcp}"
    fi

    echo ""
    print_info "Allowing port $port from IP $ip ($protocol)..."

    _allow_port_from_ip_cmd() {
        local proto="$1"
        ufw allow from "$ip" to any port "$port" proto "$proto"
        print_success "Allowed incoming $proto port $port from $ip"
    }

    case $protocol in
        tcp) _allow_port_from_ip_cmd "tcp" ;;
        udp) _allow_port_from_ip_cmd "udp" ;;
        both)
            _allow_port_from_ip_cmd "tcp"
            _allow_port_from_ip_cmd "udp"
            ;;
    esac

    [[ "$INTERACTIVE_MODE" == true ]] && pause
}

block_port_except_from() {
    if [[ "$INTERACTIVE_MODE" == true ]]; then
        print_header "Block Port Except from IPs (Whitelist Inbound)"

        read -rp "Enter port number to restrict: " port
        if ! validate_port "$port"; then
            pause
            return
        fi

        read -rp "Enter allowed source IPs (comma-separated, e.g., 10.1.2.3,10.1.2.4): " ip_list
        if ! validate_ip_list "$ip_list"; then
            pause
            return
        fi

        protocol=$(get_protocol)
    else
        local port="$1"
        local ip_list="$2"
        local protocol="${3:-tcp}"
    fi

    echo ""
    print_info "Allowing port $port only from: $ip_list ($protocol)"
    print_info "All other sources will be blocked..."

    _block_port_except_from_cmd() {
        local proto="$1"

        # First, add ALLOW rules for whitelisted IPs
        IFS=',' read -ra ips <<< "$ip_list"
        for ip in "${ips[@]}"; do
            ip=$(echo "$ip" | xargs)  # Trim whitespace
            ufw allow from "$ip" to any port "$port" proto "$proto"
            print_success "Allowed $proto port $port from $ip"
        done

        # Then, add DENY rule for all others
        ufw deny in proto "$proto" to any port "$port"
        print_success "Blocked $proto port $port from all other sources"
    }

    case $protocol in
        tcp) _block_port_except_from_cmd "tcp" ;;
        udp) _block_port_except_from_cmd "udp" ;;
        both)
            _block_port_except_from_cmd "tcp"
            _block_port_except_from_cmd "udp"
            ;;
    esac

    [[ "$INTERACTIVE_MODE" == true ]] && pause
}

allow_port_to_ip() {
    if [[ "$INTERACTIVE_MODE" == true ]]; then
        print_header "Allow Outbound Port to Specific IP"

        read -rp "Enter destination port number: " port
        if ! validate_port "$port"; then
            pause
            return
        fi

        read -rp "Enter destination IP address (e.g., 8.8.8.8 or 10.0.0.0/8): " ip
        if ! validate_ip "$ip"; then
            pause
            return
        fi

        protocol=$(get_protocol)
    else
        local port="$1"
        local ip="$2"
        local protocol="${3:-tcp}"
    fi

    echo ""
    print_info "Allowing outbound port $port to IP $ip ($protocol)..."

    _allow_port_to_ip_cmd() {
        local proto="$1"
        ufw allow out to "$ip" port "$port" proto "$proto"
        print_success "Allowed outgoing $proto port $port to $ip"
    }

    case $protocol in
        tcp) _allow_port_to_ip_cmd "tcp" ;;
        udp) _allow_port_to_ip_cmd "udp" ;;
        both)
            _allow_port_to_ip_cmd "tcp"
            _allow_port_to_ip_cmd "udp"
            ;;
    esac

    [[ "$INTERACTIVE_MODE" == true ]] && pause
}

block_port_except_to() {
    if [[ "$INTERACTIVE_MODE" == true ]]; then
        print_header "Block Outbound Port Except to IPs (Whitelist Outbound)"

        read -rp "Enter destination port number to restrict: " port
        if ! validate_port "$port"; then
            pause
            return
        fi

        read -rp "Enter allowed destination IPs (comma-separated, e.g., 8.8.8.8,8.8.4.4): " ip_list
        if ! validate_ip_list "$ip_list"; then
            pause
            return
        fi

        protocol=$(get_protocol)
    else
        local port="$1"
        local ip_list="$2"
        local protocol="${3:-tcp}"
    fi

    echo ""
    print_info "Allowing outbound port $port only to: $ip_list ($protocol)"
    print_info "All other destinations will be blocked..."

    _block_port_except_to_cmd() {
        local proto="$1"

        # First, add ALLOW rules for whitelisted IPs
        IFS=',' read -ra ips <<< "$ip_list"
        for ip in "${ips[@]}"; do
            ip=$(echo "$ip" | xargs)  # Trim whitespace
            ufw allow out to "$ip" port "$port" proto "$proto"
            print_success "Allowed outbound $proto port $port to $ip"
        done

        # Then, add DENY rule for all others
        ufw deny out proto "$proto" to any port "$port"
        print_success "Blocked outbound $proto port $port to all other destinations"
    }

    case $protocol in
        tcp) _block_port_except_to_cmd "tcp" ;;
        udp) _block_port_except_to_cmd "udp" ;;
        both)
            _block_port_except_to_cmd "tcp"
            _block_port_except_to_cmd "udp"
            ;;
    esac

    [[ "$INTERACTIVE_MODE" == true ]] && pause
}

# ============================================================================
# NEW: Service Restriction Functions
# ============================================================================

restrict_outbound_dns() {
    if [[ "$INTERACTIVE_MODE" == true ]]; then
        print_header "Restrict Outbound DNS to Approved Resolvers"

        print_info "Enter DNS resolver IPs that should be allowed."
        print_info "Common options: 8.8.8.8, 8.8.4.4 (Google), 1.1.1.1 (Cloudflare)"
        echo ""
        read -rp "Enter allowed DNS server IPs (comma-separated): " ip_list
        if ! validate_ip_list "$ip_list"; then
            pause
            return
        fi
    else
        local ip_list="$1"
    fi

    echo ""
    print_info "Restricting outbound DNS (port 53) to: $ip_list"
    print_warning "All other DNS queries will be blocked!"

    # Add ALLOW rules for each DNS server (both UDP and TCP)
    IFS=',' read -ra ips <<< "$ip_list"
    for ip in "${ips[@]}"; do
        ip=$(echo "$ip" | xargs)  # Trim whitespace
        ufw allow out to "$ip" port 53 proto udp
        ufw allow out to "$ip" port 53 proto tcp
        print_success "Allowed DNS to $ip"
    done

    # Block all other DNS
    ufw deny out proto udp to any port 53
    ufw deny out proto tcp to any port 53
    print_success "Blocked DNS to all other destinations"

    [[ "$INTERACTIVE_MODE" == true ]] && pause
}

restrict_outbound_smtp() {
    if [[ "$INTERACTIVE_MODE" == true ]]; then
        print_header "Restrict Outbound SMTP to Mail Servers"

        print_info "Enter mail server IPs that should be allowed for SMTP."
        print_info "This will restrict ports 25 (SMTP), 465 (SMTPS), and 587 (Submission)."
        echo ""
        read -rp "Enter allowed mail server IPs (comma-separated): " ip_list
        if ! validate_ip_list "$ip_list"; then
            pause
            return
        fi
    else
        local ip_list="$1"
    fi

    echo ""
    print_info "Restricting outbound SMTP (ports 25, 465, 587) to: $ip_list"
    print_warning "All other SMTP connections will be blocked!"

    # SMTP ports
    local smtp_ports=(25 465 587)

    # Add ALLOW rules for each mail server
    IFS=',' read -ra ips <<< "$ip_list"
    for ip in "${ips[@]}"; do
        ip=$(echo "$ip" | xargs)  # Trim whitespace
        for port in "${smtp_ports[@]}"; do
            ufw allow out to "$ip" port "$port" proto tcp
        done
        print_success "Allowed SMTP to $ip"
    done

    # Block all other SMTP
    for port in "${smtp_ports[@]}"; do
        ufw deny out proto tcp to any port "$port"
    done
    print_success "Blocked SMTP to all other destinations"

    [[ "$INTERACTIVE_MODE" == true ]] && pause
}

# ============================================================================
# NEW: Logging Functions
# ============================================================================

enable_drop_logging() {
    if [[ "$INTERACTIVE_MODE" == true ]]; then
        print_header "Enable Firewall Logging"
        print_info "This will enable UFW logging for blocked connections."
        echo ""
    fi

    print_info "Enabling UFW logging..."
    ufw logging on
    ufw logging medium

    print_success "Firewall logging enabled (medium level)."
    print_info "View logs with: journalctl -k | grep UFW"
    print_info "Or check: /var/log/ufw.log"

    [[ "$INTERACTIVE_MODE" == true ]] && pause
}

disable_drop_logging() {
    if [[ "$INTERACTIVE_MODE" == true ]]; then
        print_header "Disable Firewall Logging"
        echo ""
    fi

    print_info "Disabling UFW logging..."
    ufw logging off

    print_success "Firewall logging disabled."

    [[ "$INTERACTIVE_MODE" == true ]] && pause
}

# ============================================================================
# CLI Argument Parsing
# ============================================================================

show_help() {
    cat << 'EOF'
Network Isolation Script using UFW
Part of Incident Response Toolkit

Usage:
  Interactive mode: sudo ./network_isolate_ufw.sh
  CLI mode:         sudo ./network_isolate_ufw.sh [OPTIONS]

CLI Options:
  --allow-port-from <port> <ip>         Allow inbound port from specific IP
  --block-port-except-from <port> <ips> Block inbound port except from IPs (comma-separated)
  --allow-port-to <port> <ip>           Allow outbound port to specific IP
  --block-port-except-to <port> <ips>   Block outbound port except to IPs (comma-separated)
  --block-port-in <port>                Block inbound port (TCP+UDP)
  --block-port-out <port>               Block outbound port (TCP+UDP)
  --restrict-dns <ips>                  Restrict outbound DNS to resolvers (comma-separated)
  --restrict-smtp <ips>                 Restrict outbound SMTP to servers (comma-separated)
  --enable-logging                      Enable firewall logging
  --disable-logging                     Disable firewall logging
  --default-deny-in                     Set default deny incoming
  --default-deny-out                    Set default deny outgoing
  --enable                              Enable UFW
  --help                                Show this help message

Examples:
  # Restrict SSH to management IP
  sudo ./network_isolate_ufw.sh --allow-port-from 22 10.1.2.3
  sudo ./network_isolate_ufw.sh --block-port-except-from 22 10.1.2.3,10.1.2.4

  # Block outbound SMB and RDP
  sudo ./network_isolate_ufw.sh --block-port-out 445
  sudo ./network_isolate_ufw.sh --block-port-out 3389

  # Restrict DNS to approved resolvers
  sudo ./network_isolate_ufw.sh --restrict-dns 8.8.8.8,8.8.4.4,1.1.1.1

  # Restrict SMTP to mail server
  sudo ./network_isolate_ufw.sh --restrict-smtp 10.0.0.25

  # Enable logging and default deny
  sudo ./network_isolate_ufw.sh --enable-logging --default-deny-in --enable

EOF
    exit 0
}

parse_cli_args() {
    INTERACTIVE_MODE=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --help|-h)
                show_help
                ;;
            --allow-port-from)
                if [[ -z "$2" || -z "$3" ]]; then
                    print_error "--allow-port-from requires <port> <ip>"
                    exit 1
                fi
                validate_port "$2" || exit 1
                validate_ip "$3" || exit 1
                allow_port_from_ip "$2" "$3" "both"
                shift 3
                ;;
            --block-port-except-from)
                if [[ -z "$2" || -z "$3" ]]; then
                    print_error "--block-port-except-from requires <port> <ips>"
                    exit 1
                fi
                validate_port "$2" || exit 1
                validate_ip_list "$3" || exit 1
                block_port_except_from "$2" "$3" "both"
                shift 3
                ;;
            --allow-port-to)
                if [[ -z "$2" || -z "$3" ]]; then
                    print_error "--allow-port-to requires <port> <ip>"
                    exit 1
                fi
                validate_port "$2" || exit 1
                validate_ip "$3" || exit 1
                allow_port_to_ip "$2" "$3" "both"
                shift 3
                ;;
            --block-port-except-to)
                if [[ -z "$2" || -z "$3" ]]; then
                    print_error "--block-port-except-to requires <port> <ips>"
                    exit 1
                fi
                validate_port "$2" || exit 1
                validate_ip_list "$3" || exit 1
                block_port_except_to "$2" "$3" "both"
                shift 3
                ;;
            --block-port-in)
                if [[ -z "$2" ]]; then
                    print_error "--block-port-in requires <port>"
                    exit 1
                fi
                validate_port "$2" || exit 1
                ufw deny in proto tcp to any port "$2"
                ufw deny in proto udp to any port "$2"
                print_success "Blocked inbound port $2 (TCP+UDP)"
                shift 2
                ;;
            --block-port-out)
                if [[ -z "$2" ]]; then
                    print_error "--block-port-out requires <port>"
                    exit 1
                fi
                validate_port "$2" || exit 1
                ufw deny out proto tcp to any port "$2"
                ufw deny out proto udp to any port "$2"
                print_success "Blocked outbound port $2 (TCP+UDP)"
                shift 2
                ;;
            --restrict-dns)
                if [[ -z "$2" ]]; then
                    print_error "--restrict-dns requires <ips>"
                    exit 1
                fi
                validate_ip_list "$2" || exit 1
                restrict_outbound_dns "$2"
                shift 2
                ;;
            --restrict-smtp)
                if [[ -z "$2" ]]; then
                    print_error "--restrict-smtp requires <ips>"
                    exit 1
                fi
                validate_ip_list "$2" || exit 1
                restrict_outbound_smtp "$2"
                shift 2
                ;;
            --enable-logging)
                enable_drop_logging
                shift
                ;;
            --disable-logging)
                disable_drop_logging
                shift
                ;;
            --default-deny-in)
                ufw default deny incoming
                print_success "Default incoming policy set to DENY"
                shift
                ;;
            --default-deny-out)
                ufw default deny outgoing
                print_success "Default outgoing policy set to DENY"
                shift
                ;;
            --enable)
                ufw --force enable
                print_success "UFW enabled"
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                print_info "Use --help for usage information"
                exit 1
                ;;
        esac
    done
}

# ============================================================================
# Main Menu
# ============================================================================

show_menu() {
    clear
    echo -e "${CYAN}"
    echo "  _   _      _                      _      _____           _       _   _             "
    echo " | \ | |    | |                    | |    |_   _|         | |     | | (_)            "
    echo " |  \| | ___| |___      _____  _ __| | __   | |  ___  ___ | | __ _| |_ _  ___  _ __  "
    echo " | . \` |/ _ \ __\ \ /\ / / _ \| '__| |/ /   | | / __|/ _ \| |/ _\` | __| |/ _ \| '_ \ "
    echo " | |\  |  __/ |_ \ V  V / (_) | |  |   <   _| |_\__ \ (_) | | (_| | |_| | (_) | | | |"
    echo " |_| \_|\___|\__| \_/\_/ \___/|_|  |_|\_\ |_____|___/\___/|_|\__,_|\__|_|\___/|_| |_|"
    echo -e "${NC}"
    echo -e "${BLUE}                           UFW Network Isolation Tool${NC}"
    echo -e "${BLUE}                           Incident Response Toolkit${NC}"
    echo ""
    echo -e "${YELLOW}=================================================================================${NC}"
    echo -e "${GREEN} BASIC OPERATIONS${NC}"
    echo -e "  ${GREEN}1)${NC}  Show UFW status and rules"
    echo -e "  ${GREEN}2)${NC}  Show open ports and services (ss)"
    echo -e "  ${GREEN}3)${NC}  Enable UFW"
    echo -e "  ${YELLOW}4)${NC}  Disable UFW"
    echo -e "  ${GREEN}5)${NC}  Block a specific port"
    echo -e "  ${GREEN}6)${NC}  Block a specific IP address"
    echo -e "  ${GREEN}7)${NC}  Allow a specific port"
    echo -e "  ${GREEN}8)${NC}  Allow a specific IP address"
    echo -e "  ${YELLOW}9)${NC}  Delete a rule (by number)"
    echo -e "  ${RED}10)${NC} Reset UFW (remove all rules)"
    echo ""
    echo -e "${RED} EMERGENCY ISOLATION${NC}"
    echo -e "  ${RED}11)${NC} Enable default deny incoming"
    echo -e "  ${RED}12)${NC} Enable default deny outgoing"
    echo ""
    echo -e "${CYAN} INTERFACE CONTROL${NC}"
    echo -e "  ${RED}13)${NC} Take down network interface"
    echo -e "  ${GREEN}14)${NC} Bring up network interface"
    echo -e "  ${GREEN}15)${NC} Show network interfaces"
    echo ""
    echo -e "${BLUE} ADVANCED ACCESS CONTROL${NC}"
    echo -e "  ${GREEN}16)${NC} Allow port from specific IP (admin access)"
    echo -e "  ${GREEN}17)${NC} Block port except from IPs (whitelist inbound)"
    echo -e "  ${GREEN}18)${NC} Allow port to specific IP (outbound control)"
    echo -e "  ${GREEN}19)${NC} Block port except to IPs (whitelist outbound)"
    echo ""
    echo -e "${BLUE} SERVICE RESTRICTIONS${NC}"
    echo -e "  ${GREEN}20)${NC} Restrict outbound DNS to approved resolvers"
    echo -e "  ${GREEN}21)${NC} Restrict outbound SMTP to mail servers"
    echo ""
    echo -e "${BLUE} LOGGING${NC}"
    echo -e "  ${GREEN}22)${NC} Enable firewall logging"
    echo -e "  ${YELLOW}23)${NC} Disable firewall logging"
    echo ""
    echo -e "  ${CYAN}0)${NC}  Exit"
    echo ""
    echo -e "${YELLOW}=================================================================================${NC}"
    echo ""
}

run_interactive() {
    while true; do
        show_menu
        read -rp "Enter your choice [0-23]: " choice

        case $choice in
            1) show_ufw_status ;;
            2) show_open_ports ;;
            3) enable_ufw ;;
            4) disable_ufw ;;
            5) block_port ;;
            6) block_ip ;;
            7) allow_port ;;
            8) allow_ip ;;
            9) delete_rule ;;
            10) reset_ufw ;;
            11) default_deny_incoming ;;
            12) default_deny_outgoing ;;
            13) take_down_interface ;;
            14) bring_up_interface ;;
            15) show_interfaces ;;
            16) allow_port_from_ip ;;
            17) block_port_except_from ;;
            18) allow_port_to_ip ;;
            19) block_port_except_to ;;
            20) restrict_outbound_dns ;;
            21) restrict_outbound_smtp ;;
            22) enable_drop_logging ;;
            23) disable_drop_logging ;;
            0)
                print_info "Exiting UFW Network Isolation Tool."
                exit 0
                ;;
            *)
                print_error "Invalid option. Please try again."
                pause
                ;;
        esac
    done
}

# ============================================================================
# Entry Point
# ============================================================================

main() {
    check_root
    check_ufw

    if [[ $# -gt 0 ]]; then
        # CLI mode
        parse_cli_args "$@"
    else
        # Interactive mode
        INTERACTIVE_MODE=true
        run_interactive
    fi
}

main "$@"
