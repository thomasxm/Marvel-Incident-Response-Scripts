#!/bin/bash
#
# Network Isolation Script using iptables
# Part of Incident Response Toolkit
#
# This script provides an interactive menu and CLI interface for network isolation
# during incident response activities.
#
# Usage:
#   Interactive mode: sudo ./network_isolate_iptables.sh
#   CLI mode:         sudo ./network_isolate_iptables.sh [OPTIONS]
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
#   --enable-logging                      Enable firewall drop logging
#   --disable-logging                     Disable firewall drop logging
#   --save                                Save rules (auto-done after changes)
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
RULES_CHANGED=false

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

pause() {
    if [[ "$INTERACTIVE_MODE" == true ]]; then
        echo ""
        read -rp "Press Enter to continue..."
    fi
}

# ============================================================================
# Persistence Functions
# ============================================================================

save_rules() {
    print_info "Saving iptables rules..."

    # Try different persistence methods
    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save
        print_success "Rules saved using netfilter-persistent"
    elif [[ -d /etc/iptables ]]; then
        iptables-save > /etc/iptables/rules.v4
        print_success "Rules saved to /etc/iptables/rules.v4"
    elif [[ -f /etc/sysconfig/iptables ]]; then
        iptables-save > /etc/sysconfig/iptables
        print_success "Rules saved to /etc/sysconfig/iptables"
    else
        # Create directory and save
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4
        print_success "Rules saved to /etc/iptables/rules.v4"
        print_warning "You may need to configure iptables-persistent for auto-restore on boot"
    fi
}

auto_save_if_changed() {
    if [[ "$RULES_CHANGED" == true ]]; then
        save_rules
        RULES_CHANGED=false
    fi
}

mark_rules_changed() {
    RULES_CHANGED=true
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
    echo "  1) Incoming (INPUT)"
    echo "  2) Outgoing (OUTPUT)"
    echo "  3) Both (INPUT and OUTPUT)"
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

show_iptables_rules() {
    print_header "Current iptables Rules"

    print_info "Filter Table (Default):"
    echo ""
    iptables -L -n -v --line-numbers

    echo ""
    print_info "NAT Table:"
    echo ""
    iptables -t nat -L -n -v --line-numbers

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
                iptables -A INPUT -p "$proto" --dport "$prt" -j DROP
                print_success "Blocked incoming $proto port $prt"
                ;;
            out)
                iptables -A OUTPUT -p "$proto" --dport "$prt" -j DROP
                print_success "Blocked outgoing $proto port $prt"
                ;;
            both)
                iptables -A INPUT -p "$proto" --dport "$prt" -j DROP
                iptables -A OUTPUT -p "$proto" --dport "$prt" -j DROP
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

    mark_rules_changed
    auto_save_if_changed
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
            iptables -A INPUT -s "$ip" -j DROP
            print_success "Blocked incoming traffic from $ip"
            ;;
        out)
            iptables -A OUTPUT -d "$ip" -j DROP
            print_success "Blocked outgoing traffic to $ip"
            ;;
        both)
            iptables -A INPUT -s "$ip" -j DROP
            iptables -A OUTPUT -d "$ip" -j DROP
            print_success "Blocked all traffic to/from $ip"
            ;;
    esac

    mark_rules_changed
    auto_save_if_changed
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
                iptables -A INPUT -p "$proto" --dport "$prt" -j ACCEPT
                print_success "Allowed incoming $proto port $prt"
                ;;
            out)
                iptables -A OUTPUT -p "$proto" --dport "$prt" -j ACCEPT
                print_success "Allowed outgoing $proto port $prt"
                ;;
            both)
                iptables -A INPUT -p "$proto" --dport "$prt" -j ACCEPT
                iptables -A OUTPUT -p "$proto" --dport "$prt" -j ACCEPT
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

    mark_rules_changed
    auto_save_if_changed
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
            iptables -A INPUT -s "$ip" -j ACCEPT
            print_success "Allowed incoming traffic from $ip"
            ;;
        out)
            iptables -A OUTPUT -d "$ip" -j ACCEPT
            print_success "Allowed outgoing traffic to $ip"
            ;;
        both)
            iptables -A INPUT -s "$ip" -j ACCEPT
            iptables -A OUTPUT -d "$ip" -j ACCEPT
            print_success "Allowed all traffic to/from $ip"
            ;;
    esac

    mark_rules_changed
    auto_save_if_changed
    pause
}

block_all_incoming() {
    print_header "EMERGENCY: Block All Incoming Traffic"

    print_warning "This will block ALL incoming network traffic!"
    print_warning "You may lose remote access to this system!"
    echo ""
    read -rp "Are you sure you want to proceed? (yes/no): " confirm

    if [[ "$confirm" == "yes" ]]; then
        print_info "Blocking all incoming traffic..."

        # Allow established connections to prevent immediate disconnect
        iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        # Allow loopback
        iptables -A INPUT -i lo -j ACCEPT
        # Drop everything else
        iptables -P INPUT DROP

        print_success "All incoming traffic is now blocked."
        print_warning "Established connections are still allowed."
        print_warning "Loopback traffic is still allowed."
        mark_rules_changed
        auto_save_if_changed
    else
        print_info "Operation cancelled."
    fi

    pause
}

block_all_outgoing() {
    print_header "EMERGENCY: Block All Outgoing Traffic"

    print_warning "This will block ALL outgoing network traffic!"
    print_warning "This system will not be able to initiate any connections!"
    echo ""
    read -rp "Are you sure you want to proceed? (yes/no): " confirm

    if [[ "$confirm" == "yes" ]]; then
        print_info "Blocking all outgoing traffic..."

        # Allow established connections
        iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        # Allow loopback
        iptables -A OUTPUT -o lo -j ACCEPT
        # Drop everything else
        iptables -P OUTPUT DROP

        print_success "All outgoing traffic is now blocked."
        print_warning "Established connections are still allowed."
        print_warning "Loopback traffic is still allowed."
        mark_rules_changed
        auto_save_if_changed
    else
        print_info "Operation cancelled."
    fi

    pause
}

reset_iptables() {
    print_header "Reset iptables (Allow All)"

    print_warning "This will remove ALL iptables rules and allow all traffic!"
    echo ""
    read -rp "Are you sure you want to proceed? (yes/no): " confirm

    if [[ "$confirm" == "yes" ]]; then
        print_info "Resetting iptables..."

        # Set default policies to ACCEPT
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT

        # Flush all rules
        iptables -F
        iptables -X

        # Flush NAT table
        iptables -t nat -F
        iptables -t nat -X

        # Flush mangle table
        iptables -t mangle -F
        iptables -t mangle -X

        print_success "iptables has been reset. All traffic is now allowed."
        mark_rules_changed
        auto_save_if_changed
    else
        print_info "Operation cancelled."
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

    print_warning "This will disable network interface '$iface'!"
    read -rp "Are you sure you want to proceed? (yes/no): " confirm

    if [[ "$confirm" == "yes" ]]; then
        print_info "Taking down interface $iface..."
        ip link set "$iface" down
        print_success "Interface $iface is now DOWN."
    else
        print_info "Operation cancelled."
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
        iptables -A INPUT -p "$proto" --dport "$port" -s "$ip" -j ACCEPT
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

    mark_rules_changed
    auto_save_if_changed
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

        # First, add ACCEPT rules for whitelisted IPs
        IFS=',' read -ra ips <<< "$ip_list"
        for ip in "${ips[@]}"; do
            ip=$(echo "$ip" | xargs)  # Trim whitespace
            iptables -A INPUT -p "$proto" --dport "$port" -s "$ip" -j ACCEPT
            print_success "Allowed $proto port $port from $ip"
        done

        # Then, add DROP rule for all others
        iptables -A INPUT -p "$proto" --dport "$port" -j DROP
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

    mark_rules_changed
    auto_save_if_changed
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
        iptables -A OUTPUT -p "$proto" --dport "$port" -d "$ip" -j ACCEPT
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

    mark_rules_changed
    auto_save_if_changed
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

        # First, add ACCEPT rules for whitelisted IPs
        IFS=',' read -ra ips <<< "$ip_list"
        for ip in "${ips[@]}"; do
            ip=$(echo "$ip" | xargs)  # Trim whitespace
            iptables -A OUTPUT -p "$proto" --dport "$port" -d "$ip" -j ACCEPT
            print_success "Allowed outbound $proto port $port to $ip"
        done

        # Then, add DROP rule for all others
        iptables -A OUTPUT -p "$proto" --dport "$port" -j DROP
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

    mark_rules_changed
    auto_save_if_changed
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

    # Add ACCEPT rules for each DNS server (both UDP and TCP)
    IFS=',' read -ra ips <<< "$ip_list"
    for ip in "${ips[@]}"; do
        ip=$(echo "$ip" | xargs)  # Trim whitespace
        iptables -A OUTPUT -p udp --dport 53 -d "$ip" -j ACCEPT
        iptables -A OUTPUT -p tcp --dport 53 -d "$ip" -j ACCEPT
        print_success "Allowed DNS to $ip"
    done

    # Block all other DNS
    iptables -A OUTPUT -p udp --dport 53 -j DROP
    iptables -A OUTPUT -p tcp --dport 53 -j DROP
    print_success "Blocked DNS to all other destinations"

    mark_rules_changed
    auto_save_if_changed
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

    # Add ACCEPT rules for each mail server
    IFS=',' read -ra ips <<< "$ip_list"
    for ip in "${ips[@]}"; do
        ip=$(echo "$ip" | xargs)  # Trim whitespace
        for port in "${smtp_ports[@]}"; do
            iptables -A OUTPUT -p tcp --dport "$port" -d "$ip" -j ACCEPT
        done
        print_success "Allowed SMTP to $ip"
    done

    # Block all other SMTP
    for port in "${smtp_ports[@]}"; do
        iptables -A OUTPUT -p tcp --dport "$port" -j DROP
    done
    print_success "Blocked SMTP to all other destinations"

    mark_rules_changed
    auto_save_if_changed
    [[ "$INTERACTIVE_MODE" == true ]] && pause
}

# ============================================================================
# NEW: Logging Functions
# ============================================================================

enable_drop_logging() {
    if [[ "$INTERACTIVE_MODE" == true ]]; then
        print_header "Enable Firewall Drop Logging"
        print_info "This will log all dropped packets to syslog/journald."
        print_info "Log prefix: IPTABLES_DROPPED"
        echo ""
    fi

    # Check if logging rules already exist
    if iptables -L INPUT -n | grep -q "IPTABLES_DROPPED"; then
        print_warning "Logging rules already exist. Skipping..."
        [[ "$INTERACTIVE_MODE" == true ]] && pause
        return
    fi

    print_info "Adding logging rules for dropped packets..."

    # Add LOG rules before final DROP (if default policy is DROP)
    # These log packets that would be dropped
    iptables -A INPUT -j LOG --log-prefix "IPTABLES_DROPPED_IN: " --log-level 4
    iptables -A OUTPUT -j LOG --log-prefix "IPTABLES_DROPPED_OUT: " --log-level 4
    iptables -A FORWARD -j LOG --log-prefix "IPTABLES_DROPPED_FWD: " --log-level 4

    print_success "Firewall logging enabled."
    print_info "View logs with: journalctl -k | grep IPTABLES_DROPPED"
    print_info "Or check: /var/log/kern.log or /var/log/messages"

    mark_rules_changed
    auto_save_if_changed
    [[ "$INTERACTIVE_MODE" == true ]] && pause
}

disable_drop_logging() {
    if [[ "$INTERACTIVE_MODE" == true ]]; then
        print_header "Disable Firewall Drop Logging"
        echo ""
    fi

    print_info "Removing logging rules..."

    # Remove LOG rules containing our prefix
    iptables -L INPUT --line-numbers -n | grep "IPTABLES_DROPPED" | awk '{print $1}' | sort -rn | while read -r line_num; do
        iptables -D INPUT "$line_num" 2>/dev/null || true
    done

    iptables -L OUTPUT --line-numbers -n | grep "IPTABLES_DROPPED" | awk '{print $1}' | sort -rn | while read -r line_num; do
        iptables -D OUTPUT "$line_num" 2>/dev/null || true
    done

    iptables -L FORWARD --line-numbers -n | grep "IPTABLES_DROPPED" | awk '{print $1}' | sort -rn | while read -r line_num; do
        iptables -D FORWARD "$line_num" 2>/dev/null || true
    done

    print_success "Firewall logging disabled."

    mark_rules_changed
    auto_save_if_changed
    [[ "$INTERACTIVE_MODE" == true ]] && pause
}

# ============================================================================
# CLI Argument Parsing
# ============================================================================

show_help() {
    cat << 'EOF'
Network Isolation Script using iptables
Part of Incident Response Toolkit

Usage:
  Interactive mode: sudo ./network_isolate_iptables.sh
  CLI mode:         sudo ./network_isolate_iptables.sh [OPTIONS]

CLI Options:
  --allow-port-from <port> <ip>         Allow inbound port from specific IP
  --block-port-except-from <port> <ips> Block inbound port except from IPs (comma-separated)
  --allow-port-to <port> <ip>           Allow outbound port to specific IP
  --block-port-except-to <port> <ips>   Block outbound port except to IPs (comma-separated)
  --block-port-in <port>                Block inbound port (TCP+UDP)
  --block-port-out <port>               Block outbound port (TCP+UDP)
  --restrict-dns <ips>                  Restrict outbound DNS to resolvers (comma-separated)
  --restrict-smtp <ips>                 Restrict outbound SMTP to servers (comma-separated)
  --enable-logging                      Enable firewall drop logging
  --disable-logging                     Disable firewall drop logging
  --save                                Manually save rules
  --help                                Show this help message

Examples:
  # Restrict SSH to management IP
  sudo ./network_isolate_iptables.sh --allow-port-from 22 10.1.2.3
  sudo ./network_isolate_iptables.sh --block-port-except-from 22 10.1.2.3,10.1.2.4

  # Block outbound SMB and RDP
  sudo ./network_isolate_iptables.sh --block-port-out 445
  sudo ./network_isolate_iptables.sh --block-port-out 3389

  # Restrict DNS to approved resolvers
  sudo ./network_isolate_iptables.sh --restrict-dns 8.8.8.8,8.8.4.4,1.1.1.1

  # Restrict SMTP to mail server
  sudo ./network_isolate_iptables.sh --restrict-smtp 10.0.0.25

  # Enable logging
  sudo ./network_isolate_iptables.sh --enable-logging

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
                iptables -A INPUT -p tcp --dport "$2" -j DROP
                iptables -A INPUT -p udp --dport "$2" -j DROP
                print_success "Blocked inbound port $2 (TCP+UDP)"
                mark_rules_changed
                shift 2
                ;;
            --block-port-out)
                if [[ -z "$2" ]]; then
                    print_error "--block-port-out requires <port>"
                    exit 1
                fi
                validate_port "$2" || exit 1
                iptables -A OUTPUT -p tcp --dport "$2" -j DROP
                iptables -A OUTPUT -p udp --dport "$2" -j DROP
                print_success "Blocked outbound port $2 (TCP+UDP)"
                mark_rules_changed
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
            --save)
                save_rules
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                print_info "Use --help for usage information"
                exit 1
                ;;
        esac
    done

    # Auto-save at end if rules changed
    auto_save_if_changed
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
    echo -e "${BLUE}                         iptables Network Isolation Tool${NC}"
    echo -e "${BLUE}                           Incident Response Toolkit${NC}"
    echo ""
    echo -e "${YELLOW}=================================================================================${NC}"
    echo -e "${GREEN} BASIC OPERATIONS${NC}"
    echo -e "  ${GREEN}1)${NC}  Show current iptables rules"
    echo -e "  ${GREEN}2)${NC}  Show open ports and services"
    echo -e "  ${GREEN}3)${NC}  Block a specific port"
    echo -e "  ${GREEN}4)${NC}  Block a specific IP address"
    echo -e "  ${GREEN}5)${NC}  Allow a specific port"
    echo -e "  ${GREEN}6)${NC}  Allow a specific IP address"
    echo ""
    echo -e "${RED} EMERGENCY ISOLATION${NC}"
    echo -e "  ${RED}7)${NC}  Block all incoming traffic"
    echo -e "  ${RED}8)${NC}  Block all outgoing traffic"
    echo -e "  ${YELLOW}9)${NC}  Reset iptables (allow all)"
    echo ""
    echo -e "${CYAN} INTERFACE CONTROL${NC}"
    echo -e "  ${RED}10)${NC} Take down network interface"
    echo -e "  ${GREEN}11)${NC} Bring up network interface"
    echo -e "  ${GREEN}12)${NC} Show network interfaces"
    echo ""
    echo -e "${BLUE} ADVANCED ACCESS CONTROL${NC}"
    echo -e "  ${GREEN}13)${NC} Allow port from specific IP (admin access)"
    echo -e "  ${GREEN}14)${NC} Block port except from IPs (whitelist inbound)"
    echo -e "  ${GREEN}15)${NC} Allow port to specific IP (outbound control)"
    echo -e "  ${GREEN}16)${NC} Block port except to IPs (whitelist outbound)"
    echo ""
    echo -e "${BLUE} SERVICE RESTRICTIONS${NC}"
    echo -e "  ${GREEN}17)${NC} Restrict outbound DNS to approved resolvers"
    echo -e "  ${GREEN}18)${NC} Restrict outbound SMTP to mail servers"
    echo ""
    echo -e "${BLUE} LOGGING${NC}"
    echo -e "  ${GREEN}19)${NC} Enable firewall drop logging"
    echo -e "  ${YELLOW}20)${NC} Disable firewall drop logging"
    echo ""
    echo -e "  ${CYAN}0)${NC}  Exit"
    echo ""
    echo -e "${YELLOW}=================================================================================${NC}"
    echo ""
}

run_interactive() {
    while true; do
        show_menu
        read -rp "Enter your choice [0-20]: " choice

        case $choice in
            1) show_iptables_rules ;;
            2) show_open_ports ;;
            3) block_port ;;
            4) block_ip ;;
            5) allow_port ;;
            6) allow_ip ;;
            7) block_all_incoming ;;
            8) block_all_outgoing ;;
            9) reset_iptables ;;
            10) take_down_interface ;;
            11) bring_up_interface ;;
            12) show_interfaces ;;
            13) allow_port_from_ip ;;
            14) block_port_except_from ;;
            15) allow_port_to_ip ;;
            16) block_port_except_to ;;
            17) restrict_outbound_dns ;;
            18) restrict_outbound_smtp ;;
            19) enable_drop_logging ;;
            20) disable_drop_logging ;;
            0)
                print_info "Exiting Network Isolation Tool."
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
