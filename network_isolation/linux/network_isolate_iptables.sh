#!/bin/bash
#
# Network Isolation Script using iptables
# Part of Incident Response Toolkit
#
# This script provides an interactive menu for network isolation
# during incident response activities.
#

set -e

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

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
    echo ""
    read -rp "Press Enter to continue..."
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
# Menu Option Functions
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
    echo ""
    echo -e "  ${GREEN}1)${NC}  Show current iptables rules"
    echo -e "  ${GREEN}2)${NC}  Show open ports and services"
    echo -e "  ${GREEN}3)${NC}  Block a specific port"
    echo -e "  ${GREEN}4)${NC}  Block a specific IP address"
    echo -e "  ${GREEN}5)${NC}  Allow a specific port"
    echo -e "  ${GREEN}6)${NC}  Allow a specific IP address"
    echo -e "  ${RED}7)${NC}  Block all incoming traffic (emergency isolation)"
    echo -e "  ${RED}8)${NC}  Block all outgoing traffic (emergency isolation)"
    echo -e "  ${YELLOW}9)${NC}  Reset iptables (allow all)"
    echo -e "  ${RED}10)${NC} Take down network interface"
    echo -e "  ${GREEN}11)${NC} Bring up network interface"
    echo -e "  ${GREEN}12)${NC} Show network interfaces"
    echo -e "  ${CYAN}0)${NC}  Exit"
    echo ""
    echo -e "${YELLOW}=================================================================================${NC}"
    echo ""
}

main() {
    check_root

    while true; do
        show_menu
        read -rp "Enter your choice [0-12]: " choice

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

main "$@"
