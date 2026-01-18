#!/bin/bash
#
# Network Isolation Script using UFW (Uncomplicated Firewall)
# Part of Incident Response Toolkit
#
# This script provides an interactive menu for network isolation
# during incident response activities using UFW.
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

check_ufw() {
    if ! command -v ufw &>/dev/null; then
        print_error "UFW is not installed!"
        print_info "Install it with: sudo apt-get install ufw"
        exit 1
    fi
}

pause() {
    echo ""
    read -rp "Press Enter to continue..."
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
# Menu Option Functions
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
    echo ""
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
    echo -e "  ${RED}11)${NC} Enable default deny incoming"
    echo -e "  ${RED}12)${NC} Enable default deny outgoing"
    echo -e "  ${RED}13)${NC} Take down network interface"
    echo -e "  ${GREEN}14)${NC} Bring up network interface"
    echo -e "  ${CYAN}0)${NC}  Exit"
    echo ""
    echo -e "${YELLOW}=================================================================================${NC}"
    echo ""
}

main() {
    check_root
    check_ufw

    while true; do
        show_menu
        read -rp "Enter your choice [0-14]: " choice

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

main "$@"
