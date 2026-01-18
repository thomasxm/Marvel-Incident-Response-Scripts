"""Colored output utilities for terminal display."""
from colorama import init, Fore, Back, Style

# Initialize colorama for cross-platform support
init(autoreset=True)

class Colors:
    """ANSI color codes for terminal output."""
    RED = Fore.RED
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    BLUE = Fore.BLUE
    CYAN = Fore.CYAN
    MAGENTA = Fore.MAGENTA
    WHITE = Fore.WHITE
    RESET = Style.RESET_ALL
    BOLD = Style.BRIGHT

    # Background colors
    BG_RED = Back.RED
    BG_GREEN = Back.GREEN
    BG_YELLOW = Back.YELLOW

def print_header(text: str) -> None:
    """Print a formatted header."""
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}")
    print(f"  {text}")
    print(f"{'='*60}{Colors.RESET}\n")

def print_success(text: str) -> None:
    """Print success message in green."""
    print(f"{Colors.GREEN}[+] {text}{Colors.RESET}")

def print_warning(text: str) -> None:
    """Print warning message in yellow."""
    print(f"{Colors.YELLOW}[!] {text}{Colors.RESET}")

def print_error(text: str) -> None:
    """Print error message in red."""
    print(f"{Colors.RED}[-] {text}{Colors.RESET}")

def print_info(text: str) -> None:
    """Print info message in blue."""
    print(f"{Colors.BLUE}[*] {text}{Colors.RESET}")

def print_anomaly(text: str) -> None:
    """Print anomaly detection in bold red."""
    print(f"{Colors.BOLD}{Colors.RED}[ANOMALY] {text}{Colors.RESET}")

def print_table_header(columns: list) -> None:
    """Print formatted table header."""
    header = " | ".join(f"{col:^15}" for col in columns)
    print(f"{Colors.BOLD}{Colors.WHITE}{header}{Colors.RESET}")
    print(f"{Colors.WHITE}{'-' * len(header)}{Colors.RESET}")

def print_table_row(values: list, highlight: bool = False) -> None:
    """Print formatted table row."""
    row = " | ".join(f"{str(val):^15}" for val in values)
    if highlight:
        print(f"{Colors.YELLOW}{row}{Colors.RESET}")
    else:
        print(row)
