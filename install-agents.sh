#!/bin/bash
#
# Security Agents Installation Script
# Installs Claude Code agent definitions and required security tools
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENTS_DIR="$SCRIPT_DIR/agents"

# Print colored output
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Print banner
print_banner() {
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║          Security Agents for Claude Code                     ║"
    echo "║                   Installation Script                        ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command -v apt-get &> /dev/null; then
            OS="debian"
        elif command -v dnf &> /dev/null; then
            OS="fedora"
        elif command -v pacman &> /dev/null; then
            OS="arch"
        else
            OS="linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
    else
        OS="unknown"
    fi
    info "Detected OS: $OS"
}

# Install agents to Claude Code directory
install_agents() {
    local scope="$1"
    local model_override="$2"
    local target_dir

    if [[ "$scope" == "global" ]]; then
        target_dir="$HOME/.claude/agents"
    else
        target_dir=".claude/agents"
    fi

    info "Installing agents to $target_dir..."
    if [[ "$model_override" != "default" ]]; then
        info "Model override: all agents will use '$model_override'"
    fi

    mkdir -p "$target_dir"

    if [[ ! -d "$AGENTS_DIR" ]]; then
        error "Agents directory not found: $AGENTS_DIR"
        exit 1
    fi

    local count=0
    for agent_file in "$AGENTS_DIR"/*.md; do
        if [[ -f "$agent_file" && "$(basename "$agent_file")" != "README.md" ]]; then
            local basename=$(basename "$agent_file")
            if [[ "$model_override" == "default" ]]; then
                # Copy as-is
                cp "$agent_file" "$target_dir/"
            else
                # Replace model line with override
                sed "s/^model: .*/model: $model_override/" "$agent_file" > "$target_dir/$basename"
            fi
            count=$((count + 1))
        fi
    done

    success "Installed $count agent definitions to $target_dir"
}

# Install core tools (apt-based)
install_core_tools_apt() {
    info "Installing core security tools via apt..."

    sudo apt-get update

    # Core tools
    local packages=(
        nmap
        netcat-openbsd
        tcpdump
        tshark
        binutils
        binwalk
        gdb
        ltrace
        strace
        whois
        dnsutils
        curl
        wget
        jq
    )

    for pkg in "${packages[@]}"; do
        if dpkg -l "$pkg" &> /dev/null; then
            success "$pkg already installed"
        else
            info "Installing $pkg..."
            sudo apt-get install -y "$pkg" || warn "Failed to install $pkg"
        fi
    done
}

# Install core tools (homebrew)
install_core_tools_brew() {
    info "Installing core security tools via Homebrew..."

    if ! command -v brew &> /dev/null; then
        error "Homebrew not found. Install from https://brew.sh"
        return 1
    fi

    local packages=(
        nmap
        netcat
        tcpdump
        wireshark
        binutils
        binwalk
        gdb
        whois
        curl
        wget
        jq
    )

    for pkg in "${packages[@]}"; do
        if brew list "$pkg" &> /dev/null; then
            success "$pkg already installed"
        else
            info "Installing $pkg..."
            brew install "$pkg" || warn "Failed to install $pkg"
        fi
    done
}

# Prompt for Python environment
prompt_python_env() {
    local default_venv="$HOME/.venvs/security-tools"

    echo ""
    info "Python environment setup"
    echo ""
    echo "Python tools require a virtual environment. Options:"
    echo ""
    echo "  1) Use existing environment (provide path)"
    echo "  2) Create new venv at $default_venv"
    echo "  3) Create new venv at custom location"
    echo "  4) Skip Python tools"
    echo ""

    read -p "Choose option [1-4]: " choice

    case "$choice" in
        1)
            read -p "Enter path to existing Python environment: " PYTHON_ENV
            if [[ ! -f "$PYTHON_ENV/bin/activate" && ! -f "$PYTHON_ENV/bin/python" ]]; then
                error "Invalid environment: $PYTHON_ENV (no bin/activate or bin/python found)"
                return 1
            fi
            ;;
        2)
            PYTHON_ENV="$default_venv"
            create_python_venv "$PYTHON_ENV"
            ;;
        3)
            read -p "Enter path for new venv: " PYTHON_ENV
            create_python_venv "$PYTHON_ENV"
            ;;
        4)
            info "Skipping Python tools installation"
            PYTHON_ENV=""
            return 1
            ;;
        *)
            error "Invalid choice"
            return 1
            ;;
    esac

    success "Using Python environment: $PYTHON_ENV"
    return 0
}

# Create Python virtual environment
create_python_venv() {
    local venv_path="$1"

    # Check if micromamba is available
    if command -v micromamba &> /dev/null; then
        info "micromamba detected. Use micromamba or standard venv?"
        echo "  1) micromamba (conda-compatible)"
        echo "  2) python venv (standard)"
        read -p "Choose [1-2]: " env_type

        if [[ "$env_type" == "1" ]]; then
            create_micromamba_env "$venv_path"
            return $?
        fi
    fi

    # Standard venv
    create_standard_venv "$venv_path"
}

# Create standard Python venv
create_standard_venv() {
    local venv_path="$1"

    info "Creating Python venv at $venv_path..."

    # Find Python
    local python_cmd=""
    for cmd in python3.12 python3.11 python3.10 python3; do
        if command -v "$cmd" &> /dev/null; then
            python_cmd="$cmd"
            break
        fi
    done

    if [[ -z "$python_cmd" ]]; then
        error "Python 3 not found. Install Python 3.10+ first."
        return 1
    fi

    local python_version=$($python_cmd --version 2>&1 | grep -oP '\d+\.\d+')
    info "Using $python_cmd (version $python_version)"

    # Create parent directory
    mkdir -p "$(dirname "$venv_path")"

    # Create venv
    $python_cmd -m venv "$venv_path" || {
        error "Failed to create venv"
        return 1
    }

    # Upgrade pip
    "$venv_path/bin/pip" install --upgrade pip

    success "Created venv at $venv_path"
    return 0
}

# Create micromamba environment
create_micromamba_env() {
    local env_path="$1"
    local env_name=$(basename "$env_path")

    info "Creating micromamba environment: $env_name..."

    micromamba create -p "$env_path" python=3.11 -y || {
        error "Failed to create micromamba environment"
        return 1
    }

    success "Created micromamba environment at $env_path"
    return 0
}

# Install Python tools
install_python_tools() {
    info "Installing Python security tools..."

    # If PYTHON_ENV not set, prompt for it
    if [[ -z "$PYTHON_ENV" ]]; then
        prompt_python_env || return 1
    fi

    # Determine pip command
    local pip_cmd=""
    if [[ -f "$PYTHON_ENV/bin/pip" ]]; then
        pip_cmd="$PYTHON_ENV/bin/pip"
    elif [[ -f "$PYTHON_ENV/bin/pip3" ]]; then
        pip_cmd="$PYTHON_ENV/bin/pip3"
    else
        error "pip not found in $PYTHON_ENV"
        return 1
    fi

    info "Using pip: $pip_cmd"

    local packages=(
        bandit
        semgrep
        shodan
        dnspython
        requests
        pwntools
        scapy
    )

    for pkg in "${packages[@]}"; do
        if $pip_cmd show "$pkg" &> /dev/null; then
            success "$pkg already installed"
        else
            info "Installing $pkg..."
            $pip_cmd install "$pkg" || warn "Failed to install $pkg"
        fi
    done

    echo ""
    info "To use these tools, activate the environment:"
    echo "  source $PYTHON_ENV/bin/activate"
    echo ""
    info "Or add to your shell config:"
    echo "  export PATH=\"$PYTHON_ENV/bin:\$PATH\""
    echo ""
}

# Install Go tools
install_go_tools() {
    info "Installing Go security tools..."

    if ! command -v go &> /dev/null; then
        warn "Go not found. Skipping nuclei installation."
        warn "Install Go from https://go.dev/dl/ then run:"
        warn "  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        return 1
    fi

    info "Installing nuclei..."
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
        success "nuclei installed" || warn "Failed to install nuclei"
}

# Install optional offensive tools (apt)
install_offensive_tools_apt() {
    info "Installing offensive security tools..."

    local packages=(
        aircrack-ng
        hashcat
        radare2
        forensics-extra
    )

    for pkg in "${packages[@]}"; do
        if dpkg -l "$pkg" &> /dev/null; then
            success "$pkg already installed"
        else
            info "Installing $pkg..."
            sudo apt-get install -y "$pkg" || warn "Failed to install $pkg"
        fi
    done
}

# Install optional forensics tools (apt)
install_forensics_tools_apt() {
    info "Installing forensics tools..."

    # volatility3 via pip into the Python environment
    if [[ -n "$PYTHON_ENV" && -f "$PYTHON_ENV/bin/pip" ]]; then
        info "Installing volatility3 into $PYTHON_ENV..."
        "$PYTHON_ENV/bin/pip" install volatility3 || warn "Failed to install volatility3"
    elif ! dpkg -l volatility3 &> /dev/null; then
        warn "No Python environment set. Install volatility3 manually:"
        warn "  pip install volatility3"
    fi

    for pkg in sleuthkit autopsy; do
        if dpkg -l "$pkg" &> /dev/null; then
            success "$pkg already installed"
        else
            info "Installing $pkg..."
            sudo apt-get install -y "$pkg" || warn "Failed to install $pkg"
        fi
    done
}

# Print post-install instructions
print_post_install() {
    echo ""
    echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}                    Installation Complete!                       ${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Agent definitions installed. You can now use them in Claude Code:"
    echo ""
    echo "  Example usage:"
    echo "    /red-team-operator Scan the network at 192.168.1.0/24"
    echo "    /source-code-analyzer Review the code in ./src for vulnerabilities"
    echo "    /dfir-investigator Analyze the log file at /var/log/auth.log"
    echo ""
    echo "Available agents:"
    echo "  - android-sast-specialist    - memory-forensics-expert"
    echo "  - blue-team-defender         - network-security-analyst"
    echo "  - bug-bounty-hunter          - red-team-operator"
    echo "  - dfir-investigator          - replay-attack-specialist"
    echo "  - email-security-analyst     - reverse-engineer"
    echo "  - rf-security-expert         - security-developer"
    echo "  - security-reporter          - soc-analyst"
    echo "  - source-code-analyzer       - threat-intelligence-analyst"
    echo "  - vulnerability-validator    - wifi-security-tester"
    echo ""
    echo "To change the model used by agents, reinstall with --model:"
    echo "  $0 --agents-only --global --model opus    # Use Opus for all agents"
    echo "  $0 --agents-only --global --model haiku   # Use Haiku (faster, cheaper)"
    echo ""
    echo "For manual tool installation, see TOOLS.md"
    echo ""
}

# Print usage
print_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --agents-only       Install only agent definitions (no tools)"
    echo "  --global            Install agents globally (~/.claude/agents)"
    echo "  --local             Install agents locally (.claude/agents)"
    echo "  --model MODEL       Set model for all agents (default|opus|sonnet|haiku)"
    echo "                        default = keep each agent's original model"
    echo "                        opus/sonnet/haiku = override all agents"
    echo "  --tools-only        Install only security tools (no agents)"
    echo "  --core-tools        Install core tools only"
    echo "  --all-tools         Install all tools (core + offensive + forensics)"
    echo "  --python-env PATH   Path to Python environment (venv or micromamba)"
    echo "                        If not provided, will prompt interactively"
    echo "  --create-venv PATH  Create a new venv at PATH and use it"
    echo "  --help              Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --agents-only --global              # Install agents with default models"
    echo "  $0 --agents-only --global --model opus # Install agents, all using Opus"
    echo "  $0 --core-tools                        # Install basic security tools"
    echo "  $0 --all-tools --global                # Full installation"
    echo "  $0 --tools-only --python-env ~/.venvs/security  # Use existing venv"
    echo "  $0 --tools-only --create-venv ~/.venvs/security # Create new venv"
    echo ""
}

# Main
main() {
    local install_agents_flag=true
    local install_tools_flag=true
    local agent_scope="global"
    local tools_level="core"
    local model_override="default"
    PYTHON_ENV=""  # Global for use in install_python_tools

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --agents-only)
                install_tools_flag=false
                shift
                ;;
            --tools-only)
                install_agents_flag=false
                shift
                ;;
            --global)
                agent_scope="global"
                shift
                ;;
            --local)
                agent_scope="local"
                shift
                ;;
            --model)
                if [[ -z "$2" || "$2" == --* ]]; then
                    error "--model requires a value (default|opus|sonnet|haiku)"
                    exit 1
                fi
                case "$2" in
                    default|opus|sonnet|haiku)
                        model_override="$2"
                        ;;
                    *)
                        error "Invalid model: $2. Use: default, opus, sonnet, or haiku"
                        exit 1
                        ;;
                esac
                shift 2
                ;;
            --core-tools)
                tools_level="core"
                shift
                ;;
            --all-tools)
                tools_level="all"
                shift
                ;;
            --python-env)
                if [[ -z "$2" || "$2" == --* ]]; then
                    error "--python-env requires a path"
                    exit 1
                fi
                PYTHON_ENV="$2"
                if [[ ! -d "$PYTHON_ENV" ]]; then
                    error "Python environment not found: $PYTHON_ENV"
                    exit 1
                fi
                shift 2
                ;;
            --create-venv)
                if [[ -z "$2" || "$2" == --* ]]; then
                    error "--create-venv requires a path"
                    exit 1
                fi
                PYTHON_ENV="$2"
                create_standard_venv "$PYTHON_ENV" || exit 1
                shift 2
                ;;
            --help|-h)
                print_usage
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                print_usage
                exit 1
                ;;
        esac
    done

    print_banner
    detect_os

    # Install agents
    if [[ "$install_agents_flag" == true ]]; then
        install_agents "$agent_scope" "$model_override"
    fi

    # Install tools
    if [[ "$install_tools_flag" == true ]]; then
        case $OS in
            debian)
                install_core_tools_apt
                install_python_tools
                install_go_tools
                if [[ "$tools_level" == "all" ]]; then
                    install_offensive_tools_apt
                    install_forensics_tools_apt
                fi
                ;;
            macos)
                install_core_tools_brew
                install_python_tools
                install_go_tools
                ;;
            *)
                warn "Automatic tool installation not supported for $OS"
                warn "Please install tools manually. See TOOLS.md"
                install_python_tools
                install_go_tools
                ;;
        esac
    fi

    print_post_install
}

main "$@"
