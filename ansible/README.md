# Security Tools - Ansible Playbooks

Ansible playbooks for managing security tools installation across multiple machines.

## Prerequisites

```bash
# Install Ansible
pip install ansible

# Or on Ubuntu/Debian
sudo apt install ansible
```

## Quick Start

```bash
cd ansible

# Install on local machine with defaults
ansible-playbook -i inventory/hosts.yml playbook.yml

# Install with specific tags
ansible-playbook -i inventory/hosts.yml playbook.yml --tags "core,python,agents"

# Install everything
ansible-playbook -i inventory/hosts.yml playbook.yml \
  -e "install_reverse_engineering=true" \
  -e "install_forensics=true" \
  -e "install_wireless=true" \
  -e "install_offensive=true"
```

## Directory Structure

```
ansible/
├── playbook.yml              # Main playbook
├── inventory/
│   └── hosts.yml             # Target hosts
└── group_vars/
    ├── all.yml               # Global defaults
    ├── workstations.yml      # Workstation config
    ├── security_labs.yml     # Full lab config
    └── kali.yml              # Kali Linux config
```

## Configuration

### Tool Categories

Control which tools are installed via variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `install_core` | true | nmap, tcpdump, netcat, tshark, etc. |
| `install_python` | true | bandit, semgrep, shodan, pwntools, scapy |
| `install_go` | true | nuclei vulnerability scanner |
| `install_reverse_engineering` | false | radare2, binwalk, gdb, frida |
| `install_forensics` | false | volatility, sleuthkit, autopsy |
| `install_wireless` | false | aircrack-ng, reaver, mdk4 |
| `install_offensive` | false | hashcat, hydra, john, sqlmap |
| `install_claude_agents` | true | Claude Code agent definitions |

### Override Variables

```bash
# Enable forensics tools
ansible-playbook playbook.yml -e "install_forensics=true"

# Multiple overrides
ansible-playbook playbook.yml \
  -e "install_forensics=true" \
  -e "install_reverse_engineering=true"
```

## Inventory Configuration

### Local Installation

Default configuration installs on localhost:

```yaml
all:
  hosts:
    localhost:
      ansible_connection: local
```

### Remote Hosts

Add remote machines to `inventory/hosts.yml`:

```yaml
all:
  children:
    security_labs:
      hosts:
        lab1:
          ansible_host: 192.168.1.100
          ansible_user: analyst
        lab2:
          ansible_host: 192.168.1.101
          ansible_user: analyst
```

Then run:

```bash
ansible-playbook -i inventory/hosts.yml playbook.yml --limit security_labs
```

## Tags

Use tags to run specific parts:

```bash
# Only install core tools
ansible-playbook playbook.yml --tags core

# Only install Python tools
ansible-playbook playbook.yml --tags python

# Install agents only
ansible-playbook playbook.yml --tags agents

# Multiple tags
ansible-playbook playbook.yml --tags "core,python,agents"
```

Available tags:
- `core` - Core security tools
- `python` - Python packages
- `go` - Go tools (nuclei)
- `reversing` - Reverse engineering tools
- `forensics` - Forensics tools
- `wireless` - Wireless security tools
- `offensive` - Offensive security tools
- `agents` - Claude Code agents

## Host Groups

Pre-configured host groups with appropriate tool sets:

### workstations
Standard analyst workstations - core tools + RE

### security_labs
Full security lab setup - all tools enabled

### kali
Kali Linux machines - only tools not pre-installed

## Examples

### Setup New Workstation

```bash
ansible-playbook -i inventory/hosts.yml playbook.yml \
  --limit workstations
```

### Setup Security Lab

```bash
ansible-playbook -i inventory/hosts.yml playbook.yml \
  --limit security_labs
```

### Install Only Claude Agents

```bash
ansible-playbook -i inventory/hosts.yml playbook.yml \
  --tags agents \
  -e "claude_agents_scope=global"
```

### Check What Would Change (Dry Run)

```bash
ansible-playbook -i inventory/hosts.yml playbook.yml --check --diff
```

## Supported Platforms

- **Debian/Ubuntu** - Full support
- **RHEL/Fedora** - Most tools supported
- **macOS** - Partial support (use Homebrew manually)

## Troubleshooting

### Permission Denied

Run with sudo password:
```bash
ansible-playbook playbook.yml --ask-become-pass
```

### SSH Connection Issues

Test connection first:
```bash
ansible all -i inventory/hosts.yml -m ping
```

### Missing Python

Ensure Python 3 is installed on target:
```bash
ansible all -i inventory/hosts.yml -m raw -a "apt install -y python3"
```
