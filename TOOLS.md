# Security Tools - Installation Guide

This document lists the security tools used by the Claude Code agents. These are standard security tools that can be invoked via bash.

## Core Security Scanning Tools

| Tool | Purpose | Installation |
|------|---------|--------------|
| **nmap** | Network scanning & port enumeration | `sudo apt install nmap` |
| **nuclei** | Vulnerability scanner (10,200+ templates) | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| **semgrep** | Multi-language SAST | `pip install semgrep` or `brew install semgrep` |
| **bandit** | Python security linter | `pip install bandit` |

## Reverse Engineering & Binary Analysis

| Tool | Purpose | Installation |
|------|---------|--------------|
| **ghidra** | Disassembly/decompilation | Download from [ghidra-sre.org](https://ghidra-sre.org) |
| **radare2** | CLI binary analysis | `sudo apt install radare2` or `brew install radare2` |
| **binwalk** | Firmware extraction | `sudo apt install binwalk` |
| **strings** | Extract text from binaries | `sudo apt install binutils` (usually pre-installed) |
| **objdump** | Quick disassembly | `sudo apt install binutils` |
| **hexdump/xxd** | Raw binary visualization | `sudo apt install xxd` (usually pre-installed) |

## Debugging & Dynamic Analysis

| Tool | Purpose | Installation |
|------|---------|--------------|
| **gdb** | Debugger | `sudo apt install gdb` |
| **gef/peda** | GDB enhancements | `pip install gef` or from GitHub |
| **frida** | Dynamic instrumentation | `pip install frida-tools` |
| **ltrace/strace** | Library/syscall tracing | `sudo apt install ltrace strace` |

## Memory & Disk Forensics

| Tool | Purpose | Installation |
|------|---------|--------------|
| **volatility3** | Memory forensics | `pip install volatility3` |
| **autopsy** | Disk forensics GUI | `sudo apt install autopsy` |
| **sleuthkit** | Disk forensics CLI | `sudo apt install sleuthkit` |

## Network Analysis

| Tool | Purpose | Installation |
|------|---------|--------------|
| **tcpdump** | Packet capture | `sudo apt install tcpdump` |
| **tshark** | CLI Wireshark | `sudo apt install tshark` |
| **wireshark** | Packet analysis GUI | `sudo apt install wireshark` |
| **netcat** | Network utility | `sudo apt install netcat-openbsd` |

## WiFi/RF Security

| Tool | Purpose | Installation |
|------|---------|--------------|
| **aircrack-ng** | WiFi security testing | `sudo apt install aircrack-ng` |
| **bettercap** | MITM & wireless attacks | `sudo apt install bettercap` |
| **hackrf_transfer** | SDR tools for HackRF | `sudo apt install hackrf` |

## Password & Credential Testing

| Tool | Purpose | Installation |
|------|---------|--------------|
| **hashcat** | GPU password cracking | `sudo apt install hashcat` |

## Web & Recon

| Tool | Purpose | Installation |
|------|---------|--------------|
| **curl/wget** | HTTP requests | Pre-installed on most systems |
| **shodan** | Internet scanning API | `pip install shodan` + API key |

## Android Analysis

| Tool | Purpose | Installation |
|------|---------|--------------|
| **jadx** | Android APK decompilation | `sudo apt install jadx` or from GitHub |

---

## Quick Install Script (Debian/Ubuntu)

```bash
#!/bin/bash
# Security Tools Installation Script

# Core tools
sudo apt update && sudo apt install -y \
  nmap netcat-openbsd tcpdump tshark \
  binutils binwalk radare2 gdb \
  aircrack-ng hashcat \
  sleuthkit autopsy \
  ltrace strace

# Python tools
pip install bandit semgrep frida-tools volatility3 shodan

# Go tools (requires Go installed)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Ghidra (manual download required)
echo "Download Ghidra manually from https://ghidra-sre.org"
```

## macOS Installation (Homebrew)

```bash
#!/bin/bash
# Security Tools Installation Script for macOS

brew install nmap netcat tcpdump wireshark \
  binutils binwalk radare2 gdb \
  hashcat

# Python tools
pip install bandit semgrep frida-tools volatility3 shodan

# Go tools
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

---

## Tool Categories by Agent

### Red Team Operator
- nmap, netcat, nuclei, curl, wget

### Reverse Engineer
- ghidra, radare2, binwalk, strings, objdump, hexdump

### Memory Forensics Expert
- gdb, gef, frida, volatility3

### DFIR Investigator
- volatility3, autopsy, sleuthkit, strings

### Network Security Analyst
- tcpdump, tshark, wireshark, nmap, netcat

### WiFi Security Tester
- aircrack-ng, bettercap, hashcat

### Source Code Analyzer
- semgrep, bandit

### Vulnerability Validator
- nuclei, nmap, curl

### Android SAST Specialist
- jadx, semgrep

### Email Security Analyst
- DNS tools (built into Python dnspython)

### RF Security Expert
- hackrf_transfer, hackrf_info, hackrf_sweep

---

## API Keys Required

Some tools require API keys to function:

| Tool | Environment Variable | Get Key From |
|------|---------------------|--------------|
| **Shodan** | `SHODAN_API_KEY` | [shodan.io](https://shodan.io) |
| **OpenAI** (deepfake detection) | `OPENAI_API_KEY` | [platform.openai.com](https://platform.openai.com) |

---

## Claude Code Subagent Integration

Since these are standard CLI tools, Claude Code subagents can invoke them via the `Bash` tool. Example agent configuration:

```markdown
---
name: vuln-scanner
description: Runs vulnerability scans using nuclei, semgrep, and bandit
tools: Bash, Read, Grep, Glob
---

You are a vulnerability scanner. Use these tools:
- `nuclei -target <url>` for web vulnerability scanning
- `semgrep scan --config p/security-audit <path>` for code analysis
- `bandit -r <path>` for Python security issues
- `nmap -sV <target>` for service enumeration

Always use non-interactive flags (--batch, -oN, etc.) when available.
```
