# Security Agents for Claude Code

This folder contains Claude Code subagent definitions. The agent prompts originate from this repository.

## Installation

Copy these agent files to your Claude Code agents directory:

```bash
# For project-specific agents
mkdir -p .claude/agents
cp agents/*.md .claude/agents/

# OR for global agents (available in all projects)
mkdir -p ~/.claude/agents
cp agents/*.md ~/.claude/agents/
```

## Available Agents

| Agent | Description |
|-------|-------------|
| `android-sast-specialist` | Android APK static analysis and vulnerability discovery |
| `blue-team-defender` | System defense, hardening, and security monitoring |
| `bug-bounty-hunter` | Web application security testing and vulnerability discovery |
| `dfir-investigator` | Digital forensics and incident response |
| `email-security-analyst` | SPF/DKIM/DMARC analysis and email spoofing detection |
| `memory-forensics-expert` | Runtime memory examination and analysis |
| `network-security-analyst` | Network traffic analysis and threat detection |
| `red-team-operator` | Penetration testing and exploitation |
| `replay-attack-specialist` | Network replay attacks and protocol security |
| `reverse-engineer` | Binary analysis and firmware examination |
| `rf-security-expert` | Sub-GHz radio frequency security testing |
| `security-developer` | Security tool and exploit development |
| `security-reporter` | Security assessment report generation |
| `soc-analyst` | Log analysis and security monitoring |
| `source-code-analyzer` | SAST with bandit, semgrep, and manual review |
| `threat-intelligence-analyst` | IOC collection and threat actor profiling |
| `vulnerability-validator` | Vulnerability verification and triage |
| `wifi-security-tester` | Wireless network penetration testing |

## Usage

Once installed, invoke agents using the Task tool or slash commands:

```
# Via slash command
/red-team-operator Scan the target network at 192.168.1.0/24

# Via Task tool (in Claude Code)
Use the dfir-investigator agent to analyze the memory dump at /tmp/memdump.raw
```

## Required Tools

These agents expect certain security tools to be installed. See `TOOLS.md` for installation instructions.

## Agent Categories

### Offensive Security
- `red-team-operator` - General penetration testing
- `bug-bounty-hunter` - Web application testing
- `replay-attack-specialist` - Protocol attacks
- `wifi-security-tester` - Wireless attacks

### Defensive Security
- `blue-team-defender` - System hardening
- `soc-analyst` - Log analysis and monitoring
- `threat-intelligence-analyst` - Threat hunting

### Forensics & Analysis
- `dfir-investigator` - Incident response
- `memory-forensics-expert` - Memory analysis
- `network-security-analyst` - Traffic analysis
- `reverse-engineer` - Binary analysis

### Code & Application Security
- `source-code-analyzer` - SAST scanning
- `android-sast-specialist` - Android security
- `vulnerability-validator` - Finding verification

### Specialized
- `email-security-analyst` - Email security
- `rf-security-expert` - Radio frequency
- `security-developer` - Tool development
- `security-reporter` - Documentation
