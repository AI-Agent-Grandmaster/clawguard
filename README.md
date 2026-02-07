# 🛡️ ClawGuard

**Revolutionary security scanner for AI agent skills.**

ClawGuard thinks like an attacker. It uses LLM-powered semantic analysis to catch threats that pattern matching misses — prompt injection, capability abuse, multi-skill attack chains, and more.

## Why ClawGuard?

Existing security tools scan for known patterns. But AI agent attacks are different:
- **Prompt injection** hides in natural language
- **Capability abuse** looks legitimate until you understand intent  
- **Multi-skill chains** combine innocent skills into attacks
- **Social engineering** manipulates the agent, not code

ClawGuard is the first scanner built specifically for agent security.

## Features

### 🔍 Static Analysis
36 patterns detecting:
- Credential theft (`~/.ssh`, `~/.aws`, API keys)
- Code injection (eval, exec, curl|bash)
- Persistence mechanisms (cron, shell configs)
- Obfuscation (base64, hex encoding)

### 🧠 Semantic Analysis (LLM-powered)
Uses Claude to understand:
- Prompt injection and instruction override
- Capability-purpose mismatch ("weather skill reading SSH keys")
- Social engineering and persuasion attacks
- Delayed/conditional attack triggers
- Memory poisoning

### ⛓️ Multi-Skill Attack Chains
Analyzes skill libraries for dangerous combinations:
- Credential access + network = exfiltration
- File read + messaging = data theft  
- Pattern-based AND LLM-powered chain detection

### 🔒 Behavioral Sandbox (Docker)
Runs skills in isolated containers with honeypot traps:
- Plants fake credentials (~/.ssh/id_rsa, ~/.aws/credentials)
- Monitors file access, network activity, command execution
- **Definitive proof** of credential theft when honeypots are accessed
- Catches attacks that only manifest at runtime

### 🍯 Credential Access Detection
Scans for access to sensitive paths:
- SSH keys, AWS credentials, API tokens
- Environment variables, dotfiles
- Generates honeypot recommendations

### 📊 Intent Graphs
Visualizes data flow through skills:
- ASCII or Mermaid diagram output
- Shows sources, sinks, and transforms

## Installation

```bash
npm install -g clawguard
```

## Quick Start

```bash
# Configure AI provider (one-time)
clawguard config

# Scan a single skill (semantic analysis runs automatically if configured)
clawguard scan ./my-skill

# Fast scan (static only, skip semantic)
clawguard scan ./my-skill --fast

# Scan entire skill library for attack chains
clawguard library ~/.openclaw/skills

# Full audit (static + semantic + honeypot + graph)
clawguard full ./my-skill
```

## Commands

| Command | Description |
|---------|-------------|
| `scan <path>` | Scan single skill |
| `library <path>` | Analyze skill library for attack chains |
| `honeypot <path>` | Scan for credential access patterns |
| `graph <path>` | Generate intent/data flow graph |
| `full <path>` | Run all analyzers |
| `config` | Configure AI provider and API key |

### Scan Options

```bash
clawguard scan <path> [options]

Options:
  -s, --sandbox     Run behavioral sandbox with honeypots (requires Docker)
  -f, --fast        Static analysis only (skip semantic)
  -d, --deep        Deep dependency source analysis
  -o, --output      Output format: md, json (default: md)
  -v, --verbose     Verbose output
```

**Note:** Semantic analysis runs automatically when configured. Use `--fast` to skip it.

### Sandbox Detection

When `--sandbox` is enabled, ClawGuard:
1. Builds an isolated Docker container
2. Plants honeypot credential files
3. Executes the skill's scripts
4. Monitors for credential access, network exfil, dangerous commands

If the skill touches honeypot files → **definitive proof of malicious intent**.

### Library Options

```bash
clawguard library <path> [options]

Options:
  -f, --fast        Pattern analysis only (skip semantic)
  -o, --output      Output format: md, json
  -v, --verbose     Verbose output
```

## Configuration

```bash
# Interactive setup
clawguard config

# Show current config
clawguard config --show

# Test API connection
clawguard config --test

# Clear config
clawguard config --clear
```

### Supported Providers

| Provider | Models |
|----------|--------|
| Anthropic | Claude Opus 4, Sonnet 4, Haiku 3.5 |
| OpenAI | GPT-4o, GPT-4o Mini, GPT-4 Turbo |
| Local | Ollama (Llama 3, Mixtral, etc.) |

Config stored in `~/.config/clawguard/config.json`

## Output Example

```
# ClawGuard Security Report

## Skill: suspicious-helper
**Risk Level:** ⛔ **CRITICAL** (100/100)

### ⛔ Critical Findings

#### T-SEMANTIC-CAPABILITY_MISMATCH: Capability-Purpose Mismatch
This skill's stated purpose ("A helpful assistant") doesn't match 
its actual capabilities: credential_theft, data_exfiltration

**Remediation:** DO NOT INSTALL. This is malicious software.
```

## Attack Chain Detection

ClawGuard detects when multiple skills combine to form attacks:

```
⛔ Attack Chain: Credential Staging Pipeline
   Skills: notes-manager → daily-digest
   
   Combines legitimate-looking file reading with legitimate-looking 
   messaging to create a complete credential theft pipeline.
   Both skills appear helpful individually.
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Safe - no issues found |
| 1 | High risk findings |
| 2 | Critical risk findings |

## Development

```bash
git clone https://github.com/mikecavallo/clawguard
cd clawguard
npm install
npm run build
npm run test
```

## License

MIT

---

Built for the agent internet. 🦞
