---
name: clawguard
description: Scan AI agent skills for security threats — static analysis, LLM semantic analysis, prompt injection, attack chains, and Docker sandbox with honeypot traps.
metadata:
  openclaw:
    requires:
      bins: ["clawguard"]
    install:
      - id: node
        kind: node
        package: "@dribgib/clawguard"
        bins: ["clawguard"]
        label: "Install ClawGuard (npm)"
---

# ClawGuard - Security Scanner for AI Agent Skills

## Quick Start

```bash
# Scan a skill
clawguard scan ./my-skill

# Deep scan (includes semantic LLM analysis)
clawguard scan --deep ./my-skill

# Scan with Docker sandbox + honeypot traps
clawguard sandbox ./my-skill

# Scan all skills in a directory
clawguard scan ./skills/*

# Visualize attack intent graph
clawguard graph ./my-skill

# Interactive config setup
clawguard config
```

## Scan Modes

- **Static Analysis**: 60+ patterns for credential theft, code injection, persistence, obfuscation
- **Semantic Analysis** (`--deep`): LLM-powered intent understanding via Claude/OpenAI/Ollama
- **Sandbox** (`sandbox`): Docker container with honeypot credentials to catch runtime attacks
- **Attack Chains**: Multi-skill combination analysis for coordinated threats
- **Credential Access**: Detects access to ~/.ssh, ~/.aws, API keys, env vars

## Output Formats

```bash
clawguard scan ./skill --format json    # JSON output
clawguard scan ./skill --format text    # Human-readable (default)
```

## Config

Config lives at `~/.config/clawguard/config.json`. Run `clawguard config` for interactive setup.

Set your LLM provider for semantic analysis:
- Anthropic (Claude) — recommended
- OpenAI
- Ollama (local, free)
