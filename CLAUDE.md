# ClawGuard — Project Instructions

## Project Overview
ClawGuard is a security scanner for AI agent skills. It uses multi-layer analysis (static patterns, LLM semantic analysis, dependency scanning, prompt injection detection, attack chain detection, and Docker sandboxing) to catch threats that traditional security tools miss.

- **Package:** `@dribgib/clawguard` on npm (v1.0.1)
- **Repo:** https://github.com/mikecavallo/clawguard
- **Site:** https://mikecavallo.github.io/clawguard/
- **License:** MIT
- **Author:** Mike Cavallo

## Tech Stack
- TypeScript (ES Modules, NodeNext)
- Node.js >= 18
- Commander.js (CLI), Acorn (AST), Chalk (output), YAML (patterns)
- Anthropic SDK (semantic analysis — should become optional)
- Vitest (testing)
- GitHub Pages (site + docs)

## Architecture
```
src/
  cli.ts              — CLI entry point (15 commands, 481 lines — needs splitting)
  orchestrator.ts     — Loads skills, coordinates analyzers, aggregates findings
  types.ts            — Shared interfaces (Finding, ScanResult, RiskLevel, etc.)
  config.ts           — LLM provider config (~/.config/clawguard/config.json)
  report.ts           — Report generation (JSON, Markdown, HTML)
  fetch.ts            — GitHub/URL skill fetching
  database.ts         — Known-bad skill database
  reputation.ts       — Author/skill reputation
  signing.ts          — Cryptographic skill signing
  diff.ts             — Version differential analysis
  monitor.ts          — Continuous monitoring daemon
  dashboard.ts        — Web dashboard
  tui.ts              — Interactive terminal UI
  index.ts            — Library exports
  help.ts             — Help text

  analyzers/
    static.ts         — 60+ code patterns (code.yaml)
    deps.ts           — Dependency/supply chain scanner (deps.yaml)
    prompt.ts         — Prompt injection detection (prompt.yaml)
    semantic.ts       — LLM-powered intent analysis
    chains.ts         — Multi-skill attack chain detection
    semantic-chains.ts — LLM chain analysis
    honeypot.ts       — Credential access patterns
    sandbox.ts        — Docker behavioral sandbox
    intent-graph.ts   — Data flow visualization

  patterns/
    code.yaml         — 60+ code vulnerability patterns
    deps.yaml         — Known malicious packages (100+ npm, 40+ pip, 5+ go)
    prompt.yaml       — 30+ prompt injection patterns

  utils/
    ast.ts            — JS AST parsing (Acorn)
    levenshtein.ts    — String distance for typosquat detection
    registry.ts       — npm/PyPI registry validation

api/server.ts         — Known-bad database REST API (Express)
tests/                — Test suite (currently only deps + prompt tests)
tests/fixtures/       — 10 test skills (malicious + safe)
site/index.html       — Marketing site (GitHub Pages)
docs/index.html       — Documentation site
skill/SKILL.md        — ClawGuard as an installable skill
```

## Key Types
```typescript
type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
type RiskLevel = 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
SEVERITY_WEIGHTS: { critical: 25, high: 10, medium: 4, low: 1, info: 0 }
RISK_THRESHOLDS: { SAFE: 10, LOW: 25, MEDIUM: 50, HIGH: 75 }
```

## Build & Run
```bash
npm run build        # tsc + copy YAML patterns to dist/
npm run dev          # tsc --watch
npm run test         # vitest
npm run lint         # eslint (config currently missing!)
npm run scan         # node dist/cli.js
```

## Current Improvement Plan (Priority Order)

### Quick Wins
1. Remove all OpenClaw references (package.json author, site footer, skill metadata)
2. Fix duplicate SandboxAnalyzer interface in types.ts (lines 104-110)
3. Add ESLint configuration (flat config, TS support)
4. Add CHANGELOG.md and SECURITY.md

### Credibility & Quality
5. Add comprehensive test coverage (static, orchestrator, chains, report, CLI, config, fetch, types)
6. Set up GitHub Actions CI (lint + build + test, Node 18/20/22 matrix)
7. Clean up ARCHITECTURE.md (remove internal build plan phases)

### Security Fixes
8. Support CLAWGUARD_API_KEY env var (avoid --api-key in shell history/ps)
9. Secure the known-bad API (auth on /report, restrict /list, persistent storage)
10. Add input validation and path safety to scan commands

### Architecture
11. Make @anthropic-ai/sdk an optional/dynamic dependency
12. Split cli.ts into src/commands/ directory (one file per command)
13. Add pattern auto-update command (fetch latest YAML from GitHub)

### Growth & Distribution
14. Create GitHub Action for marketplace (clawguard-action)
15. Update GitHub Pages site (fix stats, remove OpenClaw, add new features)
16. Build comprehensive documentation site (docs/)
17. Benchmark against pint-benchmark dataset for accuracy metrics

## Rules
- No OpenClaw references anywhere — this is Mike Cavallo's project
- The site design (terminal green, glassmorphism, particles) should be preserved when updating
- Test everything — this is a security tool, credibility depends on it
- Keep patterns in YAML, not hardcoded
- Support offline-first — core scanning must work without an LLM API key
- Enterprise version exists at ../clawguard-enterprise (SaaS pitch, not active yet)
