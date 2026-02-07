# ClawGuard Architecture

## Overview

ClawGuard is a comprehensive security scanner for AI agent skills. It analyzes skills across multiple dimensions: static code analysis, dependency auditing, prompt injection detection, and behavioral sandbox testing.

## Design Principles

1. **Defense in Depth** — Multiple detection layers, any one can flag a threat
2. **Fast by Default** — Static analysis runs in <1s per skill, deep scans optional
3. **Actionable Output** — Clear risk ratings, specific findings, remediation hints
4. **Extensible** — New detection rules via config, not code changes
5. **Offline-First** — Core scanning works without network (sandbox optional)

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                           ClawGuard CLI                              │
│                    clawguard scan <path|url>                         │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         Orchestrator                                 │
│              Loads skill, routes to analyzers, aggregates            │
└─────────────────────────────────────────────────────────────────────┘
                                    │
            ┌───────────────────────┼───────────────────────┐
            ▼                       ▼                       ▼
┌─────────────────────┐ ┌─────────────────────┐ ┌─────────────────────┐
│   Static Analyzer   │ │  Dependency Scanner │ │  Prompt Analyzer    │
│                     │ │                     │ │                     │
│ • Pattern matching  │ │ • npm audit deep    │ │ • Injection detect  │
│ • AST parsing       │ │ • pip safety check  │ │ • Hidden instruct   │
│ • Obfuscation det   │ │ • Typosquat check   │ │ • Override patterns │
│ • Encoding detect   │ │ • Source analysis   │ │ • Persona hijack    │
└─────────────────────┘ └─────────────────────┘ └─────────────────────┘
            │                       │                       │
            └───────────────────────┼───────────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    Behavioral Sandbox (Optional)                     │
│        Run skill in isolated container, monitor syscalls/network     │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        Report Generator                              │
│         JSON, Markdown, HTML output with risk scores                 │
└─────────────────────────────────────────────────────────────────────┘
```

## Module Specifications

### 1. CLI & Orchestrator (`src/cli.ts`, `src/orchestrator.ts`)

**Responsibilities:**
- Parse CLI arguments
- Load skill from path or URL
- Route to appropriate analyzers
- Aggregate findings
- Output formatted report

**Interface:**
```typescript
interface ScanOptions {
  path: string;              // Local path or URL
  deep?: boolean;            // Include dep source analysis
  sandbox?: boolean;         // Run behavioral sandbox
  output?: 'json' | 'md' | 'html';
  verbose?: boolean;
}

interface ScanResult {
  skill: SkillMeta;
  findings: Finding[];
  riskScore: number;         // 0-100
  riskLevel: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  scanTime: number;          // ms
  analyzersRun: string[];
}

interface Finding {
  id: string;                // e.g., "T-CODE-002"
  category: string;          // e.g., "code", "supply", "prompt"
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  location?: string;         // file:line
  evidence?: string;         // code snippet
  remediation?: string;
}
```

### 2. Static Analyzer (`src/analyzers/static.ts`)

**Responsibilities:**
- Scan all files in skill directory
- Pattern matching for known bad signatures
- AST parsing for JS/TS/Python
- Detect obfuscation (base64, hex, unicode, eval)
- Identify fetch-and-execute patterns
- Check for persistence mechanisms

**Detection Patterns (from threat model):**
```yaml
patterns:
  # T-CODE-001: Plaintext malicious
  - id: curl-pipe-bash
    pattern: 'curl.*\|.*(?:bash|sh|zsh)'
    severity: critical
    
  # T-CODE-002: Base64 obfuscation
  - id: base64-decode-exec
    pattern: 'base64.*-d.*\|.*(?:bash|sh|python|node)'
    severity: critical
    
  - id: eval-base64
    pattern: 'eval\s*\(\s*(?:atob|Buffer\.from|base64)'
    severity: critical
    
  # T-CODE-003: Fetch and execute
  - id: fetch-eval
    pattern: 'fetch\s*\([^)]+\).*\.then.*eval'
    severity: critical
    
  - id: wget-execute
    pattern: 'wget.*-[qO].*\|'
    severity: high
    
  # T-PERSIST: Persistence
  - id: crontab-write
    pattern: 'crontab|/etc/cron'
    severity: high
    
  - id: bashrc-write
    pattern: '\.bashrc|\.zshrc|\.profile'
    severity: high
    
  - id: ssh-key-access
    pattern: '\.ssh/|id_rsa|authorized_keys'
    severity: critical
```

**AST Checks (JS/TS):**
- `eval()` calls with non-literal arguments
- `Function()` constructor
- `require()` with variable arguments
- Dynamic imports with variable paths
- `child_process` usage patterns
- `fs` operations on sensitive paths

### 3. Dependency Scanner (`src/analyzers/deps.ts`)

**Responsibilities:**
- Parse package.json, requirements.txt, go.mod
- Check against CVE databases
- Typosquatting detection (Levenshtein distance to popular packages)
- Verify package exists on registry
- Check package age, download count, maintainer history
- Optionally: analyze actual dependency source code

**Typosquat Database (popular packages):**
```javascript
const POPULAR_NPM = [
  'lodash', 'express', 'react', 'axios', 'moment', 'request',
  'chalk', 'commander', 'debug', 'async', 'bluebird', 'underscore',
  'uuid', 'mkdirp', 'glob', 'minimist', 'yargs', 'inquirer',
  'dotenv', 'body-parser', 'webpack', 'babel-core', 'typescript',
  'eslint', 'jest', 'mocha', 'cheerio', 'puppeteer', 'socket.io'
];

const POPULAR_PIP = [
  'requests', 'numpy', 'pandas', 'flask', 'django', 'boto3',
  'pillow', 'matplotlib', 'scikit-learn', 'tensorflow', 'torch',
  'beautifulsoup4', 'selenium', 'sqlalchemy', 'celery', 'redis',
  'pyyaml', 'cryptography', 'paramiko', 'fabric', 'ansible'
];
```

**Checks:**
1. Exact name match against known malicious packages
2. Levenshtein distance ≤2 from popular packages = flag
3. Package not found on registry = critical
4. Package <30 days old with low downloads = warning
5. Package maintainer changed recently = warning
6. Install scripts present = flag for review

### 4. Prompt Analyzer (`src/analyzers/prompt.ts`)

**Responsibilities:**
- Parse SKILL.md frontmatter and body
- Detect prompt injection patterns
- Identify override attempts
- Check for hidden instructions (unicode, whitespace, comments)
- Flag persona manipulation
- Detect conditional triggers

**Detection Patterns:**
```yaml
prompt_patterns:
  # T-PROMPT-001: Direct override
  - id: ignore-instructions
    pattern: '(?i)ignore.*(?:previous|above|prior|all).*instructions'
    severity: critical
    
  - id: new-persona
    pattern: '(?i)you are now|from now on you|forget.*you.*were'
    severity: critical
    
  # T-PROMPT-002: Persona manipulation
  - id: jailbreak-dan
    pattern: '(?i)DAN|do anything now|no restrictions'
    severity: high
    
  # T-PROMPT-003: Hidden instructions
  - id: unicode-hiding
    check: containsInvisibleUnicode
    severity: high
    
  - id: excessive-whitespace
    check: hasHiddenWhitespaceBlocks
    severity: medium
    
  # T-PROMPT-004: Conditional triggers
  - id: time-based
    pattern: '(?i)after.*(?:hours|days|date)|when.*(?:time|date)'
    severity: medium
    
  # T-PROMPT-005: Tool abuse instructions
  - id: exfil-instruction
    pattern: '(?i)send.*(?:to|via).*(?:webhook|api|server)|post.*data.*to'
    severity: high
    
  - id: cred-access
    pattern: '(?i)read.*(?:api.?key|token|password|credential|secret)'
    severity: high
```

**Semantic Analysis:**
For sophisticated attacks, use heuristics:
- Instruction sentiment shift (helpful → malicious)
- Unusual capability requests for stated purpose
- References to other users/sessions
- Instructions to hide activity

### 5. Behavioral Sandbox (`src/analyzers/sandbox.ts`)

**Responsibilities:**
- Run skill in isolated Docker container
- Mock OpenClaw agent environment
- Monitor syscalls (via strace/seccomp)
- Capture network traffic
- Log file system access
- Detect unexpected behavior

**Implementation:**
```typescript
interface SandboxConfig {
  timeout: number;           // Max execution time (default 30s)
  networkPolicy: 'none' | 'logged';
  fsPolicy: 'readonly' | 'logged';
  mockTools: boolean;        // Provide mock exec, read, write
}

interface SandboxResult {
  exitCode: number;
  syscalls: SyscallLog[];
  networkConnections: NetworkLog[];
  fileAccess: FileAccessLog[];
  suspiciousActivity: Finding[];
}
```

**Flags:**
- Network connections to non-allowlisted hosts
- File reads outside skill directory (especially ~/.ssh, ~/.aws, etc.)
- Attempts to write to system directories
- Process spawning beyond expected
- High CPU/memory usage (cryptomining)

### 6. Report Generator (`src/report.ts`)

**Output Formats:**

**JSON (machine-readable):**
```json
{
  "skill": { "name": "...", "path": "..." },
  "riskScore": 75,
  "riskLevel": "HIGH",
  "findings": [...],
  "summary": { "critical": 1, "high": 2, "medium": 3, "low": 1 }
}
```

**Markdown (human-readable):**
```markdown
# ClawGuard Security Report

## Skill: example-skill
**Risk Level:** 🔴 HIGH (75/100)

### Critical Findings
- **T-CODE-002**: Base64 obfuscated payload detected
  - Location: scripts/install.sh:15
  - Evidence: `echo "Y3VybC..." | base64 -d | bash`

### Recommendations
1. Remove obfuscated code or provide clear documentation
2. ...
```

## File Structure

```
clawguard/
├── package.json
├── tsconfig.json
├── src/
│   ├── index.ts              # Main entry
│   ├── cli.ts                # CLI argument parsing
│   ├── orchestrator.ts       # Scan coordination
│   ├── types.ts              # Shared interfaces
│   ├── analyzers/
│   │   ├── static.ts         # Static code analysis
│   │   ├── deps.ts           # Dependency scanning
│   │   ├── prompt.ts         # SKILL.md analysis
│   │   └── sandbox.ts        # Behavioral sandbox
│   ├── patterns/
│   │   ├── code.yaml         # Code detection patterns
│   │   ├── deps.yaml         # Known bad packages
│   │   └── prompt.yaml       # Prompt injection patterns
│   ├── report.ts             # Report generation
│   └── utils/
│       ├── ast.ts            # AST parsing helpers
│       ├── levenshtein.ts    # String distance
│       └── registry.ts       # npm/pip registry checks
├── tests/
│   ├── fixtures/             # Test skills (safe and malicious)
│   └── *.test.ts
└── reports/                   # Generated reports
```

## Build Plan

### Phase 3a: Core Infrastructure (Agent 1)
- package.json, tsconfig.json
- src/types.ts
- src/cli.ts
- src/orchestrator.ts
- Basic test harness

### Phase 3b: Static Analyzer (Agent 2)
- src/analyzers/static.ts
- src/patterns/code.yaml
- src/utils/ast.ts
- Tests with malicious fixtures

### Phase 3c: Dependency Scanner (Agent 3)
- src/analyzers/deps.ts
- src/patterns/deps.yaml
- src/utils/levenshtein.ts
- src/utils/registry.ts
- Tests

### Phase 3d: Prompt Analyzer (Agent 4)
- src/analyzers/prompt.ts
- src/patterns/prompt.yaml
- SKILL.md parsing
- Tests

### Phase 3e: Report Generator (Agent 1 or 5)
- src/report.ts
- JSON, Markdown, HTML templates

### Phase 4: Integration
- Wire all modules together
- End-to-end tests
- CLI polish

### Phase 5: Sandbox (Optional/Later)
- Docker integration
- Syscall monitoring
- Network capture

## Usage

```bash
# Install
npm install -g clawguard

# Scan local skill
clawguard scan ./my-skill

# Scan from URL
clawguard scan https://github.com/user/skill

# Deep scan with dependency source analysis
clawguard scan ./my-skill --deep

# Output formats
clawguard scan ./my-skill -o json > report.json
clawguard scan ./my-skill -o md > report.md

# Scan entire ClawHub
clawguard scan-registry clawhub --output ./reports/
```

## Risk Scoring

```
Score = Σ(finding.weight × severity_multiplier)

Severity multipliers:
- critical: 25
- high: 10
- medium: 4
- low: 1

Risk levels:
- 0-10: SAFE
- 11-25: LOW
- 26-50: MEDIUM
- 51-75: HIGH
- 76+: CRITICAL
```

## Dependencies

```json
{
  "dependencies": {
    "commander": "^11.0.0",
    "yaml": "^2.3.0",
    "chalk": "^5.3.0",
    "glob": "^10.3.0",
    "@babel/parser": "^7.23.0",
    "acorn": "^8.11.0",
    "acorn-walk": "^8.3.0"
  },
  "devDependencies": {
    "typescript": "^5.3.0",
    "vitest": "^1.0.0",
    "@types/node": "^20.0.0"
  }
}
```
