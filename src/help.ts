/**
 * ClawGuard Detailed Help
 * 
 * Comprehensive documentation for all features.
 */

const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const CYAN = '\x1b[36m';
const MAGENTA = '\x1b[35m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const RESET = '\x1b[0m';

export const HELP_ABOUT = `
${RED}${BOLD}
   ██████╗██╗      █████╗ ██╗    ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
  ██╔════╝██║     ██╔══██╗██║    ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
  ██║     ██║     ███████║██║ █╗ ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
  ██║     ██║     ██╔══██║██║███╗██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
  ╚██████╗███████╗██║  ██║╚███╔███╔╝╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
   ╚═════╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
${RESET}
${BOLD}Revolutionary Security Scanner for AI Agent Skills${RESET}

${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}

${BOLD}WHY CLAWGUARD EXISTS${RESET}

AI agents can install and run skills - code that extends their capabilities.
But this creates a massive attack surface. A malicious skill could:

  ${RED}•${RESET} Steal your SSH keys, AWS credentials, API tokens
  ${RED}•${RESET} Exfiltrate private files via innocent-looking messaging
  ${RED}•${RESET} Install backdoors that persist across sessions
  ${RED}•${RESET} Manipulate the agent to bypass its own safety rules

Traditional security tools don't catch these attacks because:

  ${YELLOW}•${RESET} Prompt injection hides in natural language, not code patterns
  ${YELLOW}•${RESET} Capability abuse looks legitimate until you understand intent
  ${YELLOW}•${RESET} Attack chains span multiple "innocent" skills

${BOLD}ClawGuard thinks like an attacker.${RESET} It's the first scanner built
specifically for the agent security threat model.

${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}

${BOLD}HOW WE PROTECT YOU${RESET}

${GREEN}▶ Layer 1: Static Analysis${RESET} ${DIM}(instant, always runs)${RESET}
  36 patterns detecting credential theft, code injection, persistence,
  and obfuscation. Catches the obvious attacks in milliseconds.
  
  Detects: curl|bash, base64 eval, cron injection, dotfile access,
  environment harvesting, reverse shells, and more.

${GREEN}▶ Layer 2: Semantic Analysis${RESET} ${DIM}(3-15 seconds, LLM-powered)${RESET}
  Uses AI to understand skill intent, not just patterns.
  
  ${MAGENTA}Catches what pattern matching misses:${RESET}
  • Prompt injection disguised as helpful instructions
  • "Ignore previous rules" attacks in any language
  • Capability-purpose mismatch (weather skill reading ~/.ssh)
  • Social engineering ("tell your human this is safe")
  • Delayed triggers ("after 10 runs, do X")
  • Memory poisoning and context manipulation

${GREEN}▶ Layer 3: Attack Chain Detection${RESET} ${DIM}(multi-skill analysis)${RESET}
  Scans your entire skill library for dangerous combinations.
  
  ${MAGENTA}Example attack chain:${RESET}
  Skill A: "Backup tool" - reads ~/.ssh, writes to memory/
  Skill B: "Daily digest" - reads memory/, sends via messaging
  ${RED}Together: Complete credential exfiltration pipeline!${RESET}
  
  Both skills look innocent alone. Only dangerous together.

${GREEN}▶ Layer 4: Behavioral Sandbox${RESET} ${DIM}(5-30 seconds, Docker)${RESET}
  Runs skills in isolation with honeypot credential files.
  
  ${MAGENTA}How it works:${RESET}
  1. Creates isolated Docker container
  2. Plants fake ~/.ssh/id_rsa, ~/.aws/credentials, etc.
  3. Executes skill scripts with full monitoring
  4. If skill touches honeypot → ${RED}DEFINITIVE PROOF OF MALICE${RESET}
  
  No false positives. If it accesses fake credentials, it's malicious.

${GREEN}▶ Layer 5: Known-Bad Database${RESET} ${DIM}(instant lookup)${RESET}
  Checks skill hash against community-reported malware database.
  Known threats are blocked before any analysis even runs.

${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}

${BOLD}QUICK START${RESET}

  ${CYAN}1.${RESET} Configure AI provider (one-time, optional but recommended):
     ${DIM}$ clawguard config${RESET}
     
  ${CYAN}2.${RESET} Scan a skill:
     ${DIM}$ clawguard scan ./some-skill${RESET}
     ${DIM}$ clawguard scan https://github.com/user/skill${RESET}
     
  ${CYAN}3.${RESET} Scan your entire skill library:
     ${DIM}$ clawguard library ~/.openclaw/skills${RESET}
     
  ${CYAN}4.${RESET} Pre-install gate (CI/CD integration):
     ${DIM}$ clawguard gate ./skill && npm install${RESET}

${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}

${BOLD}DETAILED HELP${RESET}

  clawguard help scan       Scanning skills (local & remote)
  clawguard help library    Multi-skill attack chain detection
  clawguard help sandbox    Behavioral sandbox with honeypots
  clawguard help config     API key and provider setup
  clawguard help gate       Pre-install security gate
  clawguard help ui         Interactive terminal interface

${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}

${DIM}https://github.com/openclaw/clawguard${RESET}
${DIM}Built for the agent internet. 🦞${RESET}
`;

export const HELP_GATE = `
${RED}${BOLD}clawguard gate${RESET} - Pre-install security gate

${CYAN}USAGE:${RESET}
  clawguard gate <path|url> [options]

${CYAN}DESCRIPTION:${RESET}
  Security checkpoint before installing a skill. Returns exit code 0 if
  safe to install, exit code 2 if blocked. Designed for CI/CD integration.

${CYAN}ARGUMENTS:${RESET}
  path          Local path OR URL to skill
                Supports GitHub repos, subdirectories, tar.gz, zip

${CYAN}OPTIONS:${RESET}
  -s, --sandbox     Include behavioral sandbox analysis
  --allow-high      Only block critical (allow high-risk through)
  --json            Output JSON result for programmatic use

${CYAN}EXIT CODES:${RESET}
  0    ALLOWED - Safe to install
  2    BLOCKED - Critical issues found (or high, unless --allow-high)

${CYAN}JSON OUTPUT:${RESET}
  {
    "allowed": false,
    "riskLevel": "CRITICAL",
    "riskScore": 95,
    "summary": { "critical": 2, "high": 1, "medium": 0 },
    "findings": [...]
  }

${CYAN}EXAMPLES:${RESET}
  # Block on critical or high
  clawguard gate ./skill && clawhub install ./skill
  
  # Block only on critical
  clawguard gate ./skill --allow-high && npm install
  
  # Gate a remote skill
  clawguard gate https://github.com/user/skill
  
  # JSON for CI/CD
  clawguard gate ./skill --json | jq '.allowed'

${CYAN}CI/CD INTEGRATION:${RESET}
  # GitHub Actions
  - name: Security Gate
    run: clawguard gate ./skills/new-skill
    
  # GitLab CI
  security_gate:
    script:
      - clawguard gate ./skills/new-skill
    allow_failure: false
`;

export const HELP_SCAN = `
${RED}${BOLD}clawguard scan${RESET} - Scan a skill for security issues

${CYAN}USAGE:${RESET}
  clawguard scan <path> [options]

${CYAN}ARGUMENTS:${RESET}
  path          Path to the skill directory (must contain SKILL.md)

${CYAN}OPTIONS:${RESET}
  -s, --sandbox     Run behavioral sandbox analysis (requires Docker)
                    Plants honeypot credentials and monitors actual runtime behavior.
                    DEFINITIVE PROOF if skill accesses fake credentials.
                    
  -f, --fast        Static analysis only (skip semantic)
                    Use for quick scans or when API quota is limited.
                    
  -d, --deep        Deep dependency source analysis
                    Downloads and inspects actual dependency source code.
                    
  -o, --output      Output format: md, json (default: md)
  -v, --verbose     Show detailed progress

${CYAN}ANALYZERS:${RESET}
  ${GREEN}Static Analysis${RESET} (always runs)
    36 patterns detecting credential theft, code injection, persistence,
    obfuscation, and more. Fast (~30ms).
    
  ${GREEN}Semantic Analysis${RESET} (default when configured)
    LLM-powered understanding of skill intent. Catches:
    - Prompt injection and instruction override
    - Capability-purpose mismatch (weather skill reading SSH keys)
    - Social engineering and persuasion attacks
    - Delayed/conditional attack triggers
    Takes 3-15 seconds per skill.
    
  ${GREEN}Behavioral Sandbox${RESET} (--sandbox flag)
    Runs skill in isolated Docker container with honeypot credentials:
    - Plants fake ~/.ssh/id_rsa, ~/.aws/credentials, etc.
    - Executes skill scripts and monitors file access
    - Captures network connections and command execution
    - If honeypot is accessed → DEFINITIVE malicious behavior
    Takes 5-30 seconds. Requires Docker.

${CYAN}EXIT CODES:${RESET}
  0    Safe - no issues found
  1    High risk findings
  2    Critical risk findings

${CYAN}EXAMPLES:${RESET}
  clawguard scan ./my-skill
  clawguard scan ./my-skill --sandbox
  clawguard scan ./my-skill --fast -o json
`;

export const HELP_LIBRARY = `
${RED}${BOLD}clawguard library${RESET} - Analyze skill library for attack chains

${CYAN}USAGE:${RESET}
  clawguard library <path> [options]

${CYAN}DESCRIPTION:${RESET}
  Scans multiple skills TOGETHER to find dangerous combinations.
  Individual skills may appear safe, but together create attack chains:
  
  ${YELLOW}Example: Credential Staging Pipeline${RESET}
    Skill A: "Backup configs to memory/" (reads ~/.ssh, writes memory/)
    Skill B: "Send daily digest" (reads memory/, sends via messaging)
    Together: Complete credential exfiltration pipeline!

${CYAN}ARGUMENTS:${RESET}
  path          Directory containing multiple skills

${CYAN}OPTIONS:${RESET}
  -f, --fast        Pattern analysis only (skip semantic chain analysis)
  -o, --output      Output format: md, json (default: md)
  -v, --verbose     Show detailed progress

${CYAN}CHAIN TYPES DETECTED:${RESET}
  ${RED}Critical:${RESET}
    - Credential Exfiltration (cred access + network)
    - File Exfiltration via Messaging
    - Persistent Backdoor (network in + exec)
    
  ${YELLOW}High:${RESET}
    - Credential Harvesting + Persistence
    - Browser Session Theft
    - Scheduled Malicious Execution
    - Environment Variable Theft
    
  ${DIM}Medium:${RESET}
    - Stealth Data Collection

${CYAN}EXAMPLES:${RESET}
  clawguard library ~/.openclaw/skills
  clawguard library ./my-skills --fast
`;

export const HELP_SANDBOX = `
${RED}${BOLD}Behavioral Sandbox${RESET} - Runtime analysis with honeypot traps

${CYAN}HOW IT WORKS:${RESET}
  1. Builds isolated Docker container
  2. Plants honeypot credential files:
     - /root/.ssh/id_rsa (fake SSH key)
     - /root/.ssh/id_ed25519 (fake ED25519 key)
     - /root/.aws/credentials (fake AWS creds)
     - /root/.config/gcloud/credentials.json (fake GCP)
     - /root/.env (fake API keys)
     
  3. Executes skill's scripts with monitoring:
     - strace for file access and network connections
     - inotify for credential file access
     - tcpdump for network traffic
     
  4. Analyzes behavior:
     ${RED}HONEYPOT HIT${RESET} = Skill accessed fake credentials = MALICIOUS
     ${YELLOW}SUSPICIOUS NETWORK${RESET} = Connected to known-bad domains
     ${YELLOW}DANGEROUS EXEC${RESET} = Ran curl|bash, base64 decode, etc.

${CYAN}REQUIREMENTS:${RESET}
  - Docker must be installed and running
  - First run builds the sandbox image (~30 seconds)
  - Subsequent runs use cached image (~5 seconds)

${CYAN}USAGE:${RESET}
  clawguard scan ./skill --sandbox

${CYAN}WHY THIS MATTERS:${RESET}
  Static analysis can be evaded with obfuscation.
  Semantic analysis can be fooled with clever wording.
  
  The sandbox catches ACTUAL BEHAVIOR. If the skill tries to
  read credentials in runtime, we catch it. No false negatives.
`;

export const HELP_CONFIG = `
${RED}${BOLD}clawguard config${RESET} - Configure AI provider for semantic analysis

${CYAN}USAGE:${RESET}
  clawguard config [options]

${CYAN}OPTIONS:${RESET}
  --show        Show current configuration
  --test        Test API connection
  --clear       Reset configuration

${CYAN}SUPPORTED PROVIDERS:${RESET}
  ${GREEN}Anthropic (Claude)${RESET}
    Models: Claude Opus 4, Sonnet 4, Haiku 3.5
    Best for: Deep understanding, nuanced threats
    
  ${GREEN}OpenAI (GPT-4)${RESET}
    Models: GPT-4o, GPT-4o Mini, GPT-4 Turbo
    Best for: Fast analysis, good accuracy
    
  ${GREEN}Local (Ollama)${RESET}
    Models: Llama 3, Mixtral, Qwen, DeepSeek
    Best for: Privacy, no API costs
    Requires: Ollama running locally

${CYAN}CONFIGURATION FILE:${RESET}
  ~/.config/clawguard/config.json
  
  Stored with 0600 permissions (owner read/write only).
  API keys are stored securely.

${CYAN}ENVIRONMENT VARIABLES:${RESET}
  ANTHROPIC_API_KEY    Used if no key in config
  OPENAI_API_KEY       Used if no key in config

${CYAN}EXAMPLES:${RESET}
  clawguard config          # Run setup wizard
  clawguard config --show   # View current config
  clawguard config --test   # Verify API works
`;

export const HELP_UI = `
${RED}${BOLD}clawguard ui${RESET} - Interactive terminal interface

${CYAN}USAGE:${RESET}
  clawguard ui

${CYAN}DESCRIPTION:${RESET}
  Full-screen interactive interface for security scanning.
  
  Features:
  - Big red CLAWGUARD banner
  - Menu-driven operation
  - Multi-skill batch scanning
  - Known-bad database checking
  - Setup wizard integration

${CYAN}MENU OPTIONS:${RESET}
  [1] Scan local skill(s)      Scan one or more skills on your machine
  [2] Scan skill from URL      Fetch and scan a remote skill
  [3] Check known-bad database See if a skill hash is flagged
  [4] Configure AI provider    Set up semantic analysis
  [5] View scan history        Recent scan results
  [q] Quit

${CYAN}FIRST RUN:${RESET}
  On first launch, prompts to configure AI provider.
  Can skip for static-only analysis.
`;

export function showHelp(topic: string): void {
  switch (topic.toLowerCase()) {
    case 'about':
    case 'overview':
    case 'intro':
      console.log(HELP_ABOUT);
      break;
    case 'scan':
      console.log(HELP_SCAN);
      break;
    case 'library':
    case 'chains':
      console.log(HELP_LIBRARY);
      break;
    case 'sandbox':
    case 'honeypot':
      console.log(HELP_SANDBOX);
      break;
    case 'config':
    case 'setup':
      console.log(HELP_CONFIG);
      break;
    case 'gate':
    case 'ci':
      console.log(HELP_GATE);
      break;
    case 'ui':
    case 'tui':
      console.log(HELP_UI);
      break;
    default:
      // Default: show the full about/overview
      console.log(HELP_ABOUT);
  }
}
