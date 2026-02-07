#!/usr/bin/env node
/**
 * ClawGuard Interactive TUI
 * 
 * Full-screen terminal interface for security scanning.
 */

import { createInterface } from 'readline';
import { stat } from 'fs/promises';
import { join } from 'path';
import { glob } from 'glob';
import { createOrchestrator } from './orchestrator.js';
import { formatResult } from './report.js';
import { loadConfig, runSetupWizard, isConfigured } from './config.js';
import { checkKnownBad, calculateSkillHash, reportMalicious } from './database.js';

// ANSI color codes
const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const BLUE = '\x1b[34m';
const MAGENTA = '\x1b[35m';
const CYAN = '\x1b[36m';
const WHITE = '\x1b[37m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const RESET = '\x1b[0m';
const BG_RED = '\x1b[41m';
const BG_BLACK = '\x1b[40m';

const BANNER = `
${RED}${BOLD}
   ██████╗██╗      █████╗ ██╗    ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
  ██╔════╝██║     ██╔══██╗██║    ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
  ██║     ██║     ███████║██║ █╗ ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
  ██║     ██║     ██╔══██║██║███╗██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
  ╚██████╗███████╗██║  ██║╚███╔███╔╝╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
   ╚═════╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
${RESET}
${DIM}  Revolutionary Security Scanner for AI Agent Skills${RESET}
${DIM}  ─────────────────────────────────────────────────${RESET}
`;

const MENU = `
${CYAN}${BOLD}  What would you like to do?${RESET}

  ${WHITE}[1]${RESET} ${GREEN}Scan local skill(s)${RESET}      - Scan skills on your machine
  ${WHITE}[2]${RESET} ${GREEN}Scan skill from URL${RESET}      - Fetch and scan a remote skill
  ${WHITE}[3]${RESET} ${GREEN}Check known-bad database${RESET} - See if a skill is flagged
  ${WHITE}[4]${RESET} ${YELLOW}Configure AI provider${RESET}   - Set up semantic analysis
  ${WHITE}[5]${RESET} ${BLUE}View scan history${RESET}        - Recent scan results
  ${WHITE}[q]${RESET} ${DIM}Quit${RESET}

`;

interface PromptInterface {
  ask: (question: string) => Promise<string>;
  close: () => void;
}

function createPrompt(): PromptInterface {
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout
  });

  return {
    ask: (question: string) => new Promise((resolve) => {
      rl.question(question, (answer) => resolve(answer.trim()));
    }),
    close: () => rl.close()
  };
}

function clearScreen(): void {
  process.stdout.write('\x1b[2J\x1b[H');
}

function printBanner(): void {
  console.log(BANNER);
}

function printMenu(): void {
  console.log(MENU);
}

/**
 * Scan a single skill with progress output
 */
async function scanSkill(
  skillPath: string, 
  options: { semantic: boolean; sandbox: boolean }
): Promise<void> {
  console.log('');
  console.log(`${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}`);
  console.log(`${BOLD}Scanning:${RESET} ${skillPath}`);
  console.log(`${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}`);
  
  // Check known-bad database first
  console.log(`${DIM}Checking known-bad database...${RESET}`);
  const skillHash = await calculateSkillHash(skillPath);
  const knownBad = await checkKnownBad(skillHash);
  
  if (knownBad.known) {
    console.log('');
    console.log(`${BG_RED}${WHITE}${BOLD} ⛔ KNOWN MALICIOUS SKILL ${RESET}`);
    console.log('');
    console.log(`${RED}This skill is in the known-bad database.${RESET}`);
    console.log(`${RED}Threat: ${knownBad.threat || 'Unknown'}${RESET}`);
    console.log(`${RED}${knownBad.description || 'No additional details.'}${RESET}`);
    console.log('');
    console.log(`${YELLOW}Skipping full scan - this skill should NOT be installed.${RESET}`);
    return;
  }
  
  console.log(`${GREEN}✓${RESET} Not in known-bad database`);
  
  // Run full scan
  console.log(`${DIM}Running security scan...${RESET}`);
  
  const config = await loadConfig();
  const orchestrator = createOrchestrator();
  
  const result = await orchestrator.scan({
    path: skillPath,
    semantic: options.semantic && config.configured,
    sandbox: options.sandbox,
    verbose: false
  });
  
  // Display results
  console.log('');
  const output = formatResult(result, 'md');
  console.log(output);
  
  // If critical findings, offer to report
  if (result.summary.critical > 0) {
    console.log(`${YELLOW}This skill has critical security issues.${RESET}`);
    
    // Auto-report to database
    await reportMalicious(skillHash, JSON.stringify(result.findings.slice(0, 5)));
    console.log(`${DIM}(Reported to known-bad database)${RESET}`);
  }
}

/**
 * Handle local skill scanning
 */
async function handleLocalScan(prompt: PromptInterface): Promise<void> {
  console.log('');
  console.log(`${CYAN}${BOLD}Scan Local Skills${RESET}`);
  console.log(`${DIM}Enter paths to skills (comma-separated or one per line)${RESET}`);
  console.log(`${DIM}Example: ./my-skill, ~/projects/other-skill${RESET}`);
  console.log(`${DIM}Or enter a directory to scan all skills within it${RESET}`);
  console.log('');
  
  const input = await prompt.ask(`${WHITE}Path(s): ${RESET}`);
  
  if (!input) {
    console.log(`${YELLOW}No paths provided.${RESET}`);
    return;
  }
  
  // Parse paths
  const paths = input.split(/[,\n]/).map(p => p.trim()).filter(Boolean);
  
  // Ask about scan options
  console.log('');
  const useSandbox = await prompt.ask(`${WHITE}Run behavioral sandbox? (requires Docker) [y/N]: ${RESET}`);
  const sandbox = useSandbox.toLowerCase() === 'y';
  
  const config = await loadConfig();
  const semantic = config.configured;
  
  if (semantic) {
    console.log(`${GREEN}✓${RESET} Semantic analysis enabled (${config.provider}/${config.model})`);
  } else {
    console.log(`${YELLOW}ℹ${RESET} Semantic analysis disabled (run option 4 to configure)`);
  }
  
  // Scan each path
  for (const path of paths) {
    try {
      const pathStat = await stat(path);
      
      if (pathStat.isDirectory()) {
        // Check if it's a skill (has SKILL.md)
        try {
          await stat(join(path, 'SKILL.md'));
          // It's a skill
          await scanSkill(path, { semantic, sandbox });
        } catch {
          // Not a skill, look for skills inside
          const skillMds = await glob('*/SKILL.md', { cwd: path });
          
          if (skillMds.length === 0) {
            console.log(`${YELLOW}No skills found in ${path}${RESET}`);
          } else {
            console.log(`${CYAN}Found ${skillMds.length} skills in ${path}${RESET}`);
            for (const skillMd of skillMds) {
              const skillPath = join(path, skillMd.replace('/SKILL.md', ''));
              await scanSkill(skillPath, { semantic, sandbox });
            }
          }
        }
      } else {
        console.log(`${YELLOW}${path} is not a directory${RESET}`);
      }
    } catch (error) {
      console.log(`${RED}Error accessing ${path}: ${(error as Error).message}${RESET}`);
    }
  }
}

/**
 * Handle URL scanning
 */
async function handleUrlScan(prompt: PromptInterface): Promise<void> {
  console.log('');
  console.log(`${CYAN}${BOLD}Scan Skill from URL${RESET}`);
  console.log(`${DIM}Enter a URL to a skill (GitHub repo, tar.gz, etc.)${RESET}`);
  console.log('');
  
  const url = await prompt.ask(`${WHITE}URL: ${RESET}`);
  
  if (!url) {
    console.log(`${YELLOW}No URL provided.${RESET}`);
    return;
  }
  
  console.log(`${DIM}Fetching skill from ${url}...${RESET}`);
  
  // TODO: Implement URL fetching
  // For now, show placeholder
  console.log(`${YELLOW}URL scanning coming soon!${RESET}`);
  console.log(`${DIM}For now, clone the repo locally and use option 1.${RESET}`);
}

/**
 * Handle database check
 */
async function handleDatabaseCheck(prompt: PromptInterface): Promise<void> {
  console.log('');
  console.log(`${CYAN}${BOLD}Check Known-Bad Database${RESET}`);
  console.log(`${DIM}Enter a skill path or hash to check${RESET}`);
  console.log('');
  
  const input = await prompt.ask(`${WHITE}Path or hash: ${RESET}`);
  
  if (!input) {
    console.log(`${YELLOW}No input provided.${RESET}`);
    return;
  }
  
  let hash: string;
  
  if (input.match(/^[a-f0-9]{64}$/i)) {
    // It's already a hash
    hash = input.toLowerCase();
  } else {
    // Calculate hash from path
    console.log(`${DIM}Calculating skill hash...${RESET}`);
    try {
      hash = await calculateSkillHash(input);
      console.log(`${DIM}Hash: ${hash}${RESET}`);
    } catch (error) {
      console.log(`${RED}Error reading skill: ${(error as Error).message}${RESET}`);
      return;
    }
  }
  
  console.log(`${DIM}Checking database...${RESET}`);
  const result = await checkKnownBad(hash);
  
  if (result.known) {
    console.log('');
    console.log(`${BG_RED}${WHITE}${BOLD} ⛔ KNOWN MALICIOUS ${RESET}`);
    console.log(`${RED}Threat: ${result.threat || 'Unknown'}${RESET}`);
    console.log(`${RED}${result.description || 'No additional details.'}${RESET}`);
  } else {
    console.log('');
    console.log(`${GREEN}✓ Not in known-bad database${RESET}`);
    console.log(`${DIM}This doesn't mean it's safe - run a full scan to be sure.${RESET}`);
  }
}

/**
 * Handle configuration
 */
async function handleConfigure(): Promise<void> {
  await runSetupWizard();
}

/**
 * Main TUI loop
 */
async function main(): Promise<void> {
  const prompt = createPrompt();
  
  // Check if first run
  if (!await isConfigured()) {
    clearScreen();
    printBanner();
    console.log(`${YELLOW}Welcome! Let's set up ClawGuard.${RESET}`);
    console.log('');
    
    const setupNow = await prompt.ask(`${WHITE}Configure AI analysis now? [Y/n]: ${RESET}`);
    if (setupNow.toLowerCase() !== 'n') {
      await runSetupWizard();
    }
  }
  
  // Main loop
  let running = true;
  
  while (running) {
    clearScreen();
    printBanner();
    
    // Show config status
    const config = await loadConfig();
    if (config.configured) {
      console.log(`  ${GREEN}✓${RESET} ${DIM}AI: ${config.provider}/${config.model}${RESET}`);
    } else {
      console.log(`  ${YELLOW}○${RESET} ${DIM}AI analysis not configured${RESET}`);
    }
    
    printMenu();
    
    const choice = await prompt.ask(`${WHITE}  Choice: ${RESET}`);
    
    switch (choice.toLowerCase()) {
      case '1':
        await handleLocalScan(prompt);
        await prompt.ask(`\n${DIM}Press Enter to continue...${RESET}`);
        break;
        
      case '2':
        await handleUrlScan(prompt);
        await prompt.ask(`\n${DIM}Press Enter to continue...${RESET}`);
        break;
        
      case '3':
        await handleDatabaseCheck(prompt);
        await prompt.ask(`\n${DIM}Press Enter to continue...${RESET}`);
        break;
        
      case '4':
        await handleConfigure();
        await prompt.ask(`\n${DIM}Press Enter to continue...${RESET}`);
        break;
        
      case '5':
        console.log(`${YELLOW}Scan history coming soon!${RESET}`);
        await prompt.ask(`\n${DIM}Press Enter to continue...${RESET}`);
        break;
        
      case 'q':
      case 'quit':
      case 'exit':
        running = false;
        break;
        
      default:
        console.log(`${YELLOW}Invalid choice. Please enter 1-5 or q.${RESET}`);
        await prompt.ask(`\n${DIM}Press Enter to continue...${RESET}`);
    }
  }
  
  prompt.close();
  clearScreen();
  console.log(`${DIM}Stay safe. 🛡️${RESET}`);
  console.log('');
}

// Run if executed directly
main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});

export { main as runTui };
