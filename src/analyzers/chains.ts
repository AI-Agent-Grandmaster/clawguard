/**
 * ClawGuard Attack Chain Analyzer
 * 
 * Analyzes multiple skills TOGETHER to find dangerous combinations
 * that wouldn't be flagged when analyzing skills in isolation.
 * 
 * Example: weather-skill (network) + notes-skill (file read) = exfil chain
 */

import { readFile } from 'fs/promises';
import { join, basename } from 'path';
import { glob } from 'glob';
import type { Finding, Severity } from '../types.js';

// Capability categories
type Capability = 
  | 'file_read'
  | 'file_write'
  | 'network_out'
  | 'network_in'
  | 'exec'
  | 'messaging'
  | 'browser'
  | 'cron'
  | 'env_access'
  | 'credential_access';

interface SkillCapabilities {
  name: string;
  path: string;
  capabilities: Set<Capability>;
  sensitiveReads: string[];  // Paths it might read
  networkTargets: string[];  // URLs/domains it contacts
  writeTargets: string[];    // Paths it might write
}

// Dangerous capability combinations
const DANGEROUS_CHAINS: Array<{
  name: string;
  requires: Capability[];
  severity: Severity;
  description: string;
  attack: string;
}> = [
  {
    name: 'Credential Exfiltration',
    requires: ['credential_access', 'network_out'],
    severity: 'critical',
    description: 'Skills can read credentials and send them over network',
    attack: 'Skill A reads ~/.ssh/id_rsa, Skill B sends data to external server'
  },
  {
    name: 'File Exfiltration via Messaging',
    requires: ['file_read', 'messaging'],
    severity: 'critical', 
    description: 'Skills can read files and exfiltrate via messaging channels',
    attack: 'Skill A reads sensitive files, Skill B sends them via Discord/Telegram/etc'
  },
  {
    name: 'Persistent Backdoor',
    requires: ['network_in', 'exec'],
    severity: 'critical',
    description: 'Skills can receive commands and execute them',
    attack: 'Skill A listens for commands, Skill B executes arbitrary code'
  },
  {
    name: 'Credential Harvesting + Persistence',
    requires: ['credential_access', 'file_write'],
    severity: 'high',
    description: 'Skills can read credentials and write them to accessible locations',
    attack: 'Skill A reads API keys, Skill B writes them to memory/ for later exfil'
  },
  {
    name: 'Browser Session Theft',
    requires: ['browser', 'network_out'],
    severity: 'high',
    description: 'Skills can control browser and exfiltrate session data',
    attack: 'Skill A has browser access, Skill B can send cookies/tokens externally'
  },
  {
    name: 'Scheduled Malicious Execution',
    requires: ['cron', 'exec'],
    severity: 'high',
    description: 'Skills can schedule and execute arbitrary commands',
    attack: 'Skill A creates cron jobs, Skill B provides malicious payloads'
  },
  {
    name: 'Environment Variable Theft',
    requires: ['env_access', 'messaging'],
    severity: 'high',
    description: 'Skills can read environment variables and leak them',
    attack: 'Skill A reads process.env (API keys, tokens), Skill B messages them out'
  },
  {
    name: 'Stealth Data Collection',
    requires: ['file_read', 'file_write'],
    severity: 'medium',
    description: 'Skills can read sensitive data and stage it for later exfiltration',
    attack: 'Skill A reads files across sessions, Skill B accumulates in memory/'
  }
];

// Patterns to detect capabilities
const CAPABILITY_PATTERNS: Record<Capability, RegExp[]> = {
  file_read: [
    /read\s*\(/i,
    /readFile/i,
    /fs\.read/i,
    /open\s*\([^)]*['"][rR]/,
    /cat\s+/,
    /~\/\./,  // dotfile access
    /\/etc\//,
    /\.ssh/i,
    /\.aws/i,
    /\.env/i,
  ],
  file_write: [
    /write\s*\(/i,
    /writeFile/i,
    /fs\.write/i,
    />>/,
    />\s*[^\s]/,
    /\.bashrc/i,
    /\.zshrc/i,
    /crontab/i,
  ],
  network_out: [
    /fetch\s*\(/i,
    /axios/i,
    /request\s*\(/i,
    /http\.get/i,
    /https\.get/i,
    /curl\s+/i,
    /wget\s+/i,
    /webhook/i,
    /api\./i,
  ],
  network_in: [
    /listen\s*\(/i,
    /createServer/i,
    /express\s*\(/i,
    /socket/i,
  ],
  exec: [
    /exec\s*\(/i,
    /spawn\s*\(/i,
    /child_process/i,
    /shell/i,
    /\$\(/,
    /`[^`]*`/,
  ],
  messaging: [
    /message\s+tool/i,
    /send.*message/i,
    /telegram/i,
    /discord/i,
    /slack/i,
    /whatsapp/i,
    /signal/i,
    /email/i,
    /smtp/i,
  ],
  browser: [
    /browser/i,
    /puppeteer/i,
    /playwright/i,
    /selenium/i,
    /webdriver/i,
  ],
  cron: [
    /cron/i,
    /schedule/i,
    /setInterval/i,
    /setTimeout.*\d{4,}/i,  // long timeouts
  ],
  env_access: [
    /process\.env/i,
    /environ/i,
    /getenv/i,
    /\$[A-Z_]+/,
    /API_KEY/i,
    /SECRET/i,
    /TOKEN/i,
  ],
  credential_access: [
    /\.ssh/i,
    /id_rsa/i,
    /id_ed25519/i,
    /\.aws/i,
    /credentials/i,
    /\.netrc/i,
    /\.npmrc/i,
    /\.pypirc/i,
    /keychain/i,
    /password/i,
    /private.?key/i,
  ]
};

// Sensitive path patterns
const SENSITIVE_PATHS = [
  /~\/\.ssh/,
  /~\/\.aws/,
  /~\/\.gnupg/,
  /~\/\.config/,
  /~\/\.netrc/,
  /\/etc\/passwd/,
  /\/etc\/shadow/,
  /\.env/,
  /credentials/i,
  /secrets?/i,
  /private/i,
];

/**
 * Analyze a single skill and extract its capabilities
 */
async function analyzeSkillCapabilities(skillPath: string): Promise<SkillCapabilities> {
  const name = basename(skillPath);
  const capabilities = new Set<Capability>();
  const sensitiveReads: string[] = [];
  const networkTargets: string[] = [];
  const writeTargets: string[] = [];

  // Read all text files in the skill
  const files = await glob('**/*.{md,js,ts,py,sh,yaml,yml,json}', {
    cwd: skillPath,
    ignore: ['node_modules/**', '.git/**'],
    nodir: true
  });

  for (const file of files) {
    try {
      const content = await readFile(join(skillPath, file), 'utf-8');
      
      // Check for each capability
      for (const [cap, patterns] of Object.entries(CAPABILITY_PATTERNS)) {
        for (const pattern of patterns) {
          if (pattern.test(content)) {
            capabilities.add(cap as Capability);
            break;
          }
        }
      }

      // Extract sensitive paths being read
      for (const pattern of SENSITIVE_PATHS) {
        const matches = content.match(pattern);
        if (matches) {
          sensitiveReads.push(...matches);
        }
      }

      // Extract URLs/domains
      const urlMatches = content.match(/https?:\/\/[^\s"'<>]+/gi);
      if (urlMatches) {
        networkTargets.push(...urlMatches);
      }

    } catch {
      // Skip unreadable files
    }
  }

  return {
    name,
    path: skillPath,
    capabilities,
    sensitiveReads: [...new Set(sensitiveReads)],
    networkTargets: [...new Set(networkTargets)],
    writeTargets: [...new Set(writeTargets)]
  };
}

/**
 * Find dangerous capability combinations across skills
 */
function findDangerousChains(skills: SkillCapabilities[]): Finding[] {
  const findings: Finding[] = [];
  
  // Aggregate all capabilities across skills
  const allCapabilities = new Set<Capability>();
  const capabilityOwners: Record<string, string[]> = {};
  
  for (const skill of skills) {
    for (const cap of skill.capabilities) {
      allCapabilities.add(cap);
      if (!capabilityOwners[cap]) {
        capabilityOwners[cap] = [];
      }
      capabilityOwners[cap].push(skill.name);
    }
  }

  // Check for dangerous chains
  for (const chain of DANGEROUS_CHAINS) {
    const hasAllCapabilities = chain.requires.every(cap => allCapabilities.has(cap));
    
    if (hasAllCapabilities) {
      // Find which skills contribute to this chain
      const contributingSkills: string[] = [];
      for (const cap of chain.requires) {
        contributingSkills.push(...(capabilityOwners[cap] || []));
      }
      const uniqueSkills = [...new Set(contributingSkills)];

      // Only flag if multiple skills are involved (that's the point of chain analysis)
      // OR if a single skill has all dangerous capabilities
      if (uniqueSkills.length >= 1) {
        findings.push({
          id: `T-CHAIN-${chain.name.toUpperCase().replace(/\s+/g, '_')}`,
          category: 'chain',
          severity: chain.severity,
          title: `Attack Chain: ${chain.name}`,
          description: `${chain.description}\n\nSkills involved: ${uniqueSkills.join(', ')}`,
          evidence: `Required capabilities: ${chain.requires.join(' + ')}\n` +
                    chain.requires.map(cap => `${cap}: ${(capabilityOwners[cap] || []).join(', ')}`).join('\n'),
          location: uniqueSkills.join(', '),
          remediation: `Review whether all these capabilities are necessary. Consider isolating skills with dangerous capability combinations.`
        });
      }
    }
  }

  // Check for specific dangerous patterns
  // Credential access + any outbound channel = critical
  const credSkills = skills.filter(s => s.capabilities.has('credential_access'));
  const outboundSkills = skills.filter(s => 
    s.capabilities.has('network_out') || 
    s.capabilities.has('messaging') ||
    s.capabilities.has('browser')
  );

  if (credSkills.length > 0 && outboundSkills.length > 0) {
    const credNames = credSkills.map(s => s.name);
    const outNames = outboundSkills.map(s => s.name);
    
    // Find sensitive paths being accessed
    const allSensitivePaths = credSkills.flatMap(s => s.sensitiveReads);
    
    if (allSensitivePaths.length > 0) {
      findings.push({
        id: 'T-CHAIN-SENSITIVE_DATA_EXPOSURE',
        category: 'chain',
        severity: 'critical',
        title: 'Sensitive Data Exposure Risk',
        description: `Skills can access sensitive paths AND have outbound channels.\n\n` +
                    `Credential access: ${credNames.join(', ')}\n` +
                    `Outbound channels: ${outNames.join(', ')}\n` +
                    `Sensitive paths accessed: ${allSensitivePaths.slice(0, 5).join(', ')}`,
        evidence: `This combination allows credential theft and exfiltration`,
        location: [...credNames, ...outNames].join(', '),
        remediation: 'Review and restrict access to sensitive paths. Consider network isolation.'
      });
    }
  }

  return findings;
}

/**
 * Analyze multiple skills for dangerous attack chains
 */
export async function analyzeAttackChains(skillPaths: string[]): Promise<Finding[]> {
  // Analyze each skill
  const skillAnalyses = await Promise.all(
    skillPaths.map(path => analyzeSkillCapabilities(path))
  );

  // Find dangerous chains
  return findDangerousChains(skillAnalyses);
}

/**
 * Generate a capability report for a set of skills
 */
export async function generateCapabilityReport(skillPaths: string[]): Promise<{
  skills: SkillCapabilities[];
  chains: Finding[];
  summary: {
    totalSkills: number;
    totalCapabilities: number;
    dangerousChains: number;
    criticalChains: number;
  };
}> {
  const skills = await Promise.all(
    skillPaths.map(path => analyzeSkillCapabilities(path))
  );
  
  const chains = findDangerousChains(skills);
  
  // Count unique capabilities
  const allCaps = new Set<Capability>();
  for (const skill of skills) {
    for (const cap of skill.capabilities) {
      allCaps.add(cap);
    }
  }

  return {
    skills,
    chains,
    summary: {
      totalSkills: skills.length,
      totalCapabilities: allCaps.size,
      dangerousChains: chains.length,
      criticalChains: chains.filter(c => c.severity === 'critical').length
    }
  };
}

export { SkillCapabilities, Capability };
