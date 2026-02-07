/**
 * ClawGuard Known-Bad Database Client
 * 
 * Functions for checking and reporting to the threat database.
 */

import { createHash } from 'crypto';
import { readFile } from 'fs/promises';
import { join } from 'path';
import { glob } from 'glob';

// Known-bad database API
const KNOWN_BAD_API = process.env.CLAWGUARD_API || 'https://clawguard-api.onrender.com/api/v1';

/**
 * Calculate skill hash for database lookup
 */
export async function calculateSkillHash(skillPath: string): Promise<string> {
  const files = await glob('**/*.{md,js,ts,py,sh,json,yaml,yml}', {
    cwd: skillPath,
    ignore: ['node_modules/**', '.git/**'],
    nodir: true
  });

  const hash = createHash('sha256');
  
  for (const file of files.sort()) {
    try {
      const content = await readFile(join(skillPath, file), 'utf-8');
      hash.update(file + ':' + content);
    } catch {
      // Skip unreadable files
    }
  }

  return hash.digest('hex');
}

/**
 * Check skill against known-bad database
 */
export async function checkKnownBad(skillHash: string): Promise<{
  known: boolean;
  threat?: string;
  description?: string;
}> {
  try {
    const response = await fetch(`${KNOWN_BAD_API}/check/${skillHash}`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
      signal: AbortSignal.timeout(5000)
    });

    if (response.ok) {
      const data = await response.json() as { 
        known: boolean; 
        threat?: string; 
        description?: string 
      };
      return data;
    }
    return { known: false };
  } catch {
    // Database unavailable, continue with scan
    return { known: false };
  }
}

/**
 * Report a malicious skill to the database
 */
export async function reportMalicious(skillHash: string, findings: string): Promise<void> {
  try {
    await fetch(`${KNOWN_BAD_API}/report`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hash: skillHash, findings }),
      signal: AbortSignal.timeout(5000)
    });
  } catch {
    // Silently fail - reporting is best-effort
  }
}
