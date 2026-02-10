/**
 * ClawGuard Known-Bad Database API
 *
 * Simple API for tracking malicious skills.
 * Deploy to Render or similar.
 */

import express from 'express';
import cors from 'cors';
import { readFile, writeFile, mkdir } from 'fs/promises';
import { join } from 'path';

const app = express();
const PORT = process.env.PORT || 3000;
const API_KEY = process.env.CLAWGUARD_API_KEY || '';
const DATA_DIR = process.env.DATA_DIR || join(process.cwd(), 'data');
const DB_FILE = join(DATA_DIR, 'known-bad.json');

app.use(cors());
app.use(express.json());

// ============================================================================
// Persistent Storage
// ============================================================================

interface ThreatEntry {
  hash: string;
  threat: string;
  description: string;
  findings: string;
  reportedAt: string;
  reportCount: number;
}

let knownBad: Map<string, ThreatEntry> = new Map();

async function loadDatabase(): Promise<void> {
  try {
    const data = await readFile(DB_FILE, 'utf-8');
    const entries: ThreatEntry[] = JSON.parse(data);
    knownBad = new Map(entries.map(e => [e.hash, e]));
    console.log(`Loaded ${knownBad.size} entries from ${DB_FILE}`);
  } catch {
    // No database file yet — start fresh
    console.log('No existing database found, starting fresh');
  }
}

async function saveDatabase(): Promise<void> {
  await mkdir(DATA_DIR, { recursive: true });
  const entries = Array.from(knownBad.values());
  await writeFile(DB_FILE, JSON.stringify(entries, null, 2), 'utf-8');
}

// ============================================================================
// Auth Middleware
// ============================================================================

function requireAuth(req: express.Request, res: express.Response, next: express.NextFunction): void {
  if (!API_KEY) {
    // No API key configured — skip auth (development mode)
    next();
    return;
  }

  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Missing authorization header. Use: Authorization: Bearer <key>' });
    return;
  }

  const token = authHeader.slice(7);
  if (token !== API_KEY) {
    res.status(403).json({ error: 'Invalid API key' });
    return;
  }

  next();
}

// ============================================================================
// Rate Limiting (simple in-memory)
// ============================================================================

const rateLimits: Map<string, { count: number; resetAt: number }> = new Map();
const RATE_LIMIT_WINDOW = 60_000; // 1 minute
const RATE_LIMIT_MAX = 10; // 10 requests per minute per IP

function rateLimit(req: express.Request, res: express.Response, next: express.NextFunction): void {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  const now = Date.now();

  const entry = rateLimits.get(ip);
  if (entry && now < entry.resetAt) {
    if (entry.count >= RATE_LIMIT_MAX) {
      res.status(429).json({ error: 'Rate limit exceeded. Try again later.' });
      return;
    }
    entry.count++;
  } else {
    rateLimits.set(ip, { count: 1, resetAt: now + RATE_LIMIT_WINDOW });
  }

  next();
}

// ============================================================================
// Routes
// ============================================================================

/**
 * Health check — public
 */
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', version: '1.0.0', entries: knownBad.size });
});

/**
 * Check if a skill hash is known-bad — public
 */
app.get('/api/v1/check/:hash', (req, res) => {
  const { hash } = req.params;

  if (!hash || !hash.match(/^[a-f0-9]{64}$/i)) {
    return res.status(400).json({ error: 'Invalid hash format' });
  }

  const entry = knownBad.get(hash.toLowerCase());

  if (entry) {
    return res.json({
      known: true,
      threat: entry.threat,
      description: entry.description,
      reportCount: entry.reportCount
    });
  }

  return res.json({ known: false });
});

/**
 * Report a malicious skill — requires auth + rate limited
 */
app.post('/api/v1/report', rateLimit, requireAuth, async (req, res) => {
  const { hash, findings, threat, description } = req.body;

  if (!hash || !hash.match(/^[a-f0-9]{64}$/i)) {
    return res.status(400).json({ error: 'Invalid hash format' });
  }

  const normalizedHash = hash.toLowerCase();
  const existing = knownBad.get(normalizedHash);

  if (existing) {
    existing.reportCount++;
    knownBad.set(normalizedHash, existing);
    await saveDatabase();

    return res.json({
      success: true,
      message: 'Report count incremented',
      reportCount: existing.reportCount
    });
  }

  const entry: ThreatEntry = {
    hash: normalizedHash,
    threat: threat || 'unknown',
    description: description || 'Reported as malicious by ClawGuard scan',
    findings: findings || '[]',
    reportedAt: new Date().toISOString(),
    reportCount: 1
  };

  knownBad.set(normalizedHash, entry);
  await saveDatabase();

  return res.json({
    success: true,
    message: 'Skill reported',
    reportCount: 1
  });
});

/**
 * Get stats — public
 */
app.get('/api/v1/stats', (_req, res) => {
  res.json({
    totalKnownBad: knownBad.size,
    lastUpdated: new Date().toISOString()
  });
});

/**
 * List reports — requires auth
 */
app.get('/api/v1/list', requireAuth, (_req, res) => {
  const entries = Array.from(knownBad.values())
    .sort((a, b) => b.reportCount - a.reportCount)
    .slice(0, 100);

  res.json({ entries });
});

// ============================================================================
// Startup
// ============================================================================

async function start(): Promise<void> {
  await loadDatabase();

  app.listen(PORT, () => {
    console.log(`ClawGuard API running on port ${PORT}`);
    console.log(`Known-bad entries: ${knownBad.size}`);
    console.log(`Auth: ${API_KEY ? 'enabled' : 'disabled (set CLAWGUARD_API_KEY to enable)'}`);
    console.log(`Data: ${DB_FILE}`);
  });
}

start().catch(console.error);

export default app;
