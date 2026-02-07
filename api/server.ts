/**
 * ClawGuard Known-Bad Database API
 * 
 * Simple API for tracking malicious skills.
 * Deploy to Render or similar.
 */

import express from 'express';
import cors from 'cors';
import { createHash } from 'crypto';

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// In-memory store (replace with Postgres/Redis for production)
interface ThreatEntry {
  hash: string;
  threat: string;
  description: string;
  findings: string;
  reportedAt: string;
  reportCount: number;
}

const knownBad: Map<string, ThreatEntry> = new Map();

// Seed with some known-bad hashes (examples)
knownBad.set('example_malicious_hash_1', {
  hash: 'example_malicious_hash_1',
  threat: 'credential_theft',
  description: 'Skill attempts to steal SSH keys and AWS credentials',
  findings: '[]',
  reportedAt: new Date().toISOString(),
  reportCount: 1
});

/**
 * Health check
 */
app.get('/health', (req, res) => {
  res.json({ status: 'ok', version: '1.0.0' });
});

/**
 * Check if a skill hash is known-bad
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
 * Report a malicious skill
 */
app.post('/api/v1/report', (req, res) => {
  const { hash, findings, threat, description } = req.body;
  
  if (!hash || !hash.match(/^[a-f0-9]{64}$/i)) {
    return res.status(400).json({ error: 'Invalid hash format' });
  }
  
  const normalizedHash = hash.toLowerCase();
  const existing = knownBad.get(normalizedHash);
  
  if (existing) {
    // Increment report count
    existing.reportCount++;
    knownBad.set(normalizedHash, existing);
    
    return res.json({ 
      success: true, 
      message: 'Report count incremented',
      reportCount: existing.reportCount
    });
  }
  
  // New entry
  const entry: ThreatEntry = {
    hash: normalizedHash,
    threat: threat || 'unknown',
    description: description || 'Reported as malicious by ClawGuard scan',
    findings: findings || '[]',
    reportedAt: new Date().toISOString(),
    reportCount: 1
  };
  
  knownBad.set(normalizedHash, entry);
  
  return res.json({ 
    success: true, 
    message: 'Skill reported',
    reportCount: 1
  });
});

/**
 * Get stats
 */
app.get('/api/v1/stats', (req, res) => {
  res.json({
    totalKnownBad: knownBad.size,
    lastUpdated: new Date().toISOString()
  });
});

/**
 * List recent reports (admin endpoint, should be protected in production)
 */
app.get('/api/v1/list', (req, res) => {
  const entries = Array.from(knownBad.values())
    .sort((a, b) => b.reportCount - a.reportCount)
    .slice(0, 100);
  
  res.json({ entries });
});

app.listen(PORT, () => {
  console.log(`ClawGuard API running on port ${PORT}`);
  console.log(`Known-bad entries: ${knownBad.size}`);
});

export default app;
