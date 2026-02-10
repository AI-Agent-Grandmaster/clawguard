/**
 * ClawGuard Orchestrator Tests
 */

import { describe, it, expect } from 'vitest';
import { parseSkillMd, Orchestrator, createOrchestrator } from '../src/orchestrator.js';
import { join } from 'path';
import { mkdir, writeFile, rm } from 'fs/promises';
import { tmpdir } from 'os';

const FIXTURES = join(process.cwd(), 'tests', 'fixtures');

// ============================================================================
// parseSkillMd
// ============================================================================

describe('parseSkillMd', () => {
  it('should parse safe-skill fixture with name and description', async () => {
    const meta = await parseSkillMd(join(FIXTURES, 'safe-skill'));
    expect(meta.name).toBe('weather-checker');
    expect(meta.description).toBe('Check current weather conditions');
    expect(meta.path).toBe(join(FIXTURES, 'safe-skill'));
    expect(meta.body).toBeDefined();
    expect(meta.body!.length).toBeGreaterThan(0);
  });

  it('should return default meta with directory name when no SKILL.md exists', async () => {
    const testDir = join(tmpdir(), 'clawguard-no-skill-md-' + Date.now());
    await mkdir(testDir, { recursive: true });

    try {
      const meta = await parseSkillMd(testDir);
      // Should use directory basename as name
      expect(meta.name).toBe(testDir.split('/').pop());
      expect(meta.path).toBe(testDir);
      // No frontmatter fields
      expect(meta.version).toBeUndefined();
      expect(meta.author).toBeUndefined();
      expect(meta.description).toBeUndefined();
    } finally {
      await rm(testDir, { recursive: true, force: true });
    }
  });

  it('should return body but no version/author when SKILL.md has no frontmatter', async () => {
    // chain-reader fixture has no frontmatter (no --- delimiters)
    const meta = await parseSkillMd(join(FIXTURES, 'chain-reader'));
    expect(meta.body).toBeDefined();
    expect(meta.body!.length).toBeGreaterThan(0);
    // Without frontmatter, name falls back to directory basename
    expect(meta.name).toBe('chain-reader');
    expect(meta.version).toBeUndefined();
    expect(meta.author).toBeUndefined();
  });
});

// ============================================================================
// Orchestrator
// ============================================================================

describe('Orchestrator', () => {
  it('createOrchestrator() returns an Orchestrator instance', () => {
    const orchestrator = createOrchestrator();
    expect(orchestrator).toBeInstanceOf(Orchestrator);
  });

  it('getAnalyzerNames() returns array including static, deps, prompt', () => {
    const orchestrator = createOrchestrator();
    const names = orchestrator.getAnalyzerNames();
    expect(Array.isArray(names)).toBe(true);
    expect(names).toContain('static');
    expect(names).toContain('deps');
    expect(names).toContain('prompt');
  });

  it('scan safe skill returns low risk with analyzersRun including static', async () => {
    const orchestrator = createOrchestrator();
    const result = await orchestrator.scan({ path: join(FIXTURES, 'safe-skill') });

    expect(result.skill).toBeDefined();
    expect(result.skill.name).toBe('weather-checker');
    expect(result.findings).toBeDefined();
    expect(Array.isArray(result.findings)).toBe(true);
    expect(['SAFE', 'LOW']).toContain(result.riskLevel);
    expect(result.analyzersRun).toContain('static');
    expect(result.scanTime).toBeGreaterThanOrEqual(0);
    expect(result.summary).toBeDefined();
    expect(typeof result.summary.critical).toBe('number');
    expect(typeof result.summary.high).toBe('number');
    expect(typeof result.summary.medium).toBe('number');
    expect(typeof result.summary.low).toBe('number');
    expect(typeof result.summary.info).toBe('number');
  });

  it('scan malicious skill returns higher risk score with non-empty findings', async () => {
    const orchestrator = createOrchestrator();
    const result = await orchestrator.scan({ path: join(FIXTURES, 'malicious-skill') });

    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.riskScore).toBeGreaterThan(0);
    // Malicious skill should have at least medium risk
    expect(['MEDIUM', 'HIGH', 'CRITICAL']).toContain(result.riskLevel);
  });

  it('scan non-existent path throws "Skill path does not exist"', async () => {
    const orchestrator = createOrchestrator();
    const fakePath = join(FIXTURES, 'does-not-exist-' + Date.now());

    await expect(orchestrator.scan({ path: fakePath }))
      .rejects
      .toThrow('Skill path does not exist');
  });

  it('scan a file (not directory) throws "Path is not a directory"', async () => {
    const orchestrator = createOrchestrator();
    const filePath = join(FIXTURES, 'safe-skill', 'SKILL.md');

    await expect(orchestrator.scan({ path: filePath }))
      .rejects
      .toThrow('Path is not a directory');
  });

  it('refuses to scan system root /', async () => {
    const orchestrator = createOrchestrator();
    await expect(orchestrator.scan({ path: '/' }))
      .rejects
      .toThrow('Refusing to scan system directory');
  });

  it('refuses to scan /etc', async () => {
    const orchestrator = createOrchestrator();
    await expect(orchestrator.scan({ path: '/etc' }))
      .rejects
      .toThrow('Refusing to scan system directory');
  });

  it('refuses to scan home directory root', async () => {
    const orchestrator = createOrchestrator();
    const home = process.env.HOME || '/home';
    await expect(orchestrator.scan({ path: home }))
      .rejects
      .toThrow('Refusing to scan home directory root');
  });
});
