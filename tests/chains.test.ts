/**
 * ClawGuard Attack Chain Analyzer Tests
 */

import { describe, it, expect } from 'vitest';
import { analyzeAttackChains, generateCapabilityReport } from '../src/analyzers/chains.js';
import { join } from 'path';

const FIXTURES = join(process.cwd(), 'tests', 'fixtures');

// ============================================================================
// analyzeAttackChains
// ============================================================================

describe('analyzeAttackChains', () => {
  it('should detect credential exfiltration chain from chain-reader + chain-sender', async () => {
    const findings = await analyzeAttackChains([
      join(FIXTURES, 'chain-reader'),
      join(FIXTURES, 'chain-sender'),
    ]);

    // These fixtures together have credential_access + messaging capabilities
    expect(findings.length).toBeGreaterThan(0);

    const chainFindings = findings.filter(f => f.category === 'chain');
    expect(chainFindings.length).toBeGreaterThan(0);

    // Should detect at least one critical-severity chain
    const criticalChains = chainFindings.filter(f => f.severity === 'critical');
    expect(criticalChains.length).toBeGreaterThan(0);
  });

  it('should produce no or fewer chain findings for safe skill alone', async () => {
    const findings = await analyzeAttackChains([
      join(FIXTURES, 'safe-skill'),
    ]);

    // A single safe skill should produce fewer or no dangerous chain findings
    const chainFindings = findings.filter(f => f.category === 'chain');
    // safe-skill doesn't have dangerous capability combos, so fewer findings
    // Compare against the chain-reader + chain-sender combo
    const comboFindings = await analyzeAttackChains([
      join(FIXTURES, 'chain-reader'),
      join(FIXTURES, 'chain-sender'),
    ]);
    expect(chainFindings.length).toBeLessThan(comboFindings.length);
  });
});

// ============================================================================
// generateCapabilityReport
// ============================================================================

describe('generateCapabilityReport', () => {
  it('should return expected structure with skills, chains, and summary', async () => {
    const report = await generateCapabilityReport([
      join(FIXTURES, 'chain-reader'),
      join(FIXTURES, 'chain-sender'),
    ]);

    expect(report).toBeDefined();
    expect(Array.isArray(report.skills)).toBe(true);
    expect(Array.isArray(report.chains)).toBe(true);
    expect(report.summary).toBeDefined();
    expect(typeof report.summary.totalSkills).toBe('number');
    expect(typeof report.summary.totalCapabilities).toBe('number');
    expect(typeof report.summary.dangerousChains).toBe('number');
    expect(typeof report.summary.criticalChains).toBe('number');
  });

  it('should report correct totalSkills count', async () => {
    const twoPaths = [
      join(FIXTURES, 'chain-reader'),
      join(FIXTURES, 'chain-sender'),
    ];
    const report = await generateCapabilityReport(twoPaths);
    expect(report.summary.totalSkills).toBe(2);

    const onePath = [join(FIXTURES, 'safe-skill')];
    const singleReport = await generateCapabilityReport(onePath);
    expect(singleReport.summary.totalSkills).toBe(1);
  });
});
