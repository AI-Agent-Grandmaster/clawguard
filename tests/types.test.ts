/**
 * ClawGuard Types & Risk Scoring Tests
 */

import { describe, it, expect } from 'vitest';
import {
  calculateRiskScore,
  getRiskLevel,
  summarizeFindings,
  type Finding,
} from '../src/types.js';

// ============================================================================
// Helpers
// ============================================================================

function makeFinding(severity: Finding['severity'], id = 'T-TEST-001'): Finding {
  return {
    id,
    category: 'code',
    severity,
    title: `Test ${severity} finding`,
    description: `A test finding with severity ${severity}`,
  };
}

// ============================================================================
// calculateRiskScore
// ============================================================================

describe('calculateRiskScore', () => {
  it('should return 0 for an empty findings array', () => {
    expect(calculateRiskScore([])).toBe(0);
  });

  it('should return 25 for a single critical finding', () => {
    const findings = [makeFinding('critical')];
    expect(calculateRiskScore(findings)).toBe(25);
  });

  it('should return 45 for 1 critical + 2 high findings', () => {
    const findings = [
      makeFinding('critical'),
      makeFinding('high', 'T-TEST-002'),
      makeFinding('high', 'T-TEST-003'),
    ];
    expect(calculateRiskScore(findings)).toBe(45);
  });

  it('should cap the score at 100 for many findings', () => {
    const findings = [
      makeFinding('critical', 'T-TEST-001'),
      makeFinding('critical', 'T-TEST-002'),
      makeFinding('critical', 'T-TEST-003'),
      makeFinding('critical', 'T-TEST-004'),
      makeFinding('critical', 'T-TEST-005'),
    ];
    // 5 * 25 = 125 => capped at 100
    expect(calculateRiskScore(findings)).toBe(100);
  });

  it('should not add score for info findings', () => {
    const findings = [
      makeFinding('info', 'T-TEST-001'),
      makeFinding('info', 'T-TEST-002'),
      makeFinding('info', 'T-TEST-003'),
    ];
    expect(calculateRiskScore(findings)).toBe(0);
  });

  it('should correctly sum mixed severities', () => {
    const findings = [
      makeFinding('critical', 'T-TEST-001'), // 25
      makeFinding('high', 'T-TEST-002'),     // 10
      makeFinding('medium', 'T-TEST-003'),   // 4
      makeFinding('low', 'T-TEST-004'),      // 1
      makeFinding('info', 'T-TEST-005'),     // 0
    ];
    expect(calculateRiskScore(findings)).toBe(40);
  });

  it('should return 1 for a single low finding', () => {
    expect(calculateRiskScore([makeFinding('low')])).toBe(1);
  });

  it('should return 4 for a single medium finding', () => {
    expect(calculateRiskScore([makeFinding('medium')])).toBe(4);
  });

  it('should return 10 for a single high finding', () => {
    expect(calculateRiskScore([makeFinding('high')])).toBe(10);
  });
});

// ============================================================================
// getRiskLevel
// ============================================================================

describe('getRiskLevel', () => {
  it('should return SAFE for score 0', () => {
    expect(getRiskLevel(0)).toBe('SAFE');
  });

  it('should return SAFE for score 10 (threshold boundary)', () => {
    expect(getRiskLevel(10)).toBe('SAFE');
  });

  it('should return LOW for score 11', () => {
    expect(getRiskLevel(11)).toBe('LOW');
  });

  it('should return LOW for score 25 (threshold boundary)', () => {
    expect(getRiskLevel(25)).toBe('LOW');
  });

  it('should return MEDIUM for score 26', () => {
    expect(getRiskLevel(26)).toBe('MEDIUM');
  });

  it('should return MEDIUM for score 50 (threshold boundary)', () => {
    expect(getRiskLevel(50)).toBe('MEDIUM');
  });

  it('should return HIGH for score 51', () => {
    expect(getRiskLevel(51)).toBe('HIGH');
  });

  it('should return HIGH for score 75 (threshold boundary)', () => {
    expect(getRiskLevel(75)).toBe('HIGH');
  });

  it('should return CRITICAL for score 76', () => {
    expect(getRiskLevel(76)).toBe('CRITICAL');
  });

  it('should return CRITICAL for score 100', () => {
    expect(getRiskLevel(100)).toBe('CRITICAL');
  });
});

// ============================================================================
// summarizeFindings
// ============================================================================

describe('summarizeFindings', () => {
  it('should return all zeros for an empty array', () => {
    const summary = summarizeFindings([]);
    expect(summary).toEqual({
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    });
  });

  it('should correctly count mixed findings', () => {
    const findings: Finding[] = [
      makeFinding('critical', 'T-TEST-001'),
      makeFinding('critical', 'T-TEST-002'),
      makeFinding('high', 'T-TEST-003'),
      makeFinding('medium', 'T-TEST-004'),
      makeFinding('medium', 'T-TEST-005'),
      makeFinding('medium', 'T-TEST-006'),
      makeFinding('low', 'T-TEST-007'),
      makeFinding('info', 'T-TEST-008'),
      makeFinding('info', 'T-TEST-009'),
    ];

    const summary = summarizeFindings(findings);
    expect(summary).toEqual({
      critical: 2,
      high: 1,
      medium: 3,
      low: 1,
      info: 2,
    });
  });

  it('should count a single severity correctly', () => {
    const findings = [
      makeFinding('high', 'T-TEST-001'),
      makeFinding('high', 'T-TEST-002'),
      makeFinding('high', 'T-TEST-003'),
    ];

    const summary = summarizeFindings(findings);
    expect(summary.high).toBe(3);
    expect(summary.critical).toBe(0);
    expect(summary.medium).toBe(0);
    expect(summary.low).toBe(0);
    expect(summary.info).toBe(0);
  });
});
