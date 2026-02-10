/**
 * ClawGuard Report Formatter Tests
 */

import { describe, it, expect } from 'vitest';
import { formatJson, formatMarkdown, formatResult } from '../src/report.js';
import type { ScanResult, Finding, SeveritySummary, RiskLevel } from '../src/types.js';

// ============================================================================
// Helpers
// ============================================================================

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'T-TEST-001',
    category: 'code',
    severity: 'high',
    title: 'Test Finding',
    description: 'A test finding for report formatting',
    ...overrides,
  };
}

function makeScanResult(overrides: Partial<ScanResult> = {}): ScanResult {
  const findings = overrides.findings ?? [];
  const summary: SeveritySummary = overrides.summary ?? {
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
    low: findings.filter(f => f.severity === 'low').length,
    info: findings.filter(f => f.severity === 'info').length,
  };

  return {
    skill: {
      name: 'test-skill',
      path: '/tmp/test-skill',
      version: '1.0.0',
    },
    findings,
    riskScore: overrides.riskScore ?? 0,
    riskLevel: overrides.riskLevel ?? 'SAFE',
    scanTime: overrides.scanTime ?? 42,
    analyzersRun: overrides.analyzersRun ?? ['static', 'deps', 'prompt'],
    summary,
    ...overrides,
  };
}

// ============================================================================
// formatJson
// ============================================================================

describe('formatJson', () => {
  it('should return valid JSON string', () => {
    const result = makeScanResult();
    const json = formatJson(result);
    expect(() => JSON.parse(json)).not.toThrow();
  });

  it('should include skill name, version, and path', () => {
    const result = makeScanResult();
    const parsed = JSON.parse(formatJson(result));
    expect(parsed.skill.name).toBe('test-skill');
    expect(parsed.skill.version).toBe('1.0.0');
    expect(parsed.skill.path).toBe('/tmp/test-skill');
  });

  it('should include riskScore and riskLevel', () => {
    const result = makeScanResult({ riskScore: 45, riskLevel: 'MEDIUM' });
    const parsed = JSON.parse(formatJson(result));
    expect(parsed.riskScore).toBe(45);
    expect(parsed.riskLevel).toBe('MEDIUM');
  });

  it('should include findings array', () => {
    const findings = [
      makeFinding({ id: 'T-CODE-001', severity: 'critical', title: 'Critical issue' }),
      makeFinding({ id: 'T-CODE-002', severity: 'low', title: 'Low issue' }),
    ];
    const result = makeScanResult({ findings });
    const parsed = JSON.parse(formatJson(result));
    expect(parsed.findings).toHaveLength(2);
    expect(parsed.findings[0].id).toBe('T-CODE-001');
    expect(parsed.findings[1].id).toBe('T-CODE-002');
  });

  it('should include summary counts', () => {
    const findings = [
      makeFinding({ id: 'T-CODE-001', severity: 'critical' }),
      makeFinding({ id: 'T-CODE-002', severity: 'high' }),
      makeFinding({ id: 'T-CODE-003', severity: 'high' }),
    ];
    const result = makeScanResult({ findings });
    const parsed = JSON.parse(formatJson(result));
    expect(parsed.summary.critical).toBe(1);
    expect(parsed.summary.high).toBe(2);
    expect(parsed.summary.medium).toBe(0);
  });

  it('should include scanTime and analyzersRun', () => {
    const result = makeScanResult({
      scanTime: 150,
      analyzersRun: ['static', 'prompt'],
    });
    const parsed = JSON.parse(formatJson(result));
    expect(parsed.scanTime).toBe(150);
    expect(parsed.analyzersRun).toEqual(['static', 'prompt']);
  });

  it('should produce empty findings array when no findings', () => {
    const result = makeScanResult({ findings: [] });
    const parsed = JSON.parse(formatJson(result));
    expect(parsed.findings).toEqual([]);
  });
});

// ============================================================================
// formatMarkdown
// ============================================================================

describe('formatMarkdown', () => {
  it('should contain the report header', () => {
    const result = makeScanResult();
    const md = formatMarkdown(result);
    expect(md).toContain('# ClawGuard Security Report');
  });

  it('should contain the skill name', () => {
    const result = makeScanResult();
    const md = formatMarkdown(result);
    expect(md).toContain('test-skill');
  });

  it('should contain the risk level and score', () => {
    const result = makeScanResult({ riskScore: 60, riskLevel: 'HIGH' });
    const md = formatMarkdown(result);
    expect(md).toContain('HIGH');
    expect(md).toContain('60/100');
  });

  it('should show "No security issues found" when there are no findings', () => {
    const result = makeScanResult({ findings: [] });
    const md = formatMarkdown(result);
    expect(md).toContain('No security issues found');
  });

  it('should contain severity table when findings exist', () => {
    const findings = [
      makeFinding({ id: 'T-CODE-001', severity: 'critical' }),
    ];
    const result = makeScanResult({ findings, riskScore: 25, riskLevel: 'LOW' });
    const md = formatMarkdown(result);
    expect(md).toContain('| Severity | Count |');
    expect(md).toContain('Critical');
  });

  it('should contain finding details with id and title', () => {
    const findings = [
      makeFinding({
        id: 'T-CODE-042',
        severity: 'high',
        title: 'Dangerous eval() usage',
        description: 'Code uses eval which can execute arbitrary code',
      }),
    ];
    const result = makeScanResult({ findings, riskScore: 10, riskLevel: 'SAFE' });
    const md = formatMarkdown(result);
    expect(md).toContain('T-CODE-042');
    expect(md).toContain('Dangerous eval() usage');
    expect(md).toContain('Code uses eval which can execute arbitrary code');
  });

  it('should include location when provided', () => {
    const findings = [
      makeFinding({
        id: 'T-CODE-001',
        severity: 'medium',
        location: 'index.js:42',
      }),
    ];
    const result = makeScanResult({ findings, riskScore: 4, riskLevel: 'SAFE' });
    const md = formatMarkdown(result);
    expect(md).toContain('index.js:42');
  });

  it('should include evidence when provided', () => {
    const findings = [
      makeFinding({
        id: 'T-CODE-001',
        severity: 'high',
        evidence: 'eval(userInput)',
      }),
    ];
    const result = makeScanResult({ findings, riskScore: 10, riskLevel: 'SAFE' });
    const md = formatMarkdown(result);
    expect(md).toContain('eval(userInput)');
  });

  it('should include remediation when provided', () => {
    const findings = [
      makeFinding({
        id: 'T-CODE-001',
        severity: 'high',
        remediation: 'Replace eval() with a safer alternative',
      }),
    ];
    const result = makeScanResult({ findings, riskScore: 10, riskLevel: 'SAFE' });
    const md = formatMarkdown(result);
    expect(md).toContain('Replace eval() with a safer alternative');
  });

  it('should include scan time in footer', () => {
    const result = makeScanResult({ scanTime: 250 });
    const md = formatMarkdown(result);
    expect(md).toContain('250ms');
  });

  it('should include analyzers run in footer', () => {
    const result = makeScanResult({ analyzersRun: ['static', 'deps'] });
    const md = formatMarkdown(result);
    expect(md).toContain('static');
    expect(md).toContain('deps');
  });

  it('should include skill version when provided', () => {
    const result = makeScanResult();
    const md = formatMarkdown(result);
    expect(md).toContain('1.0.0');
  });

  it('should group findings by severity', () => {
    const findings = [
      makeFinding({ id: 'T-CODE-001', severity: 'critical', title: 'Critical bug' }),
      makeFinding({ id: 'T-CODE-002', severity: 'low', title: 'Minor issue' }),
      makeFinding({ id: 'T-CODE-003', severity: 'critical', title: 'Another critical' }),
    ];
    const result = makeScanResult({ findings, riskScore: 51, riskLevel: 'HIGH' });
    const md = formatMarkdown(result);
    // Critical section should appear before Low section
    const criticalIdx = md.indexOf('Critical Findings');
    const lowIdx = md.indexOf('Low Findings');
    expect(criticalIdx).toBeLessThan(lowIdx);
  });
});

// ============================================================================
// formatResult
// ============================================================================

describe('formatResult', () => {
  it('should return JSON when format is "json"', () => {
    const result = makeScanResult();
    const output = formatResult(result, 'json');
    expect(() => JSON.parse(output)).not.toThrow();
    const parsed = JSON.parse(output);
    expect(parsed.skill.name).toBe('test-skill');
  });

  it('should return Markdown when format is "md"', () => {
    const result = makeScanResult();
    const output = formatResult(result, 'md');
    expect(output).toContain('# ClawGuard Security Report');
  });

  it('should return HTML wrapping markdown when format is "html"', () => {
    const result = makeScanResult();
    const output = formatResult(result, 'html');
    expect(output).toContain('<html>');
    expect(output).toContain('</html>');
    expect(output).toContain('ClawGuard Security Report');
  });

  it('should default to Markdown when no format specified', () => {
    const result = makeScanResult();
    const output = formatResult(result);
    expect(output).toContain('# ClawGuard Security Report');
  });
});
