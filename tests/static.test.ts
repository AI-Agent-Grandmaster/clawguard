/**
 * Tests for the static code analyzer
 */

import { describe, it, expect, afterAll } from 'vitest';
import { createStaticAnalyzer } from '../src/analyzers/static.js';
import { join } from 'path';
import { mkdir, rm } from 'fs/promises';
import type { Finding } from '../src/types.js';

const FIXTURES = join(process.cwd(), 'tests', 'fixtures');

const severityOrder: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

describe('Static Analyzer', () => {
  const analyzer = createStaticAnalyzer();

  describe('Safe skill', () => {
    it('should produce no critical or high findings', async () => {
      const findings = await analyzer.analyze(join(FIXTURES, 'safe-skill'));

      const criticalOrHigh = findings.filter(
        (f) => f.severity === 'critical' || f.severity === 'high'
      );
      expect(criticalOrHigh).toHaveLength(0);
    });
  });

  describe('Malicious skill — eval/exec detection', () => {
    it('should detect eval/exec patterns with T-CODE IDs', async () => {
      const findings = await analyzer.analyze(join(FIXTURES, 'malicious-skill'));

      const codeFindings = findings.filter((f) => f.id.startsWith('T-CODE'));
      expect(codeFindings.length).toBeGreaterThan(0);

      // bad.js uses eval(), atob(), setTimeout with string — these should all trigger
      const evalRelated = findings.filter(
        (f) =>
          f.evidence?.includes('eval') ||
          f.title.toLowerCase().includes('eval') ||
          f.description.toLowerCase().includes('eval')
      );
      expect(evalRelated.length).toBeGreaterThan(0);
    });

    it('should detect child_process usage', async () => {
      const findings = await analyzer.analyze(join(FIXTURES, 'malicious-skill'));

      const childProcess = findings.filter(
        (f) =>
          f.evidence?.includes('child_process') ||
          f.description.toLowerCase().includes('child_process') ||
          f.title.toLowerCase().includes('child_process') ||
          f.evidence?.includes('cp.exec')
      );
      expect(childProcess.length).toBeGreaterThan(0);
    });
  });

  describe('Malicious base64 obfuscation', () => {
    it('should detect base64 obfuscation patterns', async () => {
      const findings = await analyzer.analyze(join(FIXTURES, 'malicious-base64'));

      // init.sh uses base64 -d | bash — should trigger base64 or pipe-to-shell patterns
      expect(findings.length).toBeGreaterThan(0);

      const hasObfuscationOrExec = findings.some(
        (f) =>
          f.severity === 'critical' ||
          f.severity === 'high' ||
          f.description.toLowerCase().includes('base64') ||
          f.description.toLowerCase().includes('obfuscat') ||
          f.evidence?.includes('base64')
      );
      expect(hasObfuscationOrExec).toBe(true);
    });
  });

  describe('Malicious curl pipe patterns', () => {
    it('should detect curl pipe to shell', async () => {
      const findings = await analyzer.analyze(join(FIXTURES, 'malicious-curl-pipe'));

      expect(findings.length).toBeGreaterThan(0);

      const curlPipe = findings.some(
        (f) =>
          f.evidence?.includes('curl') ||
          f.description.toLowerCase().includes('curl') ||
          f.description.toLowerCase().includes('pipe') ||
          f.description.toLowerCase().includes('fetch')
      );
      expect(curlPipe).toBe(true);
    });
  });

  describe('Malicious credential access', () => {
    it('should detect credential stealing patterns', async () => {
      const findings = await analyzer.analyze(
        join(FIXTURES, 'malicious-credential-stealer')
      );

      expect(findings.length).toBeGreaterThan(0);

      // backup.sh reads ~/.ssh/id_rsa, ~/.aws/credentials, ~/.env
      const credentialAccess = findings.some(
        (f) =>
          f.evidence?.includes('.ssh') ||
          f.evidence?.includes('.aws') ||
          f.evidence?.includes('.env') ||
          f.evidence?.includes('credentials') ||
          f.description.toLowerCase().includes('credential') ||
          f.description.toLowerCase().includes('ssh') ||
          f.description.toLowerCase().includes('secret')
      );
      expect(credentialAccess).toBe(true);
    });
  });

  describe('Malicious persistence mechanisms', () => {
    it('should detect persistence patterns', async () => {
      const findings = await analyzer.analyze(
        join(FIXTURES, 'malicious-persistence')
      );

      expect(findings.length).toBeGreaterThan(0);

      // setup.sh appends to ~/.bashrc including a hidden curl | bash payload
      const persistence = findings.some(
        (f) =>
          f.evidence?.includes('.bashrc') ||
          f.evidence?.includes('>> ~') ||
          f.description.toLowerCase().includes('persist') ||
          f.description.toLowerCase().includes('startup') ||
          f.description.toLowerCase().includes('bashrc') ||
          f.description.toLowerCase().includes('shell config')
      );
      expect(persistence).toBe(true);
    });
  });

  describe('Findings sort order', () => {
    it('should return findings sorted by severity (critical first)', async () => {
      const findings = await analyzer.analyze(join(FIXTURES, 'malicious-skill'));

      // Need at least two findings to verify ordering
      expect(findings.length).toBeGreaterThanOrEqual(2);

      for (let i = 1; i < findings.length; i++) {
        const prevOrder = severityOrder[findings[i - 1].severity];
        const currOrder = severityOrder[findings[i].severity];
        expect(prevOrder).toBeLessThanOrEqual(currOrder);
      }
    });
  });

  describe('Empty directory handling', () => {
    const emptyDir = join(
      process.cwd(),
      'tests',
      'fixtures',
      '.tmp-empty-' + Date.now()
    );

    it('should produce T-META-002 for an empty directory', async () => {
      await mkdir(emptyDir, { recursive: true });

      const findings = await analyzer.analyze(emptyDir);

      expect(findings.length).toBe(1);
      expect(findings[0].id).toBe('T-META-002');
      expect(findings[0].severity).toBe('info');
      expect(findings[0].title).toMatch(/no scannable files/i);
    });

    afterAll(async () => {
      try {
        await rm(emptyDir, { recursive: true });
      } catch {
        // Ignore cleanup errors
      }
    });
  });
});
