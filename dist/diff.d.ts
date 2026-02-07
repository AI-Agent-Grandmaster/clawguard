/**
 * ClawGuard Differential Analysis
 *
 * Track skill versions and detect suspicious changes:
 * - "v1.2.3 added network access that wasn't in 1.2.2"
 * - Capability creep detection
 * - Content diff between versions
 */
import type { Finding } from './types.js';
interface SkillSnapshot {
    hash: string;
    version?: string;
    capturedAt: string;
    capabilities: string[];
    fileHashes: Record<string, string>;
    sensitivePatterns: string[];
}
interface SkillHistory {
    skillName: string;
    skillPath: string;
    snapshots: SkillSnapshot[];
}
/**
 * Create snapshot of skill
 */
export declare function createSnapshot(skillPath: string): Promise<SkillSnapshot>;
/**
 * Analyze skill for changes from previous version
 */
export declare function analyzeDiff(skillPath: string): Promise<{
    findings: Finding[];
    isNew: boolean;
    previousVersion?: string;
    currentVersion?: string;
}>;
/**
 * Get skill history
 */
export declare function getHistory(skillName: string): Promise<SkillHistory | null>;
/**
 * Clear skill history
 */
export declare function clearHistory(skillName: string): Promise<void>;
export {};
