/**
 * ClawGuard Attack Chain Analyzer
 *
 * Analyzes multiple skills TOGETHER to find dangerous combinations
 * that wouldn't be flagged when analyzing skills in isolation.
 *
 * Example: weather-skill (network) + notes-skill (file read) = exfil chain
 */
import type { Finding } from '../types.js';
type Capability = 'file_read' | 'file_write' | 'network_out' | 'network_in' | 'exec' | 'messaging' | 'browser' | 'cron' | 'env_access' | 'credential_access';
interface SkillCapabilities {
    name: string;
    path: string;
    capabilities: Set<Capability>;
    sensitiveReads: string[];
    networkTargets: string[];
    writeTargets: string[];
}
/**
 * Analyze multiple skills for dangerous attack chains
 */
export declare function analyzeAttackChains(skillPaths: string[]): Promise<Finding[]>;
/**
 * Generate a capability report for a set of skills
 */
export declare function generateCapabilityReport(skillPaths: string[]): Promise<{
    skills: SkillCapabilities[];
    chains: Finding[];
    summary: {
        totalSkills: number;
        totalCapabilities: number;
        dangerousChains: number;
        criticalChains: number;
    };
}>;
export { SkillCapabilities, Capability };
