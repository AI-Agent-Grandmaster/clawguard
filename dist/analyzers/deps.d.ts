/**
 * ClawGuard Dependency Scanner
 *
 * Analyzes package dependencies for:
 * - Known malicious packages
 * - Typosquatting (Levenshtein distance ≤2 from popular packages)
 * - Package registry existence
 * - Suspicious package characteristics (age, install scripts)
 */
import type { Finding, Analyzer } from '../types.js';
interface DepsPatterns {
    malicious_npm: Array<{
        name: string;
        versions: string[];
        reason: string;
    }>;
    malicious_pip: Array<{
        name: string;
        versions: string[];
        reason: string;
    }>;
    malicious_go: Array<{
        name: string;
        versions: string[];
        reason: string;
    }>;
    popular_npm: string[];
    popular_pip: string[];
    popular_go: string[];
}
interface Dependency {
    name: string;
    version: string;
    source: string;
}
/**
 * Load dependency patterns from YAML
 */
export declare function loadPatterns(): Promise<DepsPatterns>;
/**
 * Parse package.json dependencies
 */
export declare function parsePackageJson(path: string): Promise<Dependency[]>;
/**
 * Parse requirements.txt dependencies
 */
export declare function parseRequirementsTxt(path: string): Promise<Dependency[]>;
/**
 * Parse go.mod dependencies
 */
export declare function parseGoMod(path: string): Promise<Dependency[]>;
/**
 * Dependency Scanner implementation
 */
export declare class DepsAnalyzer implements Analyzer {
    name: string;
    private checkRegistry;
    constructor(options?: {
        checkRegistry?: boolean;
    });
    analyze(skillPath: string): Promise<Finding[]>;
}
export declare const depsAnalyzer: DepsAnalyzer;
export { DepsAnalyzer as DependencyAnalyzer };
export declare function createDependencyAnalyzer(options?: {
    checkRegistry?: boolean;
}): DepsAnalyzer;
export type { DepsPatterns, Dependency };
