/**
 * ClawGuard Honeypot Analyzer
 *
 * Injects fake credentials into the scan environment and monitors
 * if any skill attempts to access them.
 *
 * This catches credential theft that static analysis might miss.
 */
import type { Finding, Severity } from '../types.js';
interface HoneypotCredential {
    name: string;
    path: string;
    content: string;
    marker: string;
    severity: Severity;
    description: string;
}
interface HoneypotResult {
    credential: HoneypotCredential;
    accessed: boolean;
    accessTime?: Date;
    accessedBy?: string;
}
/**
 * Scan skill content for references to honeypot paths
 * This is a static check - doesn't require actual file deployment
 */
export declare function scanForCredentialAccess(skillPath: string): Promise<Finding[]>;
/**
 * Create a honeypot environment for behavioral testing
 * Returns a cleanup function
 */
export declare function createHoneypotEnvironment(): Promise<{
    homeDir: string;
    honeypots: HoneypotCredential[];
    cleanup: () => Promise<void>;
    checkAccess: () => Promise<HoneypotResult[]>;
}>;
/**
 * Convert honeypot results to findings
 */
export declare function honeypotResultsToFindings(results: HoneypotResult[]): Finding[];
export type { HoneypotCredential, HoneypotResult };
