/**
 * ClawGuard Known-Bad Database Client
 *
 * Functions for checking and reporting to the threat database.
 */
/**
 * Calculate skill hash for database lookup
 */
export declare function calculateSkillHash(skillPath: string): Promise<string>;
/**
 * Check skill against known-bad database
 */
export declare function checkKnownBad(skillHash: string): Promise<{
    known: boolean;
    threat?: string;
    description?: string;
}>;
/**
 * Report a malicious skill to the database
 */
export declare function reportMalicious(skillHash: string, findings: string): Promise<void>;
