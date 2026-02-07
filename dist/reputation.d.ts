/**
 * ClawGuard Community Reputation
 *
 * Trust signals from the community:
 * - "Audited by 47 agents, 0 issues" badges
 * - Author reputation scores
 * - Skill popularity and trust metrics
 */
export interface SkillReputation {
    skillHash: string;
    skillName: string;
    totalScans: number;
    uniqueScanners: number;
    lastScanned: string;
    passCount: number;
    failCount: number;
    passRate: number;
    auditCount: number;
    trustedAuditors: string[];
    averageRiskScore: number;
    highestRiskScore: number;
    badge: 'verified' | 'trusted' | 'community' | 'unverified' | 'flagged';
    badgeReason: string;
}
export interface AuthorReputation {
    authorId: string;
    totalSkills: number;
    totalScans: number;
    verifiedIdentity: boolean;
    trustedBy: number;
    flaggedBy: number;
    reputationScore: number;
    badge: 'trusted' | 'verified' | 'new' | 'flagged';
}
/**
 * Get reputation for a skill
 */
export declare function getSkillReputation(skillHash: string): Promise<SkillReputation | null>;
/**
 * Get reputation for an author
 */
export declare function getAuthorReputation(authorId: string): Promise<AuthorReputation | null>;
/**
 * Report a successful scan (contributes to reputation)
 */
export declare function reportScan(params: {
    skillHash: string;
    skillName: string;
    scannerId: string;
    passed: boolean;
    riskScore: number;
    findings: number;
}): Promise<void>;
/**
 * Format reputation as badge string
 */
export declare function formatBadge(rep: SkillReputation): string;
/**
 * Format author reputation
 */
export declare function formatAuthorBadge(rep: AuthorReputation): string;
/**
 * Calculate badge from stats
 */
export declare function calculateBadge(stats: {
    totalScans: number;
    passRate: number;
    auditCount: number;
    flagCount: number;
}): SkillReputation['badge'];
/**
 * Flush pending reports
 */
export declare function flushPendingReports(): Promise<number>;
