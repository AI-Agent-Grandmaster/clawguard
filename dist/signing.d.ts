/**
 * ClawGuard Skill Signing
 *
 * Cryptographic provenance for skills:
 * - Generate keypairs for authors
 * - Sign skills with private key
 * - Verify signatures
 * - Chain of trust (author → auditor → registry)
 */
export interface SkillSignature {
    version: '1.0';
    skillHash: string;
    author: {
        id: string;
        publicKey: string;
        signature: string;
        signedAt: string;
    };
    audits?: Array<{
        auditorId: string;
        auditorPublicKey: string;
        signature: string;
        auditedAt: string;
        riskLevel: string;
        notes?: string;
    }>;
}
export interface KeyPair {
    publicKey: string;
    privateKey: string;
    id: string;
    createdAt: string;
}
/**
 * Generate a new keypair for signing
 */
export declare function generateKeyPair(authorId: string): Promise<KeyPair>;
/**
 * Load keypair from disk
 */
export declare function loadKeyPair(authorId: string): Promise<KeyPair | null>;
/**
 * Calculate deterministic hash of skill contents
 */
export declare function hashSkill(skillPath: string): Promise<string>;
/**
 * Sign a skill
 */
export declare function signSkill(skillPath: string, authorId: string): Promise<SkillSignature>;
/**
 * Verify skill signature
 */
export declare function verifySkill(skillPath: string): Promise<{
    valid: boolean;
    author?: string;
    signedAt?: string;
    audits?: number;
    error?: string;
}>;
/**
 * Add audit signature to skill
 */
export declare function auditSkill(skillPath: string, auditorId: string, riskLevel: string, notes?: string): Promise<void>;
