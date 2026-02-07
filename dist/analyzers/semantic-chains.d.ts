/**
 * ClawGuard Semantic Chain Analyzer
 *
 * Uses LLM to analyze MULTIPLE skills together for attack chains
 * that pattern matching can't catch:
 *
 * - Memory-based exfiltration (Skill A stages data, Skill B sends)
 * - Social engineering chains (Skill A builds trust, Skill B exploits)
 * - Delayed/conditional attacks across skills
 * - Subtle capability abuse combinations
 */
import type { Finding, Severity } from '../types.js';
interface SemanticChain {
    name: string;
    severity: Severity;
    skills_involved: string[];
    attack_flow: string;
    why_dangerous: string;
    data_at_risk: string[];
    detection_difficulty: string;
    evidence: string;
}
interface SemanticChainAnalysis {
    chains: SemanticChain[];
    summary: {
        total_chains: number;
        critical_chains: number;
        highest_risk_combination: string[];
        recommendation: string;
    };
}
/**
 * Analyze multiple skills for semantic attack chains using LLM
 */
export declare function analyzeSemanticChains(skillPaths: string[], options?: {
    apiKey?: string;
}): Promise<Finding[]>;
export { SemanticChain, SemanticChainAnalysis };
