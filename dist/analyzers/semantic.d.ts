/**
 * ClawGuard Semantic Analyzer
 *
 * Uses LLMs to analyze skills for malicious intent, capability abuse,
 * and attacks that static analysis can't catch.
 *
 * Supports multiple providers: Anthropic, OpenAI, and local models (Ollama).
 */
import type { Finding, Analyzer } from '../types.js';
interface SemanticAnalyzerOptions {
    apiKey?: string;
    provider?: 'anthropic' | 'openai' | 'local';
    model?: string;
    maxTokens?: number;
    baseUrl?: string;
}
export declare class SemanticAnalyzer implements Analyzer {
    name: string;
    private provider;
    private maxTokens;
    private constructor();
    static create(options?: SemanticAnalyzerOptions): Promise<SemanticAnalyzer>;
    private static getDefaultModelStatic;
    private getDefaultModel;
    analyze(skillPath: string): Promise<Finding[]>;
    private gatherSkillContent;
    private parseAnalysis;
    private convertToFindings;
}
/**
 * Create a semantic analyzer instance from config
 */
export declare function createSemanticAnalyzerFromConfig(overrideApiKey?: string): Promise<SemanticAnalyzer>;
/**
 * Create a semantic analyzer instance with explicit options
 */
export declare function createSemanticAnalyzer(options?: SemanticAnalyzerOptions): Promise<SemanticAnalyzer>;
export default createSemanticAnalyzer;
