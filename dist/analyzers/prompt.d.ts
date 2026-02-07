/**
 * ClawGuard Prompt Analyzer
 *
 * Detects prompt injection attacks in SKILL.md files including:
 * - Direct instruction overrides
 * - Persona manipulation / jailbreaks
 * - Hidden instructions (unicode, whitespace)
 * - Conditional/time-based triggers
 * - Tool abuse instructions
 */
import type { Finding, SkillDocument } from '../types.js';
/**
 * Detect invisible unicode characters in text
 */
export declare function detectInvisibleUnicode(text: string): Array<{
    char: string;
    codePoint: string;
    position: number;
    context: string;
}>;
/**
 * Check if text contains invisible unicode (boolean helper for pattern matching)
 */
export declare function containsInvisibleUnicode(text: string): boolean;
/**
 * Detect hidden whitespace blocks (excessive spaces/newlines that might hide content)
 */
export declare function detectHiddenWhitespace(text: string): Array<{
    start: number;
    end: number;
    length: number;
    type: string;
    suspiciousContext?: string;
}>;
/**
 * Check if text has suspicious whitespace blocks
 */
export declare function hasHiddenWhitespaceBlocks(text: string): boolean;
/**
 * Detect homoglyph obfuscation
 */
export declare function detectHomoglyphs(text: string): Array<{
    char: string;
    looksLike: string;
    position: number;
    word: string;
}>;
/**
 * Check if text has homoglyph obfuscation
 */
export declare function hasHomoglyphObfuscation(text: string): boolean;
/**
 * Detect RTL (right-to-left) override attacks
 */
export declare function detectRtlOverride(text: string): Array<{
    position: number;
    type: string;
    context: string;
}>;
/**
 * Check if text has RTL override
 */
export declare function hasRtlOverride(text: string): boolean;
interface ParsedSkillDoc {
    frontmatter: Record<string, unknown>;
    body: string;
    raw: string;
}
/**
 * Parse a SKILL.md file into frontmatter (YAML) and body (Markdown)
 */
export declare function parseSkillDocument(content: string): ParsedSkillDoc;
/**
 * Prompt Analyzer class
 * Detects prompt injection attacks in SKILL.md files
 */
export declare class PromptAnalyzer {
    readonly name = "prompt";
    private patterns;
    private patternsLoaded;
    private ensurePatternsLoaded;
    private analyzeContent;
    /**
     * Analyze a skill path for prompt injection attacks
     */
    analyze(skillPath: string, skillDoc?: SkillDocument): Promise<Finding[]>;
}
export declare function createPromptAnalyzer(): PromptAnalyzer;
export default PromptAnalyzer;
