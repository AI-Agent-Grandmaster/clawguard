/**
 * ClawGuard Orchestrator
 * Coordinates skill loading, analyzer execution, and result aggregation
 */
import * as fs from 'fs/promises';
import * as path from 'path';
import { calculateRiskScore, getRiskLevel, summarizeFindings, } from './types.js';
import { createStaticAnalyzer, createDependencyAnalyzer, createPromptAnalyzer, createSandboxAnalyzer, createSemanticAnalyzer, } from './analyzers/index.js';
import { loadConfig } from './config.js';
// ============================================================================
// SKILL.md Parsing
// ============================================================================
/** Regex for YAML frontmatter (--- at start, --- to end) */
const FRONTMATTER_REGEX = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/;
/**
 * Parse YAML frontmatter (simple key: value parsing)
 * For production, use the 'yaml' package
 */
function parseSimpleYaml(content) {
    const result = {};
    const lines = content.split('\n');
    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#'))
            continue;
        const colonIndex = trimmed.indexOf(':');
        if (colonIndex > 0) {
            const key = trimmed.slice(0, colonIndex).trim();
            let value = trimmed.slice(colonIndex + 1).trim();
            // Handle quoted strings
            if ((value.startsWith('"') && value.endsWith('"')) ||
                (value.startsWith("'") && value.endsWith("'"))) {
                value = value.slice(1, -1);
            }
            // Handle arrays (simple case: [a, b, c])
            if (value.startsWith('[') && value.endsWith(']')) {
                value = value.slice(1, -1).split(',').map(s => s.trim().replace(/['"]/g, ''));
            }
            result[key] = value;
        }
    }
    return result;
}
/**
 * Parse SKILL.md file and extract metadata
 */
export async function parseSkillMd(skillPath) {
    const skillMdPath = path.join(skillPath, 'SKILL.md');
    const dirName = path.basename(skillPath);
    // Default metadata using directory name
    const defaultMeta = {
        name: dirName,
        path: skillPath,
    };
    try {
        const content = await fs.readFile(skillMdPath, 'utf-8');
        const match = content.match(FRONTMATTER_REGEX);
        if (match) {
            const [, frontmatterStr, body] = match;
            const frontmatter = parseSimpleYaml(frontmatterStr);
            return {
                name: frontmatter.name || dirName,
                version: frontmatter.version,
                author: frontmatter.author,
                description: frontmatter.description,
                path: skillPath,
                tools: frontmatter.tools,
                frontmatter,
                body: body.trim(),
            };
        }
        else {
            // No frontmatter, entire file is body
            return {
                ...defaultMeta,
                body: content.trim(),
            };
        }
    }
    catch (error) {
        // SKILL.md doesn't exist or isn't readable
        if (error.code === 'ENOENT') {
            return defaultMeta;
        }
        throw error;
    }
}
/**
 * Main scan orchestrator
 * Loads skill, runs analyzers, aggregates results
 */
export class Orchestrator {
    analyzers = [];
    constructor() {
        // Register all analyzers
        this.analyzers = [
            { name: 'static', instance: createStaticAnalyzer() },
            { name: 'deps', instance: createDependencyAnalyzer() },
            { name: 'prompt', instance: createPromptAnalyzer() },
            { name: 'sandbox', instance: createSandboxAnalyzer(), skipUnlessSandbox: true },
        ];
    }
    /**
     * Get list of available analyzer names
     */
    getAnalyzerNames() {
        return this.analyzers.map(a => a.name);
    }
    /**
     * Run a full security scan on a skill
     */
    async scan(options) {
        const startTime = Date.now();
        // Resolve and validate path
        const skillPath = path.resolve(options.path);
        await this.validateSkillPath(skillPath);
        if (options.verbose) {
            console.log(`Scanning skill at: ${skillPath}`);
        }
        // Parse SKILL.md
        const meta = await parseSkillMd(skillPath);
        if (options.verbose) {
            console.log(`Skill: ${meta.name}${meta.version ? ` v${meta.version}` : ''}`);
        }
        // Run all analyzers
        const allFindings = [];
        const analyzersRun = [];
        // Build list of analyzers to run
        const analyzersToRun = [...this.analyzers];
        // Add semantic analyzer if requested
        if (options.semantic) {
            try {
                // Load config for provider/model settings
                const config = await loadConfig();
                const semanticAnalyzer = await createSemanticAnalyzer({
                    apiKey: options.apiKey || config.apiKey,
                    provider: config.provider,
                    model: config.model,
                    baseUrl: config.baseUrl
                });
                analyzersToRun.push({
                    name: 'semantic',
                    instance: semanticAnalyzer,
                    skipUnlessSemantic: true
                });
                if (options.verbose) {
                    console.log(`🧠 Semantic analysis: ${config.provider}/${config.model}`);
                }
            }
            catch (error) {
                console.warn('Semantic analyzer not available:', error.message);
            }
        }
        for (const analyzer of analyzersToRun) {
            // Skip sandbox unless explicitly requested
            if (analyzer.skipUnlessSandbox && !options.sandbox) {
                continue;
            }
            if (options.verbose) {
                console.log(`Running ${analyzer.name} analyzer...`);
            }
            try {
                const findings = await analyzer.instance.analyze(skillPath);
                allFindings.push(...findings);
                analyzersRun.push(analyzer.name);
            }
            catch (error) {
                // Log error but continue with other analyzers
                console.error(`Error in ${analyzer.name} analyzer:`, error);
            }
        }
        // Calculate results
        const riskScore = calculateRiskScore(allFindings);
        const riskLevel = getRiskLevel(riskScore);
        const summary = summarizeFindings(allFindings);
        const scanTime = Date.now() - startTime;
        return {
            skill: meta,
            findings: allFindings,
            riskScore,
            riskLevel,
            scanTime,
            analyzersRun,
            summary,
        };
    }
    /**
     * Validate that the skill path exists and is a directory
     */
    async validateSkillPath(skillPath) {
        try {
            const stat = await fs.stat(skillPath);
            if (!stat.isDirectory()) {
                throw new Error(`Path is not a directory: ${skillPath}`);
            }
        }
        catch (error) {
            if (error.code === 'ENOENT') {
                throw new Error(`Skill path does not exist: ${skillPath}`);
            }
            throw error;
        }
    }
}
/**
 * Create a new orchestrator instance
 */
export function createOrchestrator() {
    return new Orchestrator();
}
