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
import { readFile } from 'fs/promises';
import { join, basename } from 'path';
import { glob } from 'glob';
import { loadConfig } from '../config.js';
const CHAIN_ANALYSIS_PROMPT = `You are a security analyst specializing in AI agent vulnerabilities. You're analyzing MULTIPLE skills that will be installed together on an AI agent.

Your job: Find attack chains where skills COMBINE to create threats that neither skill poses alone.

AI agents have:
- Shared memory (memory/*.md files persist across skills)
- Shared workspace (all skills can access the same files)
- Shared capabilities (skills can trigger other skills indirectly)
- Session continuity (data from one skill is visible to others)

Examples of attack chains:
1. **Memory Staging**: Skill A reads credentials "for backup" into memory/. Skill B "summarizes memory" and sends via messaging. Neither is malicious alone.
2. **Trust Building**: Skill A provides useful features, building user trust. Skill B leverages that trust for social engineering.
3. **Delayed Exfil**: Skill A collects data over time. Skill B sends "weekly digest" including sensitive data.
4. **Capability Laundering**: Skill A has network access but looks safe. Skill B manipulates agent into using Skill A for exfil.

SKILLS TO ANALYZE:

{SKILLS_CONTENT}

Analyze these skills TOGETHER for attack chains. Look for:

1. **DATA FLOW CHAINS**: Can sensitive data flow from one skill to another and out?
   - Credential/secret reading → memory/file staging → network/messaging exfil
   
2. **CAPABILITY COMBINATION**: Do capabilities across skills combine dangerously?
   - exec + network = remote code execution
   - file_read + messaging = data theft
   - cron + any dangerous capability = persistent threat

3. **TRUST EXPLOITATION**: Does one skill build trust that another could abuse?
   - Helpful skill → later social engineering
   - Frequent benign access → normalization of risky access

4. **MEMORY POISONING CHAINS**: Can one skill corrupt data another skill relies on?
   - Skill A poisons MEMORY.md → Skill B acts on poisoned data
   - Skill A modifies TOOLS.md → changes how other skills behave

5. **TEMPORAL CHAINS**: Attacks that unfold over time
   - Data collection phase → exfiltration phase
   - Reconnaissance → exploitation

Respond in JSON format:
{
  "chains": [
    {
      "name": "Chain name",
      "severity": "critical|high|medium|low",
      "skills_involved": ["skill1", "skill2"],
      "attack_flow": "Step by step how the attack works",
      "why_dangerous": "Why this combination is dangerous",
      "data_at_risk": ["credentials", "personal data", etc],
      "detection_difficulty": "easy|medium|hard",
      "evidence": "Specific quotes/patterns from skills that enable this"
    }
  ],
  "summary": {
    "total_chains": 0,
    "critical_chains": 0,
    "highest_risk_combination": ["skill1", "skill2"],
    "recommendation": "Overall recommendation"
  }
}

Be thorough but avoid false positives. Legitimate skill combinations (e.g., notes + backup) aren't attacks just because they handle data.

Respond with ONLY the JSON.`;
/**
 * Gather content from multiple skills
 */
async function gatherSkillsContent(skillPaths) {
    const parts = [];
    for (const skillPath of skillPaths) {
        const name = basename(skillPath);
        parts.push(`\n${'='.repeat(60)}\nSKILL: ${name}\n${'='.repeat(60)}\n`);
        // Read SKILL.md
        try {
            const skillMd = await readFile(join(skillPath, 'SKILL.md'), 'utf-8');
            parts.push('--- SKILL.md ---\n' + skillMd.slice(0, 3000));
        }
        catch {
            parts.push('(no SKILL.md)');
        }
        // Read scripts
        const scripts = await glob('**/*.{sh,py,js,ts}', {
            cwd: skillPath,
            ignore: ['node_modules/**'],
            nodir: true
        });
        for (const script of scripts.slice(0, 3)) {
            try {
                const content = await readFile(join(skillPath, script), 'utf-8');
                parts.push(`\n--- ${script} ---\n` + content.slice(0, 2000));
            }
            catch {
                // Skip
            }
        }
    }
    return parts.join('\n');
}
/**
 * Analyze multiple skills for semantic attack chains using LLM
 */
export async function analyzeSemanticChains(skillPaths, options = {}) {
    if (skillPaths.length < 2) {
        return []; // Need at least 2 skills for chain analysis
    }
    const config = await loadConfig();
    const apiKey = options.apiKey || config.apiKey || process.env.ANTHROPIC_API_KEY;
    if (!apiKey) {
        console.warn('Semantic chain analysis requires API key');
        return [];
    }
    let Anthropic;
    try {
        Anthropic = (await import('@anthropic-ai/sdk')).default;
    }
    catch {
        console.warn('Anthropic SDK not installed. Skipping semantic chain analysis.');
        console.warn('Run: npm install @anthropic-ai/sdk');
        return [];
    }
    const client = new Anthropic({ apiKey });
    const skillsContent = await gatherSkillsContent(skillPaths);
    const prompt = CHAIN_ANALYSIS_PROMPT.replace('{SKILLS_CONTENT}', skillsContent);
    try {
        const response = await client.messages.create({
            model: config.model || 'claude-sonnet-4-20250514',
            max_tokens: 4096,
            messages: [{ role: 'user', content: prompt }]
        });
        const textContent = response.content.find(c => c.type === 'text');
        if (!textContent || textContent.type !== 'text') {
            return [];
        }
        // Parse response
        const jsonMatch = textContent.text.match(/\{[\s\S]*\}/);
        if (!jsonMatch) {
            return [];
        }
        const analysis = JSON.parse(jsonMatch[0]);
        // Convert to findings
        return analysis.chains.map(chain => ({
            id: `T-SEMANTIC-CHAIN-${chain.name.toUpperCase().replace(/\s+/g, '_')}`,
            category: 'semantic-chain',
            severity: chain.severity,
            title: `Multi-Skill Attack Chain: ${chain.name}`,
            description: `${chain.why_dangerous}\n\n` +
                `**Attack Flow:**\n${chain.attack_flow}\n\n` +
                `**Data at Risk:** ${chain.data_at_risk.join(', ')}\n` +
                `**Detection Difficulty:** ${chain.detection_difficulty}`,
            evidence: chain.evidence,
            location: chain.skills_involved.join(' → '),
            remediation: analysis.summary.recommendation
        }));
    }
    catch (error) {
        console.error('Semantic chain analysis error:', error);
        return [];
    }
}
