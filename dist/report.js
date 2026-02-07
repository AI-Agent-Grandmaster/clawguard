/**
 * ClawGuard Report Generator
 * Formats scan results for output
 */
// ============================================================================
// Risk Level Emoji
// ============================================================================
const RISK_EMOJI = {
    SAFE: '🟢',
    LOW: '🟡',
    MEDIUM: '🟠',
    HIGH: '🔴',
    CRITICAL: '⛔',
};
const SEVERITY_EMOJI = {
    critical: '⛔',
    high: '🔴',
    medium: '🟠',
    low: '🟡',
    info: 'ℹ️',
};
// ============================================================================
// JSON Output
// ============================================================================
/**
 * Format scan result as JSON
 */
export function formatJson(result) {
    return JSON.stringify({
        skill: {
            name: result.skill.name,
            version: result.skill.version,
            path: result.skill.path,
        },
        riskScore: result.riskScore,
        riskLevel: result.riskLevel,
        findings: result.findings,
        summary: result.summary,
        scanTime: result.scanTime,
        analyzersRun: result.analyzersRun,
    }, null, 2);
}
// ============================================================================
// Markdown Output
// ============================================================================
/**
 * Format scan result as Markdown
 */
export function formatMarkdown(result) {
    const lines = [];
    // Header
    lines.push('# ClawGuard Security Report');
    lines.push('');
    // Skill info
    lines.push(`## Skill: ${result.skill.name}`);
    if (result.skill.version) {
        lines.push(`**Version:** ${result.skill.version}`);
    }
    lines.push(`**Path:** \`${result.skill.path}\``);
    lines.push('');
    // Risk assessment
    const emoji = RISK_EMOJI[result.riskLevel] || '❓';
    lines.push(`**Risk Level:** ${emoji} **${result.riskLevel}** (${result.riskScore}/100)`);
    lines.push('');
    // Summary
    lines.push('### Summary');
    lines.push('');
    if (result.findings.length === 0) {
        lines.push('✅ No security issues found.');
    }
    else {
        lines.push(`| Severity | Count |`);
        lines.push(`|----------|-------|`);
        lines.push(`| ⛔ Critical | ${result.summary.critical} |`);
        lines.push(`| 🔴 High | ${result.summary.high} |`);
        lines.push(`| 🟠 Medium | ${result.summary.medium} |`);
        lines.push(`| 🟡 Low | ${result.summary.low} |`);
        lines.push(`| ℹ️ Info | ${result.summary.info} |`);
    }
    lines.push('');
    // Findings by severity
    const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
    for (const severity of severityOrder) {
        const findings = result.findings.filter(f => f.severity === severity);
        if (findings.length === 0)
            continue;
        const emoji = SEVERITY_EMOJI[severity];
        lines.push(`### ${emoji} ${capitalize(severity)} Findings`);
        lines.push('');
        for (const finding of findings) {
            lines.push(formatFinding(finding));
            lines.push('');
        }
    }
    // Footer
    lines.push('---');
    lines.push(`*Scan completed in ${result.scanTime}ms*`);
    lines.push(`*Analyzers run: ${result.analyzersRun.join(', ')}*`);
    return lines.join('\n');
}
/**
 * Format a single finding as Markdown
 */
function formatFinding(finding) {
    const lines = [];
    lines.push(`#### ${finding.id}: ${finding.title}`);
    lines.push('');
    lines.push(finding.description);
    if (finding.location) {
        lines.push('');
        lines.push(`**Location:** \`${finding.location}\``);
    }
    if (finding.evidence) {
        lines.push('');
        lines.push('**Evidence:**');
        lines.push('```');
        lines.push(finding.evidence);
        lines.push('```');
    }
    if (finding.remediation) {
        lines.push('');
        lines.push(`**Remediation:** ${finding.remediation}`);
    }
    return lines.join('\n');
}
/**
 * Capitalize first letter
 */
function capitalize(str) {
    return str.charAt(0).toUpperCase() + str.slice(1);
}
// ============================================================================
// Console Output (with colors)
// ============================================================================
/**
 * Format scan result for console output
 * Uses ANSI colors when supported
 */
export function formatConsole(result) {
    // For now, return markdown. In future, add chalk colors.
    return formatMarkdown(result);
}
// ============================================================================
// Main Format Function
// ============================================================================
/**
 * Format scan result based on output type
 */
export function formatResult(result, format = 'md') {
    switch (format) {
        case 'json':
            return formatJson(result);
        case 'md':
            return formatMarkdown(result);
        case 'html':
            // TODO: Implement HTML output
            return `<html><body><pre>${formatMarkdown(result)}</pre></body></html>`;
        default:
            return formatMarkdown(result);
    }
}
