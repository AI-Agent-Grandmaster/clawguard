/**
 * ClawGuard shared type definitions
 */
// ============== Risk Scoring ==============
export const SEVERITY_WEIGHTS = {
    critical: 25,
    high: 10,
    medium: 4,
    low: 1,
    info: 0,
};
export const RISK_THRESHOLDS = {
    SAFE: 10,
    LOW: 25,
    MEDIUM: 50,
    HIGH: 75,
};
/**
 * Calculate the risk score from findings
 */
export function calculateRiskScore(findings) {
    const score = findings.reduce((sum, f) => sum + SEVERITY_WEIGHTS[f.severity], 0);
    return Math.min(100, score);
}
/**
 * Get risk level from score
 */
export function getRiskLevel(score) {
    if (score <= RISK_THRESHOLDS.SAFE)
        return 'SAFE';
    if (score <= RISK_THRESHOLDS.LOW)
        return 'LOW';
    if (score <= RISK_THRESHOLDS.MEDIUM)
        return 'MEDIUM';
    if (score <= RISK_THRESHOLDS.HIGH)
        return 'HIGH';
    return 'CRITICAL';
}
/**
 * Summarize findings by severity
 */
export function summarizeFindings(findings) {
    const summary = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
    };
    for (const f of findings) {
        summary[f.severity]++;
    }
    return summary;
}
