#!/usr/bin/env node
/**
 * ClawGuard CLI
 * Revolutionary security scanner for AI agent skills
 */
import { Command } from 'commander';
import { createOrchestrator } from './orchestrator.js';
import { formatResult } from './report.js';
import { generateCapabilityReport, analyzeSemanticChains, scanForCredentialAccess, buildIntentGraph, renderGraphAscii, renderGraphMermaid } from './analyzers/index.js';
import { glob } from 'glob';
import { join } from 'path';
import { showConfig, clearConfig, loadConfig, getApiKey, testConfig } from './config.js';
import { showHelp } from './help.js';
import { signSkill, verifySkill, generateKeyPair, auditSkill } from './signing.js';
import { analyzeDiff, getHistory } from './diff.js';
import { getSkillReputation, getAuthorReputation, formatBadge } from './reputation.js';
import { getMonitor, startMonitor, stopMonitor } from './monitor.js';
import { startDashboard } from './dashboard.js';
import { fetchSkillFromUrl, isUrl } from './fetch.js';
const VERSION = '1.0.0';
function createProgram() {
    const program = new Command();
    program
        .name('clawguard')
        .description('Revolutionary security scanner for AI agent skills')
        .version(VERSION);
    // ========== SCAN COMMAND (single skill) ==========
    program
        .command('scan <path>')
        .description('Scan a skill for security issues (local path or URL)')
        .option('-o, --output <format>', 'Output format: json, md (default: md)', 'md')
        .option('-d, --deep', 'Enable deep dependency source analysis')
        .option('-s, --sandbox', 'Run behavioral sandbox tests (requires Docker)')
        .option('-f, --fast', 'Static analysis only (skip semantic)')
        .option('--static-only', 'Static analysis only (skip semantic)')
        .option('--api-key <key>', 'API key for semantic analysis')
        .option('-v, --verbose', 'Enable verbose output')
        .option('--keep', 'Keep downloaded files after scan (for URLs)')
        .action(async (skillPath, options) => {
        let fetchResult = null;
        try {
            let actualPath = skillPath;
            // Check if it's a URL
            if (isUrl(skillPath)) {
                fetchResult = await fetchSkillFromUrl(skillPath);
                actualPath = fetchResult.localPath;
                console.log(`✓ Downloaded to ${actualPath}`);
                console.log('');
            }
            await runScan(actualPath, options);
        }
        catch (error) {
            console.error('Error:', error.message);
            process.exit(1);
        }
        finally {
            // Cleanup temp files unless --keep
            if (fetchResult && !options.keep) {
                await fetchResult.cleanup();
            }
            else if (fetchResult && options.keep) {
                console.log(`\n📁 Files kept at: ${fetchResult.localPath}`);
            }
        }
    });
    // ========== LIBRARY COMMAND (multi-skill attack chains) ==========
    program
        .command('library <path>')
        .description('Analyze an entire skill library for attack chains')
        .option('-o, --output <format>', 'Output format: json, md (default: md)', 'md')
        .option('-f, --fast', 'Pattern analysis only (skip semantic)')
        .option('--static-only', 'Pattern analysis only (skip semantic)')
        .option('-v, --verbose', 'Enable verbose output')
        .action(async (libraryPath, options) => {
        try {
            await runLibraryScan(libraryPath, options);
        }
        catch (error) {
            console.error('Error:', error.message);
            process.exit(1);
        }
    });
    // ========== GRAPH COMMAND (intent visualization) ==========
    program
        .command('graph <path>')
        .description('Generate intent graph showing data flow')
        .option('-f, --format <type>', 'Output format: ascii, mermaid (default: ascii)', 'ascii')
        .action(async (skillPath, options) => {
        try {
            await runGraph(skillPath, options);
        }
        catch (error) {
            console.error('Error:', error.message);
            process.exit(1);
        }
    });
    // ========== HONEYPOT COMMAND (credential access scan) ==========
    program
        .command('honeypot <path>')
        .description('Scan for credential access patterns')
        .option('-v, --verbose', 'Enable verbose output')
        .action(async (skillPath, options) => {
        try {
            await runHoneypotScan(skillPath, options);
        }
        catch (error) {
            console.error('Error:', error.message);
            process.exit(1);
        }
    });
    // ========== FULL COMMAND (everything) ==========
    program
        .command('full <path>')
        .description('Run ALL analyzers (static + semantic + honeypot + graph)')
        .option('-o, --output <format>', 'Output format: json, md (default: md)', 'md')
        .option('--api-key <key>', 'Anthropic API key for semantic analysis')
        .option('-v, --verbose', 'Enable verbose output')
        .action(async (skillPath, options) => {
        try {
            await runFullScan(skillPath, options);
        }
        catch (error) {
            console.error('Error:', error.message);
            process.exit(1);
        }
    });
    // ========== CONFIG COMMAND ==========
    program
        .command('config')
        .description('Configure ClawGuard (API keys, model selection)')
        .option('--show', 'Show current configuration')
        .option('--clear', 'Clear stored configuration')
        .option('--test', 'Test API connection')
        .action(async (options) => {
        if (options.show) {
            await showConfig();
        }
        else if (options.clear) {
            await clearConfig();
        }
        else if (options.test) {
            const success = await testConfig();
            process.exit(success ? 0 : 1);
        }
        else {
            // Launch TUI config wizard
            const { runTui } = await import('./tui.js');
            await runTui({ configOnly: true });
        }
    });
    // ========== INIT COMMAND (alias for config) ==========
    program
        .command('init')
        .description('Initialize ClawGuard with setup wizard')
        .action(async () => {
        // Launch TUI config wizard
        const { runTui } = await import('./tui.js');
        await runTui({ configOnly: true });
    });
    program
        .command('version')
        .description('Show version information')
        .action(() => {
        console.log(`ClawGuard v${VERSION}`);
        console.log('Revolutionary security scanner for AI agent skills');
    });
    // ========== INTERACTIVE TUI ==========
    program
        .command('ui')
        .alias('tui')
        .description('Launch interactive terminal interface')
        .action(async () => {
        const { runTui } = await import('./tui.js');
        await runTui();
    });
    // ========== DETAILED HELP ==========
    program
        .command('help [topic]')
        .description('Show detailed help (topics: about, scan, library, sandbox, gate, config, ui)')
        .action((topic) => {
        showHelp(topic || 'about');
    });
    // ========== ABOUT (alias for help) ==========
    program
        .command('about')
        .description('Learn how ClawGuard protects you')
        .action(() => {
        showHelp('about');
    });
    // ========== PRE-INSTALL GATE ==========
    program
        .command('gate <path>')
        .description('Pre-install security gate - blocks install if critical issues found (local path or URL)')
        .option('-s, --sandbox', 'Include behavioral sandbox analysis')
        .option('--allow-high', 'Allow high-risk skills (only block critical)')
        .option('--json', 'Output JSON result')
        .action(async (skillPath, options) => {
        let fetchResult = null;
        try {
            let actualPath = skillPath;
            // Check if it's a URL
            if (isUrl(skillPath)) {
                fetchResult = await fetchSkillFromUrl(skillPath);
                actualPath = fetchResult.localPath;
                if (!options.json) {
                    console.log(`✓ Downloaded to ${actualPath}`);
                }
            }
            await runGate(actualPath, options);
        }
        catch (error) {
            console.error('Gate error:', error.message);
            process.exit(1);
        }
        finally {
            if (fetchResult) {
                await fetchResult.cleanup();
            }
        }
    });
    // ========== SKILL SIGNING ==========
    program
        .command('sign <path>')
        .description('Sign a skill with your private key')
        .option('--generate <id>', 'Generate a new keypair')
        .option('--verify', 'Verify existing signature instead of signing')
        .option('--audit <risk>', 'Add audit signature (SAFE/LOW/MEDIUM/HIGH/CRITICAL)')
        .option('--auditor <id>', 'Auditor ID for audit signature')
        .action(async (skillPath, options) => {
        try {
            if (options.generate) {
                await generateKeyPair(options.generate);
                return;
            }
            if (options.verify) {
                const result = await verifySkill(skillPath);
                if (result.valid) {
                    console.log(`✅ Valid signature`);
                    console.log(`   Author: ${result.author}`);
                    console.log(`   Signed: ${result.signedAt}`);
                    console.log(`   Audits: ${result.audits}`);
                }
                else {
                    console.log(`❌ Invalid: ${result.error}`);
                    process.exit(1);
                }
                return;
            }
            if (options.audit) {
                if (!options.auditor) {
                    console.error('Error: --auditor required for audit');
                    process.exit(1);
                }
                await auditSkill(skillPath, options.auditor, options.audit);
                return;
            }
            // Default: sign with default key
            const config = await loadConfig();
            const authorId = 'default'; // Could be configurable
            await signSkill(skillPath, authorId);
        }
        catch (error) {
            console.error('Sign error:', error.message);
            process.exit(1);
        }
    });
    // ========== DIFFERENTIAL ANALYSIS ==========
    program
        .command('diff <path>')
        .description('Analyze changes from previous version')
        .option('--history', 'Show full version history')
        .action(async (skillPath, options) => {
        try {
            if (options.history) {
                const skillName = skillPath.split('/').pop() || 'unknown';
                const history = await getHistory(skillName);
                if (!history) {
                    console.log('No history found for this skill.');
                    return;
                }
                console.log(`📜 History for ${skillName}:`);
                for (const snap of history.snapshots) {
                    console.log(`   ${snap.capturedAt} - v${snap.version || '?'} (${snap.capabilities.join(', ') || 'no caps'})`);
                }
                return;
            }
            const result = await analyzeDiff(skillPath);
            if (result.isNew) {
                console.log('📦 First scan of this skill - baseline captured.');
                return;
            }
            console.log(`📊 Comparing versions: ${result.previousVersion || '?'} → ${result.currentVersion || '?'}`);
            if (result.findings.length === 0) {
                console.log('✅ No significant changes detected.');
            }
            else {
                console.log(`⚠️  ${result.findings.length} change(s) detected:\n`);
                for (const f of result.findings) {
                    const icon = f.severity === 'high' ? '🔴' : f.severity === 'medium' ? '🟠' : 'ℹ️';
                    console.log(`${icon} ${f.title}`);
                    console.log(`   ${f.description.split('\n')[0]}\n`);
                }
            }
        }
        catch (error) {
            console.error('Diff error:', error.message);
            process.exit(1);
        }
    });
    // ========== REPUTATION ==========
    program
        .command('reputation <target>')
        .description('Check community reputation for skill or author')
        .option('--author', 'Check author reputation instead of skill')
        .action(async (target, options) => {
        try {
            if (options.author) {
                const rep = await getAuthorReputation(target);
                if (rep) {
                    console.log(`👤 Author: ${rep.authorId}`);
                    console.log(`   Score: ${rep.reputationScore}/100`);
                    console.log(`   Skills: ${rep.totalSkills}`);
                    console.log(`   Badge: ${rep.badge}`);
                }
                else {
                    console.log('No reputation data found for this author.');
                }
            }
            else {
                // Calculate hash if path provided
                const { calculateSkillHash } = await import('./database.js');
                const hash = target.match(/^[a-f0-9]{64}$/i) ? target : await calculateSkillHash(target);
                const rep = await getSkillReputation(hash);
                if (rep) {
                    console.log(formatBadge(rep));
                    console.log(`   Scans: ${rep.totalScans} (${rep.uniqueScanners} unique scanners)`);
                    console.log(`   Audits: ${rep.auditCount}`);
                    console.log(`   Avg risk: ${rep.averageRiskScore}/100`);
                }
                else {
                    console.log('No reputation data found. This skill may not have been scanned by the community yet.');
                }
            }
        }
        catch (error) {
            console.error('Reputation error:', error.message);
            process.exit(1);
        }
    });
    // ========== CONTINUOUS MONITORING ==========
    program
        .command('monitor')
        .description('Continuous monitoring for installed skills')
        .option('--start', 'Start the monitor daemon')
        .option('--stop', 'Stop the monitor daemon')
        .option('--add <path>', 'Add a skill path to watch')
        .option('--remove <path>', 'Remove a skill path from watch')
        .option('--enable', 'Enable monitoring')
        .option('--disable', 'Disable monitoring')
        .option('--status', 'Show monitor status')
        .option('--alerts', 'Show recent alerts')
        .action(async (options) => {
        try {
            const monitor = getMonitor();
            await monitor.loadConfig();
            if (options.start) {
                await startMonitor();
                console.log('Monitor running. Press Ctrl+C to stop.');
                // Keep running
                await new Promise(() => { });
            }
            if (options.stop) {
                await stopMonitor();
                return;
            }
            if (options.add) {
                await monitor.addPath(options.add);
                console.log(`✓ Added ${options.add} to watch list`);
                return;
            }
            if (options.remove) {
                await monitor.removePath(options.remove);
                console.log(`✓ Removed ${options.remove} from watch list`);
                return;
            }
            if (options.enable) {
                await monitor.enable();
                console.log('✓ Monitoring enabled');
                return;
            }
            if (options.disable) {
                await monitor.disable();
                console.log('✓ Monitoring disabled');
                return;
            }
            if (options.alerts) {
                const alerts = await monitor.getAlerts(20);
                if (alerts.length === 0) {
                    console.log('No recent alerts.');
                }
                else {
                    console.log('Recent alerts:\n');
                    for (const a of alerts) {
                        const icon = a.severity === 'critical' ? '🚨' : a.severity === 'warning' ? '⚠️' : 'ℹ️';
                        console.log(`${icon} [${a.skillName}] ${a.message}`);
                        console.log(`   ${a.timestamp}\n`);
                    }
                }
                return;
            }
            // Default: show status
            const config = monitor.getConfig();
            console.log('📡 ClawGuard Monitor Status\n');
            console.log(`   Enabled: ${config.enabled ? 'Yes' : 'No'}`);
            console.log(`   Watch paths: ${config.watchPaths.length}`);
            for (const p of config.watchPaths) {
                console.log(`     - ${p}`);
            }
            console.log(`   Scan interval: ${config.scanIntervalMs / 1000}s`);
            if (config.alertWebhook) {
                console.log(`   Webhook: ${config.alertWebhook}`);
            }
        }
        catch (error) {
            console.error('Monitor error:', error.message);
            process.exit(1);
        }
    });
    // ========== DASHBOARD ==========
    program
        .command('dashboard')
        .description('Start the web dashboard')
        .option('-p, --port <port>', 'Port to run on', '18790')
        .action(async (options) => {
        try {
            await startDashboard(parseInt(options.port));
            console.log('Dashboard running. Press Ctrl+C to stop.');
            await new Promise(() => { });
        }
        catch (error) {
            console.error('Dashboard error:', error.message);
            process.exit(1);
        }
    });
    return program;
}
/**
 * Run standard scan on a single skill
 */
async function runScan(skillPath, options) {
    const outputFormat = (options.output || 'md');
    const skipSemantic = options.fast || options.staticOnly;
    // Load config
    let config = await loadConfig();
    // Determine if we should run semantic analysis
    // Default: ON if configured, OFF if not (unless --fast/--static-only)
    let runSemantic = !skipSemantic && (config.configured || !!options.apiKey);
    // Get API key
    let apiKey = options.apiKey;
    if (runSemantic && !apiKey) {
        apiKey = await getApiKey();
        if (!apiKey) {
            // No key available, fall back to static only
            runSemantic = false;
            if (options.verbose) {
                console.log('ℹ️  No API key configured. Running static analysis only.');
                console.log('   Run `clawguard config` to enable semantic analysis.');
                console.log('');
            }
        }
    }
    if (options.verbose) {
        console.log('ClawGuard Security Scanner v' + VERSION);
        console.log('═'.repeat(50));
        if (runSemantic) {
            console.log(`🧠 Semantic analysis: ENABLED (${config.model || 'default'})`);
        }
        else {
            console.log('📋 Static analysis only');
        }
        console.log('');
    }
    const orchestrator = createOrchestrator();
    const result = await orchestrator.scan({
        path: skillPath,
        deep: options.deep,
        sandbox: options.sandbox,
        semantic: runSemantic,
        apiKey: apiKey,
        output: outputFormat,
        verbose: options.verbose,
    });
    const output = formatResult(result, outputFormat);
    console.log(output);
    if (result.summary.critical > 0)
        process.exit(2);
    if (result.summary.high > 0)
        process.exit(1);
}
/**
 * Scan entire skill library for attack chains
 */
async function runLibraryScan(libraryPath, options) {
    const skipSemantic = options.fast || options.staticOnly;
    const config = await loadConfig();
    const runSemantic = !skipSemantic && config.configured;
    console.log('ClawGuard Library Scanner v' + VERSION);
    console.log('═'.repeat(50));
    console.log('Analyzing skill library for attack chains...');
    if (runSemantic) {
        console.log('🧠 Semantic chain analysis: ENABLED');
    }
    else if (!skipSemantic && !config.configured) {
        console.log('📋 Pattern analysis only (run `clawguard config` for semantic)');
    }
    console.log('');
    // Find all skill directories (contain SKILL.md)
    const skillMdFiles = await glob('**/SKILL.md', {
        cwd: libraryPath,
        ignore: ['node_modules/**', '.git/**']
    });
    const skillPaths = skillMdFiles.map(f => join(libraryPath, f.replace('/SKILL.md', '')));
    if (skillPaths.length === 0) {
        console.log('No skills found in', libraryPath);
        return;
    }
    console.log(`Found ${skillPaths.length} skills:`);
    for (const p of skillPaths) {
        console.log(`  • ${p.split('/').pop()}`);
    }
    console.log('');
    // Generate capability report (pattern-based)
    const report = await generateCapabilityReport(skillPaths);
    console.log('╔════════════════════════════════════════════════════════════════╗');
    console.log('║                    CAPABILITY MATRIX                            ║');
    console.log('╚════════════════════════════════════════════════════════════════╝');
    console.log('');
    for (const skill of report.skills) {
        const caps = Array.from(skill.capabilities).join(', ') || 'none';
        console.log(`📦 ${skill.name}`);
        console.log(`   Capabilities: ${caps}`);
        if (skill.sensitiveReads.length > 0) {
            console.log(`   ⚠️  Sensitive reads: ${skill.sensitiveReads.slice(0, 3).join(', ')}`);
        }
        console.log('');
    }
    // Pattern-based chains
    if (report.chains.length > 0) {
        console.log('╔════════════════════════════════════════════════════════════════╗');
        console.log('║                    ⚠️  ATTACK CHAINS DETECTED                   ║');
        console.log('╚════════════════════════════════════════════════════════════════╝');
        console.log('');
        for (const chain of report.chains) {
            const icon = chain.severity === 'critical' ? '⛔' : chain.severity === 'high' ? '🔴' : '🟠';
            console.log(`${icon} ${chain.title}`);
            console.log(`   ${chain.description}`);
            console.log(`   Evidence: ${chain.evidence}`);
            console.log('');
        }
    }
    else {
        console.log('✅ No pattern-based attack chains detected.');
    }
    // Semantic chain analysis (LLM-powered)
    let semanticChains = [];
    if (runSemantic) {
        console.log('');
        console.log('╔════════════════════════════════════════════════════════════════╗');
        console.log('║                🧠 SEMANTIC CHAIN ANALYSIS                       ║');
        console.log('╚════════════════════════════════════════════════════════════════╝');
        console.log('');
        console.log('Analyzing skill combinations with LLM...');
        semanticChains = await analyzeSemanticChains(skillPaths);
        if (semanticChains.length > 0) {
            console.log('');
            for (const chain of semanticChains) {
                const icon = chain.severity === 'critical' ? '⛔' : chain.severity === 'high' ? '🔴' : '🟠';
                console.log(`${icon} ${chain.title}`);
                console.log(`   Skills: ${chain.location}`);
                console.log(`   ${chain.description.split('\n')[0]}`);
                console.log(`   Evidence: ${(chain.evidence || '').slice(0, 100)}...`);
                console.log('');
            }
        }
        else {
            console.log('✅ No semantic attack chains detected.');
        }
    }
    // Final summary
    const totalChains = report.chains.length + semanticChains.length;
    const criticalChains = report.summary.criticalChains +
        semanticChains.filter(c => c.severity === 'critical').length;
    console.log('─'.repeat(60));
    console.log(`Summary: ${report.summary.totalSkills} skills, ${totalChains} attack chains (${criticalChains} critical)`);
    if (criticalChains > 0)
        process.exit(2);
    if (totalChains > 0)
        process.exit(1);
}
/**
 * Generate intent graph
 */
async function runGraph(skillPath, options) {
    const graph = await buildIntentGraph(skillPath);
    if (options.format === 'mermaid') {
        console.log(renderGraphMermaid(graph));
    }
    else {
        console.log(renderGraphAscii(graph));
    }
}
/**
 * Run honeypot/credential access scan
 */
async function runHoneypotScan(skillPath, options) {
    console.log('ClawGuard Honeypot Scanner v' + VERSION);
    console.log('═'.repeat(50));
    console.log('Scanning for credential access patterns...');
    console.log('');
    const findings = await scanForCredentialAccess(skillPath);
    if (findings.length === 0) {
        console.log('✅ No credential access patterns detected.');
        return;
    }
    console.log(`⚠️  Found ${findings.length} credential access patterns:`);
    console.log('');
    for (const f of findings) {
        const icon = f.severity === 'critical' ? '⛔' : f.severity === 'high' ? '🔴' : '🟠';
        console.log(`${icon} ${f.title}`);
        console.log(`   Location: ${f.location}`);
        console.log(`   Evidence: ${f.evidence}`);
        console.log('');
    }
    const critical = findings.filter(f => f.severity === 'critical').length;
    if (critical > 0)
        process.exit(2);
    if (findings.length > 0)
        process.exit(1);
}
/**
 * Run full comprehensive scan
 */
async function runFullScan(skillPath, options) {
    console.log('╔════════════════════════════════════════════════════════════════╗');
    console.log('║              ClawGuard FULL SECURITY AUDIT                      ║');
    console.log('║                        v' + VERSION + '                                    ║');
    console.log('╚════════════════════════════════════════════════════════════════╝');
    console.log('');
    // 1. Standard scan
    console.log('▶ Phase 1: Static Analysis');
    console.log('─'.repeat(60));
    const orchestrator = createOrchestrator();
    const result = await orchestrator.scan({
        path: skillPath,
        semantic: !!options.apiKey,
        apiKey: options.apiKey,
        verbose: options.verbose
    });
    console.log(formatResult(result, 'md'));
    console.log('');
    // 2. Honeypot scan
    console.log('▶ Phase 2: Credential Access Analysis');
    console.log('─'.repeat(60));
    const honeypotFindings = await scanForCredentialAccess(skillPath);
    if (honeypotFindings.length > 0) {
        for (const f of honeypotFindings) {
            const icon = f.severity === 'critical' ? '⛔' : '🔴';
            console.log(`${icon} ${f.title}: ${f.evidence}`);
        }
    }
    else {
        console.log('✅ No suspicious credential access patterns.');
    }
    console.log('');
    // 3. Intent graph
    console.log('▶ Phase 3: Intent Graph');
    console.log('─'.repeat(60));
    const graph = await buildIntentGraph(skillPath);
    console.log(renderGraphAscii(graph));
    console.log('');
    // Final summary
    const totalCritical = result.summary.critical +
        honeypotFindings.filter(f => f.severity === 'critical').length;
    const totalHigh = result.summary.high +
        honeypotFindings.filter(f => f.severity === 'high').length;
    console.log('╔════════════════════════════════════════════════════════════════╗');
    console.log('║                      FINAL VERDICT                              ║');
    console.log('╚════════════════════════════════════════════════════════════════╝');
    if (totalCritical > 0) {
        console.log('⛔ CRITICAL RISK - DO NOT INSTALL');
        process.exit(2);
    }
    else if (totalHigh > 0) {
        console.log('🔴 HIGH RISK - Review carefully before installing');
        process.exit(1);
    }
    else if (result.summary.medium > 0) {
        console.log('🟠 MEDIUM RISK - Some concerns, review recommended');
    }
    else {
        console.log('✅ LOW RISK - Appears safe');
    }
}
/**
 * Pre-install security gate
 * Returns exit code 0 if safe to install, non-zero to block
 */
async function runGate(skillPath, options) {
    const config = await loadConfig();
    const orchestrator = createOrchestrator();
    // Check known-bad database first
    const { checkKnownBad, calculateSkillHash } = await import('./database.js');
    const skillHash = await calculateSkillHash(skillPath);
    const knownBad = await checkKnownBad(skillHash);
    if (knownBad.known) {
        if (options.json) {
            console.log(JSON.stringify({
                allowed: false,
                reason: 'known_malicious',
                threat: knownBad.threat,
                description: knownBad.description
            }));
        }
        else {
            console.error('⛔ BLOCKED: Known malicious skill');
            console.error(`Threat: ${knownBad.threat}`);
        }
        process.exit(2);
    }
    // Run scan
    const result = await orchestrator.scan({
        path: skillPath,
        semantic: config.configured,
        sandbox: options.sandbox,
        verbose: false
    });
    // Determine if we should block
    const blockCritical = result.summary.critical > 0;
    const blockHigh = !options.allowHigh && result.summary.high > 0;
    const shouldBlock = blockCritical || blockHigh;
    if (options.json) {
        console.log(JSON.stringify({
            allowed: !shouldBlock,
            riskLevel: result.riskLevel,
            riskScore: result.riskScore,
            summary: result.summary,
            findings: shouldBlock ? result.findings : undefined
        }));
    }
    else {
        if (shouldBlock) {
            console.error(`⛔ BLOCKED: ${result.riskLevel} risk (score: ${result.riskScore})`);
            console.error(`Critical: ${result.summary.critical}, High: ${result.summary.high}`);
            // Show top findings
            const topFindings = result.findings
                .filter(f => f.severity === 'critical' || f.severity === 'high')
                .slice(0, 3);
            for (const f of topFindings) {
                console.error(`  - ${f.title}`);
            }
        }
        else {
            console.log(`✅ ALLOWED: ${result.riskLevel} risk (score: ${result.riskScore})`);
        }
    }
    process.exit(shouldBlock ? 2 : 0);
}
async function main() {
    const program = createProgram();
    await program.parseAsync(process.argv);
}
main().catch((error) => {
    console.error('Fatal error:', error);
    process.exit(1);
});
