/**
 * ClawGuard Dependency Scanner
 *
 * Analyzes package dependencies for:
 * - Known malicious packages
 * - Typosquatting (Levenshtein distance ≤2 from popular packages)
 * - Package registry existence
 * - Suspicious package characteristics (age, install scripts)
 */
import { readFile, access } from 'fs/promises';
import { join, dirname } from 'path';
import { parse as parseYaml } from 'yaml';
import { fileURLToPath } from 'url';
import { detectTyposquat } from '../utils/levenshtein.js';
import { checkNpmPackage, checkPypiPackage, isSuspiciouslyNew } from '../utils/registry.js';
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
let patternsCache = null;
/**
 * Load dependency patterns from YAML
 */
export async function loadPatterns() {
    if (patternsCache)
        return patternsCache;
    const patternsPath = join(__dirname, '..', 'patterns', 'deps.yaml');
    const content = await readFile(patternsPath, 'utf-8');
    patternsCache = parseYaml(content);
    return patternsCache;
}
/**
 * Check if file exists
 */
async function fileExists(path) {
    try {
        await access(path);
        return true;
    }
    catch {
        return false;
    }
}
/**
 * Parse package.json dependencies
 */
export async function parsePackageJson(path) {
    const content = await readFile(path, 'utf-8');
    const pkg = JSON.parse(content);
    const deps = [];
    const allDeps = {
        ...pkg.dependencies,
        ...pkg.devDependencies,
        ...pkg.peerDependencies,
        ...pkg.optionalDependencies
    };
    for (const [name, version] of Object.entries(allDeps)) {
        deps.push({ name, version: version || '*', source: path });
    }
    return deps;
}
/**
 * Parse requirements.txt dependencies
 */
export async function parseRequirementsTxt(path) {
    const content = await readFile(path, 'utf-8');
    const deps = [];
    for (const line of content.split('\n')) {
        const trimmed = line.trim();
        // Skip comments and empty lines
        if (!trimmed || trimmed.startsWith('#'))
            continue;
        // Skip options like -r, -e, --index-url
        if (trimmed.startsWith('-'))
            continue;
        // Parse package name and version
        // Formats: package, package==1.0, package>=1.0, package[extra]==1.0
        const match = trimmed.match(/^([a-zA-Z0-9_-]+)(?:\[.*?\])?(?:([<>=!~]+)(.+))?$/);
        if (match) {
            deps.push({
                name: match[1],
                version: match[3] || '*',
                source: path
            });
        }
    }
    return deps;
}
/**
 * Parse go.mod dependencies
 */
export async function parseGoMod(path) {
    const content = await readFile(path, 'utf-8');
    const deps = [];
    // Match require blocks and single requires
    const requireBlockMatch = content.match(/require\s*\(([\s\S]*?)\)/g);
    const singleRequireMatch = content.match(/require\s+(\S+)\s+(\S+)/g);
    // Parse require blocks
    if (requireBlockMatch) {
        for (const block of requireBlockMatch) {
            const inner = block.replace(/require\s*\(/, '').replace(/\)/, '');
            for (const line of inner.split('\n')) {
                const trimmed = line.trim();
                if (!trimmed || trimmed.startsWith('//'))
                    continue;
                const parts = trimmed.split(/\s+/);
                if (parts.length >= 2) {
                    deps.push({
                        name: parts[0],
                        version: parts[1],
                        source: path
                    });
                }
            }
        }
    }
    // Parse single requires
    if (singleRequireMatch) {
        for (const req of singleRequireMatch) {
            const parts = req.replace('require', '').trim().split(/\s+/);
            if (parts.length >= 2) {
                deps.push({
                    name: parts[0],
                    version: parts[1],
                    source: path
                });
            }
        }
    }
    return deps;
}
/**
 * Check if a version matches any malicious version pattern
 */
function versionMatches(version, patterns) {
    for (const pattern of patterns) {
        if (pattern === '*')
            return true;
        if (pattern === version)
            return true;
        // Could add semver range matching here
    }
    return false;
}
/**
 * Check npm dependencies for issues
 */
async function checkNpmDeps(deps, patterns, checkRegistry) {
    const findings = [];
    for (const dep of deps) {
        // Check known malicious packages
        const malicious = patterns.malicious_npm.find(m => m.name === dep.name);
        if (malicious && versionMatches(dep.version, malicious.versions)) {
            findings.push({
                id: 'T-DEPS-001',
                category: 'supply',
                severity: 'critical',
                title: `Known malicious package: ${dep.name}`,
                description: malicious.reason,
                location: dep.source,
                evidence: `${dep.name}@${dep.version}`,
                remediation: 'Remove this package immediately and audit your system for compromise'
            });
            continue;
        }
        // Check typosquatting
        const typosquat = detectTyposquat(dep.name, patterns.popular_npm);
        if (typosquat) {
            findings.push({
                id: 'T-DEPS-002',
                category: 'supply',
                severity: 'high',
                title: `Potential typosquat: ${dep.name}`,
                description: `Package name is suspiciously similar to popular package "${typosquat.original}". ${typosquat.detail}`,
                location: dep.source,
                evidence: `${dep.name} ≈ ${typosquat.original}`,
                remediation: `Verify you intended to use "${dep.name}" and not "${typosquat.original}"`
            });
        }
        // Check registry (if enabled)
        if (checkRegistry) {
            const result = await checkNpmPackage(dep.name);
            if (!result.exists) {
                findings.push({
                    id: 'T-DEPS-003',
                    category: 'supply',
                    severity: 'critical',
                    title: `Package not found on npm: ${dep.name}`,
                    description: result.error || 'Package does not exist on the npm registry',
                    location: dep.source,
                    evidence: dep.name,
                    remediation: 'This may indicate a private package, typo, or removed malicious package'
                });
                continue;
            }
            const info = result.info;
            // Check install scripts
            if (info.hasInstallScripts) {
                findings.push({
                    id: 'T-DEPS-004',
                    category: 'supply',
                    severity: 'medium',
                    title: `Package has install scripts: ${dep.name}`,
                    description: 'Package executes code during installation (preinstall/install/postinstall)',
                    location: dep.source,
                    evidence: `${dep.name}@${info.version}`,
                    remediation: 'Review the install scripts in node_modules or use --ignore-scripts'
                });
            }
            // Check if suspiciously new
            if (isSuspiciouslyNew(info)) {
                findings.push({
                    id: 'T-DEPS-005',
                    category: 'supply',
                    severity: 'medium',
                    title: `Suspiciously new package: ${dep.name}`,
                    description: `Package was created recently with low download count (${info.downloadsLastWeek} downloads/week)`,
                    location: dep.source,
                    evidence: `Created: ${info.createdAt.toISOString().split('T')[0]}`,
                    remediation: 'Verify package legitimacy before using'
                });
            }
            // Check if deprecated
            if (info.deprecated) {
                findings.push({
                    id: 'T-DEPS-006',
                    category: 'supply',
                    severity: 'low',
                    title: `Deprecated package: ${dep.name}`,
                    description: info.deprecated,
                    location: dep.source,
                    evidence: `${dep.name}@${info.version}`,
                    remediation: 'Consider migrating to the recommended alternative'
                });
            }
        }
    }
    return findings;
}
/**
 * Check pip dependencies for issues
 */
async function checkPipDeps(deps, patterns, checkRegistry) {
    const findings = [];
    for (const dep of deps) {
        // Check known malicious packages
        const malicious = patterns.malicious_pip.find(m => m.name === dep.name);
        if (malicious && versionMatches(dep.version, malicious.versions)) {
            findings.push({
                id: 'T-DEPS-001',
                category: 'supply',
                severity: 'critical',
                title: `Known malicious package: ${dep.name}`,
                description: malicious.reason,
                location: dep.source,
                evidence: `${dep.name}==${dep.version}`,
                remediation: 'Remove this package immediately and audit your system for compromise'
            });
            continue;
        }
        // Check typosquatting
        const typosquat = detectTyposquat(dep.name, patterns.popular_pip);
        if (typosquat) {
            findings.push({
                id: 'T-DEPS-002',
                category: 'supply',
                severity: 'high',
                title: `Potential typosquat: ${dep.name}`,
                description: `Package name is suspiciously similar to popular package "${typosquat.original}". ${typosquat.detail}`,
                location: dep.source,
                evidence: `${dep.name} ≈ ${typosquat.original}`,
                remediation: `Verify you intended to use "${dep.name}" and not "${typosquat.original}"`
            });
        }
        // Check registry (if enabled)
        if (checkRegistry) {
            const result = await checkPypiPackage(dep.name);
            if (!result.exists) {
                findings.push({
                    id: 'T-DEPS-003',
                    category: 'supply',
                    severity: 'critical',
                    title: `Package not found on PyPI: ${dep.name}`,
                    description: result.error || 'Package does not exist on the PyPI registry',
                    location: dep.source,
                    evidence: dep.name,
                    remediation: 'This may indicate a private package, typo, or removed malicious package'
                });
                continue;
            }
            const info = result.info;
            // Check if yanked
            if (info.yanked) {
                findings.push({
                    id: 'T-DEPS-007',
                    category: 'supply',
                    severity: 'high',
                    title: `Package version yanked: ${dep.name}`,
                    description: 'The latest version of this package has been yanked from PyPI',
                    location: dep.source,
                    evidence: `${dep.name}==${info.version}`,
                    remediation: 'Check for security advisories and update to a safe version'
                });
            }
            // Check if suspiciously new
            if (isSuspiciouslyNew(info)) {
                findings.push({
                    id: 'T-DEPS-005',
                    category: 'supply',
                    severity: 'medium',
                    title: `Suspiciously new package: ${dep.name}`,
                    description: 'Package was created very recently',
                    location: dep.source,
                    evidence: `Created: ${info.createdAt?.toISOString().split('T')[0] || 'unknown'}`,
                    remediation: 'Verify package legitimacy before using'
                });
            }
        }
    }
    return findings;
}
/**
 * Check Go dependencies for issues
 */
async function checkGoDeps(deps, patterns) {
    const findings = [];
    for (const dep of deps) {
        // Check known malicious packages
        const malicious = patterns.malicious_go.find(m => m.name === dep.name);
        if (malicious && versionMatches(dep.version, malicious.versions)) {
            findings.push({
                id: 'T-DEPS-001',
                category: 'supply',
                severity: 'critical',
                title: `Known malicious module: ${dep.name}`,
                description: malicious.reason,
                location: dep.source,
                evidence: `${dep.name} ${dep.version}`,
                remediation: 'Remove this module immediately and audit your system'
            });
            continue;
        }
        // Check typosquatting for Go modules
        const typosquat = detectTyposquat(dep.name, patterns.popular_go);
        if (typosquat) {
            findings.push({
                id: 'T-DEPS-002',
                category: 'supply',
                severity: 'high',
                title: `Potential typosquat: ${dep.name}`,
                description: `Module path is suspiciously similar to popular module "${typosquat.original}". ${typosquat.detail}`,
                location: dep.source,
                evidence: `${dep.name} ≈ ${typosquat.original}`,
                remediation: `Verify you intended to use "${dep.name}" and not "${typosquat.original}"`
            });
        }
    }
    return findings;
}
/**
 * Check package.json for suspicious scripts
 */
async function checkPackageJsonScripts(path) {
    const findings = [];
    try {
        const content = await readFile(path, 'utf-8');
        const pkg = JSON.parse(content);
        if (!pkg.scripts)
            return findings;
        const suspiciousScripts = ['preinstall', 'install', 'postinstall', 'preuninstall', 'postuninstall'];
        const dangerousPatterns = [
            { pattern: /curl.*\|.*(?:bash|sh)/i, desc: 'curl pipe to shell' },
            { pattern: /wget.*\|/i, desc: 'wget pipe' },
            { pattern: /eval\s*\(/i, desc: 'eval execution' },
            { pattern: /base64\s+-d/i, desc: 'base64 decode' },
            { pattern: /\$\(.*\)/i, desc: 'command substitution' },
            { pattern: /node\s+-e/i, desc: 'node eval' },
            { pattern: /python.*-c/i, desc: 'python inline' }
        ];
        for (const scriptName of suspiciousScripts) {
            const script = pkg.scripts[scriptName];
            if (!script)
                continue;
            // Check for dangerous patterns in install scripts
            for (const { pattern, desc } of dangerousPatterns) {
                if (pattern.test(script)) {
                    findings.push({
                        id: 'T-DEPS-008',
                        category: 'supply',
                        severity: 'critical',
                        title: `Dangerous install script: ${scriptName}`,
                        description: `Install script contains ${desc}`,
                        location: `${path}:scripts.${scriptName}`,
                        evidence: script.slice(0, 200),
                        remediation: 'Review this script carefully before installing'
                    });
                }
            }
        }
    }
    catch {
        // Ignore parse errors
    }
    return findings;
}
/**
 * Dependency Scanner implementation
 */
export class DepsAnalyzer {
    name = 'deps';
    checkRegistry;
    constructor(options = {}) {
        this.checkRegistry = options.checkRegistry ?? true;
    }
    async analyze(skillPath) {
        const findings = [];
        const patterns = await loadPatterns();
        // Check for package.json (npm)
        const packageJsonPath = join(skillPath, 'package.json');
        if (await fileExists(packageJsonPath)) {
            try {
                const npmDeps = await parsePackageJson(packageJsonPath);
                const npmFindings = await checkNpmDeps(npmDeps, patterns, this.checkRegistry);
                findings.push(...npmFindings);
                // Check scripts in package.json
                const scriptFindings = await checkPackageJsonScripts(packageJsonPath);
                findings.push(...scriptFindings);
            }
            catch (error) {
                findings.push({
                    id: 'T-DEPS-ERR',
                    category: 'supply',
                    severity: 'info',
                    title: 'Failed to parse package.json',
                    description: error instanceof Error ? error.message : 'Unknown error',
                    location: packageJsonPath
                });
            }
        }
        // Check for requirements.txt (pip)
        const requirementsPath = join(skillPath, 'requirements.txt');
        if (await fileExists(requirementsPath)) {
            try {
                const pipDeps = await parseRequirementsTxt(requirementsPath);
                const pipFindings = await checkPipDeps(pipDeps, patterns, this.checkRegistry);
                findings.push(...pipFindings);
            }
            catch (error) {
                findings.push({
                    id: 'T-DEPS-ERR',
                    category: 'supply',
                    severity: 'info',
                    title: 'Failed to parse requirements.txt',
                    description: error instanceof Error ? error.message : 'Unknown error',
                    location: requirementsPath
                });
            }
        }
        // Also check pyproject.toml if it exists
        const pyprojectPath = join(skillPath, 'pyproject.toml');
        if (await fileExists(pyprojectPath)) {
            // Basic TOML parsing for dependencies
            try {
                const content = await readFile(pyprojectPath, 'utf-8');
                const deps = [];
                // Extract dependencies from [project.dependencies] or [tool.poetry.dependencies]
                const depMatches = content.matchAll(/^\s*"?([a-zA-Z0-9_-]+)"?\s*[=:]/gm);
                for (const match of depMatches) {
                    deps.push({ name: match[1], version: '*', source: pyprojectPath });
                }
                if (deps.length > 0) {
                    const pipFindings = await checkPipDeps(deps, patterns, this.checkRegistry);
                    findings.push(...pipFindings);
                }
            }
            catch {
                // Ignore TOML parse errors
            }
        }
        // Check for go.mod (Go)
        const goModPath = join(skillPath, 'go.mod');
        if (await fileExists(goModPath)) {
            try {
                const goDeps = await parseGoMod(goModPath);
                const goFindings = await checkGoDeps(goDeps, patterns);
                findings.push(...goFindings);
            }
            catch (error) {
                findings.push({
                    id: 'T-DEPS-ERR',
                    category: 'supply',
                    severity: 'info',
                    title: 'Failed to parse go.mod',
                    description: error instanceof Error ? error.message : 'Unknown error',
                    location: goModPath
                });
            }
        }
        return findings;
    }
}
// Export singleton for simple usage
export const depsAnalyzer = new DepsAnalyzer();
// Alias for compatibility with index.ts
export { DepsAnalyzer as DependencyAnalyzer };
// Factory function for orchestrator
export function createDependencyAnalyzer(options = {}) {
    return new DepsAnalyzer(options);
}
