/**
 * ClawGuard Honeypot Analyzer
 *
 * Injects fake credentials into the scan environment and monitors
 * if any skill attempts to access them.
 *
 * This catches credential theft that static analysis might miss.
 */
import { writeFile, mkdir, rm, readFile, stat } from 'fs/promises';
import { join, dirname } from 'path';
import { tmpdir } from 'os';
import { randomBytes } from 'crypto';
/**
 * Generate a unique marker for tracking
 */
function generateMarker() {
    return `CLAWGUARD_HONEYPOT_${randomBytes(16).toString('hex')}`;
}
/**
 * Generate fake but realistic-looking credentials
 */
function generateHoneypots(baseDir) {
    const marker = generateMarker();
    return [
        {
            name: 'SSH Private Key',
            path: join(baseDir, '.ssh', 'id_rsa'),
            content: `-----BEGIN OPENSSH PRIVATE KEY-----
${marker}
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAIEA${randomBytes(32).toString('base64')}
${randomBytes(64).toString('base64')}
${randomBytes(64).toString('base64')}
HONEYPOT_CREDENTIAL_DO_NOT_USE
-----END OPENSSH PRIVATE KEY-----
`,
            marker,
            severity: 'critical',
            description: 'SSH private key honeypot was accessed'
        },
        {
            name: 'AWS Credentials',
            path: join(baseDir, '.aws', 'credentials'),
            content: `[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = ${marker}
# HONEYPOT - This is a fake credential for security testing
`,
            marker,
            severity: 'critical',
            description: 'AWS credentials honeypot was accessed'
        },
        {
            name: 'Environment File',
            path: join(baseDir, '.env'),
            content: `# Application secrets
DATABASE_URL=postgresql://user:password@localhost/db
API_KEY=${marker}
SECRET_KEY=honeypot_secret_${randomBytes(8).toString('hex')}
STRIPE_SECRET_KEY=sk_test_honeypot_${randomBytes(16).toString('hex')}
# HONEYPOT FILE - For security testing only
`,
            marker,
            severity: 'high',
            description: '.env file honeypot was accessed'
        },
        {
            name: 'NPM Token',
            path: join(baseDir, '.npmrc'),
            content: `//registry.npmjs.org/:_authToken=${marker}
# HONEYPOT - Fake npm token
`,
            marker,
            severity: 'high',
            description: 'NPM authentication token honeypot was accessed'
        },
        {
            name: 'Git Credentials',
            path: join(baseDir, '.git-credentials'),
            content: `https://user:${marker}@github.com
# HONEYPOT
`,
            marker,
            severity: 'high',
            description: 'Git credentials honeypot was accessed'
        },
        {
            name: 'Netrc',
            path: join(baseDir, '.netrc'),
            content: `machine github.com
login honeypot_user
password ${marker}
# HONEYPOT FILE
`,
            marker,
            severity: 'high',
            description: 'Netrc file honeypot was accessed'
        },
        {
            name: 'Kubernetes Config',
            path: join(baseDir, '.kube', 'config'),
            content: `apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: ${marker}
    server: https://honeypot-cluster.example.com
  name: honeypot-cluster
# HONEYPOT - Fake kubeconfig
`,
            marker,
            severity: 'critical',
            description: 'Kubernetes config honeypot was accessed'
        },
        {
            name: 'Docker Config',
            path: join(baseDir, '.docker', 'config.json'),
            content: JSON.stringify({
                auths: {
                    'https://index.docker.io/v1/': {
                        auth: Buffer.from(`honeypot:${marker}`).toString('base64')
                    }
                },
                _comment: 'HONEYPOT - Fake docker credentials'
            }, null, 2),
            marker,
            severity: 'high',
            description: 'Docker config honeypot was accessed'
        },
        {
            name: 'GCP Service Account',
            path: join(baseDir, '.config', 'gcloud', 'application_default_credentials.json'),
            content: JSON.stringify({
                type: 'service_account',
                project_id: 'honeypot-project',
                private_key_id: randomBytes(20).toString('hex'),
                private_key: `-----BEGIN PRIVATE KEY-----\n${marker}\nHONEYPOT\n-----END PRIVATE KEY-----\n`,
                client_email: 'honeypot@honeypot-project.iam.gserviceaccount.com',
                client_id: '123456789',
                _honeypot: true
            }, null, 2),
            marker,
            severity: 'critical',
            description: 'GCP service account honeypot was accessed'
        },
        {
            name: 'Azure Credentials',
            path: join(baseDir, '.azure', 'credentials'),
            content: `[default]
subscription_id = honeypot-subscription
client_id = honeypot-client
secret = ${marker}
tenant = honeypot-tenant
# HONEYPOT
`,
            marker,
            severity: 'critical',
            description: 'Azure credentials honeypot was accessed'
        }
    ];
}
/**
 * Deploy honeypot credentials to a directory
 */
async function deployHoneypots(honeypots) {
    for (const hp of honeypots) {
        await mkdir(dirname(hp.path), { recursive: true });
        await writeFile(hp.path, hp.content, { mode: 0o600 });
    }
}
/**
 * Remove honeypot credentials
 */
async function cleanupHoneypots(honeypots) {
    for (const hp of honeypots) {
        try {
            await rm(hp.path, { force: true });
        }
        catch {
            // Ignore cleanup errors
        }
    }
}
/**
 * Check if a honeypot was accessed by examining file access times
 * This is a simple check - more sophisticated monitoring would use inotify/fswatch
 */
async function checkHoneypotAccess(honeypot, startTime) {
    try {
        const stats = await stat(honeypot.path);
        const accessed = stats.atime > startTime;
        return {
            credential: honeypot,
            accessed,
            accessTime: accessed ? stats.atime : undefined
        };
    }
    catch {
        return {
            credential: honeypot,
            accessed: false
        };
    }
}
/**
 * Scan skill content for references to honeypot paths
 * This is a static check - doesn't require actual file deployment
 */
export async function scanForCredentialAccess(skillPath) {
    const findings = [];
    // Patterns that indicate credential access attempts
    const credentialPatterns = [
        { pattern: /~\/\.ssh|\.ssh\/id_rsa|\.ssh\/id_ed25519/gi, name: 'SSH keys', severity: 'critical' },
        { pattern: /~\/\.aws|\.aws\/credentials/gi, name: 'AWS credentials', severity: 'critical' },
        { pattern: /~\/\.kube|\.kube\/config/gi, name: 'Kubernetes config', severity: 'critical' },
        { pattern: /~\/\.docker|\.docker\/config/gi, name: 'Docker config', severity: 'high' },
        { pattern: /~\/\.gcloud|gcloud.*credentials/gi, name: 'GCP credentials', severity: 'critical' },
        { pattern: /~\/\.azure|\.azure\/credentials/gi, name: 'Azure credentials', severity: 'critical' },
        { pattern: /~\/\.npmrc|\.npmrc/gi, name: 'NPM token', severity: 'high' },
        { pattern: /~\/\.netrc|\.netrc/gi, name: 'Netrc file', severity: 'high' },
        { pattern: /~\/\.git-credentials|\.git-credentials/gi, name: 'Git credentials', severity: 'high' },
        { pattern: /~\/\.env|\.env(?:\.local|\.prod)?/gi, name: 'Environment file', severity: 'high' },
        { pattern: /~\/\.gnupg|\.gnupg\/private/gi, name: 'GPG keys', severity: 'critical' },
        { pattern: /~\/\.pypirc|\.pypirc/gi, name: 'PyPI credentials', severity: 'high' },
        { pattern: /keychain|keyring|credential.?store/gi, name: 'System keychain', severity: 'critical' },
        { pattern: /\/etc\/shadow|\/etc\/passwd/gi, name: 'System passwords', severity: 'critical' },
        { pattern: /wallet\.dat|\.bitcoin|\.ethereum/gi, name: 'Crypto wallets', severity: 'critical' },
    ];
    // Read all files in skill
    const { glob } = await import('glob');
    const files = await glob('**/*.{md,js,ts,py,sh,yaml,yml,json,txt}', {
        cwd: skillPath,
        ignore: ['node_modules/**', '.git/**'],
        nodir: true
    });
    for (const file of files) {
        try {
            const content = await readFile(join(skillPath, file), 'utf-8');
            for (const { pattern, name, severity } of credentialPatterns) {
                const matches = content.match(pattern);
                if (matches) {
                    findings.push({
                        id: `T-HONEYPOT-${name.toUpperCase().replace(/\s+/g, '_')}`,
                        category: 'honeypot',
                        severity,
                        title: `Potential ${name} Access`,
                        description: `Skill contains references to ${name} paths. This could indicate credential theft attempts.`,
                        evidence: matches.slice(0, 3).join(', '),
                        location: file,
                        remediation: `Review why this skill needs access to ${name}. If not required, remove the access.`
                    });
                }
            }
        }
        catch {
            // Skip unreadable files
        }
    }
    return findings;
}
/**
 * Create a honeypot environment for behavioral testing
 * Returns a cleanup function
 */
export async function createHoneypotEnvironment() {
    const homeDir = join(tmpdir(), `clawguard-honeypot-${randomBytes(8).toString('hex')}`);
    await mkdir(homeDir, { recursive: true });
    const honeypots = generateHoneypots(homeDir);
    await deployHoneypots(honeypots);
    const startTime = new Date();
    return {
        homeDir,
        honeypots,
        cleanup: async () => {
            await cleanupHoneypots(honeypots);
            await rm(homeDir, { recursive: true, force: true });
        },
        checkAccess: async () => {
            return Promise.all(honeypots.map(hp => checkHoneypotAccess(hp, startTime)));
        }
    };
}
/**
 * Convert honeypot results to findings
 */
export function honeypotResultsToFindings(results) {
    return results
        .filter(r => r.accessed)
        .map(r => ({
        id: `T-HONEYPOT-ACCESSED-${r.credential.name.toUpperCase().replace(/\s+/g, '_')}`,
        category: 'honeypot',
        severity: r.credential.severity,
        title: `Honeypot Accessed: ${r.credential.name}`,
        description: r.credential.description,
        evidence: `Accessed at: ${r.accessTime?.toISOString()}`,
        location: r.credential.path,
        remediation: 'This skill attempted to access sensitive credentials. Do not install.'
    }));
}
