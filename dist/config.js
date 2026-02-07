/**
 * ClawGuard Configuration Manager
 *
 * Handles setup wizard, API key storage, and model selection.
 * Supports multiple providers: Anthropic, OpenAI, and local models.
 */
import { readFile, writeFile, mkdir } from 'fs/promises';
import { join } from 'path';
import { homedir } from 'os';
import { createInterface } from 'readline';
const CONFIG_DIR = join(homedir(), '.config', 'clawguard');
const CONFIG_FILE = join(CONFIG_DIR, 'config.json');
const DEFAULT_CONFIG = {
    provider: 'anthropic',
    model: 'claude-sonnet-4-20250514',
    configured: false
};
export const PROVIDERS = {
    anthropic: {
        name: 'Anthropic (Claude)',
        models: [
            { id: 'claude-opus-4-20250514', name: 'Claude Opus 4 (Most capable, expensive)' },
            { id: 'claude-sonnet-4-20250514', name: 'Claude Sonnet 4 (Recommended balance)' },
            { id: 'claude-haiku-3-5-20241022', name: 'Claude Haiku 3.5 (Fast, cheap)' }
        ],
        envVar: 'ANTHROPIC_API_KEY',
        keyPrefix: 'sk-ant-',
        requiresKey: true
    },
    openai: {
        name: 'OpenAI (GPT-4)',
        models: [
            { id: 'gpt-4o', name: 'GPT-4o (Most capable)' },
            { id: 'gpt-4o-mini', name: 'GPT-4o Mini (Fast, cheap)' },
            { id: 'gpt-4-turbo', name: 'GPT-4 Turbo' }
        ],
        envVar: 'OPENAI_API_KEY',
        keyPrefix: 'sk-',
        requiresKey: true
    },
    local: {
        name: 'Local (Ollama)',
        models: [
            { id: 'llama3:70b', name: 'Llama 3 70B' },
            { id: 'mixtral:8x7b', name: 'Mixtral 8x7B' },
            { id: 'qwen2.5:32b', name: 'Qwen 2.5 32B' },
            { id: 'deepseek-r1:32b', name: 'DeepSeek R1 32B' }
        ],
        envVar: '',
        keyPrefix: '',
        requiresKey: false
    }
};
/**
 * Read a line with optional password masking
 */
function readLine(prompt, mask = false) {
    return new Promise((resolve) => {
        const rl = createInterface({
            input: process.stdin,
            output: process.stdout
        });
        if (mask && process.stdin.isTTY) {
            // Simple masking approach - clear line and show asterisks
            process.stdout.write(prompt);
            let input = '';
            const stdin = process.stdin;
            stdin.setRawMode(true);
            stdin.resume();
            stdin.setEncoding('utf8');
            const onData = (char) => {
                switch (char) {
                    case '\n':
                    case '\r':
                    case '\u0004': // Ctrl+D
                        stdin.removeListener('data', onData);
                        stdin.setRawMode(false);
                        stdin.pause();
                        process.stdout.write('\n');
                        rl.close();
                        resolve(input);
                        break;
                    case '\u0003': // Ctrl+C
                        process.exit();
                        break;
                    case '\u007F': // Backspace
                    case '\b':
                        if (input.length > 0) {
                            input = input.slice(0, -1);
                            process.stdout.write('\b \b');
                        }
                        break;
                    default:
                        input += char;
                        process.stdout.write('*');
                }
            };
            stdin.on('data', onData);
        }
        else {
            // Non-TTY or no masking
            rl.question(prompt, (answer) => {
                rl.close();
                resolve(answer.trim());
            });
        }
    });
}
/**
 * Load existing configuration
 */
export async function loadConfig() {
    try {
        const data = await readFile(CONFIG_FILE, 'utf-8');
        return { ...DEFAULT_CONFIG, ...JSON.parse(data) };
    }
    catch {
        return DEFAULT_CONFIG;
    }
}
/**
 * Save configuration
 */
export async function saveConfig(config) {
    await mkdir(CONFIG_DIR, { recursive: true });
    // Mode 0o600 = owner read/write only (secure for API keys)
    await writeFile(CONFIG_FILE, JSON.stringify(config, null, 2), { mode: 0o600 });
}
/**
 * Check if config exists
 */
export async function isConfigured() {
    const config = await loadConfig();
    return config.configured;
}
/**
 * Get API key from config or environment
 */
export async function getApiKey() {
    const config = await loadConfig();
    if (config.apiKey) {
        return config.apiKey;
    }
    const provider = PROVIDERS[config.provider];
    if (provider?.envVar) {
        return process.env[provider.envVar];
    }
    return undefined;
}
/**
 * Check for first run and prompt setup
 */
export async function checkFirstRun() {
    const config = await loadConfig();
    if (!config.configured) {
        console.log('');
        console.log('🛡️  Welcome to ClawGuard!');
        console.log('');
        console.log('ClawGuard can use AI for deep semantic analysis of skills.');
        console.log('This catches attacks that static patterns miss.');
        console.log('');
        const answer = await readLine('Set up AI analysis now? (Y/n): ');
        if (answer.toLowerCase() !== 'n') {
            await runSetupWizard();
        }
        else {
            console.log('');
            console.log('Skipped. Run `clawguard config` anytime to set up.');
            console.log('Static analysis (without --semantic) works without configuration.');
            console.log('');
        }
    }
}
/**
 * Run interactive setup wizard
 */
export async function runSetupWizard() {
    console.log('');
    console.log('╔════════════════════════════════════════════════════════════════╗');
    console.log('║                   ClawGuard Setup                               ║');
    console.log('╚════════════════════════════════════════════════════════════════╝');
    console.log('');
    // Provider selection
    console.log('Select your AI provider:');
    console.log('');
    const providerKeys = Object.keys(PROVIDERS);
    providerKeys.forEach((key, i) => {
        const p = PROVIDERS[key];
        const note = key === 'local' ? ' (no API key needed)' : '';
        console.log(`  ${i + 1}. ${p.name}${note}`);
    });
    console.log('  0. Skip (static analysis only)');
    console.log('');
    const providerChoice = await readLine('Enter number [1]: ');
    const providerIndex = parseInt(providerChoice || '1') - 1;
    if (providerChoice === '0' || providerIndex < 0 || providerIndex >= providerKeys.length) {
        console.log('');
        console.log('✓ Skipped. Run `clawguard config` later to enable AI analysis.');
        console.log('');
        return { ...DEFAULT_CONFIG, configured: false };
    }
    const provider = providerKeys[providerIndex];
    const providerInfo = PROVIDERS[provider];
    // Model selection
    console.log('');
    console.log(`Select ${providerInfo.name} model:`);
    console.log('');
    providerInfo.models.forEach((m, i) => {
        const recommended = i === 1 ? ' ← recommended' : '';
        console.log(`  ${i + 1}. ${m.name}${recommended}`);
    });
    console.log('');
    const modelChoice = await readLine('Enter number [2]: ');
    const modelIndex = parseInt(modelChoice || '2') - 1;
    const model = providerInfo.models[Math.max(0, Math.min(modelIndex, providerInfo.models.length - 1))];
    // API key (if required)
    let apiKey;
    let baseUrl;
    if (providerInfo.requiresKey) {
        console.log('');
        console.log(`Enter your ${providerInfo.name.split(' ')[0]} API key:`);
        if (providerInfo.keyPrefix) {
            console.log(`(starts with "${providerInfo.keyPrefix}...")`);
        }
        console.log('');
        // Check for existing env var
        const envKey = process.env[providerInfo.envVar];
        if (envKey) {
            const masked = envKey.slice(0, 10) + '...' + envKey.slice(-4);
            console.log(`Found ${providerInfo.envVar}: ${masked}`);
            const useEnv = await readLine('Use this key? (Y/n): ');
            if (useEnv.toLowerCase() !== 'n') {
                console.log('✓ Using environment variable');
                // Don't store it, just use from env
            }
            else {
                apiKey = await readLine('API Key: ', true);
            }
        }
        else {
            apiKey = await readLine('API Key: ', true);
        }
        if (apiKey && providerInfo.keyPrefix && !apiKey.startsWith(providerInfo.keyPrefix)) {
            console.log(`⚠️  Warning: Key doesn't look like a ${providerInfo.name.split(' ')[0]} key`);
        }
    }
    else if (provider === 'local') {
        // Ask for Ollama URL
        console.log('');
        const customUrl = await readLine('Ollama URL [http://localhost:11434]: ');
        if (customUrl) {
            baseUrl = customUrl;
        }
    }
    // Save config
    const config = {
        provider,
        model: model.id,
        apiKey,
        baseUrl,
        configured: true,
        configuredAt: new Date().toISOString()
    };
    await saveConfig(config);
    console.log('');
    console.log('╔════════════════════════════════════════════════════════════════╗');
    console.log('║                    ✓ Configuration Saved                        ║');
    console.log('╚════════════════════════════════════════════════════════════════╝');
    console.log('');
    console.log(`  Provider:  ${providerInfo.name}`);
    console.log(`  Model:     ${model.name}`);
    if (providerInfo.requiresKey) {
        console.log(`  API Key:   ${apiKey ? '✓ Stored securely' : `Using $${providerInfo.envVar}`}`);
    }
    if (baseUrl) {
        console.log(`  URL:       ${baseUrl}`);
    }
    console.log(`  Config:    ${CONFIG_FILE}`);
    console.log('');
    console.log('Usage:');
    console.log('  clawguard scan <path>             # Static analysis only');
    console.log('  clawguard scan <path> --semantic  # Static + AI analysis');
    console.log('  clawguard full <path>             # Everything (static + AI + honeypot)');
    console.log('');
    return config;
}
/**
 * Show current configuration
 */
export async function showConfig() {
    const config = await loadConfig();
    console.log('');
    console.log('ClawGuard Configuration');
    console.log('═'.repeat(50));
    console.log('');
    if (!config.configured) {
        console.log('  Status: Not configured');
        console.log('');
        console.log('Run `clawguard config` to set up AI analysis.');
        console.log('Static analysis works without configuration.');
        console.log('');
        return;
    }
    const providerInfo = PROVIDERS[config.provider];
    console.log(`  Provider:    ${providerInfo?.name || config.provider}`);
    console.log(`  Model:       ${config.model}`);
    if (providerInfo?.requiresKey) {
        if (config.apiKey) {
            const masked = config.apiKey.slice(0, 10) + '...' + config.apiKey.slice(-4);
            console.log(`  API Key:     ${masked} (stored)`);
        }
        else {
            const envKey = process.env[providerInfo.envVar];
            if (envKey) {
                const masked = envKey.slice(0, 10) + '...' + envKey.slice(-4);
                console.log(`  API Key:     ${masked} (from $${providerInfo.envVar})`);
            }
            else {
                console.log(`  API Key:     ⚠️  Not set (need $${providerInfo.envVar})`);
            }
        }
    }
    if (config.baseUrl) {
        console.log(`  Base URL:    ${config.baseUrl}`);
    }
    console.log(`  Config file: ${CONFIG_FILE}`);
    console.log(`  Configured:  ${config.configuredAt || 'Unknown'}`);
    console.log('');
}
/**
 * Clear stored configuration
 */
export async function clearConfig() {
    await saveConfig({ ...DEFAULT_CONFIG, configured: false });
    console.log('');
    console.log('✓ Configuration cleared.');
    console.log('');
}
/**
 * Test the current configuration by making a simple API call
 */
export async function testConfig() {
    const config = await loadConfig();
    if (!config.configured) {
        console.log('Not configured. Run `clawguard config` first.');
        return false;
    }
    const providerInfo = PROVIDERS[config.provider];
    console.log(`Testing ${providerInfo.name} connection...`);
    try {
        const apiKey = config.apiKey || (providerInfo.envVar ? process.env[providerInfo.envVar] : undefined);
        if (providerInfo.requiresKey && !apiKey) {
            console.log(`❌ No API key found. Set $${providerInfo.envVar} or run \`clawguard config\``);
            return false;
        }
        // Quick test based on provider
        if (config.provider === 'anthropic') {
            const response = await fetch('https://api.anthropic.com/v1/messages', {
                method: 'POST',
                headers: {
                    'x-api-key': apiKey,
                    'anthropic-version': '2023-06-01',
                    'content-type': 'application/json'
                },
                body: JSON.stringify({
                    model: config.model,
                    max_tokens: 10,
                    messages: [{ role: 'user', content: 'Hi' }]
                })
            });
            if (response.ok) {
                console.log('✓ Anthropic API connection successful');
                return true;
            }
            else {
                const error = await response.json();
                console.log(`❌ Anthropic API error: ${error.error?.message || response.status}`);
                return false;
            }
        }
        else if (config.provider === 'openai') {
            const response = await fetch('https://api.openai.com/v1/chat/completions', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${apiKey}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    model: config.model,
                    max_tokens: 10,
                    messages: [{ role: 'user', content: 'Hi' }]
                })
            });
            if (response.ok) {
                console.log('✓ OpenAI API connection successful');
                return true;
            }
            else {
                const error = await response.json();
                console.log(`❌ OpenAI API error: ${error.error?.message || response.status}`);
                return false;
            }
        }
        else if (config.provider === 'local') {
            const baseUrl = config.baseUrl || 'http://localhost:11434';
            const response = await fetch(`${baseUrl}/api/tags`);
            if (response.ok) {
                console.log('✓ Ollama connection successful');
                return true;
            }
            else {
                console.log(`❌ Ollama not reachable at ${baseUrl}`);
                return false;
            }
        }
        return false;
    }
    catch (error) {
        console.log(`❌ Connection error: ${error.message}`);
        return false;
    }
}
export { CONFIG_FILE, CONFIG_DIR };
