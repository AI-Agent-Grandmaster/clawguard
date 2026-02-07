/**
 * ClawGuard Configuration Manager
 *
 * Handles setup wizard, API key storage, and model selection.
 * Supports multiple providers: Anthropic, OpenAI, and local models.
 */
declare const CONFIG_DIR: string;
declare const CONFIG_FILE: string;
export interface ClawGuardConfig {
    provider: 'anthropic' | 'openai' | 'local';
    model: string;
    apiKey?: string;
    baseUrl?: string;
    configured: boolean;
    configuredAt?: string;
}
export declare const PROVIDERS: {
    anthropic: {
        name: string;
        models: {
            id: string;
            name: string;
        }[];
        envVar: string;
        keyPrefix: string;
        requiresKey: boolean;
    };
    openai: {
        name: string;
        models: {
            id: string;
            name: string;
        }[];
        envVar: string;
        keyPrefix: string;
        requiresKey: boolean;
    };
    local: {
        name: string;
        models: {
            id: string;
            name: string;
        }[];
        envVar: string;
        keyPrefix: string;
        requiresKey: boolean;
    };
};
/**
 * Load existing configuration
 */
export declare function loadConfig(): Promise<ClawGuardConfig>;
/**
 * Save configuration
 */
export declare function saveConfig(config: ClawGuardConfig): Promise<void>;
/**
 * Check if config exists
 */
export declare function isConfigured(): Promise<boolean>;
/**
 * Get API key from config or environment
 */
export declare function getApiKey(): Promise<string | undefined>;
/**
 * Check for first run and prompt setup
 */
export declare function checkFirstRun(): Promise<void>;
/**
 * Run interactive setup wizard
 */
export declare function runSetupWizard(): Promise<ClawGuardConfig>;
/**
 * Show current configuration
 */
export declare function showConfig(): Promise<void>;
/**
 * Clear stored configuration
 */
export declare function clearConfig(): Promise<void>;
/**
 * Test the current configuration by making a simple API call
 */
export declare function testConfig(): Promise<boolean>;
export { CONFIG_FILE, CONFIG_DIR };
