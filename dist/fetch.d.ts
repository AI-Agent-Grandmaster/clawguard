/**
 * URL fetching for remote skill scanning
 *
 * Supports:
 * - GitHub repos: https://github.com/user/repo
 * - GitHub subdirs: https://github.com/user/repo/tree/main/skills/my-skill
 * - Direct tar.gz: https://example.com/skill.tar.gz
 * - Direct zip: https://example.com/skill.zip
 */
export interface FetchResult {
    localPath: string;
    tempDir: string;
    source: string;
    cleanup: () => Promise<void>;
}
/**
 * Check if a string is a URL
 */
export declare function isUrl(input: string): boolean;
/**
 * Fetch a skill from a URL to a temporary directory
 */
export declare function fetchSkillFromUrl(url: string): Promise<FetchResult>;
/**
 * Cleanup temporary directory
 */
export declare function cleanupTempDir(tempDir: string): Promise<void>;
