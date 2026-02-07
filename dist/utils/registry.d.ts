/**
 * Registry API helpers for npm and PyPI
 */
export interface NpmPackageInfo {
    name: string;
    version: string;
    description?: string;
    createdAt: Date;
    modifiedAt: Date;
    downloadsLastWeek: number;
    maintainers: string[];
    hasInstallScripts: boolean;
    repository?: string;
    deprecated?: string;
}
export interface PypiPackageInfo {
    name: string;
    version: string;
    description?: string;
    createdAt?: Date;
    downloadsLastMonth?: number;
    maintainers: string[];
    repository?: string;
    yanked: boolean;
}
export interface RegistryCheckResult {
    exists: boolean;
    info?: NpmPackageInfo | PypiPackageInfo;
    error?: string;
}
/**
 * Check if a package exists on npm registry and get metadata
 */
export declare function checkNpmPackage(packageName: string): Promise<RegistryCheckResult>;
/**
 * Check if a package exists on PyPI and get metadata
 */
export declare function checkPypiPackage(packageName: string): Promise<RegistryCheckResult>;
/**
 * Check package age (returns days since creation)
 */
export declare function getPackageAge(info: NpmPackageInfo | PypiPackageInfo): number | null;
/**
 * Determine if a package is suspiciously new (< 30 days old with low downloads)
 */
export declare function isSuspiciouslyNew(info: NpmPackageInfo | PypiPackageInfo): boolean;
/**
 * Batch check multiple packages with concurrency control
 */
export declare function batchCheckNpm(packages: string[], concurrency?: number): Promise<Map<string, RegistryCheckResult>>;
/**
 * Batch check multiple PyPI packages with concurrency control
 */
export declare function batchCheckPypi(packages: string[], concurrency?: number): Promise<Map<string, RegistryCheckResult>>;
