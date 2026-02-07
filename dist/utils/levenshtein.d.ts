/**
 * Levenshtein distance calculation for typosquatting detection
 *
 * Techniques adapted from dnstwist (https://github.com/elceef/dnstwist):
 * - Character omission (lodash → lodas)
 * - Character swap (lodash → lodahs)
 * - Homoglyphs (lodash → l0dash)
 * - Adjacent key typos (lodash → kodash)
 * - Vowel dropping (lodash → ldsh)
 * - Character repetition (lodash → loddash)
 */
/**
 * Calculate the Levenshtein (edit) distance between two strings
 * @param a First string
 * @param b Second string
 * @returns Number of single-character edits required to change a into b
 */
export declare function levenshteinDistance(a: string, b: string): number;
/**
 * Check if a package name is within a given distance of any popular package
 * @param name Package name to check
 * @param popularPackages List of popular package names
 * @param maxDistance Maximum allowed edit distance (default: 2)
 * @returns Object with match info if typosquat detected, null otherwise
 */
export declare function checkTyposquat(name: string, popularPackages: string[], maxDistance?: number): {
    original: string;
    distance: number;
} | null;
/**
 * Check for common typosquatting patterns beyond Levenshtein
 * Adapted from dnstwist techniques
 * @param name Package name to check
 * @param popularPackages List of popular package names
 * @returns Object with match info if pattern detected, null otherwise
 */
export declare function checkTyposquatPatterns(name: string, popularPackages: string[]): {
    original: string;
    pattern: string;
} | null;
/**
 * Comprehensive typosquat check combining distance and pattern detection
 */
export declare function detectTyposquat(name: string, popularPackages: string[], maxDistance?: number): {
    original: string;
    type: 'distance' | 'pattern';
    detail: string;
} | null;
