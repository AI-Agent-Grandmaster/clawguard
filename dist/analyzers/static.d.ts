/**
 * ClawGuard Static Code Analyzer
 *
 * Scans skill files for:
 * - Pattern-based malware detection
 * - Obfuscation detection (base64, hex, unicode)
 * - Fetch-and-execute patterns
 * - Persistence mechanisms
 * - AST analysis for JS/TS
 */
import type { StaticAnalyzer } from '../types.js';
/**
 * Create a static analyzer instance
 */
export declare function createStaticAnalyzer(): StaticAnalyzer;
export default createStaticAnalyzer;
