/**
 * ClawGuard Report Generator
 * Formats scan results for output
 */
import type { ScanResult } from './types.js';
/**
 * Format scan result as JSON
 */
export declare function formatJson(result: ScanResult): string;
/**
 * Format scan result as Markdown
 */
export declare function formatMarkdown(result: ScanResult): string;
/**
 * Format scan result for console output
 * Uses ANSI colors when supported
 */
export declare function formatConsole(result: ScanResult): string;
/**
 * Format scan result based on output type
 */
export declare function formatResult(result: ScanResult, format?: 'json' | 'md' | 'html'): string;
