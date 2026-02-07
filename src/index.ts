/**
 * ClawGuard - Security Scanner for AI Agent Skills
 */

export * from './types.js';
export { PromptAnalyzer, createPromptAnalyzer } from './analyzers/prompt.js';

// Re-export helper functions for direct use
export {
  detectInvisibleUnicode,
  containsInvisibleUnicode,
  detectHiddenWhitespace,
  hasHiddenWhitespaceBlocks,
  detectHomoglyphs,
  hasHomoglyphObfuscation,
  detectRtlOverride,
  hasRtlOverride,
  parseSkillDocument,
} from './analyzers/prompt.js';
