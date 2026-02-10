# Changelog

All notable changes to ClawGuard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-02-06

### Added
- Interactive TUI config wizard
- Promotional website and GitHub Pages deployment
- Landing page at mikecavallo.github.io/clawguard

### Fixed
- README rendering — escaped HTML angle brackets for GitHub markdown

## [1.0.0] - 2026-02-06

### Added
- Static analyzer with 60+ code vulnerability patterns
- Dependency scanner with 100+ known-bad packages (npm, PyPI, Go)
- Prompt injection detector with 30+ injection patterns
- LLM-powered semantic analyzer (Anthropic, OpenAI, Ollama)
- Multi-skill attack chain detection (8 dangerous capability combinations)
- Behavioral Docker sandbox with honeypot credentials
- Credential access (honeypot) scanner
- Data flow intent graph visualization (ASCII and Mermaid)
- CI/CD security gate (`clawguard gate`)
- Cryptographic skill signing and verification
- Differential version analysis
- Author/skill reputation system
- Continuous monitoring daemon
- Web dashboard
- Known-bad skill database API
- GitHub/URL skill fetching (repos, subdirectories, archives)
- JSON, Markdown, and HTML report output
- Risk scoring (0-100) with severity weighting
- CLI with 15+ commands

[1.0.1]: https://github.com/mikecavallo/clawguard/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/mikecavallo/clawguard/releases/tag/v1.0.0
