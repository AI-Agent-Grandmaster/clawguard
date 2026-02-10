# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in ClawGuard, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email: **mikecavallo@gmail.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

You should receive a response within 48 hours. We will work with you to understand the issue and coordinate a fix before any public disclosure.

## Scope

The following are in scope for security reports:

- Vulnerabilities in ClawGuard's scanning logic that could cause false negatives (missing real threats)
- Bypass techniques that evade detection
- Vulnerabilities in the known-bad database API
- Issues with how API keys or credentials are stored/handled
- Path traversal or arbitrary file read via scan commands

## Out of Scope

- Issues in third-party dependencies (report those upstream)
- Social engineering attacks against ClawGuard users
- Denial of service against the CLI tool
