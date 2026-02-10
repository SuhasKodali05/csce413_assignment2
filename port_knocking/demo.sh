
#!/usr/bin/env bash

set -euo pipefail

TARGET_IP=${1:-172.20.0.40}
SEQUENCE=${2:-"1234,5678,9012"}
PROTECTED_PORT=${3:-2222}

echo "Step 1: Attempting protected port before knocking (failure expected)"
ssh -o ConnectTimeout=3 -p "$PROTECTED_PORT" sshuser@"$TARGET_IP" || true

echo
echo "Step 2: Sending knock sequence: $SEQUENCE"
python3 knock_client.py --target "$TARGET_IP" --sequence "$SEQUENCE"

# Give server time to open port
sleep 2

echo
echo "Step 3: Attempting protected port after knocking (success expected)"
ssh -o ConnectTimeout=5 -p "$PROTECTED_PORT" sshuser@"$TARGET_IP" || true
