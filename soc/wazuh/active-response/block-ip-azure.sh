#!/bin/bash
# =============================================================================
# Wazuh Active Response — block a source IP in the honeypot NSG.
# Install to: /var/ossec/active-response/bin/block-ip-azure.sh  (chmod 750)
#
# Receives the Wazuh alert on stdin (JSON) and/or argv:
#   argv on some setups: $1=add $2=<user> $3=<srcip>
# We support both. Runs on the Wazuh MANAGER.
#
# Requires: azure-cli installed and authenticated (VM managed identity:
#   `az login --identity` — grant the identity 'Network Contributor' on the NSG).
# =============================================================================

LOG="/var/ossec/logs/active-responses.log"
HONEY_RG="honeypot-rg"
HONEY_NSG="honeyNSG"
BLOCK_TTL_SECONDS=14400          # 4 hours
PRIORITY_BASE=2000               # deny rules use priority >= 2000 (below allow rules)

log() { echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') block-ip-azure: $*" >> "$LOG"; }

# --- read alert from stdin (Wazuh passes JSON when <executable> style v2) ---
INPUT="$(cat)"
[ -z "$INPUT" ] && INPUT="{}"

SRCIP="$(echo "$INPUT" | jq -r '
  .parameters.alert.data.srcip //
  .parameters.alert.data.src_ip //
  .parameters.alert.srcip //
  .parameters.alert.data.srcip //
  empty' 2>/dev/null)"
[ -z "$SRCIP" ] && SRCIP="$3"     # fall back to argv style
[ -z "$SRCIP" ] && { log "no srcip in alert, aborting"; exit 1; }

# Validate IPv4 to avoid injecting junk into the NSG rule name.
echo "$SRCIP" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || { log "non-IPv4 srcip '$SRCIP', skipping"; exit 1; }

# Skip RFC1918 / loopback — never block internal space.
echo "$SRCIP" | grep -Eq '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.)' && { log "internal IP $SRCIP, skipping"; exit 0; }

# Deterministic rule name + priority from the IP (stable across re-blocks).
SAFE_IP="$(echo "$SRCIP" | tr '.' '-')"
RULE_NAME="auto-block-${SAFE_IP}"
OCTET="$(echo "$SRCIP" | cut -d. -f4)"
PRIORITY=$(( PRIORITY_BASE + OCTET ))

# Ensure authenticated (managed identity).
az account show >/dev/null 2>&1 || az login --identity >/dev/null 2>&1 || { log "az auth failed"; exit 1; }

az network nsg rule create \
  --resource-group "$HONEY_RG" \
  --nsg-name "$HONEY_NSG" \
  --name "$RULE_NAME" \
  --priority "$PRIORITY" \
  --direction Inbound \
  --access Deny \
  --protocol '*' \
  --source-address-prefixes "$SRCIP" \
  --source-port-ranges '*' \
  --destination-address-prefixes '*' \
  --destination-port-ranges '*' \
  --description "Wazuh auto-block $(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
  --only-show-errors >/dev/null 2>&1

if [ $? -eq 0 ]; then
  log "BLOCKED $SRCIP via NSG rule $RULE_NAME (priority $PRIORITY)"
  # Schedule automatic unblock.
  SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
  echo "$SELF_DIR/unblock-ip-azure.sh $SRCIP $RULE_NAME" | at now + $((BLOCK_TTL_SECONDS / 60)) minutes 2>/dev/null \
    || log "note: 'at' scheduler unavailable — rule will not auto-expire"
else
  log "FAILED to block $SRCIP"
  exit 1
fi
