#!/bin/bash
# =============================================================================
# Wazuh Active Response — remove a previously created NSG deny rule.
# Install to: /var/ossec/active-response/bin/unblock-ip-azure.sh  (chmod 750)
# Usage: unblock-ip-azure.sh <srcip> [rule-name]
# =============================================================================

LOG="/var/ossec/logs/active-responses.log"
HONEY_RG="honeypot-rg"
HONEY_NSG="honeyNSG"

log() { echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') unblock-ip-azure: $*" >> "$LOG"; }

# Called directly (from `at`) with argv, or by Wazuh with JSON on stdin.
if [ -n "$1" ]; then
  SRCIP="$1"
  RULE_NAME="${2:-auto-block-$(echo "$SRCIP" | tr '.' '-')}"
else
  INPUT="$(cat)"; [ -z "$INPUT" ] && INPUT="{}"
  SRCIP="$(echo "$INPUT" | jq -r '.parameters.alert.data.srcip // .parameters.alert.srcip // empty')"
  RULE_NAME="auto-block-$(echo "$SRCIP" | tr '.' '-')"
fi

[ -z "$SRCIP" ] && { log "no srcip, aborting"; exit 1; }

az account show >/dev/null 2>&1 || az login --identity >/dev/null 2>&1 || { log "az auth failed"; exit 1; }

az network nsg rule delete \
  --resource-group "$HONEY_RG" \
  --nsg-name "$HONEY_NSG" \
  --name "$RULE_NAME" \
  --only-show-errors >/dev/null 2>&1 \
  && log "UNBLOCKED $SRCIP (removed $RULE_NAME)" \
  || log "unblock failed or rule already gone for $SRCIP"
