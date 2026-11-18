# SOC Lab — T-Pot honeypot → Wazuh SIEM → Ticket → Auto-Remediation

Extends the existing Azure `Azure_SEIM_Lab` (T-Pot CE honeypot) into a working
Security Operations Center with detection, ticketing, and automated response.

> The honeypot itself is provisioned by the repo root `main.tf` + `cloud-init/tpot.yaml`
> (unattended `./install.sh -s -t h`). This `soc/` layer adds the SIEM, detection,
> ticketing, and response on top. See the root [`README.md`](../README.md) for
> "Keeping T-Pot Current" and how to reach the honeypot.

## Architecture

```
  ATTACKER (internet)
        │
        ▼
┌───────────────────────┐        ┌───────────────────────────────┐
│  honeyVM  (existing)  │        │  wazuhVM  (new, locked down)  │
│  T-Pot CE honeypots   │        │  Wazuh manager + indexer      │
│  Cowrie / Dionaea /   │ logs   │  + dashboard                  │
│  HoneyTrap / p0f ...  │───────▶│                                │
│  + wazuh-agent        │ 1514   │  rules → alerts → level       │
└───────────────────────┘        │        │         │            │
                                  │        │         ▼            │
     [ LAYER 1: SENSOR ]          │        │   Active Response      │
                                  │        │   (block IP) ─────────┼──▶ Azure NSG
                                  │        ▼                        │   deny rule
                                  │   Integrator → ticket          │
                                  └────────────┬──────────────────┘
                                               ▼
                                    [ LAYER 4: TICKET ]  (webhook/email/JSON)
```

| Layer | What | Where |
|-------|------|-------|
| 1 Sensor | T-Pot CE (already deployed) | honeyVM |
| 2 SIEM | Wazuh all-in-one (manager+indexer+dashboard) | wazuhVM (new) |
| 3 Detection | T-Pot decoders + rules | wazuhVM |
| 4 Ticketing | Wazuh integrator → webhook | wazuhVM → your tool |
| 5 Response | Wazuh Active Response → Azure NSG deny | wazuhVM → Azure API |

## Why Wazuh on a separate VM (not inside T-Pot)

T-Pot is a hardened, purpose-built Docker appliance that expects to be *the*
thing exposed to the internet. Do **not** co-locate your SIEM with it. Run Wazuh
on its own VM and ship T-Pot's logs to it. Also: unlike the honeypot's NSG, the
Wazuh VM's NSG must **not** be world-open — restrict 22/443/55000 to your admin IP.

## Remediation model (important)

You don't "fix" a honeypot — you *respond to the attacker*. Automated actions:

| Trigger | Action |
|---------|--------|
| Cowrie SSH brute force (N fails / 2 min / same IP) | NSG deny for source IP, 4h TTL |
| Dionaea malware download / C2 callback | NSG deny + record file hash + notify |
| Web honeypot exploitation | NSG deny + notify |
| Any source hitting > M honeypots | NSG deny + open ticket (high) |

## Deploy order

1. `cd terraform && terraform init && terraform apply` → creates wazuhVM.
2. It auto-installs Wazuh all-in-one; grab the admin password (see `outputs`).
3. Copy `wazuh/tpot-agent.conf` fragment into honeyVM's
   `/var/ossec/etc/ossec.conf`, install `wazuh-agent`, point it at wazuhVM.
4. Copy `wazuh/decoders/` and `wazuh/rules/` to wazuhVM `/var/ossec/etc/`.
5. Copy `active-response/*.sh` to `/var/ossec/active-response/bin/`, chmod +x.
6. Add the manager snippets (agent.conf + active response + integrator) to
   `/var/ossec/etc/ossec.conf`, `systemctl restart wazuh-manager`.

## Files

```
terraform/            wazuhVM + locked-down NSG  +  Sentinel workspace/playbooks/automation
playbooks/            Sentinel Logic Apps (SOAR): block-ip-nsg, incident-ticket
wazuh/tpot-agent.conf  log collection config for the honeypot host
wazuh/decoders/        T-Pot JSON decoders
wazuh/rules/           detection rules + brute-force correlation + AR wiring
wazuh/active-response/ block/unblock source IP in Azure NSG
wazuh/integrations/    ticket webhook
```
