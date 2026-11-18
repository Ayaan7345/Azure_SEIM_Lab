# Sentinel Playbooks (SOAR) — honeypot SOC

Playbooks in Microsoft Sentinel are **Azure Logic Apps** with a Sentinel trigger.
Sentinel promotes qualifying alerts into **incidents**, an **automation rule**
fires a playbook on each incident, and the playbook takes the response action.

## Playbooks in this folder

| Playbook | Trigger | What it does |
|---|---|---|
| `block-ip-nsg` | Sentinel incident | Takes every **IP entity** in the incident and adds a **Deny** rule to the honeypot NSG, then comments on the incident. |
| `incident-ticket` | Sentinel incident | POSTs a shaped ticket (number, title, severity, status, ARM id) to a webhook — Teams, Slack, Discord, Jira, ServiceNow, n8n, or your API. |

Both are incident-triggered (`Microsoft_Sentinel_incident`, path `/incident-creation`)
and use a **system-assigned managed identity** — no secrets stored.

## Deploy

Terraform wires the whole thing (workspace, onboarding, both playbooks, two
automation rules, one sample analytics rule):

```bash
cd ../terraform
terraform init
terraform apply \
  -var 'ticket_webhook_url=https://your-webhook'
```

Or deploy a single playbook by hand:

```bash
az deployment group create \
  --resource-group soc-lab-rg \
  --template-file block-ip-nsg/azuredeploy.json \
  --parameters PlaybookName=soc-block-ip-nsg \
               NSGResourceId=/subscriptions/<sub>/resourceGroups/honeypot-rg/providers/Microsoft.Network/networkSecurityGroups/honeyNSG
```

## REQUIRED: grant the playbook permission to block

A fresh Logic App identity has **no rights** on the NSG. After deploying
`block-ip-nsg`, grant its managed identity `Network Contributor` **on the
honeypot NSG only** (least privilege — not the whole resource group):

```bash
# principalId is the `playbookPrincipalId` output of the ARM deployment
az role assignment create \
  --assignee <playbookPrincipalId> \
  --role "Network Contributor" \
  --scope /subscriptions/<sub>/resourceGroups/honeypot-rg/providers/Microsoft.Network/networkSecurityGroups/honeyNSG
```

Also **authorize the Sentinel connection** once: Sentinel → Automation →
click the Logic App → the `azuresentinel` connection should show as authorized.
If it shows an error, open the connection and grant consent.

## How incidents reach the playbooks

```
data in workspace  →  analytics rule  →  incident  →  automation rule  →  playbook
```

- The **analytics rule** must map the attacker IP to an **IP entity** (`Address`),
  or the block playbook has nothing to iterate over. The sample rule in
  `../terraform/sentinel.tf` does this.
- The **automation rule** gates on `IncidentTitle Contains "Honeypot"` so it only
  auto-blocks from our own honeypot incidents.
- Automation rules run playbooks **as the Sentinel service**, which is why the
  identity grant above is required.

## Cost warning (repeat)

Sentinel bills **per GB ingested** (~$4.30/GB analytics; live-priced). A honeypot
is a firehose. **Do not ship raw honeypot logs to this workspace.** Feed it only
Wazuh *alerts* (or a narrow curated set) so incidents — not events — drive the
playbooks. `terraform/sentinel.tf` sets a `daily_quota_gb = 1` cap as a backstop.

## Extending it

- **Enrich before blocking**: add an HTTP action to VirusTotal/GreyNoise and only
  block if the IP is malicious.
- **Approval gate**: swap the automation rule to call an "approval" playbook
  (Teams actionable message) before the block playbook runs.
- **Blocklist instead of per-IP rules**: maintain one deny rule whose
  `sourceAddressPrefixes` array holds all blocked IPs (loses per-IP TTL).
- **TTL unblock**: the ARM playbook blocks permanently. Add a scheduled playbook
  that removes `auto-block-*` rules older than N hours (Logic App recurrence + `az`
  / ARM DELETE) — the Wazuh Active Response side already does TTL via manager
  `<timeout>`.

## Hygiene

- Close the loop: have the block playbook **comment the action taken** on the
  incident (it does) so the ticket reflects the remediation.
- Prefer **one automation rule per response** with a clear display name and a
  low `order`; Sentinel runs them in order.
- Test with a **manual trigger**: create a test incident, or run the Logic App
  manually with a sample incident body, before trusting Auto-Remediation.
