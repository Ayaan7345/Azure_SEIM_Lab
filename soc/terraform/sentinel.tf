###############################################################################
# SOC Lab — Microsoft Sentinel workspace, onboarding, playbooks, automation.
#
# This is the Sentinel "SOAR" side. It confirms the design rule from the SOC
# skill: a honeypot is a log firehose, so DO NOT ship raw honeypot logs here.
# Point a Wazuh->Sentinel forwarder (or a narrow AMA DCR) at this workspace so
# only ALERTS land here and get promoted to incidents. The playbooks below then
# respond to those incidents.
###############################################################################

data "azurerm_client_config" "current" {}

# --- Workspace + onboarding -------------------------------------------------

resource "azurerm_log_analytics_workspace" "sentinel" {
  name                = "honeypot-sentinel-law"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "PerGB2018"
  retention_in_days   = 90

  # Keep the lab's ingestion cost visible: a daily cap stops a runaway honeypot
  # from producing a runaway bill.
  daily_quota_gb = 1
}

resource "azurerm_sentinel_log_analytics_workspace_onboarding" "sentinel" {
  workspace_id = azurerm_log_analytics_workspace.sentinel.id
}

locals {
  subscription_id = data.azurerm_client_config.current.subscription_id
  tenant_id       = data.azurerm_client_config.current.tenant_id

  # The honeypot's NSG — the playbook adds Deny rules here.
  honeypot_nsg_id = "/subscriptions/${local.subscription_id}/resourceGroups/${var.honeypot_resource_group}/providers/Microsoft.Network/networkSecurityGroups/${var.honeypot_nsg_name}"
}

# --- Playbook 1: block attacker IPs in the honeypot NSG ---------------------

resource "azurerm_resource_group_template_deployment" "block_ip_playbook" {
  name                = "soc-block-ip-nsg"
  resource_group_name = azurerm_resource_group.rg.name
  deployment_mode     = "Incremental"

  template_content = file("${path.module}/../playbooks/block-ip-nsg/azuredeploy.json")

  parameters_content = jsonencode({
    PlaybookName     = { value = "soc-block-ip-nsg" }
    NSGResourceId    = { value = local.honeypot_nsg_id }
    RulePriorityBase = { value = 2100 }
  })
}

# --- Playbook 2: open a ticket on every incident ----------------------------

resource "azurerm_resource_group_template_deployment" "ticket_playbook" {
  name                = "soc-incident-ticket"
  resource_group_name = azurerm_resource_group.rg.name
  deployment_mode     = "Incremental"

  template_content = file("${path.module}/../playbooks/incident-ticket/azuredeploy.json")

  parameters_content = jsonencode({
    PlaybookName     = { value = "soc-incident-ticket" }
    TicketWebhookUrl = { value = var.ticket_webhook_url }
  })
}

# --- Automation rules: run the playbooks on new incidents -------------------

resource "azurerm_sentinel_automation_rule" "block_attacker" {
  name                       = "e1f2a3b4-0001-4c1d-9a10-000000000001"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.sentinel.workspace_id
  display_name               = "Honeypot SOC - block attacker IPs"
  order                      = 1
  enabled                    = true
  triggers_on                = "Incidents"
  triggers_when              = "Created"

  # Only fire on our own honeypot incidents, so we never auto-block based on
  # an unrelated incident source.
  condition_json = jsonencode([
    {
      conditionProperties = {
        propertyName   = "IncidentTitle"
        operator       = "Contains"
        propertyValues = ["Honeypot"]
      }
    }
  ])

  action_playbook {
    logic_app_id = jsondecode(azurerm_resource_group_template_deployment.block_ip_playbook.output_content).playbookResourceId.value
    order        = 1
    tenant_id    = local.tenant_id
  }
}

resource "azurerm_sentinel_automation_rule" "open_ticket" {
  name                       = "e1f2a3b4-0002-4c1d-9a10-000000000002"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.sentinel.workspace_id
  display_name               = "Honeypot SOC - open ticket"
  order                      = 2
  enabled                    = true
  triggers_on                = "Incidents"
  triggers_when              = "Created"

  action_playbook {
    logic_app_id = jsondecode(azurerm_resource_group_template_deployment.ticket_playbook.output_content).playbookResourceId.value
    order        = 1
    tenant_id    = local.tenant_id
  }
}

# --- Sample analytics rule: honeypot brute force -> incident ----------------
# Assumes a table `HoneypotAttack_CL` (or replace with your forwarder's table,
# e.g. `WazuhAlerts_CL`) that carries the attacker IP as `IpAddress`.

resource "azurerm_sentinel_alert_rule_scheduled" "cowrie_bruteforce" {
  name                       = "honeypot-cowrie-bruteforce"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.sentinel.workspace_id
  display_name               = "Honeypot: SSH brute force against Cowrie"
  description                = "Fires when a single source IP racked up many failed logins against the honeypot."
  severity                   = "High"
  enabled                    = true

  query_frequency = "PT5M"
  query_period    = "PT5M"

  query = <<QUERY
HoneypotAttack_CL
| where EventID_s in ("cowrie.login.failed", "cowrie.login.success")
| summarize Attempts = count() by IpAddress = SrcIp_s, bin(TimeGenerated, 5m)
| where Attempts >= 8
| project TimeGenerated, IpAddress, Attempts
QUERY

  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "IpAddress"
    }
  }

  incident {
    create_incident_enabled = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT1H"
      reopen_closed_incidents = false
      entity_matching_method  = "Selected"
      by_entities             = ["IP"]
    }
  }
}
