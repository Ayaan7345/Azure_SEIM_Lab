###############################################################################
# Variables for the Sentinel / SOAR layer.
###############################################################################

variable "ticket_webhook_url" {
  description = "Webhook the ticket playbook POSTs to (Teams/Slack/Discord/Jira/ServiceNow/n8n)."
  type        = string
  default     = "https://example.invalid/soc/tickets"
}

variable "honeypot_resource_group" {
  description = "Resource group containing the honeypot NSG."
  type        = string
  default     = "honeypot-rg"
}

variable "honeypot_nsg_name" {
  description = "Name of the honeypot Network Security Group the block playbook writes Deny rules to."
  type        = string
  default     = "honeyNSG"
}
