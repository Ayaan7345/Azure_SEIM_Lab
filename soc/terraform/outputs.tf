output "wazuh_public_ip" {
  value       = azurerm_public_ip.pip.ip_address
  description = "Public IP of the Wazuh manager VM"
}

output "wazuh_dashboard_url" {
  value       = "https://${azurerm_public_ip.pip.ip_address}"
  description = "Wazuh dashboard (admin creds in wazuh-install-files.tar)"
}

output "wazuh_ssh" {
  value       = "ssh ${var.admin_username}@${azurerm_public_ip.pip.ip_address}"
  description = "SSH to the Wazuh manager"
}

output "wazuh_manager_identity" {
  value       = azurerm_linux_virtual_machine.wazuh.identity[0].principal_id
  description = "Managed identity principal ID — grant it 'Network Contributor' on the honeypot NSG for auto-remediation"
}
