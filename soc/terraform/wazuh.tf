###############################################################################
# SOC Lab — Wazuh manager VM
# Deploy from the soc-lab/terraform directory.
# Deliberately locked down: NOT world-open like the honeypot.
###############################################################################

provider "azurerm" {
  features {}
}

variable "resource_group_name" { default = "soc-lab-rg" }
variable "location" { default = "East US" }
variable "admin_username" { default = "socuser" }
variable "ssh_public_key_path" { default = "~/.ssh/id_rsa.pub" }

# Restrict Wazuh access to your own admin IP. Change this.
variable "admin_cidr" {
  description = "Your admin public IP/CIDR, e.g. 203.0.113.4/32"
  default     = "203.0.113.4/32"
}

# T-Pot honeypot host — where the agent lives.
variable "honeypot_private_cidr" {
  description = "Private CIDR of the honeypot host, allowed to reach 1514/1515"
  default     = "0.0.0.0/0" # tighten to the honeypot's IP/VNet once known
}

resource "azurerm_resource_group" "rg" {
  name     = var.resource_group_name
  location = var.location
}

resource "azurerm_virtual_network" "vnet" {
  name                = "soc-vnet"
  address_space       = ["10.10.0.0/16"]
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
}

resource "azurerm_subnet" "subnet" {
  name                 = "soc-subnet"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.10.1.0/24"]
}

resource "azurerm_public_ip" "pip" {
  name                = "wazuhPublicIP"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_network_security_group" "nsg" {
  name                = "wazuhNSG"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
}

# --- Rules: locked down, admin-IP restricted ------------------------------

# SSH + Wazuh dashboard/API from admin only
resource "azurerm_network_security_rule" "admin_all" {
  name                        = "admin-management"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_ranges     = ["22", "443", "55000"]
  source_address_prefix       = var.admin_cidr
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.rg.name
  network_security_group_name = azurerm_network_security_group.nsg.name
}

# Wazuh agent traffic (1514/1515) from honeypot only
resource "azurerm_network_security_rule" "agent_traffic" {
  name                        = "wazuh-agent"
  priority                    = 110
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_ranges     = ["1514", "1515"]
  source_address_prefix       = var.honeypot_private_cidr
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.rg.name
  network_security_group_name = azurerm_network_security_group.nsg.name
}

# Explicit deny-all default (Azure's built-in DenyAllInbound also covers this)
resource "azurerm_network_security_rule" "deny_all" {
  name                        = "deny-all-inbound"
  priority                    = 4000
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.rg.name
  network_security_group_name = azurerm_network_security_group.nsg.name
}

resource "azurerm_network_interface" "nic" {
  name                = "wazuhNIC"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.subnet.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.pip.id
  }
}

resource "azurerm_network_interface_security_group_association" "assoc" {
  network_interface_id      = azurerm_network_interface.nic.id
  network_security_group_id = azurerm_network_security_group.nsg.id
}

resource "azurerm_linux_virtual_machine" "wazuh" {
  name                  = "wazuhVM"
  resource_group_name   = azurerm_resource_group.rg.name
  location              = azurerm_resource_group.rg.location
  size                  = "Standard_D4s_v3" # indexer needs RAM; >=8GB recommended
  admin_username        = var.admin_username
  network_interface_ids = [azurerm_network_interface.nic.id]

  admin_ssh_key {
    username   = var.admin_username
    public_key = file(var.ssh_public_key_path)
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
    disk_size_gb         = 64
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }

  # Give the VM a managed identity so the active-response scripts can
  # block IPs in Azure without embedding a service principal secret.
  identity {
    type = "SystemAssigned"
  }

  depends_on = [azurerm_network_interface_security_group_association.assoc]
}

###############################################################################
# Bootstrap: install Wazuh all-in-one (manager + indexer + dashboard)
###############################################################################
resource "null_resource" "install_wazuh" {
  depends_on = [azurerm_linux_virtual_machine.wazuh]

  connection {
    type        = "ssh"
    user        = var.admin_username
    private_key = file(replace(var.ssh_public_key_path, ".pub", ""))
    host        = azurerm_public_ip.pip.ip_address
  }

  provisioner "remote-exec" {
    inline = [
      "sudo apt-get update -y",
      "sudo apt-get install -y curl jq azure-cli",
      "curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh",
      "sudo bash wazuh-install.sh -a -i", # -a all-in-one, -i ignore hw check
      "echo 'Wazuh install complete — retrieve admin password with: sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt'"
    ]
  }
}
