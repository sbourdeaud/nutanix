terraform {
  required_providers {
    nutanix = {
      source  = "nutanix/nutanix"
      version = "2.0"
    }
  }
}

#defining nutanix configuration
provider "nutanix" {
  username = var.nutanix_username
  password = var.nutanix_password
  endpoint = var.nutanix_endpoint
  port     = 9440
  insecure = true
}

#creating networks
resource "nutanix_subnet" "hci-uvm-171" {
  # What cluster will this VLAN live on?
  cluster_uuid = "00062b45-8b3c-be2b-50cf-3cecef82a4d9"

  # General Information
  name        = "hci-uvm-171"
  vlan_id     = 171
  subnet_type = "VLAN"
}