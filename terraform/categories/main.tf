terraform {
  required_providers {
    nutanix = {
      source  = "nutanix/nutanix"
      version = "1.9.5"
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



#creating category
resource "nutanix_category_key" "MyAppType" {
  name         = "MyAppType"
}
resource "nutanix_category_key" "MyAppTier" {
  name         = "MyAppTier"
}


resource "nutanix_category_value" "Az01SingleVmApp" {
  count = 7
  name        = nutanix_category_key.MyAppType.id
  value         = "Az01SingleVmApp${format("%02d", count.index + 1)}"
  description = "NVD"
}
resource "nutanix_category_value" "Az01MultiVmApp" {
  count = 6
  name        = nutanix_category_key.MyAppType.id
  value         = "Az01MultiVmApp${format("%02d", count.index + 1)}"
  description = "NVD"
}

resource "nutanix_category_value" "values" {
  for_each = toset(var.tier_values)

  name        = nutanix_category_key.MyAppTier.id
  value       = each.value
  description = "NVD"
}