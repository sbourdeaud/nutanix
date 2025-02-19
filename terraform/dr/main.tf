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

#creating recovery plan
resource "nutanix_recovery_plan" "AZ01-AZ02-NVD-test2" {
  name = "AZ01-AZ02-NVD-test2"
  description = "NVD recovery plan for NVD-test2 categorized async VMs (Linux)"
  stage_list {
    stage_work {
      recover_entities {
        entity_info_list {
          categories {
            name = "NVD"
            value = "test2"
          }
        }
      }
    }
    delay_time_secs = 0
  }
  parameters {
    network_mapping_list {
      availability_zone_network_mapping_list {
          availability_zone_url = "a9ba73d1-7bfd-43c2-9224-9f4733e41312"
          recovery_network {
            name = "uvm-170"
            subnet_list {
              gateway_ip = "10.47.40.1"
              external_connectivity_state = "DISABLED"
              prefix_length = 21
            }
          }
          cluster_reference_list {
              kind = "cluster"
              name = "AZ01APP02"
              uuid = "00062b20-a48b-1b2d-7cca-3cecef82f0e1"
          }
      }
      availability_zone_network_mapping_list {
        availability_zone_url = "2d0ac349-9756-4fb3-86b1-8486c9a2dacd"
        recovery_network {
                name = "uvm-172"
                subnet_list {
                  gateway_ip = "10.47.88.1"
                  external_connectivity_state = "DISABLED"
                  prefix_length = 21
                }
        }
        cluster_reference_list {
            kind = "cluster"
            name = "AZ02APP02"
            uuid = "00062b45-8b3c-be2b-50cf-3cecef82a4d9"
        }
      }
    }
  }
}

resource "nutanix_recovery_plan" "AZ01-AZ02-NVD-test1" {
  name = "AZ01-AZ02-NVD-test1"
  description = "NVD recovery plan for NVD-test1 categorized async VMs (Windows)"
  stage_list {
    stage_work {
      recover_entities {
        entity_info_list {
          categories {
            name = "NVD"
            value = "test1"
          }
        }
      }
    }
    delay_time_secs = 0
  }
  parameters {
    network_mapping_list {
      availability_zone_network_mapping_list {
          availability_zone_url = "a9ba73d1-7bfd-43c2-9224-9f4733e41312"
          recovery_network {
            name = "hci-uvm-169"
            subnet_list {
              gateway_ip = "10.124.0.1"
              external_connectivity_state = "DISABLED"
              prefix_length = 21
            }
          }
          cluster_reference_list {
              kind = "cluster"
              name = "AZ01APP01"
              uuid = "000629f5-3449-38d1-6071-58a2e10e3810"
          }
      }
      availability_zone_network_mapping_list {
        availability_zone_url = "2d0ac349-9756-4fb3-86b1-8486c9a2dacd"
        recovery_network {
                name = "hci-uvm-171"
                subnet_list {
                  gateway_ip = "10.124.16.1"
                  external_connectivity_state = "DISABLED"
                  prefix_length = 21
                }
        }
        cluster_reference_list {
            kind = "cluster"
            name = "AZ02APP01"
            uuid = "000629f2-8a38-a346-29f7-58a2e10e3624"
        }
      }
    }
  }
}