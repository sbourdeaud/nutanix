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



#creating security rule
resource "nutanix_network_security_rule" "windows" {
  count = 12
  name            = "AZ02SingleVMApp${format("%02d", count.index + 1)}"
  description     = "AZ02SingleVMApp${format("%02d", count.index + 1)}"
  app_rule_action = "APPLY"

  is_policy_hitlog_enabled = true
  app_rule_target_group_peer_specification_type = "FILTER"
  app_rule_target_group_default_internal_policy = "ALLOW_ALL"
  app_rule_target_group_filter_type = "CATEGORIES_MATCH_ALL"
  app_rule_target_group_filter_kind_list = [
    "vm"
  ]

  app_rule_target_group_filter_params {
    name = "AppType"
    values = [
      "Az02SingleVmApp${format("%02d", count.index + 1)}"
    ]
  }
  #filter with previously created category key-value
  app_rule_target_group_filter_params {
    name = "AppTier"
    values = [
      "RDP"
    ]
  }

  app_rule_inbound_allow_list {
    ip_subnet               = "0.0.0.0"
    ip_subnet_prefix_length = "0"
    peer_specification_type = "IP_SUBNET"
    protocol                = "TCP"
    tcp_port_range_list {
      end_port   = 3389
      start_port = 3389
    }
    tcp_port_range_list {
      end_port = 5985
      start_port = 5985
    }
    tcp_port_range_list {
      end_port = 2074
      start_port = 2074
    }
  }
  app_rule_inbound_allow_list {
    ip_subnet               = "0.0.0.0"
    ip_subnet_prefix_length = "0"
    peer_specification_type = "IP_SUBNET"
    protocol                = "ICMP"
    icmp_type_code_list {
      code = 0
      type = 8
    }
  }
  app_rule_outbound_allow_list {
    peer_specification_type               = "ALL"
  }
}

resource "nutanix_network_security_rule" "linux" {
  count = 12
  name            = "AZ02SingleVMApp${format("%02d", count.index + 1)}"
  description     = "AZ02SingleVMApp${format("%02d", count.index + 1)}"
  app_rule_action = "APPLY"


  app_rule_target_group_peer_specification_type = "FILTER"
  app_rule_target_group_default_internal_policy = "ALLOW_ALL"
  app_rule_target_group_filter_type = "CATEGORIES_MATCH_ALL"
  app_rule_target_group_filter_kind_list = [
    "vm"
  ]

  app_rule_target_group_filter_params {
    name = "AppType"
    values = [
      "Az02SingleVmApp${format("%02d", count.index + 1)}"
    ]
  }
  #filter with previously created category key-value
  app_rule_target_group_filter_params {
    name = "AppTier"
    values = [
      "SSH"
    ]
  }

  app_rule_inbound_allow_list {
    ip_subnet               = "0.0.0.0"
    ip_subnet_prefix_length = "0"
    peer_specification_type = "IP_SUBNET"
    protocol                = "TCP"
    tcp_port_range_list {
      end_port   = 22
      start_port = 22
    }
    tcp_port_range_list {
      end_port = 2074
      start_port = 2074
    }
  }
  app_rule_inbound_allow_list {
    ip_subnet               = "0.0.0.0"
    ip_subnet_prefix_length = "0"
    peer_specification_type = "IP_SUBNET"
    protocol                = "ICMP"
    icmp_type_code_list {
      code = 0
      type = 8
    }
  }
  app_rule_outbound_allow_list {
    peer_specification_type               = "ALL"
  }
}

resource "nutanix_network_security_rule" "web" {
  count = 6
  name            = "AZ02MultiVMApp${format("%02d", count.index + 1)}"
  description     = "AZ02MultiVMApp${format("%02d", count.index + 1)}"
  app_rule_action = "APPLY"

  is_policy_hitlog_enabled = true
  app_rule_target_group_peer_specification_type = "FILTER"
  app_rule_target_group_default_internal_policy = "DENY_ALL"
  app_rule_target_group_filter_type = "CATEGORIES_MATCH_ALL"
  app_rule_target_group_filter_kind_list = [
    "vm"
  ]

  app_rule_target_group_filter_params {
    name = "AppType"
    values = [
      "Az02MultiVmApp${format("%02d", count.index + 1)}"
    ]
  }
  #filter with previously created category key-value
  app_rule_target_group_filter_params {
    name = "AppTier"
    values = [
      "Web"
    ]
  }

  app_rule_inbound_allow_list {
    ip_subnet               = "0.0.0.0"
    ip_subnet_prefix_length = "0"
    peer_specification_type = "IP_SUBNET"
    protocol                = "TCP"
    tcp_port_range_list {
      end_port   = 3389
      start_port = 3389
    }
    tcp_port_range_list {
      end_port = 5985
      start_port = 5985
    }
    tcp_port_range_list {
      end_port   = 22
      start_port = 22
    }
    tcp_port_range_list {
      end_port   = 443
      start_port = 443
    }
    tcp_port_range_list {
      end_port = 2074
      start_port = 2074
    }
  }
  app_rule_inbound_allow_list {
    ip_subnet               = "0.0.0.0"
    ip_subnet_prefix_length = "0"
    peer_specification_type = "IP_SUBNET"
    protocol                = "ICMP"
    icmp_type_code_list {
      code = 0
      type = 8
    }
  }
  app_rule_outbound_allow_list {
    peer_specification_type               = "ALL"
  }
  app_rule_outbound_allow_list {
    filter_type = "CATEGORIES_MATCH_ALL"
    filter_params {
      name = "AppType"
      values = [
        "Az02MultiVmApp${format("%02d", count.index + 1)}"
      ]
    }
    #filter with previously created category key-value
    filter_params {
      name = "AppTier"
      values = [
        "App"
      ]
    }
    filter_kind_list        = ["vm"]
    peer_specification_type = "FILTER"
    protocol                = "TCP"
    tcp_port_range_list {
      end_port   = 3000
      start_port = 3000
    }
  }
}

resource "nutanix_network_security_rule" "app" {
  count = 6
  name            = "AZ02MultiVMApp${format("%02d", count.index + 1)}"
  description     = "AZ02MultiVMApp${format("%02d", count.index + 1)}"
  app_rule_action = "APPLY"

  is_policy_hitlog_enabled = true
  app_rule_target_group_peer_specification_type = "FILTER"
  app_rule_target_group_default_internal_policy = "DENY_ALL"
  app_rule_target_group_filter_type = "CATEGORIES_MATCH_ALL"
  app_rule_target_group_filter_kind_list = [
    "vm"
  ]

  app_rule_target_group_filter_params {
    name = "AppType"
    values = [
      "Az02MultiVmApp${format("%02d", count.index + 1)}"
    ]
  }
  #filter with previously created category key-value
  app_rule_target_group_filter_params {
    name = "AppTier"
    values = [
      "App"
    ]
  }
  app_rule_inbound_allow_list {
    ip_subnet               = "0.0.0.0"
    ip_subnet_prefix_length = "0"
    peer_specification_type = "IP_SUBNET"
    protocol                = "TCP"
    tcp_port_range_list {
      end_port   = 3389
      start_port = 3389
    }
    tcp_port_range_list {
      end_port = 5985
      start_port = 5985
    }
    tcp_port_range_list {
      end_port   = 22
      start_port = 22
    }
    tcp_port_range_list {
      end_port = 2074
      start_port = 2074
    }
  }
  app_rule_inbound_allow_list {
    filter_type = "CATEGORIES_MATCH_ALL"
    filter_params {
      name = "AppType"
      values = [
        "Az02MultiVmApp${format("%02d", count.index + 1)}"
      ]
    }
    #filter with previously created category key-value
    filter_params {
      name = "AppTier"
      values = [
        "Web"
      ]
    }
    filter_kind_list        = ["vm"]
    peer_specification_type = "FILTER"
    protocol                = "TCP"
    tcp_port_range_list {
      end_port   = 3000
      start_port = 3000
    }
  }
  app_rule_inbound_allow_list {
    ip_subnet               = "0.0.0.0"
    ip_subnet_prefix_length = "0"
    peer_specification_type = "IP_SUBNET"
    protocol                = "ICMP"
    icmp_type_code_list {
      code = 0
      type = 8
    }
  }
  app_rule_outbound_allow_list {
    peer_specification_type               = "ALL"
  }
  app_rule_outbound_allow_list {
    filter_type = "CATEGORIES_MATCH_ALL"
    filter_params {
      name = "AppType"
      values = [
        "Az02MultiVmApp${format("%02d", count.index + 1)}"
      ]
    }
    #filter with previously created category key-value
    filter_params {
      name = "AppTier"
      values = [
        "DB"
      ]
    }
    filter_kind_list        = ["vm"]
    peer_specification_type = "FILTER"
    protocol                = "TCP"
    tcp_port_range_list {
      end_port   = 3306
      start_port = 3306
    }
  }
}

resource "nutanix_network_security_rule" "db" {
  count = 6
  name            = "AZ02MultiVMApp${format("%02d", count.index + 1)}"
  description     = "AZ02MultiVMApp${format("%02d", count.index + 1)}"
  app_rule_action = "APPLY"

  is_policy_hitlog_enabled = true
  app_rule_target_group_peer_specification_type = "FILTER"
  app_rule_target_group_default_internal_policy = "DENY_ALL"
  app_rule_target_group_filter_type = "CATEGORIES_MATCH_ALL"
  app_rule_target_group_filter_kind_list = [
    "vm"
  ]

  app_rule_target_group_filter_params {
    name = "AppType"
    values = [
      "Az02MultiVmApp${format("%02d", count.index + 1)}"
    ]
  }
  #filter with previously created category key-value
  app_rule_target_group_filter_params {
    name = "AppTier"
    values = [
      "DB"
    ]
  }

  app_rule_inbound_allow_list {
    ip_subnet               = "0.0.0.0"
    ip_subnet_prefix_length = "0"
    peer_specification_type = "IP_SUBNET"
    protocol                = "TCP"
    tcp_port_range_list {
      end_port   = 3389
      start_port = 3389
    }
    tcp_port_range_list {
      end_port = 5985
      start_port = 5985
    }
    tcp_port_range_list {
      end_port   = 22
      start_port = 22
    }
    tcp_port_range_list {
      end_port = 2074
      start_port = 2074
    }
  }
  app_rule_inbound_allow_list {
    filter_type = "CATEGORIES_MATCH_ALL"
    filter_params {
      name = "AppType"
      values = [
        "Az02MultiVmApp${format("%02d", count.index + 1)}"
      ]
    }
    #filter with previously created category key-value
    filter_params {
      name = "AppTier"
      values = [
        "App"
      ]
    }
    filter_kind_list        = ["vm"]
    peer_specification_type = "FILTER"
    protocol                = "TCP"
    tcp_port_range_list {
      end_port   = 3306
      start_port = 3306
    }
  }
  app_rule_inbound_allow_list {
    ip_subnet               = "0.0.0.0"
    ip_subnet_prefix_length = "0"
    peer_specification_type = "IP_SUBNET"
    protocol                = "ICMP"
    icmp_type_code_list {
      code = 0
      type = 8
    }
  }
  app_rule_outbound_allow_list {
    peer_specification_type               = "ALL"
  }
}
