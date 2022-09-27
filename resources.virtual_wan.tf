locals {
  waf_config = {
    for k, v in local.configure_connectivity_resources.settings.waf_config :
    k => v
  }
}

resource "azurerm_resource_group" "virtual_wan" {
  for_each = local.azurerm_resource_group_virtual_wan

  provider = azurerm.connectivity

  # Mandatory resource attributes
  name     = each.value.template.name
  location = each.value.template.location
  tags     = each.value.template.tags
}

resource "azurerm_virtual_wan" "virtual_wan" {
  for_each = local.azurerm_virtual_wan_virtual_wan

  provider = azurerm.connectivity

  # Mandatory resource attributes
  name                = each.value.template.name
  resource_group_name = each.value.template.resource_group_name
  location            = each.value.template.location

  # Optional resource attributes
  disable_vpn_encryption            = each.value.template.disable_vpn_encryption
  allow_branch_to_branch_traffic    = each.value.template.allow_branch_to_branch_traffic
  office365_local_breakout_category = each.value.template.office365_local_breakout_category
  type                              = each.value.template.type
  tags                              = each.value.template.tags

  # Set explicit dependencies
  depends_on = [
    azurerm_resource_group.connectivity,
    azurerm_resource_group.virtual_wan,
  ]

}

resource "azurerm_virtual_hub" "virtual_wan" {
  for_each = local.azurerm_virtual_hub_virtual_wan

  provider = azurerm.connectivity

  # Mandatory resource attributes
  name                = each.value.template.name
  resource_group_name = each.value.template.resource_group_name
  location            = each.value.template.location

  # Optional resource attributes
  sku            = each.value.template.sku
  address_prefix = each.value.template.address_prefix
  virtual_wan_id = each.value.template.virtual_wan_id
  tags           = each.value.template.tags

  # Dynamic configuration blocks
  dynamic "route" {
    for_each = each.value.template.route
    content {
      # Mandatory attributes
      address_prefixes    = route.value["address_prefixes"]
      next_hop_ip_address = route.value["next_hop_ip_address"]
    }
  }

  # Set explicit dependencies
  depends_on = [
    azurerm_resource_group.connectivity,
    azurerm_resource_group.virtual_wan,
    azurerm_virtual_wan.virtual_wan,
  ]

}

resource "azurerm_express_route_gateway" "virtual_wan" {
  for_each = local.azurerm_express_route_gateway_virtual_wan

  provider = azurerm.connectivity

  # Mandatory resource attributes
  name                = each.value.template.name
  resource_group_name = each.value.template.resource_group_name
  location            = each.value.template.location
  virtual_hub_id      = each.value.template.virtual_hub_id
  scale_units         = each.value.template.scale_units

  # Optional resource attributes
  tags = each.value.template.tags

  # Set explicit dependencies
  depends_on = [
    azurerm_resource_group.connectivity,
    azurerm_resource_group.virtual_wan,
    azurerm_virtual_wan.virtual_wan,
    azurerm_virtual_hub.virtual_wan,
  ]

}

resource "azurerm_vpn_gateway" "virtual_wan" {
  for_each = local.azurerm_vpn_gateway_virtual_wan

  provider = azurerm.connectivity

  # Mandatory resource attributes
  name                = each.value.template.name
  resource_group_name = each.value.template.resource_group_name
  location            = each.value.template.location
  virtual_hub_id      = each.value.template.virtual_hub_id

  # Optional resource attributes
  routing_preference = each.value.template.routing_preference
  scale_unit         = each.value.template.scale_unit
  tags               = each.value.template.tags

  # Dynamic configuration blocks
  dynamic "bgp_settings" {
    for_each = each.value.template.bgp_settings
    content {
      # Mandatory attributes
      asn         = bgp_settings.value["asn"]
      peer_weight = bgp_settings.value["peer_weight"]
      # Dynamic configuration blocks
      dynamic "instance_0_bgp_peering_address" {
        for_each = bgp_settings.value["instance_0_bgp_peering_address"]
        content {
          custom_ips = instance_0_bgp_peering_address.value["custom_ips"]
        }
      }
      dynamic "instance_1_bgp_peering_address" {
        for_each = bgp_settings.value["instance_1_bgp_peering_address"]
        content {
          custom_ips = instance_1_bgp_peering_address.value["custom_ips"]
        }
      }
    }
  }

  # Set explicit dependencies
  depends_on = [
    azurerm_resource_group.connectivity,
    azurerm_resource_group.virtual_wan,
    azurerm_virtual_wan.virtual_wan,
    azurerm_virtual_hub.virtual_wan,
  ]

}

resource "azurerm_firewall_policy" "virtual_wan" {
  for_each = local.azurerm_firewall_policy_virtual_wan

  provider = azurerm.connectivity

  # Mandatory resource attributes
  name                = each.value.template.name
  resource_group_name = each.value.template.resource_group_name
  location            = each.value.template.location

  # Optional resource attributes
  base_policy_id           = each.value.template.base_policy_id
  private_ip_ranges        = each.value.template.private_ip_ranges
  sku                      = each.value.template.sku
  tags                     = each.value.template.tags
  threat_intelligence_mode = each.value.template.threat_intelligence_mode

  # Dynamic configuration blocks
  dynamic "dns" {
    for_each = each.value.template.dns
    content {
      # Optional attributes
      proxy_enabled = lookup(dns.value, "proxy_enabled", null)
      servers       = lookup(dns.value, "servers", null)
    }
  }

  dynamic "identity" {
    for_each = each.value.template.identity
    content {
      # Mandatory attributes
      type         = identity.value.type
      identity_ids = identity.value.identity_ids
    }
  }

  dynamic "insights" {
    for_each = each.value.template.insights
    content {
      # Mandatory attributes
      enabled                            = insights.value.enabled
      default_log_analytics_workspace_id = insights.value.default_log_analytics_workspace_id
      # Optional attributes
      retention_in_days = lookup(insights.value, "retention_in_days", null)
      # Dynamic configuration blocks
      dynamic "log_analytics_workspace" {
        for_each = lookup(insights.value, "log_analytics_workspace", local.empty_list)
        content {
          # Mandatory attributes
          id                = log_analytics_workspace.value["id"]
          firewall_location = log_analytics_workspace.value["firewall_location"]
        }
      }
    }
  }

  dynamic "intrusion_detection" {
    for_each = each.value.template.intrusion_detection
    content {
      # Optional attributes
      mode = lookup(intrusion_detection.value, "mode", null)
      # Dynamic configuration blocks
      dynamic "signature_overrides" {
        for_each = lookup(intrusion_detection.value, "signature_overrides", local.empty_list)
        content {
          # Optional attributes
          id    = lookup(signature_overrides.value, "id", null)
          state = lookup(signature_overrides.value, "state", null)
        }
      }
      dynamic "traffic_bypass" {
        for_each = lookup(intrusion_detection.value, "traffic_bypass", local.empty_list)
        content {
          # Mandatory attributes
          name     = traffic_bypass.value["name"]
          protocol = traffic_bypass.value["protocol"]
          # Optional attributes
          description           = lookup(traffic_bypass.value, "description", null)
          destination_addresses = lookup(traffic_bypass.value, "destination_addresses", null)
          destination_ip_groups = lookup(traffic_bypass.value, "destination_ip_groups", null)
          destination_ports     = lookup(traffic_bypass.value, "destination_ports", null)
          source_addresses      = lookup(traffic_bypass.value, "source_addresses", null)
          source_ip_groups      = lookup(traffic_bypass.value, "source_ip_groups", null)
        }
      }
    }
  }

  dynamic "threat_intelligence_allowlist" {
    for_each = each.value.template.threat_intelligence_allowlist
    content {
      # Optional attributes
      fqdns        = lookup(threat_intelligence_allowlist.value, "fqdns", null)
      ip_addresses = lookup(threat_intelligence_allowlist.value, "ip_addresses", null)
    }
  }

  # Set explicit dependencies
  depends_on = [
    azurerm_resource_group.connectivity,
    azurerm_resource_group.virtual_wan,
  ]

}

resource "azurerm_firewall" "virtual_wan" {
  for_each = local.azurerm_firewall_virtual_wan

  provider = azurerm.connectivity

  # Mandatory resource attributes
  name                = each.value.template.name
  resource_group_name = each.value.template.resource_group_name
  location            = each.value.template.location

  # Optional resource attributes
  sku_name           = each.value.template.sku_name
  sku_tier           = each.value.template.sku_tier
  firewall_policy_id = each.value.template.firewall_policy_id
  dns_servers        = each.value.template.dns_servers
  private_ip_ranges  = each.value.template.private_ip_ranges
  threat_intel_mode  = each.value.template.threat_intel_mode
  zones              = each.value.template.zones
  tags               = each.value.template.tags

  # Dynamic configuration blocks
  dynamic "ip_configuration" {
    for_each = each.value.template.ip_configuration
    content {
      # Mandatory attributes
      name                 = ip_configuration.value["name"]
      public_ip_address_id = ip_configuration.value["public_ip_address_id"]
      # Optional attributes
      subnet_id = try(ip_configuration.value["subnet_id"], null)
    }
  }

  dynamic "management_ip_configuration" {
    for_each = each.value.template.management_ip_configuration
    content {
      # Mandatory attributes
      name                 = management_ip_configuration.value["name"]
      public_ip_address_id = management_ip_configuration.value["public_ip_address_id"]
      # Optional attributes
      subnet_id = try(management_ip_configuration.value["subnet_id"], null)
    }
  }

  dynamic "virtual_hub" {
    for_each = each.value.template.virtual_hub
    content {
      # Mandatory attributes
      virtual_hub_id = virtual_hub.value["virtual_hub_id"]
      # Optional attributes
      public_ip_count = try(virtual_hub.value["public_ip_count"], null)
    }
  }

  # Set explicit dependencies
  depends_on = [
    azurerm_resource_group.connectivity,
    azurerm_resource_group.virtual_wan,
    azurerm_virtual_wan.virtual_wan,
    azurerm_virtual_hub.virtual_wan,
    azurerm_firewall_policy.virtual_wan,
  ]

}

resource "azurerm_virtual_hub_connection" "virtual_wan" {
  for_each = local.azurerm_virtual_hub_connection

  provider = azurerm.connectivity

  # Mandatory resource attributes
  name                      = each.value.template.name
  virtual_hub_id            = each.value.template.virtual_hub_id
  remote_virtual_network_id = each.value.template.remote_virtual_network_id

  # Optional resource attributes
  internet_security_enabled = each.value.template.internet_security_enabled

  # Dynamic configuration blocks
  dynamic "routing" {
    for_each = each.value.template.routing
    content {
      # Optional attributes
      associated_route_table_id = lookup(routing.value, "associated_route_table_id", null)
      dynamic "propagated_route_table" {
        for_each = lookup(routing.value, "propagated_route_table", local.empty_list)
        content {
          # Optional attributes
          labels          = lookup(propagated_route_table.value, "labels", null)
          route_table_ids = lookup(propagated_route_table.value, "route_table_ids", null)
        }
      }
      dynamic "static_vnet_route" {
        for_each = lookup(routing.value, "static_vnet_route", local.empty_list)
        content {
          # Optional attributes
          name                = lookup(static_vnet_route.value, "name", null)
          address_prefixes    = lookup(static_vnet_route.value, "address_prefixes", null)
          next_hop_ip_address = lookup(static_vnet_route.value, "next_hop_ip_address", null)
        }
      }
    }
  }

  # Set explicit dependencies
  depends_on = [
    azurerm_resource_group.connectivity,
    azurerm_resource_group.virtual_wan,
    azurerm_virtual_wan.virtual_wan,
    azurerm_virtual_hub.virtual_wan,
  ]

}

resource "azurerm_virtual_network" "shared_service_vnet" {
  for_each            = azurerm_resource_group.virtual_wan
  provider            = azurerm.connectivity
  name                = "vnet-shared-${local.configure_connectivity_resources.location}-001"
  location            = local.configure_connectivity_resources.location
  resource_group_name = each.value.name
  address_space       = [local.configure_connectivity_resources.settings.shared_service_vnet.vnet_prefix]

  # dynamic "subnet" {
  #   for_each = local.configure_connectivity_resources.settings.shared_service_vnet.subnet
  #   content {
  #     name           = "snet-shared-${local.configure_connectivity_resources.location}-${subnet.key < 9 ? "00${subnet.key + 1}" : "0${subnet.key + 1}"}"
  #     address_prefix = subnet.value["subnet_prefix"]
  #   }
  # }

  tags = local.configure_connectivity_resources.tags
  depends_on = [
    azurerm_resource_group.connectivity,
    azurerm_resource_group.virtual_wan,
    azurerm_virtual_wan.virtual_wan,
    azurerm_virtual_hub.virtual_wan,
    azurerm_virtual_hub_connection.virtual_wan
  ]
}

resource "azurerm_subnet" "shared_service_subnet" {
  for_each = {
    for key, subnet in local.configure_connectivity_resources.settings.shared_service_vnet.subnet :
    key => subnet
    if subnet != ""
  }
  provider = azurerm.connectivity

  name                 = "snet-${each.key}-${local.configure_connectivity_resources.location}-001"
  resource_group_name  = [for v in azurerm_resource_group.virtual_wan : v.name][0]
  virtual_network_name = [for n in azurerm_virtual_network.shared_service_vnet : n.name][0]
  address_prefixes     = [each.value]

  # delegation {
  #   name = "delegation"

  #   service_delegation {
  #     name    = "Microsoft.ContainerInstance/containerGroups"
  #     actions = ["Microsoft.Network/virtualNetworks/subnets/join/action", "Microsoft.Network/virtualNetworks/subnets/prepareNetworkPolicies/action"]
  #   }
  # }

  private_endpoint_network_policies_enabled = true
  depends_on = [
    azurerm_resource_group.connectivity,
    azurerm_resource_group.virtual_wan,
    azurerm_virtual_wan.virtual_wan,
    azurerm_virtual_hub.virtual_wan,
    azurerm_virtual_network.shared_service_vnet
  ]
}

resource "azurerm_virtual_hub_connection" "vhub_shared" {
  provider                  = azurerm.connectivity
  name                      = "peer-shared-${local.configure_connectivity_resources.location}-001"
  virtual_hub_id            = [for v in azurerm_virtual_hub.virtual_wan : v.id][0]
  remote_virtual_network_id = [for n in azurerm_virtual_network.shared_service_vnet : n.id][0]
  internet_security_enabled = true
  depends_on = [
    azurerm_resource_group.connectivity,
    azurerm_resource_group.virtual_wan,
    azurerm_virtual_wan.virtual_wan,
    azurerm_virtual_hub.virtual_wan,
    azurerm_virtual_hub_connection.virtual_wan,
    azurerm_virtual_network.shared_service_vnet,
    azurerm_subnet.shared_service_subnet
  ]
}

resource "azurerm_public_ip" "pip_agw" {
  provider            = azurerm.connectivity
  name                = "pip-agw-${local.configure_connectivity_resources.location}-001"
  resource_group_name = [for v in azurerm_resource_group.virtual_wan : v.name][0]
  location            = local.configure_connectivity_resources.location
  sku                 = "Standard"
  allocation_method   = "Static"

  tags = local.configure_connectivity_resources.tags
  depends_on = [
    azurerm_resource_group.connectivity,
    azurerm_resource_group.virtual_wan,
  ]
}

resource "azurerm_network_security_group" "shared_service_nsg" {
  provider            = azurerm.connectivity
  name                = "nsg-shared-${local.configure_connectivity_resources.location}-001"
  location            = local.configure_connectivity_resources.location
  resource_group_name = [for v in azurerm_resource_group.virtual_wan : v.name][0]
  tags                = local.configure_connectivity_resources.tags
  dynamic "security_rule" {
    for_each = local.configure_connectivity_resources.settings.nsg_security_rule
    content {
      name                         = security_rule.value["name"]
      priority                     = security_rule.value["priority"]
      direction                    = security_rule.value["direction"]
      access                       = security_rule.value["access"]
      protocol                     = security_rule.value["protocol"]
      source_port_range            = security_rule.value["source_port_range"]
      source_port_ranges           = security_rule.value["source_port_ranges"]
      destination_port_range       = security_rule.value["destination_port_range"]
      destination_port_ranges      = security_rule.value["destination_port_ranges"]
      source_address_prefix        = security_rule.value["source_address_prefix"]
      source_address_prefixes      = security_rule.value["source_address_prefixes"]
      destination_address_prefix   = security_rule.value["destination_address_prefix"]
      destination_address_prefixes = security_rule.value["destination_address_prefixes"]
    }
  }
  depends_on = [
    azurerm_resource_group.connectivity,
    azurerm_resource_group.virtual_wan,
    azurerm_virtual_network.shared_service_vnet,
    azurerm_subnet.shared_service_subnet
  ]
}

resource "azurerm_subnet_network_security_group_association" "nsg_association" {
  for_each                  = azurerm_subnet.shared_service_subnet
  provider                  = azurerm.connectivity
  subnet_id                 = each.value.id
  network_security_group_id = azurerm_network_security_group.shared_service_nsg.id
  depends_on = [
    azurerm_network_security_group.shared_service_nsg
  ]
}
resource "azurerm_web_application_firewall_policy" "waf_agw_policies" {
  provider            = azurerm.connectivity
  name                = "waf-agw-${local.configure_connectivity_resources.location}-001"
  resource_group_name = [for v in azurerm_resource_group.virtual_wan : v.name][0]
  location            = local.configure_connectivity_resources.location

  dynamic "custom_rules" {
    for_each = local.configure_connectivity_resources.settings.waf_config
    content {
      name      = custom_rules.value["name"]
      priority  = custom_rules.value["priority"]
      rule_type = custom_rules.value["rule_type"]

      dynamic "match_conditions" {
        for_each = custom_rules.value["match_conditions"]
        content {
          match_variables {
            variable_name = match_conditions.value["match_variables"].variable_name
            selector      = match_conditions.value["match_variables"].selector
          }
          operator           = match_conditions.value["operator"]
          negation_condition = match_conditions.value["negation_condition"]
          match_values       = match_conditions.value["match_values"]
        }
      }

      action = custom_rules.value["action"]
    }
  }
  policy_settings {
    enabled                     = false
    mode                        = "Prevention"
    request_body_check          = true
    file_upload_limit_in_mb     = 100
    max_request_body_size_in_kb = 128
  }

  managed_rules {
    exclusion {
      match_variable          = "RequestHeaderNames"
      selector                = "x-company-secret-header"
      selector_match_operator = "Equals"
    }
    exclusion {
      match_variable          = "RequestCookieNames"
      selector                = "too-tasty"
      selector_match_operator = "EndsWith"
    }

    managed_rule_set {
      type    = "OWASP"
      version = "3.2"
      rule_group_override {
        rule_group_name = "REQUEST-920-PROTOCOL-ENFORCEMENT"
        disabled_rules = [
          "920300",
          "920440"
        ]
      }
    }
  }
  depends_on = [
    azurerm_resource_group.connectivity,
    azurerm_resource_group.virtual_wan
  ]
}
resource "azurerm_application_gateway" "agw_shared_service" {
  provider                          = azurerm.connectivity
  name                              = "agw-shared-${local.configure_connectivity_resources.location}-001"
  resource_group_name               = [for v in azurerm_resource_group.virtual_wan : v.name][0]
  location                          = local.configure_connectivity_resources.location
  force_firewall_policy_association = true
  firewall_policy_id                = azurerm_web_application_firewall_policy.waf_agw_policies.id
  waf_configuration {
    enabled                  = false
    file_upload_limit_mb     = 100
    firewall_mode            = "Detection"
    max_request_body_size_kb = 128
    request_body_check       = true
    rule_set_type            = "OWASP"
    rule_set_version         = "3.2"
  }

  sku {
    name = "WAF_v2"
    tier = "WAF_v2"
  }

  autoscale_configuration {
    min_capacity = 0
    max_capacity = 5
  }

  gateway_ip_configuration {
    name      = "config-agw-${local.configure_connectivity_resources.location}-001"
    subnet_id = azurerm_subnet.shared_service_subnet["agw_fe"].id
  }

  frontend_port {
    name = "port-agw_fe-${local.configure_connectivity_resources.location}-001"
    port = 80
  }

  frontend_ip_configuration {
    name                 = "config-agw_fe-${local.configure_connectivity_resources.location}-001"
    public_ip_address_id = azurerm_public_ip.pip_agw.id
  }

  backend_address_pool {
    name = "pool-agw_be-${local.configure_connectivity_resources.location}-001"
  }

  backend_http_settings {
    name                  = "config-agw_be-${local.configure_connectivity_resources.location}-001"
    cookie_based_affinity = "Disabled"
    port                  = 80
    protocol              = "Http"
    request_timeout       = 60
  }

  http_listener {
    name                           = "listener-agw_fe-${local.configure_connectivity_resources.location}-001"
    frontend_ip_configuration_name = "config-agw_fe-${local.configure_connectivity_resources.location}-001"
    frontend_port_name             = "port-agw_fe-${local.configure_connectivity_resources.location}-001"
    protocol                       = "Http"
  }

  request_routing_rule {
    name                       = "rule-agw-${local.configure_connectivity_resources.location}-001"
    rule_type                  = "Basic"
    http_listener_name         = "listener-agw_fe-${local.configure_connectivity_resources.location}-001"
    backend_address_pool_name  = "pool-agw_be-${local.configure_connectivity_resources.location}-001"
    backend_http_settings_name = "config-agw_be-${local.configure_connectivity_resources.location}-001"
    priority                   = 1001
  }

  tags = local.configure_connectivity_resources.tags

  depends_on = [
    azurerm_resource_group.connectivity,
    azurerm_resource_group.virtual_wan,
    azurerm_virtual_network.shared_service_vnet,
    azurerm_subnet.shared_service_subnet,
    azurerm_web_application_firewall_policy.waf_agw_policies
  ]
}

output "name" {

  value = azurerm_subnet.shared_service_subnet["agw_fe"].name
}
