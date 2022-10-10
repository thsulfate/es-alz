resource "azurerm_resource_group" "management" {
  for_each = local.azurerm_resource_group_management

  provider = azurerm.management

  # Mandatory resource attributes
  name     = each.value.template.name
  location = each.value.template.location
  tags     = each.value.template.tags
}

resource "azurerm_log_analytics_workspace" "management" {
  for_each = local.azurerm_log_analytics_workspace_management

  provider = azurerm.management

  # Mandatory resource attributes
  name                = each.value.template.name
  location            = each.value.template.location
  resource_group_name = each.value.template.resource_group_name

  # Optional resource attributes
  sku                        = each.value.template.sku
  retention_in_days          = each.value.template.retention_in_days
  daily_quota_gb             = each.value.template.daily_quota_gb
  internet_ingestion_enabled = each.value.template.internet_ingestion_enabled
  internet_query_enabled     = each.value.template.internet_query_enabled
  tags                       = each.value.template.tags

  # Optional resource attributes (removed for backward
  # compatibility with older azurerm provider versions,
  # as not currently used by Enterprise-scale)/
  # Requires version = "~> 2.48.0"
  # reservation_capcity_in_gb_per_day = each.value.template.reservation_capcity_in_gb_per_day

  # Set explicit dependency on Resource Group deployment
  depends_on = [
    azurerm_resource_group.management,
  ]

}

resource "azurerm_log_analytics_solution" "management" {
  for_each = local.azurerm_log_analytics_solution_management

  provider = azurerm.management

  # Mandatory resource attributes
  solution_name         = each.value.template.solution_name
  location              = each.value.template.location
  resource_group_name   = each.value.template.resource_group_name
  workspace_resource_id = each.value.template.workspace_resource_id
  workspace_name        = each.value.template.workspace_name

  plan {
    publisher = each.value.template.plan.publisher
    product   = each.value.template.plan.product
  }

  # Optional resource attributes
  tags = each.value.template.tags

  # Set explicit dependency on Resource Group, Log Analytics
  # workspace and Automation Account to fix issue #109.
  # Ideally we would limit to specific solutions, but the
  # depends_on block only supports static values.
  depends_on = [
    azurerm_resource_group.management,
    azurerm_log_analytics_workspace.management,
    azurerm_automation_account.management,
    azurerm_log_analytics_linked_service.management,
  ]

}

resource "azurerm_automation_account" "management" {
  for_each = local.azurerm_automation_account_management

  provider = azurerm.management

  # Mandatory resource attributes
  name                = each.value.template.name
  location            = each.value.template.location
  resource_group_name = each.value.template.resource_group_name

  # Optional resource attributes
  sku_name = each.value.template.sku_name
  tags     = each.value.template.tags

  # Dynamic configuration blocks
  # Identity block
  dynamic "identity" {
    for_each = each.value.template.identity
    content {
      type = identity.value.type
      # Optional attributes
      identity_ids = lookup(identity.value, "identity_ids", null)
    }
  }

  # Set explicit dependency on Resource Group deployment
  depends_on = [
    azurerm_resource_group.management,
  ]

}

resource "azurerm_log_analytics_linked_service" "management" {
  for_each = local.azurerm_log_analytics_linked_service_management

  provider = azurerm.management

  # Mandatory resource attributes
  resource_group_name = each.value.template.resource_group_name
  workspace_id        = each.value.template.workspace_id

  # Optional resource attributes
  read_access_id  = each.value.template.read_access_id
  write_access_id = each.value.template.write_access_id

  # Set explicit dependency on Resource Group, Log Analytics workspace and Automation Account deployments
  depends_on = [
    azurerm_resource_group.management,
    azurerm_log_analytics_workspace.management,
    azurerm_automation_account.management,
  ]

}
resource "azurerm_monitor_aad_diagnostic_setting" "aad_logging" {
  for_each                   = azurerm_log_analytics_workspace.management
  provider                   = azurerm.management
  name                       = "AAD Log Workspace"
  log_analytics_workspace_id = each.value.id
  log {
    category = "SignInLogs"
    enabled  = true
    retention_policy {
      enabled = true
      days    = local.configure_management_resources.settings.log_analytics.config.retention_in_days
    }
  }
  log {
    category = "B2CRequestLogs"
    enabled  = false
    retention_policy {
    }
  }
  log {
    category = "AuditLogs"
    enabled  = true
    retention_policy {
      enabled = true
      days    = local.configure_management_resources.settings.log_analytics.config.retention_in_days
    }
  }
  log {
    category = "NonInteractiveUserSignInLogs"
    enabled  = true
    retention_policy {
      enabled = true
      days    = local.configure_management_resources.settings.log_analytics.config.retention_in_days
    }
  }
  log {
    category = "ServicePrincipalSignInLogs"
    enabled  = true
    retention_policy {
      enabled = true
      days    = local.configure_management_resources.settings.log_analytics.config.retention_in_days
    }
  }
  log {
    category = "ManagedIdentitySignInLogs"
    enabled  = false
    retention_policy {}
  }
  log {
    category = "ProvisioningLogs"
    enabled  = false
    retention_policy {}
  }
  log {
    category = "ADFSSignInLogs"
    enabled  = true
    retention_policy {
      enabled = true
      days    = local.configure_management_resources.settings.log_analytics.config.retention_in_days
    }
  }
  log {
    category = "NetworkAccessTrafficLogs"
    enabled  = false

    retention_policy {
    }
  }
  log {
    category = "RiskyServicePrincipals"
    enabled  = false

    retention_policy {
    }
  }
  log {
    category = "RiskyUsers"
    enabled  = false

    retention_policy {
    }
  }
  log {
    category = "ServicePrincipalRiskEvents"
    enabled  = false

    retention_policy {
    }
  }
  log {
    category = "UserRiskEvents"
    enabled  = false

    retention_policy {
    }
  }

  depends_on = [
    azurerm_resource_group.management,
    azurerm_log_analytics_workspace.management
  ]
}

resource "azurerm_monitor_action_group" "global_admin_alert" {
  provider            = azurerm.management
  name                = "GlobalAdminAlert"
  resource_group_name = [for v in azurerm_resource_group.management : v.name][0]
  short_name          = "adminalert"
  enabled             = false

  email_receiver {
    name                    = "sendtoadmin"
    email_address           = "thio@ysi.co.id"
    use_common_alert_schema = true
  }

  email_receiver {
    name                    = "sendtospv"
    email_address           = "andik@ysi.co.id"
    use_common_alert_schema = true
  }

  depends_on = [
    azurerm_resource_group.management
  ]
}

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "global_admin_login_query" {
  provider            = azurerm.management
  name                = "query-login-global-admin"
  resource_group_name = [for v in azurerm_resource_group.management : v.name][0]
  location            = local.configure_management_resources.location
  enabled             = false

  evaluation_frequency = "PT1M"
  window_duration      = "PT1M"
  scopes               = [for v in azurerm_log_analytics_workspace.management : v.id]
  severity             = 4
  criteria {
    query                   = <<-QUERY
      SigninLogs
        | project UserPrincipalName 
        | where UserPrincipalName == "thio@ysi.co.id"
      QUERY
    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    # resource_id_column    = "client_CountryOrRegion"
    # metric_measure_column = "CountByCountry"
    # dimension {
    #   name     = "client_CountryOrRegion"
    #   operator = "Exclude"
    #   values   = ["123"]
    # }
    # failing_periods {
    #   minimum_failing_periods_to_trigger_alert = 1
    #   number_of_evaluation_periods             = 1
    # }
  }

  # auto_mitigation_enabled          = true
  # workspace_alerts_storage_enabled = false
  description  = "Alerting Administrator when Abuse of Global Administrator Detected"
  display_name = "Global Administrator Login Abuse"
  # query_time_range_override        = "PT1H"
  # skip_query_validation            = true
  action {
    action_groups = [azurerm_monitor_action_group.global_admin_alert.id]
  }

  depends_on = [
    azurerm_resource_group.management,
    azurerm_monitor_action_group.global_admin_alert
  ]
}


resource "azurerm_data_protection_backup_vault" "backup_vault" {
  provider            = azurerm.management
  name                = "bsv-${local.configure_management_resources.location}-001"
  resource_group_name = [for v in azurerm_resource_group.management : v.name][0]
  location            = local.configure_management_resources.location
  datastore_type      = "VaultStore"
  redundancy          = "LocallyRedundant"
  tags                = local.configure_management_resources.tags
  depends_on = [
    azurerm_resource_group.management
  ]
}

resource "azurerm_recovery_services_vault" "site_recovery_vault" {
  provider            = azurerm.management
  name                = "rsv-${local.configure_management_resources.location}-001"
  location            = local.configure_management_resources.location
  resource_group_name = [for v in azurerm_resource_group.management : v.name][0]
  sku                 = "Standard"
  tags                = local.configure_management_resources.tags
  depends_on = [
    azurerm_resource_group.management
  ]
}

resource "azurerm_storage_account" "backup_storage" {
  provider                 = azurerm.management
  name                     = "backupst01"
  resource_group_name      = [for v in azurerm_resource_group.management : v.name][0]
  location                 = local.configure_management_resources.location
  account_tier             = "Standard"
  account_replication_type = "GRS"
  tags                     = local.configure_management_resources.tags
  depends_on = [
    azurerm_resource_group.management
  ]
}

data "azurerm_client_config" "current" {}

locals {
  kv-key-permissions-full = ["Backup", "Create", "Decrypt", "Delete", "Encrypt", "Get", "Import", "List", "Purge",
  "Recover", "Restore", "Sign", "UnwrapKey", "Update", "Verify", "WrapKey"]
  kv-secret-permissions-full = ["Backup", "Delete", "Get", "List", "Purge", "Recover", "Restore", "Set"]
  kv-certificate-permissions-full = ["Create", "Delete", "DeleteIssuers", "Get", "GetIssuers", "Import", "List", "ListIssuers",
  "ManageContacts", "ManageIssuers", "Purge", "Recover", "SetIssuers", "Update", "Backup", "Restore"]
  kv-storage-permissions-full = ["Backup", "Delete", "DeleteSAS", "Get", "GetSAS", "List", "ListSAS",
  "Purge", "Recover", "RegenerateKey", "Restore", "Set", "SetSAS", "Update"]
  kv-key-permissions-read         = ["Get", "List"]
  kv-secret-permissions-read      = ["Get", "List"]
  kv-certificate-permissions-read = ["Get", "GetIssuers", "List", "ListIssuers"]
  kv-storage-permissions-read     = ["Get", "GetSAS", "List", "ListSAS"]
}

# Create the Azure Key Vault
resource "azurerm_key_vault" "key-vault" {
  provider                   = azurerm.management
  name                       = "kv-mgmt-demo-001"
  location                   = local.configure_management_resources.location
  resource_group_name        = [for v in azurerm_resource_group.management : v.name][0]
  soft_delete_retention_days = 7
  purge_protection_enabled   = false

  enabled_for_deployment          = true
  enabled_for_disk_encryption     = true
  enabled_for_template_deployment = true

  tenant_id = data.azurerm_client_config.current.tenant_id
  sku_name  = "standard"
  tags      = local.configure_management_resources.tags

  network_acls {
    default_action = "Allow"
    bypass         = "AzureServices"
  }
  depends_on = [
    azurerm_resource_group.management
  ]
}

# Create a Default Azure Key Vault access policy with Admin permissions
# This policy must be kept for a proper run of the "destroy" process
resource "azurerm_key_vault_access_policy" "default_policy" {
  provider     = azurerm.management
  key_vault_id = azurerm_key_vault.key-vault.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = data.azurerm_client_config.current.object_id

  lifecycle {
    create_before_destroy = true
  }

  key_permissions         = local.kv-key-permissions-full
  secret_permissions      = local.kv-secret-permissions-full
  certificate_permissions = local.kv-certificate-permissions-full
  storage_permissions     = local.kv-storage-permissions-full
  depends_on = [
    azurerm_resource_group.management,
    azurerm_key_vault.key-vault
  ]
}
