"""Guidance for the Azure posture rules (AZ-*), including the shared "family" rules that repeat across
resource types (minimum TLS, public access behind a private endpoint, App Service vs Function app)."""
from __future__ import annotations

from typing import Any

from .common import g

GUIDANCE: dict[str, dict[str, Any]] = {}


# ----------------------------------------------------------------------------- families
def _pe_public(rid: str, what: str, *, score: float, show: str, console: str, cli: str, tf: str,
               docs: list[str | tuple[str, str]]) -> None:
    GUIDANCE[rid] = g(
        score, 668, ["T1190", "T1530"],
        [("Private endpoint is bypassed", f"The {what} has a private endpoint, so the team believes it is private, but its public "
                                          "endpoint still answers. Anyone on the internet can reach it, limited only by its firewall and credentials."),
         ("False sense of security", "Network reviews that look at the private endpoint miss the open public path; attackers scan "
                                     "public endpoints continuously."),
         ("Credential attacks stay possible", "Leaked keys, tokens or passwords work from anywhere while public access is on.")],
        [f"Open the {what} and find its networking / firewall settings.",
         "Check that public network access is Enabled while a private endpoint connection is Approved.",
         "Confirm which clients still use the public hostname before disabling it (check the resource's metrics or logs)."],
        show,
        [console, "Move every client to the private endpoint (private DNS zone linked to the client VNet) first.",
         "Set public network access to Disabled and save; test a client from inside the VNet."],
        cli, tf,
        "Create the resource with public network access disabled and add a policy that denies public network access on new resources.",
        ["az-pe", "mcsb", *docs])


def _tls(rid: str, what: str, *, show: str, console: str, cli: str, tf: str, docs: list[str | tuple[str, str]],
         score: float = 5.3) -> None:
    GUIDANCE[rid] = g(
        score, 326, ["T1557", "T1040"],
        [("Weak protocol versions accepted", f"The {what} still lets clients negotiate TLS 1.0 or 1.1, which have known cryptographic weaknesses."),
         ("Downgrade and interception", "A network attacker can push a connection down to a weak version and read or alter traffic."),
         ("Compliance finding", "Most standards (PCI DSS, CIS, MCSB) require TLS 1.2 or newer.")],
        [f"Open the {what} and find the minimum TLS version setting.",
         "Confirm it is lower than 1.2 (or unset).",
         "Check that no legacy client still depends on TLS 1.0/1.1 before raising it (connection logs show the TLS version)."],
        show, [console, "Set the minimum TLS version to 1.2 and save.", "Re-test the application connections."],
        cli, tf, "Set the minimum TLS version to 1.2 in your templates and enforce it with an Azure Policy that audits or denies older values.",
        ["mcsb", *docs])


# ----------------------------------------------------------------------------- storage
GUIDANCE["AZ-STG-001"] = g(
    8.2, 284, ["T1530"],
    [("Data readable without credentials", "Anonymous read access lets anyone who knows or guesses a container URL download its blobs."),
     ("Breach and disclosure risk", "Public storage accounts are a common cause of data leaks; automated scanners search for them."),
     ("Hard to see later", "A single container set to Blob or Container access level can expose data long after the account setting was changed.")],
    ["Open the storage account, then Settings > Configuration.", "Check 'Allow Blob anonymous access' is Enabled.",
     "Open Containers and list any whose public access level is not Private."],
    "az storage account show -n <name> -g <rg> --query allowBlobPublicAccess",
    ["Open the storage account in the Azure portal.", "Go to Settings > Configuration.",
     "Set 'Allow Blob anonymous access' to Disabled and select Save.",
     "First set any container that must stay public to a separate, dedicated account or serve it through a CDN with SAS tokens."],
    "az storage account update -n <name> -g <rg> --allow-blob-public-access false",
    'resource "azurerm_storage_account" "this" {\n  name                            = "<name>"\n  resource_group_name             = "<rg>"\n'
    '  location                        = "<region>"\n  account_tier                    = "Standard"\n  account_replication_type        = "GRS"\n'
    '  allow_nested_items_to_be_public = false\n}',
    "Deny storage accounts with anonymous blob access using the built-in Azure Policy 'Storage account public access should be disallowed' (audit or deny effect).",
    ["az-stg-pub", "cis-azure", "mcsb"])

GUIDANCE["AZ-STG-002"] = g(
    5.9, 319, ["T1557", "T1040"],
    [("Cleartext transfer", "Requests over plain HTTP are accepted, so data and SAS tokens can cross the network unencrypted."),
     ("Token theft", "A SAS token or key sent over HTTP can be captured and replayed by anyone on the path."),
     ("Easy to fix", "Almost every modern client supports HTTPS; the setting rarely breaks anything.")],
    ["Open the storage account > Settings > Configuration.", "Check 'Secure transfer required' is Disabled."],
    "az storage account show -n <name> -g <rg> --query enableHttpsTrafficOnly",
    ["Open the storage account in the Azure portal.", "Go to Settings > Configuration.",
     "Set 'Secure transfer required' to Enabled and select Save.", "Update any client that still uses http:// URLs."],
    "az storage account update -n <name> -g <rg> --https-only true",
    'resource "azurerm_storage_account" "this" {\n  name                      = "<name>"\n  resource_group_name       = "<rg>"\n  location                  = "<region>"\n'
    '  account_tier              = "Standard"\n  account_replication_type  = "GRS"\n  https_traffic_only_enabled = true # azurerm 4.x; "enable_https_traffic_only" in 3.x\n}',
    "Enforce the built-in Azure Policy 'Secure transfer to storage accounts should be enabled' with the deny effect.",
    ["az-stg-https", "cis-azure"])

_tls("AZ-STG-003", "storage account", show="az storage account show -n <name> -g <rg> --query minimumTlsVersion",
     console="Open the storage account > Settings > Configuration and set 'Minimum TLS version' to Version 1.2.",
     cli="az storage account update -n <name> -g <rg> --min-tls-version TLS1_2",
     tf='resource "azurerm_storage_account" "this" {\n  name                = "<name>"\n  resource_group_name = "<rg>"\n  location            = "<region>"\n'
        '  account_tier        = "Standard"\n  account_replication_type = "GRS"\n  min_tls_version     = "TLS1_2"\n}',
     docs=["az-stg-tls"])

_pe_public("AZ-STG-004", "storage account", score=5.3,
           show="az storage account show -n <name> -g <rg> --query \"{public:publicNetworkAccess, default:networkRuleSet.defaultAction}\"",
           console="Open the storage account > Security + networking > Networking and review 'Public network access'.",
           cli="az storage account update -n <name> -g <rg> --public-network-access Disabled",
           tf='resource "azurerm_storage_account" "this" {\n  name                          = "<name>"\n  resource_group_name           = "<rg>"\n'
              '  location                      = "<region>"\n  account_tier                  = "Standard"\n  account_replication_type      = "GRS"\n'
              '  public_network_access_enabled = false\n}',
           docs=["az-stg-fw"])

# ----------------------------------------------------------------------------- NSG
_NSG_CONSOLE_TAIL = ["Use Azure Bastion, just-in-time VM access or a VPN for administration instead of an open inbound rule."]
_NSG_TF = ('resource "azurerm_network_security_rule" "ssh" {\n  name                        = "allow-ssh-from-corp"\n  priority                    = 200\n'
           '  direction                   = "Inbound"\n  access                      = "Allow"\n  protocol                    = "Tcp"\n'
           '  source_port_range           = "*"\n  destination_port_range      = "%s"\n'
           '  source_address_prefix       = "203.0.113.0/24" # your trusted range, never "*" or "Internet"\n'
           '  destination_address_prefix  = "*"\n  resource_group_name         = "<rg>"\n  network_security_group_name = "<name>"\n}')

GUIDANCE["AZ-NSG-001"] = g(
    8.1, 284, ["T1133", "T1021.004", "T1110"],
    [("SSH reachable from anywhere", "Any host on the internet can attempt to log in to every VM behind this NSG on TCP 22."),
     ("Constant brute-force traffic", "Open SSH is found within minutes and hit with password guessing and exploit attempts."),
     ("Foothold for lateral movement", "A compromised VM gives an attacker an internal position to reach databases and other workloads.")],
    ["Open the NSG > Settings > Inbound security rules.", "Find the Allow rule whose source is Any / Internet / 0.0.0.0/0 and port is 22 or *.",
     "Note which subnets and NICs the NSG is attached to."],
    "az network nsg rule list -g <rg> --nsg-name <name> --query \"[?access=='Allow' && direction=='Inbound']\" -o table",
    ["Open the NSG in the Azure portal > Inbound security rules.", "Edit the offending rule and replace the source with your corporate IP range or a service tag you trust, or delete it.",
     *_NSG_CONSOLE_TAIL],
    "az network nsg rule update -g <rg> --nsg-name <name> -n <rule-name> --source-address-prefixes 203.0.113.0/24\n"
    "# or remove the rule entirely:\naz network nsg rule delete -g <rg> --nsg-name <name> -n <rule-name>",
    _NSG_TF % "22",
    "Add an Azure Policy / pipeline check that rejects NSG rules allowing 22, 3389 or * from Internet, and give admins Bastion or JIT instead.",
    ["az-nsg", "az-bastion", "az-jit", "cis-azure"])

GUIDANCE["AZ-NSG-002"] = g(
    8.1, 284, ["T1133", "T1021.001", "T1110"],
    [("RDP reachable from anywhere", "Any host on the internet can attempt to sign in over Remote Desktop on TCP 3389."),
     ("Ransomware entry point", "Exposed RDP, with weak or stolen credentials or an unpatched flaw, is a leading ransomware entry path."),
     ("Credential stuffing", "Leaked passwords are replayed against open RDP endpoints around the clock.")],
    ["Open the NSG > Settings > Inbound security rules.", "Find the Allow rule with source Any / Internet / 0.0.0.0/0 and port 3389 or *.",
     "Check which VMs sit behind the NSG."],
    "az network nsg rule list -g <rg> --nsg-name <name> --query \"[?access=='Allow' && direction=='Inbound']\" -o table",
    ["Open the NSG in the Azure portal > Inbound security rules.", "Edit the rule: replace the source with a trusted corporate range or delete it.",
     *_NSG_CONSOLE_TAIL],
    "az network nsg rule update -g <rg> --nsg-name <name> -n <rule-name> --source-address-prefixes 203.0.113.0/24\n"
    "# or remove the rule entirely:\naz network nsg rule delete -g <rg> --nsg-name <name> -n <rule-name>",
    _NSG_TF % "3389",
    "Block internet-sourced 3389 with an Azure Policy or pipeline check and use Bastion or JIT access for administration.",
    ["az-nsg", "az-bastion", "az-jit", "cis-azure"])

GUIDANCE["AZ-NSG-003"] = g(
    9.6, 284, ["T1133", "T1190", "T1110"],
    [("Every port is open", "All ports on every VM behind this NSG are reachable from the internet, including databases, admin consoles and management protocols."),
     ("Defence by NSG is gone", "The NSG no longer filters anything, so the only protection left is each service's own authentication."),
     ("Rapid exploitation", "Mass scanners find fully open hosts quickly and try known exploits against every service.")],
    ["Open the NSG > Inbound security rules.", "Find the Allow rule with source Any/Internet and destination port range *.",
     "List the workloads in the attached subnets and the ports they really need."],
    "az network nsg rule list -g <rg> --nsg-name <name> --query \"[?access=='Allow' && direction=='Inbound' && destinationPortRange=='*']\" -o table",
    ["Open the NSG in the Azure portal > Inbound security rules.", "Delete the allow-all rule (or change its source to a trusted range and its ports to the ones needed).",
     "Add narrow allow rules for the specific ports that must be reachable.", *_NSG_CONSOLE_TAIL],
    "az network nsg rule delete -g <rg> --nsg-name <name> -n <rule-name>",
    '# remove the rule from the azurerm_network_security_group, and allow only what is needed:\nresource "azurerm_network_security_rule" "https" {\n'
    '  name                        = "allow-https"\n  priority                    = 200\n  direction                   = "Inbound"\n  access                      = "Allow"\n'
    '  protocol                    = "Tcp"\n  source_port_range           = "*"\n  destination_port_range      = "443"\n'
    '  source_address_prefix       = "Internet"\n  destination_address_prefix  = "<load-balancer-or-app-subnet-prefix>"\n'
    '  resource_group_name         = "<rg>"\n  network_security_group_name = "<name>"\n}',
    "Reject allow-all inbound rules in code review and with a deny policy; start from the NSG default deny and add only what is required.",
    ["az-nsg", "cis-azure", "mcsb"])

GUIDANCE["AZ-NSG-004"] = g(
    3.7, 284, ["T1133", "T1021"],
    [("Management ports exposed to some public addresses", "SSH, RDP or WinRM is reachable from specific public (non-private) address ranges rather than the whole internet."),
     ("Depends on those networks", "If a listed range is shared, reassigned or compromised, it becomes a path in."),
     ("Lower risk than open-to-all", "The exposure is narrower, but a VPN, Bastion or JIT access is still safer than public allow-lists.")],
    ["Open the NSG > Inbound security rules.", "Review the source ranges on the rules that open 22, 3389 or 5985/5986.",
     "Confirm each range is a network you control and still need."],
    "az network nsg rule list -g <rg> --nsg-name <name> --query \"[?access=='Allow' && direction=='Inbound']\" -o table",
    ["Open the NSG > Inbound security rules.", "Remove ranges you no longer control, or replace the rule with Bastion / VPN access.",
     *_NSG_CONSOLE_TAIL],
    "az network nsg rule update -g <rg> --nsg-name <name> -n <rule-name> --source-address-prefixes <trusted-cidr>",
    _NSG_TF % "22",
    "Review allow-listed public ranges on a schedule and prefer private access (VPN, Bastion, JIT) for administration.",
    ["az-nsg", "az-bastion", "az-jit", "cis-azure"])

# ----------------------------------------------------------------------------- VM / VMSS
GUIDANCE["AZ-VM-001"] = g(
    5.4, 668, ["T1133", "T1190"],
    [("Direct internet exposure", "The VM has its own public IP, so it is reachable from the internet whenever an NSG allows traffic."),
     ("Larger attack surface", "Every listening service and every NSG mistake becomes an internet-facing risk."),
     ("Bypasses central controls", "Traffic does not pass through a firewall, load balancer or WAF.")],
    ["Open the VM > Networking.", "Check the network interface for an attached public IP address.",
     "Decide whether the VM must be directly reachable."],
    "az vm list-ip-addresses -g <rg> -n <name> -o table",
    ["Open the VM > Networking > network interface > IP configurations.", "Set Public IP address to Disabled / dissociate it, then delete the unused public IP resource.",
     "Publish the service through Application Gateway, Front Door or a load balancer, and use Bastion for administration."],
    "az network nic ip-config update -g <rg> --nic-name <nic-name> -n <ip-config-name> --remove publicIpAddress\naz network public-ip delete -g <rg> -n <public-ip-name>",
    '# in azurerm_network_interface, remove the public_ip_address_id argument from ip_configuration\nresource "azurerm_network_interface" "this" {\n'
    '  name                = "<nic-name>"\n  location            = "<region>"\n  resource_group_name = "<rg>"\n  ip_configuration {\n'
    '    name                          = "internal"\n    subnet_id                     = azurerm_subnet.this.id\n    private_ip_address_allocation = "Dynamic"\n  }\n}',
    "Deny public IP creation on NICs outside a designated perimeter subscription with an Azure Policy (for example 'Network interfaces should not have public IPs').",
    ["az-vm-pip", "az-bastion", "mcsb", "cis-azure"])

GUIDANCE["AZ-VM-002"] = g(
    5.5, 311, ["T1530"],
    [("Disks readable if copied", "Without host or customer-managed encryption, a leaked snapshot or disk export is readable."),
     ("Compliance gap", "Many frameworks require encryption at rest with controls you manage."),
     ("Platform encryption is not enough here", "Server-side encryption with platform keys is always on, but this rule asks for ADE, encryption at host or a CMK.")],
    ["Open the VM > Disks.", "Check the 'Encryption' column and the VM's Security settings (encryption at host).",
     "Check whether the disks use a disk encryption set (customer-managed key)."],
    "az vm show -g <rg> -n <name> --query \"{host:securityProfile.encryptionAtHost, os:storageProfile.osDisk.encryptionSettings}\"",
    ["Enable the EncryptionAtHost feature on the subscription if needed (Microsoft.Compute).", "Stop (deallocate) the VM.",
     "Open the VM > Disks > Additional settings and enable 'Encryption at host', or choose a disk encryption set for each disk.", "Start the VM."],
    "az vm deallocate -g <rg> -n <name>\naz vm update -g <rg> -n <name> --set securityProfile.encryptionAtHost=true\naz vm start -g <rg> -n <name>",
    'resource "azurerm_linux_virtual_machine" "this" {\n  name                = "<name>"\n  resource_group_name = "<rg>"\n  location            = "<region>"\n'
    '  encryption_at_host_enabled = true\n  # ... size, admin credentials, network_interface_ids, os_disk, source_image_reference\n}',
    "Require encryption at host or a disk encryption set in your VM modules and audit with the built-in 'Virtual machines and virtual machine scale sets should have encryption at host enabled' policy.",
    ["az-vm-enc", "cis-azure", "mcsb"])

GUIDANCE["AZ-VMSS-001"] = g(
    5.4, 668, ["T1133", "T1190"],
    [("Every instance is internet-facing", "Each scale-set instance gets its own public IP, multiplying the exposed surface as the set grows."),
     ("Bypasses the load balancer", "Traffic can hit instances directly and skip WAF or filtering."),
     ("Hard to audit", "Instances appear and disappear, so exposure changes with every scale event.")],
    ["Open the scale set > Networking and inspect the network interface configuration.",
     "Check whether 'Public IP address per instance' is set."],
    "az vmss show -g <rg> -n <name> --query \"virtualMachineProfile.networkProfile.networkInterfaceConfigurations[].ipConfigurations[].publicIPAddressConfiguration\"",
    ["Open the scale set > Networking and edit the network interface.", "Remove the per-instance public IP configuration.",
     "Front the set with a public load balancer or Application Gateway and use Bastion for administration."],
    "az vmss update -g <rg> -n <name> --remove virtualMachineProfile.networkProfile.networkInterfaceConfigurations[0].ipConfigurations[0].publicIPAddressConfiguration",
    '# in azurerm_linux_virtual_machine_scale_set, delete the public_ip_address block inside network_interface.ip_configuration\n'
    'resource "azurerm_linux_virtual_machine_scale_set" "this" {\n  name                = "<name>"\n  resource_group_name = "<rg>"\n  location            = "<region>"\n'
    '  # network_interface { ip_configuration { name = "internal" primary = true subnet_id = azurerm_subnet.this.id } }\n}',
    "Policy-deny public IP configurations on scale sets and expose them only behind a load balancer.",
    ["az-vm-pip", "mcsb", "cis-azure"])

GUIDANCE["AZ-VMSS-002"] = g(
    5.5, 311, ["T1530"],
    [("Disks readable if copied", "Instance disks lack host-level or customer-managed encryption."),
     ("Compliance gap", "Standards commonly require encryption at rest with keys you control."),
     ("Applies to every instance", "New instances inherit the model, so the gap grows with scale.")],
    ["Open the scale set > Disks and check encryption.", "Check securityProfile.encryptionAtHost in the scale set model."],
    "az vmss show -g <rg> -n <name> --query virtualMachineProfile.securityProfile.encryptionAtHost",
    ["Open the scale set > Disks > Additional settings.", "Enable 'Encryption at host' (register the EncryptionAtHost feature first) or select a disk encryption set.",
     "Roll the change out to existing instances (upgrade instances)."],
    "az vmss update -g <rg> -n <name> --set virtualMachineProfile.securityProfile.encryptionAtHost=true\naz vmss update-instances -g <rg> -n <name> --instance-ids '*'",
    'resource "azurerm_linux_virtual_machine_scale_set" "this" {\n  name                       = "<name>"\n  resource_group_name        = "<rg>"\n  location                   = "<region>"\n'
    '  encryption_at_host_enabled = true\n  # ... sku, instances, admin settings, network_interface, os_disk\n}',
    "Bake encryption at host into your scale-set module and audit it with Azure Policy.",
    ["az-vm-enc", "cis-azure", "mcsb"])

# ----------------------------------------------------------------------------- SQL
GUIDANCE["AZ-SQL-001"] = g(
    5.6, 668, ["T1190", "T1110"],
    [("Database reachable from the internet", "The SQL server accepts connections from public networks, limited only by firewall rules and credentials."),
     ("Credential attacks", "Public SQL endpoints receive constant password-guessing traffic."),
     ("Sensitive data nearby", "SQL servers usually hold customer or business data.")],
    ["Open the SQL server > Security > Networking.", "Check 'Public network access' is Selected networks or Enabled."],
    "az sql server show -g <rg> -n <name> --query publicNetworkAccess",
    ["Open the SQL server > Security > Networking.", "Create a private endpoint for the VNet that needs access.",
     "Set 'Public network access' to Disable and save."],
    "az sql server update -g <rg> -n <name> --enable-public-network false",
    'resource "azurerm_mssql_server" "this" {\n  name                          = "<name>"\n  resource_group_name           = "<rg>"\n  location                      = "<region>"\n'
    '  version                       = "12.0"\n  public_network_access_enabled = false\n  minimum_tls_version           = "1.2"\n}',
    "Deny SQL servers with public network access using the built-in policy 'Public network access on Azure SQL Database should be disabled'.",
    ["az-sql-net", "cis-azure", "mcsb"])

GUIDANCE["AZ-SQL-002"] = g(
    5.0, 778, ["T1562.008"],
    [("No audit trail", "Without server auditing there is no record of who connected or what queries ran."),
     ("Incidents are hard to investigate", "A data theft or privilege abuse cannot be reconstructed."),
     ("Compliance", "PCI DSS, ISO 27001 and similar require database access logging.")],
    ["Open the SQL server > Security > Auditing.", "Check Auditing is Off."],
    "az sql server audit-policy show -g <rg> -n <name> --query state",
    ["Open the SQL server > Security > Auditing.", "Switch Auditing to On.", "Choose at least one destination: a Log Analytics workspace, a storage account or an Event Hub.", "Save."],
    "az sql server audit-policy update -g <rg> -n <name> --state Enabled --lats Enabled --lawri <log-analytics-workspace-resource-id>",
    'resource "azurerm_mssql_server_extended_auditing_policy" "this" {\n  server_id              = azurerm_mssql_server.this.id\n  log_monitoring_enabled = true # send to Log Analytics via diagnostic settings\n  retention_in_days      = 90\n}',
    "Enable auditing in the SQL server module and audit it with the built-in policy 'Auditing on SQL server should be enabled'.",
    [("Auditing for Azure SQL Database and Azure Synapse Analytics", "https://learn.microsoft.com/azure/azure-sql/database/auditing-overview"), "cis-azure", "mcsb"])

GUIDANCE["AZ-SQL-003"] = g(
    9.1, 284, ["T1190", "T1110"],
    [("Whole internet allowed", "A firewall rule covering 0.0.0.0 to 255.255.255.255 lets every IPv4 address reach the SQL server."),
     ("Direct data theft risk", "Anyone with a valid or guessed login, or an exploit, can reach your data."),
     ("Defeats the firewall", "The server firewall provides no filtering at all.")],
    ["Open the SQL server > Security > Networking > Firewall rules.", "Find the rule whose start IP is 0.0.0.0 and end IP is 255.255.255.255."],
    "az sql server firewall-rule list -g <rg> -s <name> -o table",
    ["Open the SQL server > Security > Networking.", "Delete the 0.0.0.0-255.255.255.255 rule.", "Add rules only for known client IPs, or switch to a private endpoint."],
    "az sql server firewall-rule delete -g <rg> -s <name> -n <rule-name>",
    '# remove the azurerm_mssql_firewall_rule that spans 0.0.0.0 - 255.255.255.255, e.g.:\nresource "azurerm_mssql_firewall_rule" "office" {\n'
    '  name             = "office"\n  server_id        = azurerm_mssql_server.this.id\n  start_ip_address = "203.0.113.10"\n  end_ip_address   = "203.0.113.10"\n}',
    "Review firewall rules in pull requests, forbid full-range rules in code and prefer private endpoints.",
    ["az-sql-net", "cis-azure", "mcsb"])

_pe_public("AZ-SQL-004", "SQL server", score=5.3,
           show="az sql server show -g <rg> -n <name> --query publicNetworkAccess",
           console="Open the SQL server > Security > Networking and review 'Public network access'.",
           cli="az sql server update -g <rg> -n <name> --enable-public-network false",
           tf='resource "azurerm_mssql_server" "this" {\n  name                          = "<name>"\n  resource_group_name           = "<rg>"\n  location                      = "<region>"\n'
              '  version                       = "12.0"\n  public_network_access_enabled = false\n}',
           docs=["az-sql-net"])

_tls("AZ-SQL-005", "SQL server", show="az sql server show -g <rg> -n <name> --query minimalTlsVersion",
     console="Open the SQL server > Security > Networking > Connectivity and set 'Minimum TLS version' to 1.2.",
     cli="az sql server update -g <rg> -n <name> --minimal-tls-version 1.2",
     tf='resource "azurerm_mssql_server" "this" {\n  name                = "<name>"\n  resource_group_name = "<rg>"\n  location            = "<region>"\n'
        '  version             = "12.0"\n  minimum_tls_version = "1.2"\n}',
     docs=["az-sql-tls"])

# ----------------------------------------------------------------------------- Key Vault
GUIDANCE["AZ-KV-001"] = g(
    5.4, 693, ["T1485"],
    [("Deleted secrets are gone for good", "Without soft delete a deleted vault, key or secret cannot be recovered."),
     ("Accidents become outages", "Applications that depend on a deleted key or secret fail and may lose encrypted data."),
     ("Destruction by an attacker", "A compromised identity can delete keys with no way back.")],
    ["Open the key vault > Properties.", "Check the soft-delete setting and retention days."],
    "az keyvault show -n <name> -g <rg> --query \"{softDelete:properties.enableSoftDelete, days:properties.softDeleteRetentionInDays}\"",
    ["Open the key vault > Properties.", "Enable soft delete (new vaults have it permanently on) and set retention to 90 days.", "Also enable purge protection (see AZ-KV-002)."],
    "az keyvault update -n <name> -g <rg> --enable-soft-delete true --retention-days 90",
    'resource "azurerm_key_vault" "this" {\n  name                       = "<name>"\n  resource_group_name        = "<rg>"\n  location                   = "<region>"\n'
    '  tenant_id                  = data.azurerm_client_config.current.tenant_id\n  sku_name                   = "standard"\n  soft_delete_retention_days = 90\n  purge_protection_enabled   = true\n}',
    "Use a vault module that always sets retention and purge protection and audit with the built-in 'Key vaults should have soft delete enabled' policy.",
    ["az-kv-sd", "cis-azure", "mcsb"])

GUIDANCE["AZ-KV-002"] = g(
    5.0, 693, ["T1485"],
    [("Permanent purge is possible", "With soft delete but no purge protection, someone with permission can purge a deleted key or secret before retention ends."),
     ("Insider or stolen-credential risk", "An attacker can destroy keys that protect other data."),
     ("Irreversible", "Purge protection is a one-way setting: once on, it cannot be turned off.")],
    ["Open the key vault > Properties.", "Check 'Purge protection' is disabled."],
    "az keyvault show -n <name> -g <rg> --query properties.enablePurgeProtection",
    ["Open the key vault > Properties.", "Under Purge protection select 'Enable purge protection' and save. This cannot be undone."],
    "az keyvault update -n <name> -g <rg> --enable-purge-protection true",
    'resource "azurerm_key_vault" "this" {\n  name                     = "<name>"\n  resource_group_name      = "<rg>"\n  location                 = "<region>"\n'
    '  tenant_id                = data.azurerm_client_config.current.tenant_id\n  sku_name                 = "standard"\n  purge_protection_enabled = true\n}',
    "Set purge protection in your vault module and audit with the built-in policy 'Key vaults should have deletion protection enabled'.",
    ["az-kv-sd", "cis-azure", "mcsb"])

_pe_public("AZ-KV-003", "Key Vault", score=5.3,
           show="az keyvault show -n <name> -g <rg> --query properties.publicNetworkAccess",
           console="Open the key vault > Settings > Networking and review the Firewalls and virtual networks tab.",
           cli="az keyvault update -n <name> -g <rg> --public-network-access Disabled",
           tf='resource "azurerm_key_vault" "this" {\n  name                          = "<name>"\n  resource_group_name           = "<rg>"\n  location                      = "<region>"\n'
              '  tenant_id                     = data.azurerm_client_config.current.tenant_id\n  sku_name                      = "standard"\n'
              '  public_network_access_enabled = false\n}',
           docs=["az-kv-net"])

GUIDANCE["AZ-KV-004"] = g(
    6.5, 668, ["T1190", "T1528"],
    [("Secrets store reachable from anywhere", "The vault firewall allows every network, so only credentials stand between the internet and your secrets."),
     ("High-value target", "Key vaults hold connection strings, certificates and encryption keys for other systems."),
     ("One stolen token is enough", "A leaked token or over-broad access policy is exploitable from any location.")],
    ["Open the key vault > Settings > Networking.", "Check 'Allow public access from all networks' is selected."],
    "az keyvault show -n <name> -g <rg> --query \"{public:properties.publicNetworkAccess, default:properties.networkAcls.defaultAction}\"",
    ["Open the key vault > Settings > Networking.", "Select 'Allow public access from specific virtual networks and IP addresses' (or Disable public access) and add only the networks that need it.",
     "Keep 'Allow trusted Microsoft services to bypass this firewall' only if required."],
    "az keyvault update -n <name> -g <rg> --default-action Deny --bypass AzureServices\naz keyvault network-rule add -n <name> -g <rg> --ip-address 203.0.113.0/24",
    'resource "azurerm_key_vault" "this" {\n  name                = "<name>"\n  resource_group_name = "<rg>"\n  location            = "<region>"\n'
    '  tenant_id           = data.azurerm_client_config.current.tenant_id\n  sku_name            = "standard"\n  network_acls {\n    default_action = "Deny"\n'
    '    bypass         = "AzureServices"\n    ip_rules       = ["203.0.113.0/24"]\n  }\n}',
    "Create vaults with a deny-by-default firewall or private endpoint only, and audit with the built-in 'Azure Key Vault should have firewall enabled' policy.",
    ["az-kv-net", "cis-azure", "mcsb"])

# ----------------------------------------------------------------------------- AKS / pods
GUIDANCE["AZ-AKS-001"] = g(
    8.0, 285, ["T1078.004", "T1610", "T1068"],
    [("No Kubernetes authorization", "Without RBAC any authenticated identity can read and change cluster resources."),
     ("Cluster takeover path", "A stolen kubeconfig or token gives full control, including secrets and workloads."),
     ("Hard to retrofit", "RBAC cannot be switched off on current clusters, so a finding here usually means a legacy cluster.")],
    ["Open the AKS cluster > Settings > Properties (or Cluster configuration).", "Check Kubernetes RBAC and the authentication mode."],
    "az aks show -g <rg> -n <name> --query \"{rbac:enableRbac, aad:aadProfile}\"",
    ["Open the AKS cluster > Settings > Cluster configuration.", "Set the authentication and authorization to 'Microsoft Entra ID authentication with Kubernetes RBAC'.",
     "If RBAC cannot be enabled on this legacy cluster, create a new cluster with RBAC and migrate workloads."],
    "az aks update -g <rg> -n <name> --enable-aad --aad-admin-group-object-ids <entra-group-object-id>",
    'resource "azurerm_kubernetes_cluster" "this" {\n  name                = "<name>"\n  location            = "<region>"\n  resource_group_name = "<rg>"\n  dns_prefix          = "<name>"\n'
    '  role_based_access_control_enabled = true\n  azure_active_directory_role_based_access_control {\n    azure_rbac_enabled     = true\n    admin_group_object_ids = ["<entra-group-object-id>"]\n  }\n  # ... default_node_pool, identity\n}',
    "Create all clusters with Entra ID integration and RBAC; audit with 'Role-Based Access Control (RBAC) should be used on Kubernetes Services'.",
    ["az-aks-auth", ("AKS security best practices", "https://learn.microsoft.com/azure/aks/operator-best-practices-cluster-security"), "cis-k8s"])

GUIDANCE["AZ-AKS-002"] = g(
    7.5, 668, ["T1190", "T1133"],
    [("Control plane reachable from anywhere", "The Kubernetes API server answers requests from any internet address."),
     ("Exposure of an admin interface", "Any API flaw or stolen credential becomes remotely exploitable."),
     ("Easy to narrow", "Authorized IP ranges or a private cluster remove the exposure without changing workloads.")],
    ["Open the AKS cluster > Settings > Networking.", "Check 'Authorized IP ranges' is empty and that the cluster is not private."],
    "az aks show -g <rg> -n <name> --query \"{ranges:apiServerAccessProfile.authorizedIpRanges, private:apiServerAccessProfile.enablePrivateCluster}\"",
    ["Open the AKS cluster > Settings > Networking.", "Enable authorized IP ranges and enter your office / CI egress CIDRs.", "For new clusters, prefer a private cluster."],
    "az aks update -g <rg> -n <name> --api-server-authorized-ip-ranges 203.0.113.0/24",
    'resource "azurerm_kubernetes_cluster" "this" {\n  name                = "<name>"\n  location            = "<region>"\n  resource_group_name = "<rg>"\n  dns_prefix          = "<name>"\n'
    '  api_server_access_profile {\n    authorized_ip_ranges = ["203.0.113.0/24"]\n  }\n  # or private_cluster_enabled = true (set at creation)\n}',
    "Make authorized ranges or a private cluster mandatory in your AKS module and audit with 'Authorized IP ranges should be defined on Kubernetes Services'.",
    ["az-aks-api", "cis-k8s", "mcsb"])

GUIDANCE["AZ-POD-001"] = g(
    7.8, 250, ["T1611", "T1610"],
    [("Container can escape to the node", "A privileged container has nearly all kernel capabilities and host device access."),
     ("Cluster-wide blast radius", "From the node an attacker can reach other pods, node credentials and secrets."),
     ("Rarely necessary", "Most workloads need no privileged mode; specific capabilities are the safer way.")],
    ["Find the pod and read its securityContext.", "Check `privileged: true` on the container or its init containers.",
     "Ask the owner why it is needed and whether a narrower capability suffices."],
    "kubectl get pod <name> -o jsonpath='{.spec.containers[*].securityContext.privileged}'",
    ["Edit the Deployment / Pod spec that creates this pod.", "Remove `privileged: true` (set `allowPrivilegeEscalation: false`) and add only the specific capabilities required.",
     "Roll the workload out again."],
    "kubectl label namespace <namespace> pod-security.kubernetes.io/enforce=baseline --overwrite\n# then fix the workload: securityContext.privileged: false",
    'resource "kubernetes_namespace" "app" {\n  metadata {\n    name = "<namespace>"\n    labels = {\n      "pod-security.kubernetes.io/enforce" = "baseline"\n    }\n  }\n}',
    "Enforce the Pod Security Standards (baseline or restricted) on every namespace, or use the AKS Azure Policy add-on 'no privileged containers' initiative.",
    ["k8s-pss", "k8s-psa", "cis-k8s"])

# ----------------------------------------------------------------------------- Identity / subscription
GUIDANCE["AZ-ID-001"] = g(
    8.0, 272, ["T1078.004", "T1548"],
    [("Workload identity can change anything", "Owner or Contributor at subscription scope lets the workload modify or delete any resource."),
     ("Compromise turns into a subscription takeover", "Code execution in that workload is enough to act on the whole subscription."),
     ("Owner can also grant access", "With Owner the identity can assign roles, which allows persistence.")],
    ["Open the subscription > Access control (IAM) > Role assignments.", "Find the managed identity and its role and scope.", "List what the workload really needs to do."],
    "az role assignment list --assignee <principal-id> --scope /subscriptions/<subscription> -o table",
    ["Open the subscription > Access control (IAM) > Role assignments.", "Remove the broad assignment.", "Add a narrower built-in role (for example Storage Blob Data Contributor) scoped to the specific resource or resource group."],
    "az role assignment delete --assignee <principal-id> --role Contributor --scope /subscriptions/<subscription>\n"
    "az role assignment create --assignee <principal-id> --role \"<specific-role>\" --scope /subscriptions/<subscription>/resourceGroups/<rg>",
    'resource "azurerm_role_assignment" "scoped" {\n  scope                = azurerm_resource_group.this.id # not the subscription\n  role_definition_name = "<specific-role>"\n  principal_id         = "<principal-id>"\n}',
    "Grant workload identities the narrowest role at the narrowest scope and review role assignments regularly (Entra access reviews, Defender for Cloud recommendations).",
    ["az-rbac", "az-mi", "cis-azure"])

GUIDANCE["AZ-SUB-001"] = g(
    5.2, 269, ["T1078.004", "T1098"],
    [("Too many people can do anything", "More than three Owners means many accounts can change access and delete resources subscription-wide."),
     ("Larger phishing prize", "Each Owner account is a high-value target."),
     ("Weak accountability", "Broad ownership makes changes hard to attribute.")],
    ["Open the subscription > Access control (IAM) > Role assignments.", "Filter by the Owner role and list who holds it, including groups and service principals."],
    "az role assignment list --role Owner --scope /subscriptions/<subscription> --query \"[].{who:principalName, type:principalType}\" -o table",
    ["Open the subscription > Access control (IAM) > Role assignments.", "Remove Owner from anyone who does not need it and give them a narrower role.",
     "Use Privileged Identity Management for just-in-time Owner where possible."],
    "az role assignment delete --assignee <principal-id> --role Owner --scope /subscriptions/<subscription>",
    'resource "azurerm_role_assignment" "owner" {\n  scope                = "/subscriptions/<subscription>"\n  role_definition_name = "Owner"\n  principal_id         = "<break-glass-or-group-object-id>" # keep this list short\n}',
    "Keep subscription Owners to a small set (CIS suggests fewer than four), prefer groups with PIM, and review quarterly.",
    ["az-rbac", "cis-azure"])

GUIDANCE["AZ-SUB-002"] = g(
    3.4, 272, ["T1078.004"],
    [("Many privileged principals", "A large number of Owner/Contributor assignments widens who can change production."),
     ("Least privilege drift", "Roles granted for one task tend to stay forever."),
     ("Lower urgency", "This is a hygiene signal rather than a direct exposure.")],
    ["Open the subscription > Access control (IAM) > Role assignments.", "Filter for Owner and Contributor and review each one."],
    "az role assignment list --scope /subscriptions/<subscription> --query \"[?roleDefinitionName=='Owner' || roleDefinitionName=='Contributor'].{who:principalName, role:roleDefinitionName}\" -o table",
    ["Open the subscription > Access control (IAM) > Role assignments.", "Replace Contributor with scoped roles on resource groups, and remove unused assignments."],
    "az role assignment delete --assignee <principal-id> --role Contributor --scope /subscriptions/<subscription>",
    'resource "azurerm_role_assignment" "rg_contributor" {\n  scope                = azurerm_resource_group.this.id\n  role_definition_name = "Contributor"\n  principal_id         = "<group-object-id>"\n}',
    "Assign roles to groups at resource-group scope and run recurring access reviews.",
    ["az-rbac", "cis-azure"])

# ----------------------------------------------------------------------------- Azure Firewall
GUIDANCE["AZ-FW-001"] = g(
    8.1, 284, ["T1133", "T1021", "T1110"],
    [("Management port published to the internet", "A DNAT rule forwards SSH, RDP or WinRM from any source to a private host."),
     ("Bypasses NSGs and Bastion", "The firewall deliberately exposes an admin protocol that would otherwise be private."),
     ("Brute force and exploitation", "The target host is probed continuously from the internet.")],
    ["Open the firewall's policy > DNAT rules.", "Find rules with source '*' and destination port 22, 3389 or 5985/5986.", "Identify the translated address and owner."],
    "az network firewall policy rule-collection-group list -g <rg> --policy-name <policy-name> -o table",
    ["Open the Azure Firewall policy > Rules > DNAT rules.", "Delete the rule, or restrict its source to a trusted IP range.", "Provide admin access through Azure Bastion or a VPN instead."],
    "# list the rule collection groups, then edit or delete the DNAT rule in the group that contains it\naz network firewall policy rule-collection-group list -g <rg> --policy-name <policy-name>",
    '# in azurerm_firewall_policy_rule_collection_group, remove the nat_rule_collection rule, or set source_addresses to a trusted CIDR\n'
    'nat_rule_collection {\n  name     = "dnat"\n  priority = 100\n  action   = "Dnat"\n  rule {\n    name                = "admin-from-office"\n    protocols           = ["TCP"]\n    source_addresses    = ["203.0.113.0/24"]\n'
    '    destination_address = "<firewall-public-ip>"\n    destination_ports   = ["22"]\n    translated_address  = "10.0.1.4"\n    translated_port     = "22"\n  }\n}',
    "Require review of every DNAT rule and ban management-port DNAT from '*' with a policy-as-code check.",
    ["az-fw", "az-fw-policy", "az-bastion", "cis-azure"])

GUIDANCE["AZ-FW-002"] = g(
    8.1, 284, ["T1133", "T1190", "T1048"],
    [("Database or file share exposed", "A DNAT rule publishes a database or file-sharing port (for example SQL, MySQL, PostgreSQL, SMB) to any source."),
     ("Direct data access attempts", "Databases are targeted by credential stuffing and known exploits."),
     ("Rarely intended", "Data tiers are normally reached over private paths only.")],
    ["Open the firewall policy > DNAT rules.", "Find rules from '*' to ports such as 1433, 3306, 5432, 445 or 6379.", "Confirm the owner and whether clients can use a private path."],
    "az network firewall policy rule-collection-group list -g <rg> --policy-name <policy-name> -o table",
    ["Open the Azure Firewall policy > Rules > DNAT rules.", "Delete the rule or limit its sources to specific trusted IPs.", "Use a private endpoint or VPN for client access to the data tier."],
    "az network firewall policy rule-collection-group list -g <rg> --policy-name <policy-name>\n# then remove or edit the DNAT rule in its rule collection group",
    '# remove the DNAT rule, or limit source_addresses to a trusted CIDR instead of "*"',
    "Forbid DNAT to data ports in your firewall policy review and use private endpoints for data services.",
    ["az-fw", "az-fw-policy", "az-pe", "mcsb"])

GUIDANCE["AZ-FW-003"] = g(
    5.0, 693, ["T1190", "T1133"],
    [("Known-bad traffic is not filtered", "With threat intelligence off, traffic to and from known malicious IPs and domains is not alerted or blocked."),
     ("Missed command-and-control", "Compromised workloads can talk to known attacker infrastructure unnoticed."),
     ("Cheap protection", "Alert mode costs nothing in functionality; Deny mode blocks known-bad addresses.")],
    ["Open the firewall policy > Threat intelligence.", "Check the mode is Off."],
    "az network firewall policy show -g <rg> -n <policy-name> --query threatIntelMode",
    ["Open the Azure Firewall policy > Threat intelligence.", "Set the mode to 'Alert and deny' (or at least 'Alert only') and save."],
    "az network firewall policy update -g <rg> -n <policy-name> --threat-intel-mode Deny",
    'resource "azurerm_firewall_policy" "this" {\n  name                     = "<policy-name>"\n  resource_group_name      = "<rg>"\n  location                 = "<region>"\n  threat_intelligence_mode = "Deny"\n}',
    "Set threat-intelligence mode in your firewall policy module and audit it with Azure Policy.",
    ["az-fw-ti", "mcsb"])

GUIDANCE["AZ-FW-004"] = g(
    2.5, 1188, ["T1562"],
    [("Classic rules limit features", "Premium IDPS, TLS inspection and policy inheritance need a Firewall Policy."),
     ("Operational drift", "Rules managed directly on each firewall are harder to review and keep consistent."),
     ("Low direct risk", "This is a modernisation and governance finding.")],
    ["Open the firewall overview.", "Check whether a Firewall Policy is associated or classic rule collections are used."],
    "az network firewall show -g <rg> -n <name> --query firewallPolicy",
    ["Open the firewall in the Azure portal.", "Use 'Migrate to Firewall Policy' to create a policy from the classic rules and associate it."],
    "az network firewall show -g <rg> -n <name> --query firewallPolicy   # confirm after migrating in the portal",
    'resource "azurerm_firewall" "this" {\n  name                = "<name>"\n  resource_group_name = "<rg>"\n  location            = "<region>"\n  sku_name            = "AZFW_VNet"\n  sku_tier            = "Standard"\n  firewall_policy_id  = azurerm_firewall_policy.this.id\n  # ... ip_configuration\n}',
    "Create new firewalls with a Firewall Policy and manage rules centrally in code.",
    ["az-fw-policy", "az-fw", "mcsb"])

GUIDANCE["AZ-FW-005"] = g(
    6.8, 284, ["T1133", "T1048"],
    [("Any source to any port", "An Allow network rule accepts every source address on every destination port."),
     ("Firewall acts like a router", "Segmentation through the firewall provides no filtering for the covered traffic."),
     ("Easy lateral movement and exfiltration", "Traffic between networks flows freely once an attacker is inside.")],
    ["Open the firewall policy > Rules > Network rules.", "Find Allow rules with source '*' and destination port '*'."],
    "az network firewall policy rule-collection-group list -g <rg> --policy-name <policy-name> -o table",
    ["Open the Azure Firewall policy > Rules > Network rules.", "Replace the broad rule with rules naming specific sources, destinations and ports."],
    "az network firewall policy rule-collection-group list -g <rg> --policy-name <policy-name>\n# then replace the rule in its rule collection group",
    '# in azurerm_firewall_policy_rule_collection_group network_rule_collection, give each rule explicit source_addresses, destination_addresses and destination_ports',
    "Ban any-any allow rules by policy-as-code review; start from deny and add specific flows.",
    ["az-fw", "az-fw-policy", "mcsb"])

GUIDANCE["AZ-FW-006"] = g(
    3.0, 693, ["T1190", "T1562"],
    [("No intrusion detection or prevention", "The Premium firewall is paid for but its IDPS signatures are not inspecting traffic."),
     ("Missed exploit traffic", "Known exploit patterns pass without an alert or block."),
     ("Wasted capability", "Premium SKU features are only effective when enabled in the policy.")],
    ["Open the firewall policy > IDPS.", "Check the mode is Off."],
    "az network firewall policy show -g <rg> -n <policy-name> --query intrusionDetection",
    ["Open the Azure Firewall policy > IDPS.", "Set the mode to 'Alert' to start, then 'Alert and deny' after tuning."],
    "az network firewall policy intrusion-detection add -g <rg> --policy-name <policy-name> --mode Deny",
    'resource "azurerm_firewall_policy" "this" {\n  name                = "<policy-name>"\n  resource_group_name = "<rg>"\n  location            = "<region>"\n  sku                 = "Premium"\n  intrusion_detection {\n    mode = "Deny"\n  }\n}',
    "Turn IDPS on in the policy module for every Premium firewall and review alerts.",
    ["az-fw-premium", "mcsb"])

# ----------------------------------------------------------------------------- App Service and Function apps
def _app(prefix: str, kind: str, cli: str, ident: str) -> None:
    """Rules shared by web apps (AZ-APP-*) and function apps (AZ-FN-*); `cli` is webapp / functionapp."""
    tfres = "azurerm_linux_web_app" if cli == "webapp" else "azurerm_linux_function_app"
    show = f"az {cli} show -g <rg> -n <name>"
    cfg = f"az {cli} config show -g <rg> -n <name>"

    def tf(inner: str) -> str:
        return (f'resource "{tfres}" "this" {{\n  name                = "<name>"\n  resource_group_name = "<rg>"\n  location            = "<region>"\n'
                f'  service_plan_id     = azurerm_service_plan.this.id\n{inner}\n  site_config {{}}\n}}')

    def tf_site(inner: str) -> str:
        return (f'resource "{tfres}" "this" {{\n  name                = "<name>"\n  resource_group_name = "<rg>"\n  location            = "<region>"\n'
                f'  service_plan_id     = azurerm_service_plan.this.id\n  site_config {{\n{inner}\n  }}\n}}')

    n = {"web": "App Service", "fn": "Function app"}[ident]
    fixed = "az functionapp update" if cli == "functionapp" else "az webapp update"

    if cli == "webapp":  # AZ-FN-001 is the function app HTTPS rule defined separately below
        GUIDANCE[f"{prefix}-001"] = g(
            5.9, 319, ["T1557", "T1040"],
            [("Cleartext requests accepted", "The app answers plain HTTP, so credentials, cookies and tokens can cross the network unencrypted."),
             ("Session hijacking", "A network attacker can capture or alter traffic."),
             ("Easy to fix", "HTTPS-only redirects every request to HTTPS without code changes.")],
            ["Open the app > Settings > Configuration (General settings).", "Check 'HTTPS Only' is Off."],
            f"{show} --query httpsOnly",
            ["Open the app in the Azure portal.", "Go to Settings > Configuration > General settings (or TLS/SSL settings).", "Set 'HTTPS Only' to On and save."],
            f"{fixed} -g <rg> -n <name> --https-only true",
            tf("  https_only          = true"),
            "Set https_only in your app module and audit with the built-in 'App Service apps should only be accessible over HTTPS' policy.",
            ["az-appsvc-tls", "cis-azure"])

    GUIDANCE[f"{prefix}-002"] = g(
        5.3, 326, ["T1557", "T1040"],
        [("Weak TLS accepted", f"The {n} negotiates TLS 1.0/1.1 with clients."),
         ("Downgrade risk", "A network attacker can force a weak protocol version."),
         ("Compliance", "TLS 1.2 or newer is required by CIS, PCI DSS and most policies.")],
        ["Open the app > Settings > Configuration > General settings.", "Check 'Minimum Inbound TLS Version'."],
        f"{cfg} --query minTlsVersion",
        ["Open the app in the Azure portal.", "Go to Settings > Configuration > General settings.", "Set 'Minimum Inbound TLS Version' to 1.2 and save."],
        f"az {cli} config set -g <rg> -n <name> --min-tls-version 1.2",
        tf_site('    minimum_tls_version = "1.2"'),
        "Set the minimum TLS version in your module and audit with Azure Policy.",
        ["az-appsvc-tls", "mcsb", "cis-azure"])

    GUIDANCE[f"{prefix}-003"] = g(
        5.9, 319, ["T1040", "T1557"],
        [("Cleartext deployment credentials", "FTP state AllAllowed lets deployment credentials and content travel unencrypted."),
         ("Credentials captured on the wire", "Anyone on the path can read the FTP username and password."),
         ("Obsolete path", "Modern deployments use zip deploy, Git or CI pipelines.")],
        ["Open the app > Settings > Configuration > General settings.", "Check 'FTP state' is 'All allowed'."],
        f"{cfg} --query ftpsState",
        ["Open the app in the Azure portal.", "Go to Settings > Configuration > General settings.", "Set 'FTP state' to 'FTPS only' or 'Disabled' and save."],
        f"az {cli} config set -g <rg> -n <name> --ftps-state Disabled",
        tf_site('    ftps_state = "Disabled" # or "FtpsOnly"'),
        "Disable FTP in your module and deploy through CI; audit with 'App Service apps should require FTPS only'.",
        ["az-appsvc-ftp", "cis-azure", "mcsb"])

    GUIDANCE[f"{prefix}-004"] = g(
        2.0, 16, ["T1190"],
        [("Older protocol in use", "HTTP/1.1 is slower and has less efficient connection handling than HTTP/2."),
         ("Mostly a hygiene finding", "There is little direct security impact."),
         ("Easy to enable", "Toggling it rarely affects clients.")],
        ["Open the app > Settings > Configuration > General settings.", "Check 'HTTP version'."],
        f"{cfg} --query http20Enabled",
        ["Open the app > Settings > Configuration > General settings.", "Set 'HTTP version' to 2.0 and save."],
        f"az {cli} config set -g <rg> -n <name> --http20-enabled true",
        tf_site("    http2_enabled = true"),
        "Enable HTTP/2 by default in your module.",
        ["az-appsvc-cfg", "cis-azure"])

    GUIDANCE[f"{prefix}-005"] = g(
        3.1, 798, ["T1552", "T1078.004"],
        [("Stored credentials needed", "Without a managed identity the app must hold secrets (keys, connection strings) to reach other Azure services."),
         ("Secrets can leak", "Stored secrets end up in settings, repos and logs."),
         ("No automatic rotation", "Managed identities need no secret and rotate automatically.")],
        ["Open the app > Settings > Identity.", "Check System assigned status is Off and no user-assigned identity is attached."],
        f"az {cli} identity show -g <rg> -n <name>",
        ["Open the app > Settings > Identity.", "Turn System assigned On (or attach a user-assigned identity) and save.", "Grant it the needed roles on target resources and remove stored secrets."],
        f"az {cli} identity assign -g <rg> -n <name>",
        tf("  identity {\n    type = \"SystemAssigned\"\n  }"),
        "Give every app an identity in your module and ban secrets in app settings.",
        ["az-appsvc-mi", "az-mi", "cis-azure"])

    GUIDANCE[f"{prefix}-006"] = g(
        7.4, 489, ["T1190", "T1133"],
        [("Debugger can attach", "Remote debugging opens extra ports and lets a debugger attach to the running app."),
         ("Code and memory exposure", "An attacker with credentials can inspect or influence the running process."),
         ("Left on by accident", "It is a development feature that is often forgotten in production.")],
        ["Open the app > Settings > Configuration > General settings.", "Check 'Remote debugging' is On."],
        f"{cfg} --query remoteDebuggingEnabled",
        ["Open the app > Settings > Configuration > General settings.", "Set 'Remote debugging' to Off and save."],
        f"az {cli} config set -g <rg> -n <name> --remote-debugging-enabled false",
        tf_site("    remote_debugging_enabled = false"),
        "Keep remote debugging off in production by default and enforce with Azure Policy ('... should have remote debugging turned off').",
        ["az-appsvc-sec", "mcsb"])

    GUIDANCE[f"{prefix}-007"] = g(
        5.8, 284, ["T1190", "T1078"],
        [("Deployment endpoint open to anyone", "The Kudu/SCM site (admin and deployment tools) accepts requests from any address."),
         ("Powerful interface", "With credentials it allows file access, a console and deployment."),
         ("Often forgotten", "It is a separate site with its own restrictions.")],
        ["Open the app > Settings > Networking > Access restrictions.", "Check the Advanced tool site (SCM) uses the main site's rules or has its own restrictions."],
        f"az {cli} config access-restriction show -g <rg> -n <name>",
        ["Open the app > Settings > Networking > Access restrictions.", "Under the Advanced tool site, add Allow rules for your CI/office ranges, or tick 'Use main site rules'."],
        f"az {cli} config access-restriction add -g <rg> -n <name> --rule-name office --action Allow --ip-address 203.0.113.0/24 --priority 100 --scm-site true",
        tf_site("    scm_use_main_ip_restriction = true\n    ip_restriction_default_action = \"Deny\""),
        "Restrict the SCM site by default (same rules as the main site) in your module.",
        ["az-appsvc-ipr", "mcsb"])

    GUIDANCE[f"{prefix}-008"] = g(
        5.4, 306, ["T1190", "T1078"],
        [("Anonymous users reach the app", "The app is internet-facing and App Service authentication (Easy Auth) is off."),
         ("Relies on app code alone", "Any flaw in app-level authentication is directly exploitable."),
         ("Easy Auth adds a gate", "It can require sign-in before any request reaches your code.")],
        ["Open the app > Settings > Authentication.", "Check no identity provider is configured / authentication is disabled."],
        f"az {cli} auth show -g <rg> -n <name> --query enabled",
        ["Open the app > Settings > Authentication.", "Select Add identity provider (Microsoft) and set 'Restrict access' to 'Require authentication'.",
         "Skip this finding only for intentionally public sites and document the reason."],
        f"az {cli} auth update -g <rg> -n <name> --enabled true --action RedirectToLoginPage   # then configure a provider, e.g. az {cli} auth microsoft update",
        tf("  auth_settings_v2 {\n    auth_enabled           = true\n    require_authentication = true\n    unauthenticated_action = \"RedirectToLoginPage\"\n    # login { }, active_directory_v2 { client_id = ..., tenant_auth_endpoint = ... }\n  }"),
        "Require authentication by default in your module, with explicit exceptions for public apps.",
        ["az-appsvc-auth", "cis-azure"])

    GUIDANCE[f"{prefix}-009"] = g(
        7.5, 1104, ["T1190", "T1068"],
        [("Runtime no longer patched", "The language runtime has reached end of life and no longer receives security fixes."),
         ("Known vulnerabilities stay open", "Any new runtime flaw will never be patched for this version."),
         ("Compliance and support", "Microsoft eventually stops supporting retired stacks on App Service.")],
        ["Open the app > Settings > Configuration > Stack settings.", "Note the runtime and version, and compare with the vendor's support dates (endoflife.date)."],
        f"{cfg} --query \"{{linux:linuxFxVersion, windows:windowsFxVersion, net:netFrameworkVersion, php:phpVersion, python:pythonVersion, node:nodeVersion, java:javaVersion}}\"",
        ["Test the app on a supported version in a staging slot.", "Open the app > Settings > Configuration > Stack settings.", "Select a supported version of the runtime and save; swap the slot into production."],
        f"az {cli} config set -g <rg> -n <name> --linux-fx-version \"PYTHON|3.12\"   # use your stack and a supported version",
        tf_site("    application_stack {\n      python_version = \"3.12\" # your stack, a supported version\n    }"),
        "Track runtime end-of-life dates and upgrade on a schedule; Defender for Cloud and this scanner flag retiring versions early.",
        ["az-appsvc-lang", "az-appsvc-cfg", ("Product end-of-life dates", "https://endoflife.date/")])

    GUIDANCE[f"{prefix}-010"] = g(
        2.8, 306, ["T1190"],
        [("Client certificates not requested", "The app does not ask clients for a certificate, so mutual TLS is unavailable."),
         ("Only matters for some apps", "It is relevant for service-to-service and high-assurance APIs."),
         ("Defence in depth", "Mutual TLS adds a second factor at the transport layer.")],
        ["Open the app > Settings > Configuration > General settings.", "Check 'Incoming client certificates'."],
        f"{show} --query clientCertEnabled",
        ["Open the app > Settings > Configuration > General settings.", "Enable 'Client certificate mode' (Require or Allow) if the app serves certificate-authenticated clients."],
        f"{fixed} -g <rg> -n <name> --set clientCertEnabled=true",
        tf("  client_certificate_enabled = true\n  client_certificate_mode    = \"Required\""),
        "Decide per app whether mutual TLS is needed; document apps where it is not.",
        ["az-appsvc-sec", "cis-azure"])

    pe_key = f"{prefix}-011"
    _pe_public(pe_key, n.lower(), score=5.3,
               show="az resource show -g <rg> -n <name> --resource-type Microsoft.Web/sites --query properties.publicNetworkAccess",
               console=f"Open the {n.lower()} > Settings > Networking and review Public network access.",
               cli="az resource update -g <rg> -n <name> --resource-type Microsoft.Web/sites --set properties.publicNetworkAccess=Disabled",
               tf=tf("  public_network_access_enabled = false"),
               docs=["az-appsvc-ipr"])


_app("AZ-APP", "web", "webapp", "web")
_app("AZ-FN", "fn", "functionapp", "fn")

GUIDANCE["AZ-FN-001"] = g(
    5.9, 319, ["T1557", "T1040"],
    [("Cleartext requests accepted", "The function app answers plain HTTP, so keys, tokens and payloads can cross the network unencrypted."),
     ("Function keys exposed", "Function keys sent over HTTP can be captured and replayed."),
     ("Easy to fix", "HTTPS-only redirects all requests without code changes.")],
    ["Open the function app > Settings > Configuration (General settings).", "Check 'HTTPS Only' is Off."],
    "az functionapp show -g <rg> -n <name> --query httpsOnly",
    ["Open the function app in the Azure portal.", "Go to Settings > Configuration > General settings.", "Set 'HTTPS Only' to On and save."],
    "az functionapp update -g <rg> -n <name> --set httpsOnly=true",
    'resource "azurerm_linux_function_app" "this" {\n  name                       = "<name>"\n  resource_group_name        = "<rg>"\n  location                   = "<region>"\n'
    '  service_plan_id            = azurerm_service_plan.this.id\n  storage_account_name       = azurerm_storage_account.this.name\n  https_only                 = true\n  site_config {}\n}',
    "Set https_only in your function module and audit with 'Function apps should only be accessible over HTTPS'.",
    ["az-appsvc-tls", "cis-azure"])

# ----------------------------------------------------------------------------- PostgreSQL / MySQL flexible servers
def _db(prefix: str, eng: str, cli: str, tfres: str, hint: str) -> None:
    pub = "az-pg-net" if eng == "PostgreSQL" else "az-my-net"
    tls = "az-pg-tls" if eng == "PostgreSQL" else "az-my-tls"
    ent = "az-pg-entra" if eng == "PostgreSQL" else "az-my-entra"
    bkp = "az-pg-bkp" if eng == "PostgreSQL" else "az-my-bkp"
    ver = "az-pg-ver" if eng == "PostgreSQL" else "az-my-ver"
    tlsparam = "ssl_min_protocol_version" if eng == "PostgreSQL" else "tls_version"
    tlsval = "TLSv1.2"
    cfgres = "azurerm_postgresql_flexible_server_configuration" if eng == "PostgreSQL" else "azurerm_mysql_flexible_server_configuration"
    fwres = "azurerm_postgresql_flexible_server_firewall_rule" if eng == "PostgreSQL" else "azurerm_mysql_flexible_server_firewall_rule"
    sname = "-s" if eng == "PostgreSQL" else "-s"

    GUIDANCE[f"{prefix}-001"] = g(
        9.1, 284, ["T1190", "T1110"],
        [("Whole internet allowed", f"A firewall rule covering 0.0.0.0-255.255.255.255 lets every IPv4 address reach the {eng} server."),
         ("Direct data theft risk", "Anyone with a valid or guessed login or an exploit can reach your data."),
         ("Firewall is ineffective", "The server firewall gives no protection.")],
        ["Open the server > Settings > Networking.", "Find the firewall rule with start 0.0.0.0 and end 255.255.255.255."],
        f"az {cli} flexible-server firewall-rule list -g <rg> -n <name> -o table",
        ["Open the server > Settings > Networking.", "Delete the rule spanning the whole IPv4 range.", "Add rules for specific client IPs, or use private access (VNet integration / private endpoint)."],
        f"az {cli} flexible-server firewall-rule delete -g <rg> -n <name> --rule-name <rule-name> --yes",
        f'resource "{fwres}" "office" {{\n  name             = "office"\n  server_id        = azurerm_{ "postgresql" if eng == "PostgreSQL" else "mysql"}_flexible_server.this.id\n'
        '  start_ip_address = "203.0.113.10"\n  end_ip_address   = "203.0.113.10"\n}',
        "Prefer private access, and review firewall rules in pull requests so full-range rules are rejected.",
        [pub, "mcsb", "cis-azure"])

    GUIDANCE[f"{prefix}-002"] = g(
        5.3, 284, ["T1190", "T1078.004"],
        [("Any Azure tenant can connect", "The 0.0.0.0 'Allow Azure services' rule admits traffic from any Azure customer's resources, not only yours."),
         ("Wider than it looks", "An attacker with a free Azure subscription can reach the server's endpoint."),
         ("Credentials still needed", "The rule does not grant access by itself, but removes a network barrier.")],
        ["Open the server > Settings > Networking.", "Check 'Allow public access from any Azure service within Azure to this server'."],
        f"az {cli} flexible-server firewall-rule list -g <rg> -n <name> --query \"[?startIpAddress=='0.0.0.0']\" -o table",
        ["Open the server > Settings > Networking.", "Untick the Azure services option (delete the 0.0.0.0 rule).", "Allow specific resources by their outbound IPs or use private endpoints."],
        f"az {cli} flexible-server firewall-rule delete -g <rg> -n <name> --rule-name <rule-name> --yes   # the 0.0.0.0 rule",
        '# remove the firewall rule whose start_ip_address and end_ip_address are both "0.0.0.0"',
        "Do not create the 0.0.0.0 rule; use private endpoints or explicit client IPs.",
        [pub, "mcsb", "cis-azure"])

    GUIDANCE[f"{prefix}-003"] = g(
        5.9, 319, ["T1557", "T1040"],
        [("Unencrypted connections allowed", "Clients may connect without TLS, so credentials and data can cross the network in clear."),
         ("Interception", "A network attacker can read or alter queries and results."),
         ("Server parameter", "The fix is the require_secure_transport parameter.")],
        ["Open the server > Settings > Server parameters.", "Search for require_secure_transport and check its value is OFF."],
        f"az {cli} flexible-server parameter show -g <rg> {sname} <name> --name require_secure_transport",
        ["Open the server > Settings > Server parameters.", "Set require_secure_transport to ON and save.", "Make sure clients use SSL/TLS (sslmode=require / --ssl-mode=REQUIRED)."],
        f"az {cli} flexible-server parameter set -g <rg> {sname} <name> --name require_secure_transport --value on",
        f'resource "{cfgres}" "secure_transport" {{\n  name      = "require_secure_transport"\n  server_id = azurerm_{"postgresql" if eng == "PostgreSQL" else "mysql"}_flexible_server.this.id\n  value     = "on"\n}}',
        "Set require_secure_transport in your server module and audit it with Azure Policy.",
        [tls, "mcsb", "cis-azure"])

    GUIDANCE[f"{prefix}-004"] = g(
        5.3, 326, ["T1557", "T1040"],
        [("Weak TLS accepted", f"The {eng} server still negotiates TLS 1.0/1.1."),
         ("Downgrade risk", "A network attacker can force a weak version."),
         ("Compliance", "TLS 1.2+ is a common baseline requirement.")],
        ["Open the server > Settings > Server parameters.", f"Search for {tlsparam} and check the minimum version."],
        f"az {cli} flexible-server parameter show -g <rg> {sname} <name> --name {tlsparam}",
        ["Open the server > Settings > Server parameters.", f"Set {tlsparam} to {tlsval} (or higher) and save."],
        f"az {cli} flexible-server parameter set -g <rg> {sname} <name> --name {tlsparam} --value {tlsval}",
        f'resource "{cfgres}" "min_tls" {{\n  name      = "{tlsparam}"\n  server_id = azurerm_{"postgresql" if eng == "PostgreSQL" else "mysql"}_flexible_server.this.id\n  value     = "{tlsval}"\n}}',
        "Set the minimum TLS parameter in your module.",
        [tls, "mcsb", "cis-azure"])

    GUIDANCE[f"{prefix}-005"] = g(
        2.5, 693, ["T1485", "T1490"],
        [("Backups not protected from a regional outage", "Backups are kept only in the server's own region, so a regional disaster can lose both data and backups."),
         ("Slower recovery", "Cross-region restore is unavailable."),
         ("Cannot change later", "Geo-redundant backup is a create-time choice on flexible servers.")],
        ["Open the server > Settings > Compute + storage (or Backup).", "Check 'Geo-redundancy' is not enabled."],
        f"az {cli} flexible-server show -g <rg> -n <name> --query backup",
        ["Geo-redundant backup is chosen when the server is created.", "Create a new server with geo-redundant backup enabled, restore or migrate data, and cut over.",
         "Alternatively add a read replica in another region."],
        f"az {cli} flexible-server create -g <rg> -n <new-name> --geo-redundant-backup Enabled   # at creation time",
        f'resource "azurerm_{"postgresql" if eng == "PostgreSQL" else "mysql"}_flexible_server" "this" {{\n  # ...\n  geo_redundant_backup_enabled = true\n}}',
        "Choose geo-redundant backup at creation for servers that need regional-disaster recovery.",
        [bkp, "mcsb"])

    GUIDANCE[f"{prefix}-006"] = g(
        3.3, 308, ["T1078.004", "T1110"],
        [("Passwords only", "Only local password authentication is configured, so there is no central identity control or MFA."),
         ("Shared and long-lived secrets", "Database passwords tend to be shared and rarely rotated."),
         ("Entra ID gives lifecycle control", "Tokens expire, MFA and Conditional Access apply, and access follows the directory.")],
        ["Open the server > Security > Authentication.", "Check whether Microsoft Entra authentication is enabled."],
        f"az {cli} flexible-server show -g <rg> -n <name> --query authConfig" if eng == "PostgreSQL" else f"az {cli} flexible-server ad-admin list -g <rg> -s <name>",
        ["Open the server > Security > Authentication.", "Enable Microsoft Entra authentication and add an Entra administrator.", "Move applications to Entra tokens and then consider disabling password authentication."],
        f"az {cli} flexible-server ad-admin create -g <rg> -s <name> -u <admin-upn> -i <admin-object-id>",
        hint,
        "Create servers with Entra authentication and use managed identities for applications.",
        [ent, "cis-azure"])

    GUIDANCE[f"{prefix}-007"] = g(
        7.5, 1104, ["T1190", "T1068"],
        [("Engine no longer patched", f"This {eng} major version has reached end of community support."),
         ("Known flaws stay open", "New vulnerabilities will not be fixed in this version."),
         ("Upgrade effort grows", "Staying on old versions makes later upgrades harder.")],
        ["Open the server > Overview.", "Note the server version and compare with the vendor support policy (endoflife.date)."],
        f"az {cli} flexible-server show -g <rg> -n <name> --query version",
        ["Review the application compatibility for the next supported major version, test on a restored copy.", "Open the server > Settings > Overview and run the major version upgrade (maintenance window).", "Verify and update client drivers."],
        f"az {cli} flexible-server upgrade -g <rg> -n <name> --version <target-major-version>",
        f'resource "azurerm_{"postgresql" if eng == "PostgreSQL" else "mysql"}_flexible_server" "this" {{\n  # ...\n  version = "<supported-major-version>"\n}}',
        "Track database engine end-of-life dates and plan major upgrades at least a quarter ahead.",
        [ver, ("Product end-of-life dates", "https://endoflife.date/")])

    GUIDANCE[f"{prefix}-008"] = g(
        7.4, 1104, ["T1190", "T1068"],
        [("Retired service", f"Azure Database for {eng} Single Server is retired and no longer receives updates."),
         ("Security fixes stop", "Unpatched flaws accumulate."),
         ("Forced migration", "Microsoft migrates or shuts down remaining single servers, which is disruptive when unplanned.")],
        ["Open the server and read the retirement banner.", "Confirm the resource type is Microsoft.DBfor" + eng + "/servers (Single Server) rather than flexibleServers."],
        f"az resource show -g <rg> -n <name> --resource-type Microsoft.DBfor{eng}/servers --query sku",
        ["Plan a migration to Flexible Server using Microsoft's single-to-flexible migration tool.", "Test the application against a Flexible Server, then cut over in a maintenance window."],
        f"az {cli} flexible-server create -g <rg> -n <new-name>   # then migrate using the portal migration tool",
        f'resource "azurerm_{"postgresql" if eng == "PostgreSQL" else "mysql"}_flexible_server" "this" {{\n  name                = "<new-name>"\n  resource_group_name = "<rg>"\n  location            = "<region>"\n  # ... sku_name, version, administrator settings\n}}',
        "Do not create new Single Servers; deploy Flexible Server only.",
        [ver, "mcsb"])

    _pe_public(f"{prefix}-009", f"{eng} server", score=5.3,
               show=f"az {cli} flexible-server show -g <rg> -n <name> --query network.publicNetworkAccess",
               console="Open the server > Settings > Networking and review public network access.",
               cli=f"az {cli} flexible-server update -g <rg> -n <name> --public-access Disabled",
               tf=f'resource "azurerm_{"postgresql" if eng == "PostgreSQL" else "mysql"}_flexible_server" "this" {{\n  # ...\n  public_network_access_enabled = false\n}}',
               docs=[pub])


_db("AZ-PG", "PostgreSQL", "postgres", "azurerm_postgresql_flexible_server",
    'resource "azurerm_postgresql_flexible_server" "this" {\n  # ...\n  authentication {\n    active_directory_auth_enabled = true\n    password_auth_enabled         = true # set false once clients use Entra\n    tenant_id                     = data.azurerm_client_config.current.tenant_id\n  }\n}')
_db("AZ-MYSQL", "MySQL", "mysql", "azurerm_mysql_flexible_server",
    'resource "azurerm_mysql_flexible_server_active_directory_administrator" "this" {\n  server_id   = azurerm_mysql_flexible_server.this.id\n  identity_id = azurerm_user_assigned_identity.mysql.id\n  login       = "<admin-upn>"\n  object_id   = "<admin-object-id>"\n  tenant_id   = data.azurerm_client_config.current.tenant_id\n}')

# ----------------------------------------------------------------------------- Cosmos DB
GUIDANCE["AZ-COSMOS-001"] = g(
    7.5, 668, ["T1190", "T1530"],
    [("Database reachable from anywhere", "Public network access is on with no IP or virtual-network filters."),
     ("Key theft is enough", "Anyone who obtains an account key can read and write data from the internet."),
     ("Customer data at risk", "Cosmos DB commonly holds application and customer data.")],
    ["Open the account > Settings > Networking.", "Check 'Public network access' is All networks."],
    "az cosmosdb show -g <rg> -n <name> --query \"{public:publicNetworkAccess, ip:ipRules, vnet:isVirtualNetworkFilterEnabled}\"",
    ["Open the account > Settings > Networking.", "Choose 'Selected networks' and add your VNets / client IPs, or add a private endpoint and disable public access."],
    "az cosmosdb update -g <rg> -n <name> --ip-range-filter 203.0.113.0/24\n# or, with a private endpoint in place:\naz cosmosdb update -g <rg> -n <name> --public-network-access DISABLED",
    'resource "azurerm_cosmosdb_account" "this" {\n  name                          = "<name>"\n  resource_group_name           = "<rg>"\n  location                      = "<region>"\n'
    '  offer_type                    = "Standard"\n  kind                          = "GlobalDocumentDB"\n  public_network_access_enabled = false\n  # consistency_policy, geo_location ...\n}',
    "Create accounts with public access disabled and audit with the built-in 'Azure Cosmos DB accounts should have firewall rules' policy.",
    ["az-cosmos-fw", "az-cosmos-pe", "mcsb", "cis-azure"])

GUIDANCE["AZ-COSMOS-002"] = g(
    5.4, 522, ["T1078.004", "T1552"],
    [("Shared keys give full access", "Account keys grant full data-plane access and cannot be scoped or tied to a person."),
     ("Hard to audit and rotate", "Keys leak into config and code; rotation breaks applications."),
     ("Entra RBAC is better", "Role-based access with managed identities gives least privilege and an audit trail.")],
    ["Open the account > Settings > Keys and check the usage.", "Check disableLocalAuth on the account."],
    "az cosmosdb show -g <rg> -n <name> --query disableLocalAuth",
    ["Move applications to Microsoft Entra authentication with Cosmos DB data-plane RBAC roles.", "Then open the account and disable key-based authentication (disableLocalAuth)."],
    "az resource update --ids $(az cosmosdb show -g <rg> -n <name> --query id -o tsv) --set properties.disableLocalAuth=true",
    'resource "azurerm_cosmosdb_account" "this" {\n  name                           = "<name>"\n  resource_group_name            = "<rg>"\n  location                       = "<region>"\n'
    '  offer_type                     = "Standard"\n  local_authentication_disabled  = true\n  # kind, consistency_policy, geo_location ...\n}',
    "Use Entra RBAC from the start and keep local authentication disabled.",
    ["az-cosmos-rbac", "mcsb", "cis-azure"])

_tls("AZ-COSMOS-003", "Cosmos DB account",
     show="az cosmosdb show -g <rg> -n <name> --query minimalTlsVersion",
     console="Open the account > Settings > Networking (or the account's properties) and set the minimum TLS version to TLS 1.2.",
     cli="az cosmosdb update -g <rg> -n <name> --minimal-tls-version Tls12",
     tf='resource "azurerm_cosmosdb_account" "this" {\n  name                = "<name>"\n  resource_group_name = "<rg>"\n  location            = "<region>"\n'
        '  offer_type          = "Standard"\n  minimal_tls_version = "Tls12"\n  # kind, consistency_policy, geo_location ...\n}',
     docs=["az-cosmos-fw"])

GUIDANCE["AZ-COSMOS-004"] = g(
    2.6, 693, ["T1485", "T1490"],
    [("Backups tied to a region or zone", "Periodic backups sit in local or zone-redundant storage and would not survive a regional disaster."),
     ("Longer recovery", "Data could be unrecoverable after a regional loss."),
     ("Cheap to change", "Switching backup redundancy to Geo is a setting.")],
    ["Open the account > Settings > Backup & Restore.", "Check the backup storage redundancy."],
    "az cosmosdb show -g <rg> -n <name> --query backupPolicy",
    ["Open the account > Settings > Backup & Restore.", "Set Backup storage redundancy to Geo-redundant and save."],
    "az cosmosdb update -g <rg> -n <name> --backup-redundancy Geo",
    'resource "azurerm_cosmosdb_account" "this" {\n  # ...\n  backup {\n    type                = "Periodic"\n    storage_redundancy  = "Geo"\n  }\n}',
    "Choose Geo redundancy for production accounts or enable continuous backup.",
    ["az-cosmos-bkp", "mcsb"])

_pe_public("AZ-COSMOS-005", "Cosmos DB account", score=5.3,
           show="az cosmosdb show -g <rg> -n <name> --query publicNetworkAccess",
           console="Open the account > Settings > Networking and review 'Public network access'.",
           cli="az cosmosdb update -g <rg> -n <name> --public-network-access DISABLED",
           tf='resource "azurerm_cosmosdb_account" "this" {\n  # ...\n  public_network_access_enabled = false\n}',
           docs=["az-cosmos-pe"])

# ----------------------------------------------------------------------------- Redis
GUIDANCE["AZ-REDIS-001"] = g(
    7.5, 319, ["T1040", "T1557"],
    [("Cleartext Redis traffic", "The non-TLS port 6379 is enabled, so keys, commands and data cross the network unencrypted."),
     ("Access key theft", "The access key travels with the connection and can be sniffed."),
     ("Easy to fix", "Clients can use TLS on port 6380.")],
    ["Open the cache > Settings > Advanced settings.", "Check 'Allow access only via SSL' is No."],
    "az redis show -g <rg> -n <name> --query enableNonSslPort",
    ["Open the cache > Settings > Advanced settings.", "Set 'Allow access only via SSL' to Yes and save.", "Point clients to port 6380 with TLS."],
    "az redis update -g <rg> -n <name> --set enableNonSslPort=false",
    'resource "azurerm_redis_cache" "this" {\n  name                = "<name>"\n  resource_group_name = "<rg>"\n  location            = "<region>"\n  capacity            = 1\n  family              = "C"\n  sku_name            = "Standard"\n'
    '  non_ssl_port_enabled = false # azurerm 4.x; "enable_non_ssl_port" in 3.x\n}',
    "Set the non-TLS port off in your module and audit with the built-in 'Only secure connections to your Azure Cache for Redis should be enabled' policy.",
    ["az-redis", "az-redis-sec", "mcsb"])

_tls("AZ-REDIS-002", "Redis cache", show="az redis show -g <rg> -n <name> --query minimumTlsVersion",
     console="Open the cache > Settings > Advanced settings and set 'Minimum TLS version' to 1.2.",
     cli="az redis update -g <rg> -n <name> --set minimumTlsVersion=1.2",
     tf='resource "azurerm_redis_cache" "this" {\n  name                = "<name>"\n  resource_group_name = "<rg>"\n  location            = "<region>"\n  capacity            = 1\n  family              = "C"\n  sku_name            = "Standard"\n  minimum_tls_version = "1.2"\n}',
     docs=["az-redis"])

GUIDANCE["AZ-REDIS-003"] = g(
    7.5, 668, ["T1190", "T1133"],
    [("Cache reachable from anywhere", "Public access is enabled with no firewall rules (or an allow-all rule)."),
     ("Data and key exposure", "Caches hold session data and tokens; the access key is the only barrier."),
     ("Abuse as a pivot", "Attackers use open caches to store data or reach back-end services.")],
    ["Open the cache > Settings > Firewall.", "Check there are no rules or one that spans all addresses."],
    "az redis firewall-rules list -g <rg> -n <name> -o table",
    ["Open the cache > Settings > Firewall and remove allow-all rules.", "Add specific client IP ranges, or use a private endpoint and disable public network access."],
    "az redis firewall-rules delete -g <rg> -n <name> --rule-name <rule-name>\naz redis update -g <rg> -n <name> --set publicNetworkAccess=Disabled   # with a private endpoint",
    'resource "azurerm_redis_cache" "this" {\n  name                          = "<name>"\n  resource_group_name           = "<rg>"\n  location                      = "<region>"\n  capacity                      = 1\n  family                        = "C"\n  sku_name                      = "Standard"\n  public_network_access_enabled = false\n}',
    "Deploy caches with a private endpoint and disabled public access.",
    ["az-redis", "az-pe", "mcsb"])

GUIDANCE["AZ-REDIS-004"] = g(
    3.4, 522, ["T1078.004", "T1552"],
    [("Shared access keys", "Access keys give full access and are shared between clients."),
     ("Hard to attribute and rotate", "Keys leak into config; rotation disrupts applications."),
     ("Entra ID is better", "Microsoft Entra authentication gives per-identity access and short-lived tokens.")],
    ["Open the cache > Settings > Authentication.", "Check 'Access keys authentication' is enabled."],
    "az redis show -g <rg> -n <name> --query redisConfiguration",
    ["Open the cache > Settings > Authentication.", "Enable Microsoft Entra authentication, add the clients' identities as Redis users.", "Once migrated, disable access-key authentication."],
    "az redis show -g <rg> -n <name> --query redisConfiguration   # then configure Entra authentication in the portal and disable access keys",
    'resource "azurerm_redis_cache" "this" {\n  # ...\n  redis_configuration {\n    active_directory_authentication_enabled = true\n    authentication_enabled                  = false # disable access keys once clients use Entra\n  }\n}',
    "Use Entra authentication for new caches and keep access keys off.",
    ["az-redis", "az-redis-sec"])

GUIDANCE["AZ-REDIS-005"] = g(
    7.4, 1104, ["T1190", "T1068"],
    [("Retired Redis version", "The Redis version is retired on Azure Cache for Redis and no longer receives fixes."),
     ("Known flaws stay open", "New vulnerabilities in the engine are not patched."),
     ("Forced upgrade", "Azure upgrades retired versions on its own schedule.")],
    ["Open the cache > Overview and note the Redis version.", "Compare with the Azure Cache for Redis version support policy."],
    "az redis show -g <rg> -n <name> --query redisVersion",
    ["Test your application against the newer Redis version.", "Open the cache > Settings > Advanced settings (or Overview) and upgrade the Redis version, in a maintenance window."],
    "az redis update -g <rg> -n <name> --set redisVersion=<supported-version>",
    'resource "azurerm_redis_cache" "this" {\n  # ...\n  redis_version = "<supported-version>"\n}',
    "Track the Azure Cache for Redis version lifecycle and upgrade ahead of retirement.",
    ["az-redis", ("Product end-of-life dates", "https://endoflife.date/")])

_pe_public("AZ-REDIS-006", "Redis cache", score=5.3,
           show="az redis show -g <rg> -n <name> --query publicNetworkAccess",
           console="Open the cache > Settings > Private Endpoint / Firewall and review 'Public network access'.",
           cli="az redis update -g <rg> -n <name> --set publicNetworkAccess=Disabled",
           tf='resource "azurerm_redis_cache" "this" {\n  # ...\n  public_network_access_enabled = false\n}',
           docs=["az-redis"])

# ----------------------------------------------------------------------------- SQL Managed Instance
GUIDANCE["AZ-SQLMI-001"] = g(
    7.7, 668, ["T1190", "T1110"],
    [("Managed instance public endpoint open", "The public data endpoint (TCP 3342) is enabled and the subnet NSG allows it from any address."),
     ("Private-by-design service exposed", "A managed instance normally lives only in its VNet."),
     ("Credential attacks", "Sign-in attempts from the internet reach the instance directly.")],
    ["Open the managed instance > Security > Networking.", "Check 'Public endpoint (data)' is Enabled.", "Check the subnet NSG rule for port 3342."],
    "az sql mi show -g <rg> -n <name> --query publicDataEndpointEnabled",
    ["Open the managed instance > Security > Networking.", "Set 'Public endpoint (data)' to Disable and save.", "If it must stay on, restrict the NSG rule for port 3342 to specific source IPs."],
    "az sql mi update -g <rg> -n <name> --public-data-endpoint-enabled false",
    'resource "azurerm_mssql_managed_instance" "this" {\n  name                         = "<name>"\n  resource_group_name          = "<rg>"\n  location                     = "<region>"\n'
    '  public_data_endpoint_enabled = false\n  # ... sku_name, vcores, storage_size_in_gb, subnet_id, license_type, administrator_login\n}',
    "Keep the public endpoint off by default and audit with 'Public network access on Azure SQL Managed Instances should be disabled'.",
    ["az-mi-pub", "az-sql-net", "mcsb"])

_tls("AZ-SQLMI-002", "SQL Managed Instance", show="az sql mi show -g <rg> -n <name> --query minimalTlsVersion",
     console="Open the managed instance > Security > Networking > Connectivity and set 'Minimum TLS version' to 1.2.",
     cli="az sql mi update -g <rg> -n <name> --minimal-tls-version 1.2",
     tf='resource "azurerm_mssql_managed_instance" "this" {\n  # ...\n  minimum_tls_version = "1.2"\n}', docs=["az-sql-tls"])

GUIDANCE["AZ-SQLMI-003"] = g(
    3.3, 308, ["T1078.004", "T1110"],
    [("SQL authentication available", "SQL logins with passwords can be used, so Entra controls such as MFA are bypassed."),
     ("Password guessing", "SQL logins are a target for brute force."),
     ("Entra-only closes the gap", "Microsoft Entra-only authentication disables SQL logins.")],
    ["Open the managed instance > Settings > Microsoft Entra ID.", "Check 'Microsoft Entra-only authentication' is Off."],
    "az sql mi ad-only-auth get -g <rg> -n <name>",
    ["Set a Microsoft Entra admin and move applications to Entra authentication.", "Open the managed instance > Settings > Microsoft Entra ID and enable 'Microsoft Entra-only authentication'."],
    "az sql mi ad-only-auth enable -g <rg> -n <name>",
    'resource "azurerm_mssql_managed_instance_active_directory_administrator" "this" {\n  managed_instance_id         = azurerm_mssql_managed_instance.this.id\n  login_username              = "<admin-name>"\n'
    '  object_id                   = "<admin-object-id>"\n  tenant_id                   = data.azurerm_client_config.current.tenant_id\n  azuread_authentication_only = true\n}',
    "Create new instances with Entra-only authentication.",
    ["az-sql-net", "cis-azure"])
