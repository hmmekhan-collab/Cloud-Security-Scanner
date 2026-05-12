"""
Cloud Security Analyzer (CSA) - Azure Scanner
University of Wah FYP - Azure Security Checks
Categories: iam, storage, vm, nsg, keyvault, sql, monitor
"""

try:
    from azure.identity import ClientSecretCredential
    from azure.mgmt.resource import SubscriptionClient
    from azure.mgmt.authorization import AuthorizationManagementClient
    from azure.mgmt.storage import StorageManagementClient
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.keyvault import KeyVaultManagementClient
    from azure.mgmt.sql import SqlManagementClient
    from azure.mgmt.monitor import MonitorManagementClient
    from azure.mgmt.security import SecurityCenter
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False


AZURE_COMPLIANCE_MAP = {
    "CIS-AZ-1.1":  "CIS Azure v2.0 §1.1",
    "CIS-AZ-1.3":  "CIS Azure v2.0 §1.3",
    "CIS-AZ-2.1":  "CIS Azure v2.0 §2.1",
    "CIS-AZ-2.3":  "CIS Azure v2.0 §2.3",
    "CIS-AZ-3.1":  "CIS Azure v2.0 §3.1",
    "CIS-AZ-3.2":  "CIS Azure v2.0 §3.2",
    "CIS-AZ-4.1":  "CIS Azure v2.0 §4.1",
    "CIS-AZ-4.3":  "CIS Azure v2.0 §4.3",
    "CIS-AZ-5.1":  "CIS Azure v2.0 §5.1",
    "CIS-AZ-6.1":  "CIS Azure v2.0 §6.1",
    "CIS-AZ-7.1":  "CIS Azure v2.0 §7.1",
    "CIS-AZ-8.1":  "CIS Azure v2.0 §8.1",
    "NIST-PR.AC-1":"NIST CSF PR.AC-1",
    "NIST-PR.DS-1":"NIST CSF PR.DS-1",
    "MSWAF-SR-1":  "MS Cloud Well-Arch: Security",
}


class AzureScanner:
    def __init__(self):
        self.findings = []
        self._seen = set()

    def run_scan(self, account, categories):
        self.findings = []
        self._seen = set()

        if not AZURE_AVAILABLE:
            return self._demo_findings(account, categories)

        # Parse credentials from account fields:
        # access_key  = tenant_id
        # secret_key  = JSON with client_id + client_secret
        # region      = subscription_id
        import json as _json
        tenant_id = getattr(account, "access_key", "")
        subscription_id = getattr(account, "region", "")

        raw_secret = getattr(account, "secret_key", "{}")
        try:
            secret_data = _json.loads(raw_secret)
            client_id = secret_data.get("client_id", "")
            client_secret = secret_data.get("client_secret", "")
        except Exception:
            client_id = raw_secret
            client_secret = ""

        if not all([tenant_id, client_id, client_secret, subscription_id]):
            return self._demo_findings(account, categories)

        try:
            cred = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
            )
            # Verify credentials
            sub_client = SubscriptionClient(cred)
            next(sub_client.subscriptions.list())
        except Exception as e:
            raise Exception(f"Azure Authentication failed: {e}")

        dispatch = {
            "iam":      lambda: self._iam(cred, subscription_id),
            "storage":  lambda: self._storage(cred, subscription_id),
            "vm":       lambda: self._vm(cred, subscription_id),
            "nsg":      lambda: self._nsg(cred, subscription_id),
            "keyvault": lambda: self._keyvault(cred, subscription_id),
            "sql":      lambda: self._sql(cred, subscription_id),
            "monitor":  lambda: self._monitor(cred, subscription_id),
        }

        for cat in categories:
            if cat in dispatch:
                try:
                    dispatch[cat]()
                except Exception as e:
                    self._add(cat.upper(), "error", f"{cat.upper()} Scan Error", "Low",
                              f"Could not complete {cat.upper()} checks: {e}",
                              f"Verify Azure RBAC permissions include Reader on the subscription.", "MSWAF-SR-1")

        return self.findings

    # ── helpers ──────────────────────────────────────────────────────────────────

    def _add(self, rt, rid, name, sev, desc, rec, comp):
        key = f"{rt}:{rid}:{name}"
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append({
            "resource_type": rt,
            "resource_id": str(rid)[:200],
            "check_name": name,
            "severity": sev,
            "description": desc,
            "recommendation": rec,
            "compliance": AZURE_COMPLIANCE_MAP.get(comp, comp),
        })

    def _f(self, rt, rid, name, sev, desc, rec, comp):
        return {
            "resource_type": rt, "resource_id": rid,
            "check_name": name, "severity": sev,
            "description": desc, "recommendation": rec,
            "compliance": AZURE_COMPLIANCE_MAP.get(comp, comp),
        }

    # ── IAM / Azure AD ────────────────────────────────────────────────────────────

    def _iam(self, cred, sub_id):
        auth = AuthorizationManagementClient(cred, sub_id)
        try:
            for ra in auth.role_assignments.list_for_subscription():
                # Check for Owner role (built-in ID)
                if ra.role_definition_id and ra.role_definition_id.endswith("8e3af657-a8ff-443c-a75c-2fe8c4bcb635"):
                    principal = ra.principal_id or "unknown"
                    self._add("IAM", f"assignment/{principal}",
                        f"Owner Role Assigned: {principal[:16]}",
                        "High",
                        f"Principal '{principal[:32]}' has Owner role on the subscription. "
                        "Owner can do anything including modifying security controls.",
                        "Remove Owner and assign least-privilege roles (Contributor/Reader).",
                        "CIS-AZ-1.1")
        except Exception:
            pass

        try:
            # Check for too many subscription owners (if manageable)
            owners = [ra for ra in auth.role_assignments.list_for_subscription()
                      if ra.role_definition_id and ra.role_definition_id.endswith("8e3af657-a8ff-443c-a75c-2fe8c4bcb635")]
            if len(owners) > 3:
                self._add("IAM", "subscription", "Too Many Subscription Owners",
                    "Medium",
                    f"There are {len(owners)} Owner role assignments. CIS recommends max 3.",
                    "Reduce Owners to 2-3 named individuals. Use PIM for JIT access.",
                    "CIS-AZ-1.3")
        except Exception:
            pass

    # ── Storage Accounts ──────────────────────────────────────────────────────────

    def _storage(self, cred, sub_id):
        storage_client = StorageManagementClient(cred, sub_id)
        try:
            for account in storage_client.storage_accounts.list():
                name = account.name
                rg = account.id.split("/")[4] if account.id else "unknown"

                # Public blob access
                if getattr(account, "allow_blob_public_access", True):
                    self._add("Storage", name, f"Storage Public Blob Access Enabled: {name}",
                        "High",
                        f"Storage account '{name}' allows anonymous public blob access. "
                        "Sensitive data may be publicly readable.",
                        "Set allowBlobPublicAccess=false on the storage account.",
                        "CIS-AZ-3.1")

                # HTTPS-only
                if not getattr(account, "enable_https_traffic_only", True):
                    self._add("Storage", name, f"Storage HTTP Traffic Allowed: {name}",
                        "High",
                        f"Storage account '{name}' allows unencrypted HTTP. Data in transit exposed.",
                        "Enable 'Secure transfer required' (HTTPS only).",
                        "CIS-AZ-3.1")

                # Minimum TLS
                min_tls = getattr(account, "minimum_tls_version", None)
                if min_tls and min_tls != "TLS1_2":
                    self._add("Storage", name, f"Storage Minimum TLS Not 1.2: {name}",
                        "Medium",
                        f"Storage account '{name}' minimum TLS is {min_tls}. TLS 1.0/1.1 are deprecated.",
                        "Set minimumTlsVersion to TLS1_2.",
                        "CIS-AZ-3.2")

                # Soft delete check for blobs
                try:
                    blob_props = storage_client.blob_services.get_service_properties(rg, name)
                    sd = getattr(blob_props, "delete_retention_policy", None)
                    if not sd or not getattr(sd, "enabled", False):
                        self._add("Storage", name, f"Storage Soft Delete Disabled: {name}",
                            "Medium",
                            f"Blob soft delete is off for '{name}'. Accidental deletions are unrecoverable.",
                            "Enable blob soft delete with at least 7-day retention.",
                            "CIS-AZ-3.2")
                except Exception:
                    pass

                # Infrastructure encryption
                if not getattr(account, "encryption", None) or \
                   not getattr(account.encryption, "require_infrastructure_encryption", False):
                    self._add("Storage", name, f"Storage Infrastructure Encryption Disabled: {name}",
                        "Low",
                        f"Double encryption not enabled on '{name}'.",
                        "Enable infrastructure encryption for extra security layer.",
                        "NIST-PR.DS-1")

                # No network restrictions (allow all)
                net_rules = getattr(account, "network_rule_set", None)
                if net_rules and getattr(net_rules, "default_action", "Allow") == "Allow":
                    self._add("Storage", name, f"Storage Allows All Network Traffic: {name}",
                        "Medium",
                        f"Storage account '{name}' network rules default to Allow. "
                        "All IPs can reach the storage account.",
                        "Set defaultAction=Deny and whitelist specific VNets/IPs.",
                        "CIS-AZ-3.1")

        except Exception:
            pass

    # ── Virtual Machines ──────────────────────────────────────────────────────────

    def _vm(self, cred, sub_id):
        compute = ComputeManagementClient(cred, sub_id)
        try:
            for vm in compute.virtual_machines.list_all():
                name = vm.name

                # Unmanaged disks
                if vm.storage_profile and vm.storage_profile.os_disk:
                    if vm.storage_profile.os_disk.managed_disk is None:
                        self._add("VM", name, f"VM Uses Unmanaged Disk: {name}",
                            "Medium",
                            f"VM '{name}' uses unmanaged OS disk. Unmanaged disks are not covered by Azure backup.",
                            "Migrate to Managed Disks for better security and resilience.",
                            "CIS-AZ-7.1")

                # Disk encryption
                if vm.storage_profile and vm.storage_profile.os_disk:
                    enc = vm.storage_profile.os_disk.encryption_settings
                    if not enc or not getattr(enc, "enabled", False):
                        # Check for Azure Disk Encryption via extension
                        has_ade = False
                        if vm.resources:
                            has_ade = any("AzureDiskEncryption" in (r.type or "") for r in vm.resources)
                        if not has_ade:
                            self._add("VM", name, f"VM OS Disk Not Encrypted: {name}",
                                "High",
                                f"VM '{name}' OS disk does not have Azure Disk Encryption enabled. "
                                "Data at rest is not encrypted.",
                                "Enable Azure Disk Encryption (ADE) using Key Vault.",
                                "CIS-AZ-7.1")

                # Boot diagnostics
                if not vm.diagnostics_profile or \
                   not vm.diagnostics_profile.boot_diagnostics or \
                   not vm.diagnostics_profile.boot_diagnostics.enabled:
                    self._add("VM", name, f"VM Boot Diagnostics Disabled: {name}",
                        "Low",
                        f"VM '{name}' does not have boot diagnostics enabled. "
                        "Troubleshooting VM boot issues will be difficult.",
                        "Enable boot diagnostics to a storage account.",
                        "MSWAF-SR-1")

        except Exception:
            pass

    # ── Network Security Groups ───────────────────────────────────────────────────

    def _nsg(self, cred, sub_id):
        network = NetworkManagementClient(cred, sub_id)
        DANGEROUS_PORTS = {
            22: ("SSH", "High", "CIS-AZ-6.1"),
            3389: ("RDP", "High", "CIS-AZ-6.1"),
            3306: ("MySQL", "Medium", "CIS-AZ-6.1"),
            5432: ("PostgreSQL", "Medium", "CIS-AZ-6.1"),
            1433: ("MSSQL", "Medium", "CIS-AZ-6.1"),
            27017: ("MongoDB", "High", "CIS-AZ-6.1"),
            6379: ("Redis", "High", "CIS-AZ-6.1"),
            9200: ("Elasticsearch", "High", "CIS-AZ-6.1"),
            2375: ("Docker-API", "Critical", "CIS-AZ-6.1"),
            23: ("Telnet", "High", "CIS-AZ-6.1"),
            445: ("SMB", "High", "CIS-AZ-6.1"),
        }
        try:
            for nsg in network.network_security_groups.list_all():
                name = nsg.name
                if not nsg.security_rules:
                    continue
                for rule in nsg.security_rules:
                    if rule.direction != "Inbound":
                        continue
                    if rule.access != "Allow":
                        continue
                    src = rule.source_address_prefix or ""
                    if src not in ("*", "Internet", "0.0.0.0/0"):
                        continue

                    # All traffic open
                    if rule.destination_port_range == "*" and rule.protocol in ("*", "Tcp"):
                        self._add("NSG", name, f"NSG All Inbound Traffic Open: {name}",
                            "Critical",
                            f"NSG '{name}' rule '{rule.name}' allows ALL inbound TCP from Internet.",
                            "Remove this rule and add specific port allowances.",
                            "CIS-AZ-6.1")
                        continue

                    # Check specific ports
                    port_range = rule.destination_port_range or ""
                    for port, (pname, sev, comp) in DANGEROUS_PORTS.items():
                        try:
                            if "-" in port_range:
                                lo, hi = port_range.split("-")
                                exposed = int(lo) <= port <= int(hi)
                            else:
                                exposed = str(port) == port_range
                        except Exception:
                            exposed = False

                        if exposed:
                            self._add("NSG", name,
                                f"NSG Exposes {pname}({port}) to Internet: {name}",
                                sev,
                                f"NSG '{name}' allows inbound {pname} port {port} from Internet (0.0.0.0/0).",
                                f"Restrict port {port} to known IP ranges or route through VPN/Bastion.",
                                comp)
        except Exception:
            pass

    # ── Key Vault ──────────────────────────────────────────────────────────────────

    def _keyvault(self, cred, sub_id):
        kv_client = KeyVaultManagementClient(cred, sub_id)
        try:
            for vault in kv_client.vaults.list_by_subscription():
                name = vault.name
                props = vault.properties

                if not getattr(props, "enable_soft_delete", False):
                    self._add("KeyVault", name, f"Key Vault Soft Delete Disabled: {name}",
                        "High",
                        f"Key Vault '{name}' does not have soft delete enabled. "
                        "Deleted secrets/keys cannot be recovered.",
                        "Enable soft delete with at least 90-day retention period.",
                        "CIS-AZ-8.1")

                if not getattr(props, "enable_purge_protection", False):
                    self._add("KeyVault", name, f"Key Vault Purge Protection Disabled: {name}",
                        "High",
                        f"Key Vault '{name}' can be permanently purged immediately after deletion. "
                        "No recovery window.",
                        "Enable purge protection to prevent permanent deletion.",
                        "CIS-AZ-8.1")

                # Network access
                net = getattr(props, "network_acls", None)
                if not net or getattr(net, "default_action", "Allow") == "Allow":
                    self._add("KeyVault", name, f"Key Vault Public Network Access: {name}",
                        "Medium",
                        f"Key Vault '{name}' is accessible from all networks. "
                        "Any IP can attempt to access secrets.",
                        "Restrict Key Vault to specific VNets or use Private Endpoint.",
                        "CIS-AZ-8.1")

                # Access policies — check for wildcard/overly broad permissions
                for ap in getattr(props, "access_policies", []) or []:
                    perms = getattr(ap, "permissions", None)
                    if perms:
                        key_p = getattr(perms, "keys", []) or []
                        sec_p = getattr(perms, "secrets", []) or []
                        if "all" in [p.lower() for p in key_p + sec_p]:
                            obj_id = getattr(ap, "object_id", "unknown")
                            self._add("KeyVault", name,
                                f"Key Vault All Permissions Granted: {name}",
                                "High",
                                f"Key Vault '{name}' grants ALL permissions to principal '{obj_id[:24]}'. "
                                "This violates least privilege.",
                                "Restrict Key Vault access policies to minimum required permissions.",
                                "NIST-PR.AC-1")
        except Exception:
            pass

    # ── Azure SQL ─────────────────────────────────────────────────────────────────

    def _sql(self, cred, sub_id):
        sql_client = SqlManagementClient(cred, sub_id)
        try:
            for rg_iter in sql_client.servers.list():
                server = rg_iter
                server_name = server.name
                rg_name = server.id.split("/")[4] if server.id else "unknown"

                # TDE (Transparent Data Encryption)
                for db in sql_client.databases.list_by_server(rg_name, server_name):
                    db_name = db.name
                    if db_name == "master":
                        continue
                    try:
                        tde = sql_client.transparent_data_encryptions.get(rg_name, server_name, db_name, "current")
                        if getattr(tde, "status", "").lower() != "enabled":
                            self._add("SQL", f"{server_name}/{db_name}",
                                f"SQL TDE Disabled: {db_name}",
                                "High",
                                f"Azure SQL database '{db_name}' on server '{server_name}' has "
                                "Transparent Data Encryption disabled. Data at rest is unencrypted.",
                                "Enable TDE on the database.",
                                "CIS-AZ-4.1")
                    except Exception:
                        pass

                # Auditing
                try:
                    audit = sql_client.server_blob_auditing_policies.get(rg_name, server_name)
                    if getattr(audit, "state", "").lower() != "enabled":
                        self._add("SQL", server_name, f"SQL Auditing Disabled: {server_name}",
                            "High",
                            f"SQL Server '{server_name}' auditing is disabled. "
                            "Database activity is not logged.",
                            "Enable SQL Server Auditing with 90+ day retention.",
                            "CIS-AZ-4.3")
                except Exception:
                    pass

                # Advanced Threat Protection
                try:
                    atp = sql_client.server_advanced_threat_protection_settings.get(
                        rg_name, server_name, "Default")
                    if getattr(atp, "state", "").lower() not in ("enabled",):
                        self._add("SQL", server_name,
                            f"SQL Advanced Threat Protection Disabled: {server_name}",
                            "Medium",
                            f"Advanced Threat Protection not enabled on SQL Server '{server_name}'. "
                            "SQL injection and anomaly attacks go undetected.",
                            "Enable Advanced Threat Protection (Microsoft Defender for SQL).",
                            "MSWAF-SR-1")
                except Exception:
                    pass

                # Public access
                if getattr(server, "public_network_access", "Enabled") == "Enabled":
                    self._add("SQL", server_name, f"SQL Server Public Access Enabled: {server_name}",
                        "High",
                        f"SQL Server '{server_name}' is accessible from public internet. "
                        "It should be restricted to VNet or private endpoint.",
                        "Disable public network access and use Private Endpoint.",
                        "CIS-AZ-4.1")

        except Exception:
            pass

    # ── Monitor / Logging ─────────────────────────────────────────────────────────

    def _monitor(self, cred, sub_id):
        monitor = MonitorManagementClient(cred, sub_id)

        # Check diagnostic settings exist for subscription
        try:
            diag_settings = list(monitor.diagnostic_settings.list(
                f"/subscriptions/{sub_id}"))
            if not diag_settings:
                self._add("Monitor", "subscription",
                    "No Subscription Diagnostic Settings",
                    "High",
                    "No diagnostic/activity log settings found for the subscription. "
                    "Admin operations are not being logged or exported.",
                    "Create a diagnostic setting to export Activity Logs to Log Analytics or Storage.",
                    "CIS-AZ-5.1")
        except Exception:
            pass

        # Check activity log alerts exist
        try:
            alerts = list(monitor.activity_log_alerts.list_by_subscription_id())
            if not alerts:
                self._add("Monitor", "subscription",
                    "No Activity Log Alerts Configured",
                    "Medium",
                    "No activity log alerts found. Security-critical events (policy changes, "
                    "firewall changes) will not trigger notifications.",
                    "Create activity log alerts for critical operations: "
                    "delete policy assignment, create/update/delete NSG, etc.",
                    "CIS-AZ-5.1")
        except Exception:
            pass

    # ── Demo Data ──────────────────────────────────────────────────────────────────

    def _demo_findings(self, account, categories):
        ALL = {
            "iam": [
                self._f("IAM", "assignment/owner-principal-abc123",
                    "Owner Role Assigned: owner-principal-abc123", "High",
                    "Principal 'owner-principal-abc123' has Owner role on the subscription. "
                    "Owner can modify all security controls.",
                    "Replace Owner with least-privilege roles (Contributor/Reader).",
                    "CIS-AZ-1.1"),
                self._f("IAM", "subscription",
                    "Too Many Subscription Owners", "Medium",
                    "5 Owner role assignments found. CIS recommends max 3.",
                    "Reduce Owners to 2-3. Use PIM for JIT privileged access.",
                    "CIS-AZ-1.3"),
            ],
            "storage": [
                self._f("Storage", "prodstorageacct",
                    "Storage Public Blob Access Enabled: prodstorageacct", "High",
                    "Storage account 'prodstorageacct' allows anonymous public blob access. "
                    "Sensitive containers may be exposed.",
                    "Set allowBlobPublicAccess=false.",
                    "CIS-AZ-3.1"),
                self._f("Storage", "backupstorage",
                    "Storage HTTP Traffic Allowed: backupstorage", "High",
                    "Storage account 'backupstorage' allows unencrypted HTTP connections.",
                    "Enable 'Secure transfer required'.",
                    "CIS-AZ-3.1"),
                self._f("Storage", "logstorage",
                    "Storage Minimum TLS Not 1.2: logstorage", "Medium",
                    "Storage account 'logstorage' minimum TLS is TLS1_0. Deprecated protocol.",
                    "Set minimumTlsVersion to TLS1_2.",
                    "CIS-AZ-3.2"),
                self._f("Storage", "devstorageacct",
                    "Storage Soft Delete Disabled: devstorageacct", "Medium",
                    "Blob soft delete disabled. Accidental deletions are unrecoverable.",
                    "Enable soft delete with 7-day retention.",
                    "CIS-AZ-3.2"),
                self._f("Storage", "appstorageacct",
                    "Storage Allows All Network Traffic: appstorageacct", "Medium",
                    "Network rules default to Allow. All IPs can reach the storage account.",
                    "Set defaultAction=Deny and whitelist specific VNets.",
                    "CIS-AZ-3.1"),
            ],
            "vm": [
                self._f("VM", "prod-vm-001",
                    "VM OS Disk Not Encrypted: prod-vm-001", "High",
                    "VM 'prod-vm-001' OS disk does not have Azure Disk Encryption (ADE). "
                    "Data at rest is unprotected.",
                    "Enable ADE using Azure Key Vault.",
                    "CIS-AZ-7.1"),
                self._f("VM", "dev-vm-002",
                    "VM Uses Unmanaged Disk: dev-vm-002", "Medium",
                    "VM 'dev-vm-002' uses unmanaged OS disk. Not covered by managed backup.",
                    "Migrate to Managed Disks.",
                    "CIS-AZ-7.1"),
                self._f("VM", "worker-vm-003",
                    "VM Boot Diagnostics Disabled: worker-vm-003", "Low",
                    "Boot diagnostics disabled. VM startup issues cannot be diagnosed.",
                    "Enable boot diagnostics to a storage account.",
                    "MSWAF-SR-1"),
            ],
            "nsg": [
                self._f("NSG", "web-nsg",
                    "NSG All Inbound Traffic Open: web-nsg", "Critical",
                    "NSG 'web-nsg' allows ALL inbound TCP from Internet (0.0.0.0/0). "
                    "Complete attack surface exposed.",
                    "Remove all-traffic rule. Specify only required ports.",
                    "CIS-AZ-6.1"),
                self._f("NSG", "mgmt-nsg",
                    "NSG Exposes SSH(22) to Internet: mgmt-nsg", "High",
                    "NSG 'mgmt-nsg' allows SSH port 22 from Internet. Brute-force target.",
                    "Restrict SSH to known IP ranges or use Azure Bastion.",
                    "CIS-AZ-6.1"),
                self._f("NSG", "mgmt-nsg",
                    "NSG Exposes RDP(3389) to Internet: mgmt-nsg", "High",
                    "NSG 'mgmt-nsg' allows RDP port 3389 from Internet. Major attack vector.",
                    "Close RDP or restrict to known IPs. Use Azure Bastion instead.",
                    "CIS-AZ-6.1"),
                self._f("NSG", "db-nsg",
                    "NSG Exposes MSSQL(1433) to Internet: db-nsg", "Medium",
                    "NSG 'db-nsg' exposes MSSQL port 1433 to Internet. Database at risk.",
                    "Move SQL to private subnet with no internet access.",
                    "CIS-AZ-6.1"),
                self._f("NSG", "docker-nsg",
                    "NSG Exposes Docker-API(2375) to Internet: docker-nsg", "Critical",
                    "Docker API port 2375 exposed to Internet. Full host compromise possible.",
                    "Close port 2375 immediately.",
                    "CIS-AZ-6.1"),
            ],
            "keyvault": [
                self._f("KeyVault", "prod-keyvault",
                    "Key Vault Soft Delete Disabled: prod-keyvault", "High",
                    "Key Vault 'prod-keyvault' has no soft delete. Deleted secrets are unrecoverable.",
                    "Enable soft delete with 90-day retention.",
                    "CIS-AZ-8.1"),
                self._f("KeyVault", "app-keyvault",
                    "Key Vault Purge Protection Disabled: app-keyvault", "High",
                    "Key Vault 'app-keyvault' can be permanently purged. No recovery possible.",
                    "Enable purge protection.",
                    "CIS-AZ-8.1"),
                self._f("KeyVault", "dev-keyvault",
                    "Key Vault Public Network Access: dev-keyvault", "Medium",
                    "Key Vault 'dev-keyvault' accessible from all networks. Attack surface exposed.",
                    "Restrict to VNet or use Private Endpoint.",
                    "CIS-AZ-8.1"),
                self._f("KeyVault", "secrets-vault",
                    "Key Vault All Permissions Granted: secrets-vault", "High",
                    "Key Vault 'secrets-vault' grants ALL permissions to a service principal.",
                    "Restrict access policies to minimum required permissions.",
                    "NIST-PR.AC-1"),
            ],
            "sql": [
                self._f("SQL", "prod-sql-server/user-db",
                    "SQL TDE Disabled: user-db", "High",
                    "Azure SQL database 'user-db' has Transparent Data Encryption disabled. "
                    "Data at rest is unencrypted.",
                    "Enable TDE on the database.",
                    "CIS-AZ-4.1"),
                self._f("SQL", "prod-sql-server",
                    "SQL Auditing Disabled: prod-sql-server", "High",
                    "SQL Server 'prod-sql-server' auditing is disabled. No database activity log.",
                    "Enable SQL Server Auditing with 90+ day retention.",
                    "CIS-AZ-4.3"),
                self._f("SQL", "prod-sql-server",
                    "SQL Advanced Threat Protection Disabled: prod-sql-server", "Medium",
                    "Advanced Threat Protection not enabled. SQL injection attacks go undetected.",
                    "Enable Microsoft Defender for SQL.",
                    "MSWAF-SR-1"),
                self._f("SQL", "dev-sql-server",
                    "SQL Server Public Access Enabled: dev-sql-server", "High",
                    "SQL Server 'dev-sql-server' is accessible from public Internet.",
                    "Disable public network access. Use Private Endpoint.",
                    "CIS-AZ-4.1"),
            ],
            "monitor": [
                self._f("Monitor", "subscription",
                    "No Subscription Diagnostic Settings", "High",
                    "No diagnostic settings found. Admin operations not being logged.",
                    "Create diagnostic setting to export Activity Logs to Log Analytics.",
                    "CIS-AZ-5.1"),
                self._f("Monitor", "subscription",
                    "No Activity Log Alerts Configured", "Medium",
                    "No activity log alerts. Security-critical events trigger no notifications.",
                    "Create activity log alerts for NSG changes, policy assignments, etc.",
                    "CIS-AZ-5.1"),
            ],
        }

        out = []
        for cat in categories:
            out.extend(ALL.get(cat, []))
        return out


azure_scanner = AzureScanner()
