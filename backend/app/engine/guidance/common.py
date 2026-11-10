"""Shared vocabulary for the per-rule guidance: CWE and ATT&CK names, reference links, and the
`g()` builder every provider module uses so entries stay short and uniform.

CWE / ATT&CK ids are resolved to their official names here (one place to audit); an unknown id is a
programming error and fails at import time.
"""
from __future__ import annotations

from typing import Any

CWE: dict[int, str] = {
    16: "Configuration",
    250: "Execution with Unnecessary Privileges",
    269: "Improper Privilege Management",
    272: "Least Privilege Violation",
    284: "Improper Access Control",
    285: "Improper Authorization",
    306: "Missing Authentication for Critical Function",
    308: "Use of Single-factor Authentication",
    311: "Missing Encryption of Sensitive Data",
    319: "Cleartext Transmission of Sensitive Information",
    324: "Use of a Key Past its Expiration Date",
    326: "Inadequate Encryption Strength",
    327: "Use of a Broken or Risky Cryptographic Algorithm",
    353: "Missing Support for Integrity Check",
    489: "Active Debug Code",
    521: "Weak Password Requirements",
    522: "Insufficiently Protected Credentials",
    668: "Exposure of Resource to Wrong Sphere",
    693: "Protection Mechanism Failure",
    732: "Incorrect Permission Assignment for Critical Resource",
    778: "Insufficient Logging",
    798: "Use of Hard-coded Credentials",
    923: "Improper Restriction of Communication Channel to Intended Endpoints",
    1104: "Use of Unmaintained Third Party Components",
    1188: "Initialization of a Resource with an Insecure Default",
    1392: "Use of Default Credentials",
    1327: "Binding to an Unrestricted IP Address",
}

ATTACK: dict[str, str] = {
    "T1021": "Remote Services",
    "T1021.001": "Remote Services: Remote Desktop Protocol",
    "T1021.004": "Remote Services: SSH",
    "T1040": "Network Sniffing",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1068": "Exploitation for Privilege Escalation",
    "T1078": "Valid Accounts",
    "T1078.004": "Valid Accounts: Cloud Accounts",
    "T1098": "Account Manipulation",
    "T1098.001": "Account Manipulation: Additional Cloud Credentials",
    "T1110": "Brute Force",
    "T1133": "External Remote Services",
    "T1190": "Exploit Public-Facing Application",
    "T1485": "Data Destruction",
    "T1486": "Data Encrypted for Impact",
    "T1490": "Inhibit System Recovery",
    "T1528": "Steal Application Access Token",
    "T1530": "Data from Cloud Storage",
    "T1537": "Transfer Data to Cloud Account",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1552": "Unsecured Credentials",
    "T1552.005": "Unsecured Credentials: Cloud Instance Metadata API",
    "T1557": "Adversary-in-the-Middle",
    "T1562": "Impair Defenses",
    "T1562.008": "Impair Defenses: Disable or Modify Cloud Logs",
    "T1610": "Deploy Container",
    "T1611": "Escape to Host",
}

#: reusable reference links (title, url); providers add their own tuples next to these keys
REF: dict[str, tuple[str, str]] = {
    "cis-azure": ("CIS Microsoft Azure Foundations Benchmark", "https://www.cisecurity.org/benchmark/azure"),
    "cis-aws": ("CIS Amazon Web Services Foundations Benchmark", "https://www.cisecurity.org/benchmark/amazon_web_services"),
    "cis-gcp": ("CIS Google Cloud Platform Foundation Benchmark", "https://www.cisecurity.org/benchmark/google_cloud_computing_platform"),
    "cis-k8s": ("CIS Kubernetes Benchmarks", "https://www.cisecurity.org/benchmark/kubernetes"),
    "mcsb": ("Microsoft cloud security benchmark", "https://learn.microsoft.com/security/benchmark/azure/overview"),
    "aws-fsbp": ("AWS Foundational Security Best Practices", "https://docs.aws.amazon.com/securityhub/latest/userguide/fsbp-standard.html"),
    "az-nsg": ("Azure network security groups", "https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview"),
    "az-bastion": ("Azure Bastion", "https://learn.microsoft.com/azure/bastion/bastion-overview"),
    "az-jit": ("Just-in-time VM access", "https://learn.microsoft.com/azure/defender-for-cloud/just-in-time-access-overview"),
    "az-rbac": ("Azure RBAC best practices", "https://learn.microsoft.com/azure/role-based-access-control/best-practices"),
    "az-mi": ("Managed identities for Azure resources", "https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/overview"),
    "az-pe": ("Azure Private Link and private endpoints", "https://learn.microsoft.com/azure/private-link/private-endpoint-overview"),
    "az-appsvc-sec": ("Security in Azure App Service", "https://learn.microsoft.com/azure/app-service/overview-security"),
    "az-appsvc-ipr": ("App Service access restrictions", "https://learn.microsoft.com/azure/app-service/app-service-ip-restrictions"),
    "az-appsvc-ftp": ("Deploy to App Service using FTP/S", "https://learn.microsoft.com/azure/app-service/deploy-ftp"),
    "az-appsvc-auth": ("Authentication and authorization in App Service", "https://learn.microsoft.com/azure/app-service/overview-authentication-authorization"),
    "az-appsvc-tls": ("Secure a custom DNS name with a TLS/SSL binding in App Service", "https://learn.microsoft.com/azure/app-service/configure-ssl-bindings"),
    "az-appsvc-mi": ("Managed identities in App Service", "https://learn.microsoft.com/azure/app-service/overview-managed-identity"),
    "az-appsvc-cfg": ("Configure an App Service app", "https://learn.microsoft.com/azure/app-service/configure-common"),
    "az-appsvc-lang": ("App Service language runtime support policy", "https://learn.microsoft.com/azure/app-service/language-support-policy"),
    "az-sql-net": ("Azure SQL Database network access controls", "https://learn.microsoft.com/azure/azure-sql/database/network-access-controls-overview"),
    "az-sql-tls": ("Azure SQL connectivity and minimal TLS version", "https://learn.microsoft.com/azure/azure-sql/database/connectivity-settings"),
    "az-kv-net": ("Azure Key Vault network security", "https://learn.microsoft.com/azure/key-vault/general/network-security"),
    "az-kv-sd": ("Azure Key Vault soft-delete overview", "https://learn.microsoft.com/azure/key-vault/general/soft-delete-overview"),
    "az-stg-pub": ("Prevent anonymous read access to blob data", "https://learn.microsoft.com/azure/storage/blobs/anonymous-read-access-prevent"),
    "az-stg-https": ("Require secure transfer for a storage account", "https://learn.microsoft.com/azure/storage/common/storage-require-secure-transfer"),
    "az-stg-tls": ("Enforce a minimum TLS version for a storage account", "https://learn.microsoft.com/azure/storage/common/transport-layer-security-configure-minimum-version"),
    "az-stg-fw": ("Configure Azure Storage firewalls and virtual networks", "https://learn.microsoft.com/azure/storage/common/storage-network-security"),
    "az-aks-auth": ("Use Microsoft Entra ID and Kubernetes RBAC in AKS", "https://learn.microsoft.com/azure/aks/azure-ad-rbac"),
    "az-aks-api": ("AKS API server authorized IP ranges", "https://learn.microsoft.com/azure/aks/api-server-authorized-ip-ranges"),
    "az-fw": ("Azure Firewall", "https://learn.microsoft.com/azure/firewall/overview"),
    "az-fw-policy": ("Azure Firewall Manager policy overview", "https://learn.microsoft.com/azure/firewall-manager/policy-overview"),
    "az-fw-premium": ("Azure Firewall Premium features", "https://learn.microsoft.com/azure/firewall/premium-features"),
    "az-fw-ti": ("Azure Firewall threat intelligence-based filtering", "https://learn.microsoft.com/azure/firewall/threat-intel"),
    "az-pg-net": ("Networking with public access for Azure Database for PostgreSQL flexible server", "https://learn.microsoft.com/azure/postgresql/flexible-server/concepts-networking-public"),
    "az-pg-tls": ("Encrypted connectivity using TLS in Azure Database for PostgreSQL flexible server", "https://learn.microsoft.com/azure/postgresql/flexible-server/concepts-networking-ssl-tls"),
    "az-pg-entra": ("Microsoft Entra authentication in Azure Database for PostgreSQL flexible server", "https://learn.microsoft.com/azure/postgresql/flexible-server/concepts-azure-ad-authentication"),
    "az-pg-bkp": ("Backup and restore in Azure Database for PostgreSQL flexible server", "https://learn.microsoft.com/azure/postgresql/flexible-server/concepts-backup-restore"),
    "az-pg-ver": ("Azure Database for PostgreSQL version policy", "https://learn.microsoft.com/azure/postgresql/flexible-server/concepts-version-policy"),
    "az-my-net": ("Public network access for Azure Database for MySQL flexible server", "https://learn.microsoft.com/azure/mysql/flexible-server/concepts-networking-public"),
    "az-my-tls": ("Connect with TLS in Azure Database for MySQL flexible server", "https://learn.microsoft.com/azure/mysql/flexible-server/how-to-connect-tls-ssl"),
    "az-my-entra": ("Microsoft Entra authentication in Azure Database for MySQL flexible server", "https://learn.microsoft.com/azure/mysql/flexible-server/concepts-azure-ad-authentication"),
    "az-my-bkp": ("Backup and restore in Azure Database for MySQL flexible server", "https://learn.microsoft.com/azure/mysql/flexible-server/concepts-backup-restore"),
    "az-my-ver": ("Azure Database for MySQL version support policy", "https://learn.microsoft.com/azure/mysql/concepts-version-policy"),
    "az-cosmos-fw": ("Configure IP firewall in Azure Cosmos DB", "https://learn.microsoft.com/azure/cosmos-db/how-to-configure-firewall"),
    "az-cosmos-rbac": ("Role-based access control in Azure Cosmos DB for NoSQL", "https://learn.microsoft.com/azure/cosmos-db/role-based-access-control"),
    "az-cosmos-pe": ("Configure Azure Private Link for Azure Cosmos DB", "https://learn.microsoft.com/azure/cosmos-db/how-to-configure-private-endpoints"),
    "az-cosmos-bkp": ("Online backup and on-demand data restore in Azure Cosmos DB", "https://learn.microsoft.com/azure/cosmos-db/online-backup-and-restore"),
    "az-redis": ("Azure Cache for Redis configuration", "https://learn.microsoft.com/azure/azure-cache-for-redis/cache-configure"),
    "az-redis-sec": ("Azure Cache for Redis security baseline", "https://learn.microsoft.com/security/benchmark/azure/baselines/azure-cache-for-redis-security-baseline"),
    "az-vm-enc": ("Overview of managed disk encryption options", "https://learn.microsoft.com/azure/virtual-machines/disk-encryption-overview"),
    "az-vm-pip": ("Public IP addresses in Azure", "https://learn.microsoft.com/azure/virtual-network/ip-services/public-ip-addresses"),
    "az-mi-pub": ("Configure public endpoint in Azure SQL Managed Instance", "https://learn.microsoft.com/azure/azure-sql/managed-instance/public-endpoint-configure"),
    "k8s-pss": ("Kubernetes Pod Security Standards", "https://kubernetes.io/docs/concepts/security/pod-security-standards/"),
    "k8s-psa": ("Kubernetes Pod Security Admission", "https://kubernetes.io/docs/concepts/security/pod-security-admission/"),
    "aws-iam-bp": ("Security best practices in IAM", "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"),
    "aws-root": ("AWS account root user", "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html"),
    "aws-mfa": ("Multi-factor authentication in IAM", "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html"),
    "aws-pwd": ("Set an account password policy for IAM users", "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html"),
    "aws-keys": ("Rotate access keys", "https://docs.aws.amazon.com/IAM/latest/UserGuide/id-credentials-access-keys-update.html"),
    "aws-least": ("Grant least privilege", "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"),
    "aws-s3-bpa": ("Blocking public access to your Amazon S3 storage", "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"),
    "aws-s3-sec": ("Security best practices for Amazon S3", "https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html"),
    "aws-imds": ("Configure the instance metadata service options", "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html"),
    "aws-sg": ("Security groups for your VPC", "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html"),
    "aws-ssm": ("AWS Systems Manager Session Manager", "https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html"),
    "aws-rds-enc": ("Encrypting Amazon RDS resources", "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html"),
    "aws-rds-bkp": ("Working with backups in Amazon RDS", "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html"),
    "aws-rds-pub": ("Working with a DB instance in a VPC", "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html"),
    "aws-eks-ep": ("Amazon EKS cluster endpoint access control", "https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html"),
    "aws-eks-log": ("Amazon EKS control plane logging", "https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html"),
    "aws-kms-rot": ("Rotating AWS KMS keys", "https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html"),
    "aws-ct-mr": ("Creating a trail that applies to all Regions", "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html"),
    "aws-ct-val": ("Validating CloudTrail log file integrity", "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html"),
    "aws-lambda-url": ("Control access to Lambda function URLs", "https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html"),
    "gcp-sa-bp": ("Best practices for using service accounts", "https://cloud.google.com/iam/docs/best-practices-service-accounts"),
    "gcp-sa-keys": ("Best practices for managing service account keys", "https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys"),
    "gcp-roles": ("Understanding IAM roles", "https://cloud.google.com/iam/docs/roles-overview"),
    "gcp-imp": ("Service account impersonation", "https://cloud.google.com/iam/docs/service-account-impersonation"),
    "gcp-fw": ("VPC firewall rules", "https://cloud.google.com/firewall/docs/firewalls"),
    "gcp-iap": ("Using IAP for TCP forwarding", "https://cloud.google.com/iap/docs/using-tcp-forwarding"),
    "gcp-gce-sa": ("Create and enable service accounts for instances", "https://cloud.google.com/compute/docs/access/create-enable-service-accounts-for-instances"),
    "gcp-gcs-pap": ("Public access prevention", "https://cloud.google.com/storage/docs/public-access-prevention"),
    "gcp-gcs-ubla": ("Uniform bucket-level access", "https://cloud.google.com/storage/docs/uniform-bucket-level-access"),
    "gcp-gke-hard": ("Harden your cluster's security", "https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster"),
    "gcp-gke-an": ("Add authorized networks for control plane access", "https://cloud.google.com/kubernetes-engine/docs/how-to/authorized-networks"),
    "gcp-gke-priv": ("Private clusters", "https://cloud.google.com/kubernetes-engine/docs/concepts/private-cluster-concept"),
    "gcp-gke-wi": ("Workload Identity Federation for GKE", "https://cloud.google.com/kubernetes-engine/docs/concepts/workload-identity"),
    "gcp-sql-ip": ("Configure IP connectivity (Cloud SQL)", "https://cloud.google.com/sql/docs/mysql/configure-ip"),
    "gcp-sql-ssl": ("Configure SSL/TLS certificates (Cloud SQL)", "https://cloud.google.com/sql/docs/mysql/configure-ssl-instance"),
    "gcp-sql-bkp": ("Create and manage on-demand and automatic backups (Cloud SQL)", "https://cloud.google.com/sql/docs/mysql/backup-recovery/backing-up"),
    "gcp-kms-rot": ("Key rotation (Cloud KMS)", "https://cloud.google.com/kms/docs/key-rotation"),
    "gcp-run-auth": ("Allow public (unauthenticated) access to Cloud Run", "https://cloud.google.com/run/docs/authenticating/public"),
    "gcp-fn-iam": ("Authenticate for invocation (Cloud Run functions)", "https://cloud.google.com/functions/docs/securing/authenticating"),
}


def cwe_ref(n: int) -> tuple[str, str]:
    return (f"CWE-{n}: {CWE[n]}", f"https://cwe.mitre.org/data/definitions/{n}.html")


def attack_ref(tid: str) -> tuple[str, str]:
    path = tid.replace(".", "/")
    return (f"MITRE ATT&CK {tid}: {ATTACK[tid]}", f"https://attack.mitre.org/techniques/{path}/")


def g(score: float, cwe: int, attack: list[str], impact: list[tuple[str, str]], verify: list[str], cli: str,
      console: list[str], fix_cli: str, tf: str, prevent: str, refs: list[str | tuple[str, str]]) -> dict[str, Any]:
    """Build one guidance entry. `refs` holds REF keys or (title, url) tuples; the CWE and ATT&CK
    reference links are appended automatically."""
    out: list[dict[str, str]] = []
    for r in refs:
        title, url = REF[r] if isinstance(r, str) else r
        out.append({"title": title, "url": url})
    for t, u in (cwe_ref(cwe), *[attack_ref(a) for a in attack]):
        out.append({"title": t, "url": u})
    return {
        "impact": [{"title": t, "text": x} for t, x in impact],
        "cwe": {"id": f"CWE-{cwe}", "name": CWE[cwe]},
        "attack": [{"id": a, "name": ATTACK[a]} for a in attack],
        "risk_score": score,
        "verify_steps": verify,
        "verify_cli": cli,
        "fix_console": console,
        "fix_cli": fix_cli,
        "fix_terraform": tf,
        "prevent": prevent,
        "references": out,
    }
