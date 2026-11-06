"""Guidance for the AWS posture rules (AWS-*)."""
from __future__ import annotations

from typing import Any

from .common import g

GUIDANCE: dict[str, dict[str, Any]] = {}

# ----------------------------------------------------------------------------- IAM / account
GUIDANCE["AWS-IAM-001"] = g(
    9.1, 308, ["T1078.004", "T1110"],
    [("Root can be taken over with a password", "The root user has unrestricted power over the account, billing and every resource, and it can sign in with a password alone."),
     ("Cannot be limited by IAM", "No IAM policy restricts the root user, so a stolen password means total compromise."),
     ("Phishing target", "Root credentials are the highest-value credentials in the account.")],
    ["Sign in as the root user (not an IAM user) or check the IAM credential report.", "Look at the account summary: AccountMFAEnabled should be 1."],
    "aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled'",
    ["Sign in to the AWS console as the root user.", "Open the account menu > Security credentials.", "Under Multi-factor authentication (MFA) choose Assign MFA device.",
     "Prefer a hardware key or passkey; store the recovery method safely and keep the root email and phone current."],
    "# Root MFA can only be enabled while signed in as root, in the console (the API cannot enable it).\naws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled'   # should be 1",
    '# Root MFA cannot be created in Terraform. Detect regressions with an AWS Config managed rule:\nresource "aws_config_config_rule" "root_mfa" {\n  name = "root-account-mfa-enabled"\n  source {\n    owner             = "AWS"\n    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"\n  }\n}',
    "Never use root for daily work, protect it with a hardware MFA key, and alert on root sign-in with an AWS Config rule or EventBridge.",
    ["aws-root", "aws-mfa", "cis-aws", "aws-fsbp"])

GUIDANCE["AWS-IAM-002"] = g(
    9.4, 798, ["T1078.004", "T1552"],
    [("Unrestricted long-lived credentials", "Root access keys carry full account power and are not limited by IAM policies or permission boundaries."),
     ("Leak equals total compromise", "Keys in scripts, repositories or laptops give an attacker everything."),
     ("Nearly never needed", "AWS recommends deleting root access keys and using IAM roles.")],
    ["Sign in as root > Security credentials.", "Under Access keys see whether any key exists (the credential report also shows root key status)."],
    "aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent'",
    ["Sign in to the AWS console as the root user.", "Open Security credentials > Access keys.", "Make the key inactive, confirm nothing breaks, then delete it.",
     "Replace its use with an IAM role or an IAM Identity Center user."],
    "# Root keys can only be removed while signed in as root (console). Verify afterwards:\naws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent'   # should be 0",
    'resource "aws_config_config_rule" "root_keys" {\n  name = "iam-root-access-key-check"\n  source {\n    owner             = "AWS"\n    source_identifier = "IAM_ROOT_ACCESS_KEY_CHECK"\n  }\n}',
    "Block root access-key creation by policy and alert if a root key ever appears.",
    ["aws-root", "aws-iam-bp", "cis-aws", "aws-fsbp"])

GUIDANCE["AWS-IAM-003"] = g(
    5.3, 521, ["T1110", "T1078.004"],
    [("Short passwords allowed", "The account password policy does not require at least 14 characters."),
     ("Easier password guessing", "Short passwords fall quickly to brute force and credential stuffing."),
     ("Baseline control", "CIS and most standards require a minimum length of 14.")],
    ["Open IAM > Account settings > Password policy.", "Check the minimum length and that a custom policy exists."],
    "aws iam get-account-password-policy",
    ["Open the IAM console > Account settings.", "Choose Edit password policy and select a custom policy.", "Set Minimum password length to 14 or more, require character types, and set password reuse prevention."],
    "aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters --password-reuse-prevention 24",
    'resource "aws_iam_account_password_policy" "strict" {\n  minimum_password_length        = 14\n  require_lowercase_characters   = true\n  require_uppercase_characters   = true\n  require_numbers                = true\n  require_symbols                = true\n  password_reuse_prevention      = 24\n}',
    "Manage the password policy as code and prefer federated sign-in (IAM Identity Center) so IAM passwords are rare.",
    ["aws-pwd", "cis-aws"])

GUIDANCE["AWS-IAM-004"] = g(
    7.4, 308, ["T1078.004", "T1110"],
    [("Password-only console access", "The user can sign in to the console without a second factor."),
     ("Phishing and stuffing", "A stolen or guessed password is enough to access the account as this user."),
     ("MFA blocks most account takeovers", "A second factor stops attacks that rely on the password alone.")],
    ["Open IAM > Users > the user > Security credentials.", "Check Console access is enabled and Assigned MFA device is empty."],
    "aws iam list-mfa-devices --user-name <name>",
    ["Open IAM > Users > the user > Security credentials.", "Under Multi-factor authentication choose Assign MFA device and follow the prompts.", "Alternatively move the user to IAM Identity Center with enforced MFA."],
    "aws iam create-virtual-mfa-device --virtual-mfa-device-name <name> --outfile qr.png --bootstrap-method QRCodePNG\n"
    "aws iam enable-mfa-device --user-name <name> --serial-number <mfa-device-arn> --authentication-code1 <code1> --authentication-code2 <code2>",
    '# Enforce MFA for the group the user is in: deny everything except MFA self-service when MFA is absent\nresource "aws_iam_policy" "require_mfa" {\n  name = "require-mfa"\n  policy = jsonencode({\n    Version = "2012-10-17"\n    Statement = [{\n'
    '      Sid       = "DenyAllWithoutMFA"\n      Effect    = "Deny"\n      NotAction = ["iam:CreateVirtualMFADevice", "iam:EnableMFADevice", "iam:ListMFADevices", "iam:ResyncMFADevice", "sts:GetSessionToken"]\n'
    '      Resource  = "*"\n      Condition = { BoolIfExists = { "aws:MultiFactorAuthPresent" = "false" } }\n    }]\n  })\n}',
    "Require MFA through a group policy or IAM Identity Center and review the credential report monthly.",
    ["aws-mfa", "aws-iam-bp", "cis-aws"])

GUIDANCE["AWS-IAM-005"] = g(
    5.4, 324, ["T1078.004", "T1098.001"],
    [("Old long-lived key", "An active access key older than 90 days has had a long time to be copied, logged or leaked."),
     ("Unnoticed misuse", "Old keys are rarely monitored and often forgotten."),
     ("Rotation limits exposure", "Regular rotation shortens the useful life of a leaked key.")],
    ["Open IAM > Users > the user > Security credentials.", "Read the Access key age and last-used information."],
    "aws iam list-access-keys --user-name <name>",
    ["Open IAM > Users > the user > Security credentials.", "Create a second access key and update the application to use it.", "Make the old key Inactive, check nothing breaks, then delete it.",
     "Better: replace the key with an IAM role or IAM Identity Center credentials."],
    "aws iam create-access-key --user-name <name>\naws iam update-access-key --user-name <name> --access-key-id <old-key-id> --status Inactive\naws iam delete-access-key --user-name <name> --access-key-id <old-key-id>",
    '# Prefer roles (no long-lived keys). If a key is unavoidable, recreate it by tainting/replacing aws_iam_access_key:\nresource "aws_iam_access_key" "app" {\n  user = "<name>"\n}',
    "Eliminate long-lived keys with roles and federation; where unavoidable, rotate every 90 days or less and alert on old keys with AWS Config (access-keys-rotated).",
    ["aws-keys", "aws-iam-bp", "cis-aws"])

GUIDANCE["AWS-IAM-006"] = g(
    8.4, 269, ["T1078.004", "T1548"],
    [("Full administrator", "The user can perform any action on any resource, including creating users and disabling logging."),
     ("Compromise equals account takeover", "A stolen key or password for this user controls the whole account."),
     ("Rarely justified", "Few humans need standing administrator rights.")],
    ["Open IAM > Users > the user > Permissions.", "Find AdministratorAccess or a policy with Action * on Resource *, including via groups."],
    "aws iam list-attached-user-policies --user-name <name>",
    ["Open IAM > Users > the user > Permissions.", "Remove the AdministratorAccess policy (check group memberships too).", "Grant a narrower job-specific managed or custom policy instead."],
    "aws iam detach-user-policy --user-name <name> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
    '# remove this attachment and attach a scoped policy instead\nresource "aws_iam_user_policy_attachment" "scoped" {\n  user       = "<name>"\n  policy_arn = aws_iam_policy.scoped.arn\n}',
    "Use least-privilege policies, IAM Identity Center permission sets with session limits, and Access Analyzer unused-access findings to trim permissions.",
    ["aws-least", "aws-iam-bp", "cis-aws"])

GUIDANCE["AWS-IAM-007"] = g(
    8.4, 269, ["T1078.004", "T1548"],
    [("Role grants full administration", "Anything that can assume this role (a workload, another account or a person) controls the whole account."),
     ("Trust policy becomes critical", "A loose trust policy or a compromised workload turns into account takeover."),
     ("Lateral and privilege escalation", "Attackers look for admin roles to assume after any initial foothold.")],
    ["Open IAM > Roles > the role > Permissions.", "Find AdministratorAccess or an Action * / Resource * policy.", "Review the trust relationships tab to see who can assume it."],
    "aws iam list-attached-role-policies --role-name <name>",
    ["Open IAM > Roles > the role > Permissions.", "Detach AdministratorAccess and attach a policy limited to what the workload does.", "Tighten the trust policy to the specific principals that need it."],
    "aws iam detach-role-policy --role-name <name> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
    'resource "aws_iam_role_policy_attachment" "scoped" {\n  role       = "<name>"\n  policy_arn = aws_iam_policy.scoped.arn # not AdministratorAccess\n}',
    "Generate least-privilege policies from CloudTrail activity (IAM Access Analyzer policy generation) and restrict who may create admin roles with SCPs or permission boundaries.",
    ["aws-least", "aws-iam-bp", "cis-aws"])

# ----------------------------------------------------------------------------- S3
_S3_BPA_TF = ('resource "aws_s3_bucket_public_access_block" "this" {\n  bucket                  = "<name>"\n  block_public_acls       = true\n  block_public_policy     = true\n'
              '  ignore_public_acls      = true\n  restrict_public_buckets = true\n}')
_S3_BPA_CLI = ("aws s3api put-public-access-block --bucket <name> --public-access-block-configuration "
               "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true")

GUIDANCE["AWS-S3-001"] = g(
    9.1, 284, ["T1530"],
    [("Bucket data readable by anyone", "The bucket policy or ACL grants access to everyone and Block Public Access does not stop it."),
     ("Data breach", "Misconfigured public buckets are among the most common sources of cloud data leaks."),
     ("Discovered by scanners", "Public buckets are indexed and enumerated automatically.")],
    ["Open S3 > the bucket > Permissions.", "Check Block public access settings, the bucket policy for Principal * and the ACL.", "Review what the bucket contains before changing it."],
    "aws s3api get-bucket-policy-status --bucket <name>\naws s3api get-public-access-block --bucket <name>",
    ["Open S3 > the bucket > Permissions.", "Turn on all four Block public access settings.", "Delete or tighten any bucket policy statement with Principal * and any public ACL grant.",
     "Serve public content through CloudFront with origin access control instead."],
    _S3_BPA_CLI + "\n# remove a public bucket policy if it is not needed:\naws s3api delete-bucket-policy --bucket <name>",
    _S3_BPA_TF,
    "Turn on S3 Block Public Access at the account level and with an SCP, and alert on public-bucket findings from IAM Access Analyzer.",
    ["aws-s3-bpa", "aws-s3-sec", "cis-aws", "aws-fsbp"])

GUIDANCE["AWS-S3-002"] = g(
    5.3, 732, ["T1530"],
    [("Safety net is incomplete", "Not all four Block Public Access settings are on, so a future policy or ACL could expose the bucket."),
     ("One mistake away from a leak", "Block Public Access overrides risky policies and ACLs."),
     ("Cheap to enable", "It rarely affects private buckets.")],
    ["Open S3 > the bucket > Permissions > Block public access.", "Check all four options are On, and the same at account level."],
    "aws s3api get-public-access-block --bucket <name>",
    ["Open S3 > the bucket > Permissions > Block public access (bucket settings).", "Edit and select 'Block all public access', then save.", "Also enable it at the account level (S3 > Block Public Access settings for this account)."],
    _S3_BPA_CLI + "\naws s3control put-public-access-block --account-id <account> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
    _S3_BPA_TF + '\n\nresource "aws_s3_account_public_access_block" "account" {\n  block_public_acls       = true\n  block_public_policy     = true\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n}',
    "Enable account-level Block Public Access and use AWS Config (s3-bucket-level-public-access-prohibited) to catch regressions.",
    ["aws-s3-bpa", "cis-aws", "aws-fsbp"])

GUIDANCE["AWS-S3-003"] = g(
    3.7, 319, ["T1557", "T1040"],
    [("Plain HTTP requests allowed", "No bucket policy statement denies requests made without TLS."),
     ("Interception of data in transit", "Objects and credentials sent over HTTP can be read on the network."),
     ("Low effort fix", "A deny statement on aws:SecureTransport enforces HTTPS for every request.")],
    ["Open S3 > the bucket > Permissions > Bucket policy.", "Look for a Deny statement with Condition Bool aws:SecureTransport = false."],
    "aws s3api get-bucket-policy --bucket <name> --query Policy --output text",
    ["Open S3 > the bucket > Permissions > Bucket policy and choose Edit.", "Add a statement that denies s3:* when aws:SecureTransport is false.", "Save and test an HTTPS request."],
    "aws s3api put-bucket-policy --bucket <name> --policy file://deny-http.json\n"
    "# deny-http.json: {\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"DenyInsecureTransport\",\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\","
    "\"Resource\":[\"arn:aws:s3:::<name>\",\"arn:aws:s3:::<name>/*\"],\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}]}",
    'resource "aws_s3_bucket_policy" "tls_only" {\n  bucket = "<name>"\n  policy = jsonencode({\n    Version = "2012-10-17"\n    Statement = [{\n      Sid       = "DenyInsecureTransport"\n      Effect    = "Deny"\n      Principal = "*"\n      Action    = "s3:*"\n'
    '      Resource  = ["arn:aws:s3:::<name>", "arn:aws:s3:::<name>/*"]\n      Condition = { Bool = { "aws:SecureTransport" = "false" } }\n    }]\n  })\n}',
    "Include the TLS-only statement in your bucket module and check it with the AWS Config rule s3-bucket-ssl-requests-only.",
    ["aws-s3-sec", "cis-aws", "aws-fsbp"])

# ----------------------------------------------------------------------------- EC2 / security groups
_REVOKE = "aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp --port %s --cidr 0.0.0.0/0 --region <region>"
_SG_TF = ('resource "aws_vpc_security_group_ingress_rule" "admin" {\n  security_group_id = "<sg-id>"\n  ip_protocol       = "tcp"\n  from_port         = %s\n  to_port           = %s\n'
          '  cidr_ipv4         = "203.0.113.0/24" # your trusted range, never 0.0.0.0/0\n}')

GUIDANCE["AWS-EC2-001"] = g(
    8.1, 284, ["T1133", "T1021", "T1110"],
    [("Admin ports open on a public instance", "The instance has a public IP and a security group allows 0.0.0.0/0 or ::/0 to SSH, RDP or all ports."),
     ("Brute force and exploitation", "Internet scanners find and attack open admin ports within minutes."),
     ("Foothold in your VPC", "A compromised instance can reach internal services and use its instance role.")],
    ["Open EC2 > Instances > the instance > Security.", "Read the inbound rules of every attached security group.", "Check for 0.0.0.0/0 or ::/0 on ports 22, 3389 or all."],
    "aws ec2 describe-instances --instance-ids <instance-id> --region <region> --query 'Reservations[].Instances[].SecurityGroups'",
    ["Open EC2 > Security groups and the group attached to the instance.", "Edit inbound rules: delete the open rule or restrict the source to a trusted range.",
     "Use AWS Systems Manager Session Manager for shell access without any inbound port."],
    _REVOKE % "22" + "\n" + _REVOKE % "3389",
    _SG_TF % ("22", "22"),
    "Deny open admin ports with an SCP or AWS Config (restricted-ssh) and standardise on Session Manager.",
    ["aws-sg", "aws-ssm", "cis-aws", "aws-fsbp"])

GUIDANCE["AWS-EC2-002"] = g(
    6.5, 1188, ["T1552.005", "T1190"],
    [("IMDSv1 allows simple credential theft", "A server-side request forgery bug in any app on the instance can fetch the instance role's credentials."),
     ("Role credentials leaked", "Stolen role credentials work from anywhere until they expire."),
     ("IMDSv2 requires a session token", "That token requirement blocks most SSRF-based theft.")],
    ["Open EC2 > the instance > Details > Instance metadata options.", "Check 'IMDSv2' is Optional rather than Required."],
    "aws ec2 describe-instances --instance-ids <instance-id> --region <region> --query 'Reservations[].Instances[].MetadataOptions'",
    ["Open EC2 > the instance > Actions > Instance settings > Modify instance metadata options.", "Set IMDSv2 to Required and save.", "Update any software that still uses IMDSv1 first (SDKs support IMDSv2)."],
    "aws ec2 modify-instance-metadata-options --instance-id <instance-id> --region <region> --http-tokens required --http-endpoint enabled",
    'resource "aws_instance" "this" {\n  # ami, instance_type, ...\n  metadata_options {\n    http_endpoint = "enabled"\n    http_tokens   = "required"\n  }\n}',
    "Require IMDSv2 in launch templates and set it account-wide with EC2 account defaults or an SCP.",
    ["aws-imds", "cis-aws", "aws-fsbp"])

GUIDANCE["AWS-SG-001"] = g(
    8.1, 284, ["T1133", "T1021", "T1110"],
    [("Remote admin open to the internet", "An ingress rule allows 0.0.0.0/0 or ::/0 to SSH (22) or RDP (3389)."),
     ("Instances behind it are exposed", "Every resource using the group can be attacked directly."),
     ("Constant scanning", "These ports are probed continuously by botnets.")],
    ["Open VPC > Security groups > the group > Inbound rules.", "Find rules whose source is 0.0.0.0/0 or ::/0 on ports 22 or 3389.", "Check which network interfaces use the group."],
    "aws ec2 describe-security-groups --group-ids <sg-id> --region <region> --query 'SecurityGroups[].IpPermissions'",
    ["Open VPC > Security groups and select the group.", "Edit inbound rules: delete the open rule or set its source to a trusted CIDR or another security group.", "Use Session Manager instead of public SSH/RDP."],
    _REVOKE % "22" + "\n" + _REVOKE % "3389" + "\n# for IPv6 use --ip-permissions with Ipv6Ranges=[{CidrIpv6=::/0}]",
    _SG_TF % ("22", "22"),
    "Prevent open admin ports with an SCP / AWS Config rule (restricted-ssh, restricted-common-ports) and remediate automatically.",
    ["aws-sg", "aws-ssm", "cis-aws", "aws-fsbp"])

GUIDANCE["AWS-SG-002"] = g(
    9.6, 284, ["T1133", "T1190"],
    [("Everything open", "An ingress rule allows all traffic or every port from the internet."),
     ("No network filtering left", "Every service on the attached resources is directly reachable."),
     ("Rapid exploitation", "Databases and admin tools on open hosts are found and attacked quickly.")],
    ["Open VPC > Security groups > the group > Inbound rules.", "Find a rule with protocol All / ports 0-65535 from 0.0.0.0/0 or ::/0."],
    "aws ec2 describe-security-groups --group-ids <sg-id> --region <region> --query 'SecurityGroups[].IpPermissions'",
    ["Open VPC > Security groups and select the group.", "Delete the allow-all inbound rule.", "Add specific rules (for example HTTPS 443 from the load balancer) only for what is needed."],
    "aws ec2 revoke-security-group-ingress --group-id <sg-id> --region <region> --protocol all --cidr 0.0.0.0/0",
    'resource "aws_vpc_security_group_ingress_rule" "https" {\n  security_group_id = "<sg-id>"\n  ip_protocol       = "tcp"\n  from_port         = 443\n  to_port           = 443\n  cidr_ipv4         = "0.0.0.0/0" # only if this is a public web tier; otherwise a trusted range\n}',
    "Deny allow-all rules in review and with AWS Config; start from the default deny and add only required flows.",
    ["aws-sg", "cis-aws", "aws-fsbp"])

GUIDANCE["AWS-SG-003"] = g(
    3.5, 1188, ["T1190"],
    [("Default group permits traffic", "The VPC default security group has ingress rules, so resources launched without a group inherit them."),
     ("Silent exposure", "New resources can be reachable by accident."),
     ("Best practice", "The default group should allow nothing.")],
    ["Open VPC > Security groups and filter for the VPC's default group.", "Check it has no inbound or outbound rules."],
    "aws ec2 describe-security-groups --filters Name=group-name,Values=default --region <region> --query 'SecurityGroups[].{id:GroupId,in:IpPermissions,out:IpPermissionsEgress}'",
    ["Open VPC > Security groups > the default group.", "Remove all inbound rules (and outbound rules if you wish to be strict).", "Make sure no resource depends on the default group before removing."],
    "aws ec2 revoke-security-group-ingress --group-id <sg-id> --region <region> --security-group-rule-ids <rule-id>",
    'resource "aws_default_security_group" "default" {\n  vpc_id = aws_vpc.main.id\n  # no ingress or egress blocks: the default group allows nothing\n}',
    "Manage the default group in Terraform with no rules and attach explicit groups to every resource.",
    ["aws-sg", "cis-aws"])

# ----------------------------------------------------------------------------- RDS
GUIDANCE["AWS-RDS-001"] = g(
    7.5, 668, ["T1190", "T1110"],
    [("Database has a public endpoint", "PubliclyAccessible is true, so the endpoint resolves to a public IP."),
     ("Direct attack surface", "If a security group allows it, anyone on the internet can attempt to connect."),
     ("Data at risk", "Databases hold your most sensitive data.")],
    ["Open RDS > Databases > the instance > Connectivity & security.", "Check Publicly accessible is Yes.", "Review the attached security groups' inbound rules."],
    "aws rds describe-db-instances --db-instance-identifier <name> --region <region> --query 'DBInstances[].PubliclyAccessible'",
    ["Open RDS > Databases > the instance > Modify.", "Under Connectivity choose Publicly accessible: No.", "Apply immediately, and tighten the security group to the app tier only."],
    "aws rds modify-db-instance --db-instance-identifier <name> --region <region> --no-publicly-accessible --apply-immediately",
    'resource "aws_db_instance" "this" {\n  identifier          = "<name>"\n  publicly_accessible = false\n  # engine, instance_class, db_subnet_group_name, vpc_security_group_ids ...\n}',
    "Place databases in private subnets and deny publicly accessible RDS with an SCP or AWS Config (rds-instance-public-access-check).",
    ["aws-rds-pub", "cis-aws", "aws-fsbp"])

GUIDANCE["AWS-RDS-002"] = g(
    5.5, 311, ["T1530"],
    [("Storage, backups and snapshots unencrypted", "Anyone with access to a snapshot copy can read the data."),
     ("Compliance gap", "Encryption at rest is a baseline requirement in most standards."),
     ("Needs a rebuild", "Encryption cannot be turned on in place for an existing instance.")],
    ["Open RDS > Databases > the instance > Configuration.", "Check Encryption is Not enabled."],
    "aws rds describe-db-instances --db-instance-identifier <name> --region <region> --query 'DBInstances[].{enc:StorageEncrypted,key:KmsKeyId}'",
    ["Take a snapshot of the instance.", "Copy the snapshot and choose Enable encryption with a KMS key.", "Restore a new instance from the encrypted copy and switch the application over.", "Delete the old instance when verified."],
    "aws rds create-db-snapshot --db-instance-identifier <name> --db-snapshot-identifier <name>-pre-enc\n"
    "aws rds copy-db-snapshot --source-db-snapshot-identifier <name>-pre-enc --target-db-snapshot-identifier <name>-enc --kms-key-id <kms-key-id>\n"
    "aws rds restore-db-instance-from-db-snapshot --db-instance-identifier <name>-new --db-snapshot-identifier <name>-enc",
    'resource "aws_db_instance" "this" {\n  identifier        = "<name>"\n  storage_encrypted = true\n  kms_key_id        = aws_kms_key.rds.arn\n  # changing this on an existing instance forces replacement: restore from an encrypted snapshot\n}',
    "Enable default encryption for new databases (set storage_encrypted in modules) and use the AWS Config rule rds-storage-encrypted.",
    ["aws-rds-enc", "cis-aws", "aws-fsbp"])

GUIDANCE["AWS-RDS-003"] = g(
    4.4, 693, ["T1485", "T1490"],
    [("Short or no point-in-time recovery", "Automated backups are off or kept less than 7 days."),
     ("Data loss after an error or attack", "Accidental deletion or ransomware may be unrecoverable beyond the retention window."),
     ("Cheap protection", "Backup storage up to the database size is generally included.")],
    ["Open RDS > Databases > the instance > Maintenance & backups.", "Check the backup retention period."],
    "aws rds describe-db-instances --db-instance-identifier <name> --region <region> --query 'DBInstances[].BackupRetentionPeriod'",
    ["Open RDS > Databases > the instance > Modify.", "Set Backup retention period to at least 7 days (35 max).", "Apply immediately or in the maintenance window."],
    "aws rds modify-db-instance --db-instance-identifier <name> --region <region> --backup-retention-period 7 --apply-immediately",
    'resource "aws_db_instance" "this" {\n  identifier              = "<name>"\n  backup_retention_period = 7\n  backup_window           = "03:00-04:00"\n}',
    "Set retention in your database module and use AWS Backup plans for cross-region copies.",
    ["aws-rds-bkp", "aws-fsbp"])

# ----------------------------------------------------------------------------- EKS
GUIDANCE["AWS-EKS-001"] = g(
    7.5, 668, ["T1190", "T1133"],
    [("Kubernetes API open to the internet", "The cluster endpoint is public and accepts connections from any address."),
     ("Admin interface exposed", "Any API flaw or leaked credential is exploitable remotely."),
     ("Easy to narrow", "Public access CIDRs or a private-only endpoint remove the exposure.")],
    ["Open EKS > Clusters > the cluster > Networking.", "Check Public access is enabled and Public access source allow list is 0.0.0.0/0."],
    "aws eks describe-cluster --name <name> --region <region> --query cluster.resourcesVpcConfig",
    ["Open EKS > Clusters > the cluster > Networking > Manage networking.", "Restrict the public access source allow list to your trusted CIDRs, or disable public access and enable private access.", "Make sure CI/CD and operators can still reach the endpoint."],
    "aws eks update-cluster-config --name <name> --region <region> --resources-vpc-config endpointPublicAccess=true,publicAccessCidrs=203.0.113.0/24,endpointPrivateAccess=true",
    'resource "aws_eks_cluster" "this" {\n  name     = "<name>"\n  role_arn = aws_iam_role.eks.arn\n  vpc_config {\n    subnet_ids              = var.subnet_ids\n    endpoint_private_access = true\n    endpoint_public_access  = true\n    public_access_cidrs     = ["203.0.113.0/24"]\n  }\n}',
    "Prefer a private endpoint and require explicit public_access_cidrs in your cluster module.",
    ["aws-eks-ep", "cis-k8s", "aws-fsbp"])

GUIDANCE["AWS-EKS-002"] = g(
    5.0, 778, ["T1562.008"],
    [("No Kubernetes audit trail", "API server audit logs are not sent to CloudWatch Logs."),
     ("Investigations are blind", "You cannot see who changed or read cluster resources."),
     ("Compliance", "Audit logging is expected by CIS and most standards.")],
    ["Open EKS > Clusters > the cluster > Observability (Logging).", "Check which control plane log types are enabled."],
    "aws eks describe-cluster --name <name> --region <region> --query cluster.logging",
    ["Open EKS > Clusters > the cluster > Observability > Manage logging.", "Enable at least API server, Audit and Authenticator logs and save."],
    "aws eks update-cluster-config --name <name> --region <region> --logging '{\"clusterLogging\":[{\"types\":[\"api\",\"audit\",\"authenticator\",\"controllerManager\",\"scheduler\"],\"enabled\":true}]}'",
    'resource "aws_eks_cluster" "this" {\n  name     = "<name>"\n  role_arn = aws_iam_role.eks.arn\n  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]\n  # vpc_config ...\n}',
    "Enable all control plane log types in your module and set a log retention period.",
    ["aws-eks-log", "cis-k8s"])

# ----------------------------------------------------------------------------- KMS / CloudTrail / Lambda
GUIDANCE["AWS-KMS-001"] = g(
    4.4, 324, ["T1552"],
    [("Key material is never rotated", "The same cryptographic material protects data indefinitely."),
     ("Larger exposure window", "If the key material is ever compromised, all data encrypted with it is affected."),
     ("Automatic and free of downtime", "Rotation keeps old material for decryption and uses new material for encryption.")],
    ["Open KMS > Customer managed keys > the key > Key rotation.", "Check automatic rotation is off."],
    "aws kms get-key-rotation-status --key-id <key-id> --region <region>",
    ["Open KMS > Customer managed keys > the key.", "On the Key rotation tab select 'Automatically rotate this KMS key every year' (or set a custom period) and save."],
    "aws kms enable-key-rotation --key-id <key-id> --region <region>",
    'resource "aws_kms_key" "this" {\n  description         = "<name>"\n  enable_key_rotation = true\n}',
    "Enable rotation in your key module and check with the AWS Config rule cmk-backing-key-rotation-enabled.",
    ["aws-kms-rot", "cis-aws"])

GUIDANCE["AWS-CT-001"] = g(
    7.2, 778, ["T1562.008", "T1078.004"],
    [("Activity in some regions is not recorded", "No active multi-region trail logs management events everywhere."),
     ("Attackers use unwatched regions", "Crypto-mining and persistence often start in regions nobody monitors."),
     ("No forensic record", "Without CloudTrail you cannot reconstruct who did what.")],
    ["Open CloudTrail > Trails.", "Check a trail exists with 'Multi-region trail: Yes' and logging is On."],
    "aws cloudtrail describe-trails --query 'trailList[].{name:Name,multi:IsMultiRegionTrail}'\naws cloudtrail get-trail-status --name <trail-name>",
    ["Open the CloudTrail console > Trails > Create trail.", "Choose 'Enable for all regions', select a dedicated S3 bucket, enable log file validation and CloudWatch Logs.", "Make sure logging is started."],
    "aws cloudtrail create-trail --name org-trail --s3-bucket-name <log-bucket> --is-multi-region-trail --enable-log-file-validation\naws cloudtrail start-logging --name org-trail",
    'resource "aws_cloudtrail" "main" {\n  name                          = "org-trail"\n  s3_bucket_name                = aws_s3_bucket.trail.id\n  is_multi_region_trail         = true\n  include_global_service_events = true\n  enable_log_file_validation    = true\n}',
    "Use an organization trail managed centrally and alert when logging is stopped.",
    ["aws-ct-mr", "cis-aws", "aws-fsbp"])

GUIDANCE["AWS-CT-002"] = g(
    4.4, 353, ["T1562.008"],
    [("Log tampering is undetectable", "Without log file validation you cannot prove delivered logs were not altered."),
     ("Weaker forensics", "Altered logs undermine investigations and compliance evidence."),
     ("Simple to enable", "It adds digest files without affecting the trail.")],
    ["Open CloudTrail > Trails > the trail > General details.", "Check Log file validation is Disabled."],
    "aws cloudtrail describe-trails --trail-name-list <name> --query 'trailList[].LogFileValidationEnabled'",
    ["Open CloudTrail > Trails > the trail > General details > Edit.", "Enable Log file validation and save."],
    "aws cloudtrail update-trail --name <name> --enable-log-file-validation",
    'resource "aws_cloudtrail" "main" {\n  name                       = "<name>"\n  s3_bucket_name             = aws_s3_bucket.trail.id\n  enable_log_file_validation = true\n}',
    "Set log file validation in your trail module and restrict deletion of the log bucket.",
    ["aws-ct-val", "cis-aws"])

GUIDANCE["AWS-LMB-001"] = g(
    7.5, 306, ["T1190"],
    [("Anyone can invoke the function", "The function URL uses AuthType NONE, so no IAM authentication is required."),
     ("Cost and abuse", "Public invocation can be flooded or used to reach whatever the function's role can reach."),
     ("Application-level auth only", "Any flaw in the handler's own checks is directly exploitable.")],
    ["Open Lambda > the function > Configuration > Function URL.", "Check Auth type is NONE."],
    "aws lambda get-function-url-config --function-name <name> --region <region>",
    ["Open Lambda > the function > Configuration > Function URL > Edit.", "Set Auth type to AWS_IAM, or delete the function URL and front the function with API Gateway and an authorizer.", "Remove the resource-based permission that allows public invoke."],
    "aws lambda update-function-url-config --function-name <name> --region <region> --auth-type AWS_IAM",
    'resource "aws_lambda_function_url" "this" {\n  function_name      = "<name>"\n  authorization_type = "AWS_IAM"\n}',
    "Default to AWS_IAM for function URLs and require explicit approval for public ones.",
    ["aws-lambda-url", "aws-fsbp"])
