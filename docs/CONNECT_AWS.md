# Connect AWS (read-only)

The AWS connector inventories one or more AWS accounts with boto3 and feeds the
same inventory, posture findings, attack paths and dashboard as the Azure
connector (`source="aws"`). It never changes anything in AWS:

- the IAM principal only gets the AWS managed policies **SecurityAudit** and
  **ViewOnlyAccess**, and
- in code every boto3 client is wrapped in `ReadOnlyAwsClient`, which only lets
  `describe_*` / `list_*` / `get_*` calls (plus `generate_credential_report`)
  through and blocks the read calls that return data or secrets (`get_object`,
  Lambda code, SSM parameters, Secrets Manager values, EC2 password data). Tests
  enforce it.

This guide sets it up for the **on-prem server** (`cnapp-ctl`, settings in
`/opt/cnapp/cnapp.env`). For a local/dev backend put the same variables in `.env`.

## What is scanned

| Resource | Collected | Rules |
|---|---|---|
| Account | alias, root MFA + root access keys (credential report / account summary), password policy, S3 account Block Public Access, CloudTrail coverage | AWS-IAM-001 root MFA (CIS 1.5), AWS-IAM-002 root keys (CIS 1.4), AWS-IAM-003 password length (CIS 1.8), AWS-CT-001 multi-region trail (CIS 3.1) |
| IAM users / roles | attached, group and inline policies, `*:*` admin, console access, MFA, access key age, trust policy, instance profiles | AWS-IAM-004 console user without MFA (CIS 1.10), AWS-IAM-005 key older than 90 days (CIS 1.14), AWS-IAM-006/007 `*:*` admin user / role (CIS 1.16) |
| S3 buckets | region, Block Public Access (bucket + account), policy status, ACL, encryption, versioning, TLS-only policy, tags | AWS-S3-001 public (CIS 2.1.4), AWS-S3-002 Block Public Access (CIS 2.1.4), AWS-S3-003 HTTP not denied (CIS 2.1.1) |
| EC2 instances | public IP, security groups, instance profile → role, IMDSv2 | AWS-EC2-001 SSH/RDP open to the internet (CIS 5.2/5.3), AWS-EC2-002 IMDSv1 (CIS 5.6) |
| Security groups | normalized ingress rules | AWS-SG-001 22/3389 from 0.0.0.0/0 or ::/0 (CIS 5.2/5.3), AWS-SG-002 all ports (CIS 5.2/5.3), AWS-SG-003 default SG has rules (CIS 5.4) |
| RDS instances | public, encryption, backup retention, security groups | AWS-RDS-001 public (CIS 2.3.3), AWS-RDS-002 unencrypted (CIS 2.3.1), AWS-RDS-003 backups < 7 days (FSBP RDS.11) |
| EKS clusters | endpoint public/private access + CIDRs, control-plane logging | AWS-EKS-001 public unrestricted endpoint (CIS EKS 5.4.2), AWS-EKS-002 audit logging (CIS EKS 2.1.1) |
| KMS keys | customer managed symmetric keys, rotation | AWS-KMS-001 rotation disabled (CIS 3.6) |
| CloudTrail trails | multi-region, logging, log file validation | AWS-CT-002 log file validation (CIS 3.2) |
| Lambda functions | runtime, execution role, function URL auth type | AWS-LMB-001 function URL with `AuthType NONE` (FSBP Lambda.1) |

Relationships: security group → instance / RDS (`protects`), instance and Lambda
→ IAM role (`uses_identity`), role/user with admin, PowerUser or S3/RDS full-access
policies → S3 buckets / RDS instances (`has_access`). An EC2 instance is
internet-exposed when it has a public IP **and** an attached security group allows
0.0.0.0/0 or ::/0; that gives attack paths such as *Internet → web-1 (SSH open) →
web-admin role (AdministratorAccess) → customer-data bucket (PII)*; a
security group finding (SSH/RDP/all ports open) is attributed to the instances it
protects, e.g. *Exposed via security group web: SSH (22) open to Internet*. Buckets are
sensitive when tagged `data-classification` / `classification` / `sensitivity` /
`data` (not `public`); RDS databases always are.

## Choose a layout

- **One account:** a dedicated IAM user with the two policies (step 1), or the
  server's instance role if it runs on EC2 (`AWS_USE_DEFAULT_CREDENTIALS=true`).
- **Several accounts (recommended for organizations):** the IAM user may only
  assume a read-only role, and every target account has that role with an
  **external ID** (steps 1 + 2). Only the accounts listed in `AWS_ROLE_ARNS` are
  scanned, so also deploy the role into the user's own account if it should be
  scanned.

## 1. Create the scanner IAM user

Run with an administrator profile in the account that will hold the user (for
multi-account setups, e.g. your security/audit account):

```bash
aws iam create-user --user-name cnapp-scanner

# One account: give the user the read-only policies directly
aws iam attach-user-policy --user-name cnapp-scanner \
  --policy-arn arn:aws:iam::aws:policy/SecurityAudit
aws iam attach-user-policy --user-name cnapp-scanner \
  --policy-arn arn:aws:iam::aws:policy/job-function/ViewOnlyAccess

aws iam create-access-key --user-name cnapp-scanner
# -> AccessKeyId and SecretAccessKey: shown once, keep them for step 3
```

Note `ViewOnlyAccess` lives under `policy/job-function/`.

For **multi-account**, do not attach the two policies to the user. Allow it only to
assume the scanner role instead:

```bash
aws iam put-user-policy --user-name cnapp-scanner --policy-name assume-cnapp-readonly \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
    "Action":"sts:AssumeRole","Resource":"arn:aws:iam::*:role/CNAPPReadOnly"}]}'
```

Optional hardening: deny every call that does not come from the server's public
egress address (replace `203.0.113.10`):

```bash
aws iam put-user-policy --user-name cnapp-scanner --policy-name only-from-cnapp-server \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*",
    "Condition":{"NotIpAddress":{"aws:SourceIp":["203.0.113.10/32"]},"Bool":{"aws:ViaAWSService":"false"}}}]}'
```

## 2. Cross-account read-only role (multi-account only)

Generate an external ID once (it is not a password, but keep it out of tickets
and chat): `openssl rand -hex 16`.

**CloudFormation** (deploy into every target account, or to all accounts of an
organization with a service-managed **StackSet**):

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: Read-only role for the CloudSecurity CNAPP scanner
Parameters:
  ScannerPrincipalArn:
    Type: String
    Description: ARN of the cnapp-scanner IAM user, e.g. arn:aws:iam::111111111111:user/cnapp-scanner
  ExternalId:
    Type: String
    NoEcho: true
    MinLength: 16
Resources:
  CNAPPReadOnly:
    Type: AWS::IAM::Role
    Properties:
      RoleName: CNAPPReadOnly
      MaxSessionDuration: 3600
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal: { AWS: !Ref ScannerPrincipalArn }
            Action: sts:AssumeRole
            Condition:
              StringEquals: { "sts:ExternalId": !Ref ExternalId }
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/SecurityAudit
        - arn:aws:iam::aws:policy/job-function/ViewOnlyAccess
Outputs:
  RoleArn:
    Value: !GetAtt CNAPPReadOnly.Arn
```

```bash
aws cloudformation deploy --stack-name cnapp-readonly --template-file cnapp-readonly.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides ScannerPrincipalArn=arn:aws:iam::111111111111:user/cnapp-scanner ExternalId=<external-id>
```

**AWS CLI** equivalent (run in each target account):

```bash
cat > trust.json <<'EOF'
{"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
  "Principal": {"AWS": "arn:aws:iam::111111111111:user/cnapp-scanner"},
  "Action": "sts:AssumeRole",
  "Condition": {"StringEquals": {"sts:ExternalId": "<external-id>"}}}]}
EOF
aws iam create-role --role-name CNAPPReadOnly --max-session-duration 3600 \
  --assume-role-policy-document file://trust.json
aws iam attach-role-policy --role-name CNAPPReadOnly --policy-arn arn:aws:iam::aws:policy/SecurityAudit
aws iam attach-role-policy --role-name CNAPPReadOnly --policy-arn arn:aws:iam::aws:policy/job-function/ViewOnlyAccess
```

The scanner assumes each role with the session name `cnapp-readonly-scan` (visible
in CloudTrail) and refreshes the 1-hour credentials during long scans.

## 3. Configure the server

Edit `/opt/cnapp/cnapp.env` (root only, mode 0600) and fill the AWS block:

```bash
sudo nano /opt/cnapp/cnapp.env
```

```bash
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
# Multi-account only (comma-separated) + the external ID from step 2
AWS_ROLE_ARNS=arn:aws:iam::222222222222:role/CNAPPReadOnly,arn:aws:iam::333333333333:role/CNAPPReadOnly
AWS_EXTERNAL_ID=<external-id>
# Optional: limit regions (default: every region enabled in each account)
AWS_REGIONS=eu-west-1,us-east-1
```

Older installs whose `cnapp.env` predates these settings: just add the lines.
On EC2 with an instance role use `AWS_USE_DEFAULT_CREDENTIALS=true` instead of the
access key. GovCloud / China: also set `AWS_HOME_REGION` (`us-gov-west-1`,
`cn-north-1`).

Apply and check:

```bash
sudo cnapp-ctl restart
sudo cnapp-ctl logs backend --tail 50     # the secret is never logged
```

The backend refuses to start on malformed values (half an access key pair, a role
ARN that is not `arn:aws:iam::<12 digits>:role/...`, an invalid region or external
ID) and says which setting is wrong, without echoing secrets.

Then open **Connectors & scans**: the AWS card shows *Configured*, the accounts and
regions; click **Run scan** (analyst or admin). `GET /api/health` reports
`aws_configured: true`. Results appear in **Inventory** and **Findings** (filter
**Cloud = AWS**), attack paths and the dashboard.

## Network and proxy

The server needs outbound HTTPS (TCP 443) to the AWS API endpoints:
`sts.amazonaws.com` / `sts.<region>.amazonaws.com`, `iam.amazonaws.com`,
`s3.amazonaws.com` / `s3.<region>.amazonaws.com`, `<account>.s3-control.<region>.amazonaws.com`
and `ec2|eks|rds|kms|lambda|cloudtrail.<region>.amazonaws.com` for every scanned
region. If it must use a proxy, set it in `/opt/cnapp/cnapp.env` (boto3 honours it):

```bash
HTTPS_PROXY=http://proxy.corp.local:3128
NO_PROXY=.corp.local
```

and `sudo cnapp-ctl restart`. If the proxy inspects TLS, its CA must be trusted
by the backend image (otherwise certificate verification fails; verification is
never disabled).

## Scans, throttling and partial results

- API throttling is retried automatically (botocore *adaptive* retry mode, up to
  10 attempts); every list call is paginated.
- A failure in one account, region or service (AccessDenied from an SCP, a region
  that is not enabled, an API outage) is recorded in the scan's **errors** (see
  **Scan history**, *N errors*) and the rest of the scan continues. A scan is only
  *failed* when it collected nothing.
- Re-scans resolve findings that now pass. Scheduled scans use the same entry
  point as **Run scan**.

## Rotate or remove

- Rotate the access key: `aws iam create-access-key --user-name cnapp-scanner`, put
  the new pair in `cnapp.env`, `sudo cnapp-ctl restart`, then
  `aws iam delete-access-key --user-name cnapp-scanner --access-key-id <old>`.
- Disconnect: empty the `AWS_*` values in `cnapp.env`, restart, and delete the
  user (and the `cnapp-readonly` stacks / roles).

## Troubleshooting

| Symptom | Fix |
|---|---|
| Card says *Not configured* | Both `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` set (or `AWS_USE_DEFAULT_CREDENTIALS=true`), then `sudo cnapp-ctl restart` |
| `credentials: ...` error, nothing scanned | Wrong/deleted key, clock skew on the server, or no route/proxy to `sts.amazonaws.com` |
| `arn:aws:iam::...: ClientError ... AssumeRole ... AccessDenied` | Trust policy principal or external ID does not match, or the user lacks `sts:AssumeRole` on that role |
| `<account>/<region>/<service>: ... AccessDenied` | An SCP or permissions boundary denies the read; the other services still scan |
| `<account>/<region>/...: AuthFailure` / `UnrecognizedClientException` | Region not enabled for the account: limit `AWS_REGIONS` |
| Findings for every VPC's default security group | Expected by CIS 5.4: remove all rules from the default security groups |
