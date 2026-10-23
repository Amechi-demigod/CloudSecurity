"""AWS connector tests against moto's in-memory AWS (no network, no real credentials)."""
from __future__ import annotations

import io
import json
import zipfile
from datetime import UTC, datetime, timedelta

import pytest

boto3 = pytest.importorskip("boto3")
moto = pytest.importorskip("moto")

from botocore.exceptions import ClientError  # noqa: E402

from app.config import Settings  # noqa: E402
from app.connectors import aws as awsmod  # noqa: E402
from app.connectors.aws import (  # noqa: E402
    AwsConnector,
    ReadOnlyAwsClient,
    ReadOnlyViolation,
    check_operation,
    denies_insecure_transport,
    is_admin_policy,
    sg_rules,
)
from app.engine.attack_paths import compute_attack_paths  # noqa: E402
from app.engine.posture import evaluate_asset  # noqa: E402
from app.models import Finding  # noqa: E402
from app.services.ingest import asset_to_dict, ingest_collection  # noqa: E402

ACCOUNT = "123456789012"
REGIONS = ["us-east-1", "eu-west-1"]
TRUST_EC2 = json.dumps({"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]})
TRUST_LAMBDA = TRUST_EC2.replace("ec2.amazonaws.com", "lambda.amazonaws.com")
LATER = datetime.now(UTC) + timedelta(days=200)  # makes freshly created access keys "old"


@pytest.fixture()
def aws(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    with moto.mock_aws():
        build_environment()
        yield


def build_environment():
    ec2 = boto3.client("ec2", "us-east-1")
    vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    web_sg = ec2.create_security_group(GroupName="web", Description="web", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=web_sg, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}])
    db_sg = ec2.create_security_group(GroupName="db", Description="db", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=db_sg, IpPermissions=[
        {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    internal_sg = ec2.create_security_group(GroupName="internal", Description="i", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=internal_sg, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}])

    iam = boto3.client("iam")
    iam.create_role(RoleName="web-admin", AssumeRolePolicyDocument=TRUST_EC2)
    iam.attach_role_policy(RoleName="web-admin", PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    iam.create_instance_profile(InstanceProfileName="web-admin")
    iam.add_role_to_instance_profile(InstanceProfileName="web-admin", RoleName="web-admin")
    iam.create_role(RoleName="fn-role", AssumeRolePolicyDocument=TRUST_LAMBDA)
    iam.put_role_policy(RoleName="fn-role", PolicyName="logs", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "logs:*", "Resource": "*"}]}))
    iam.create_role(RoleName="inline-admin", AssumeRolePolicyDocument=TRUST_EC2)
    iam.put_role_policy(RoleName="inline-admin", PolicyName="all", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}))
    iam.create_user(UserName="alice")
    iam.create_login_profile(UserName="alice", Password="An0ther-long-Passw0rd!")
    iam.create_access_key(UserName="alice")
    iam.create_group(GroupName="admins")
    iam.attach_group_policy(GroupName="admins", PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    iam.create_user(UserName="bob")
    iam.add_user_to_group(GroupName="admins", UserName="bob")
    iam.update_account_password_policy(MinimumPasswordLength=8)

    image = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    ec2.run_instances(ImageId=image, MinCount=1, MaxCount=1, SecurityGroupIds=[web_sg],
                      IamInstanceProfile={"Name": "web-admin"},
                      TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "web-1"}]}])
    ec2.run_instances(ImageId=image, MinCount=1, MaxCount=1, SecurityGroupIds=[internal_sg],
                      MetadataOptions={"HttpTokens": "required"},
                      TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "worker-1"}]}])

    s3 = boto3.client("s3")
    s3.create_bucket(Bucket="acme-pii")
    s3.put_bucket_tagging(Bucket="acme-pii", Tagging={"TagSet": [{"Key": "data-classification", "Value": "PII"}]})
    s3.create_bucket(Bucket="acme-site")
    s3.put_bucket_acl(Bucket="acme-site", ACL="public-read")
    s3.create_bucket(Bucket="acme-locked", CreateBucketConfiguration={"LocationConstraint": "eu-west-1"})
    s3.put_public_access_block(Bucket="acme-locked", PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    s3.put_bucket_policy(Bucket="acme-locked", Policy=json.dumps({"Version": "2012-10-17", "Statement": [{
        "Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": ["arn:aws:s3:::acme-locked/*"],
        "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}))
    s3.put_bucket_versioning(Bucket="acme-locked", VersioningConfiguration={"Status": "Enabled"})

    rds = boto3.client("rds", "us-east-1")
    rds.create_db_instance(DBInstanceIdentifier="orders", DBInstanceClass="db.t3.micro", Engine="postgres",
                           MasterUsername="u", MasterUserPassword="p" * 12, AllocatedStorage=20,
                           PubliclyAccessible=True, StorageEncrypted=False, BackupRetentionPeriod=0,
                           VpcSecurityGroupIds=[db_sg])
    rds.create_db_instance(DBInstanceIdentifier="ledger", DBInstanceClass="db.t3.micro", Engine="postgres",
                           MasterUsername="u", MasterUserPassword="p" * 12, AllocatedStorage=20,
                           PubliclyAccessible=False, StorageEncrypted=True, BackupRetentionPeriod=14,
                           VpcSecurityGroupIds=[internal_sg])

    kms = boto3.client("kms", "eu-west-1")
    k1 = kms.create_key(Description="no rotation")["KeyMetadata"]["KeyId"]
    kms.create_alias(AliasName="alias/app-data", TargetKeyId=k1)
    k2 = kms.create_key(Description="rotated")["KeyMetadata"]["KeyId"]
    kms.enable_key_rotation(KeyId=k2)

    eks = boto3.client("eks", "eu-west-1")
    eks.create_cluster(name="prod-eks", roleArn=f"arn:aws:iam::{ACCOUNT}:role/eks", version="1.30",
                       resourcesVpcConfig={"subnetIds": [], "endpointPublicAccess": True,
                                           "publicAccessCidrs": ["0.0.0.0/0"]})

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("index.py", "def handler(e, c):\n    return 1\n")
    lam = boto3.client("lambda", "us-east-1")
    lam.create_function(FunctionName="hook", Runtime="python3.12", Role=f"arn:aws:iam::{ACCOUNT}:role/fn-role",
                        Handler="index.handler", Code={"ZipFile": buf.getvalue()})
    lam.create_function_url_config(FunctionName="hook", AuthType="NONE")

    s3.create_bucket(Bucket="trail-logs")
    ct = boto3.client("cloudtrail", "us-east-1")
    ct.create_trail(Name="local-trail", S3BucketName="trail-logs", IsMultiRegionTrail=False)
    ct.start_logging(Name="local-trail")


def settings(**kw) -> Settings:
    s = Settings()
    s.aws_auth_mode, s.aws_access_key_id, s.aws_secret_access_key = "auto", None, None
    s.aws_use_default_credentials, s.aws_role_arns, s.aws_external_id = True, [], None
    s.aws_regions, s.aws_home_region = list(REGIONS), "us-east-1"
    for k, v in kw.items():
        setattr(s, k, v)
    return s


def connector(**kw) -> AwsConnector:
    factory = kw.pop("session_factory", None)
    return AwsConnector(settings(**kw), session_factory=factory, sleep=lambda s: None, now=lambda: LATER)


def by_name(res, name, type_=None):
    return next(a for a in res.assets if a.name == name and (type_ is None or a.type == type_))


def failing(a):
    return {r.id for r, _ in evaluate_asset(asset_to_dict(a))}


def test_inventory_mapping(aws):
    res = connector().collect()
    assert res.errors == []
    for a in res.assets:
        assert a.provider == "aws" and a.subscription_id == ACCOUNT
    types = {a.type for a in res.assets}
    assert {"aws_account", "iam_role", "iam_user", "security_group", "ec2_instance", "s3_bucket", "rds_instance",
            "kms_key", "eks_cluster", "lambda_function", "cloudtrail_trail"} <= types
    acct = by_name(res, ACCOUNT, "aws_account")
    assert acct.properties["root_mfa_enabled"] is False and acct.properties["root_access_keys"] is False
    assert acct.properties["password_policy"]["minimum_length"] == 8
    assert acct.properties["cloudtrail_multi_region_logging"] is False

    web = by_name(res, "web-1")
    assert web.internet_exposed and web.properties["public_ip"]
    assert web.properties["iam_role"] == f"arn:aws:iam::{ACCOUNT}:role/web-admin"
    assert web.properties["imdsv2_required"] is False and "tcp/22" in web.properties["exposure"]
    worker = by_name(res, "worker-1")
    assert not worker.internet_exposed and worker.properties["imdsv2_required"] is True

    role = by_name(res, "web-admin", "iam_role")
    assert role.properties["admin"] and role.properties["admin_via"] == ["AdministratorAccess"]
    assert role.properties["scope"] == "account"
    assert "ec2.amazonaws.com" in role.properties["trusted_principals"]
    assert by_name(res, "inline-admin", "iam_role").properties["admin_via"] == ["*:* (customer/inline policy)"]
    assert not by_name(res, "fn-role", "iam_role").properties["admin"]
    alice, bob = by_name(res, "alice", "iam_user"), by_name(res, "bob", "iam_user")
    assert alice.properties["console_access"] and alice.properties["mfa_active"] is False
    assert alice.properties["access_keys"][0]["age_days"] >= 199
    assert bob.properties["admin"] and bob.properties["groups"] == ["admins"] and not bob.properties["direct_policies"]

    pii, site, locked = by_name(res, "acme-pii"), by_name(res, "acme-site"), by_name(res, "acme-locked")
    assert pii.sensitive_data and not pii.internet_exposed and pii.properties["data_classification"] == "PII"
    assert site.internet_exposed and site.properties["acl_public"] and "ACL" in site.properties["exposure"]
    assert locked.region == "eu-west-1" and locked.properties["public_access_block_enabled"]
    assert locked.properties["denies_insecure_transport"] and locked.properties["versioning"] == "Enabled"

    orders, ledger = by_name(res, "orders"), by_name(res, "ledger")
    assert orders.internet_exposed and orders.sensitive_data and orders.properties["backup_retention_days"] == 0
    assert not ledger.internet_exposed and ledger.properties["storage_encrypted"]
    eks = by_name(res, "prod-eks")
    assert eks.internet_exposed and eks.region == "eu-west-1" and eks.properties["audit_logging"] is False
    fn = by_name(res, "hook")
    assert fn.internet_exposed and fn.properties["url_auth_type"] == "NONE"
    keys = {a.name: a for a in res.assets if a.type == "kms_key"}
    assert keys["alias/app-data"].properties["rotation_enabled"] is False
    assert [k.properties["rotation_enabled"] for n, k in keys.items() if n != "alias/app-data"] == [True]
    trail = by_name(res, "local-trail")
    assert trail.properties["is_logging"] and not trail.properties["is_multi_region"]


def test_relationships(aws):
    res = connector().collect()
    ids = {(a.type, a.name): a.id for a in res.assets}
    rels = {(r.source_id, r.type, r.target_id) for r in res.relationships}
    web, role = ids[("ec2_instance", "web-1")], ids[("iam_role", "web-admin")]
    assert (ids[("security_group", "web")], "protects", web) in rels
    assert (web, "uses_identity", role) in rels
    assert (role, "has_access", ids[("s3_bucket", "acme-pii")]) in rels
    assert (role, "has_access", ids[("rds_instance", "orders")]) in rels
    assert (ids[("lambda_function", "hook")], "uses_identity", ids[("iam_role", "fn-role")]) in rels
    assert not any(s == ids[("iam_role", "fn-role")] and t == "has_access" for s, t, _ in rels)
    assert (ids[("security_group", "db")], "protects", ids[("rds_instance", "orders")]) in rels


def test_rules_fire_on_scanned_shapes(aws):
    res = connector().collect()
    assert failing(by_name(res, ACCOUNT, "aws_account")) == {"AWS-IAM-001", "AWS-IAM-003", "AWS-CT-001"}
    assert failing(by_name(res, "alice", "iam_user")) == {"AWS-IAM-004", "AWS-IAM-005"}
    assert failing(by_name(res, "bob", "iam_user")) == {"AWS-IAM-006"}
    assert failing(by_name(res, "web-admin", "iam_role")) == {"AWS-IAM-007"}
    assert failing(by_name(res, "fn-role", "iam_role")) == set()
    assert failing(by_name(res, "web-1")) == {"AWS-EC2-001", "AWS-EC2-002"}
    assert failing(by_name(res, "worker-1")) == set()
    assert failing(by_name(res, "web", "security_group")) == {"AWS-SG-001"}
    assert failing(by_name(res, "db", "security_group")) == {"AWS-SG-001", "AWS-SG-002"}
    assert failing(by_name(res, "internal", "security_group")) == set()
    assert failing(by_name(res, "acme-site")) == {"AWS-S3-001", "AWS-S3-002", "AWS-S3-003"}
    assert failing(by_name(res, "acme-locked")) == set()
    assert failing(by_name(res, "orders")) == {"AWS-RDS-001", "AWS-RDS-002", "AWS-RDS-003"}
    assert failing(by_name(res, "ledger")) == set()
    assert failing(by_name(res, "prod-eks")) == {"AWS-EKS-001", "AWS-EKS-002"}
    assert failing(by_name(res, "alias/app-data")) == {"AWS-KMS-001"}
    assert failing(by_name(res, "local-trail")) == {"AWS-CT-002"}
    assert failing(by_name(res, "hook")) == {"AWS-LMB-001"}


def test_attack_path_internet_ec2_admin_role_sensitive_data(aws):
    res = connector().collect()
    assets = {a.id: asset_to_dict(a) | {"sensitive_data": a.sensitive_data, "internet_exposed": a.internet_exposed}
              for a in res.assets}
    rels = [{"source_id": r.source_id, "target_id": r.target_id, "type": r.type} for r in res.relationships]
    findings = {a.id: [{"severity": r.severity, "title": r.title} for r, _ in evaluate_asset(asset_to_dict(a))]
                for a in res.assets}
    paths = compute_attack_paths(assets, rels, {}, findings, limit=50)
    web, pii, orders = by_name(res, "web-1").id, by_name(res, "acme-pii").id, by_name(res, "orders").id
    p = next(p for p in paths if p.entry_id == web and p.target_id == pii)
    assert [s.type for s in p.steps] == ["ec2_instance", "iam_role", "s3_bucket"]
    assert any("SSH/RDP" in r for r in p.steps[0].reasons)
    # the security group's finding is attributed to the instance through `protects`
    assert any(r.startswith("Exposed via security group web") and "SSH (22)" in r and r.endswith("open to Internet")
               for r in p.steps[0].reasons), p.steps[0].reasons
    assert p.confirmed and p.steps[0].weak
    assert any("AdministratorAccess (account scope)" in r for r in p.steps[1].reasons)
    assert p.severity in ("critical", "high")
    assert any(p.entry_id == web and p.target_id == orders for p in paths)
    assert any(p.entry_id == p.target_id == orders for p in paths)  # public database: one hop
    assert not any(p.entry_id == by_name(res, "worker-1").id for p in paths)


def test_only_read_operations_reach_aws(aws):
    calls = []

    def factory():
        s = boto3.Session(region_name="us-east-1")
        s.events.register("before-call.*.*", lambda model, **kw: calls.append(model.name))
        return s

    res = connector(session_factory=factory).collect()
    assert res.assets and calls
    for op in set(calls):
        assert op.startswith(("Describe", "List", "Get")) or op == "GenerateCredentialReport", op
    assert "GetObject" not in calls


@pytest.mark.parametrize("op", [
    "run_instances", "terminate_instances", "create_bucket", "put_bucket_policy", "delete_bucket", "put_object",
    "authorize_security_group_ingress", "modify_instance_attribute", "create_access_key", "attach_role_policy",
    "get_object", "get_password_data", "get_console_output", "get_secret_value", "get_parameter",
    "get_session_token", "get_function", "get_waiter", "generate_presigned_url", "generate_data_key",
])
def test_read_only_guard_blocks_writes_and_secret_reads(op):
    with pytest.raises(ReadOnlyViolation):
        check_operation("svc", op)


def test_read_only_guard_wraps_real_clients():
    c = ReadOnlyAwsClient(boto3.client("ec2", "us-east-1", aws_access_key_id="x", aws_secret_access_key="y"), "ec2")
    assert callable(c.describe_instances) and c.can_paginate("describe_instances")
    c.get_paginator("describe_instances")
    for name in ("run_instances", "terminate_instances", "get_password_data", "meta", "get_waiter"):
        with pytest.raises(ReadOnlyViolation):
            getattr(c, name)
    with pytest.raises(ReadOnlyViolation):
        c.get_paginator("describe_instances_with_side_effects".replace("describe", "create"))
    with pytest.raises(AttributeError):
        c._make_api_call  # noqa: B018 - raw escape hatch not exposed
    s3 = ReadOnlyAwsClient(boto3.client("s3", "us-east-1", aws_access_key_id="x", aws_secret_access_key="y"), "s3")
    for name in ("get_object", "put_object", "delete_bucket", "generate_presigned_url"):
        with pytest.raises(ReadOnlyViolation):
            getattr(s3, name)
    assert callable(s3.get_bucket_policy_status)
    iam = ReadOnlyAwsClient(boto3.client("iam", aws_access_key_id="x", aws_secret_access_key="y"), "iam")
    assert callable(iam.generate_credential_report) and callable(iam.get_account_password_policy)


def test_region_and_service_failures_are_isolated(aws, monkeypatch):
    original = awsmod.AwsClients.__call__

    def flaky(self, service, region):
        if region == "eu-west-1":
            raise ClientError({"Error": {"Code": "AuthFailure", "Message": "region not enabled"}}, "Describe")
        if service == "lambda":
            raise ClientError({"Error": {"Code": "ThrottlingException", "Message": "Rate exceeded"}}, "ListFunctions")
        return original(self, service, region)

    monkeypatch.setattr(awsmod.AwsClients, "__call__", flaky)
    res = connector().collect()
    assert {"ec2_instance", "rds_instance", "iam_role", "s3_bucket"} <= {a.type for a in res.assets}
    assert not any(a.type in {"eks_cluster", "kms_key", "lambda_function"} for a in res.assets)
    assert f"{ACCOUNT}/us-east-1/lambda: ClientError: An error occurred (ThrottlingException) when calling the " \
           "ListFunctions operation: Rate exceeded" in res.errors
    assert sum(e.startswith(f"{ACCOUNT}/eu-west-1/") for e in res.errors) == 6
    assert any(e.startswith(f"{ACCOUNT}/s3 acme-locked:") for e in res.errors)  # bucket in the failing region


def test_partial_scan_is_recorded_on_the_scan_run(aws, monkeypatch, session):
    from app.services import scans

    original = awsmod.AwsClients.__call__

    def flaky(self, service, region):
        if service == "eks":
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "nope"}}, "ListClusters")
        return original(self, service, region)

    monkeypatch.setattr(awsmod.AwsClients, "__call__", flaky)
    run = scans.start_scan(connector(), background=False)
    assert run.status == "succeeded" and run.connector == "aws" and run.assets_found > 15
    assert len(run.errors) == 2 and all("/eks: ClientError" in e for e in run.errors)
    rule_ids = {f.rule_id for f in session.query(Finding).filter(Finding.source == "aws")}
    assert {"AWS-EC2-001", "AWS-S3-001", "AWS-IAM-001"} <= rule_ids


def test_cross_account_roles_with_external_id(aws, monkeypatch):
    assumed = []

    def factory():
        s = boto3.Session(region_name="us-east-1")
        s.events.register("provide-client-params.sts.AssumeRole", lambda params, **kw: assumed.append(dict(params)))
        return s

    good = "arn:aws:iam::111111111111:role/cnapp-readonly"
    bad = "arn:aws:iam::222222222222:role/cnapp-readonly"
    real = awsmod.assume_role_session

    def assume(base, arn, external_id, region):
        if arn == bad:
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "not authorized"}}, "AssumeRole")
        return real(base, arn, external_id, region)

    monkeypatch.setattr(awsmod, "assume_role_session", assume)
    conn = connector(session_factory=factory, aws_role_arns=[bad, good], aws_external_id="cnapp-ext-123",
                     aws_regions=["us-east-1"])
    res = conn.collect()
    assert assumed and assumed[0]["RoleArn"] == good and assumed[0]["ExternalId"] == "cnapp-ext-123"
    assert assumed[0]["RoleSessionName"] == "cnapp-readonly-scan"
    assert {a.subscription_id for a in res.assets} == {"111111111111"}
    assert res.errors[0].startswith(f"{bad}: ClientError")
    assert conn.scope() == ["222222222222", "111111111111"]


def test_credentials_failure_is_reported():
    def boom():
        raise RuntimeError("no credentials")
    res = connector(session_factory=boom).collect()
    assert res.assets == [] and res.errors == ["credentials: RuntimeError: no credentials"]


@pytest.mark.parametrize("kw,mode", [
    ({}, None),
    ({"aws_access_key_id": "AKIAABCDEFGHIJKLMNOP", "aws_secret_access_key": "s"}, "access_key"),
    ({"aws_use_default_credentials": True}, "default"),
    ({"aws_auth_mode": "default"}, "default"),
    ({"aws_auth_mode": "access_key"}, None),
    ({"aws_auth_mode": "access_key", "aws_access_key_id": "AKIAABCDEFGHIJKLMNOP", "aws_secret_access_key": "s"},
     "access_key"),
])
def test_auth_mode_and_is_configured(kw, mode):
    s = settings(**{"aws_use_default_credentials": False, **kw})
    assert awsmod.resolve_auth_mode(s) == mode
    assert AwsConnector(s).is_configured() is (mode is not None)
    info = AwsConnector(s).info()
    assert info["auth_mode"] == mode and "SecurityAudit" in info["description"]


def test_secrets_never_in_info_or_repr():
    s = settings(aws_access_key_id="AKIAABCDEFGHIJKLMNOP", aws_secret_access_key="TOP-SECRET-VALUE",
                 aws_external_id="EXTERNAL-ID-VALUE")
    blob = json.dumps(AwsConnector(s).info()) + repr(s)
    assert "TOP-SECRET-VALUE" not in blob and "EXTERNAL-ID-VALUE" not in blob


def test_boto_config_retries_throttling():
    cfg = awsmod.boto_config()
    assert cfg.retries == {"mode": "adaptive", "max_attempts": 10}
    assert "readonly" in cfg.user_agent_extra


def test_policy_helpers():
    assert is_admin_policy({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
    assert is_admin_policy({"Statement": {"Effect": "Allow", "Action": ["s3:Get*", "*:*"], "Resource": ["*"]}})
    assert is_admin_policy("%7B%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22%2A%22%2C"
                           "%22Resource%22%3A%22%2A%22%7D%5D%7D")
    assert not is_admin_policy({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::x"}]})
    assert not is_admin_policy({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*",
                                               "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}]})
    assert not is_admin_policy({"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]})
    assert denies_insecure_transport({"Statement": [{"Effect": "Deny", "Condition": {
        "Bool": {"aws:SecureTransport": False}}}]})
    assert not denies_insecure_transport({"Statement": [{"Effect": "Allow", "Condition": {
        "Bool": {"aws:SecureTransport": "false"}}}]})
    rules = sg_rules("sg-1", [{"IpProtocol": "icmp", "FromPort": -1, "ToPort": -1, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                              {"IpProtocol": "tcp", "FromPort": 0, "ToPort": 65535, "IpRanges": [{"CidrIp": "1.2.3.4/32"}]},
                              {"IpProtocol": "udp", "FromPort": 53, "ToPort": 54,
                               "UserIdGroupPairs": [{"GroupId": "sg-2"}]}])
    assert [r["port_ranges"] for r in rules] == [["none"], ["*"], ["53-54"]]
    assert rules[2]["source_prefixes"] == ["sg:sg-2"]
    assert awsmod.internet_rules(rules) == []


def test_rescan_resolves_fixed_findings(aws, session):
    ingest_collection(session, connector().collect(), source="aws")
    boto3.client("ec2", "us-east-1").modify_instance_metadata_options(
        InstanceId=by_name(connector().collect(), "web-1").properties["instance_id"], HttpTokens="required")
    stats = ingest_collection(session, connector().collect(), source="aws")
    assert stats["findings_resolved"] >= 1
    f = session.query(Finding).filter(Finding.rule_id == "AWS-EC2-002").one()
    assert f.status == "resolved" and f.source == "aws"
