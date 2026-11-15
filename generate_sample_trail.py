"""
Generate a reproducible synthetic AWS CloudTrail log for the lab.

Scenario (account 111122223333, 2026-11-12, us-east-1):
  * 203.0.113.77  brute-forces the AWS console as IAM user 'j.smith' and gets in
                  WITHOUT MFA -> recon burst -> creates backdoor user 'backup-svc'
                  -> gives it an access key + AdministratorAccess -> stops CloudTrail
  * 198.51.100.200 uses the backdoor access key to make an S3 bucket public and
                  mass-download customer data
  * Benign noise that must NOT be flagged: 'alice' (MFA logins, normal admin reads),
    'bob' (one typo then MFA login), a CI role uploading build artifacts.

All IPs are RFC 5737 documentation ranges. Run: python generate_sample_trail.py
"""
import json
import zlib
import random
from datetime import datetime, timedelta, timezone

SEED = 1337
ACCOUNT = "111122223333"
REGION = "us-east-1"
OUT = "cloudtrail_sample.json"

ATTACKER_IP = "203.0.113.77"
EXFIL_IP = "198.51.100.200"
CORP_IP = "192.0.2.10"
BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36"
CLI_UA = "aws-cli/2.17.0 Python/3.11.8 Linux/6.5 exe/x86_64"
BACKDOOR_KEY = "AKIAEXAMPLEBACKDOOR1"

rng = random.Random(SEED)
records = []


def iam_user(name, key=None):
    ident = {
        "type": "IAMUser",
        "principalId": f"AIDA{zlib.crc32(name.encode()):012d}",
        "arn": f"arn:aws:iam::{ACCOUNT}:user/{name}",
        "accountId": ACCOUNT,
        "userName": name,
    }
    if key:
        ident["accessKeyId"] = key
    return ident


def role(name, session):
    return {
        "type": "AssumedRole",
        "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/{name}/{session}",
        "accountId": ACCOUNT,
        "sessionContext": {"sessionIssuer": {"type": "Role", "userName": name}},
    }


def event(ts, source, name, ident, ip, ua=CLI_UA, req=None, resp=None, extra=None, error=None):
    rec = {
        "eventVersion": "1.09",
        "eventTime": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventSource": source,
        "eventName": name,
        "awsRegion": REGION,
        "sourceIPAddress": ip,
        "userAgent": ua,
        "userIdentity": ident,
        "requestParameters": req,
        "responseElements": resp,
        "eventID": f"{rng.getrandbits(64):016x}",
        "recipientAccountId": ACCOUNT,
    }
    if extra:
        rec["additionalEventData"] = extra
    if error:
        rec["errorCode"] = error
        rec["errorMessage"] = "User is not authorized to perform this operation"
    records.append(rec)


def console_login(ts, user, ip, ok, mfa):
    event(ts, "signin.amazonaws.com", "ConsoleLogin", iam_user(user), ip, BROWSER_UA,
          resp={"ConsoleLogin": "Success" if ok else "Failure"},
          extra={"MFAUsed": "Yes" if mfa else "No", "LoginTo": "https://console.aws.amazon.com/"})


day = datetime(2026, 11, 12, tzinfo=timezone.utc)

# ---------------- benign background ----------------
console_login(day.replace(hour=8, minute=2, second=11), "alice", CORP_IP, True, True)
for i, (src, name) in enumerate([
    ("ec2.amazonaws.com", "DescribeInstances"), ("s3.amazonaws.com", "ListBuckets"),
    ("cloudwatch.amazonaws.com", "DescribeAlarms"), ("ec2.amazonaws.com", "DescribeSecurityGroups"),
    ("rds.amazonaws.com", "DescribeDBInstances"), ("iam.amazonaws.com", "ListUsers"),
]):
    event(day.replace(hour=8, minute=5 + i * 7), src, name, iam_user("alice"), CORP_IP, BROWSER_UA)

console_login(day.replace(hour=9, minute=14, second=3), "bob", CORP_IP, False, False)  # typo
console_login(day.replace(hour=9, minute=14, second=40), "bob", CORP_IP, True, True)
event(day.replace(hour=9, minute=20), "lambda.amazonaws.com", "ListFunctions20150331", iam_user("bob"), CORP_IP, BROWSER_UA)

ci = role("github-actions-deploy", "run-8812")
for i in range(25):  # build artifact uploads every ~20 min
    ts = day.replace(hour=0) + timedelta(minutes=20 * i, seconds=rng.randint(0, 50))
    event(ts, "s3.amazonaws.com", "PutObject", ci, "192.0.2.50", "aws-sdk-js/3.600",
          req={"bucketName": "acme-build-artifacts", "key": f"builds/{8000 + i}.zip"})
    event(ts + timedelta(seconds=4), "s3.amazonaws.com", "GetObject", ci, "192.0.2.50", "aws-sdk-js/3.600",
          req={"bucketName": "acme-build-artifacts", "key": "cache/deps.tar.gz"})

# ---------------- attack ----------------
t = day.replace(hour=2, minute=41, second=5)
for _ in range(14):  # console brute force
    console_login(t, "j.smith", ATTACKER_IP, False, False)
    t += timedelta(seconds=rng.randint(12, 30))
console_login(t, "j.smith", ATTACKER_IP, True, False)  # success, no MFA
compromised_login = t

# Recon burst: many distinct read APIs in a few minutes (some denied)
recon = [
    ("sts.amazonaws.com", "GetCallerIdentity"), ("iam.amazonaws.com", "ListUsers"),
    ("iam.amazonaws.com", "ListRoles"), ("iam.amazonaws.com", "ListPolicies"),
    ("iam.amazonaws.com", "ListAttachedUserPolicies"), ("iam.amazonaws.com", "GetAccountAuthorizationDetails"),
    ("s3.amazonaws.com", "ListBuckets"), ("s3.amazonaws.com", "GetBucketPolicy"),
    ("s3.amazonaws.com", "GetBucketAcl"), ("ec2.amazonaws.com", "DescribeInstances"),
    ("ec2.amazonaws.com", "DescribeVpcs"), ("ec2.amazonaws.com", "DescribeSecurityGroups"),
    ("rds.amazonaws.com", "DescribeDBInstances"), ("lambda.amazonaws.com", "ListFunctions20150331"),
    ("secretsmanager.amazonaws.com", "ListSecrets"), ("kms.amazonaws.com", "ListKeys"),
    ("cloudtrail.amazonaws.com", "DescribeTrails"), ("guardduty.amazonaws.com", "ListDetectors"),
    ("organizations.amazonaws.com", "DescribeOrganization"), ("iam.amazonaws.com", "ListAccessKeys"),
]
t += timedelta(seconds=40)
for src, name in recon:
    denied = name in {"GetAccountAuthorizationDetails", "DescribeOrganization", "ListSecrets"}
    event(t, src, name, iam_user("j.smith"), ATTACKER_IP, CLI_UA, error="AccessDenied" if denied else None)
    t += timedelta(seconds=rng.randint(5, 12))

# Persistence + privilege escalation
t += timedelta(seconds=30)
event(t, "iam.amazonaws.com", "CreateUser", iam_user("j.smith"), ATTACKER_IP,
      req={"userName": "backup-svc"}, resp={"user": {"userName": "backup-svc"}})
t += timedelta(seconds=22)
event(t, "iam.amazonaws.com", "CreateAccessKey", iam_user("j.smith"), ATTACKER_IP,
      req={"userName": "backup-svc"},
      resp={"accessKey": {"userName": "backup-svc", "accessKeyId": BACKDOOR_KEY, "status": "Active"}})
t += timedelta(seconds=19)
event(t, "iam.amazonaws.com", "AttachUserPolicy", iam_user("j.smith"), ATTACKER_IP,
      req={"userName": "backup-svc", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"})

# Defense evasion
t += timedelta(seconds=48)
event(t, "cloudtrail.amazonaws.com", "StopLogging", iam_user("j.smith"), ATTACKER_IP,
      req={"name": f"arn:aws:cloudtrail:{REGION}:{ACCOUNT}:trail/org-trail"})

# Exfiltration with the backdoor key from a second IP
bd = iam_user("backup-svc", BACKDOOR_KEY)
t += timedelta(minutes=6)
event(t, "s3.amazonaws.com", "DeletePublicAccessBlock", bd, EXFIL_IP, req={"bucketName": "acme-customer-data"})
t += timedelta(seconds=15)
policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*",
          "Action": "s3:GetObject", "Resource": "arn:aws:s3:::acme-customer-data/*"}]}
event(t, "s3.amazonaws.com", "PutBucketPolicy", bd, EXFIL_IP,
      req={"bucketName": "acme-customer-data", "bucketPolicy": policy})
for i in range(120):
    t += timedelta(seconds=rng.randint(1, 3))
    event(t, "s3.amazonaws.com", "GetObject", bd, EXFIL_IP,
          req={"bucketName": "acme-customer-data", "key": f"exports/customers_{i:03d}.csv"})

records.sort(key=lambda r: r["eventTime"])
with open(OUT, "w") as fh:
    json.dump({"Records": records}, fh, indent=1)
print(f"[+] Wrote {len(records)} CloudTrail records to {OUT} (seed {SEED})")
