# AWS CloudTrail Hunter ☁️🛡️

A Python tool that hunts an **AWS CloudTrail** log for every stage of a cloud account takeover, from console brute force to S3 data theft. It maps each stage to **MITRE ATT&CK**, follows the attacker across identities (a compromised user, a backdoor user and a stolen access key) and rebuilds the **attack timeline**. Built as a hands-on cloud SOC / incident-response lab.

![Python](https://img.shields.io/badge/Python-3.9+-blue) ![Dependencies](https://img.shields.io/badge/dependencies-stdlib%20only-lightgrey) ![Tests](https://img.shields.io/badge/tests-11%20passing-brightgreen) ![AWS](https://img.shields.io/badge/AWS-CloudTrail-orange)

## What it detects

| Stage | Detection | How | MITRE ATT&CK |
|---|---|---|---|
| Credential access | **Console brute force** | ≥5 failed `ConsoleLogin` from one IP inside a 10-minute sliding window | T1110.001 |
| Initial access | **Account compromise** | Successful console login from an IP already flagged for brute force (flags missing MFA) | T1078.004 |
| Initial access | **Root login / login without MFA** | Root console use, or any console login with `MFAUsed: No` | T1078.004 |
| Discovery | **Cloud discovery burst** | One identity calls ≥12 *different* List/Describe/Get APIs in 5 minutes; counts `AccessDenied` probing | T1580 |
| Persistence | **New IAM user / console password** | `CreateUser`, `CreateLoginProfile` | T1136.003, T1098.001 |
| Persistence | **Access key created for another user** | `CreateAccessKey` where the target user is not the caller | T1098.001 |
| Privilege escalation | **Admin policy attached** | `AdministratorAccess` or an inline `"Action": "*"` policy attached to a user/role/group | T1098.003 |
| Defense evasion | **Logging disabled** | `StopLogging`, `DeleteTrail`, GuardDuty `DeleteDetector`, `DeleteFlowLogs`, Config recorder stopped… | T1562.008 |
| Collection / exfiltration | **S3 bucket exposed** | Public access block removed, or a bucket policy/ACL granting `*` / `AllUsers` | T1530 |
| Collection / exfiltration | **S3 mass download** | ≥50 `GetObject` calls by one identity on one bucket in 10 minutes | T1530 |

### Identity correlation

Cloud attackers rarely stay as one user. The hunter **taints** every identity the attacker controls and follows it:

1. `j.smith` logs in from the brute-forcing IP → **compromised**
2. `j.smith` creates `backup-svc` → `backup-svc` is tainted
3. `j.smith` creates access key `AKIA…BACKDOOR1` for `backup-svc` → the **key** is tainted
4. That key is later used from a **completely different IP** → still attributed to the intrusion

Any finding by a tainted identity is **escalated one severity level** and annotated with how it links back to the original compromise.

## Lab scenario

`generate_sample_trail.py` builds a reproducible synthetic CloudTrail log (221 records, seed 1337) for account `111122223333`:

- **203.0.113.77**: 14 failed console logins as `j.smith`, then **gets in without MFA** → 20-API recon burst (3 denied) → creates `backup-svc` → gives it an access key and **AdministratorAccess** → **stops CloudTrail**
- **198.51.100.200**: uses the backdoor key to remove the public access block on `acme-customer-data`, make it **public**, and download **120 customer export files**
- **Benign noise that must not be flagged:** `alice` (MFA login, routine admin reads), `bob` (one password typo, then MFA login), and a GitHub Actions CI role uploading and downloading build artifacts all day

All IPs are RFC 5737 documentation ranges; all keys and account IDs are fake.

## Quick start

```bash
python generate_sample_trail.py                 # creates cloudtrail_sample.json
python cloudtrail_hunter.py cloudtrail_sample.json --report report.md --json findings.json
pip install -r requirements.txt && pytest -q    # 11 tests
```

Works on a real trail too: point it at a single file or an unzipped S3 export directory (`AWSLogs/…`, `.json` or `.json.gz`). The exit code is `1` when any CRITICAL finding exists, so it can gate a CI job or a SOAR playbook.

## Results

```
[CRITICAL] Account Compromise: Successful console login as 'j.smith' from brute-forcing IP 203.0.113.77 without MFA  (T1078.004)
      - 14 failed attempts from this IP before the success
[CRITICAL] Access Key Created: 'j.smith' created access key AKIAEXAMPLEBACKDOOR1 for 'backup-svc'  (T1098.001)
[CRITICAL] Admin Policy Attached: 'j.smith' granted full admin rights to 'backup-svc'  (T1098.003)
[CRITICAL] Logging Disabled: CloudTrail logging stopped by 'j.smith'  (T1562.008)
[CRITICAL] S3 Bucket Exposed: 'backup-svc' made public: bucket 'acme-customer-data'  (T1530)
      - Used access key AKIAEXAMPLEBACKDOOR1 created by attacker-controlled 'j.smith' for 'backup-svc'
[CRITICAL] S3 Mass Download: 'backup-svc' downloaded 120 objects from 'acme-customer-data' (peak 120 in 10 min)  (T1530)
[HIGH] Console Brute Force: 203.0.113.77 made 14 failed console logins (peak 14 in 10 min)  (T1110.001)
[HIGH] Cloud Discovery Burst: 'j.smith' called 20 different List/Describe/Get APIs within 5 minutes  (T1580)
      - 3 of 20 calls were AccessDenied (permission probing)
[HIGH] New IAM User: 'j.smith' created IAM user 'backup-svc'  (T1136.003)
[+] 10 findings

[*] Attack timeline
    2026-11-12 02:41:05  Console Brute Force        j.smith      203.0.113.77
    2026-11-12 02:45:45  Account Compromise         j.smith      203.0.113.77
    2026-11-12 02:46:25  Cloud Discovery Burst      j.smith      203.0.113.77
    2026-11-12 02:49:58  New IAM User               j.smith      203.0.113.77
    2026-11-12 02:50:20  Access Key Created         j.smith      203.0.113.77
    2026-11-12 02:50:39  Admin Policy Attached      j.smith      203.0.113.77
    2026-11-12 02:51:27  Logging Disabled           j.smith      203.0.113.77
    2026-11-12 02:57:27  S3 Bucket Exposed          backup-svc   198.51.100.200
    2026-11-12 02:57:42  S3 Bucket Exposed          backup-svc   198.51.100.200
    2026-11-12 02:57:44  S3 Mass Download           backup-svc   198.51.100.200
```

Full output: [`sample_output.txt`](sample_output.txt) · Markdown report: [`sample_report.md`](sample_report.md) · JSON: [`sample_findings.json`](sample_findings.json)

**Zero false positives** on the benign users and the CI role, verified by the test suite.

## Incident response takeaways

1. **Sixteen minutes from first password guess to data theft.** Cloud intrusions move fast; detections need to alert in near-real time, not in a daily report.
2. **Contain:** disable `j.smith`'s console password and sessions, **deactivate access key `AKIA…BACKDOOR1`**, delete `backup-svc`, re-enable the public access block on `acme-customer-data`, and **restart CloudTrail** (`StartLogging`).
3. **Assume blind spots:** logging was off from 02:51. Check S3 server access logs, VPC Flow Logs and GuardDuty for what happened while CloudTrail was dark.
4. **Scope the breach:** 120 customer export files were read by an outside IP. That is a reportable data breach in most jurisdictions.
5. **Harden:** enforce MFA on every IAM user (an SCP or IAM condition `aws:MultiFactorAuthPresent`), use SSO instead of IAM users, alert on `StopLogging` with EventBridge, enable S3 Block Public Access at the account level, and protect the trail with an SCP so even admins can't stop it.

## Skills demonstrated

AWS CloudTrail log analysis · IAM attack paths · Python (JSON, dataclasses, sliding windows) · identity and access-key correlation · MITRE ATT&CK for Cloud · incident timeline reconstruction · unit testing

## Roadmap

- [ ] AssumeRole chain tracking (role hopping across accounts)
- [ ] EventBridge / Lambda deployment for real-time alerting
- [ ] Sigma rule export for each detection

---
**Author:** Rakesh Rajbali · Cybersecurity, St. John's University
