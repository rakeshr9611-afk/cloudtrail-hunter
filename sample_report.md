# CloudTrail Hunt Report - `cloudtrail_sample.json`

- **CloudTrail records parsed:** 221
- **Findings:** 10 (CRITICAL: 7, HIGH: 3)

## Findings

| Severity | Category | MITRE | Actor | Source IP | Summary |
|---|---|---|---|---|---|
| CRITICAL | Account Compromise | T1078.004 | j.smith | 203.0.113.77 | Successful console login as 'j.smith' from brute-forcing IP 203.0.113.77 without MFA |
| CRITICAL | Access Key Created | T1098.001 | j.smith | 203.0.113.77 | 'j.smith' created access key AKIAEXAMPLEBACKDOOR1 for 'backup-svc' |
| CRITICAL | Admin Policy Attached | T1098.003 | j.smith | 203.0.113.77 | 'j.smith' granted full admin rights to 'backup-svc' |
| CRITICAL | Logging Disabled | T1562.008 | j.smith | 203.0.113.77 | CloudTrail logging stopped by 'j.smith' |
| CRITICAL | S3 Bucket Exposed | T1530 | backup-svc | 198.51.100.200 | 'backup-svc' removed the public access block on bucket 'acme-customer-data' |
| CRITICAL | S3 Bucket Exposed | T1530 | backup-svc | 198.51.100.200 | 'backup-svc' made public: bucket 'acme-customer-data' |
| CRITICAL | S3 Mass Download | T1530 | backup-svc | 198.51.100.200 | 'backup-svc' downloaded 120 objects from 'acme-customer-data' (peak 120 in 10 min) |
| HIGH | Console Brute Force | T1110.001 | j.smith | 203.0.113.77 | 203.0.113.77 made 14 failed console logins (peak 14 in 10 min) |
| HIGH | Cloud Discovery Burst | T1580 | j.smith | 203.0.113.77 | 'j.smith' called 20 different List/Describe/Get APIs within 5 minutes |
| HIGH | New IAM User | T1136.003 | j.smith | 203.0.113.77 | 'j.smith' created IAM user 'backup-svc' |

## Attack timeline

- `2026-11-12 02:41:05` **Console Brute Force** - 203.0.113.77 made 14 failed console logins (peak 14 in 10 min)
- `2026-11-12 02:45:45` **Account Compromise** - Successful console login as 'j.smith' from brute-forcing IP 203.0.113.77 without MFA
- `2026-11-12 02:46:25` **Cloud Discovery Burst** - 'j.smith' called 20 different List/Describe/Get APIs within 5 minutes
- `2026-11-12 02:49:58` **New IAM User** - 'j.smith' created IAM user 'backup-svc'
- `2026-11-12 02:50:20` **Access Key Created** - 'j.smith' created access key AKIAEXAMPLEBACKDOOR1 for 'backup-svc'
- `2026-11-12 02:50:39` **Admin Policy Attached** - 'j.smith' granted full admin rights to 'backup-svc'
- `2026-11-12 02:51:27` **Logging Disabled** - CloudTrail logging stopped by 'j.smith'
- `2026-11-12 02:57:27` **S3 Bucket Exposed** - 'backup-svc' removed the public access block on bucket 'acme-customer-data'
- `2026-11-12 02:57:42` **S3 Bucket Exposed** - 'backup-svc' made public: bucket 'acme-customer-data'
- `2026-11-12 02:57:44` **S3 Mass Download** - 'backup-svc' downloaded 120 objects from 'acme-customer-data' (peak 120 in 10 min)
