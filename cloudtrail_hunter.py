#!/usr/bin/env python3
"""
CloudTrail Hunter - hunt an AWS CloudTrail log for the stages of a cloud
account takeover, map each to MITRE ATT&CK, correlate them to the attacker
and rebuild the attack timeline.

Usage:
    python cloudtrail_hunter.py cloudtrail_sample.json [--report r.md] [--json f.json]

Input: a CloudTrail JSON file ({"Records": [...]}), a JSON list of records,
or a directory of such files (e.g. an unzipped S3 trail export, .json or .json.gz).
"""
import argparse
import gzip
import json
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
ESCALATE = {"LOW": "MEDIUM", "MEDIUM": "HIGH", "HIGH": "CRITICAL", "CRITICAL": "CRITICAL"}

# Tunables
BRUTE_FORCE_FAILURES = 5          # failed console logins from one IP ...
BRUTE_FORCE_WINDOW = timedelta(minutes=10)  # ... inside this window
RECON_DISTINCT_APIS = 12          # distinct read-only APIs by one identity ...
RECON_WINDOW = timedelta(minutes=5)          # ... inside this window
S3_MASS_DOWNLOAD = 50             # GetObject calls by one identity ...
S3_WINDOW = timedelta(minutes=10)            # ... inside this window

LOGGING_TAMPER = {
    "StopLogging": "CloudTrail logging stopped",
    "DeleteTrail": "CloudTrail trail deleted",
    "UpdateTrail": "CloudTrail trail modified",
    "PutEventSelectors": "CloudTrail event selectors changed",
    "DeleteFlowLogs": "VPC Flow Logs deleted",
    "DeleteDetector": "GuardDuty detector deleted",
    "DisableSecurityHub": "Security Hub disabled",
    "DeleteConfigurationRecorder": "AWS Config recorder deleted",
    "StopConfigurationRecorder": "AWS Config recorder stopped",
}
POLICY_ATTACH = {"AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy",
                 "PutUserPolicy", "PutRolePolicy", "PutGroupPolicy"}
READ_PREFIXES = ("List", "Describe", "Get")


@dataclass
class Finding:
    time: str
    severity: str
    category: str
    mitre: str
    actor: str
    source_ip: str
    summary: str
    details: list = field(default_factory=list)


# ---------------------------------------------------------------- parsing
def load_records(path):
    p = Path(path)
    files = sorted(f for f in p.rglob("*") if f.suffix in {".json", ".gz"}) if p.is_dir() else [p]
    records = []
    for f in files:
        opener = gzip.open if f.suffix == ".gz" else open
        with opener(f, "rt", encoding="utf-8") as fh:
            data = json.load(fh)
        records.extend(data["Records"] if isinstance(data, dict) else data)
    records.sort(key=lambda r: r.get("eventTime", ""))
    return records


def ts(rec):
    return datetime.strptime(rec["eventTime"], "%Y-%m-%dT%H:%M:%SZ")


def actor(rec):
    """Human-readable identity: IAM user name, role name, or Root."""
    ident = rec.get("userIdentity") or {}
    kind = ident.get("type")
    if kind == "Root":
        return "root"
    if kind == "AssumedRole":
        return "role/" + ident.get("sessionContext", {}).get("sessionIssuer", {}).get("userName", "?")
    return ident.get("userName") or ident.get("arn", "unknown")


def req(rec):
    return rec.get("requestParameters") or {}


def policy_is_public(policy):
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except ValueError:
            return '"Principal":"*"' in policy.replace(" ", "")
    for stmt in (policy or {}).get("Statement", []):
        principal = stmt.get("Principal")
        if stmt.get("Effect") == "Allow" and (principal == "*" or (isinstance(principal, dict) and "*" in principal.values())):
            return True
    return False


def sliding_peak(times, window):
    """Largest number of timestamps inside any `window`-long span, and where it starts."""
    best, best_start, lo = 0, None, 0
    for hi, t in enumerate(times):
        while t - times[lo] > window:
            lo += 1
        if hi - lo + 1 > best:
            best, best_start = hi - lo + 1, times[lo]
    return best, best_start


# ---------------------------------------------------------------- detection
def analyze(path):
    records = load_records(path)
    findings = []
    fmt = lambda t: t.strftime("%Y-%m-%d %H:%M:%S")

    # --- 1. Console brute force (T1110) ---
    failures = defaultdict(list)          # ip -> [(time, user)]
    for r in records:
        if r["eventName"] == "ConsoleLogin" and (r.get("responseElements") or {}).get("ConsoleLogin") == "Failure":
            failures[r["sourceIPAddress"]].append((ts(r), actor(r)))
    attacker_ips = set()
    for ip, events in failures.items():
        peak, start = sliding_peak([t for t, _ in events], BRUTE_FORCE_WINDOW)
        if peak >= BRUTE_FORCE_FAILURES:
            attacker_ips.add(ip)
            users = sorted({u for _, u in events})
            findings.append(Finding(fmt(start), "HIGH", "Console Brute Force", "T1110.001", ", ".join(users), ip,
                                    f"{ip} made {len(events)} failed console logins (peak {peak} in 10 min)",
                                    [f"Targeted: {', '.join(users)}"]))

    # --- 2. Console logins: compromise / no MFA / root (T1078.004) ---
    compromised = {}                      # user -> (ip, time)
    for r in records:
        if r["eventName"] != "ConsoleLogin" or (r.get("responseElements") or {}).get("ConsoleLogin") != "Success":
            continue
        who, ip, t = actor(r), r["sourceIPAddress"], ts(r)
        mfa = (r.get("additionalEventData") or {}).get("MFAUsed") == "Yes"
        if ip in attacker_ips:
            compromised[who] = (ip, t)
            n = len(failures[ip])
            findings.append(Finding(fmt(t), "CRITICAL", "Account Compromise", "T1078.004", who, ip,
                                    f"Successful console login as '{who}' from brute-forcing IP {ip}"
                                    + ("" if mfa else " without MFA"),
                                    [f"{n} failed attempts from this IP before the success", f"MFA used: {'Yes' if mfa else 'No'}"]))
        elif who == "root":
            findings.append(Finding(fmt(t), "HIGH", "Root Account Login", "T1078.004", who, ip,
                                    f"Root user signed in to the console from {ip}",
                                    ["Root should be locked away; daily work belongs to IAM roles"]))
        elif not mfa:
            findings.append(Finding(fmt(t), "MEDIUM", "Console Login Without MFA", "T1078.004", who, ip,
                                    f"'{who}' signed in to the console without MFA from {ip}"))

    # Identities controlled by the attacker: compromised users + users/keys they create
    tainted_users = set(compromised)
    tainted_keys = {}                     # access key id -> description
    tainted_ips = set(attacker_ips)

    def is_tainted(r):
        key = (r.get("userIdentity") or {}).get("accessKeyId")
        return actor(r) in tainted_users or key in tainted_keys or r["sourceIPAddress"] in tainted_ips

    def correlate(f, r):
        """Escalate and annotate findings performed by attacker-controlled identities."""
        key = (r.get("userIdentity") or {}).get("accessKeyId")
        if key in tainted_keys:
            f.details.append(f"Used {tainted_keys[key]}")
        elif actor(r) in compromised:
            ip, t = compromised[actor(r)]
            f.details.append(f"'{actor(r)}' was compromised from {ip} at {t:%H:%M:%S}")
        elif actor(r) in tainted_users:
            f.details.append(f"'{actor(r)}' is a backdoor identity created by the attacker")
        f.severity = ESCALATE[f.severity]
        return f

    # --- 3. Recon burst (T1580 / T1087.004) ---
    reads = defaultdict(list)             # actor -> [(time, api, denied, ip, rec)]
    for r in records:
        # Data reads (S3 GetObject) are handled by the mass-download check, not recon
        if r["eventName"].startswith(READ_PREFIXES) and r["eventName"] != "GetObject":
            reads[actor(r)].append((ts(r), r["eventName"], bool(r.get("errorCode")), r))
    for who, events in reads.items():
        best, lo = [], 0
        for hi in range(len(events)):        # widest 5-minute window by distinct APIs
            while events[hi][0] - events[lo][0] > RECON_WINDOW:
                lo += 1
            if len({e[1] for e in events[lo:hi + 1]}) > len({e[1] for e in best}):
                best = events[lo:hi + 1]
        apis = {e[1] for e in best}
        if len(apis) >= RECON_DISTINCT_APIS:
            denied = sum(e[2] for e in best)
            first = best[0][3]
            f = Finding(fmt(best[0][0]), "MEDIUM", "Cloud Discovery Burst", "T1580", who, first["sourceIPAddress"],
                        f"'{who}' called {len(apis)} different List/Describe/Get APIs within 5 minutes",
                        [f"{denied} of {len(best)} calls were AccessDenied (permission probing)",
                         "APIs: " + ", ".join(sorted(apis)[:8]) + (" ..." if len(apis) > 8 else "")])
            findings.append(correlate(f, first) if is_tainted(first) else f)

    # --- 4-7. Per-event detections, in time order so taint propagates ---
    s3_gets = defaultdict(list)
    for r in records:
        name, who, ip, t, p = r["eventName"], actor(r), r["sourceIPAddress"], ts(r), req(r)
        if r.get("errorCode"):
            continue
        f = None
        if name == "CreateUser":
            f = Finding(fmt(t), "MEDIUM", "New IAM User", "T1136.003", who, ip,
                        f"'{who}' created IAM user '{p.get('userName')}'")
            if is_tainted(r):
                tainted_users.add(p.get("userName"))
        elif name == "CreateLoginProfile":
            f = Finding(fmt(t), "MEDIUM", "Console Password Added", "T1098.001", who, ip,
                        f"'{who}' gave '{p.get('userName')}' a console password")
        elif name == "CreateAccessKey":
            target = p.get("userName") or who
            key = ((r.get("responseElements") or {}).get("accessKey") or {}).get("accessKeyId", "?")
            sev = "HIGH" if target != who else "LOW"
            f = Finding(fmt(t), sev, "Access Key Created", "T1098.001", who, ip,
                        f"'{who}' created access key {key} for '{target}'",
                        ["Key created for a different user (persistence pattern)"] if target != who else [])
            if is_tainted(r):
                tainted_keys[key] = f"access key {key} created by attacker-controlled '{who}' for '{target}'"
                tainted_users.add(target)
        elif name in POLICY_ATTACH:
            arn = p.get("policyArn", "") + json.dumps(p.get("policyDocument", ""))
            target = p.get("userName") or p.get("roleName") or p.get("groupName")
            admin = "AdministratorAccess" in arn or '"Action": "*"' in arn or '\\"Action\\":\\"*\\"' in arn
            if admin:
                f = Finding(fmt(t), "HIGH", "Admin Policy Attached", "T1098.003", who, ip,
                            f"'{who}' granted full admin rights to '{target}'",
                            [f"Policy: {p.get('policyArn') or 'inline policy with Action *'}"])
        elif name in LOGGING_TAMPER:
            f = Finding(fmt(t), "CRITICAL", "Logging Disabled", "T1562.008", who, ip,
                        f"{LOGGING_TAMPER[name]} by '{who}'",
                        [f"Target: {p.get('name') or p.get('detectorId') or p}", "Events after this point may be missing"])
        elif name in {"PutBucketPolicy", "PutBucketAcl", "DeletePublicAccessBlock", "DeleteBucketPublicAccessBlock"}:
            bucket = p.get("bucketName")
            public = (name in {"DeletePublicAccessBlock", "DeleteBucketPublicAccessBlock"}
                      or (name == "PutBucketPolicy" and policy_is_public(p.get("bucketPolicy")))
                      or (name == "PutBucketAcl" and "AllUsers" in json.dumps(p)))
            if public:
                what = "removed the public access block on" if "PublicAccessBlock" in name else "made public:"
                f = Finding(fmt(t), "HIGH", "S3 Bucket Exposed", "T1530", who, ip,
                            f"'{who}' {what} bucket '{bucket}'")
        elif name == "GetObject" and r["eventSource"] == "s3.amazonaws.com":
            s3_gets[(who, p.get("bucketName"))].append(r)
        if f:
            tainted = is_tainted(r)
            findings.append(correlate(f, r) if tainted else f)
            if tainted:
                tainted_ips.add(ip)

    # --- 8. Mass S3 download (T1530) ---
    for (who, bucket), recs in s3_gets.items():
        peak, start = sliding_peak([ts(r) for r in recs], S3_WINDOW)
        if peak >= S3_MASS_DOWNLOAD:
            first = next(r for r in recs if ts(r) >= start)
            f = Finding(fmt(start), "HIGH", "S3 Mass Download", "T1530", who, first["sourceIPAddress"],
                        f"'{who}' downloaded {len(recs)} objects from '{bucket}' (peak {peak} in 10 min)",
                        [f"Sample keys: {', '.join(req(r)['key'] for r in recs[:3])}"])
            findings.append(correlate(f, first) if is_tainted(first) else f)

    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.time))
    return records, findings


# ---------------------------------------------------------------- output
def print_findings(findings):
    for f in findings:
        print(f"[{f.severity}] {f.category}: {f.summary}  ({f.mitre})")
        for d in f.details:
            print(f"      - {d}")
    print(f"[+] {len(findings)} findings\n")
    print("[*] Attack timeline")
    for f in sorted(findings, key=lambda f: f.time):
        print(f"    {f.time}  {f.category:<26} {f.actor:<12} {f.source_ip}")


def write_report(path, source, records, findings):
    counts = {s: sum(f.severity == s for f in findings) for s in SEVERITY_ORDER}
    lines = [f"# CloudTrail Hunt Report - `{Path(source).name}`", "",
             f"- **CloudTrail records parsed:** {len(records)}",
             f"- **Findings:** {len(findings)} (" + ", ".join(f"{s}: {n}" for s, n in counts.items() if n) + ")", "",
             "## Findings", "", "| Severity | Category | MITRE | Actor | Source IP | Summary |", "|---|---|---|---|---|---|"]
    lines += [f"| {f.severity} | {f.category} | {f.mitre} | {f.actor} | {f.source_ip} | {f.summary} |" for f in findings]
    lines += ["", "## Attack timeline", ""]
    lines += [f"- `{f.time}` **{f.category}** - {f.summary}" for f in sorted(findings, key=lambda f: f.time)]
    Path(path).write_text("\n".join(lines) + "\n")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Hunt AWS CloudTrail logs for account-takeover activity.")
    ap.add_argument("path", help="CloudTrail JSON file, or a directory of .json/.json.gz files")
    ap.add_argument("--report", help="write a Markdown report")
    ap.add_argument("--json", help="write findings as JSON")
    args = ap.parse_args(argv)

    records, findings = analyze(args.path)
    print(f"[*] Parsed {len(records)} CloudTrail records from {args.path}\n")
    print_findings(findings)
    if args.report:
        write_report(args.report, args.path, records, findings)
        print(f"\n[+] Report written to {args.report}")
    if args.json:
        Path(args.json).write_text(json.dumps([asdict(f) for f in findings], indent=2))
        print(f"[+] JSON written to {args.json}")
    return 1 if any(f.severity == "CRITICAL" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
