import json
import subprocess
import sys
from pathlib import Path

import pytest

import cloudtrail_hunter as ch

HERE = Path(__file__).parent
TRAIL = HERE / "cloudtrail_sample.json"
BENIGN = {"alice", "bob", "role/github-actions-deploy"}


@pytest.fixture(scope="session", autouse=True)
def sample_trail():
    if not TRAIL.exists():
        subprocess.run([sys.executable, "generate_sample_trail.py"], cwd=HERE, check=True)


@pytest.fixture(scope="session")
def findings():
    return ch.analyze(str(TRAIL))[1]


def by_cat(findings, cat):
    return [f for f in findings if f.category == cat]


def test_detects_console_brute_force(findings):
    bf = by_cat(findings, "Console Brute Force")
    assert len(bf) == 1 and bf[0].source_ip == "203.0.113.77"


def test_compromise_without_mfa_is_critical(findings):
    (c,) = by_cat(findings, "Account Compromise")
    assert c.actor == "j.smith" and c.severity == "CRITICAL"
    assert "without MFA" in c.summary


def test_discovery_burst_reports_whole_burst(findings):
    (r,) = by_cat(findings, "Cloud Discovery Burst")
    assert r.actor == "j.smith"
    assert "20 different" in r.summary
    assert any("3 of 20 calls were AccessDenied" in d for d in r.details)


def test_persistence_and_privilege_escalation_chain(findings):
    assert by_cat(findings, "New IAM User")[0].severity == "HIGH"          # escalated: compromised actor
    assert by_cat(findings, "Access Key Created")[0].severity == "CRITICAL"
    assert "backup-svc" in by_cat(findings, "Admin Policy Attached")[0].summary


def test_logging_disabled(findings):
    (l,) = by_cat(findings, "Logging Disabled")
    assert l.severity == "CRITICAL" and "StopLogging" not in l.summary  # human-readable text
    assert "CloudTrail logging stopped" in l.summary


def test_backdoor_key_correlated_to_exfiltration(findings):
    exposed = by_cat(findings, "S3 Bucket Exposed")
    (dl,) = by_cat(findings, "S3 Mass Download")
    assert len(exposed) == 2
    assert dl.source_ip == "198.51.100.200" and "120 objects" in dl.summary
    for f in exposed + [dl]:
        assert f.severity == "CRITICAL"
        assert any("AKIAEXAMPLEBACKDOOR1" in d for d in f.details)


def test_zero_false_positives_on_benign_activity(findings):
    assert not [f for f in findings if f.actor in BENIGN]
    assert len(findings) == 10


def _write(tmp_path, records):
    p = tmp_path / "trail.json"
    p.write_text(json.dumps({"Records": records}))
    return str(p)


def _login(user, ok, mfa, ip="192.0.2.99", t="2026-11-12T10:00:00Z", kind="IAMUser"):
    return {"eventTime": t, "eventSource": "signin.amazonaws.com", "eventName": "ConsoleLogin",
            "sourceIPAddress": ip, "userIdentity": {"type": kind, "userName": user},
            "responseElements": {"ConsoleLogin": "Success" if ok else "Failure"},
            "additionalEventData": {"MFAUsed": "Yes" if mfa else "No"}}


def test_root_login_and_no_mfa_login(tmp_path):
    path = _write(tmp_path, [_login("root", True, True, kind="Root"), _login("carol", True, False)])
    cats = {f.category: f for f in ch.analyze(path)[1]}
    assert cats["Root Account Login"].severity == "HIGH"
    assert cats["Console Login Without MFA"].actor == "carol"


def test_public_bucket_policy_detection():
    assert ch.policy_is_public({"Statement": [{"Effect": "Allow", "Principal": "*"}]})
    assert ch.policy_is_public({"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}}]})
    assert not ch.policy_is_public({"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::1:root"}}]})
    assert ch.policy_is_public('{"Statement":[{"Effect":"Allow","Principal":"*"}]}')


def test_directory_and_gzip_input(tmp_path):
    import gzip
    d = tmp_path / "AWSLogs"
    d.mkdir()
    with gzip.open(d / "part1.json.gz", "wt") as fh:
        json.dump({"Records": [_login("x", False, False, ip="203.0.113.9", t=f"2026-11-12T10:00:0{i}Z") for i in range(6)]}, fh)
    (findings,) = [ch.analyze(str(d))[1]]
    assert by_cat(findings, "Console Brute Force")[0].source_ip == "203.0.113.9"


def test_cli_exit_code_and_outputs(tmp_path):
    report, out = tmp_path / "r.md", tmp_path / "f.json"
    code = ch.main([str(TRAIL), "--report", str(report), "--json", str(out)])
    assert code == 1  # CRITICAL findings present
    assert "Attack timeline" in report.read_text()
    assert len(json.loads(out.read_text())) == 10
