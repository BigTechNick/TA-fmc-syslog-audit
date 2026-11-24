#!/usr/bin/env python3
"""
regex_test.py - the EXTRACTs in default/props.conf against sample FMC audit, correlation and sshd
lines (made-up names, documentation IP ranges), plus a Python stand-in for the fmc_category / action
EVALs that decide the CIM event types. Splunk's (?<name>...) groups become Python's (?P<name>...).
"""
import os
import re
import sys

APP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "TA-fmc-syslog-audit")
H = "<110>Oct 22 18:42:45 fmc-example-01: "


def extracts():
    out, stanza = {}, None
    for line in open(os.path.join(APP, "default", "props.conf"), encoding="utf-8"):
        s = line.strip()
        if s.startswith("["):
            stanza = s[1:-1]
        elif s.startswith("EXTRACT-"):
            key, value = (x.strip() for x in s.split("=", 1))
            out.setdefault(stanza, []).append((key, re.compile(re.sub(r"\(\?<(?=[A-Za-z_])", "(?P<", value))))
    return out


def fields(rules, sourcetype, line):
    got = {}
    for key, rx in rules[sourcetype]:
        m = rx.search(line)
        if m:
            got.update({k: v for k, v in m.groupdict().items() if v is not None})
    return got


def category(f):                      # the fmc_category EVAL
    sub, msg, meth = f.get("fmc_subsystem", ""), f.get("fmc_message", ""), f.get("http_method")
    if sub == "Login":
        return "authentication"
    if sub in ("Logout", "Session Expiration"):
        return "session"
    if f.get("fmc_deploy_device") or f.get("fmc_rule_name") or f.get("fmc_rule_update") or sub == "SRU Install" \
            or msg.startswith("Policy Committed") or re.match(r"^(Save|Add|Create|Delete|Remove|Edit|Modify|Update|Apply)( |$)", msg) \
            or (sub == "API" and meth in ("POST", "PUT", "PATCH", "DELETE")):
        return "change"
    return "api_read" if sub == "API" else "activity"


def ssh_action(f):                    # the cisco:fmc:syslog EVAL-action
    return {"Failed": "failure", "Accepted": "success"}.get(f.get("fmc_ssh_result"))


AUDIT = [
    (H + "IPRep.pl: csm_processes@Default User IP, Login, Login Success",
     dict(fmc_name="fmc-example-01", fmc_process="IPRep.pl", user="csm_processes", fmc_src="Default User IP",
          fmc_subsystem="Login", fmc_message="Login Success"), "authentication"),
    (H + "HTTPS: jdoe@example.com@192.0.2.15, Login, Login Failed: invalid credentials",
     dict(user="jdoe@example.com", fmc_src="192.0.2.15", fmc_message="Login Failed: invalid credentials"), "authentication"),
    (H + "HTTPS: jdoe@example.com@192.0.2.15, Policies > Access Control > Access Control Editor, Save Policy Branch-ACP#012",
     dict(fmc_subsystem="Policies > Access Control > Access Control Editor", fmc_saved_policy="Branch-ACP"), "change"),
    (H + "HTTPS: jdoe@example.com@192.0.2.15, Deploy, Policy Deployment to ftd-example-02 - SUCCESS",
     dict(fmc_deploy_device="ftd-example-02", fmc_deploy_result="SUCCESS"), "change"),
    (H + 'HTTPS: jdoe@example.com@192.0.2.15, Policies > Intrusion > Intrusion Policy, Added "Drop and Generate Events" to '
         'MALWARE-CNC Example rule (1:58001)',
     dict(fmc_rule_change="Added", fmc_rule_state="Drop and Generate Events", fmc_rule_name="MALWARE-CNC Example rule",
          fmc_rule_gid_sid="1:58001"), "change"),
    (H + 'sfmgr: System@localhost, Rule Updates, Completed install of rule update "Snort Rule Update 2026-10-22-001-vrt"',
     dict(fmc_rule_update="Snort Rule Update 2026-10-22-001-vrt"), "change"),
    (H + "API: apiuser@198.51.100.20, API, POST https://fmc.example.com/api/fmc_config/v1/domain/x/object/hosts Created (201)",
     dict(http_method="POST", url="https://fmc.example.com/api/fmc_config/v1/domain/x/object/hosts", fmc_api_result="Created",
          status_code="201"), "change"),
    (H + "API: apiuser@198.51.100.20, API, GET https://fmc.example.com/api/fmc_config/v1/domain/x/devices OK (200)",
     dict(http_method="GET", status_code="200"), "api_read"),
    (H + "HTTPS: jdoe@example.com@192.0.2.15, Overview > Dashboards, Page View", dict(fmc_message="Page View"), "activity"),
    (H + "HTTPS: jdoe@example.com@192.0.2.15, Logout, Logout Success", dict(fmc_subsystem="Logout"), "session"),
]
CORRELATION = [
    ("<41>Oct 22 19:55:45 fmc-example-01 alerter: Correlation Event: Example_Rule/Example-Policy at Thu Oct 22 19:55:45 2026 "
     "UTCConnection Type: FireSIGHT 192.0.2.30:59929 (unknown) -> 203.0.113.40:443 (united states) (tcp)",
     dict(syslog_pri="41", fmc_correlation_rule="Example_Rule", fmc_correlation_policy="Example-Policy",
          fmc_connection_type="FireSIGHT", src="192.0.2.30", src_port="59929", src_country="unknown", dest="203.0.113.40",
          dest_port="443", dest_country="united states", transport="tcp")),
]

# sshd on the FMC, with a syslog PRI header (RFC 5424 style) and without one
P1 = "<38>1 2026-11-22T08:28:20+00:00 fmc-example-01 "
P0 = "2026-11-22T22:09:16+00:00 fmc-example-02 "
SSH = [
    (P1 + "sshd[17029]: Failed password for invalid user scanuser from 198.51.100.7 port 40078 ssh2",
     dict(process_id="17029", fmc_ssh_result="Failed", authentication_method="password", fmc_ssh_invalid_user="invalid user",
          user="scanuser", src="198.51.100.7", src_port="40078"), "failure"),
    (P0 + "sshd[33148]: Failed keyboard-interactive/pam for invalid user scanuser from 198.51.100.8 port 37142 ssh2",
     dict(authentication_method="keyboard-interactive/pam", user="scanuser", src="198.51.100.8", src_port="37142"), "failure"),
    (P0 + "sshd[33149]: Failed password for admin from 192.0.2.25 port 51000 ssh2",
     dict(authentication_method="password", user="admin", src="192.0.2.25", fmc_ssh_invalid_user=None), "failure"),
    (P0 + "sshd[33150]: Accepted publickey for admin from 192.0.2.25 port 50000 ssh2",
     dict(fmc_ssh_result="Accepted", authentication_method="publickey", user="admin", src="192.0.2.25"), "success"),
    (P1 + "sshd[17030]: Accepted keyboard-interactive/pam for admin from 2001:db8::25 port 50002 ssh2",
     dict(authentication_method="keyboard-interactive/pam", user="admin", src="2001:db8::25"), "success"),
]
# The other lines sshd writes for the same try must not become Authentication events
SSH_NOT_MAPPED = [
    P1 + "sshd[17029]: Invalid user scanuser from 198.51.100.7 port 40078",
    P1 + "sshd[17029]: Postponed keyboard-interactive for invalid user scanuser from 198.51.100.7 port 40078 ssh2 [preauth]",
    P0 + "sshd[33148]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.8 ",
    P0 + "sshd[33148]: error: PAM: Authentication failure for illegal user scanuser from 198.51.100.8",
    P1 + "sshd[17029]: Connection reset by invalid user scanuser  198.51.100.7 port 40078 [preauth]",
    P1 + "sshd[650]: Disconnected from invalid user scanuser  198.51.100.9 port 62674 [preauth]",
]


def main():
    rules = extracts()
    fails = []
    for line, want, cat in AUDIT:
        got = fields(rules, "cisco:fmc:audit", line)
        bad = {k: (v, got.get(k)) for k, v in want.items() if got.get(k) != v}
        c = category(got)
        ok = not bad and c == cat
        print(("PASS  " if ok else "FAIL  ") + f"audit {cat:14s} {line[len(H):][:70]}")
        if not ok:
            fails.append(line)
            print("      mismatched:", bad, "category:", c)
    for line, want in CORRELATION:
        got = fields(rules, "cisco:fmc:syslog", line)
        bad = {k: (v, got.get(k)) for k, v in want.items() if got.get(k) != v}
        ok = not bad and "fmc_ssh_result" not in got
        print(("PASS  " if ok else "FAIL  ") + "correlation " + line[40:100])
        if not ok:
            fails.append(line)
            print("      mismatched:", bad)
    for line, want, action in SSH:
        got = fields(rules, "cisco:fmc:syslog", line)
        bad = {k: (v, got.get(k)) for k, v in want.items() if got.get(k) != v}
        a = ssh_action(got)
        ok = not bad and a == action and "fmc_correlation_rule" not in got
        print(("PASS  " if ok else "FAIL  ") + f"sshd {action:8s} {line.split('sshd', 1)[1][:70]}")
        if not ok:
            fails.append(line)
            print("      mismatched:", bad, "action:", a)
    for line in SSH_NOT_MAPPED:
        got = fields(rules, "cisco:fmc:syslog", line)
        ok = ssh_action(got) is None
        print(("PASS  " if ok else "FAIL  ") + f"sshd not mapped {line.split('sshd', 1)[1][:60]}")
        if not ok:
            fails.append(line)
    print("\nALL PASSED" if not fails else f"\n{len(fails)} failed")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
