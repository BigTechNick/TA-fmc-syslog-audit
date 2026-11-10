# FMC Syslog and Audit Log Add-on for Cisco Secure Firewall

Splunk add-on `TA-fmc-syslog-audit`, version 1.0.0.

Search-time fields and CIM mappings for Cisco Secure Firewall Management Center (FMC) syslog: the FMC audit log (sourcetype cisco:fmc:audit: Authentication for logins, Change for configuration changes, deployments and rule updates) and correlation events (sourcetype cisco:fmc:syslog: Alerts). Not affiliated with Cisco.

## Layout

- `TA-fmc-syslog-audit/`: the app exactly as shipped to Splunkbase (unpacked from the release package)
- `tools/package.py`: builds the Splunkbase package and runs offline AppInspect-style checks

## Build

```
python3 tools/package.py TA-fmc-syslog-audit dist --vendor cisco
```

Good: `RESULT: OK`. Then AppInspect:

```
splunk-appinspect inspect dist/TA-fmc-syslog-audit-<version>.tgz --mode precert --included-tags cloud
```

## Releases

Each version is tagged `v<version>`. Its GitHub release has the exact package uploaded to
Splunkbase attached, with its md5.

## License

Apache-2.0. Independent project, not affiliated with or endorsed by Cisco.
