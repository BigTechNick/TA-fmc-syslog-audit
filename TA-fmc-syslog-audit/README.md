# FMC Syslog and Audit Log Add-on for Cisco Secure Firewall

Version 1.0.0. App ID (folder name): `TA-fmc-syslog-audit`.

Search-time fields and CIM mappings for Cisco Secure Firewall Management Center
(FMC) syslog: the FMC audit log and FMC correlation events.

| Sourcetype | What it is | CIM data model |
|---|---|---|
| `cisco:fmc:audit` | FMC audit log sent to syslog | Authentication (logins), Change (configuration changes, deployments, rule updates) |
| `cisco:fmc:syslog` | FMC system syslog | Alerts (correlation events) |

> Independent project, not affiliated with or endorsed by Cisco. Cisco and
> Cisco Secure Firewall are trademarks of Cisco Systems, Inc. See NOTICE.

## Where to install

| Splunk instance | Install? |
|---|---|
| Search heads (including Splunk Cloud and Enterprise Security) | Yes |
| Heavy forwarders, indexers | No (search-time settings only) |

## Getting the data in

The add-on does not collect data. Send the FMC's syslog to Splunk (a syslog server
with a forwarder, Splunk Connect for Syslog, or a network input on a heavy
forwarder) and give it these sourcetypes:

1. **Audit log:** in the FMC, *System > Configuration > Audit Log*, turn on
   *Send Audit Log to Syslog* with the syslog host, a facility and a severity.
   Sourcetype `cisco:fmc:audit`.
2. **Correlation events:** *Policies > Actions > Alerts*, create a syslog alert and
   use it in your correlation policy's responses. Sourcetype `cisco:fmc:syslog`.

The easiest split is a separate port (or syslog destination) for the audit log. If
both arrive on one input as `cisco:fmc:syslog`, you can move the audit log to its
own sourcetype by the facility you chose, on the heavy forwarder or indexers that
parse the data. Example for facility 13 (log audit, syslog PRI 104-111):

```
# props.conf
[cisco:fmc:syslog]
TRANSFORMS-fmc_audit = fmc_audit_by_facility

# transforms.conf
[fmc_audit_by_facility]
REGEX = ^<1(?:0[4-9]|1[01])>
DEST_KEY = MetaData:Sourcetype
FORMAT = sourcetype::cisco:fmc:audit
```

For Enterprise Security, add the indexes to the CIM index macros:
`cim_Authentication_indexes` and `cim_Change_indexes` (audit log index), and
`cim_Alerts_indexes` (FMC syslog index).

## cisco:fmc:audit

Raw format: `<110>Oct 22 18:42:45 <fmc>: <process>: <user>@<source>, <subsystem>, <message>`

| Field | Value |
|---|---|
| `fmc_name`, `fmc_process`, `fmc_subsystem`, `fmc_message` | The FMC name and the three parts of the audit line |
| `user` | Account; can contain `@` (`jdoe@example.com`) |
| `src` | Client address, only when the FMC logged one (not `Default User IP` or `localhost`) |
| `user_type` | `system` for `System`, `Default User`, `csm_processes`; otherwise `user` |
| `fmc_category` | `authentication`, `change`, `session`, `api_read` or `activity` |
| `action` | Logins: `success` / `failure`. Changes: `created`, `modified`, `deleted`, `updated`. API GET: `read` |
| `status` | `success` / `failure` (deploy result, HTTP status code, or failure wording) |
| `change_type` | `configuration`, `deployment` or `rule_update` (changes only) |
| `object`, `object_category` | The policy, device, intrusion rule, rule update or API path changed |
| `object_path` | The FMC menu path (`fmc_subsystem`) |
| `object_attrs` | The intrusion rule state set (rule changes) |
| `command` | API method and path (API calls) |
| `dest` | The FTD for a policy deployment, otherwise the FMC |
| `dvc`, `vendor_product`, `app` | The FMC, `Cisco Secure Firewall Management Center`, `fmc` |

What counts as a change (event type `cisco_fmc_audit_change`, tags `change`, `network`):
`Save Policy ...`, `Policy Committed`, intrusion rule state changes, `Policy Deployment to ...`,
rule update and SRU installs, messages starting with Add / Create / Delete / Remove / Edit /
Modify / Update / Apply, and API POST / PUT / PATCH / DELETE.

Not tagged: page views, API GET calls, reports, backups, task completions, purges,
logouts and session expiry.

## cisco:fmc:syslog (correlation events)

`Correlation Event: <rule>/<policy> at <time> UTC Connection Type: ... <src>:<port> (<country>) -> <dest>:<port> (<country>) (<protocol>)`

Fields: `fmc_correlation_rule` (= `signature`), `fmc_correlation_policy`, `fmc_connection_type`,
`src`, `src_port`, `src_country`, `dest`, `dest_port`, `dest_country`, `transport`, `severity`
(from the syslog priority), `type=alarm`, `description`. Event type `cisco_fmc_correlation`,
tag `alert`.

Correlation events with IPv6 addresses are not extracted.

## Event types and tags

| Event type | Tags | CIM |
|---|---|---|
| `cisco_fmc_audit` | | (all audit records) |
| `cisco_fmc_audit_authentication` | authentication | Authentication |
| `cisco_fmc_audit_change` | change, network | Change (Network_Changes) |
| `cisco_fmc_correlation` | alert | Alerts |

## Check after installing

```
index=<audit index> sourcetype="cisco:fmc:audit" earliest=-24h
| stats count by fmc_category action status
```

```
| datamodel Change All_Changes search
| search sourcetype="cisco:fmc:audit"
| stats count by All_Changes.action All_Changes.object_category
```

## Release notes

### 1.0.0

* First release.

## Support

Community-supported, best effort, through Splunkbase. Licensed under Apache 2.0.
