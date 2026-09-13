# detection-as-code

A small detection-as-code repo built from a personal Active Directory attack/defense
lab (Elastic Stack + Sysmon/Winlogbeat on a domain-joined Windows 10 host and a
Server 2022 DC). Every rule here started life as an ad hoc Kibana hunt query
written *after* running the real attack technique against the lab and confirming
the telemetry — then formalized into vendor-agnostic Sigma, compiled to
Elastic/KQL, and tuned against deliberately-generated false positives.

Workflow used throughout the lab: **log first, attack second, hunt third, then
formalize.** This repo is the "formalize" step.

## Repo layout

```
rules/sigma/     Vendor-agnostic Sigma detections (source of truth)
rules/elastic/   Compiled output: .kql files (plain queries) and
                 .kibana-rule.json files (native rule config, for
                 correlation logic Sigma/Lucene can't express as a query string)
tuning/          Deliberate false-positive generation + rule refinement writeups
docs/            Supporting notes
CHANGELOG.md     Version history of the rule set
```

## Rules → MITRE ATT&CK mapping

| Rule | ATT&CK Technique | Data Source | Level | Status |
|---|---|---|---|---|
| [`kerberoasting_rc4_tgs_request.yml`](rules/sigma/kerberoasting_rc4_tgs_request.yml) | [T1558.003 - Kerberoasting](https://attack.mitre.org/techniques/T1558/003/) | Security 4769 (Kerberos Service Ticket Operations) | High | Tuned (v1.1) |
| [`asrep_roasting_no_preauth.yml`](rules/sigma/asrep_roasting_no_preauth.yml) | [T1558.004 - AS-REP Roasting](https://attack.mitre.org/techniques/T1558/004/) | Security 4768 (Kerberos Authentication Service) | High | Test |
| [`password_spraying_distributed_failures.yml`](rules/sigma/password_spraying_distributed_failures.yml) | [T1110.003 - Password Spraying](https://attack.mitre.org/techniques/T1110/003/) | Security 4625 (Failed Logon), correlation | Medium | Test |
| [`account_lockout_burst.yml`](rules/sigma/account_lockout_burst.yml) | [T1110.003 - Password Spraying](https://attack.mitre.org/techniques/T1110/003/) (corroborating signal) | Security 4740 (Account Lockout), correlation | Medium | Test |
| [`dcsync_replication_rights_abuse.yml`](rules/sigma/dcsync_replication_rights_abuse.yml) | [T1003.006 - DCSync](https://attack.mitre.org/techniques/T1003/006/) | Security 4662 (Directory Service Access) | Critical | Tuned (v1.1) |
| [`lateral_movement_atexec_svchost_child.yml`](rules/sigma/lateral_movement_atexec_svchost_child.yml) | [T1053.002](https://attack.mitre.org/techniques/T1053/002/) / [T1569.002](https://attack.mitre.org/techniques/T1569/002/) | Sysmon EventID 1 (Process Creation) | Medium | Test |

Each rule file carries the full detail (`falsepositives`, `references`, exact
field logic) in its own frontmatter — this table is a navigation aid, not a
substitute for reading the rule.

### Known gap - not covered here

LLMNR/NBT-NS poisoning (T1557.001), the first technique run in this lab, has
**no rule in this repo**. Sysmon Event ID 3 (Network Connection) and 22 (DNS
Query) were found not to be firing on the Windows 10 endpoint despite the
SwiftOnSecurity config, so the attack is currently invisible to host-based
logging. Formalizing this detection is blocked on restoring that visibility
(tracked separately as the network-visibility project). Writing a Sigma rule
against telemetry that isn't actually flowing would just be theater.

## Why some rules compile to `.kql` and others to `.kibana-rule.json`

Sigma's Elasticsearch backend converts simple field-match logic straight to a
Lucene/KQL query string. But two of these detections are Sigma **correlation
rules** (count distinct failed-logon targets per source IP over a time
window, count distinct lockouts per domain over a time window) - that logic
can't be expressed as a single query string at all, in Sigma or in Kibana.
Sigma's own `elasticsearch`/`lucene` backend confirms this directly:

```
Error: Feature required for conversion of Sigma rule is not supported by backend:
Backend does not support correlation rules.
```

The real compile target for those two is Kibana's native Threshold /
Elasticsearch-query alerting rule type - the same rule type used to build the
"DCSync Detected" alert earlier in this lab, just generated from the Sigma
source this time instead of clicked together by hand in the UI. Those two
rules ship as `.kibana-rule.json` instead of `.kql`.

## Validating compiled output against real field names

The Sigma `ecs_windows` pipeline is a generic mapping and it does not always
match what a given Winlogbeat version actually ships. Two fields needed manual
correction after compiling and comparing against fields already validated live
in Kibana earlier in this lab (`winlog.event_data.TicketEncryptionType`,
`winlog.event_data.PreAuthType`):

- Kerberoasting rule: pipeline emitted `service.name`, corrected to
  `winlog.event_data.ServiceName`.
- DCSync rule: pipeline emitted `user.name`, corrected to
  `winlog.event_data.SubjectUserName`.

Lesson: never ship a compiled rule straight from the converter. Diff the
field names against a known-good index pattern first.

## Tuning

See [`tuning/false_positive_scenarios.md`](tuning/false_positive_scenarios.md)
for the two deliberate false-positive exercises (a legitimate client hitting
an RC4-only service account, and an AD auditing tool holding real replication
rights) and the resulting rule refinements, tracked in
[`CHANGELOG.md`](CHANGELOG.md).
