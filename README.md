# Detection-Engineering

![Validate Sigma rules](https://github.com/joshuagodwin7929/Detection-Engineering/actions/workflows/validate-rules.yml/badge.svg)

By OKUNNUWA JOSHUA GODWIN | [LinkedIn](https://www.linkedin.com/in/okunnuwa-joshua-godwin)

Sigma detections I wrote for Active Directory attacks after running each attack against my own lab: a Windows Server 2022 DC and a Windows 10 client, logging with Sysmon and Winlogbeat into Elastic Stack 8.12.

Every rule here started as a hunt query I wrote after running the real technique and finding its events in Kibana. I then turned it into vendor-neutral Sigma, compiled it to Elastic, and tested it against false positives I created on purpose. My working rule for the lab is **log first, attack second, hunt third, then formalize.** This repo is the formalize step.

## Rules

| Rule | ATT&CK | Data source | Level | Lab validation |
|---|---|---|---|---|
| [`kerberoasting_rc4_tgs_request.yml`](rules/sigma/kerberoasting_rc4_tgs_request.yml) | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) Kerberoasting | Security 4769 | High | ✅ Alert, 25 Nov 2026 |
| [`asrep_roasting_no_preauth.yml`](rules/sigma/asrep_roasting_no_preauth.yml) | [T1558.004](https://attack.mitre.org/techniques/T1558/004/) AS-REP Roasting | Security 4768 | High | ✅ Alert, 25 Nov 2026 |
| [`password_spraying_distributed_failures.yml`](rules/sigma/password_spraying_distributed_failures.yml) | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) Password Spraying | Security 4625, 4771 (correlation) | Medium | ✅ Alert, 25 Nov 2026 |
| [`dcsync_replication_rights_abuse.yml`](rules/sigma/dcsync_replication_rights_abuse.yml) | [T1003.006](https://attack.mitre.org/techniques/T1003/006/) DCSync | Security 4662 | Critical | ✅ Alert, 25 Nov 2026 |
| [`account_lockout_burst.yml`](rules/sigma/account_lockout_burst.yml) | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) (supporting signal) | Security 4740 (correlation) | Medium | Not yet tested |
| [`lateral_movement_atexec_svchost_child.yml`](rules/sigma/lateral_movement_atexec_svchost_child.yml) | [T1053.002](https://attack.mitre.org/techniques/T1053/002/), [T1569.002](https://attack.mitre.org/techniques/T1569/002/) | Sysmon 1 | Medium | Not yet tested |

"Alert" means the rule was deployed in Kibana and raised a real alert against the attack, run through Caldera in my [Purple-Team-Automation](https://github.com/joshuagodwin7929/Purple-Team-Automation) lab. A search that finds the events doesn't count. I learned that the hard way (see below).

## Repo layout

```
rules/sigma/               Sigma rules (the source of truth)
rules/elastic/             Compiled Elastic output
  *.kql                    Built from Sigma by scripts/build.sh
  *.kibana-rule.json       Hand-maintained configs for the two correlation rules
  LAB-OVERRIDES.md         Where my deployed queries differ, and why
pipelines/                 Field mappings for my Winlogbeat 8.12 data
scripts/build.sh           Compiles the rules, or checks them for drift
tuning/                    False-positive exercises and what I changed
.github/workflows/         CI that validates every rule on each push
CHANGELOG.md               Version history
```

## How the build works

`scripts/build.sh` compiles every non-correlation rule with `sigma-cli`, using the Elasticsearch Lucene backend, the standard `ecs_windows` pipeline, and my own pipeline in [`pipelines/lab_winlogbeat.yml`](pipelines/lab_winlogbeat.yml).

I need the extra pipeline because `ecs_windows` maps some fields to names my Winlogbeat doesn't use. It turned `ServiceName` into `service.name` and `SubjectUserName` into `user.name`, but my events have them as `winlog.event_data.ServiceName` and `winlog.event_data.SubjectUserName`. I used to fix these by hand after compiling. Now the pipeline does it, so the build is repeatable.

On every push and pull request, GitHub Actions:

1. runs `sigma check` on every rule
2. rebuilds the `.kql` files and fails if any committed file differs from what the Sigma source produces

So a Sigma rule and its compiled query can't quietly drift apart.

To run it locally:

```bash
pip install sigma-cli pySigma-backend-elasticsearch pysigma-pipeline-windows
scripts/build.sh          # write the compiled files
scripts/build.sh --check  # check for drift, as CI does
```

## Correlation rules

Password spraying and account lockout burst are Sigma correlation rules: "count distinct usernames per source over a time window." That can't be written as a single query string, and the Elasticsearch backend refuses to compile them:

```
Error: Feature required for conversion of Sigma rule is not supported by backend:
Backend does not support correlation rules.
```

So I maintain those two as Kibana rule configs (`.kibana-rule.json`) by hand. The password spray config is the exact one that alerted in my lab, with its limitations listed in the file.

## What the purple team re-test taught me

In September I wrote here that these rules were validated. What I'd really done was find the attack events with searches in Kibana. When I checked in November, only the DCSync rule had ever been deployed as an alerting rule, and it had never fired. Getting all four to alert changed three rules in this repo:

- **Kerberoasting:** I removed the `svc_sql` allow-list. It was the account being roasted, so the allow-list hid the attack. [Details](tuning/false_positive_scenarios.md#update-november-2026-allow-list-removed-v030).
- **Password spraying:** I added event 4771. Kerbrute talks Kerberos directly, so a failed password shows up as 4771, never 4625. The old rule could not have caught it.
- **DCSync:** I fixed two swapped GUID comments. The bigger lesson was in the deployed query: Sigma's `contains` compiles to a wildcard, which never matches a hyphenated GUID in a text field like `message`. See [`LAB-OVERRIDES.md`](rules/elastic/LAB-OVERRIDES.md).

The full investigation, including the six lab problems I found and fixed, is in [Purple-Team-Automation](https://github.com/joshuagodwin7929/Purple-Team-Automation/blob/main/validation/detection-results.md).

## Tuning

[`tuning/false_positive_scenarios.md`](tuning/false_positive_scenarios.md) covers two exercises where I created false positives on purpose: a legitimate client using an RC4-only service account, and an AD auditing tool with real replication rights. It also covers what I changed afterwards, including the Kerberoasting change I later reversed.

## Known gap

There's no rule here for LLMNR/NBT-NS poisoning (T1557.001), the first attack I ran in the lab. Sysmon Event IDs 3 (network connection) and 22 (DNS query) aren't firing on my Windows 10 endpoint, so the attack leaves nothing to detect. I'd rather leave the gap visible than write a rule against data that isn't arriving. Restoring that telemetry comes first.
