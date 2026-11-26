# Where my deployed rules differ from the compiled output

The `.kql` files in this folder are built from the Sigma rules by `scripts/build.sh`, and CI checks they stay in sync. For two rules, the query I actually run in my lab is different, because the compiled query doesn't work against my Winlogbeat 8.12 data. This file records those differences and why.

All four lab rules raised real alerts in a purple team re-test on 25 November 2026. Full results: [Purple-Team-Automation](https://github.com/joshuagodwin7929/Purple-Team-Automation/blob/main/validation/detection-results.md).

## DCSync

**Compiled:**

```
winlog.channel:Security AND ((event.code:4662 AND (winlog.event_data.Properties:(*1131f6ad\-9c07\-11d1\-f79f\-00c04fc2dcd2* OR *1131f6aa\-9c07\-11d1\-f79f\-00c04fc2dcd2*))) AND (NOT (winlog.event_data.SubjectUserName:(*$ OR svc_adaudit))))
```

**Deployed in my lab:**

```
event.code:4662 and message:"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" and not winlog.event_data.SubjectUserName:*$
```

Two problems with the compiled version in my lab:

1. My Winlogbeat doesn't populate `winlog.event_data.Properties` on 4662 events. The GUID only appears inside `message`.
2. I can't just map `Properties` to `message` in the pipeline. Sigma's `contains` compiles to a leading and trailing wildcard, and `message` is a text field. Elasticsearch splits text fields into words at every hyphen before storing them, and a wildcard is matched against one word at a time, so a hyphenated GUID never matches. That's exactly why my original DCSync alert rule raised 0 alerts in 57 runs. Searching for the GUID as a quoted phrase matches the words in order and works.

The deployed rule also doesn't exclude `svc_adaudit` yet. That account only exists for the tuning exercise, so it's a known false positive in my lab.

## Password spraying

This is a correlation rule, so there's no compiled query to compare against. The deployed config is [`password_spraying_distributed_failures.kibana-rule.json`](password_spraying_distributed_failures.kibana-rule.json), and its known limitations are listed in the file.

## Rules that match

- **Kerberoasting:** the deployed query is the compiled query without the `winlog.channel:Security` clause.
- **AS-REP Roasting:** the alert on 25 Nov 2026 came from the v0.3.0 rule, without the `SessionKeyEncryptionType` condition added in v0.3.1. The tuned query was tested against the recorded events in Discover, but the Kibana rule still needs updating to match.
