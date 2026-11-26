# Changelog

## [v0.1.0] - 2026-09-12
### Added
- Initial rule set: 6 Sigma detections covering Kerberoasting, AS-REP
  Roasting, Password Spraying, Account Lockout Burst, DCSync, and
  atexec-style lateral movement, sourced from validated hunt queries in the
  AD attack/defense lab.
- Compiled Elastic output for all 6 rules (.kql for direct query rules,
  .kibana-rule.json for the two correlation rules that Sigma's
  elasticsearch/lucene backend cannot express as a query string).
- README with MITRE ATT&CK mapping table and documented LLMNR visibility gap.

## [v0.2.0] - 2026-09-12
### Changed
- Kerberoasting rule: added `filter_known_rc4_accounts` after confirming via
  a deliberate false-positive test that any legitimate client authenticating
  to the RC4-only `svc_sql` account trips the rule identically to an
  attacker. See tuning/false_positive_scenarios.md, Exercise 1.
- DCSync rule: added `filter_known_sync_accounts` after confirming via a
  deliberate false-positive test that a legitimate non-DC directory-sync/
  audit account holding real replication rights trips the rule identically
  to a DCSync attack. See tuning/false_positive_scenarios.md, Exercise 2.
### Added
- tuning/false_positive_scenarios.md documenting both exercises, findings,
  and the reasoning behind allow-listing named accounts instead of loosening
  field logic.

## [v0.3.0] - 2026-11-26
### Changed
- Kerberoasting rule: removed `filter_known_rc4_accounts`. The allow-listed
  `svc_sql` account was the account being roasted, so the filter hid the
  attack. See tuning/false_positive_scenarios.md, Exercise 1 update.
- Password spraying rule: the base rule now matches EventID 4771 as well as
  4625. Kerbrute only produces 4771, so the old rule couldn't catch it.
- Password spraying Kibana config replaced with the version that alerted in
  the lab on 25 Nov 2026, with its known limitations documented.
- DCSync rule: fixed swapped comments on the two replication GUIDs.
- AS-REP Roasting rule: PreAuthType written as a number; added a false
  positive for normal logons by accounts with pre-auth disabled.
- All rules: author set to Okunnuwa Joshua Godwin; `modified` dates added.
- README rewritten with lab validation status for each rule.
### Added
- `pipelines/lab_winlogbeat.yml`: maps `ServiceName` and `SubjectUserName`
  to the field names my Winlogbeat 8.12 actually uses, replacing the manual
  corrections I used to make after compiling.
- `scripts/build.sh`: compiles every non-correlation rule, or checks the
  committed output for drift with `--check`.
- GitHub Actions workflow running `sigma check` and the drift check on
  every push and pull request.
- `rules/elastic/LAB-OVERRIDES.md`: where my deployed lab queries differ
  from the compiled output, and why.
