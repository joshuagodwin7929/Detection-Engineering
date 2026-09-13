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
