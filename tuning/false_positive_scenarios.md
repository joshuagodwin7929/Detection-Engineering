# Tuning: Deliberate False-Positive Generation

Two of the high/critical-severity rules were stress-tested against normal
admin activity crafted to look like the attack. Goal: find where the rule's
selection logic alone can't tell attacker from admin, then decide whether the
fix belongs in the rule or in the environment.

---

## Exercise 1 - Kerberoasting rule vs. a legitimate RC4-only client

### Why this rule is vulnerable to FPs

The rule fires on any 4769 with `TicketEncryptionType: 0x17` (RC4) for a
non-machine, non-krbtgt SPN. In this lab, `svc_sql` was deliberately
downgraded to RC4 by clearing `msDS-SupportedEncryptionTypes` back in the
Kerberoasting technique writeup, to get a crackable hash. **That
misconfiguration is permanent on the account, not something the attacker's
tool does at request time.** Which means *any* client authenticating to that
SQL service - a real application, a health-check script, a DBA connecting
with SSMS - will request an RC4 ticket and trip this rule identically to
`impacket-GetUserSPNs`.

### Test plan

1. On a domain-joined host, as a normal (non-attacker) user, connect to the
   SQL service the SPN is registered against, e.g.:
   `sqlcmd -S joshua-server2022.joshua.local,1433 -E`
   (Any action that causes a real Kerberos service-ticket request for
   `MSSQLSvc/joshua-server2022.joshua.local:1433` reproduces this - it does
   not require SQL Server to actually be running the service correctly.)
2. Confirm in Kibana that this produces a 4769 with
   `winlog.event_data.TicketEncryptionType:"0x17"` for `ServiceName: svc_sql`,
   identical in shape to the earlier attacker-generated event.
3. Confirm the current rule (`kerberoasting_rc4_tgs_request.yml`) fires on
   both the legitimate connection and the earlier attack traffic - i.e. it
   cannot distinguish them by request shape alone.

### Finding

A single RC4 TGS request is **not**, by itself, evidence of an attack when
the target account is *known* to be RC4-only. The rule as originally written
treats every RC4 ticket request as equally suspicious regardless of whether
RC4 is expected for that specific SPN.

### Refinement applied (v1.1)

Two changes, addressing the false positive at both layers:

1. **Detection-side (this repo):** added a `filter_known_rc4_accounts` block
   so an inventoried, intentionally-RC4 service account doesn't page anyone
   on every legitimate connection. This is an explicit allow-list, not a
   blanket suppression - each entry has to be justified and dated.
2. **Environment-side (the actual fix):** the real remediation is not a
   detection rule at all - it's setting `msDS-SupportedEncryptionTypes` on
   `svc_sql` to AES (`0x18`) so the account stops being RC4-eligible entirely.
   Once that's done, *any* RC4 request against it becomes suspicious again
   without needing the allow-list, because a properly-configured account has
   no legitimate reason to negotiate RC4. Tuning a detection rule to tolerate
   a known-bad configuration is a stopgap, not the fix - the allow-list exists
   so the rule doesn't fire during the (hopefully short) window before the
   account gets remediated, and should be removed once it is.

See the updated rule for the exact filter; the allow-list is a single
placeholder entry (`svc_sql`) meant to be replaced with a real, dated
inventory once more than one legacy account exists.

---

## Exercise 2 - DCSync rule vs. a legitimate AD auditing tool

### Why this rule is vulnerable to FPs

`DS-Replication-Get-Changes` / `Get-Changes-All` are exactly the rights a
directory-sync tool needs to function - Azure AD Connect / Entra Connect is
the common example, but so are several commercial AD-auditing and
identity-governance products (Quest Change Auditor, ManageEngine ADAudit
Plus, etc.), which read AD via the same replication API to build change
history without touching the DC's live LDAP load. The original rule only
excludes accounts ending in `$` (real DC machine accounts) - it has no
concept of "a non-DC account that is *supposed* to hold this right."

### Test plan

1. Grant a dedicated non-DC service account (e.g. `svc_adaudit`) the
   `DS-Replication-Get-Changes` and `Get-Changes-All` extended rights on the
   domain root, the same way `dsacls` was used earlier in this lab to grant
   `j.jenkins` DCSync rights for validation - except this time documented as
   an intentional, legitimate grant for a monitoring tool rather than an
   attack simulation.
2. From a host authenticated as `svc_adaudit`, run
   `impacket-secretsdump -just-dc-user krbtgt <domain>/svc_adaudit@<dc>`
   (or any tool that exercises the same replication call) to generate a
   realistic "legitimate sync tool doing its job" event.
3. Confirm this produces a 4662 with the same GUIDs as the attack scenario,
   from a `SubjectUserName` that doesn't end in `$` - confirming the current
   rule fires on it identically to the `j.jenkins` DCSync attack.

### Finding

The machine-account filter only rules out the *most obvious* legitimate
holder of this right (real DCs). It does nothing for the much more common
real-world case: a deliberately provisioned, non-DC service account that
*should* have this right. Without an inventory, every legitimate sync/audit
tool becomes a permanent false positive - which is exactly the kind of noise
that gets an analyst to quietly disable a critical-severity rule.

### Refinement applied (v1.1)

Added a `filter_known_sync_accounts` block excluding a documented, dated
list of accounts that are supposed to hold replication rights (placeholder
entry: `svc_adaudit`). Two things this refinement deliberately does *not* do:

- It does not widen the exclusion to a pattern (e.g. `svc_*`) - each entry is
  a specific, named account added on purpose, not a naming convention that
  an attacker could pre-empt by naming their own account similarly.
- It does not lower the rule's severity. DCSync from an unexpected account is
  still `critical` - the fix is narrowing *which* accounts are "expected,"
  not deciding the technique itself is less dangerous.

---

## Process note

Both exercises followed the same shape: reproduce the FP for real against the
lab (not hypothetically), confirm the rule actually fires on it, then decide
whether the fix is a rule change, an environment change, or both. That
decision explicitly favored allow-listing named accounts over loosening field
logic - a rule that's easy to bypass by guessing the exclusion pattern is
worse than no rule at all.
