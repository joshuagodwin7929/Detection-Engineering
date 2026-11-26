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

### Refinement applied (v0.2.0)

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

### Update, November 2026: allow-list removed (v0.3.0)

My purple team re-test showed this refinement was a mistake. `svc_sql` is the
only Kerberoastable account in my lab, so it's exactly the account an attacker
roasts. With `svc_sql` allow-listed by `ServiceName`, the rule ignored every
request for it, legitimate or malicious, and would have stayed silent during
the very attack it was written for.

The lesson: allow-listing by the *target* of a technique is different from
allow-listing a known-good *actor*. For Kerberoasting the target is the service
account, so filtering on `ServiceName` hides the attack along with the noise.
If a false positive has to be filtered, filter on something that identifies the
legitimate client (its source IP or account), not on the account being
requested.

What I did instead:

- Removed `filter_known_rc4_accounts` from the rule.
- Kept the environment-side fix as the real answer: set
  `msDS-SupportedEncryptionTypes` on `svc_sql` to AES. Once the account can't
  issue RC4 tickets, the legitimate false positive disappears and any RC4
  request for it is suspicious again.

With the allow-list removed, the deployed version of this rule raised an alert
for the Kerberoasting step of the re-test. See
[Purple-Team-Automation](https://github.com/joshuagodwin7929/Purple-Team-Automation/blob/main/validation/detection-results.md).

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

### Refinement applied (v0.2.0)

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

## Exercise 3 - AS-REP Roasting rule vs. normal logons by the same account

### Why this rule is vulnerable to FPs

The rule fires on any 4768 with `PreAuthType: 0`. That's every Kerberos logon
by an account with "Do not require Kerberos preauthentication" set, not just
an attacker requesting its AS-REP. In my lab that account is `j.jenkins`,
deliberately left pre-auth-disabled so the attack works.

### What happened

In the November purple team re-test the rule alerted twice when no AS-REP
Roasting was running. I checked the events behind one of those alerts
(25 Nov 2026, 23:29:24 UTC): `TargetUserName: j.jenkins`, result `0x0`, a
successful logon during the password spray. `Get-ADUser j.jenkins -Properties
DoesNotRequirePreAuth` returned `True`.

### First idea: filter on RC4 ticket encryption (rejected)

Attack tools want an RC4 reply because it's much easier to crack, so I tried
adding `TicketEncryptionType: 0x17`, the same field the Kerberoasting rule
uses. In Discover over the attack window (25 Nov, 04:00 to 05:00 UTC) that
query returned **0 hits**. The attack's 4768 had `TicketEncryptionType: 0x12`
(AES), like the normal logon. The filter would have removed the attack along
with the noise.

### Second idea: filter on the session key encryption type (kept)

Expanding the attack event (04:59:35 UTC, from the Kali host) showed why:

| Field | Attack event | Normal `j.jenkins` logon |
|---|---|---|
| Ticket Encryption Type | `0x12` (AES) | `0x12` (AES) |
| Session Encryption Type | `0x17` (RC4) | `0x12` (AES) |
| Advertized Etypes | RC4-HMAC-NT only | not RC4-only |

The ticket is encrypted with the `krbtgt` key, so the DC uses AES there
regardless. The part the attacker cracks offline is protected with the user's
key using the etype the client asked for, and the attack tool asked for RC4
only. That shows up as `SessionKeyEncryptionType: 0x17`.

Results with `SessionKeyEncryptionType: 0x17` added, against the recorded
events:

| Window (25 Nov 2026, UTC) | Hits | Meaning |
|---|---|---|
| 04:50 to 05:00 (attack) | 3 | The AS-REP ability at 04:59:35, plus Impacket logging in as `j.jenkins` for the Kerberoasting steps at 04:56:00 and 04:58:22 |
| 23:20 to 23:35 (noise) | 0 | The normal `j.jenkins` logons are gone |

The two Kerberoasting matches aren't false positives: they're Impacket
authenticating as the pre-auth-disabled account and asking for RC4, which is
attacker tooling. Kerbrute's successful `j.jenkins` logons during the spray
negotiated normally and dropped out.

### Refinement applied (v0.3.1)

Added `SessionKeyEncryptionType: '0x17'` to the selection.

Limits:

- I tested this against recorded events in Discover. The alerting rule in
  Kibana needs the same condition added and a fresh run before I can call it
  validated as an alert.
- A tool that asks for AES would get past it. That's harder to crack, but not
  impossible with a weak password.
- The real fix is still in the environment: require pre-authentication on
  every account. Then any `PreAuthType: 0` is suspicious by definition.

---

## Process note

All three exercises followed the same shape: reproduce the FP for real against the
lab (not hypothetically), confirm the rule actually fires on it, then decide
whether the fix is a rule change, an environment change, or both. That
decision explicitly favored allow-listing named accounts over loosening field
logic - a rule that's easy to bypass by guessing the exclusion pattern is
worse than no rule at all.
