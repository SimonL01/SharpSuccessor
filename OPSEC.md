# SharpSuccessor - OPSEC & Engagement Considerations

> For **authorized** red team engagements only. BadSuccessor is a high-impact Active Directory
> privilege-escalation technique; using it outside the scope and rules of engagement (ROE) of a
> signed authorization is illegal. This document assumes written authorization is in place.

## 1. Why the technique is relatively quiet

BadSuccessor abuses the dMSA (delegated Managed Service Account) migration feature. Its appeal is
what it does **not** require:

- No code execution on a domain controller.
- No DCSync / replication of secrets.
- No new membership in a privileged group.
- No password reset of the target account.

Account takeover is achieved purely by creating a dMSA and setting a few attributes, then letting
the KDC mint a ticket that inherits the target's context. The footprint is therefore a small number
of **LDAP operations** and **one Kerberos exchange** - the stealth problem is about *how and when*
those touch the directory and the KDC, not about hiding a payload.

## 2. What this tool does on the wire

The optimized implementation keeps directory interaction minimal:

| Command | Domain interactions |
| --------- | -------------------- |
| `add` | 1 LDAP search (resolves target + access principal together) + 2 writes (create dMSA, link target) |
| `remove` | 1 LDAP search (target) + 1 write (reset target) + 1 delete (dMSA) |

- The domain DNS/DN is derived from the `/path` argument, so there is **no** extra
  `Domain.GetCurrentDomain()` / RootDSE round-trip in the normal case.
- `tgtdeleg` (Rubeus) uses the current logon context, avoiding a fresh password-based bind.

## 3. Detections a mature SOC will have

Assume these are monitored and plan around them rather than assuming you are invisible:

| Event | Source | Trigger |
| ------- | -------- | --------- |
| **5137** | DC Directory Service log | Creation of an `msDS-DelegatedManagedServiceAccount` object |
| **5136** | DC Directory Service log | Modification of `msDS-ManagedAccountPrecededByLink` (and the superseded-state attributes) |
| **4769** | DC Security log | TGS request for the dMSA with KERB-DMSA fields (the `asktgs /dmsa` step) |
| **4662** | DC Security log | Directory access to the new object's attributes (if object-access auditing is on) |

The single strongest signal is the **tight temporal correlation** between the 5137 (create) and the
5136 (link) - "a brand-new dMSA that is linked to a privileged account within the same second" is a
trivial, high-fidelity hunt query.

## 4. Stealth guidance

**Decorrelate the writes in time.** Use `/opsec` so the dMSA creation and the target-link write are
separated by a randomized interval. This is the highest-value, lowest-effort lever against the
5137<->5136 correlation rule. See §5.

**Blend with the baseline.**

- Create the dMSA in an OU where service accounts already live, and name it to match local
  convention (`svc-...`, `gmsa-...`) - not `attacker_dMSA`.
- Operate during business hours when service-account churn is normal. A 03:00 object creation by a
  workstation user account is anomalous on its own.

**Pin to one DC.** Use `/dc` so every operation hits a single domain controller. Spreading writes across DCs multiplies the event sources and makes replication-timing analysis easier for defenders.

**Shorten the exposure window.** Treat the dMSA as ephemeral:
`add` -> `tgtdeleg` / `asktgs` -> act -> `remove`. A privileged link that exists for minutes instead of
days drastically shrinks the window for a scheduled audit or a BadSuccessor hunt to catch it.

Note that during engagements where Credential Guard was enabled, `tgtdeleg` can't be used no more. Therefore, the workaround is to write a ticket to a file and use the ticket that way.

**Reduce credential noise.** Prefer running in an already-authorized context (so `tgtdeleg` reuses
the logon) over `/username` + `/password`, which adds an authentication event (4624) against the DC.

**Encryption types.** The dMSA is created with AES-only (`msDS-SupportedEncryptionTypes = 0x1c`).
RC4 in the subsequent Kerberos traffic would itself be an anomaly in an AES environment.

## 5. The `/opsec` timing flag

`/opsec` inserts a randomized sleep between the two directory writes (and, for `remove`, between the
attribute reset and the delete). Randomized jitter is preferable to a fixed delay because a constant
gap is itself a signature.

```cmd
# Default jittered delay (30-180s) between create and link
SharpSuccessor.exe add /impersonate:Administrator /path:"ou=svc,dc=lab,dc=lan" \
                       /account:jdoe /name:svc-sync01 /dc:dc01.lab.lan /opsec

# Custom range (seconds)
... /delay:60-600

# Fixed delay (seconds)
... /delay:120
```

- `/opsec` - enable jitter with the default 30–180s range.
- `/delay:<min>-<max>` - randomized range, in seconds (implies `/opsec`).
- `/delay:<n>` - fixed delay, in seconds (implies `/opsec`).

Trade-off: a longer gap decorrelates the events better but keeps the tool process (and your session)
alive longer. Choose the range from the environment's logging cadence and your tolerance for session
duration. The delay only spaces the two *writes*; the read-only search still happens up front.

## 6. Cleanup / teardown

Always run `remove` when finished (and consider `/opsec` here too):

```cmd
SharpSuccessor.exe remove /impersonate:Administrator /path:"ou=svc,dc=lab,dc=lan" \
                          /name:svc-sync01 /dc:dc01.lab.lan /opsec
```

This clears `msDS-SupersededManagedAccountLink` and `msDS-SupersededServiceAccountState` on the
target and deletes the dMSA object. Note that `remove` **does not** erase the 5137/5136/4769 events
already written to the DC logs - cleanup removes the standing artifacts, not the historical record.

## 7. Honest caveats

- **Real stealth is a property of the whole engagement** - egress, C2, timing, and matching the
  environment baseline - not of any single tool.
- **On a well-instrumented domain, assume the technique leaves detectable artifacts.** Plan the ROE
  and the teardown around the possibility of being caught, and coordinate with the client where the
  engagement calls for it.
- If the engagement goal includes **validating detections**, the event IDs in §3 are the ones the
  blue team should confirm coverage for; the `/opsec` delay is a useful way to test whether their
  correlation rules depend on a tight time window.
