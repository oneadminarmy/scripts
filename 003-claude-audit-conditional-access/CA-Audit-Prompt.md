# Conditional Access audit prompt

Paste this prompt into Claude, then attach the redacted `CA-Audit-<date>.json` file from
`Export-CAPolicyForAudit.ps1`. Never attach the `CA-Audit-Map-<date>.csv` file.

Use a business plan where your conversations are not used for model training, and check
your organization's AI use policy before you upload tenant configuration.

---

You are a senior Microsoft Entra ID security reviewer. Attached is a JSON export of every
Conditional Access policy in a small Microsoft 365 tenant (about 80 users, Microsoft 365
Business Premium, so Entra ID P1 and no P2). Object IDs have been replaced with labels such as
"Role: Global Administrator", "Group: SG-BreakGlass [BREAK-GLASS]" and "User-03".
"Unresolved-NN" means the policy points at an object that no longer exists or cannot be read.

Audit the policies against this checklist:

1. Break-glass: every policy excludes the group labeled [BREAK-GLASS]. List any policy that does not.
2. Coverage: is there an enforced (state "enabled") policy requiring MFA for all users and all
   resources? Name the gaps: users, guests, apps or client app types left out.
3. Legacy authentication: is it blocked by an enforced policy (clientAppTypes
   exchangeActiveSync and other, grant control block)?
4. Admins: do privileged roles require a phishing-resistant authentication strength?
5. Exclusions: list every user, group and app excluded from an MFA or block policy. Say which
   exclusions look temporary or too broad, and why.
6. Report-only: list policies still in state "enabledForReportingButNotEnforced" and what they
   would protect if switched on.
7. Device code flow and other risky authentication flows: is there a policy for them?
8. Guests and external users: are they covered by MFA?
9. Stale or broken references: any "Unresolved-NN" entries, disabled policies, or duplicates
   that overlap or conflict.
10. Anything else a reviewer should raise for a tenant of this size.

Rules for your answer:

- Only report what the JSON shows. Quote the policy name and the exact field as evidence.
- If you cannot tell from the export, write "Unknown from export" instead of guessing.
- Do not recommend features that need Entra ID P2 (sign-in risk, user risk) without labeling
  them "Needs P2".
- Do not invent policy names, groups or settings that are not in the file.

Output format:

1. A table with columns: #, Severity (High, Medium, Low), Policy, Finding, Evidence, Fix,
   License needed, Confidence (High, Medium, Low).
2. Below the table, the three fixes you would do first, in order, with one sentence each.
3. A list of findings you are least sure about, so a human checks them in the What If tool first.
