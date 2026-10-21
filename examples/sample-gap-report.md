# Google Workspace security gap report

- **Snapshot:** 2026-02-02
- **Edition:** Business Starter
- **Method:** read-only GAM pull + Drive metadata inventory + public DNS

Severity: 🔴 critical/high: act this week · 🟠 medium: act this month · 🟡 low: hardening · 🔵 info: review

## Summary

| # | Finding | Severity | Category |
|---|---|---|---|
| 1 | 3 active user(s) not enrolled in 2SV | 🔴 critical | Identity |
| 2 | Any user can grant any third-party app access to company data | 🔴 high | Apps |
| 3 | 2 third-party app(s) hold high-risk scopes | 🔴 high | Apps |
| 4 | 1 suspicious sign-in or blocked risky-action event(s) | 🔴 high | Sign-ins |
| 5 | 1 account(s) signing in from several countries | 🔴 high | Sign-ins |
| 6 | Any 2SV method is allowed, including SMS and voice codes | 🟠 medium | Identity |
| 7 | 1 active account(s) with no sign-in for 90+ days | 🟠 medium | Identity |
| 8 | 1 domain-wide delegation grant(s) in the audit window | 🟠 medium | Apps |
| 9 | 3 company-owned file(s) open to anyone with the link | 🟠 medium | Drive |
| 10 | 3 sharing grant(s) to 3 outside domain(s) | 🟠 medium | Drive |
| 11 | Gmail spoofing and authentication protections are partial | 🟠 medium | Gmail |
| 12 | Password policy is weaker than recommended | 🟡 low | Identity |
| 13 | Shared drive defaults allow outside or non-member access | 🟡 low | Drive |
| 14 | Drive for desktop works on any computer | 🟡 low | Drive |
| 15 | External Chat spaces are open to every domain | 🟡 low | Collaboration |
| 16 | Google Groups can be opened to outsiders | 🟡 low | Collaboration |
| 17 | Users can export data with Google Takeout | 🟡 low | Data protection |
| 18 | Mail authentication DNS records are incomplete | 🟡 low | Gmail |
| 19 | 1 stale, 1 unlocked, 0 compromised mobile device(s) of 3 | 🟡 low | Devices |
| 20 | 2 security-relevant admin change(s) in the audit window | 🔵 info | Admin activity |

## 🔴 1. 3 active user(s) not enrolled in 2SV

3 of 9 active users have no 2SV. Org-wide enforcement starts 2026-02-10 (8 days): they will be locked out.

- casey@example.com
- emery@example.com
- frontdesk@example.com

**Fix:** Chase enrollment (passkeys count only once 2SV is turned on), or suspend unused accounts.

*Reference: CIS Google Workspace Foundations Benchmark: 2-Step Verification*

## 🔴 2. Any user can grant any third-party app access to company data

Unconfigured third-party apps access level: ACCESS_LEVEL_UNSPECIFIED.

**Fix:** Security → API controls → Manage third-party app access: review the apps already used, mark the needed ones Trusted or Limited, then set unconfigured apps to 'Sign in with Google only' or block.

**Edition note:** Available on every edition.

*Reference: CIS Google Workspace Foundations Benchmark: API controls*

## 🔴 3. 2 third-party app(s) hold high-risk scopes

4 distinct apps were authorized in the token audit window; 2 have full Gmail, full Drive or admin scopes.

- Acme Mail Assistant: 2 user(s), mail.google.com (FULL GMAIL)
- Sample PDF Toolkit: 1 user(s), drive

**Fix:** Review each app with its users; mark the needed ones Trusted or Limited and block the rest.

*Reference: CIS Google Workspace Foundations Benchmark: API controls*

## 🔴 4. 1 suspicious sign-in or blocked risky-action event(s)

Google flagged these sign-ins or blocked sensitive actions.

- 2026-01-29T03:12 suspicious_login casey@example.com ZZ

**Fix:** Confirm each with the user; reset password and revoke sessions for anything unexplained.

*Reference: Google Admin: Login audit log*

## 🔴 5. 1 account(s) signing in from several countries

Travel and VPNs explain most of these; an admin account in this list deserves a direct check.

- alex@example.com (super admin): DE, US

**Fix:** Ask each user to confirm; check Security → Alert center for related alerts.

*Reference: Google Admin: Login audit log*

## 🟠 6. Any 2SV method is allowed, including SMS and voice codes

SMS and voice codes can be phished or SIM-swapped.

**Fix:** Require security keys or passkeys at least for admins: put them in their own OU or group and set 'Only security key'.

**Edition note:** Security-key-only enforcement is available on every edition.

*Reference: CIS Google Workspace Foundations Benchmark: 2-Step Verification*

## 🟠 7. 1 active account(s) with no sign-in for 90+ days

Dormant and shared mailboxes keep working passwords nobody watches.

- frontdesk@example.com (last sign-in 2025-06-01)

**Fix:** Suspend or archive them, or convert shared mailboxes to Groups / delegated access.

*Reference: CIS Google Workspace Foundations Benchmark: User account management*

## 🟠 8. 1 domain-wide delegation grant(s) in the audit window

Domain-wide delegation lets a service account act as any user for the granted scopes.

- 2026-01-27 alex@example.com: Example Backup Service https://www.googleapis.com/auth/drive.readonly

**Fix:** Security → API controls → Domain-wide delegation: confirm each client and trim scopes.

*Reference: CIS Google Workspace Foundations Benchmark: API controls*

## 🟠 9. 3 company-owned file(s) open to anyone with the link

Anyone who obtains the URL can open these files without signing in.

- alex@example.com: 1 file(s)
- blake@example.com: 1 file(s)
- frankie@example.com: 1 file(s)

**Fix:** Ask owners to review drive_link_shared_full.csv; restrict links to the organization by default.

*Reference: CIS Google Workspace Foundations Benchmark: Drive sharing*

## 🟠 10. 3 sharing grant(s) to 3 outside domain(s)

1 grant edit or higher rights; 1 go to personal mail domains.

- example.org: 1 grant(s)
- gmail.com: 1 grant(s)
- example.net: 1 grant(s)

**Fix:** Review drive_external_shares.csv with owners; turn on the warning when sharing outside the organization; consider an allowlist of trusted domains.

**Edition note:** Trust rules and Drive DLP are not available on Business Starter; use the standard sharing settings.

*Reference: CIS Google Workspace Foundations Benchmark: Drive sharing*

## 🟠 11. Gmail spoofing and authentication protections are partial

Some protections are off, and others only show a warning banner.

- detectUnauthenticatedEmails: off
- detectGroupsSpoofing: off
- domainSpoofingConsequence: warning only

**Fix:** Apps → Gmail → Safety → Spoofing and authentication: turn every check on and move suspicious mail to spam.

*Reference: CIS Google Workspace Foundations Benchmark: Gmail safety*

## 🟡 12. Password policy is weaker than recommended

Minimum length 8 (recommend 12+); requirements not enforced at next sign-in.

- minimum length 8 (recommend 12+)
- requirements not enforced at next sign-in

**Fix:** Security → Authentication → Password management: minimum 12, enforce at next sign-in.

*Reference: CIS Google Workspace Foundations Benchmark: Password management*

## 🟡 13. Shared drive defaults allow outside or non-member access

New shared drives allow: allowNonMemberAccess, allowExternalUserAccess.

- allowNonMemberAccess
- allowExternalUserAccess

**Fix:** Apps → Drive and Docs → Sharing settings → Shared drive creation: tighten the defaults.

*Reference: CIS Google Workspace Foundations Benchmark: Drive sharing*

## 🟡 14. Drive for desktop works on any computer

Users can sync company files to personal, unmanaged computers.

**Fix:** Restrict Drive for desktop to authorized devices where the edition allows it.

**Edition note:** Restricting to authorized devices needs advanced endpoint management (Business Plus and above).

*Reference: CIS Google Workspace Foundations Benchmark: Drive and Docs*

## 🟡 15. External Chat spaces are open to every domain

Users can create or join spaces with any outside organization.

**Fix:** Apps → Google Chat → External Chat settings: restrict to allowlisted domains.

*Reference: CIS Google Workspace Foundations Benchmark: Google Chat*

## 🟡 16. Google Groups can be opened to outsiders

Owners can add external members; owners can accept mail from the public.

- owners can add external members
- owners can accept mail from the public

**Fix:** Apps → Google Groups for Business → Sharing settings: keep groups internal.

*Reference: CIS Google Workspace Foundations Benchmark: Groups for Business*

## 🟡 17. Users can export data with Google Takeout

Takeout lets any user download a full copy of their account data.

- photos
- takeout

**Fix:** Apps → Additional Google services → Takeout: turn off for users who don't need it.

*Reference: CIS Google Workspace Foundations Benchmark: Takeout*

## 🟡 18. Mail authentication DNS records are incomplete

Without an enforcing DMARC policy, anyone can send mail that appears to come from your domain.

- example.com: no MTA-STS
- example.com: no TLS-RPT

**Fix:** Publish SPF and DKIM, then move DMARC from p=none to quarantine and reject with rua= reports; add MTA-STS and TLS-RPT.

*Reference: CIS Google Workspace Foundations Benchmark: Email authentication (SPF, DKIM, DMARC)*

## 🟡 19. 1 stale, 1 unlocked, 0 compromised mobile device(s) of 3

Stale devices may still hold synced mail; unlocked ones expose it to anyone holding the phone.

- no screen lock: blake@example.com iPhone 16
- no sync since 2025-05-30: frontdesk@example.com iPhone 11

**Fix:** Remove stale devices from the account (Devices → Mobile), and require a screen lock.

**Edition note:** Business Starter has basic mobile management only: no remote wipe of the whole device, no app management.

*Reference: CIS Google Workspace Foundations Benchmark: Mobile device management*

## 🔵 20. 2 security-relevant admin change(s) in the audit window

Role assignments and authentication or app-access setting changes.

- 2026-01-26 admin@example.com: ASSIGN_ROLE _SEED_ADMIN_ROLE gray@example.com
- 2025-12-15 admin@example.com: CHANGE_TWO_STEP_VERIFICATION_START_DATE

**Fix:** Confirm each change was intended and made by the expected admin.

*Reference: Google Admin: Admin audit log*

## ✅ Already good

- Every super admin is enrolled in 2SV
- 2SV enforcement configured at the root OU (from 2026-02-10)
- 3 super admins (2-4 recommended)
- Super admin self-recovery is off
- Web session length 336 h
- External calendar sharing capped (EXTERNAL_FREE_BUSY_ONLY)
- Gmail attachment protections are on and act on messages
- 1 Chrome browser(s) enrolled
