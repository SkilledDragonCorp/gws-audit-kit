# Check catalog

Every check `tools/analyze.py` runs, the default severity, where to fix it, and what each edition can do. Section names follow the [CIS Google Workspace Foundations Benchmark](https://www.cisecurity.org/benchmark/google_workspace) and Google's [Security checklist for small businesses](https://support.google.com/a/answer/9211704). This kit doesn't reproduce either document, so use them for the full control text. GAM command reference: the [GAM wiki](https://github.com/GAM-team/GAM/wiki).

## Severity

| Severity | Meaning | Default timing |
|---|---|---|
| 🔴 critical | Active takeover path or imminent lockout | today |
| 🔴 high | Broad exposure of company data or accounts | this week |
| 🟠 medium | Real risk that needs a planned change | this month |
| 🟡 low | Hardening | next quarter |
| 🔵 info | Review only; not a weakness by itself | when convenient |

Raise one level for super admins or tenant-wide settings; lower one level when the exposure is already contained (say why).

## Edition notes

Edition capabilities change. Treat these as a starting point and confirm on Google's edition comparison page before telling an admin a control is unavailable.

| Control | Business Starter | Business Standard | Business Plus | Enterprise |
|---|---|---|---|---|
| 2SV enforcement, security-key-only, Advanced Protection | ✅ | ✅ | ✅ | ✅ |
| Password policy, web session length, login challenges | ✅ | ✅ | ✅ | ✅ |
| Third-party app access control (API controls) | ✅ | ✅ | ✅ | ✅ |
| Alert Center (basic alerts) | ✅ | ✅ | ✅ | ✅ |
| Gmail safety (spoofing, attachments, links), SPF / DKIM / DMARC | ✅ | ✅ | ✅ | ✅ |
| Drive / Calendar / Chat / Groups sharing settings, Takeout | ✅ | ✅ | ✅ | ✅ |
| Chrome Enterprise Core (browser management) | ✅ free | ✅ free | ✅ free | ✅ free |
| Basic mobile management (screen lock, account wipe) | ✅ | ✅ | ✅ | ✅ |
| Advanced endpoint management (device approval, full wipe, Drive for desktop on authorized devices only) | ❌ | ❌ | ✅ | ✅ |
| Vault (retention, eDiscovery) | ❌ | ❌ | ✅ | ✅ |
| Context-Aware Access | ❌ | ❌ | ❌ | ✅ |
| Drive trust rules, Drive DLP | ❌ | ❌ | ❌ | ✅ |
| Security center, security sandbox | ❌ | ❌ | ❌ | ✅ (Enterprise Plus for some) |

**Business Starter alternatives** when a control is missing:

- No trust rules / DLP → default link sharing to "Restricted", turn on the warning when sharing outside, allowlist trusted domains, and review `drive_external_shares.csv` monthly.
- No advanced endpoint management → require a screen lock, remove stale devices, and train users to report lost phones; consider upgrading only the admins' OU.
- No Context-Aware Access → security keys for admins, short sessions for admins, Advanced Protection for super admins.
- No Vault → document an offboarding process that transfers data before deleting users.

## Checks

| ID | Check | Default severity | Fix (Admin console) |
|---|---|---|---|
| `super-admin-2sv` | Super admin without 2SV | critical | Security → Authentication → 2-step verification |
| `2sv-enrollment` | Active users without 2SV (critical if enforcement starts within 14 days) | high | Same; chase enrollment or suspend unused accounts |
| `2sv-enforced` | 2SV not enforced at the root OU | high | Same → Enforcement |
| `2sv-methods` | Any 2SV method allowed (SMS / voice) | medium | Same → Methods: "Only security key" for an admins OU or group |
| `super-admin-count` | Fewer than 2 or more than 4 super admins | medium | Account → Admin roles |
| `super-admin-recovery` | Super admins can self-recover | medium | Security → Authentication → Account recovery |
| `password-policy` | Minimum length < 12, not enforced at sign-in, reuse allowed | low | Security → Authentication → Password management |
| `dormant-users` | Active accounts with no sign-in for 90+ days | medium | Directory → Users: suspend, archive or convert to a group |
| `session-length` | Web session longer than 14 days | low | Security → Access and data control → Google session control |
| `third-party-apps-policy` | Unconfigured third-party apps allowed | high | Security → API controls → Manage third-party app access → Settings |
| `risky-apps` | Non-Google apps with full Gmail, full Drive or admin scopes (high), other sensitive scopes (medium) | high / medium | Same → App access control: Trusted / Limited / Blocked |
| `dwd-changes` | Domain-wide delegation granted in the audit window | medium | Security → API controls → Manage domain-wide delegation |
| `suspicious-logins` | Suspicious sign-ins, hijack / leaked-password disables, blocked risky actions | high | Reporting → Audit → Login; Security → Alert center |
| `login-regions` | Accounts signing in from 3+ countries (2+ for super admins; high if an admin) | medium / high | Verify with the user |
| `admin-changes` | Role assignments and authentication / app-access changes | info | Reporting → Audit → Admin |
| `drive-public-files` | Company-owned files open to anyone with the link (high at 500+) | medium | Apps → Drive and Docs → Sharing settings; owners fix files |
| `drive-external-grants` | Files shared with outside accounts or domains | medium | Same: warn when sharing outside, allowlist domains |
| `shared-drive-settings` | Shared drive defaults allow non-member or outside access | low | Same → Shared drive creation |
| `drive-desktop` | Drive for desktop on any computer | low | Apps → Drive and Docs → Features and applications (needs advanced endpoint management to restrict) |
| `calendar-external` | Calendars shareable outside with edit / manage rights | medium | Apps → Calendar → Sharing settings |
| `chat-external` | External Chat spaces open to all domains | low | Apps → Google Chat → External Chat settings |
| `groups-external` | Groups can add outside members, accept public mail or be public | low | Apps → Google Groups for Business → Sharing settings |
| `takeout` | Users can export their data with Takeout | low | Apps → Additional Google services → Takeout |
| `gmail-spoofing` | Spoofing / authentication protections off (medium) or warning only (low) | medium / low | Apps → Gmail → Safety → Spoofing and authentication |
| `gmail-attachments` | Attachment protections off or warning only | low | Apps → Gmail → Safety → Attachments |
| `mail-dns` | Missing SPF or DMARC, or `+all` (high); DMARC `p=none` or no `rua=` (medium); no MTA-STS / TLS-RPT (low) | high / medium / low | Your DNS provider; Apps → Gmail → Authenticate email for DKIM |
| `mobile-devices` | Stale (90+ days), unlocked or compromised (high) devices | low / high | Devices → Mobile and endpoints |
| `chrome-browsers` | No Chrome browsers enrolled | info | Devices → Chrome → Managed browsers (free) |

## Not checked by the tools

These need the Admin console or extra scopes the kit deliberately doesn't take. List them in the report so the admin can tick them off:

- DKIM signing turned on for every domain (Apps → Gmail → Authenticate email)
- Alert Center: rules on and sent to a monitored mailbox
- Super admins: recovery phone / email current, enrolled in Advanced Protection, not used for daily work
- App access control: list of Trusted apps still needed
- Login challenges (employee ID) and less-secure-app access
- Third-party email forwarding and auto-forwarding rules
- Offboarding: data transfer before deleting users
