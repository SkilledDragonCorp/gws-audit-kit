# Changes since 2026-01-05

Comparing snapshot 2026-01-05 → 2026-02-02.

## Findings

**New:**
  - high: 1 suspicious sign-in or blocked risky-action event(s)
  - medium: 1 domain-wide delegation grant(s) in the audit window
**Resolved:**
  - medium: Super admins can recover their own accounts
  - medium: Calendars can be shared outside with edit or manage rights
  - info: No Chrome browsers are enrolled for management
**Changed:**
  - 2 security-relevant admin change(s) in the audit window: info (1) → info (2)
  - 2 third-party app(s) hold high-risk scopes: high (1) → high (2)
  - 3 active user(s) not enrolled in 2SV: high (4) → critical (3)
  - 3 company-owned file(s) open to anyone with the link: medium (2) → medium (3)
  - 3 sharing grant(s) to 3 outside domain(s): medium (2) → medium (3)
  - Mail authentication DNS records are incomplete: medium (4) → low (2)

## Entities

**Super admins:** 2 → 3
- added:
  - gray@example.com
**Users without 2SV:** 4 → 3
- gone:
  - blake@example.com
**Third-party apps with high-risk scopes:** 1 → 2
- new:
  - Sample PDF Toolkit
**Outside domains with Drive grants:** 2 → 3
- new:
  - example.net
**Mail DNS problems:** 4 → 2
- gone:
  - example.com: DMARC has no rua= reporting address
  - example.com: DMARC p=none (monitoring only)
**Company files open to anyone with the link:** 2 → 3 (1 new, 0 closed or deleted)
  - Draft budget 2026

## Policy changes

- calendar.primary_calendar_max_allowed_external_sharing@ou:/: maxAllowedExternalSharing EXTERNAL_ALL_INFO_READ_WRITE_MANAGE → EXTERNAL_FREE_BUSY_ONLY
- security.super_admin_account_recovery@ou:/: enableAccountRecovery True → False

