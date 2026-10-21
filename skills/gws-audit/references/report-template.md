# Report template

Write `<snapshot>/gap-report.md` in this shape. Replace everything in `<angle brackets>`. Keep it short enough to read in ten minutes; push long lists to "see `<file>.csv`".

```markdown
# Google Workspace security gap report — <primary domain>

- **Date:** <snapshot date>
- **Edition:** <edition> (<seats> seats, if known)
- **Method:** read-only GAM pull (users, admins, policies, audit logs, devices), Drive metadata inventory, public DNS
- **Previous snapshot:** <date, or "none: first run">

Severity: 🔴 act this week · 🟠 act this month · 🟡 hardening · 🔵 review · ✅ already good

## Changes since <previous date>

- **Worse:** <new super admin, new risky app, users who lost 2SV, newly public files, loosened policies>
- **Better:** <resolved findings, tightened policies>

## Summary

| # | Finding | Sev | Effort |
|---|---|---|---|
| 1 | <one line, with the number that matters> | 🔴 | <minutes / hours / project> |

## 🔴 1. <Finding title>

<Two or three sentences: what is true, why it matters for this tenant.>

- <evidence: accounts to act on, or counts per owner; never file URLs>

**Fix:** <Admin console path and the setting to choose.>
**Edition note:** <only when the edition limits the fix; give the closest alternative.>
**Watch out:** <lockout or user-impact risk, if any.>

## ✅ Already good

- <passed checks>

## Not checked by the tools

- [ ] <manual items from checks.md>

## Rollout order

1. <first, usually 2SV for admins and enrollment chasing>
2. <…>
```

A filled-in example built from fake data is in [`examples/sample-gap-report.md`](../../../examples/sample-gap-report.md). It's the raw `analyze.py` draft; the skill's version adds the changes section, effort, edition alternatives and rollout order.
