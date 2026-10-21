# Data handling

A snapshot contains **no keys, tokens or passwords**, but it is still sensitive:

| File | Contains | Treat as |
|---|---|---|
| `drive_link_shared_full.csv`, `drive_external_shares.csv` | **Working URLs** to files anyone with the link can open | Credentials. Never upload or paste them. |
| `mobile.csv` | IMEI, serial number and Wi-Fi MAC per device | Personal data |
| `users.csv`, `*_audit.csv` | Names, emails, sign-in IPs and countries, apps used | Personal data |
| `findings.json`, `gap-report.md`, `diff.md` | Your security weaknesses, with emails as evidence | Confidential |

Rules:

- Keep snapshots **outside git and outside synced folders**. The default is `~/gws-audit-snapshots`; change it with `GWS_AUDIT_OUT`. The repo's `.gitignore` also excludes CSVs and credential files, as a backstop.
- Share the gap report only with the people fixing it.
- When you use an AI assistant to analyze a snapshot, prefer one that runs locally against the files (such as Claude Code with the bundled skill) over pasting CSVs into a chat. The skill reads counts and findings and never pastes file URLs.
- Delete old snapshots once their findings are tracked elsewhere. Keep the last one or two for diffs.
