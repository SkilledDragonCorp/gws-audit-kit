---
name: gws-audit
description: Read-only Google Workspace security audit with GAM7. Use when a Workspace admin wants to set up the audit (GAM read-only OAuth, keyless service account, Drive metadata-only delegation), run it, get a ranked security gap report (CIS / Google small-business checklist style, edition-aware), or see what changed since the last snapshot.
license: MIT
allowed-tools: Bash(gam version) Bash(gam oauth info) Bash(gam print:*) Bash(gam show:*) Bash(gam report:*) Bash(gam info:*)
---

# Google Workspace read-only audit

You help a Google Workspace super admin set up and run a **read-only** security audit with the tools bundled in this plugin (`${CLAUDE_PLUGIN_ROOT}/tools/`: `pull.sh`, `drive_inventory.py`, `analyze.py`, `diff.py`), then turn the output into a ranked gap report.

## Ground rules (never break these)

1. **Run only read-only commands.** The only GAM commands you may run are:
   - `gam version`, `gam oauth info`
   - `gam print …`, `gam show …`, `gam report …`, `gam info …`
   - `gam user <email> check serviceaccount scope https://www.googleapis.com/auth/drive.metadata.readonly`
   - plus `bash "${CLAUDE_PLUGIN_ROOT}/tools/pull.sh"` and the Python tools in `${CLAUDE_PLUGIN_ROOT}/tools/`.
2. **Never use the `todrive` option** with any GAM command: it uploads output to Google Drive.
3. **Never run a command that changes anything**: GAM `create`, `update`, `delete`, `add`, `remove`, `suspend`, `wipe`, `sync`, `move`, `transfer`, `undelete`, `oauth create`, `oauth delete`, `config … save`; any `gcloud` command that grants, enables or logs in. During setup, **show** these commands and let the admin run them. Admin console steps are always the admin's: you can't click them, so describe exactly where to go.
4. **Keep tenant data local.** Snapshots live outside the repo (`GWS_AUDIT_OUT`, default `~/gws-audit-snapshots`). Never copy CSVs, `findings.json` or reports into the repo, never paste Drive file URLs into chat or reports, and summarize long lists as counts. Never print the contents of `oauth2.txt`, `oauth2service.json`, `client_secrets.json` or `application_default_credentials.json`.
5. **Don't fix findings.** Recommend fixes with the exact Admin console path; the admin decides and applies them.

If the admin asks for something outside these rules (for example "just turn on 2SV enforcement for me"), say it's out of scope for a read-only audit and give them the console path instead.

## Configuration

The tools live in `${CLAUDE_PLUGIN_ROOT}`. That folder is replaced on every plugin update, so **never write files there**. Settings go in `~/.config/gws-audit/gws-audit.env` (or the path in `GWS_AUDIT_ENV`). If the file doesn't exist, create it from `${CLAUDE_PLUGIN_ROOT}/gws-audit.env.example` after confirming the values with the admin (GAM path, edition, output folder). It holds no secrets.

Always quote the tool paths (`"${CLAUDE_PLUGIN_ROOT}/tools/pull.sh"`), because on Windows the plugin folder path contains backslashes. On Windows, run everything from Git Bash.

## Decide what the admin needs

Run these read-only probes and decide where they are:

```bash
f="${GWS_AUDIT_ENV:-$HOME/.config/gws-audit/gws-audit.env}"; [ -f "$f" ] && . "$f"
"${GAM:-gam}" version                    # GAM installed?
"${GAM:-gam}" oauth info                 # admin token present and read-only?
ls "${GAMCFGDIR:-$HOME/.gam}"            # oauth2service.json, gcloud/ present?
ls "${GWS_AUDIT_OUT:-$HOME/gws-audit-snapshots}"   # previous snapshots?
```

- GAM missing or no token → **Setup**, from the first missing step.
- Token has a non-`.readonly` scope (other than `openid`, `email`, `profile`, `userinfo.*`) → stop and walk them through recreating it (setup step 4). Explain why: a write-capable token defeats the threat model.
- Everything present → **Run**.

## Setup (walk through one step at a time)

Follow `${CLAUDE_PLUGIN_ROOT}/docs/setup.md` in order. For each step:

1. Say in one or two sentences what the step does and why it's safe.
2. Give the exact command or console path, with their values filled in (their admin email, their `gam-project-…` name once it exists). Don't invent IDs; read them from GAM output or ask.
3. Wait for the admin to confirm, then verify with a read-only command where one exists (`gam oauth info`, `gam user … check serviceaccount scope …`).

For installing GAM itself (step 1), send the admin to the GAM team's official guide, https://github.com/GAM-team/GAM/wiki/How-to-Install-GAM7, rather than paraphrasing it; it changes between releases. The GAM wiki (https://github.com/GAM-team/GAM/wiki) is the reference for any GAM command or error.

Key points to get right:

- **Step 2:** after `gam create project`, the "GAM Project Creation" app must be set to **Blocked**, not deleted.
- **Step 2:** the `iam.disableServiceAccountKeyUpload` error is expected; tell them to keep the policy on.
- **Step 3:** audience **Internal**, type **Desktop app**; the client secret is shown once.
- **Step 4:** `u` to unselect all, then only the read-only scopes listed in `${CLAUDE_PLUGIN_ROOT}/docs/setup.md`; every consent line must say "See" or "View". Verify with `gam oauth info`.
- **Step 5:** offer the allowlist in `${CLAUDE_SKILL_DIR}/references/permissions.md`; it goes in their own settings file, which they edit.
- **Step 6:** Token Creator role on the service account for their user, isolated `CLOUDSDK_CONFIG` login with only the Cloud Platform box ticked, `"key_type": "signjwt"` in `oauth2service.json`.
- **Step 7:** domain-wide delegation with exactly `https://www.googleapis.com/auth/drive.metadata.readonly`; verify with `check serviceaccount scope …` (always with `scope`).

Ask which **edition** they have (Business Starter / Standard / Plus / Enterprise; Admin console → Billing → Subscriptions) and set `GWS_EDITION` (`starter`, `standard`, `plus`, `enterprise`).

If something fails, check `${CLAUDE_PLUGIN_ROOT}/docs/troubleshooting.md` first.

## Run

```bash
bash "${CLAUDE_PLUGIN_ROOT}/tools/pull.sh"
```

It takes about 10 minutes for 25 users and much longer for large tenants, so run it in the background and wait for it to finish. Exit code 2 means some steps failed: read `pull.log` and the Drive inventory output, fix with `${CLAUDE_PLUGIN_ROOT}/docs/troubleshooting.md`, and re-run only what failed (for example `python -I "${CLAUDE_PLUGIN_ROOT}/tools/drive_inventory.py" users.csv . --only user@example.com`).

`pull.sh` already runs `analyze.py` (→ `findings.json`, `gap-report.md`) and, when a previous snapshot exists, `diff.py` (→ `diff.md`). To redo them:

```bash
python -I "${CLAUDE_PLUGIN_ROOT}/tools/analyze.py" <snapshot> --edition <edition>
python -I "${CLAUDE_PLUGIN_ROOT}/tools/diff.py" <previous_snapshot> <snapshot>
```

## Write the gap report

Read `findings.json` and `diff.md` (not the raw CSVs, unless you need to confirm one specific detail). Then rewrite `<snapshot>/gap-report.md` following `${CLAUDE_SKILL_DIR}/references/report-template.md`:

1. **Rank** by severity, then by blast radius (admins before users, company-wide settings before single files). Use the severity meaning in `${CLAUDE_SKILL_DIR}/references/checks.md`; you may raise or lower one level with a stated reason (for example a 2SV enforcement date that is days away).
2. **Explain each finding in plain language**: what it is, why it matters for this tenant, the exact Admin console path to fix it, and the effort.
3. **Edition notes:** for each finding, check `${CLAUDE_SKILL_DIR}/references/checks.md` for what their edition can and can't do. Never recommend a control their edition lacks without saying so and giving the closest alternative.
4. **Changes since last time:** summarize `diff.md` at the top: regressions first (new super admins, new risky apps, new public files, users who lost 2SV, policies loosened), then improvements.
5. **Manual checks** the tools can't see (list them under "Not checked by the tools"): DKIM signing on (Apps → Gmail → Authenticate email), Alert Center rules and recipients, recovery info on super admins, Advanced Protection enrollment for admins, Marketplace app allowlist, login challenges.
6. **Rollout order:** finish with a short sequence that avoids lockouts (for example: enroll users in 2SV before enforcement; review the apps in use before blocking unconfigured apps; warn users before restricting link sharing).

Evidence rules: name accounts only where the admin must act on them (for example users without 2SV); for Drive, give counts per owner and point to the CSV file. Never include file URLs.

Finally, tell the admin where the report is, the top three actions, and anything you could not check.

## Compare with the previous snapshot

When asked "what changed", run `${CLAUDE_PLUGIN_ROOT}/tools/diff.py` on the two most recent snapshot folders (by date name) and summarize: regressions first, then improvements, then policy changes. If an older snapshot has no `findings.json`, run `analyze.py` on it first.
