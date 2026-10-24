# gws-audit-kit

A **read-only** security audit for Google Workspace, built on [GAM7](https://github.com/GAM-team/GAM), plus a [Claude Code](https://claude.com/claude-code) skill that walks you through setup, runs the audit and writes a ranked gap report.

It's made for small and mid-size tenants (Business Starter through Enterprise) whose admins want a repeatable answer to "how exposed are we?" without buying a security product or handing a vendor write access.

What you get from one run:

- a dated snapshot of users, admins, 2SV status, org security policies, third-party app grants, sign-in and admin audit logs, mobile devices, browsers and mail DNS records
- a per-user **Drive sharing inventory** (files open to anyone with the link, grants to outside accounts) using **metadata-only** access
- `findings.json` and a ranked `gap-report.md` in the style of the CIS Google Workspace Foundations Benchmark and Google's small-business security checklist, with **edition-aware notes** (what Business Starter can't do, for example)
- `diff.md` against the previous snapshot: new admins, new risky apps, 2SV regressions, newly public files, changed policies

- optionally, `report.html`: a **visual report** (severity tiles, chart by area, finding cards, changes since last time). It's a self-contained page that opens in your browser and never uploads anything. The Claude Code skill offers it when the gap report is done.

See a [sample report](examples/sample-gap-report.md), [sample diff](examples/sample-diff.md) and [sample visual report](examples/sample-report.html) (download and open it). All use fake data only.

## Threat model: why read-only

An audit tool is a juicy target: whoever steals its credentials gets whatever the tool can do. This kit is built so a stolen credential **can't change anything**.

| Layer | Control |
|---|---|
| Admin token | GAM is authorized with **only `.readonly` scopes**. `pull.sh` checks `gam oauth info` and refuses to run if any scope can write. |
| Service account | **No key exists.** The org policy `iam.disableServiceAccountKeyUpload` stays on; signing goes through IAM `signJwt` with your own login and the Token Creator role. |
| Domain-wide delegation | One scope: `drive.metadata.readonly`. File names, owners and sharing; **never file content**, never mail. |
| Signing login | An isolated gcloud config folder, separate from your everyday gcloud login. |
| OAuth client | Your own **Internal** Desktop client, so no third-party app sits in the middle. |
| Claude Code | A permission allowlist auto-approves only `gam print/show/report/info`; every other GAM verb asks first. The skill never runs write commands; setup steps that change things are run by you. |
| Output | Snapshots go outside the repo (default `~/gws-audit-snapshots`). `.gitignore` blocks CSVs and every known credential file name. |

What this does **not** protect against: someone with your super admin session can do anything regardless of this kit. Protect admin accounts with security keys or passkeys.

## Prerequisites

- A Google Workspace **super admin** account (for setup; a delegated read-only admin can run audits afterwards)
- [GAM7](https://github.com/GAM-team/GAM) by the GAM team, installed with the official guide: [How to Install GAM7](https://github.com/GAM-team/GAM/wiki/How-to-Install-GAM7) ([downloads](https://github.com/GAM-team/GAM/wiki/Downloads-Installs), [releases](https://github.com/GAM-team/GAM/releases)). This kit doesn't bundle or modify GAM.
- [Google Cloud CLI](https://cloud.google.com/sdk/docs/install) (`gcloud`), for the Drive inventory only
- Python 3.9+ (standard library only, no `pip install`)
- Bash: Git Bash on Windows, or any shell on macOS / Linux
- `nslookup` for the mail DNS check (preinstalled on most systems)

## Setup

Follow [docs/setup.md](docs/setup.md). Short version:

1. Install GAM7 and run `gam create project`; block the project-creation app afterwards.
2. Create an **Internal Desktop** OAuth client and trust it.
3. `gam oauth create` with **read-only scopes only**.
4. Keyless service account: Token Creator role, isolated gcloud login, `key_type: signjwt`.
5. Domain-wide delegation with `drive.metadata.readonly` only.

Or open this repo in Claude Code and ask: **"set up the Workspace audit"**. The `gws-audit` skill checks what's already done and walks you through the rest one step at a time. Opening the checkout loads that skill from `.claude/skills/gws-audit` (the same files as `skills/gws-audit`).

## Usage

```bash
cp gws-audit.env.example gws-audit.env   # set GAM path, edition, output folder
bash tools/pull.sh
```

A run takes about 10 minutes for 25 users, mostly the Drive inventory. It writes `~/gws-audit-snapshots/<YYYY-MM-DD>/`:

| File | Content |
|---|---|
| `users.csv`, `admins.csv`, `groups.csv`, `orgunits.csv`, `domains.csv`, `domainaliases.csv` | Directory and tenant structure |
| `policies.csv` | Org security settings (2SV, passwords, Gmail safety, Drive, Calendar, Chat, Groups, Takeout, API controls…) |
| `tokens_audit.csv`, `login_audit.csv`, `admin_audit.csv`, `drive_visibility_audit.csv` | Audit logs (180/30/180/180 days) |
| `mobile.csv`, `browsers.csv` | Devices |
| `drive_link_shared_full.csv`, `drive_external_shares.csv` | Drive sharing inventory |
| `dns.txt` | SPF, DMARC, MTA-STS and TLS-RPT records |
| `findings.json`, `gap-report.md` | Ranked findings |
| `diff.md` | Changes since the previous snapshot |
| `report.html` | Visual report, only when you ask for it: `python -I tools/render_html.py <snapshot> --previous <older_snapshot>` |

Re-run the analysis without pulling again:

```bash
python -I tools/analyze.py ~/gws-audit-snapshots/2026-02-02 --edition starter
python -I tools/diff.py ~/gws-audit-snapshots/2026-01-05 ~/gws-audit-snapshots/2026-02-02
```

### With Claude Code

This repo is a Claude Code **plugin** and its own **plugin marketplace**. Install it once and the `gws-audit` skill is available in every project:

```
/plugin marketplace add skilledDragoncorp/gws-audit-kit
/plugin install gws-audit@gws-audit-kit
```

Or from a shell:

```bash
claude plugin marketplace add skilledDragoncorp/gws-audit-kit
claude plugin install gws-audit@gws-audit-kit
```

Updates arrive with `/plugin marketplace update gws-audit-kit`. The plugin folder is replaced on update, so keep your settings in `~/.config/gws-audit/gws-audit.env` (the skill creates it with you on first run).

Trying a local clone without installing:

```bash
claude --plugin-dir /path/to/gws-audit-kit
```

Things to ask:

- "Set up the Workspace audit"
- "Run the Workspace audit and write the gap report"
- "What changed since the last audit?"

While the skill is active, read-only GAM verbs (`print`, `show`, `report`, `info`) run without a prompt; everything else asks. For the same rule outside the skill, add the [permission allowlist](skills/gws-audit/references/permissions.md).

**claude.ai and the Claude desktop chat aren't supported.** The audit runs GAM and Python on your own machine, which chat skills can't do, and it would mean uploading tenant data. Use Claude Code (terminal, desktop app Code tab, or IDE extension).

## What's checked

| Area | Checks |
|---|---|
| Identity | super admins without 2SV, users without 2SV and the enforcement date, 2SV enforcement and allowed methods, super admin count and self-recovery, password policy, dormant accounts, session length |
| Apps | unconfigured third-party app policy, apps with full Gmail / Drive / admin scopes, domain-wide delegation grants |
| Sign-ins | suspicious sign-ins and blocked risky actions, accounts signing in from several countries |
| Admin activity | role assignments and authentication / app-access setting changes |
| Drive | files open to anyone with the link, grants to outside domains, shared drive defaults, Drive for desktop |
| Collaboration | external calendar sharing, external Chat spaces, Groups external access, Takeout |
| Gmail | spoofing and attachment protections, SPF / DMARC / MTA-STS / TLS-RPT |
| Devices | stale, unlocked or compromised mobile devices; Chrome browser enrollment |

The full catalog with edition notes is in [checks.md](skills/gws-audit/references/checks.md).

## Roadmap

1. **Now:** manual runs + Claude Code analysis.
2. **Next:** a scheduled collector (cron / Task Scheduler) that writes dated snapshots and the diff, with alerts on regressions.
3. **Later:** a cloud collector with workload identity (no user login, no keys), automated analysis, and a read-only report viewer that holds no Google credentials. Google's Alert Center stays the real-time channel.

## Contributing

Issues and pull requests are welcome. Keep the kit read-only, and never add real tenant data. See [CONTRIBUTING.md](CONTRIBUTING.md) for running the tests, testing the plugin and releasing.

## Credits

This kit stands on other people's work:

- **[GAM](https://github.com/GAM-team/GAM)** by the GAM team (Apache-2.0). It does the heavy lifting: every admin query in `pull.sh` is a GAM command. Their [wiki](https://github.com/GAM-team/GAM/wiki) is the reference for installing, [authorizing](https://github.com/GAM-team/GAM/wiki/Authorization) and every command used here. If GAM saves you time, star the repo and consider supporting the project.
- **[CIS Google Workspace Benchmarks](https://www.cisecurity.org/benchmark/google_workspace)** by the Center for Internet Security, the basis for the check categories. The benchmark text isn't reproduced here; download it from CIS for the full controls.
- **[Security checklist for small businesses (1-100 users)](https://support.google.com/a/answer/9211704)** by Google, the basis for the small-business recommendations.
- **[Google Cloud CLI](https://cloud.google.com/sdk/docs/install)**, used only for the keyless signing login.

## License

[MIT](LICENSE) for this kit's own code and docs. GAM and the other tools above keep their own licenses.

Not affiliated with or endorsed by Google, the GAM team, CIS or Anthropic.
