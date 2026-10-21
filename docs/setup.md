# Setup

One-time setup for a **read-only** audit. Plan for 45–60 minutes. You need a **super admin** account.

Throughout this guide:

| Placeholder | Meaning |
|---|---|
| `admin@example.com` | Your super admin account |
| `gam-project-xxxxx` | The GCP project `gam create project` makes for you |
| `gam-project-xxxxx@gam-project-xxxxx.iam.gserviceaccount.com` | That project's service account |
| `<SA_UNIQUE_ID>` | The service account's numeric unique ID (the "client ID" for domain-wide delegation) |
| `<GAMCFGDIR>` | GAM's config folder: `~/.gam` on macOS/Linux, `C:\Users\<you>\.gam` on Windows |

Steps 1–5 give GAM a read-only admin token. Steps 6–7 add the optional per-user Drive inventory.

---

## 1. Install GAM7

GAM is maintained by the GAM team at [github.com/GAM-team/GAM](https://github.com/GAM-team/GAM). Follow their guide, **[How to Install GAM7](https://github.com/GAM-team/GAM/wiki/How-to-Install-GAM7)**, which is always current; the notes below only add what this kit needs.

- Get the installer from [Downloads-Installs](https://github.com/GAM-team/GAM/wiki/Downloads-Installs) or the [releases page](https://github.com/GAM-team/GAM/releases), and verify the checksum if one is listed.
- **Windows:** install the `.msi` (for example to `C:\GAM7`). Run the kit from **Git Bash**.
- **macOS / Linux:** use the install script from the guide.
- When the installer offers to set up authorization, you can stop and continue with step 2 here: steps 2–4 follow GAM's [Authorization](https://github.com/GAM-team/GAM/wiki/Authorization) page, narrowed to read-only scopes.

GAM keeps its config and tokens in `<GAMCFGDIR>`. Keep that folder **out of** synced folders such as OneDrive or Dropbox.

```bash
gam version
```

If `gam` isn't on your `PATH`, copy `gws-audit.env.example` to `gws-audit.env` and set `GAM=` to its full path (Git Bash example: `/c/GAM7/gam.exe`).

## 2. Create the GCP project

```bash
gam create project
```

1. GAM asks you to trust its **"GAM Project Creation"** app. In the Admin console go to **Security → Access and data control → API controls → Manage third-party app access → Configure new app**, find it, and set it to **Trusted** for your admin's org unit.
   - "Specific Google data" fails because that app has requested more than 50 scopes over time; use Trusted.
2. Press Enter in the terminal and approve the browser consent. GAM creates the project and enables about 40 APIs. Enabling an API grants no access by itself.
3. **Afterwards, set "GAM Project Creation" to Blocked.** Don't just delete its configuration: deleting returns it to your org default for unconfigured apps, which may allow it. Also remove it at myaccount.google.com → Security → Third-party apps.

> GAM will also try to upload a service account key and fail with `constraints/iam.disableServiceAccountKeyUpload violated`. That's Google's secure-by-default org policy. **Keep it on.** This kit uses a keyless service account (step 6).

## 3. Create GAM's OAuth client

In the Google Cloud console, check the project selector shows **gam-project-xxxxx**, then open **Google Auth Platform**:

1. **Get started:** App name `GAM`, support email = your admin. **Audience: Internal.** Contact email = your admin. Create.
2. **Clients → Create client:** type **Desktop app**, name `GAM`. Create.
3. **Copy the client ID and client secret from the dialog right away.** Google only shows a new secret once. If you missed it: open the client → **Add secret**, copy it, then disable and delete the old one.
4. Paste both at GAM's prompts. Paste the **client ID**, not the project ID. If you made a mistake: `gam use project gam-project-xxxxx`.
5. Trust your own client: Admin console → API controls → Manage third-party app access → Configure new app → search the client ID → **Trusted** for the admin's org unit.

## 4. Authorize GAM with read-only scopes

```bash
gam oauth create
```

1. Enter your admin email.
2. Type `u` to unselect everything.
3. Select **only** these scopes, adding `r` to make each one read-only where the menu offers it (for example `7r`). Menu numbers change between GAM versions, so match by name:

   | Scope | Why |
   |---|---|
   | Directory API: Customers | tenant info |
   | Directory API: Domains | domains and aliases |
   | Directory API: Groups | groups |
   | Directory API: Mobile Devices | mobile inventory |
   | Directory API: Organizational Units | OUs |
   | Directory API: Roles | admin role assignments |
   | Directory API: Users | users, 2SV status, last sign-in |
   | Directory API: User Schemas | custom user fields |
   | Chrome Browser Cloud Management | enrolled browsers |
   | Chrome Management API: reports / policy | browser reports |
   | Cloud Identity: Policies | org security settings (`gam print policies`) |
   | Cloud Identity: Inbound SSO / Allowlisted domains | SSO and allowlists |
   | Reports API: Audit Reports | login, admin, token and Drive audit logs |
   | Reports API: Usage Reports | usage reports |

   **Leave unselected** anything with no read-only version, for example User Security (tokens/ASPs), Groups Settings, Alert Center, Data Transfer, License Manager, Vault, Classroom and Cloud Storage.
4. Press `c`. In the browser, **every consent line must read "See…" or "View…"**. If any line says "Manage", "Edit" or "Delete", cancel and start again.
5. Verify:

   ```bash
   gam oauth info
   ```

   Every scope must end in `.readonly`, apart from `openid`, `email`, `profile` and `userinfo.*`. `tools/pull.sh` checks this and refuses to run otherwise. A known-good result:

   ```
   admin.directory.customer.readonly         admin.directory.device.chromebrowsers.readonly
   admin.directory.device.mobile.readonly    admin.directory.domain.readonly
   admin.directory.group.readonly            admin.directory.orgunit.readonly
   admin.directory.rolemanagement.readonly   admin.directory.user.readonly
   admin.directory.userschema.readonly       admin.reports.audit.readonly
   admin.reports.usage.readonly              chrome.management.policy.readonly
   chrome.management.reports.readonly        cloud-identity.allowlisteddomains.readonly
   cloud-identity.inboundsso.readonly        cloud-identity.policies.readonly
   + openid, email, profile
   ```

## 5. Claude Code guardrail (optional, recommended)

If you drive the audit with Claude Code, add the read-only allowlist from [`skills/gws-audit/references/permissions.md`](../skills/gws-audit/references/permissions.md). Read-only GAM verbs then run without a prompt and everything else asks first. The token is read-only anyway; this is a second layer.

---

## 6. Keyless service account (for the Drive inventory)

GAM's own Drive commands need full Drive or `drive.readonly`, and both expose file **contents**. `tools/drive_inventory.py` uses only `drive.metadata.readonly` (names, owners, sharing; never content). It signs as the service account through the IAM Credentials API, so **no private key exists anywhere**.

**A. Let your admin account sign as the service account.** Repeat for each operator.

```bash
gcloud iam service-accounts add-iam-policy-binding \
  gam-project-xxxxx@gam-project-xxxxx.iam.gserviceaccount.com \
  --member="user:admin@example.com" \
  --role="roles/iam.serviceAccountTokenCreator" \
  --project=gam-project-xxxxx
```

**B. IAM Credentials API.** `gam create project` already enables it. If not:

```bash
gcloud services enable iamcredentials.googleapis.com --project=gam-project-xxxxx
```

**C. Isolated gcloud login, used only for signing.** A separate config folder keeps your normal gcloud login (used for other projects) untouched.

Git Bash / macOS / Linux:

```bash
CLOUDSDK_CONFIG="$HOME/.gam/gcloud" gcloud auth application-default login
```

Windows cmd:

```bat
set CLOUDSDK_CONFIG=%USERPROFILE%\.gam\gcloud
gcloud auth application-default login
```

Sign in as your admin. On the consent screen tick **only** "See, edit, configure, and delete your Google Cloud data". That scope is what IAM `signJwt` needs; the Token Creator role on one service account limits what it can do.

**D. Switch GAM's service account to keyless.** In `<GAMCFGDIR>/oauth2service.json` set `"key_type": "signjwt"` and leave `private_key` and `private_key_id` empty. GAM then signs via IAM too, using `GOOGLE_APPLICATION_CREDENTIALS` (which `pull.sh` points at the isolated login).

## 7. Domain-wide delegation: Drive metadata only

1. Find the service account's **unique ID** (a long number) in Cloud console → IAM → Service accounts, or in `oauth2service.json` as `client_id`.
2. Admin console → **Security → Access and data control → API controls → Manage domain-wide delegation** → **Add new**:
   - Client ID: `<SA_UNIQUE_ID>`
   - OAuth scopes: `https://www.googleapis.com/auth/drive.metadata.readonly`
   - Leave "Overwrite existing client ID" unchecked.
3. Verify (Git Bash shown):

   ```bash
   GOOGLE_APPLICATION_CREDENTIALS="$HOME/.gam/gcloud/application_default_credentials.json" \
     gam user admin@example.com check serviceaccount scope https://www.googleapis.com/auth/drive.metadata.readonly
   ```

   Expect `Authentication PASS` and `drive.metadata.readonly PASS`. Always pass `scope …`: without it GAM tests every possible scope, which takes minutes and is noisy.

---

## 8. First run

With the Claude Code plugin installed, ask Claude to "run the Workspace audit"; it creates the settings file with you. From a clone:

```bash
mkdir -p ~/.config/gws-audit
cp gws-audit.env.example ~/.config/gws-audit/gws-audit.env   # then edit GAM, GWS_EDITION, GWS_AUDIT_OUT
bash tools/pull.sh
```

See the [README](../README.md#usage) for what it produces, and [troubleshooting](troubleshooting.md) if anything fails.

## Adding another operator

1. Give them a Workspace admin role: a second super admin, or a custom role with read access to users, groups, OUs, reports, mobile and Chrome. Require security keys or passkeys for them.
2. Give them access to the GCP project if they need to manage it.
3. They install GAM, receive `client_secrets.json` from you **over a secure channel**, and run step 4 **signing in as themselves**, so they get their own token.
4. For the Drive inventory: repeat 6A, 6C and 6D with their account.

Never share `oauth2.txt`, `application_default_credentials.json` or a login. Separate authorizations keep the audit logs honest about who did what.

## Tear down

| To remove | How |
|---|---|
| Per-user Drive access | Admin console → Domain-wide delegation → delete the client (takes effect immediately) |
| An operator's signing ability | Remove `roles/iam.serviceAccountTokenCreator` for that user on the service account |
| Admin token | Delete `<GAMCFGDIR>/oauth2.txt`, and/or remove "GAM" at myaccount.google.com → Third-party apps |
| GAM entirely | Admin console → API controls → set the GAM client to Blocked |
| Everything | Shut down the GCP project, then delete `<GAMCFGDIR>` |
