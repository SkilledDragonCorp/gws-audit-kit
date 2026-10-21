# Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Can't find the OAuth client secret | Google shows a new secret only once. Open the client → **Add secret**, then delete the old one. |
| Pasted the project ID instead of the client ID | Ctrl+C, then `gam use project gam-project-xxxxx` |
| `constraints/iam.disableServiceAccountKeyUpload violated` | Expected. Use the keyless setup ([setup step 6](setup.md#6-keyless-service-account-for-the-drive-inventory)); don't turn the policy off. |
| `pull.sh` says "Refusing to run: … scopes that are not read-only" | The admin token has a write scope. Delete `oauth2.txt` and redo [setup step 4](setup.md#4-authorize-gam-with-read-only-scopes). |
| `Drive API v3 Service/App not enabled` from `gam user … print filelist` | GAM asks for full Drive or `drive.readonly`, which you didn't delegate on purpose. Use `tools/drive_inventory.py`. |
| `drive_inventory.py`: `gcloud could not print a token` | The isolated login is missing or expired. Redo [setup step 6C](setup.md#6-keyless-service-account-for-the-drive-inventory). Check `GWS_GCLOUD_CONFIG` points at the same folder. |
| `drive_inventory.py`: HTTP 403 on `signJwt` | Your account lacks `roles/iam.serviceAccountTokenCreator` on the service account (6A), or the IAM Credentials API is off (6B). |
| `drive_inventory.py`: HTTP 401 `unauthorized_client` on the token exchange | Domain-wide delegation is missing, or the scope doesn't match exactly (step 7). Changes can take a few minutes to apply. |
| `drive_inventory.py`: HTTP 500 for one user | Transient Google error (the script already retries). Re-run just that user: `python -I tools/drive_inventory.py users.csv . --only user@example.com`. It writes `*_partial.csv` files. |
| `gam … check serviceaccount` runs for minutes | Add `scope https://www.googleapis.com/auth/drive.metadata.readonly` to test only the delegated scope. |
| Warning about "end user credentials … without a quota project" | Harmless. |
| Admin console says more users lack 2SV than `users.csv` does | Console security reports lag 1–3 days. GAM output is live. |
| A user added a passkey but still shows no 2SV | Passkeys count only after the user turns on 2-Step Verification. |
| `python3` does nothing on Windows | That's the Microsoft Store stub. `pull.sh` falls back to `python`; or set `PYTHON=python` in `gws-audit.env`. |
| `dns.txt` is empty | `nslookup` isn't installed. The mail DNS check is then listed under "Not checked". |
| "GAM Project Creation" still listed under configured apps | Open it → Access → **Blocked**. Don't delete it. |
| Admin console "Email setup status: MX incorrect" | Often a leftover `mx-verification.google.com` MX record from domain verification. Mail is unaffected; delete that record at your DNS provider. |
