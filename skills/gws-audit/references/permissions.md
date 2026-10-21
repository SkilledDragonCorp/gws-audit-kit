# Claude Code permission allowlist

Put this in your **user** settings (`~/.claude/settings.json`) or in this repo's `.claude/settings.local.json` (git-ignored). Read-only GAM verbs then run without a prompt; every other GAM command (create, update, delete, oauth create…) still asks for approval.

The admin token is read-only regardless, so this is a second layer: it also keeps an assistant from running a write command if you ever authorize a broader token by mistake.

```json
{
  "permissions": {
    "allow": [
      "Bash(gam version)",
      "Bash(gam oauth info)",
      "Bash(gam print:*)",
      "Bash(gam show:*)",
      "Bash(gam report:*)",
      "Bash(gam info:*)",
      "Bash(python -I *tools/analyze.py*)",
      "Bash(python -I *tools/diff.py*)"
    ],
    "deny": [
      "Bash(gam * todrive*)",
      "Read(~/.gam/oauth2.txt)",
      "Read(~/.gam/oauth2service.json)",
      "Read(~/.gam/client_secrets.json)",
      "Read(~/.gam/gcloud/**)"
    ]
  }
}
```

Notes:

- If GAM isn't on your `PATH`, repeat the `gam` rules with the full path you call it by, for example `Bash(/c/GAM7/gam.exe print:*)` in Git Bash on Windows.
- If your GAM config folder isn't `~/.gam`, adjust the `Read` deny rules.
- `bash tools/pull.sh` and `tools/drive_inventory.py` are deliberately **not** auto-approved: they make many API calls, so approving each run is a useful checkpoint. Add them if you prefer.
- `gam print … todrive` would upload output to Google Drive. The read-only token can't do that anyway, and the deny rule blocks it as a backstop. Check that your Claude Code version supports `*` in the middle of a rule; if not, rely on the skill's ground rules and the read-only token.
