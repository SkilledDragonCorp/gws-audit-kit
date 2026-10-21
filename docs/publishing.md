# Publishing (maintainers)

The repo is both a Claude Code plugin (`.claude-plugin/plugin.json`, skill in `skills/gws-audit/`) and a single-plugin marketplace (`.claude-plugin/marketplace.json`, `"source": "./"`). Pushing to GitHub is all it takes for people to install it; the official directory listing is optional.

## Before every release

```bash
python -m unittest discover -s tests       # tools still work on the fake fixtures
claude plugin validate .                   # marketplace manifest
claude plugin validate .claude-plugin/plugin.json
claude plugin validate . --strict          # newer CLIs: also fails on warnings
```

Then load it for real in a session and ask "set up the Workspace audit":

```bash
claude --plugin-dir .
```

Check that the skill shows as `/gws-audit:gws-audit`, and that the paths it prints under `${CLAUDE_PLUGIN_ROOT}/tools/` exist.

Bump `version` in `.claude-plugin/plugin.json` for every release. Installed copies don't update while the version stays the same.

## Make it installable (GitHub)

1. Create the public repo `skilledDragoncorp/gws-audit-kit` and push `main`.
2. Users install with:

   ```
   /plugin marketplace add skilledDragoncorp/gws-audit-kit
   /plugin install gws-audit@gws-audit-kit
   ```

3. Tag releases (`v0.1.0`) to match `version`, so people can see what changed.

## Submit to the Claude plugin directory (optional)

1. Run `claude plugin validate . --strict` with a current Claude Code and fix every warning.
2. Re-read the README: no Google logos, and keep the "Not affiliated with Google or the GAM project" line.
3. Submit at **claude.ai/directory/manage** (needs a paid claude.ai plan; on Team/Enterprise an Owner submits). The portal runs extra checks and a review, so a clean local validation doesn't guarantee acceptance.

The `claude-plugins-official` marketplace doesn't take portal submissions.

## Spread the word

- Add the GitHub topics `claude-code-plugin`, `claude-skills`, `google-workspace`, `gam`, `security-audit`.
- Link the sample report in the announcement; it's the fastest way to show what the kit does.
- Community lists of Claude Code plugins and skills accept pull requests; add a one-line entry pointing at the repo.
