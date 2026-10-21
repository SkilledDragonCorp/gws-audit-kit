# Contributing

Issues and pull requests are welcome.

## Ground rules

- **Read-only, always.** New checks must work from the existing read-only scopes. If one truly needs another scope, it must be a **read-only** scope, and the PR must say which one and why.
- **No real tenant data.** Everything under `tests/fixtures/` and `examples/` is synthetic and uses `example.com` (RFC 2606). Never commit a real snapshot, email, file URL or device ID, not even in an issue.
- **Standard library only** for the Python tools, so nobody has to `pip install` anything to audit their tenant.

## Development

```bash
python -I tests/make_fixtures.py          # regenerate the fake snapshots
python -m unittest discover -s tests      # run the tests
```

When you add a check:

1. Add a `check_*` function to `tools/analyze.py` and register it in `CHECKS`.
2. Add fake data for it in `tests/make_fixtures.py` and a test in `tests/test_tools.py`.
3. Document it in [`skills/gws-audit/references/checks.md`](skills/gws-audit/references/checks.md), with an edition note if some editions can't fix it.
4. Regenerate the examples: run `analyze.py`, `diff.py` and `render_html.py --previous` on copies of the two fixture folders and copy the results to `examples/`.

The visual report (`tools/render_html.py`) must stay self-contained: no external scripts, fonts, images or network calls, because it holds tenant data and must work offline.

## Testing the Claude Code plugin

```bash
claude plugin validate .                          # marketplace manifest
claude plugin validate .claude-plugin/plugin.json # plugin manifest
claude plugin validate . --strict                 # newer CLIs: also fails on warnings
claude --plugin-dir .                             # load it for one session
```

In that session, ask "set up the Workspace audit". The skill should show as `/gws-audit:gws-audit`, and the paths it prints under `${CLAUDE_PLUGIN_ROOT}/tools/` should exist.

## Releasing (maintainers)

1. Run the tests and the validation commands above.
2. Bump `version` in `.claude-plugin/plugin.json`. Installed copies don't update while the version stays the same.
3. Commit, tag `vX.Y.Z` to match, and push the tag.
4. Optional, once per major change: submit or update the listing in the Claude plugin directory at **claude.ai/directory/manage** (paid claude.ai plan; on Team/Enterprise an Owner submits). Validate with `--strict` on a current Claude Code first. The portal runs its own review, so a clean local validation doesn't guarantee acceptance.
