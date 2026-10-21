"""Compare two analyzed snapshots and print what changed, as Markdown.

Usage: python -I diff.py <previous_snapshot_dir> <current_snapshot_dir>
Both folders need a findings.json from analyze.py.
"""
import json
import os
import sys

SEVERITIES = ("critical", "high", "medium", "low", "info")
MAX_ITEMS = 20

# fact name -> (label, what an addition means)
SET_FACTS = {
    "super_admins": ("Super admins", "added"),
    "users_without_2sv": ("Users without 2SV", "newly without 2SV"),
    "dormant_users": ("Dormant accounts", "newly dormant"),
    "risky_apps": ("Third-party apps with high-risk scopes", "new"),
    "external_grantee_domains": ("Outside domains with Drive grants", "new"),
    "dns_problems": ("Mail DNS problems", "new"),
}


def load(folder):
    path = os.path.join(folder, "findings.json")
    if not os.path.exists(path):
        sys.exit(f"{path} not found: run analyze.py on that snapshot first")
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def bullet_list(items):
    shown = [f"  - {i}" for i in items[:MAX_ITEMS]]
    if len(items) > MAX_ITEMS:
        shown.append(f"  - … and {len(items) - MAX_ITEMS} more")
    return shown


def diff(prev, cur):
    out = [f"# Changes since {prev['snapshot_date']}", "",
           f"Comparing snapshot {prev['snapshot_date']} → {cur['snapshot_date']}.", ""]

    before = {f["id"]: f for f in prev["findings"]}
    after = {f["id"]: f for f in cur["findings"]}
    new = [after[i] for i in after if i not in before]
    resolved = [before[i] for i in before if i not in after]
    changed = []
    for i in after.keys() & before.keys():
        a, b = after[i], before[i]
        if a["severity"] != b["severity"] or a.get("count") != b.get("count"):
            changed.append(f"{a['title']}: {b['severity']} ({b.get('count')}) → {a['severity']} ({a.get('count')})")

    out += ["## Findings", ""]
    if not (new or resolved or changed):
        out.append("No finding appeared, disappeared or changed severity.")
    if new:
        out.append("**New:**")
        out += bullet_list([f"{f['severity']}: {f['title']}"
                            for f in sorted(new, key=lambda f: SEVERITIES.index(f["severity"]))])
    if resolved:
        out.append("**Resolved:**")
        out += bullet_list([f"{f['severity']}: {f['title']}" for f in resolved])
    if changed:
        out.append("**Changed:**")
        out += bullet_list(sorted(changed))

    pf, cf = prev.get("facts", {}), cur.get("facts", {})
    out += ["", "## Entities", ""]
    quiet = True
    for key, (label, added_word) in SET_FACTS.items():
        if key not in pf or key not in cf:
            continue
        added = sorted(set(cf[key]) - set(pf[key]))
        removed = sorted(set(pf[key]) - set(cf[key]))
        if added or removed:
            quiet = False
            out.append(f"**{label}:** {len(pf[key])} → {len(cf[key])}")
            if added:
                out.append(f"- {added_word}:")
                out += bullet_list(added)
            if removed:
                out.append("- gone:")
                out += bullet_list(removed)

    if "public_files" in pf and "public_files" in cf:
        added = [cf["public_files"][k] or k for k in cf["public_files"] if k not in pf["public_files"]]
        removed = [k for k in pf["public_files"] if k not in cf["public_files"]]
        if added or removed:
            quiet = False
            out.append(f"**Company files open to anyone with the link:** {len(pf['public_files'])} → "
                       f"{len(cf['public_files'])} ({len(added)} new, {len(removed)} closed or deleted)")
            out += bullet_list(sorted(added))

    for key, label in (("stale_devices", "Stale mobile devices"), ("mobile_devices", "Mobile devices")):
        if key in pf and key in cf and pf[key] != cf[key]:
            quiet = False
            out.append(f"**{label}:** {pf[key]} → {cf[key]}")
    if quiet:
        out.append("No change in admins, 2SV, apps, Drive exposure or devices.")

    pp, cp = pf.get("policies", {}), cf.get("policies", {})
    policy_lines = []
    for key in sorted(pp.keys() | cp.keys()):
        old, new_vals = pp.get(key), cp.get(key)
        if old == new_vals:
            continue
        if old is None:
            policy_lines.append(f"{key}: added {new_vals}")
        elif new_vals is None:
            policy_lines.append(f"{key}: removed")
        else:
            fields = sorted(k for k in old.keys() | new_vals.keys() if old.get(k) != new_vals.get(k))
            policy_lines.append(f"{key}: " + ", ".join(f"{k} {old.get(k)} → {new_vals.get(k)}" for k in fields))
    out += ["", "## Policy changes", ""]
    if policy_lines:
        out += [f"- {line}" for line in policy_lines]
    else:
        out.append("No policy setting changed.")
    return "\n".join(out) + "\n"


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    sys.stdout.reconfigure(encoding="utf-8")
    print(diff(load(sys.argv[1]), load(sys.argv[2])))


if __name__ == "__main__":
    main()
