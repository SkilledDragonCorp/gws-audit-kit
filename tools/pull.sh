#!/usr/bin/env bash
# Read-only Google Workspace audit pull.
#   bash tools/pull.sh [snapshot_root]
# Writes CSVs, dns.txt, findings.json and gap-report.md to <snapshot_root>/<YYYY-MM-DD>/.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOOLS="$ROOT/tools"
# Config lives outside the kit folder: a plugin update replaces that folder.
ENV_FILE="${GWS_AUDIT_ENV:-$HOME/.config/gws-audit/gws-audit.env}"
if [ ! -f "$ENV_FILE" ] && [ -f "$ROOT/gws-audit.env" ]
then
  ENV_FILE="$ROOT/gws-audit.env"
fi
if [ -f "$ENV_FILE" ]
then
  # shellcheck disable=SC1090
  . "$ENV_FILE"
fi

GAM="${GAM:-gam}"
export GAMCFGDIR="${GAMCFGDIR:-$HOME/.gam}"
export GWS_GCLOUD_CONFIG="${GWS_GCLOUD_CONFIG:-$GAMCFGDIR/gcloud}"
export GOOGLE_APPLICATION_CREDENTIALS="${GOOGLE_APPLICATION_CREDENTIALS:-$GWS_GCLOUD_CONFIG/application_default_credentials.json}"
OUT_ROOT="${1:-${GWS_AUDIT_OUT:-$HOME/gws-audit-snapshots}}"
OUT="$OUT_ROOT/$(date +%F)"

if [ -z "${PYTHON:-}" ]
then
  # On Windows `python3` is often the Microsoft Store stub, which exists but does nothing.
  if python3 -c "" >/dev/null 2>&1
  then
    PYTHON=python3
  else
    PYTHON=python
  fi
fi

if ! "$GAM" version >/dev/null 2>&1
then
  echo "GAM not found at '$GAM'. Set GAM in $ENV_FILE (see gws-audit.env.example)." >&2
  exit 1
fi

# Refuse to run with a token that can write. The kit's threat model depends on it.
bad_scopes="$("$GAM" oauth info 2>/dev/null \
  | sed -n '/^Scopes/,/^Expires/p' \
  | grep -E '^[[:space:]]+[^[:space:]]+' \
  | tr -d ' \t\r' \
  | grep -vE '\.readonly$|^(openid|email|profile)$|/userinfo\.(email|profile)$' || true)"
if [ -n "$bad_scopes" ]
then
  echo "Refusing to run: the GAM admin token has scopes that are not read-only:" >&2
  echo "$bad_scopes" >&2
  echo "Recreate it with read-only scopes (docs/setup.md, step 4)." >&2
  exit 1
fi

mkdir -p "$OUT"
cd "$OUT" || exit 1
: > pull.log

failed=()
pull() {
  local file="$1"
  shift
  echo "-> $file"
  if ! "$GAM" "$@" > "$file" 2>>pull.log
  then
    failed+=("$file")
  fi
}

pull users.csv print users fields primaryemail,name,isadmin,isdelegatedadmin,isenrolledin2sv,isenforcedin2sv,lastlogintime,creationtime,suspended,archived,orgunitpath,agreedtoterms,changepasswordatnextlogin
pull admins.csv print admins
pull domains.csv print domains
pull domainaliases.csv print domainaliases
pull orgunits.csv print orgs allfields
pull groups.csv print groups fields email,name,directmemberscount,adminCreated
pull policies.csv print policies
pull mobile.csv print mobile
pull browsers.csv print browsers
pull tokens_audit.csv report token start -180d
pull login_audit.csv report login start -30d
pull admin_audit.csv report admin start -180d
pull drive_visibility_audit.csv report drive start -180d event change_document_visibility

# Public DNS: mail authentication records for every domain in the tenant.
: > dns.txt
if command -v nslookup >/dev/null 2>&1
then
  for d in $(tail -n +2 domains.csv domainaliases.csv 2>/dev/null | grep -v '^==>' | cut -d, -f1 | tr -d '\r' | sort -u)
  do
    for name in "$d" "_dmarc.$d" "_mta-sts.$d" "_smtp._tls.$d"
    do
      echo "### $name TXT" >> dns.txt
      nslookup -type=TXT "$name" >> dns.txt 2>&1
    done
  done
else
  echo "nslookup not found; skipping DNS checks" | tee -a pull.log
fi

# Per-user Drive sharing inventory (keyless domain-wide delegation, drive.metadata.readonly)
echo "-> drive inventory"
if ! "$PYTHON" -I "$TOOLS/drive_inventory.py" users.csv .
then
  failed+=("drive inventory")
fi

"$PYTHON" -I "$TOOLS/analyze.py" . --edition "${GWS_EDITION:-unknown}" > /dev/null

prev="$(ls -1d "$OUT_ROOT"/????-??-?? 2>/dev/null | grep -v "$(date +%F)$" | tail -n 1)"
if [ -n "$prev" ] && [ -f "$prev/findings.json" ]
then
  "$PYTHON" -I "$TOOLS/diff.py" "$prev" . > diff.md
fi

echo
echo "Snapshot: $OUT"
if [ ${#failed[@]} -gt 0 ]
then
  echo "Failed steps (see pull.log): ${failed[*]}"
  exit 2
fi
