"""Keyless Drive sharing inventory using domain-wide delegation with drive.metadata.readonly only.

GAM's Drive commands need the full Drive scope or drive.readonly, both of which expose file
contents. This script stays metadata-only: an isolated gcloud login signs a JWT as the service
account (IAM signJwt, no key file), which is exchanged for a per-user token.

Usage:
  python -I drive_inventory.py <users.csv> <out_dir> [--only user@example.com ...]

Environment (all optional):
  GWS_SA_EMAIL          service account; default client_email in $GAMCFGDIR/oauth2service.json
  GAMCFGDIR             GAM config folder; default ~/.gam
  GWS_GCLOUD_CONFIG     isolated gcloud config folder; default $GAMCFGDIR/gcloud
  GWS_INTERNAL_DOMAINS  extra internal domains, comma separated
"""
import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

SCOPE = "https://www.googleapis.com/auth/drive.metadata.readonly"
TOKEN_URL = "https://oauth2.googleapis.com/token"
RETRY_CODES = (429, 500, 502, 503, 504)
ADMIN_TOKEN_TTL = 45 * 60

GAMCFGDIR = os.path.expanduser(os.environ.get("GAMCFGDIR") or "~/.gam")
GCLOUD_CONFIG = os.path.expanduser(os.environ.get("GWS_GCLOUD_CONFIG") or os.path.join(GAMCFGDIR, "gcloud"))


def http(method, url, headers=None, data=None, attempts=4):
    for attempt in range(attempts):
        req = urllib.request.Request(url, method=method, headers=headers or {}, data=data)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code not in RETRY_CODES or attempt == attempts - 1:
                raise
            time.sleep(2 ** attempt)


def service_account():
    email = os.environ.get("GWS_SA_EMAIL")
    if not email:
        path = os.path.join(GAMCFGDIR, "oauth2service.json")
        try:
            with open(path, encoding="utf-8") as fh:
                email = json.load(fh).get("client_email")
        except FileNotFoundError:
            pass
    if not email:
        sys.exit("No service account: set GWS_SA_EMAIL or create oauth2service.json (docs/setup.md, step 6)")
    # Service account emails look like name@<project>.iam.gserviceaccount.com
    project = email.split("@", 1)[1].split(".", 1)[0]
    return email, project


class AdminToken:
    """Access token from the isolated gcloud login, refreshed before it expires."""

    def __init__(self):
        self.value, self.fetched = None, 0.0

    def get(self):
        if self.value is None or time.time() - self.fetched > ADMIN_TOKEN_TTL:
            gcloud = shutil.which("gcloud")
            if not gcloud:
                sys.exit("gcloud not found on PATH")
            env = dict(os.environ, CLOUDSDK_CONFIG=GCLOUD_CONFIG)
            out = subprocess.run([gcloud, "auth", "application-default", "print-access-token"],
                                 env=env, capture_output=True, text=True)
            if out.returncode != 0:
                sys.exit(f"gcloud could not print a token from {GCLOUD_CONFIG}:\n{out.stderr.strip()}")
            self.value, self.fetched = out.stdout.strip(), time.time()
        return self.value


def user_token(admin, sa, project, user):
    now = int(time.time())
    claims = {"iss": sa, "sub": user, "scope": SCOPE, "aud": TOKEN_URL, "iat": now, "exp": now + 3600}
    signed = http("POST",
                  f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{sa}:signJwt",
                  {"Authorization": f"Bearer {admin.get()}", "Content-Type": "application/json",
                   "x-goog-user-project": project},
                  json.dumps({"payload": json.dumps(claims)}).encode())["signedJwt"]
    body = urllib.parse.urlencode({"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                   "assertion": signed}).encode()
    return http("POST", TOKEN_URL, {"Content-Type": "application/x-www-form-urlencoded"}, body)["access_token"]


def list_files(token, params):
    params = dict(params, pageSize=1000, supportsAllDrives="true", includeItemsFromAllDrives="true")
    while True:
        page = http("GET", "https://www.googleapis.com/drive/v3/files?" + urllib.parse.urlencode(params),
                    {"Authorization": f"Bearer {token}"})
        yield from page.get("files", [])
        if not page.get("nextPageToken"):
            return
        params["pageToken"] = page["nextPageToken"]


def read_csv(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def internal_domains(out_dir):
    domains = {d.strip().lower() for d in os.environ.get("GWS_INTERNAL_DOMAINS", "").split(",") if d.strip()}
    domains |= {r["domainName"].lower() for r in read_csv(os.path.join(out_dir, "domains.csv")) if r.get("domainName")}
    domains |= {r["domainAliasName"].lower() for r in read_csv(os.path.join(out_dir, "domainaliases.csv"))
                if r.get("domainAliasName")}
    return domains


def is_internal(address, domains):
    domain = address.lower().rsplit("@", 1)[-1]
    # Exact or subdomain match; a plain endswith() would treat evil-example.com as internal.
    return any(domain == d or domain.endswith("." + d) for d in domains)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("users_csv")
    parser.add_argument("out_dir")
    parser.add_argument("--only", nargs="+", metavar="EMAIL", help="re-run for these users only")
    args = parser.parse_args()

    sa, project = service_account()
    domains = internal_domains(args.out_dir)
    if not domains:
        sys.exit("No internal domains: run from a snapshot with domains.csv or set GWS_INTERNAL_DOMAINS")

    users = [u["primaryEmail"] for u in read_csv(args.users_csv)
             if u.get("suspended") != "True" and u.get("archived") != "True"]
    if args.only:
        wanted = {e.lower() for e in args.only}
        users = [u for u in users if u.lower() in wanted]

    admin = AdminToken()
    link, external, errors = {}, [], []
    for user in users:
        try:
            token = user_token(admin, sa, project, user)
            for f in list_files(token, {
                "corpora": "allDrives",
                "q": "(visibility='anyoneWithLink' or visibility='anyoneCanFind') and trashed=false",
                "fields": "nextPageToken,files(id,name,mimeType,owners(emailAddress),driveId,createdTime,modifiedTime,webViewLink)",
            }):
                link.setdefault(f["id"], f)
            for f in list_files(token, {
                "corpora": "user",
                "q": "'me' in owners and trashed=false",
                "fields": "nextPageToken,files(id,name,mimeType,modifiedTime,webViewLink,permissions(type,role,emailAddress,domain))",
            }):
                for p in f.get("permissions", []):
                    who = p.get("emailAddress") or p.get("domain") or ""
                    if p["type"] in ("user", "group", "domain") and who and not is_internal(who, domains):
                        external.append([user, f["id"], f["name"], f["mimeType"], p["type"], p["role"], who,
                                         f.get("modifiedTime", "")[:10], f.get("webViewLink", "")])
            print(f"{user}: ok", flush=True)
        except urllib.error.HTTPError as e:
            errors.append(user)
            print(f"{user}: HTTP {e.code} {e.read()[:200]!r}", flush=True)

    suffix = "_partial" if args.only else ""
    with open(os.path.join(args.out_dir, f"drive_link_shared_full{suffix}.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["owner", "internal_owner", "shared_drive_id", "file_id", "type", "name", "created", "modified", "url"])
        for f in link.values():
            owner = (f.get("owners") or [{}])[0].get("emailAddress", "")
            internal = bool(f.get("driveId")) or (bool(owner) and is_internal(owner, domains))
            w.writerow([owner, internal, f.get("driveId", ""), f["id"], f["mimeType"], f["name"],
                        f.get("createdTime", "")[:10], f.get("modifiedTime", "")[:10], f.get("webViewLink", "")])
    with open(os.path.join(args.out_dir, f"drive_external_shares{suffix}.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["owner", "file_id", "name", "type", "grantee_type", "role", "grantee", "modified", "url"])
        w.writerows(external)
    with open(os.path.join(args.out_dir, f"drive_errors{suffix}.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(errors))
    print(f"link/public files: {len(link)}  external grants: {len(external)}  users with errors: {len(errors)}")
    if errors:
        print("Re-run the failed users with: --only " + " ".join(errors))
        sys.exit(2)


if __name__ == "__main__":
    main()
