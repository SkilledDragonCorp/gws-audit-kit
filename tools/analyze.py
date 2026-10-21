"""Turn a snapshot folder into ranked, structured findings.

Usage:
  python -I analyze.py <snapshot_dir> [--edition starter|standard|plus|enterprise|unknown] [--today YYYY-MM-DD]

Writes <snapshot_dir>/findings.json (used by diff.py and the Claude Code skill) and
<snapshot_dir>/gap-report.md (a ranked draft report), then prints the report.
Every check tolerates missing files and columns: a missing input becomes a "not checked" line.
"""
import argparse
import collections
import csv
import datetime as dt
import json
import os
import re
import sys

SEVERITIES = ("critical", "high", "medium", "low", "info")
ICONS = {"critical": "🔴", "high": "🔴", "medium": "🟠", "low": "🟡", "info": "🔵"}
EDITIONS = ("starter", "standard", "plus", "enterprise", "unknown")
EDITION_NAMES = {"starter": "Business Starter", "standard": "Business Standard", "plus": "Business Plus",
                 "enterprise": "Enterprise", "unknown": "unknown edition"}
SUPER_ADMIN_ROLES = ("_SEED_ADMIN_ROLE", "Super Admin")
GOOGLE_APP_PREFIXES = ("Google", "Android", "iOS", "macOS", "Gmail", "Chrome", "YouTube")
CIS = "CIS Google Workspace Foundations Benchmark"
MAX_EVIDENCE = 15


class Snapshot:
    def __init__(self, folder):
        self.folder = folder
        self.missing = set()
        self._cache = {}

    def rows(self, name):
        if name not in self._cache:
            path = os.path.join(self.folder, name)
            if not os.path.exists(path) or os.path.getsize(path) == 0:
                self.missing.add(name)
                self._cache[name] = None
            else:
                with open(path, encoding="utf-8", newline="") as fh:
                    self._cache[name] = list(csv.DictReader(fh))
        return self._cache[name]

    def text(self, name):
        path = os.path.join(self.folder, name)
        if not os.path.exists(path):
            self.missing.add(name)
            return None
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()


class Context:
    def __init__(self, snap, edition, today):
        self.snap = snap
        self.edition = edition
        self.today = today
        self.facts = {}
        self.root_policies, self.policy_values = self._load_policies()

    def _load_policies(self):
        root, values = {}, {}
        for r in self.snap.rows("policies.csv") or []:
            kind = r.get("setting.type", "").replace("settings/", "", 1)
            vals = {k[len("setting.value."):]: v for k, v in r.items() if k.startswith("setting.value.") and v}
            if r.get("policyQuery.group"):
                scope = "group:" + r["policyQuery.group"]
            else:
                scope = "ou:" + (r.get("policyQuery.orgUnitPath") or "/")
            values.setdefault(f"{kind}@{scope}", vals)
            if scope == "ou:/":
                root.setdefault(kind, vals)
        return root, values

    def policy(self, kind):
        return self.root_policies.get(kind)

    def overrides(self, kind):
        return sorted(k.split("@", 1)[1] for k in self.policy_values if k.startswith(kind + "@") and not k.endswith("@ou:/"))

    def active_users(self):
        users = self.snap.rows("users.csv")
        if users is None:
            return None
        return [u for u in users if u.get("suspended") != "True" and u.get("archived") != "True"]

    def super_admins(self):
        users = self.snap.rows("users.csv") or []
        found = {u["primaryEmail"].lower() for u in users if u.get("isAdmin") == "True"}
        for r in self.snap.rows("admins.csv") or []:
            if r.get("role") in SUPER_ADMIN_ROLES and r.get("assignedToUser"):
                found.add(r["assignedToUser"].lower())
        return sorted(found)


def parse_time(value):
    if not value or value.startswith(("Never", "1970")):
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).date()
    except ValueError:
        return None


def finding(id, title, severity, category, detail, recommendation, evidence=None, count=None,
            reference=None, edition_note=None):
    return {"id": id, "status": "fail", "title": title, "severity": severity, "category": category,
            "detail": detail, "count": count, "evidence": (evidence or [])[:MAX_EVIDENCE],
            "evidence_total": len(evidence or []), "recommendation": recommendation,
            "reference": reference, "edition_note": edition_note}


def passed(id, title, category):
    return {"id": id, "status": "pass", "title": title, "category": category}


def edition_note(ctx, notes):
    """notes maps edition -> text; 'all' applies to every edition, 'unknown' when edition is unknown."""
    return notes.get(ctx.edition) or notes.get("all")


# --- Identity ---------------------------------------------------------------------------------

def check_super_admin_2sv(ctx):
    users = {u["primaryEmail"].lower(): u for u in ctx.active_users() or []}
    admins = ctx.super_admins()
    ctx.facts["super_admins"] = admins
    if not users:
        return None
    weak = [a for a in admins if a in users and users[a].get("isEnrolledIn2Sv") != "True"]
    if not weak:
        return passed("super-admin-2sv", "Every super admin is enrolled in 2SV", "Identity")
    return finding("super-admin-2sv", f"{len(weak)} super admin(s) without 2-Step Verification", "critical",
                   "Identity", "A super admin without 2SV is one phished password away from full tenant takeover.",
                   "Enroll these accounts in 2SV today, ideally with a security key or passkey.",
                   evidence=weak, count=len(weak), reference=f"{CIS}: Administrative accounts")


def check_2sv_enrollment(ctx):
    users = ctx.active_users()
    if users is None:
        return None
    missing = sorted(u["primaryEmail"].lower() for u in users if u.get("isEnrolledIn2Sv") != "True")
    ctx.facts["users_active"] = sorted(u["primaryEmail"].lower() for u in users)
    ctx.facts["users_without_2sv"] = missing
    if not missing:
        return passed("2sv-enrollment", "Every active user is enrolled in 2SV", "Identity")
    enforcement = (ctx.policy("security.two_step_verification_enforcement") or {}).get("enforcedFrom", "")
    when = parse_time(enforcement)
    severity, detail = "high", f"{len(missing)} of {len(users)} active users have no 2SV."
    if when and when >= ctx.today:
        days = (when - ctx.today).days
        detail += f" Org-wide enforcement starts {when.isoformat()} ({days} days): they will be locked out."
        if days <= 14:
            severity = "critical"
    elif when:
        detail += " Enforcement is already on, so these are likely shared, service or never-signed-in accounts."
    return finding("2sv-enrollment", f"{len(missing)} active user(s) not enrolled in 2SV", severity, "Identity",
                   detail, "Chase enrollment (passkeys count only once 2SV is turned on), or suspend unused accounts.",
                   evidence=missing, count=len(missing), reference=f"{CIS}: 2-Step Verification")


def check_2sv_enforcement(ctx):
    pol = ctx.policy("security.two_step_verification_enforcement")
    if pol is None:
        return None
    when = parse_time(pol.get("enforcedFrom", ""))
    if when:
        return passed("2sv-enforced", f"2SV enforcement configured at the root OU (from {when.isoformat()})", "Identity")
    return finding("2sv-enforced", "2SV is not enforced at the root org unit", "high", "Identity",
                   "Users can opt out of 2SV entirely.",
                   "Security → Authentication → 2-step verification: allow enrollment, then turn on enforcement with a "
                   "short new-user enrollment period.", reference=f"{CIS}: 2-Step Verification")


def check_2sv_methods(ctx):
    pol = ctx.policy("security.two_step_verification_enforcement_factor")
    if pol is None:
        return None
    allowed = pol.get("allowedSignInFactorSet", "")
    if allowed and allowed != "ALL":
        return passed("2sv-methods", f"2SV methods restricted ({allowed})", "Identity")
    return finding("2sv-methods", "Any 2SV method is allowed, including SMS and voice codes", "medium", "Identity",
                   "SMS and voice codes can be phished or SIM-swapped.",
                   "Require security keys or passkeys at least for admins: put them in their own OU or group and set "
                   "'Only security key'.", reference=f"{CIS}: 2-Step Verification",
                   edition_note=edition_note(ctx, {"all": "Security-key-only enforcement is available on every edition."}))


def check_super_admin_count(ctx):
    admins = ctx.super_admins()
    if not admins:
        return None
    if 2 <= len(admins) <= 4:
        return passed("super-admin-count", f"{len(admins)} super admins (2-4 recommended)", "Identity")
    detail = "Only one super admin: no break-glass backup." if len(admins) < 2 else \
        f"{len(admins)} super admins. Each one is a full-takeover target."
    return finding("super-admin-count", f"{len(admins)} super admin account(s)", "medium", "Identity", detail,
                   "Keep 2-4 super admins and use delegated admin roles for daily work.", evidence=admins,
                   count=len(admins), reference=f"{CIS}: Administrative accounts")


def check_super_admin_recovery(ctx):
    pol = ctx.policy("security.super_admin_account_recovery")
    if pol is None:
        return None
    if pol.get("enableAccountRecovery") != "True":
        return passed("super-admin-recovery", "Super admin self-recovery is off", "Identity")
    return finding("super-admin-recovery", "Super admins can recover their own accounts", "medium", "Identity",
                   "Self-service recovery via phone or email is a takeover path for the most powerful accounts.",
                   "Security → Authentication → Account recovery: turn off super admin self-recovery.",
                   reference=f"{CIS}: Administrative accounts")


def check_password_policy(ctx):
    pol = ctx.policy("security.password")
    if pol is None:
        return None
    problems = []
    if int(pol.get("minimumLength", "0") or 0) < 12:
        problems.append(f"minimum length {pol.get('minimumLength', '?')} (recommend 12+)")
    if pol.get("enforceRequirementsAtLogin") != "True":
        problems.append("requirements not enforced at next sign-in")
    if pol.get("allowReuse") == "True":
        problems.append("password reuse allowed")
    if not problems:
        return passed("password-policy", "Password policy meets length and enforcement guidance", "Identity")
    return finding("password-policy", "Password policy is weaker than recommended", "low", "Identity",
                   "; ".join(problems).capitalize() + ".",
                   "Security → Authentication → Password management: minimum 12, enforce at next sign-in.",
                   evidence=problems, reference=f"{CIS}: Password management")


def check_dormant_users(ctx):
    users = ctx.active_users()
    if users is None:
        return None
    cutoff = ctx.today - dt.timedelta(days=90)
    dormant = []
    for u in users:
        created = parse_time(u.get("creationTime", ""))
        last = parse_time(u.get("lastLoginTime", ""))
        if created and created > cutoff:
            continue
        if last is None or last < cutoff:
            dormant.append(f"{u['primaryEmail'].lower()} (last sign-in {last.isoformat() if last else 'never'})")
    ctx.facts["dormant_users"] = sorted(d.split(" ", 1)[0] for d in dormant)
    if not dormant:
        return passed("dormant-users", "No active account is dormant for 90+ days", "Identity")
    return finding("dormant-users", f"{len(dormant)} active account(s) with no sign-in for 90+ days", "medium",
                   "Identity", "Dormant and shared mailboxes keep working passwords nobody watches.",
                   "Suspend or archive them, or convert shared mailboxes to Groups / delegated access.",
                   evidence=sorted(dormant), count=len(dormant), reference=f"{CIS}: User account management")


def check_session_length(ctx):
    pol = ctx.policy("security.session_controls")
    if pol is None:
        return None
    seconds = int((pol.get("webSessionDuration") or "0s").rstrip("s") or 0)
    if 0 < seconds <= 14 * 86400:
        return passed("session-length", f"Web session length {seconds // 3600} h", "Identity")
    return finding("session-length", "Web sessions last longer than 14 days", "low", "Identity",
                   f"Web session duration is {seconds // 86400} days.",
                   "Security → Access and data control → Google Cloud session control / Google session control: "
                   "14 days or less.", reference=f"{CIS}: Session control")


# --- Third-party apps -------------------------------------------------------------------------

def risky_scopes(scopes):
    out = []
    for s in scopes:
        tail = s.replace("https://www.googleapis.com/auth/", "")
        if s == "https://mail.google.com/":
            out.append("mail.google.com (FULL GMAIL)")
        elif tail in ("drive", "admin.directory.user", "cloud-platform", "gmail.modify", "gmail.readonly",
                      "gmail.send", "gmail.compose", "gmail.settings.sharing", "script.projects") \
                or tail.startswith("admin."):
            out.append(tail)
    return sorted(set(out))


def check_third_party_policy(ctx):
    pol = ctx.policy("api_controls.unconfigured_third_party_apps")
    if pol is None:
        return None
    level = pol.get("accessLevel", "")
    if any(k in level for k in ("BLOCK", "BASIC", "SIGN_IN", "LIMITED")):
        return passed("third-party-apps-policy", f"Unconfigured third-party apps are restricted ({level})", "Apps")
    return finding("third-party-apps-policy", "Any user can grant any third-party app access to company data", "high",
                   "Apps", f"Unconfigured third-party apps access level: {level or 'not set (default: allowed)'}.",
                   "Security → API controls → Manage third-party app access: review the apps already used, mark the "
                   "needed ones Trusted or Limited, then set unconfigured apps to 'Sign in with Google only' or block.",
                   reference=f"{CIS}: API controls",
                   edition_note=edition_note(ctx, {"all": "Available on every edition."}))


def check_risky_apps(ctx):
    rows = ctx.snap.rows("tokens_audit.csv")
    if rows is None:
        return None
    apps = {}
    for r in rows:
        if r.get("name") != "authorize":
            continue
        name = r.get("app_name") or r.get("client_id", "?")
        a = apps.setdefault(name, {"users": set(), "scopes": set()})
        a["users"].add(r.get("actor.email", ""))
        a["scopes"].update((r.get("scope") or "").split())
    ctx.facts["apps_authorized"] = sorted(apps)
    risky = {n: a for n, a in apps.items()
             if not n.startswith(GOOGLE_APP_PREFIXES) and risky_scopes(a["scopes"])}
    ctx.facts["risky_apps"] = sorted(risky)
    if not risky:
        return passed("risky-apps", f"No non-Google app holds high-risk scopes ({len(apps)} apps seen)", "Apps")
    full = [n for n, a in risky.items() if any("FULL" in s or s == "drive" or s.startswith("admin.")
                                              for s in risky_scopes(a["scopes"]))]
    evidence = [f"{n}: {len(a['users'])} user(s), {', '.join(risky_scopes(a['scopes'])[:4])}"
                for n, a in sorted(risky.items(), key=lambda kv: -len(kv[1]["users"]))]
    return finding("risky-apps", f"{len(risky)} third-party app(s) hold high-risk scopes", "high" if full else "medium",
                   "Apps", f"{len(apps)} distinct apps were authorized in the token audit window; {len(full)} have full "
                   "Gmail, full Drive or admin scopes.",
                   "Review each app with its users; mark the needed ones Trusted or Limited and block the rest.",
                   evidence=evidence, count=len(risky), reference=f"{CIS}: API controls")


def check_dwd_changes(ctx):
    rows = ctx.snap.rows("admin_audit.csv")
    if rows is None:
        return None
    grants = [f"{r.get('id.time', '')[:10]} {r.get('actor.email', '')}: {r.get('API_CLIENT_NAME', '')} "
              f"{r.get('API_SCOPES', '')[:120]}" for r in rows if r.get("name") == "AUTHORIZE_API_CLIENT_ACCESS"]
    if not grants:
        return passed("dwd-changes", "No domain-wide delegation grants in the admin audit window", "Apps")
    return finding("dwd-changes", f"{len(grants)} domain-wide delegation grant(s) in the audit window", "medium",
                   "Apps", "Domain-wide delegation lets a service account act as any user for the granted scopes.",
                   "Security → API controls → Domain-wide delegation: confirm each client and trim scopes.",
                   evidence=grants, count=len(grants), reference=f"{CIS}: API controls")


# --- Sign-ins and admin activity ----------------------------------------------------------------

SUSPICIOUS_EVENTS = ("suspicious_login", "suspicious_login_less_secure_app", "suspicious_programmatic_login",
                     "account_disabled_hijacked", "account_disabled_password_leak", "gov_attack_warning",
                     "risky_sensitive_action_blocked")


def check_suspicious_logins(ctx):
    rows = ctx.snap.rows("login_audit.csv")
    if rows is None:
        return None
    hits = [f"{r.get('id.time', '')[:16]} {r.get('name')} {r.get('actor.email', '')} {r.get('networkInfo.regionCode', '')}"
            for r in rows if r.get("name") in SUSPICIOUS_EVENTS]
    if not hits:
        return passed("suspicious-logins", "No suspicious sign-in events in the login audit window", "Sign-ins")
    return finding("suspicious-logins", f"{len(hits)} suspicious sign-in or blocked risky-action event(s)", "high",
                   "Sign-ins", "Google flagged these sign-ins or blocked sensitive actions.",
                   "Confirm each with the user; reset password and revoke sessions for anything unexplained.",
                   evidence=sorted(hits, reverse=True), count=len(hits), reference="Google Admin: Login audit log")


def check_login_regions(ctx):
    rows = ctx.snap.rows("login_audit.csv")
    if rows is None:
        return None
    regions = collections.defaultdict(set)
    for r in rows:
        if r.get("name") == "login_success" and r.get("networkInfo.regionCode"):
            regions[r.get("actor.email", "").lower()].add(r["networkInfo.regionCode"])
    admins = set(ctx.super_admins())
    many = {u: rs for u, rs in regions.items() if len(rs) >= 3 or (u in admins and len(rs) >= 2)}
    if not many:
        return passed("login-regions", "No account signs in from an unusual spread of countries", "Sign-ins")
    evidence = [f"{u}{' (super admin)' if u in admins else ''}: {', '.join(sorted(rs))}"
                for u, rs in sorted(many.items(), key=lambda kv: -len(kv[1]))]
    severity = "high" if admins & set(many) else "medium"
    return finding("login-regions", f"{len(many)} account(s) signing in from several countries", severity, "Sign-ins",
                   "Travel and VPNs explain most of these; an admin account in this list deserves a direct check.",
                   "Ask each user to confirm; check Security → Alert center for related alerts.",
                   evidence=evidence, count=len(many), reference="Google Admin: Login audit log")


def check_admin_changes(ctx):
    rows = ctx.snap.rows("admin_audit.csv")
    if rows is None:
        return None
    keys = ("ROLE", "PRIVILEGE", "TWO_STEP", "STRONG_AUTH", "PASSWORD", "SSO", "OAUTH", "APP_ACCESS", "TRUST")
    hits = [f"{r.get('id.time', '')[:10]} {r.get('actor.email', '')}: {r.get('name')} "
            f"{r.get('ROLE_NAME', '') or r.get('SETTING_NAME', '')[:60]} {r.get('USER_EMAIL', '')}".rstrip()
            for r in rows if any(k in r.get("name", "") for k in keys)]
    if not hits:
        return None
    return finding("admin-changes", f"{len(hits)} security-relevant admin change(s) in the audit window", "info",
                   "Admin activity", "Role assignments and authentication or app-access setting changes.",
                   "Confirm each change was intended and made by the expected admin.",
                   evidence=sorted(hits, reverse=True), count=len(hits), reference="Google Admin: Admin audit log")


# --- Drive --------------------------------------------------------------------------------------

def check_public_files(ctx):
    rows = ctx.snap.rows("drive_link_shared_full.csv")
    if rows is None:
        return None
    domains = {r["domainName"].lower() for r in ctx.snap.rows("domains.csv") or [] if r.get("domainName")}
    domains |= {r["domainAliasName"].lower() for r in ctx.snap.rows("domainaliases.csv") or [] if r.get("domainAliasName")}

    def is_internal(r):
        if "internal_owner" in r:
            return r["internal_owner"] == "True"
        # Older inventories have no internal_owner column.
        owner_domain = (r.get("owner") or "").lower().rsplit("@", 1)[-1]
        return bool(r.get("shared_drive_id")) or any(owner_domain == d or owner_domain.endswith("." + d) for d in domains)

    internal = [r for r in rows if is_internal(r)]
    ctx.facts["public_files"] = {(r.get("file_id") or r.get("url", "")): r.get("name", "") for r in internal}
    if not internal:
        return passed("drive-public-files", "No company-owned file is shared with 'anyone with the link'", "Drive")
    owners = collections.Counter(r.get("owner") or f"shared drive {r.get('shared_drive_id', '')}" for r in internal)
    evidence = [f"{o}: {n} file(s)" for o, n in owners.most_common()]
    severity = "high" if len(internal) >= 500 else "medium"
    return finding("drive-public-files", f"{len(internal)} company-owned file(s) open to anyone with the link",
                   severity, "Drive", "Anyone who obtains the URL can open these files without signing in.",
                   "Ask owners to review drive_link_shared_full.csv; restrict links to the organization by default.",
                   evidence=evidence, count=len(internal), reference=f"{CIS}: Drive sharing")


def check_external_grants(ctx):
    rows = ctx.snap.rows("drive_external_shares.csv")
    if rows is None:
        return None
    domains = collections.Counter(r.get("grantee", "").lower().rsplit("@", 1)[-1] for r in rows)
    ctx.facts["external_grantee_domains"] = sorted(domains)
    if not rows:
        return passed("drive-external-grants", "No company-owned file is shared with outside accounts", "Drive")
    personal = sum(n for d, n in domains.items() if d in ("gmail.com", "googlemail.com", "outlook.com", "hotmail.com",
                                                           "yahoo.com", "icloud.com"))
    writers = sum(1 for r in rows if r.get("role") in ("writer", "fileOrganizer", "organizer", "owner"))
    evidence = [f"{d}: {n} grant(s)" for d, n in domains.most_common()]
    return finding("drive-external-grants", f"{len(rows)} sharing grant(s) to {len(domains)} outside domain(s)",
                   "medium", "Drive", f"{writers} grant edit or higher rights; {personal} go to personal mail domains.",
                   "Review drive_external_shares.csv with owners; turn on the warning when sharing outside the "
                   "organization; consider an allowlist of trusted domains.",
                   evidence=evidence, count=len(rows), reference=f"{CIS}: Drive sharing",
                   edition_note=edition_note(ctx, {"starter": "Trust rules and Drive DLP are not available on "
                                                   "Business Starter; use the standard sharing settings.",
                                                   "standard": "Trust rules and Drive DLP need an Enterprise edition.",
                                                   "plus": "Trust rules and Drive DLP need an Enterprise edition."}))


def check_shared_drive_settings(ctx):
    pol = ctx.policy("drive_and_docs.shared_drive_creation")
    if pol is None:
        return None
    problems = [k for k in ("allowNonMemberAccess", "allowExternalUserAccess", "allowManagersToOverrideSettings")
                if pol.get(k) == "True"]
    if not problems:
        return passed("shared-drive-settings", "Shared drive defaults keep content inside", "Drive")
    return finding("shared-drive-settings", "Shared drive defaults allow outside or non-member access", "low", "Drive",
                   "New shared drives allow: " + ", ".join(problems) + ".",
                   "Apps → Drive and Docs → Sharing settings → Shared drive creation: tighten the defaults.",
                   evidence=problems, reference=f"{CIS}: Drive sharing")


def check_drive_desktop(ctx):
    pol = ctx.policy("drive_and_docs.drive_for_desktop")
    if pol is None or pol.get("allowDriveForDesktop") != "True":
        return None
    if pol.get("restrictToAuthorizedDevices") == "True":
        return passed("drive-desktop", "Drive for desktop limited to authorized devices", "Drive")
    return finding("drive-desktop", "Drive for desktop works on any computer", "low", "Drive",
                   "Users can sync company files to personal, unmanaged computers.",
                   "Restrict Drive for desktop to authorized devices where the edition allows it.",
                   reference=f"{CIS}: Drive and Docs",
                   edition_note=edition_note(ctx, {"starter": "Restricting to authorized devices needs advanced "
                                                   "endpoint management (Business Plus and above).",
                                                   "standard": "Restricting to authorized devices needs advanced "
                                                   "endpoint management (Business Plus and above).",
                                                   "unknown": "Restricting to authorized devices needs advanced "
                                                   "endpoint management (Business Plus and above)."}))


# --- Collaboration ------------------------------------------------------------------------------

def check_calendar_sharing(ctx):
    pol = ctx.policy("calendar.primary_calendar_max_allowed_external_sharing")
    if pol is None:
        return None
    level = pol.get("maxAllowedExternalSharing", "")
    if "WRITE" not in level and "MANAGE" not in level:
        return passed("calendar-external", f"External calendar sharing capped ({level})", "Collaboration")
    return finding("calendar-external", "Calendars can be shared outside with edit or manage rights", "medium",
                   "Collaboration", f"Maximum external sharing: {level}.",
                   "Apps → Calendar → Sharing settings: limit external sharing to free/busy only.",
                   reference=f"{CIS}: Calendar sharing")


def check_chat_external(ctx):
    pol = ctx.policy("chat.chat_external_spaces")
    if pol is None:
        return None
    if pol.get("enabled") != "True" or pol.get("domainAllowlistMode") != "ALL_DOMAINS":
        return passed("chat-external", "External Chat spaces are off or allowlisted", "Collaboration")
    return finding("chat-external", "External Chat spaces are open to every domain", "low", "Collaboration",
                   "Users can create or join spaces with any outside organization.",
                   "Apps → Google Chat → External Chat settings: restrict to allowlisted domains.",
                   reference=f"{CIS}: Google Chat")


def check_groups_external(ctx):
    pol = ctx.policy("groups_for_business.groups_sharing")
    if pol is None:
        return None
    problems = []
    if pol.get("ownersCanAllowExternalMembers") == "True":
        problems.append("owners can add external members")
    if pol.get("ownersCanAllowIncomingMailFromPublic") == "True":
        problems.append("owners can accept mail from the public")
    if pol.get("collaborationCapability") == "ANYONE_CAN_ACCESS":
        problems.append("groups can be visible to anyone on the internet")
    if not problems:
        return passed("groups-external", "Groups sharing stays inside the organization", "Collaboration")
    return finding("groups-external", "Google Groups can be opened to outsiders", "low", "Collaboration",
                   "; ".join(problems).capitalize() + ".",
                   "Apps → Google Groups for Business → Sharing settings: keep groups internal.",
                   evidence=problems, reference=f"{CIS}: Groups for Business")


def check_takeout(ctx):
    if not ctx.root_policies:
        return None
    enabled = sorted(k.split(".")[0] for k, v in ctx.root_policies.items()
                     if (k.endswith(".user_takeout") and v.get("takeoutStatus") == "ENABLED")
                     or (k == "takeout.service_status" and v.get("serviceState") == "ENABLED"))
    if not enabled:
        return passed("takeout", "Google Takeout is off", "Data protection")
    return finding("takeout", "Users can export data with Google Takeout", "low", "Data protection",
                   "Takeout lets any user download a full copy of their account data.",
                   "Apps → Additional Google services → Takeout: turn off for users who don't need it.",
                   evidence=enabled, count=len(enabled), reference=f"{CIS}: Takeout")


# --- Gmail and DNS -----------------------------------------------------------------------------

def check_gmail_spoofing(ctx):
    pol = ctx.policy("gmail.spoofing_and_authentication")
    if pol is None:
        return None
    off = [k for k in ("detectDomainNameSpoofing", "detectEmployeeNameSpoofing", "detectDomainSpoofingFromUnauthenticatedSenders",
                       "detectUnauthenticatedEmails", "detectGroupsSpoofing") if pol.get(k) == "False"]
    warn_only = [k for k, v in pol.items() if k.endswith("Consequence") and v == "WARNING"]
    if not off and not warn_only:
        return passed("gmail-spoofing", "Gmail spoofing protections are on and act on messages", "Gmail")
    evidence = [f"{k}: off" for k in off] + [f"{k}: warning only" for k in warn_only]
    return finding("gmail-spoofing", "Gmail spoofing and authentication protections are partial", "medium" if off else "low",
                   "Gmail", "Some protections are off, and others only show a warning banner.",
                   "Apps → Gmail → Safety → Spoofing and authentication: turn every check on and move suspicious "
                   "mail to spam.", evidence=evidence, reference=f"{CIS}: Gmail safety")


def check_gmail_attachments(ctx):
    pol = ctx.policy("gmail.email_attachment_safety")
    if pol is None:
        return None
    off = [k for k in ("enableAnomalousAttachmentProtection", "enableAttachmentWithScriptsProtection",
                       "enableEncryptedAttachmentProtection") if pol.get(k) == "False"]
    warn_only = [k for k, v in pol.items() if k.endswith("Consequence") and v == "WARNING"]
    if not off and not warn_only:
        return passed("gmail-attachments", "Gmail attachment protections are on and act on messages", "Gmail")
    evidence = [f"{k}: off" for k in off] + [f"{k}: warning only" for k in warn_only]
    return finding("gmail-attachments", "Gmail attachment protections are partial", "low", "Gmail",
                   "Some attachment protections are off or only warn.",
                   "Apps → Gmail → Safety → Attachments: turn every protection on and move matches to spam.",
                   evidence=evidence, reference=f"{CIS}: Gmail safety")


def parse_dns(text):
    """Return {name: [txt records]} from the nslookup sections pull.sh writes."""
    records, name = {}, None
    for line in text.splitlines():
        if line.startswith("### "):
            name = line[4:].rsplit(" ", 1)[0].lower()
            records[name] = []
            continue
        if name is None:
            continue
        # Linux prints `text = "..."` on one line; Windows puts the quoted chunks on the next lines.
        if "text =" in line:
            records[name].append("")
        chunks = re.findall(r'"([^"]*)"', line)
        if chunks:
            if not records[name]:
                records[name].append("")
            records[name][-1] += "".join(chunks)
    return records


def check_dns(ctx):
    text = ctx.snap.text("dns.txt")
    if not text:
        return None
    records = parse_dns(text)
    domains = sorted(n for n in records if not n.startswith("_"))
    problems, high = [], False
    for d in domains:
        dmarc = next((r for r in records.get(f"_dmarc.{d}", []) if r.lower().startswith("v=dmarc1")), None)
        spf = next((r for r in records.get(d, []) if r.lower().startswith("v=spf1")), None)
        if not dmarc:
            problems.append(f"{d}: no DMARC record")
            high = True
        else:
            policy = re.search(r"\bp=(\w+)", dmarc, re.I)
            if not policy or policy.group(1).lower() == "none":
                problems.append(f"{d}: DMARC p=none (monitoring only)")
            if "rua=" not in dmarc.lower():
                problems.append(f"{d}: DMARC has no rua= reporting address")
        if not spf:
            problems.append(f"{d}: no SPF record")
            high = True
        elif spf.rstrip().endswith("+all"):
            problems.append(f"{d}: SPF ends in +all")
            high = True
        if not any(r.lower().startswith("v=stsv1") for r in records.get(f"_mta-sts.{d}", [])):
            problems.append(f"{d}: no MTA-STS")
        if not any(r.lower().startswith("v=tlsrptv1") for r in records.get(f"_smtp._tls.{d}", [])):
            problems.append(f"{d}: no TLS-RPT")
    ctx.facts["dns_problems"] = problems
    if not problems:
        return passed("mail-dns", "SPF, DMARC (enforcing), MTA-STS and TLS-RPT present on every domain", "Gmail")
    serious = [p for p in problems if "MTA-STS" not in p and "TLS-RPT" not in p]
    severity = "high" if high else ("medium" if serious else "low")
    return finding("mail-dns", "Mail authentication DNS records are incomplete", severity, "Gmail",
                   "Without an enforcing DMARC policy, anyone can send mail that appears to come from your domain.",
                   "Publish SPF and DKIM, then move DMARC from p=none to quarantine and reject with rua= reports; "
                   "add MTA-STS and TLS-RPT.", evidence=problems, count=len(problems),
                   reference=f"{CIS}: Email authentication (SPF, DKIM, DMARC)")


# --- Devices ------------------------------------------------------------------------------------

def check_mobile(ctx):
    rows = ctx.snap.rows("mobile.csv")
    if rows is None:
        return None
    cutoff = ctx.today - dt.timedelta(days=90)
    stale = [r for r in rows if (parse_time(r.get("lastSync", "")) or cutoff) < cutoff]
    no_lock = [r for r in rows if r.get("devicePasswordStatus") == "Off"]
    compromised = [r for r in rows if r.get("deviceCompromisedStatus", "").lower().startswith("compromised")]
    ctx.facts["mobile_devices"] = len(rows)
    ctx.facts["stale_devices"] = len(stale)
    if not (stale or no_lock or compromised):
        return passed("mobile-devices", f"{len(rows)} mobile device(s), none stale, unlocked or compromised", "Devices")
    evidence = []
    evidence += [f"compromised: {r.get('email', '')} {r.get('model', '')}" for r in compromised]
    evidence += [f"no screen lock: {r.get('email', '')} {r.get('model', '')}" for r in no_lock]
    evidence += [f"no sync since {r.get('lastSync', '')[:10]}: {r.get('email', '')} {r.get('model', '')}" for r in stale]
    severity = "high" if compromised else "low"
    return finding("mobile-devices", f"{len(stale)} stale, {len(no_lock)} unlocked, {len(compromised)} compromised "
                   f"mobile device(s) of {len(rows)}", severity, "Devices",
                   "Stale devices may still hold synced mail; unlocked ones expose it to anyone holding the phone.",
                   "Remove stale devices from the account (Devices → Mobile), and require a screen lock.",
                   evidence=evidence, count=len(stale) + len(no_lock) + len(compromised),
                   reference=f"{CIS}: Mobile device management",
                   edition_note=edition_note(ctx, {"starter": "Business Starter has basic mobile management only: "
                                                   "no remote wipe of the whole device, no app management.",
                                                   "standard": "Business Standard has basic mobile management only "
                                                   "unless advanced management is turned on.",
                                                   "unknown": "Advanced mobile management needs Business Plus or "
                                                   "above."}))


def check_browsers(ctx):
    rows = ctx.snap.rows("browsers.csv")
    if rows is None:
        return None
    if rows:
        return passed("chrome-browsers", f"{len(rows)} Chrome browser(s) enrolled", "Devices")
    return finding("chrome-browsers", "No Chrome browsers are enrolled for management", "info", "Devices",
                   "Without enrollment you can't see or enforce browser extensions and settings.",
                   "Chrome Enterprise Core is free: enroll company browsers and block risky extensions.",
                   reference="Chrome Enterprise Core")


CHECKS = [check_super_admin_2sv, check_2sv_enrollment, check_2sv_enforcement, check_2sv_methods,
          check_super_admin_count, check_super_admin_recovery, check_password_policy, check_dormant_users,
          check_session_length, check_third_party_policy, check_risky_apps, check_dwd_changes,
          check_suspicious_logins, check_login_regions, check_admin_changes, check_public_files,
          check_external_grants, check_shared_drive_settings, check_drive_desktop, check_calendar_sharing,
          check_chat_external, check_groups_external, check_takeout, check_gmail_spoofing,
          check_gmail_attachments, check_dns, check_mobile, check_browsers]


def analyze(folder, edition="unknown", today=None):
    if today is None:
        name = os.path.basename(os.path.normpath(os.path.abspath(folder)))
        try:
            today = dt.date.fromisoformat(name)
        except ValueError:
            today = dt.date.today()
    ctx = Context(Snapshot(folder), edition, today)
    results = [r for r in (check(ctx) for check in CHECKS) if r]
    failures = sorted((r for r in results if r["status"] == "fail"), key=lambda r: SEVERITIES.index(r["severity"]))
    ctx.facts["policies"] = ctx.policy_values
    return {
        "schema": 1,
        "snapshot_date": today.isoformat(),
        "edition": edition,
        "counts": dict(collections.Counter(r["severity"] for r in failures)),
        "findings": failures,
        "passed": [r for r in results if r["status"] == "pass"],
        "not_checked": sorted(ctx.snap.missing),
        "facts": ctx.facts,
    }


def render_markdown(result):
    edition = EDITION_NAMES.get(result["edition"], result["edition"])
    out = [f"# Google Workspace security gap report", "",
           f"- **Snapshot:** {result['snapshot_date']}",
           f"- **Edition:** {edition}",
           "- **Method:** read-only GAM pull + Drive metadata inventory + public DNS",
           "", "Severity: 🔴 critical/high: act this week · 🟠 medium: act this month · 🟡 low: hardening · "
           "🔵 info: review", "", "## Summary", "", "| # | Finding | Severity | Category |", "|---|---|---|---|"]
    for i, f in enumerate(result["findings"], 1):
        out.append(f"| {i} | {f['title']} | {ICONS[f['severity']]} {f['severity']} | {f['category']} |")
    for i, f in enumerate(result["findings"], 1):
        out += ["", f"## {ICONS[f['severity']]} {i}. {f['title']}", "", f["detail"], ""]
        if f["evidence"]:
            out += [f"- {e}" for e in f["evidence"]]
            if f["evidence_total"] > len(f["evidence"]):
                out.append(f"- … and {f['evidence_total'] - len(f['evidence'])} more")
            out.append("")
        out.append(f"**Fix:** {f['recommendation']}")
        if f.get("edition_note"):
            out += ["", f"**Edition note:** {f['edition_note']}"]
        if f.get("reference"):
            out += ["", f"*Reference: {f['reference']}*"]
    if result["passed"]:
        out += ["", "## ✅ Already good", ""] + [f"- {p['title']}" for p in result["passed"]]
    if result["not_checked"]:
        out += ["", "## Not checked (input missing)", ""] + [f"- {n}" for n in result["not_checked"]]
    return "\n".join(out) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("snapshot_dir")
    parser.add_argument("--edition", choices=EDITIONS, default=os.environ.get("GWS_EDITION", "unknown"))
    parser.add_argument("--today", type=dt.date.fromisoformat, help="evaluate as of this date (default: folder name)")
    args = parser.parse_args()
    result = analyze(args.snapshot_dir, args.edition, args.today)
    with open(os.path.join(args.snapshot_dir, "findings.json"), "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, sort_keys=True)
    report = render_markdown(result)
    with open(os.path.join(args.snapshot_dir, "gap-report.md"), "w", encoding="utf-8") as fh:
        fh.write(report)
    sys.stdout.reconfigure(encoding="utf-8")
    print(report)


if __name__ == "__main__":
    main()
