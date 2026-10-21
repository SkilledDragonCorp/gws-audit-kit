"""Generate the two fake snapshots in tests/fixtures/. Every value is synthetic (example.com, RFC 2606).

Usage: python -I tests/make_fixtures.py
"""
import csv
import os

HERE = os.path.dirname(os.path.abspath(__file__))
D = "example.com"


def write(folder, name, header, rows):
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, name), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(header)
        w.writerows(rows)


def users(snap):
    # name, admin, 2sv (A, B), last login, created
    people = [
        ("admin", True, (True, True), "2026-01-30", "2021-03-01"),
        ("alex", True, (True, True), "2026-01-31", "2021-03-01"),
        ("blake", False, (False, True), "2026-01-29", "2022-06-10"),
        ("casey", False, (False, False), "2026-01-28", "2022-06-10"),
        ("devon", False, (True, True), "2026-01-27", "2023-01-15"),
        ("emery", False, (False, False), "2026-01-02", "2023-01-15"),
        ("frankie", False, (True, True), "2026-01-30", "2024-02-20"),
        ("frontdesk", False, (False, False), "2025-06-01", "2020-05-05"),
        ("gray", snap == "B", (True, True), "2026-01-30", "2025-11-01"),
    ]
    i = 0 if snap == "A" else 1
    rows = [[f"{n}@{D}", n.capitalize() + " Example", str(adm), "False", str(tsv[i]), str(tsv[i]),
             f"{last}T10:00:00Z", f"{created}T09:00:00Z", "False", "False", "/"]
            for n, adm, tsv, last, created in people]
    rows.append([f"former@{D}", "Former Example", "False", "False", "False", "False", "2025-02-01T10:00:00Z",
                 "2020-01-01T09:00:00Z", "True", "False", "/"])
    return rows


POLICY_COLUMNS = ["name", "customer", "policyQuery.group", "policyQuery.orgUnitPath", "policyQuery.sortOrder",
                  "setting.type"]


def policies(snap):
    root = [
        ("security.two_step_verification_enforcement", {"enforcedFrom": "2026-02-10T08:00:00Z"}),
        ("security.two_step_verification_enforcement_factor", {"allowedSignInFactorSet": "ALL"}),
        ("security.two_step_verification_device_trust", {"allowTrustingDevice": "True"}),
        ("security.super_admin_account_recovery", {"enableAccountRecovery": "True" if snap == "A" else "False"}),
        ("security.password", {"minimumLength": "8", "enforceRequirementsAtLogin": "False", "allowReuse": "False",
                               "allowedStrength": "STRONG", "maximumLength": "100", "expirationDuration": "0s"}),
        ("security.session_controls", {"webSessionDuration": "1209600s"}),
        ("api_controls.unconfigured_third_party_apps", {"accessLevel": "ACCESS_LEVEL_UNSPECIFIED"}),
        ("calendar.primary_calendar_max_allowed_external_sharing",
         {"maxAllowedExternalSharing": "EXTERNAL_ALL_INFO_READ_WRITE_MANAGE" if snap == "A" else "EXTERNAL_FREE_BUSY_ONLY"}),
        ("chat.chat_external_spaces", {"enabled": "True", "domainAllowlistMode": "ALL_DOMAINS"}),
        ("groups_for_business.groups_sharing", {"ownersCanAllowExternalMembers": "True",
                                                "ownersCanAllowIncomingMailFromPublic": "True",
                                                "collaborationCapability": "DOMAIN_USERS_ONLY"}),
        ("drive_and_docs.shared_drive_creation", {"allowNonMemberAccess": "True", "allowExternalUserAccess": "True",
                                                  "allowManagersToOverrideSettings": "False"}),
        ("drive_and_docs.drive_for_desktop", {"allowDriveForDesktop": "True", "restrictToAuthorizedDevices": "False"}),
        ("gmail.spoofing_and_authentication", {"detectDomainNameSpoofing": "True", "detectEmployeeNameSpoofing": "True",
                                               "detectDomainSpoofingFromUnauthenticatedSenders": "True",
                                               "detectUnauthenticatedEmails": "False", "detectGroupsSpoofing": "False",
                                               "domainSpoofingConsequence": "WARNING"}),
        ("gmail.email_attachment_safety", {"enableAnomalousAttachmentProtection": "True",
                                           "enableAttachmentWithScriptsProtection": "True",
                                           "enableEncryptedAttachmentProtection": "True",
                                           "anomalousAttachmentProtectionConsequence": "SPAM_FOLDER"}),
        ("takeout.service_status", {"serviceState": "ENABLED"}),
        ("photos.user_takeout", {"takeoutStatus": "ENABLED"}),
    ]
    rows = [(kind, "", "/", vals) for kind, vals in root]
    rows.append(("security.two_step_verification_enforcement", "groups/00fakegroup01", "",
                 {"enforcedFrom": "2026-01-01T08:00:00Z"}))
    keys = sorted({k for *_, vals in rows for k in vals})
    header = POLICY_COLUMNS + [f"setting.value.{k}" for k in keys]
    out = []
    for i, (kind, group, ou, vals) in enumerate(rows):
        out.append([f"policies/fake{i:03d}", "customers/C00fake00", group, ou, str(i), f"settings/{kind}"]
                   + [vals.get(k, "") for k in keys])
    return header, out


def tokens(snap):
    rows = [
        ["authorize", f"alex@{D}", "Google Chrome", "100000000000-fake.apps.googleusercontent.com", "NATIVE_DESKTOP",
         "2026-01-03T10:00:00Z", "https://www.googleapis.com/auth/drive"],
        ["authorize", f"blake@{D}", "Acme Mail Assistant", "100000000001-fake.apps.googleusercontent.com", "WEB",
         "2026-01-04T10:00:00Z", "https://mail.google.com/ openid"],
        ["authorize", f"casey@{D}", "Acme Mail Assistant", "100000000001-fake.apps.googleusercontent.com", "WEB",
         "2026-01-04T11:00:00Z", "https://mail.google.com/"],
        ["authorize", f"devon@{D}", "Example Scheduler", "100000000002-fake.apps.googleusercontent.com", "WEB",
         "2025-12-20T10:00:00Z", "https://www.googleapis.com/auth/calendar.readonly"],
    ]
    if snap == "B":
        rows.append(["authorize", f"frankie@{D}", "Sample PDF Toolkit", "100000000003-fake.apps.googleusercontent.com",
                     "WEB", "2026-01-25T10:00:00Z", "https://www.googleapis.com/auth/drive"])
    rows.append(["revoke", f"devon@{D}", "Example Scheduler", "100000000002-fake.apps.googleusercontent.com", "WEB",
                 "2026-01-05T09:00:00Z", ""])
    return rows


def logins(snap):
    rows = [["login_success", f"{u}@{D}", "2026-01-20T08:00:00Z", "US", "google_password", "False"]
            for u in ("admin", "alex", "blake", "casey", "devon", "frankie")]
    rows += [["login_success", f"alex@{D}", "2026-01-21T08:00:00Z", "DE", "google_password", "False"],
             ["login_failure", f"casey@{D}", "2026-01-22T08:00:00Z", "US", "google_password", "False"]]
    if snap == "B":
        rows.append(["suspicious_login", f"casey@{D}", "2026-01-29T03:12:00Z", "ZZ", "google_password", "True"])
    return rows


def admin_audit(snap):
    rows = [["CHANGE_TWO_STEP_VERIFICATION_START_DATE", f"admin@{D}", "2025-12-15T10:00:00Z", "", "", "", "", "", "", ""]]
    if snap == "B":
        rows += [["ASSIGN_ROLE", f"admin@{D}", "2026-01-26T10:00:00Z", "_SEED_ADMIN_ROLE", "", f"gray@{D}", "", "", "", ""],
                 ["AUTHORIZE_API_CLIENT_ACCESS", f"alex@{D}", "2026-01-27T10:00:00Z", "", "", "",
                  "Example Backup Service", "https://www.googleapis.com/auth/drive.readonly", "", ""]]
    return rows


def mobile(snap):
    rows = [[f"devon@{D}", "Pixel 9", "ANDROID", "APPROVED", "2026-01-30T08:00:00Z", "On", "No compromise detected", "Encrypted"],
            [f"blake@{D}", "iPhone 16", "IOS_SYNC", "APPROVED", "2026-01-29T08:00:00Z", "Off", "Undetected", ""],
            [f"frontdesk@{D}", "iPhone 11", "IOS_SYNC", "APPROVED", "2025-05-30T08:00:00Z", "On", "Undetected", ""]]
    return rows


def drive(snap):
    def url(fid):
        return f"https://docs.google.com/document/d/{fid}/edit"
    public = [[f"alex@{D}", "True", "", "1FAKEpublic0001", "application/vnd.google-apps.document", "Team handbook",
               "2024-01-01", "2025-11-01", url("1FAKEpublic0001")],
              [f"blake@{D}", "True", "", "1FAKEpublic0002", "application/vnd.google-apps.spreadsheet", "Price list",
               "2024-03-01", "2025-12-01", url("1FAKEpublic0002")],
              ["partner@example.org", "False", "", "1FAKEexternal01", "application/pdf", "Partner brochure",
               "2024-03-01", "2025-12-01", url("1FAKEexternal01")]]
    if snap == "B":
        public.append([f"frankie@{D}", "True", "", "1FAKEpublic0003", "application/vnd.google-apps.document",
                       "Draft budget 2026", "2026-01-20", "2026-01-28", url("1FAKEpublic0003")])
    external = [[f"alex@{D}", "1FAKEshare0001", "Joint proposal", "application/vnd.google-apps.document", "user",
                 "writer", "contact@example.org", "2026-01-10", url("1FAKEshare0001")],
                [f"blake@{D}", "1FAKEshare0002", "Q4 receipts", "application/vnd.google-apps.spreadsheet", "user",
                 "reader", "someone@gmail.com", "2025-12-10", url("1FAKEshare0002")]]
    if snap == "B":
        external.append([f"casey@{D}", "1FAKEshare0003", "Roadmap", "application/vnd.google-apps.presentation",
                         "domain", "reader", "example.net", "2026-01-20", url("1FAKEshare0003")])
    return public, external


def dns(snap):
    dmarc = "v=DMARC1; p=none" if snap == "A" else "v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@example.com"
    return "\n".join([
        f"### {D} TXT", "Non-authoritative answer:", f"{D}\ttext =", "", '\t"v=spf1 include:_spf.google.com ~all"', "",
        f"### _dmarc.{D} TXT", "Non-authoritative answer:", f"_dmarc.{D}\ttext =", "", f'\t"{dmarc}"', "",
        f"### _mta-sts.{D} TXT", f"*** UnKnown can't find _mta-sts.{D}: Non-existent domain", "",
        f"### _smtp._tls.{D} TXT", f"*** UnKnown can't find _smtp._tls.{D}: Non-existent domain", "",
    ])


def make(snap, date):
    folder = os.path.join(HERE, "fixtures", date)
    write(folder, "users.csv", ["primaryEmail", "name.fullName", "isAdmin", "isDelegatedAdmin", "isEnrolledIn2Sv",
                                "isEnforcedIn2Sv", "lastLoginTime", "creationTime", "suspended", "archived",
                                "orgUnitPath"], users(snap))
    admins = [["fake-ra-1", "fake-role-1", "_SEED_ADMIN_ROLE", "100000000000000000001", f"admin@{D}", "CUSTOMER"],
              ["fake-ra-2", "fake-role-1", "_SEED_ADMIN_ROLE", "100000000000000000002", f"alex@{D}", "CUSTOMER"]]
    if snap == "B":
        admins.append(["fake-ra-3", "fake-role-1", "_SEED_ADMIN_ROLE", "100000000000000000009", f"gray@{D}", "CUSTOMER"])
    write(folder, "admins.csv", ["roleAssignmentId", "roleId", "role", "assignedTo", "assignedToUser", "scopeType"], admins)
    write(folder, "domains.csv", ["domainName", "parentDomainName", "creationTime", "type", "verified"],
          [[D, "", "2020-01-01T00:00:00Z", "primary", "True"]])
    write(folder, "domainaliases.csv", ["domainAliasName", "parentDomainName", "creationTime", "verified"], [])
    write(folder, "orgunits.csv", ["orgUnitPath", "orgUnitId", "name", "description", "parentOrgUnitPath"],
          [["/Staff", "id:00fakeou", "Staff", "", "/"]])
    write(folder, "groups.csv", ["email", "name", "directMembersCount", "adminCreated"],
          [[f"team@{D}", "Team", "7", "True"]])
    header, rows = policies(snap)
    write(folder, "policies.csv", header, rows)
    write(folder, "mobile.csv", ["email", "model", "type", "status", "lastSync", "devicePasswordStatus",
                                 "deviceCompromisedStatus", "encryptionStatus"], mobile(snap))
    write(folder, "browsers.csv", ["deviceId"], [["fake-browser-1"]] if snap == "B" else [])
    write(folder, "tokens_audit.csv", ["name", "actor.email", "app_name", "client_id", "client_type", "id.time", "scope"],
          tokens(snap))
    write(folder, "login_audit.csv", ["name", "actor.email", "id.time", "networkInfo.regionCode", "login_type",
                                      "is_suspicious"], logins(snap))
    write(folder, "admin_audit.csv", ["name", "actor.email", "id.time", "ROLE_NAME", "SETTING_NAME", "USER_EMAIL",
                                      "API_CLIENT_NAME", "API_SCOPES", "OLD_VALUE", "NEW_VALUE"], admin_audit(snap))
    public, external = drive(snap)
    write(folder, "drive_link_shared_full.csv", ["owner", "internal_owner", "shared_drive_id", "file_id", "type", "name",
                                                 "created", "modified", "url"], public)
    write(folder, "drive_external_shares.csv", ["owner", "file_id", "name", "type", "grantee_type", "role", "grantee",
                                                "modified", "url"], external)
    with open(os.path.join(folder, "dns.txt"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(dns(snap))


if __name__ == "__main__":
    make("A", "2026-01-05")
    make("B", "2026-02-02")
    print("fixtures written to tests/fixtures/")
