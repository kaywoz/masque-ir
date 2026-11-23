"""Deterministic detectors: which columns hold identities, and which spans of
free text are identifiers. No model involved; the local model (later) can
only add spans, never remove them.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import date

# --- columns ------------------------------------------------------------------

# Whole-value tokenisation: (pattern on the column name, token kind,
# case-sensitive?). First match wins. Anything not matched and not in KEEP is
# scanned as free text, so the default is the safe one.
COLUMN_RULES: list[tuple[str, str, bool]] = [
    (r"tenantid$", "TENANT", False),
    (r"^deviceid$|machineid$|aaddeviceid$|entraiddeviceid$", "DEVICE_ID", False),
    (r"(DeviceName|HostName|NodeName|ComputerName)$", "HOST", True),
    (r"(Account|User|Cloud|OnPrem)?Sid$", "SID", True),
    (r"(accountobjectid|objectid|userid|aadid)$", "OBJECT_ID", False),
    (r"(upn|userprincipalname|signinname)$", "UPN", False),
    (r"(emailaddress|^accountemail|alternateemails|fromaddress|toaddress|^cc|^bcc)$", "EMAIL", False),
    (r"(accountdomain|domainname)$", "DOMAIN", False),
    (r"(displayname|^givenname|^surname|^manager|username)$", "PERSON", False),
    (r"accountname$", "ACCOUNT", False),
    (r"distinguishedname$", "DN", False),
    (r"(IP|Ip)(v4|v6|Address|Addresses)?$", "IP", True),
    (r"MacAddress$", "MAC", True),
    (r"(phone\w*|mobile)$", "PHONE", False),
    (r"^(address|streetaddress)$", "ADDRESS", False),
    (r"^companyname$", "ORG", False),
    (r"(storageaccount|vaultname|resourcegroup|resourcename|awsresourcename|gcpfullresourcename|"
     r"kubernetesnamespace|kubernetespodname|containername|cloudresource|machinegroup|^site|"
     r"teamschannelname|teamsteamname|threadname|groupname|sharename|printername|"
     r"serviceprincipalname|subscriptionid|resourceid)$", "RESOURCE", False),
    (r"(recipientdomain|senderfromdomain|sendermailfromdomain|urldomain)$", "DOMAIN", False),
]

# Columns kept as they are. Deliberately short: every other string column is
# scanned as free text, because exports can carry free text in unexpected
# columns (descriptions, version info, failure reasons).
KEEP = re.compile(r"^(timestamp|actiontype|.*sha1|.*sha256|.*md5)$", re.IGNORECASE)


def column_kind(name: str) -> str | None:
    """Token kind for whole-value tokenisation, "keep", or None for free text."""
    if KEEP.match(name):
        return "keep"
    for pattern, kind, cs in COLUMN_RULES:
        if re.search(pattern, name if cs else name.lower()):
            return kind
    return None


# --- validators ---------------------------------------------------------------

def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _date_ok(dd: int, mm: int, yy: int) -> bool:
    for century in (1900, 2000):
        try:
            date(century + yy, mm, dd)
            return True
        except ValueError:
            pass
    return False


def se_personnummer(s: str) -> bool:
    d = re.sub(r"[-+]", "", s)
    if len(d) == 12:
        d = d[2:]
    if len(d) != 10 or not d.isdigit():
        return False
    yy, mm, dd = int(d[0:2]), int(d[2:4]), int(d[4:6])
    if dd > 60:  # samordningsnummer
        dd -= 60
    return _date_ok(dd, mm, yy) and luhn_ok(d)


def se_orgnr(s: str) -> bool:
    d = s.replace("-", "")
    return len(d) == 10 and d.isdigit() and int(d[2]) >= 2 and luhn_ok(d)


def no_fodselsnummer(s: str) -> bool:
    if len(s) != 11 or not s.isdigit():
        return False
    w1, w2 = [3, 7, 6, 1, 8, 9, 4, 5, 2, 1], [5, 4, 3, 2, 7, 6, 5, 4, 3, 2, 1]
    return (_date_ok(int(s[0:2]) % 40, int(s[2:4]) % 40, int(s[4:6]))
            and sum(int(a) * b for a, b in zip(s, w1)) % 11 == 0
            and sum(int(a) * b for a, b in zip(s, w2)) % 11 == 0)


def dk_cpr(s: str) -> bool:
    d = s.replace("-", "")
    return len(d) == 10 and d.isdigit() and _date_ok(int(d[0:2]), int(d[2:4]), int(d[4:6]))


def fi_hetu(s: str) -> bool:
    m = re.fullmatch(r"(\d{6})[-+A-FU-Y](\d{3})([0-9A-Y])", s)
    if not m:
        return False
    if not _date_ok(int(m.group(1)[0:2]), int(m.group(1)[2:4]), int(m.group(1)[4:6])):
        return False
    return "0123456789ABCDEFHJKLMNPRSTUVWXY"[int(m.group(1) + m.group(2)) % 31] == m.group(3)


def iban_ok(s: str) -> bool:
    s = s.replace(" ", "").upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{10,30}", s):
        return False
    return int("".join(str(int(c, 36)) for c in s[4:] + s[:4])) % 97 == 1


# --- free-text detectors ------------------------------------------------------
# (kind, regex, validator or None). Applied in order to text outside tokens.

FILE_EXT = ("exe|dll|ps1|psm1|js|vbs|bat|cmd|msi|lnk|sys|tmp|log|json|xml|csv|txt|pdf|"
            "docx?|docm|xlsx?|xlsm|pptx?|zip|7z|rar|iso|png|jpe?g|gif|dat|ini|cfg|php|html?|"
            "aspx?|py|sh|jar|hta|scr|cpl|ocx|tar|gz")

DETECTORS: list[tuple[str, re.Pattern, object]] = [
    ("EMAIL", re.compile(r"[\w.+'-]+@[\w-]+(?:\.[\w-]+)+", re.UNICODE), None),
    ("SID", re.compile(r"\bS-1-5-21(?:-\d+){3,4}\b"), None),
    ("GUID", re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), None),
    ("IBAN", re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b"), iban_ok),
    ("NATIONAL_ID", re.compile(r"(?<![\w-])(?:\d{2})?\d{6}[-+]?\d{4}(?![\w-])"), se_personnummer),
    ("ORG_ID", re.compile(r"(?<![\w-])\d{6}-?\d{4}(?![\w-])"), se_orgnr),
    ("NATIONAL_ID", re.compile(r"(?<![\w-])\d{11}(?![\w-])"), no_fodselsnummer),
    ("NATIONAL_ID", re.compile(r"(?<![\w-])\d{6}-\d{4}(?![\w-])"), dk_cpr),
    ("NATIONAL_ID", re.compile(r"(?<![\w])\d{6}[-+A-FU-Y]\d{3}[0-9A-Y](?![\w])"), fi_hetu),
    ("NATIONAL_ID", re.compile(r"\b(?!BG|GB|NK|KN|TN|NT|ZZ)[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\d{6}[A-D]\b"), None),
    ("NATIONAL_ID", re.compile(r"(?<![\d-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\d-])"), None),
    ("PHONE", re.compile(r"(?<![\w+])\+\d{1,3}(?:[ .-]?\d{1,4}){2,6}(?!\d)"), None),
    ("MAC", re.compile(r"\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b"), None),
    ("IP", re.compile(r"(?<![\w:.])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F:]*[0-9a-fA-F](?![\w:])"), None),
    ("IP", re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"), None),
]

URL_RE = re.compile(r"\b(?:https?|ftp|hxxps?)://[^\s\"'<>|]+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"(?<![\w.@-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24}))(?![\w-]|\.\w)",
                       re.IGNORECASE)
USERPATH_RE = re.compile(r"(?i)(\\Users\\|/Users/|/home/)([^\\/\s\"']+)")
UNC_RE = re.compile(r"(?<![\w:\\])\\\\([A-Za-z0-9][\w.-]*)\\")
SINGLE_EXT = re.compile(rf"^[^.]+\.(?:{FILE_EXT})$", re.IGNORECASE)
SYSTEM_PROFILES = {"public", "default", "all users", "default user", "administrator"}


def ip_kind(s: str) -> str | None:
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return None
    if ip.is_loopback or ip.is_unspecified or ip.is_link_local or ip.is_multicast:
        return "keep"
    return "IP_PRIV" if ip.is_private and not ip.is_global and not str(ip).startswith(("192.0.2.", "198.51.100.", "203.0.113.")) and not s.startswith("2001:db8") else "IP_PUB"


def is_domain_candidate(s: str) -> bool:
    """A dotted name that's a host or domain rather than a file name or version."""
    if SINGLE_EXT.match(s):
        return False
    if re.fullmatch(r"[\d.]+", s):
        return False
    return True
