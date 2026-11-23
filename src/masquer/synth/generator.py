"""Synthetic Defender XDR advanced-hunting exports for tests and benchmarks.

Columns come from the schema extracted from Microsoft Learn
(`masquer/schema/defender_tables.json`); values come from `values.Faker`.
Each run writes one file per table plus `canaries.json`, the list of every
sensitive value planted, for leak tests.
"""
from __future__ import annotations

import csv
import io
import json
import random
import re
from datetime import datetime, timedelta, timezone
from importlib import resources
from pathlib import Path

from .values import CITIES, Faker

# Common ActionType values per table. Docs pages list only a few; these are
# well-known values from the portal schema reference (not from the extracted
# pages), used only to make synthetic data realistic.
COMMON_ACTIONS = {
    "DeviceProcessEvents": ["ProcessCreated", "OpenProcessApiCall"],
    "DeviceNetworkEvents": ["ConnectionSuccess", "ConnectionFailed", "InboundConnectionAccepted",
                            "ListeningConnectionCreated", "ConnectionRequest"],
    "DeviceLogonEvents": ["LogonSuccess", "LogonFailed", "LogonAttempted"],
    "DeviceFileEvents": ["FileCreated", "FileModified", "FileDeleted", "FileRenamed"],
    "DeviceRegistryEvents": ["RegistryValueSet", "RegistryKeyCreated", "RegistryKeyDeleted",
                             "RegistryValueDeleted"],
    "DeviceImageLoadEvents": ["ImageLoaded"],
    "DeviceEvents": ["AntivirusDetection", "PowerShellCommand", "ScheduledTaskCreated",
                     "UsbDriveMounted", "DnsQueryResponse", "ProcessCreatedUsingWmiQuery",
                     "ExploitGuardNetworkProtectionBlocked", "SmartScreenUrlWarning"],
    "IdentityLogonEvents": ["LogonSuccess", "LogonFailed"],
    "IdentityDirectoryEvents": ["Account Password changed", "Group Membership changed",
                                "Account enabled"],
    "IdentityQueryEvents": ["LDAP query", "DNS query", "SAMR query"],
    "CloudAppEvents": ["FileDownloaded", "MailItemsAccessed", "New-InboxRule", "UserLoggedIn"],
}

DYNAMIC_BUILDERS = ("AdditionalFields", "Fields", "Details", "Properties")


def load_schema() -> dict:
    text = resources.files("masquer.schema").joinpath("defender_tables.json").read_text("utf-8")
    return json.loads(text)


class Generator:
    def __init__(self, seed: int = 1, start: datetime | None = None):
        self.rng = random.Random(seed)
        self.fake = Faker(self.rng)
        self.start = start or datetime(2026, 11, 1, 8, 0, tzinfo=timezone.utc)

    # --- per-column values ------------------------------------------------

    def value(self, table: str, actions: list[str], name: str, typ: str, ts: datetime):
        f, n = self.fake, name.lower()
        if typ == "datetime":
            return (ts if n == "timestamp" else ts - timedelta(seconds=self.rng.randint(0, 86400))) \
                .strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"
        if typ == "bool":
            return self.rng.random() < 0.3
        if typ == "float":
            return round(self.rng.uniform(0, 100), 3)
        if typ == "int":
            if n.endswith("port"):
                return self.rng.choice([22, 53, 80, 135, 389, 443, 445, 3389, 5985, 8080, self.rng.randint(49152, 65535)])
            if n == "reportid":
                return self.rng.randint(1, 10**9)
            return self.rng.randint(0, 5000)
        if typ == "dynamic" or n.endswith(DYNAMIC_BUILDERS):
            return json.dumps(self.dynamic(), ensure_ascii=False, separators=(",", ":"))
        if typ == "guid":
            return f.uuid()
        return self.string(table, actions, name, n)

    def string(self, table: str, actions: list[str], name: str, n: str):
        f = self.fake
        # (pattern, match on original-case name?, factory). First match wins.
        rules = [
            (r"^actiontype$", False, lambda: self.rng.choice(actions) if actions else "Event"),
            (r"tenantid$", False, f.tenant_id),
            (r"(sha1|signerhash)$", False, lambda: f.hex(40)),
            (r"sha256$", False, lambda: f.hex(64)),
            (r"md5$", False, lambda: f.hex(32)),
            (r"^deviceid$|machineid$", False, f.device_id),
            (r"(IP|Ip)(v4|v6|Address|Addresses)?$", True, f.ip),
            (r"MacAddress$", True, f.mac),
            (r"(DeviceName|HostName|NodeName|ComputerName)$", True, f.device_name),
            (r"(Account|User|Cloud|OnPrem)?Sid$", True, f.sid),
            (r"ProcessId$", True, lambda: str(self.rng.randint(4, 65000))),
            (r"(accountobjectid|objectid|userid|aadid)$", False, f.object_id),
            (r"(upn|userprincipalname|signinname)$", False, f.upn),
            (r"(emailaddress|^accountemail|alternateemails|fromaddress|toaddress|^cc|^bcc)$", False, f.email),
            (r"(accountdomain|domainname)$", False, f.netbios),
            (r"(displayname|^givenname|^surname|^manager|username)$", False, f.full_name),
            (r"accountname$", False, f.sam),
            (r"loggedonusers$", False, f.logged_on_users),
            (r"distinguishedname$", False, f.distinguished_name),
            (r"serviceprincipalname$", False, lambda: f"HTTP/{f.device_name()}"),
            (r"(sharename|printername)$", False, lambda: f"\\\\{f.device_name()}\\{self.rng.choice(['HR', 'Finance', 'Scans'])}"),
            (r"(url|uri)$", False, f.url),
            (r"(dnsquery|^query|querytarget|dnsaddresses)$", False, f.dns_query),
            (r"commandline$", False, f.command_line),
            (r"(folderpath|filepath|^path)$", False, lambda: f.user_path(f.file_name())),
            (r"FileName$", True, f.file_name),
            (r"ProcessName$", True, f.file_name),
            (r"(registrykey)$", False, lambda: f"HKEY_USERS\\{f.sid()}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
            (r"(phone\w*|mobile)$", False, f.phone),
            (r"^(address|streetaddress)$", False, f.postal_address),
            (r"versioninfocompanyname$", False, lambda: self.rng.choice(["Microsoft Corporation", "Google LLC", "Unknown"])),
            (r"^companyname$", False, f.customer_company),
            (r"(storageaccount|vaultname|resourcegroup|resourcename|awsresourcename|gcpfullresourcename|"
             r"kubernetesnamespace|kubernetespodname|containername|cloudresource|machinegroup|^site)$", False, f.cloud_resource),
            (r"(teamschannelname|teamsteamname|threadname|groupname)$", False,
             lambda: f"{self.rng.choice(['Finance', 'HR', 'Board', 'IT-Ops'])} {f.customer_company()}"),
            (r"useragent\w*$", False, f.user_agent),
            (r"city$", False, lambda: self.rng.choice(CITIES)[0]),
            (r"(country\w*|region)$", False, lambda: self.rng.choice(CITIES)[1]),
            (r"(location|sourcelocation)$", False, lambda: self.rng.choice(CITIES)[0]),
            (r"(subject|description|title|snippet|message|reason|comment)$", False, f.free_text),
            (r"domain$", False, f.domain),
            (r"osplatform$", False, lambda: self.rng.choice(["Windows11", "Windows10", "WindowsServer2022", "macOS", "Linux"])),
            (r"severity$", False, lambda: self.rng.choice(["Low", "Medium", "High", "Informational"])),
            (r"id$", False, f.uuid),
        ]
        for pattern, case_sensitive, make in rules:
            if re.search(pattern, name if case_sensitive else n):
                return make()
        # Unknown string column: mostly harmless text, sometimes PII.
        if self.rng.random() < 0.15:
            return f.free_text()
        return self.rng.choice(["Unknown", "Default", "Enabled", "None", f.hex(6)])

    def dynamic(self) -> dict:
        f = self.fake
        return self.rng.choice([
            lambda: {"Command": f.command_line(), "InitiatedBy": f.upn()},
            lambda: {"RemoteMachine": f.device_name(), "IpAddress": f.ip(), "Port": 445},
            lambda: {"Mailbox": f.email(), "Phone": f.phone(), "Note": f.free_text()},
            lambda: {"Entities": [{"Type": "account", "Name": f.sam(), "Sid": f.sid()},
                                  {"Type": "ip", "Address": f.ip()}]},
            lambda: {"Payment": {"Iban": f.iban(), "Org": f.orgnr_se()}, "Pnr": f.national_id()},
        ])()

    # --- rows -----------------------------------------------------------------

    def rows(self, table: str, spec: dict, count: int, dup_rate: float):
        actions = spec["action_types"] or COMMON_ACTIONS.get(table, [])
        cols = spec["columns"]
        ts = self.start
        out = []
        while len(out) < count:
            ts += timedelta(seconds=self.rng.randint(1, 900), microseconds=self.rng.randint(0, 999999))
            row = {c["name"]: self.value(table, actions, c["name"], c["type"], ts) for c in cols}
            out.append(row)
            # Exact repeats (only Timestamp differs) to test event collapsing:
            # most within 1 h of each other, some beyond it.
            if dup_rate and self.rng.random() < dup_rate:
                rep_ts = ts
                for _ in range(self.rng.randint(1, 4)):
                    if len(out) >= count:
                        break
                    gap = self.rng.randint(60, 3000) if self.rng.random() < 0.8 else self.rng.randint(3700, 9000)
                    rep_ts += timedelta(seconds=gap)
                    rep = dict(row)
                    if "Timestamp" in rep:
                        rep["Timestamp"] = rep_ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"
                    out.append(rep)
        return out


def write_csv(path: Path, rows: list[dict], encoding: str) -> None:
    buf = io.StringIO(newline="")
    w = csv.DictWriter(buf, fieldnames=list(rows[0]), lineterminator="\r\n")
    w.writeheader()
    for r in rows:
        w.writerow({k: ("true" if v is True else "false" if v is False else v) for k, v in r.items()})
    data = buf.getvalue()
    if encoding == "utf-16":
        path.write_bytes(data.encode("utf-16"))  # with BOM
    else:
        path.write_bytes(b"\xef\xbb\xbf" + data.encode("utf-8"))


def generate(out_dir: Path, tables: list[str] | None = None, rows: int = 50, seed: int = 1,
             fmt: str = "csv", encoding: str = "utf-8", dup_rate: float = 0.1) -> dict:
    schema = load_schema()
    names = tables or sorted(schema["tables"])
    unknown = [t for t in names if t not in schema["tables"]]
    if unknown:
        raise SystemExit(f"unknown table(s): {', '.join(unknown)}")
    out_dir.mkdir(parents=True, exist_ok=True)
    gen = Generator(seed)
    written = {}
    for t in names:
        data = gen.rows(t, schema["tables"][t], rows, dup_rate)
        if fmt == "json":
            p = out_dir / f"{t}.json"
            p.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
        else:
            p = out_dir / f"{t}.csv"
            write_csv(p, data, encoding)
        written[t] = len(data)
    canaries = {k: sorted(v) for k, v in sorted(gen.fake.canaries.items())}
    (out_dir / "canaries.json").write_text(
        json.dumps({"seed": seed, "tables": written, "canaries": canaries}, ensure_ascii=False, indent=1),
        encoding="utf-8")
    return {"tables": written, "canaries": sum(len(v) for v in canaries.values())}
