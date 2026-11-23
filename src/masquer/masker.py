"""Pseudonymise and defang rows: column rules first, then free-text detectors,
then a sweep for every original already in the mapping store or deny-lists.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from . import detect
from .store import TOKEN_RE, Store
from .triere import compile_literals

# Provably not the customer's: vendor and public-service domains.
BUILTIN_ALLOW = {
    "microsoft.com", "windows.com", "windowsupdate.com", "office.com", "office365.com",
    "microsoftonline.com", "live.com", "outlook.com", "sharepoint.com", "azure.com",
    "azureedge.net", "azure.net", "msftncsi.com", "msedge.net", "bing.com", "akamaiedge.net",
    "google.com", "googleapis.com", "gstatic.com", "github.com", "githubusercontent.com",
    "apple.com", "icloud.com", "amazonaws.com", "cloudflare.com", "digicert.com",
}
BLOB_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{64,}={0,2}(?![A-Za-z0-9+/=])|\b[0-9a-fA-F]{129,}\b")
CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def load_list(*paths: Path) -> set[str]:
    out: set[str] = set()
    for p in paths:
        if p and p.is_file():
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    out.add(line)
    return out


class Masker:
    def __init__(self, store: Store, deny: set[str] = frozenset(), allow: set[str] = frozenset(), ner=None):
        self.store = store
        self.ner = ner  # NameDetector or None
        self.allow = {d.casefold() for d in (BUILTIN_ALLOW | set(allow))}
        for v in deny:
            store.token("DENY", v)
        self._sweep = None
        self._sweep_size = -1

    # --- helpers --------------------------------------------------------------

    def allowed_domain(self, host: str) -> bool:
        h = host.casefold().rstrip(".")
        return any(h == d or h.endswith("." + d) for d in self.allow)

    def tok(self, kind: str, value: str) -> str:
        return self.store.token(kind, value)

    def _segments(self, text: str):
        """Yield (is_token, segment) so detectors never touch existing tokens."""
        pos = 0
        for m in TOKEN_RE.finditer(text):
            if m.start() > pos:
                yield False, text[pos:m.start()]
            yield True, m.group(0)
            pos = m.end()
        if pos < len(text):
            yield False, text[pos:]

    def _sub(self, text: str, pattern: re.Pattern, repl) -> str:
        return "".join(seg if is_tok else pattern.sub(repl, seg) for is_tok, seg in self._segments(text))

    # --- free text ------------------------------------------------------------

    def refresh_sweep(self) -> None:
        """Rebuild the known-values regex. Called once after the identity
        columns of an import are tokenised, not per new token (that would be
        O(n^2) in the number of distinct values)."""
        self._sweep = compile_literals([o for o in self.store.originals() if len(o) >= 3])
        self._sweep_size = len(self.store._by_norm)

    def sweep_regex(self):
        if self._sweep_size < 0:
            self.refresh_sweep()
        return self._sweep

    def sweep(self, text: str) -> str:
        rx = self.sweep_regex()
        if rx is None:
            return text
        return self._sub(text, rx, lambda m: self.store._by_norm.get(m.group(0).casefold()) or m.group(0))

    def url(self, m: re.Match) -> str:
        raw = m.group(0)
        scheme, _, rest = raw.partition("://")
        host, sep, tail = rest.partition("/")
        hostname = host.split("@")[-1].split(":")[0].replace("[.]", ".")
        if self.allowed_domain(hostname):
            host = host.replace("[.]", ".")
            out_host = host.replace(".", "[.]")
        else:
            out_host = self.tok("DOMAIN", hostname)
        scheme = scheme.lower().replace("http", "hxxp").replace("ftp", "fxp")
        return f"{scheme}://{out_host}{sep}{self.text(tail, urls=False) if tail else ''}"

    def text(self, value: str, urls: bool = True) -> str:
        if not value:
            return value
        s = CTRL_RE.sub("", value)
        if self.ner is not None:
            # Names the model finds (longest first), replaced before the rules run.
            for span in sorted(set(self.ner.spans(s)), key=len, reverse=True):
                if span in s:
                    s = s.replace(span, self.tok("PERSON", span))
        s = self.sweep(s)
        if urls:
            s = self._sub(s, detect.URL_RE, self.url)
        for kind, rx, validator in detect.DETECTORS:
            def repl(m, kind=kind, validator=validator):
                v = m.group(0)
                if validator and not validator(v):
                    return v
                if kind == "IP":
                    k = detect.ip_kind(v)
                    if k is None or k == "keep":
                        return v
                    return self.tok(k, v)
                if kind == "EMAIL":
                    domain = v.rsplit("@", 1)[1]
                    if self.allowed_domain(domain) and v.split("@")[0].lower() in {"noreply", "no-reply"}:
                        return v
                return self.tok(kind, v)
            s = self._sub(s, rx, repl)
        s = self._sub(s, detect.ACCOUNT_ARG_RE,
                      lambda m: m.group(0) if detect.well_known(m.group(2))
                      else m.group(1) + self.tok("ACCOUNT", m.group(2)))

        s = self._sub(s, detect.USERPATH_RE,
                      lambda m: m.group(0) if m.group(2).casefold() in detect.SYSTEM_PROFILES
                      else m.group(1) + self.tok("ACCOUNT", m.group(2)))

        def domain_user(m):
            dom, user = m.group(1), m.group(2)
            if dom.casefold() in detect.SYSTEM_DOMAINS or detect.SINGLE_EXT.match(user):
                return m.group(0)
            return self.tok("DOMAIN", dom) + "\\" + self.tok("ACCOUNT", user)
        s = self._sub(s, detect.DOMAIN_USER_RE, domain_user)
        # The account part may already be a token (swept as a known value).
        s = re.sub(r"(?<![\w\\.:/-])([A-Z][A-Z0-9-]{1,14})\\(«(?:ACCOUNT|PERSON|UPN)_\d+»)",
                   lambda m: m.group(0) if m.group(1).casefold() in detect.SYSTEM_DOMAINS
                   else self.tok("DOMAIN", m.group(1)) + "\\" + m.group(2), s)
        # The domain part may already be a token (swept as a known value).
        s = re.sub(r"(?<![\\/\w])(«(?:DOMAIN|PERSON|ORG|RESOURCE)_\d+»)\\([A-Za-z0-9][\w.$-]{0,63})(?![\w\\])",
                   lambda m: m.group(0) if detect.SINGLE_EXT.match(m.group(2))
                   else m.group(1) + "\\" + self.tok("ACCOUNT", m.group(2)), s)
        s = self._sub(s, detect.UNC_RE, lambda m: "\\\\" + self.tok("HOST", m.group(1)) + "\\")

        def dom(m):
            v = m.group(1)
            if not detect.is_domain_candidate(v) or self.allowed_domain(v):
                return v.replace(".", "[.]") if self.allowed_domain(v) else v
            return self.tok("DOMAIN", v)
        s = self._sub(s, detect.DOMAIN_RE, dom)
        s = self._sub(s, detect.DOTTED_NAME_RE,
                      lambda m: m.group(0) if detect.SINGLE_EXT.match(m.group(0)) or self.allowed_domain(m.group(0))
                      else self.tok("ACCOUNT", m.group(0)))
        s = self._sub(s, BLOB_RE, self.blob)
        return s

    @staticmethod
    def blob(m: re.Match) -> str:
        v = m.group(0)
        return f"«BLOB sha256={hashlib.sha256(v.encode()).hexdigest()[:16]} len={len(v)}»"

    # --- values -----------------------------------------------------------------

    def value(self, column: str, value):
        if value is None or value == "" or isinstance(value, (bool, int, float)):
            return value
        s = str(value)
        if s[:1] in "[{":
            try:
                return json.dumps(self.dynamic(json.loads(s)), ensure_ascii=False, separators=(",", ":"))
            except ValueError:
                pass
        kind = detect.column_kind(column)
        if kind == "keep":
            return s
        if kind == "IP":
            k = detect.ip_kind(s)
            return s if k in (None, "keep") else self.tok(k, s)
        if kind == "DOMAIN" and self.allowed_domain(s):
            return s.replace(".", "[.]")
        if kind in ("ACCOUNT", "DOMAIN", "SID", "PERSON", "UPN") and detect.well_known(s):
            return s  # built-in Windows principal (SYSTEM, NT AUTHORITY, S-1-5-18 …)
        if kind:
            return self.tok(kind, s)
        return self.text(s)

    def dynamic(self, obj, key: str = ""):
        if isinstance(obj, dict):
            return {k: self.dynamic(v, k) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.dynamic(v, key) for v in obj]
        if isinstance(obj, str):
            return self.value(key or "Value", obj)
        return obj

    def row(self, row: dict) -> dict:
        return {k: self.value(k, v) for k, v in row.items()}


# Fields Defender sets per event: a repeat of the same activity differs in
# these and nothing else. The collapsed row keeps the first event's values.
EVENT_FIELDS = {"Timestamp", "ReportId", "ProcessId", "ProcessCreationTime", "ProcessUniqueId", "LocalPort",
                "NetworkMessageId", "InternetMessageId", "LogonId", "EventId"}


def collapse(rows: list[dict], gap_seconds: int = 3600) -> list[dict]:
    """Merge rows identical except the per-event fields (EVENT_FIELDS) while
    repeats are < gap apart. Adds FirstSeen, LastSeen, Count. O(n log n)."""
    if not rows or "Timestamp" not in rows[0]:
        return [dict(r, Count=1) for r in rows]
    from datetime import datetime

    def ts(r):
        t = str(r.get("Timestamp") or "")
        t = re.sub(r"(\.\d{6})\d*", r"\1", t).replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(t)
        except ValueError:
            return None

    keyed = []
    for r in rows:
        key = json.dumps({k: v for k, v in r.items() if k not in EVENT_FIELDS}, sort_keys=True, ensure_ascii=False)
        keyed.append((key, ts(r), r))
    keyed.sort(key=lambda x: (x[0], x[1] is None, x[1] or 0))
    out: list[dict] = []
    cur = None
    for key, t, r in keyed:
        if cur and cur["_key"] == key and t and cur["_last"] and (t - cur["_last"]).total_seconds() < gap_seconds:
            cur["_last"] = t
            cur["Count"] += 1
            cur["LastSeen"] = r["Timestamp"]
            continue
        cur = {k: v for k, v in r.items() if k != "Timestamp"}
        cur.update(_key=key, _last=t, FirstSeen=r["Timestamp"], LastSeen=r["Timestamp"], Count=1)
        out.append(cur)
    for r in out:
        r.pop("_key"), r.pop("_last")
    out.sort(key=lambda r: str(r["FirstSeen"]))
    return out

