"""System clipboard through the platform's own tools; no temp files, no network.

macOS: pbcopy/pbpaste. WSL: powershell.exe Set-/Get-Clipboard, with the text
passed as Base64 of UTF-8 so « » survive the console code page. Linux:
wl-copy/wl-paste (Wayland) or xclip (X11). Nothing found: available() is
False and callers show file paths instead.
"""
from __future__ import annotations

import base64
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

TIMEOUT = 15  # seconds; powershell.exe can take a few to start

# PowerShell reads ASCII Base64 from stdin, so no console encoding applies.
_PS_SET = ("$b=[Console]::In.ReadToEnd();"
           "Set-Clipboard -Value ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b.Trim())))")
_PS_GET = "$t=Get-Clipboard -Raw; if ($t) { [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($t)) }"


class ClipboardError(RuntimeError):
    pass


@dataclass(frozen=True)
class Backend:
    name: str
    copy_cmd: list[str]
    paste_cmd: list[str]
    b64: bool = False  # WSL: text crosses as Base64 of UTF-8

    def copy(self, text: str) -> None:
        data = base64.b64encode(text.encode()) if self.b64 else text.encode()
        _run(self.copy_cmd, data)

    def paste(self) -> str:
        out = _run(self.paste_cmd, None)
        text = base64.b64decode(out.strip()).decode() if self.b64 else out.decode()
        return text.replace("\r\n", "\n")


def _run(cmd: list[str], data: bytes | None) -> bytes:
    env = dict(os.environ, LC_CTYPE="UTF-8") if sys.platform == "darwin" else None  # pbcopy honours the locale
    try:
        r = subprocess.run(cmd, input=data, capture_output=True, timeout=TIMEOUT, env=env, check=False)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise ClipboardError(f"{cmd[0]}: {e}") from e
    if r.returncode != 0:
        raise ClipboardError(f"{cmd[0]} exited {r.returncode}: {r.stderr.decode(errors='replace').strip()[:200]}")
    return r.stdout


def is_wsl() -> bool:
    try:
        return "microsoft" in Path("/proc/version").read_text().lower()
    except OSError:
        return False


def detect() -> Backend | None:
    """The clipboard backend for this machine, or None."""
    if sys.platform == "darwin" and shutil.which("pbcopy") and shutil.which("pbpaste"):
        return Backend("pbcopy", ["pbcopy"], ["pbpaste"])
    if is_wsl() and (ps := shutil.which("powershell.exe")):
        base = [ps, "-NoProfile", "-NonInteractive", "-Command"]
        return Backend("powershell", base + [_PS_SET], base + [_PS_GET], b64=True)
    if os.environ.get("WAYLAND_DISPLAY") and shutil.which("wl-copy") and shutil.which("wl-paste"):
        return Backend("wl-copy", ["wl-copy"], ["wl-paste", "--no-newline"])
    if os.environ.get("DISPLAY") and shutil.which("xclip"):
        return Backend("xclip", ["xclip", "-selection", "clipboard", "-in"],
                       ["xclip", "-selection", "clipboard", "-out"])
    return None
