"""Name-detection stage: a local GLiNER model finds person names in free text
(command lines, file names, subjects, alert text) that no rule can know.

The model only adds spans; the deterministic egress gate still decides what
leaves. Loaded from a local folder, never from the network.
Optional dependency: `masquer[ner]` (gliner + torch).
"""
from __future__ import annotations

import logging
import os
import re
import warnings
from pathlib import Path

LABELS = ("person", "first name", "last name", "full name")
# Only texts with two letter-runs next to each other can hold a name.
CANDIDATE = re.compile(r"[^\W\d_]{2,}[ _.,][^\W\d_]{2,}")
MAX_CHARS = 1500  # long values are split into windows of this size
# Words the model sometimes tags as names but that carry the analysis.
NOT_NAMES = {
    "powershell", "cmd", "svchost", "certutil", "rundll32", "schtasks", "wmic", "curl", "net", "whoami",
    "outlook", "winword", "word", "excel", "teams", "chrome", "edge", "msedge", "explorer", "windows",
    "microsoft", "system", "admin", "administrator", "user", "users", "update", "invoice", "payload",
    "setup", "temp", "downloads", "documents", "desktop", "appdata", "local", "program", "files",
    "lönespec", "faktura", "utbetalning", "budget", "public", "default", "guest", "service",
}
# Gap text allowed between two spans that form one name ("Anna Berg", "Anna_Berg").
JOIN = re.compile(r"[ _.\-]{1,2}")


def trim(span: str) -> str:
    """Drop leading/trailing words that aren't name parts (Lönespec_Anna_Berg
    -> Anna_Berg), keeping the original separators in between."""
    parts = re.split(r"([ _.\-]+)", span.strip(" _.,"))
    words = parts[0::2]
    lo, hi = 0, len(words)
    while lo < hi and (words[lo].casefold() in NOT_NAMES or words[lo].islower() or words[lo].isdigit()):
        lo += 1
    while hi > lo and (words[hi - 1].casefold() in NOT_NAMES or words[hi - 1].islower() or words[hi - 1].isdigit()):
        hi -= 1
    return "".join(parts[2 * lo:2 * hi - 1]) if hi > lo else ""


def keep(span: str) -> bool:
    return (len(span) >= 2 and not span.islower() and span.casefold() not in NOT_NAMES
            and not re.search(r"\.(exe|dll|ps1|bat|cmd|js|vbs)$", span, re.I))


def default_model_dir() -> Path:
    base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "masquer" / "models"
    return base / "gliner-pii"


class NameDetector:
    def __init__(self, model_dir: Path, threshold: float = 0.4, batch: int = 16):
        os.environ["HF_HUB_OFFLINE"] = "1"
        os.environ["TRANSFORMERS_OFFLINE"] = "1"
        os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")
        # torch and gliner print deprecation notes and a macOS redirect notice
        # on import; they say nothing about the result.
        warnings.filterwarnings("ignore", category=FutureWarning)
        warnings.filterwarnings("ignore", category=UserWarning, module=r"(torch|gliner|transformers)")
        logging.getLogger("torch.distributed.elastic.multiprocessing.redirects").setLevel(logging.ERROR)
        try:
            from gliner import GLiNER
        except ImportError as e:  # pragma: no cover - depends on the extra
            raise SystemExit("The name-detection stage needs masquer[ner]: re-run install.sh --with-ner") from e
        if not (Path(model_dir) / "gliner_config.json").is_file():
            raise SystemExit(f"No GLiNER model in {model_dir}: re-run install.sh --with-ner "
                             "(or --models-from DIR)")
        self.model = GLiNER.from_pretrained(str(model_dir), local_files_only=True)
        self.name = Path(model_dir).name
        self.threshold, self.batch = threshold, batch
        self.cache: dict[str, list[str]] = {}

    @staticmethod
    def _probe(text: str) -> str:
        """Same length as text, with separators turned into spaces, so
        Lönespec_Anna_Berg.pdf reads as words and offsets still match."""
        return re.sub(r"[_.\\/]", " ", text)

    def prime(self, texts) -> None:
        """Batch-predict all new candidate texts. O(n) model calls / batch."""
        todo = [t for t in dict.fromkeys(texts) if t not in self.cache and CANDIDATE.search(t)]
        windows: list[tuple[str, int, str]] = []
        for t in todo:
            self.cache[t] = []
            for i in range(0, len(t), MAX_CHARS):
                windows.append((t, i, self._probe(t[i:i + MAX_CHARS])))
        for b in range(0, len(windows), self.batch):
            chunk = windows[b:b + self.batch]
            results = self.model.inference([w[2] for w in chunk], list(LABELS),
                                           threshold=self.threshold, batch_size=self.batch)
            for (t, off, _), ents in zip(chunk, results):
                # Merge neighbouring spans into one name, then filter.
                merged: list[list[int]] = []
                for e in sorted(ents, key=lambda e: e["start"]):
                    st, en = off + e["start"], off + e["end"]
                    if merged and JOIN.fullmatch(t[merged[-1][1]:st] or "-"):
                        merged[-1][1] = max(merged[-1][1], en)
                    else:
                        merged.append([st, en])
                for st, en in merged:
                    span = trim(t[st:en])
                    if keep(span):
                        self.cache[t].append(span)

    def spans(self, text: str) -> list[str]:
        if text not in self.cache:
            self.prime([text])
        return self.cache.get(text, [])
