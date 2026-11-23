"""Name-detection stage with a stand-in detector (CI doesn't download the model)."""
import json

import pytest

from masquer.case import Case
from masquer.masker import Masker
from masquer.ner import CANDIDATE, NameDetector
from masquer.store import Store
from masquer.synth import generate


class FakeNER:
    """Finds names from a fixed list, like a model would; counts calls."""
    name = "fake"

    def __init__(self, names):
        self.names = names
        self.primed = 0

    def prime(self, texts):
        self.primed += len(list(texts))

    def spans(self, text):
        probe = NameDetector._probe(text)
        out = []
        for n in self.names:
            for variant in (n, n.replace(" ", "_")):
                if variant in text:
                    out.append(variant)
        return out or [w for w in probe.split() if False]


def test_probe_keeps_offsets():
    t = "Lönespec_Anna_Berg_2025.pdf"
    assert len(NameDetector._probe(t)) == len(t) and "Anna Berg" in NameDetector._probe(t)


def test_candidate_filter():
    assert CANDIDATE.search("Lönespec_Anna_Berg.pdf")
    assert not CANDIDATE.search("4f2a99c1")


def test_masker_uses_ner(tmp_path):
    m = Masker(Store(tmp_path / "m.sqlite"), ner=FakeNER(["Anna Berg"]))
    out = m.text(r"copy C:\x\Lönespec_Anna_Berg_2025.pdf and mail to Anna Berg")
    assert "Anna" not in out and out.count("«PERSON_") == 2


def test_outbox_gate_by_import_log(tmp_path):
    generate(tmp_path / "s", tables=["DeviceProcessEvents"], rows=20, seed=2)
    c = Case.create(tmp_path / "c")
    c.import_files(sorted((tmp_path / "s").glob("*.csv")))
    with pytest.raises(SystemExit, match="without the name-detection stage"):
        c.outbox()
    c2 = Case.create(tmp_path / "c2")
    c2.import_files(sorted((tmp_path / "s").glob("*.csv")), ner=FakeNER([]))
    assert c2.outbox(max_chars=10**8)  # no flag needed
    assert json.loads((c2.root / "imports.json").read_text())[0]["ner"] == "fake"


def test_ner_closes_name_leaks(tmp_path):
    generate(tmp_path / "s", tables=["DeviceProcessEvents", "EmailEvents"], rows=80, seed=9, injections=False)
    can = json.loads((tmp_path / "s" / "canaries.json").read_text("utf-8"))["canaries"]
    import re
    names = set(can.get("person_name", []))
    for f in can.get("file_pii", []):  # names that only occur inside file names
        m = re.match(r"Lönespec_([^_]+)_([^_.]+)", f)
        if m:
            names.add(f"{m.group(1)} {m.group(2)}")
    c = Case.create(tmp_path / "c")
    c.import_files(sorted((tmp_path / "s").glob("*.csv")), ner=FakeNER(names))
    text = "".join(p.read_text("utf-8") for p in c.outbox(max_chars=10**8)).casefold()
    leaks = [v for k, vals in can.items() for v in vals if v.casefold() in text]
    assert not leaks, leaks[:5]


def test_keep_filter():
    from masquer.ner import keep
    assert keep("Anna Berg") and keep("Sigrún")
    assert not keep("powershell") and not keep("Powershell") and not keep("a") and not keep("cmd.exe")
    assert not keep("Office16")


def test_trim():
    from masquer.ner import trim
    assert trim("Lönespec_Anna_Berg_2025") == "Anna_Berg"
    assert trim("Anna Berg") == "Anna Berg"
    assert trim("powershell") == ""


def test_account_after_person_token(tmp_path):
    from masquer.masker import Masker
    m = Masker(Store(tmp_path / "m.sqlite"), ner=FakeNER(["REVONTULI"]))
    out = m.text(r"schtasks /ru REVONTULI\sigrun.y /tr C:\Users\x\Downloads\u.ps1")
    assert "sigrun" not in out and "Downloads" in out, out
