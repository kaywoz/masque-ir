"""Headless TUI flow on a synthetic case (needs the tui extra)."""
import asyncio
import json
import os
import time
from pathlib import Path

import pytest

textual = pytest.importorskip("textual")

from masquer.case import Case  # noqa: E402
from masquer.synth import generate  # noqa: E402
from masquer.tui import (CaseScreen, MasquerApp, case_age_days, export_candidates,  # noqa: E402
                         highlight_tokens, list_cases)


def test_helpers(tmp_path):
    Case.create(tmp_path / "c1")
    (tmp_path / "not-a-case").mkdir()
    assert [p.name for p in list_cases(tmp_path)] == ["c1"]
    f = tmp_path / "c1" / "input" / "x.csv"
    f.write_text("a\n")
    old = time.time() - 40 * 86400
    os.utime(f, (old, old))
    assert case_age_days(tmp_path / "c1") > 30
    (tmp_path / "e.csv").write_text("x")
    (tmp_path / "e.txt").write_text("x")
    assert [p.name for p in export_candidates([tmp_path, tmp_path / "missing"])] == ["e.csv"]
    assert [s.style for s in highlight_tokens("a «HOST_0001» b").spans]


def test_flow_matches_cli(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))  # no name model
    synth = tmp_path / "synth"
    generate(synth, tables=["DeviceProcessEvents", "EmailEvents"], rows=30, seed=5)
    canaries = json.loads((synth / "canaries.json").read_text("utf-8"))["canaries"]
    cases = tmp_path / "cases"

    async def flow():
        app = MasquerApp(cases, exports_dir=synth, clipboard=None)
        async with app.run_test(size=(140, 45)) as pilot:
            await pilot.pause()
            await pilot.click("#new-name")
            await pilot.press(*"tui1", "enter")
            await pilot.pause()
            assert (cases / "tui1" / "map.sqlite").is_file()
            assert oct((cases / "tui1").stat().st_mode & 0o777) == "0o700"
            app.screen.query_one("#case-table").focus()
            await pilot.press("enter")
            await pilot.pause()
            scr = app.screen
            assert isinstance(scr, CaseScreen)
            sl = scr.query_one("#files")
            for i in range(sl.option_count):  # the CSV exports, not canaries.json
                if sl.get_option_at_index(i).value.endswith(".csv"):
                    sl.select(sl.get_option_at_index(i).value)
            await pilot.click("#do-import")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert scr.query_one("#import-result").row_count == 2, scr.query_one("#import-msg").render()
            # Without the model the gate refuses unless explicitly allowed.
            scr.query_one("TabbedContent").active = "review"
            await pilot.pause()
            scr.query_one("#do-outbox").press()
            await pilot.pause()
            assert not scr.parts
            scr.query_one("#allow-no-ner").value = True
            scr.query_one("#do-outbox").press()
            await pilot.pause()
            assert scr.parts and "passed" in str(scr.query_one("#outbox-msg").render())
            return scr.parts

    parts = asyncio.run(flow())
    tui_text = parts[0].read_text("utf-8")

    # The same import and outbox through the Case API (what the CLI calls).
    ref = Case.create(tmp_path / "ref")
    ref.import_files(sorted(synth.glob("*.csv")), 3600, None)
    cli_text = ref.outbox(None, 150_000, True, False)[0].read_text("utf-8")
    assert tui_text == cli_text  # same import order, same tokens, same bytes

    text = tui_text.casefold()  # names wait for the model, as in test_pipeline
    leaked = {v for kind, vals in canaries.items() if kind not in ("person_name", "file_pii")
              for v in vals if v.casefold() in text}
    assert not leaked


def test_expand_paths(tmp_path):
    from masquer.tui import expand_paths
    base = tmp_path / "exports"
    (base / "case-x").mkdir(parents=True)
    for n in ("A.csv", "B.json", "canaries.json", "notes.txt"):
        (base / "case-x" / n).write_text("x")
    (tmp_path / "outside.csv").write_text("x")
    (base / "link.csv").symlink_to(tmp_path / "outside.csv")
    names = lambda fs: sorted(f.name for f in fs)  # noqa: E731
    # a subfolder: its exports, not canaries.json or other files
    files, bad = expand_paths("case-x", base)
    assert names(files) == ["A.csv", "B.json"] and not bad
    # relative names, a quoted glob, newline and ';' separators, absolute inside
    files, bad = expand_paths(f"case-x/A.csv;\n'case-x/*.json'; {base}/case-x/B.json", base)
    assert names(files) == ["A.csv", "B.json", "B.json", "canaries.json"] and not bad
    # outside the exports folder: refused, also through '..', '~' or a symlink
    files, bad = expand_paths(f"../outside.csv; {tmp_path}/outside.csv; link.csv; nope.csv; ../*.csv", base)
    assert not files
    assert bad == ["../outside.csv (outside the exports folder)", f"{tmp_path}/outside.csv (outside the exports folder)",
                   "link.csv (outside the exports folder)", "nope.csv",
                   "../*.csv (no match inside the exports folder)"]
    # the list looks one folder deep
    assert names(export_candidates([base])) == ["A.csv", "B.json"]


def fake_clipboard(tmp_path):
    """A clipboard backed by a file, through real subprocesses."""
    import sys
    from masquer.clip import Backend
    store = tmp_path / "clipboard.bin"
    w = f"import sys,pathlib; pathlib.Path({str(store)!r}).write_bytes(sys.stdin.buffer.read())"
    r = f"import sys,pathlib; sys.stdout.buffer.write(pathlib.Path({str(store)!r}).read_bytes())"
    return store, Backend("fake", [sys.executable, "-c", w], [sys.executable, "-c", r])


def test_clip_backend_b64_roundtrip(tmp_path):
    from dataclasses import replace
    store, cb = fake_clipboard(tmp_path)
    text = "«HOST_0001» hxxps://«DOMAIN_0002»/gate\r\nLönespec ⚠ ✓"
    cb.copy(text)
    assert cb.paste() == text.replace("\r\n", "\n")
    wsl = replace(cb, b64=True)  # what the PowerShell backend sends: ASCII only
    wsl.copy(text)
    assert store.read_bytes().isascii()
    assert wsl.paste() == text.replace("\r\n", "\n")


def test_no_exports_folder(tmp_path, monkeypatch):
    monkeypatch.delenv("MASQUER_EXPORTS", raising=False)
    Case.create(tmp_path / "cases" / "c1")

    async def flow():
        app = MasquerApp(tmp_path / "cases", clipboard=None)
        async with app.run_test(size=(140, 45)) as pilot:
            await pilot.pause()
            app.screen.query_one("#case-table").focus()
            await pilot.press("enter")
            await pilot.pause()
            scr = app.screen
            assert scr.query_one("#do-import").disabled
            assert "--exports" in str(scr.query_one("#exports-title").render())
            assert scr.query_one("#files").option_count == 0

    asyncio.run(flow())


def test_clipboard_flow(tmp_path):
    synth = tmp_path / "exports"
    generate(synth, tables=["DeviceProcessEvents", "DeviceNetworkEvents", "EmailEvents"], rows=40, seed=7)
    case = Case.create(tmp_path / "cases" / "c1")
    case.import_files(sorted(synth.glob("*.csv")), 3600, None)
    store, cb = fake_clipboard(tmp_path)

    async def flow():
        app = MasquerApp(tmp_path / "cases", exports_dir=synth, clipboard=cb)
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            app.screen.query_one("#case-table").focus()
            await pilot.press("enter")
            await pilot.pause()
            scr = app.screen
            scr.query_one("TabbedContent").active = "review"
            scr.query_one("#allow-no-ner").value = True
            scr.query_one("#part-size").value = 25_000
            await pilot.pause()
            scr.query_one("#do-outbox").press()
            await pilot.pause()
            assert len(scr.parts) > 1, "25k parts should split three tables"
            assert all(len(p.read_text("utf-8")) <= 25_000 + 32 for p in scr.parts)  # + "[part i of n]" label
            # copy part 1, the selector moves on to part 2
            scr.query_one("#copy-part").press()
            await pilot.pause()
            assert store.read_text("utf-8") == scr.parts[0].read_text("utf-8")
            assert scr.query_one("#part").value == str(scr.parts[1])
            # the answer comes back through the clipboard
            tok = next(iter(__import__("re").findall(r"«HOST_\d{4}»", scr.parts[0].read_text("utf-8"))))
            store.write_text(f"```markdown\nIsolate {tok} now.\n```\n", "utf-8")
            scr.query_one("TabbedContent").active = "answer"
            await pilot.pause()
            scr.query_one("#paste-answer").press()
            await pilot.pause()
            assert tok in scr.query_one("#answer-text").text
            scr.query_one("#do-restore").press()
            await pilot.pause()
            report = scr.report_path.read_text("utf-8")
            assert tok not in report and report.startswith("Isolate ")
            assert (case.root / "inbox-1.md").stat().st_mode & 0o777 == 0o600
            scr.query_one("#copy-report").press()
            await pilot.pause()
            assert store.read_text("utf-8") == report
            assert "carry it off" in str(scr.query_one("#restore-msg").render())

    asyncio.run(flow())
