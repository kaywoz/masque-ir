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
    monkeypatch.setenv("HOME", str(tmp_path))  # no real ~/Downloads, no model
    synth = tmp_path / "synth"
    generate(synth, tables=["DeviceProcessEvents", "EmailEvents"], rows=30, seed=5)
    canaries = json.loads((synth / "canaries.json").read_text("utf-8"))["canaries"]
    cases = tmp_path / "cases"

    async def flow():
        app = MasquerApp(cases, exports_dir=synth)
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
