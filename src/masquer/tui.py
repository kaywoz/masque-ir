"""masquer TUI: a guided flow over the same Case API the CLI uses.

Only Case.outbox() writes an outbox, so the egress gate always runs.
Install with the extra: masquer[tui] (install.sh --with-tui).
"""
from __future__ import annotations

import os
import re
import time
from pathlib import Path

from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import (Button, DataTable, Footer, Header, Input, Label, RichLog, Select, SelectionList,
                             Static, Switch, TabbedContent, TabPane)

from .case import Case
from .store import TOKEN_RE

RETENTION_DAYS = 30
EXPORT_GLOBS = ("*.csv", "*.json")


def default_cases_dir() -> Path:
    return Path(os.environ.get("MASQUER_CASES", Path.home() / "masquer-cases")).expanduser()


def is_case(p: Path) -> bool:
    return (p / "masked").is_dir() and (p / "map.sqlite").is_file()


def case_age_days(p: Path, now: float | None = None) -> float:
    """Age since the case was created: its oldest input copy, else the folder."""
    now = now or time.time()
    stamps = [f.stat().st_mtime for f in (p / "input").glob("*") if f.is_file()] or [p.stat().st_mtime]
    return (now - min(stamps)) / 86400


def list_cases(base: Path) -> list[Path]:
    if not base.is_dir():
        return []
    return sorted((p for p in base.iterdir() if p.is_dir() and is_case(p)), key=lambda p: p.name)


NOT_EXPORTS = {"canaries.json", "imports.json"}  # synth's leak list, a case's import log


def _exports_in(d: Path, depth: int) -> set[Path]:
    globs = EXPORT_GLOBS + tuple(f"*/{g}" for g in EXPORT_GLOBS) if depth > 1 else EXPORT_GLOBS
    return {f.resolve() for g in globs for f in d.glob(g) if f.is_file() and f.name not in NOT_EXPORTS}


def export_candidates(dirs: list[Path], limit: int = 200, depth: int = 2) -> list[Path]:
    """CSV/JSON files in the given folders and (depth 2) their subfolders, newest first."""
    found = set().union(*(_exports_in(d, depth) for d in dirs if d.is_dir())) if dirs else set()
    return sorted(found, key=lambda f: f.stat().st_mtime, reverse=True)[:limit]


def expand_paths(text: str, cwd: Path | None = None) -> tuple[list[Path], list[str]]:
    """Paths typed by the user: separated by ';' or newlines; '~', relative
    (to cwd), globs, and folders (their CSV/JSON exports). Returns (files, not found)."""
    cwd = cwd or Path.cwd()
    files, missing = [], []
    for raw in re.split(r"[;\n]", text):
        item = raw.strip().strip("'\"")
        if not item:
            continue
        p = Path(item).expanduser()
        p = p if p.is_absolute() else cwd / p
        if any(c in item for c in "*?["):
            hits = sorted(f for f in Path(p.anchor).glob(str(p.relative_to(p.anchor))) if f.is_file())
            files += hits
            if not hits:
                missing.append(item)
        elif p.is_dir():
            hits = sorted(_exports_in(p, 1))
            files += hits
            if not hits:
                missing.append(f"{item} (no CSV/JSON inside)")
        elif p.is_file():
            files.append(p.resolve())
        else:
            missing.append(item)
    return files, missing


def short(p: Path) -> str:
    """Path for display: ~ for the home folder."""
    try:
        return "~/" + str(p.relative_to(Path.home()))
    except ValueError:
        return str(p)


def highlight_tokens(text: str) -> Text:
    t = Text(text, no_wrap=True, overflow="ignore")
    t.highlight_regex(TOKEN_RE.pattern, "bold #1fb6ff")
    t.highlight_regex(r"\bhxxps?://|\[\.\]", "#ff8fa3")
    return t


def name_model():
    """The installed name detector, or None."""
    try:
        from .ner import NameDetector, default_model_dir
    except ImportError:
        return None
    model = default_model_dir()
    return NameDetector(model) if (model / "gliner_config.json").is_file() else None


def ner_installed() -> bool:
    try:
        from .ner import default_model_dir
    except ImportError:
        return False
    return (default_model_dir() / "gliner_config.json").is_file()


# --- screens ------------------------------------------------------------------


class CasesScreen(Screen):
    BINDINGS = [("n", "focus_new", "New case"), ("r", "refresh", "Refresh"), ("q", "app.quit", "Quit")]

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="cases"):
            yield Label(f"Cases in {self.app.cases_dir}", id="cases-title")
            yield DataTable(id="case-table", cursor_type="row")
            with Horizontal(id="new-row"):
                yield Input(placeholder="new case name (letters, digits, - and _)", id="new-name")
                yield Button("Create", id="create", variant="primary")
            yield Static("", id="cases-msg")
        yield Footer()

    def on_mount(self) -> None:
        t = self.query_one(DataTable)
        t.add_columns("Case", "Age (days)", "Outboxes", "Reports", "")
        self.action_refresh()

    def action_refresh(self) -> None:
        t = self.query_one(DataTable)
        t.clear()
        for p in list_cases(self.app.cases_dir):
            age = case_age_days(p)
            t.add_row(p.name, f"{age:.0f}", str(len(list(p.glob("outbox-*.md")))),
                      str(len(list(p.glob("report-*.md")))),
                      Text(f"older than {RETENTION_DAYS} days: wipe or archive", style="bold red")
                      if age > RETENTION_DAYS else "", key=str(p))

    def action_focus_new(self) -> None:
        self.query_one("#new-name", Input).focus()

    @on(Button.Pressed, "#create")
    @on(Input.Submitted, "#new-name")
    def create(self) -> None:
        name = self.query_one("#new-name", Input).value.strip()
        msg = self.query_one("#cases-msg", Static)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", name):
            msg.update("Use letters, digits, - and _ (max 64).")
            return
        dest = self.app.cases_dir / name
        if dest.exists():
            msg.update(f"{dest} already exists.")
            return
        self.app.cases_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.app.cases_dir, 0o700)
        Case.create(dest)
        self.query_one("#new-name", Input).value = ""
        msg.update(f"Created {dest} (mode 700).")
        self.action_refresh()

    @on(DataTable.RowSelected)
    def open_case(self, ev: DataTable.RowSelected) -> None:
        self.app.push_screen(CaseScreen(Case(Path(ev.row_key.value))))


class CaseScreen(Screen):
    BINDINGS = [("escape", "app.pop_screen", "Cases"), ("q", "app.quit", "Quit")]

    def __init__(self, case: Case):
        super().__init__()
        self.case = case
        self.parts: list[Path] = []

    def compose(self) -> ComposeResult:
        yield Header()
        yield Label(f"Case {self.case.root.name}  ·  {self.case.root}", id="case-title")
        with TabbedContent(initial="import"):
            with TabPane("1 Import", id="import"):
                yield Label("Pick exports (newest first), or type files, folders or globs separated by ';'.")
                yield SelectionList[str](id="files")
                yield Input(placeholder="~/Downloads/masquer-demo   or   ~/exports/*.csv; ./EmailEvents.csv", id="paths")
                with Horizontal(classes="row"):
                    yield Label("Name model", classes="lbl")
                    yield Switch(value=ner_installed(), disabled=not ner_installed(), id="use-ner")
                    yield Label("" if ner_installed() else "not installed (install.sh --with-ner)",
                                classes="hint")
                yield Button("Import", id="do-import", variant="primary")
                yield DataTable(id="import-result")
                yield Static("", id="import-msg")
            with TabPane("2 Review", id="review"):
                with Horizontal(classes="row"):
                    yield Label("Neutralise injection", classes="lbl")
                    yield Switch(value=False, id="neutralise")
                    yield Label("Allow without name model", classes="lbl")
                    yield Switch(value=False, id="allow-no-ner")
                with Horizontal(classes="row"):
                    yield Button("Write outbox (egress gate runs first)", id="do-outbox", variant="primary")
                    yield Select[str]([], prompt="part", id="part", allow_blank=True)
                yield Static("", id="outbox-msg")
                yield RichLog(id="preview", wrap=False, markup=False, highlight=False, auto_scroll=False)
        yield Footer()

    def on_mount(self) -> None:
        self.refresh_files()
        t = self.query_one("#import-result", DataTable)
        t.add_columns("Table", "Rows", "After collapsing")
        t.display = False
        self.show_imported()

    def refresh_files(self) -> None:
        dirs = [Path.home() / "Downloads", self.app.exports_dir] if self.app.exports_dir else [Path.home() / "Downloads"]
        sl = self.query_one("#files", SelectionList)
        sl.clear_options()
        for f in export_candidates(dirs):
            sl.add_option((f"{f.name}  ({short(f.parent)})", str(f)))

    def show_imported(self) -> None:
        done = self.case.imports()
        if done:
            self.query_one("#import-msg", Static).update(
                f"Already imported: {', '.join(sorted({i['file'] for i in done}))}")

    @on(Button.Pressed, "#do-import")
    def start_import(self) -> None:
        picked = [Path(p) for p in self.query_one("#files", SelectionList).selected]
        typed, missing = expand_paths(self.query_one("#paths", Input).value)
        files = sorted(dict.fromkeys(f.resolve() for f in picked + typed), key=lambda f: (f.name, str(f)))  # stable tokens
        msg = self.query_one("#import-msg", Static)
        if not files or missing:
            msg.update("Pick or type at least one file or folder." if not missing
                       else Text(f"Not found: {', '.join(missing)}", style="bold red"))
            return
        self.query_one("#do-import", Button).disabled = True
        msg.update(f"Importing {len(files)} file(s)…")
        self.run_import(files, self.query_one("#use-ner", Switch).value)

    @work(thread=True, exclusive=True)
    def run_import(self, files: list[Path], use_ner: bool) -> None:
        try:
            res = self.case.import_files(files, 3600, name_model() if use_ner else None)
            self.app.call_from_thread(self.import_done, res, None)
        except (SystemExit, Exception) as e:  # noqa: BLE001 (shown to the user)
            self.app.call_from_thread(self.import_done, None, str(e))

    def import_done(self, res: dict | None, err: str | None) -> None:
        self.query_one("#do-import", Button).disabled = False
        msg = self.query_one("#import-msg", Static)
        if err:
            msg.update(Text(f"Import failed: {err}", style="bold red"))
            return
        t = self.query_one("#import-result", DataTable)
        t.clear()
        for table, (rows, merged) in res.items():
            t.add_row(table, str(rows), str(merged))
        t.display = True
        msg.update("Imported. Next: 2 Review.")

    @on(Button.Pressed, "#do-outbox")
    def write_outbox(self) -> None:
        msg = self.query_one("#outbox-msg", Static)
        try:
            self.parts = self.case.outbox(None, 150_000, self.query_one("#allow-no-ner", Switch).value,
                                          self.query_one("#neutralise", Switch).value)
        except SystemExit as e:
            msg.update(Text(str(e), style="bold red"))
            return
        flagged = getattr(self.case, "last_flagged", 0)
        msg.update(Text.assemble(("Egress gate: passed. ", "bold green"),
                                 f"{len(self.parts)} file(s): {', '.join(p.name for p in self.parts)}",
                                 f"  ·  instruction-like rows: {flagged}" if flagged else ""))
        sel = self.query_one("#part", Select)
        sel.set_options([(p.name, str(p)) for p in self.parts])
        sel.value = str(self.parts[0])

    @on(Select.Changed, "#part")
    def show_part(self, ev: Select.Changed) -> None:
        if isinstance(ev.value, str):
            log = self.query_one("#preview", RichLog)
            log.clear()
            log.write(highlight_tokens(Path(ev.value).read_text("utf-8")), expand=True, shrink=False)
            log.scroll_home(animate=False)


class MasquerApp(App):
    TITLE = "masquer"
    SUB_TITLE = "mask · paste · restore"
    CSS = """
    Screen { background: #0d1117; }
    #cases, TabPane { padding: 1 2; }
    #cases-title, #case-title { color: #7fd3ff; padding: 0 2; }
    #case-table { height: 1fr; }
    #new-row, .row { height: auto; margin: 1 0 0 0; }
    #new-name { width: 1fr; }
    .lbl { padding: 1 1 0 0; }
    .hint { padding: 1 0 0 1; color: #8b949e; }
    #files { height: 10; }
    #import-result { height: auto; max-height: 12; margin-top: 1; }
    #part { width: 30; }
    #preview { height: 1fr; border: round #1fb6ff; }
    #outbox-msg, #import-msg, #cases-msg { margin-top: 1; }
    """

    def __init__(self, cases_dir: Path | None = None, exports_dir: Path | None = None):
        super().__init__()
        self.cases_dir = Path(cases_dir) if cases_dir else default_cases_dir()
        self.exports_dir = exports_dir

    def on_mount(self) -> None:
        self.push_screen(CasesScreen())


def run(cases_dir: Path | None = None, exports_dir: Path | None = None) -> int:
    MasquerApp(cases_dir, exports_dir).run()
    return 0
