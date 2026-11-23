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
                             Static, Switch, TabbedContent, TabPane, TextArea)

from . import clip
from .case import Case, write_private
from .store import TOKEN_RE

RETENTION_DAYS = 30
PART_SIZES = [("150,000 chars (default)", 150_000), ("50,000 chars", 50_000), ("25,000 chars", 25_000),
              ("one part, no split", 10**12)]
REPORT_WARNING = ("The report holds the real values. Clipboard history and cloud clipboard sync "
                  "(Windows: Win+V, Sync across devices) can carry it off this machine.")
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
    root = d.resolve()
    return {r for g in globs for f in d.glob(g)
            if f.is_file() and f.name not in NOT_EXPORTS and (r := f.resolve()).is_relative_to(root)}


def export_candidates(dirs: list[Path], limit: int = 200, depth: int = 2) -> list[Path]:
    """CSV/JSON files in the given folders and (depth 2) their subfolders, newest first."""
    found = set().union(*(_exports_in(d, depth) for d in dirs if d.is_dir())) if dirs else set()
    return sorted(found, key=lambda f: f.stat().st_mtime, reverse=True)[:limit]


def expand_paths(text: str, base: Path) -> tuple[list[Path], list[str]]:
    """Paths typed by the user, confined to the exports folder `base`.

    Separated by ';' or newlines; relative to `base`, or absolute/'~' inside it;
    globs; folders (their CSV/JSON exports). Anything resolving outside `base`
    (symlinks included) is refused. Returns (files, problems)."""
    root = base.resolve()
    inside = lambda f: f.resolve().is_relative_to(root)  # noqa: E731
    files, problems = [], []
    for raw in re.split(r"[;\n]", text):
        item = raw.strip().strip("'\"")
        if not item:
            continue
        p = Path(item).expanduser()
        p = p if p.is_absolute() else root / p
        if any(c in item for c in "*?["):
            hits = sorted(f.resolve() for f in Path(p.anchor).glob(str(p.relative_to(p.anchor))) if f.is_file())
            kept = [f for f in hits if inside(f)]
            files += kept
            if not kept:
                problems.append(f"{item} (no match inside the exports folder)" if hits else item)
        elif not inside(p):
            problems.append(f"{item} (outside the exports folder)")
        elif p.is_dir():
            hits = sorted(f for f in _exports_in(p, 1) if inside(f))
            files += hits
            if not hits:
                problems.append(f"{item} (no CSV/JSON inside)")
        elif p.is_file():
            files.append(p.resolve())
        else:
            problems.append(item)
    return files, problems


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


def highlight_report(text: str) -> Text:
    t = Text(text, no_wrap=True, overflow="ignore")
    t.highlight_regex(r"⚠[^\n]*", "bold #ffb000")
    return t


def latest_round(root: Path) -> int:
    """Number N of the newest outbox-N*.md, 0 if none."""
    n = [int(m.group(1)) for p in root.glob("outbox-*.md") if (m := re.match(r"outbox-(\d+)", p.name))]
    return max(n, default=0)


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
                yield Label("", id="exports-title")
                yield SelectionList[str](id="files")
                yield Input(placeholder="relative to the exports folder: DeviceProcessEvents.csv; case-x/*.csv; subfolder", id="paths")
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
                    yield Label("Part size", classes="lbl")
                    yield Select[int](PART_SIZES, value=150_000, allow_blank=False, id="part-size")
                with Horizontal(classes="row"):
                    yield Button("Write outbox (egress gate runs first)", id="do-outbox", variant="primary")
                    yield Select[str]([], prompt="part", id="part", allow_blank=True)
                    yield Button("Copy this part", id="copy-part", disabled=True)
                yield Static("", id="outbox-msg")
                yield RichLog(id="preview", wrap=False, markup=False, highlight=False, auto_scroll=False)
            with TabPane("3 Answer", id="answer"):
                yield Label("Paste the chat's answer below (terminal paste), or read it from the clipboard.")
                with Horizontal(classes="row"):
                    yield Button("Paste from clipboard", id="paste-answer")
                    yield Button("Save as inbox and restore", id="do-restore", variant="primary")
                yield TextArea(id="answer-text", soft_wrap=True)
                yield Static("", id="restore-msg")
                yield RichLog(id="report", wrap=False, markup=False, highlight=False, auto_scroll=False)
                with Horizontal(classes="row"):
                    yield Button("Copy report", id="copy-report", disabled=True, variant="warning")
                    yield Label(REPORT_WARNING, id="report-warning", classes="hint")
        yield Footer()

    def on_mount(self) -> None:
        if self.app.clip_backend is None:
            for b in ("#copy-part", "#paste-answer", "#copy-report"):
                self.query_one(b, Button).tooltip = "no clipboard tool found: use the file path shown"
        self.query_one("#report").display = False
        self.refresh_files()
        t = self.query_one("#import-result", DataTable)
        t.add_columns("Table", "Rows", "After collapsing")
        t.display = False
        self.show_imported()

    def refresh_files(self) -> None:
        base = self.app.exports_dir
        title = self.query_one("#exports-title", Label)
        sl = self.query_one("#files", SelectionList)
        sl.clear_options()
        if base is None or not base.is_dir():
            title.update(Text("No exports folder. Start masquer with --exports DIR (or set MASQUER_EXPORTS); "
                              "the TUI reads exports only from there."
                              + (f" Not a folder: {base}" if base else ""), style="bold #ffb000"))
            for w in ("#paths", "#do-import"):
                self.query_one(w).disabled = True
            return
        title.update(f"Exports in {short(base)} (and its subfolders), newest first. "
                     "Tick them, or type names, subfolders or globs relative to it, separated by ';'.")
        for f in export_candidates([base]):
            sl.add_option((str(f.relative_to(base.resolve())), str(f)))

    def show_imported(self) -> None:
        done = self.case.imports()
        if done:
            self.query_one("#import-msg", Static).update(
                f"Already imported: {', '.join(sorted({i['file'] for i in done}))}")

    @on(Button.Pressed, "#do-import")
    def start_import(self) -> None:
        picked = [Path(p) for p in self.query_one("#files", SelectionList).selected]
        typed, missing = expand_paths(self.query_one("#paths", Input).value, self.app.exports_dir)
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
            self.parts = self.case.outbox(None, self.query_one("#part-size", Select).value,
                                          self.query_one("#allow-no-ner", Switch).value,
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
        self.query_one("#copy-part", Button).disabled = False

    @on(Select.Changed, "#part")
    def show_part(self, ev: Select.Changed) -> None:
        if isinstance(ev.value, str):
            log = self.query_one("#preview", RichLog)
            log.clear()
            log.write(highlight_tokens(Path(ev.value).read_text("utf-8")), expand=True, shrink=False)
            log.scroll_home(animate=False)

    # clipboard and answer ---------------------------------------------------------

    def _clip(self, msg: Static, fallback: str) -> clip.Backend | None:
        if self.app.clip_backend is None:
            msg.update(Text(f"No clipboard tool found (pbcopy, powershell.exe in WSL, wl-copy, xclip). {fallback}",
                            style="bold #ffb000"))
        return self.app.clip_backend

    @on(Button.Pressed, "#copy-part")
    def copy_part(self) -> None:
        sel = self.query_one("#part", Select)
        msg = self.query_one("#outbox-msg", Static)
        if not isinstance(sel.value, str):
            return
        path = Path(sel.value)
        if (cb := self._clip(msg, f"Open {path}")) is None:
            return
        text = path.read_text("utf-8")
        try:
            cb.copy(text)
        except clip.ClipboardError as e:
            msg.update(Text(f"Copy failed: {e}. Open {path}", style="bold red"))
            return
        i = [str(p) for p in self.parts].index(sel.value)
        more = i + 1 < len(self.parts)
        msg.update(Text.assemble((f"Copied {path.name} ", "bold green"), f"({len(text):,} chars). Paste it into the chat",
                                 "; then copy the next part." if more else "; then save the answer in 3 Answer."))
        if more:
            sel.value = str(self.parts[i + 1])

    @on(Button.Pressed, "#paste-answer")
    def paste_answer(self) -> None:
        msg = self.query_one("#restore-msg", Static)
        if (cb := self._clip(msg, "Paste into the box with the terminal's paste instead.")) is None:
            return
        try:
            text = cb.paste()
        except clip.ClipboardError as e:
            msg.update(Text(f"Paste failed: {e}", style="bold red"))
            return
        self.query_one("#answer-text", TextArea).text = text
        msg.update(f"Read {len(text):,} chars from the clipboard. Check it, then save and restore.")

    @on(Button.Pressed, "#do-restore")
    def save_and_restore(self) -> None:
        msg = self.query_one("#restore-msg", Static)
        text = self.query_one("#answer-text", TextArea).text
        n = latest_round(self.case.root)
        if not text.strip():
            msg.update("The answer box is empty.")
            return
        if not n:
            msg.update("No outbox in this case yet: write one in 2 Review first.")
            return
        inbox = self.case.root / f"inbox-{n}.md"
        write_private(inbox, text if text.endswith("\n") else text + "\n")
        try:
            dest, stats = self.case.restore(inbox)
        except (SystemExit, Exception) as e:  # noqa: BLE001 (shown to the user)
            msg.update(Text(f"Restore failed: {e}", style="bold red"))
            return
        self.report_path = dest
        warn = stats.get("unknown", 0) + stats.get("restored_altered", 0)
        msg.update(Text.assemble((f"{inbox.name} -> {dest.name}: ", "bold green"),
                                 ", ".join(f"{k} {v}" for k, v in sorted(stats.items())) or "no tokens",
                                 (f"  ·  check the {warn} ⚠ line(s)" if warn else "", "bold #ffb000")))
        log = self.query_one("#report", RichLog)
        log.clear()
        log.write(highlight_report(dest.read_text("utf-8")), expand=True, shrink=False)
        log.scroll_home(animate=False)
        log.display = True
        self.query_one("#copy-report", Button).disabled = False

    @on(Button.Pressed, "#copy-report")
    def copy_report(self) -> None:
        msg = self.query_one("#restore-msg", Static)
        path = getattr(self, "report_path", None)
        if path is None or (cb := self._clip(msg, f"Open {path}")) is None:
            return
        try:
            cb.copy(path.read_text("utf-8"))
        except clip.ClipboardError as e:
            msg.update(Text(f"Copy failed: {e}. Open {path}", style="bold red"))
            return
        msg.update(Text.assemble((f"Copied {path.name}. ", "bold green"), (REPORT_WARNING, "#ffb000")))


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
    #part-size { width: 32; }
    #preview, #report { height: 1fr; border: round #1fb6ff; }
    #report { border: round #ffb000; }
    #answer-text { height: 12; }
    #report-warning { width: 1fr; }
    #outbox-msg, #import-msg, #cases-msg, #restore-msg { margin-top: 1; }
    """

    def __init__(self, cases_dir: Path | None = None, exports_dir: Path | None = None,
                 clipboard: clip.Backend | None | bool = True):
        super().__init__()
        self.cases_dir = Path(cases_dir) if cases_dir else default_cases_dir()
        env = os.environ.get("MASQUER_EXPORTS")
        self.exports_dir = (Path(exports_dir) if exports_dir else Path(env) if env else None)
        self.exports_dir = self.exports_dir.expanduser().resolve() if self.exports_dir else None
        # True: detect; None/False: no clipboard; a Backend: use it (tests).
        self.clip_backend = clip.detect() if clipboard is True else (clipboard or None)

    def on_mount(self) -> None:
        self.push_screen(CasesScreen())


def run(cases_dir: Path | None = None, exports_dir: Path | None = None) -> int:
    MasquerApp(cases_dir, exports_dir).run()
    return 0
