"""masquer command line."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__


def cmd_synth(a: argparse.Namespace) -> int:
    from .synth import generate, load_schema

    if a.list:
        for name, spec in sorted(load_schema()["tables"].items()):
            print(f"{name}\t{len(spec['columns'])} columns")
        return 0
    if not a.out:
        print("masquer synth: --out DIR is required", file=sys.stderr)
        return 2
    res = generate(Path(a.out), a.table or None, a.rows, a.seed, a.format, a.encoding, a.dup_rate,
                   injections=not a.no_injection)
    print(f"{len(res['tables'])} tables, {sum(res['tables'].values())} rows, "
          f"{res['canaries']} canaries -> {a.out}")
    return 0


def cmd_case(a: argparse.Namespace) -> int:
    from .case import Case

    c = Case.create(Path(a.dir))
    print(f"case folder {c.root} (mode 700)")
    return 0


def cmd_import(a: argparse.Namespace) -> int:
    from .case import Case

    ner = None
    if not a.no_ner:
        from .ner import NameDetector, default_model_dir

        model = Path(a.ner_model) if a.ner_model else default_model_dir()
        if a.ner_model or (model / "gliner_config.json").is_file():
            ner = NameDetector(model, threshold=a.ner_threshold)
        else:
            print(f"Name-detection model not installed ({model}); importing without it. "
                  "outbox will then need --allow-without-ner.", file=sys.stderr)
    res = Case(Path(a.case)).import_files([Path(f) for f in a.files], a.gap, ner)
    for table, (rows, merged) in res.items():
        print(f"{table}: {rows} rows -> {merged} after collapsing")
    return 0


def cmd_outbox(a: argparse.Namespace) -> int:
    from .case import Case

    prompt = Path(a.prompt).read_text(encoding="utf-8") if a.prompt else None
    case = Case(Path(a.case))
    paths = case.outbox(prompt, a.max_chars, a.allow_without_ner, a.neutralise_injection)
    for p in paths:
        print(f"{p}  ({p.stat().st_size} bytes)")
    if getattr(case, "last_flagged", 0):
        print(f"Instruction-like text in {case.last_flagged} row(s)"
              + (": replaced by «INJECTION_n» tokens." if a.neutralise_injection
                 else "; noted in the header. Use --neutralise-injection if the assistant refuses."))
    print("Egress gate: passed. Paste the file(s) into the chat; save the answer as inbox-N.md in the case.")
    return 0


def cmd_restore(a: argparse.Namespace) -> int:
    import re

    from .case import Case

    case = Case(Path(a.case))
    if a.inbox:
        inbox = Path(a.inbox)
    else:
        found = sorted(case.root.glob("inbox-*.md"),
                       key=lambda p: int(m.group(1)) if (m := re.search(r"(\d+)", p.stem)) else 0)
        if not found:
            print(f"masquer restore: no inbox-N.md in {case.root}. Save the chat answer there first, e.g.\n"
                  f"  macOS: pbpaste > {case.root}/inbox-1.md\n"
                  f"  WSL:   powershell.exe -NoProfile -Command Get-Clipboard > {case.root}/inbox-1.md",
                  file=sys.stderr)
            return 2
        inbox = found[-1]
    if not inbox.is_file() or inbox.stat().st_size == 0:
        print(f"masquer restore: {inbox} is missing or empty; save the chat answer there first", file=sys.stderr)
        return 2
    dest, stats = case.restore(inbox)
    print(f"{dest}: " + ", ".join(f"{k} {v}" for k, v in sorted(stats.items())) or "no tokens")
    if stats.get("unknown") or stats.get("restored_altered"):
        print("Check the lines marked ⚠ in the report.")
    return 0


def cmd_tui(a: argparse.Namespace) -> int:
    try:
        from .tui import run
    except ImportError:
        print("masquer: the TUI isn't installed. Re-run the installer with --with-tui,\n"
              "or use the commands: masquer --help", file=sys.stderr)
        return 2
    return run(Path(a.cases).expanduser() if a.cases else None)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        argv = ["tui"]  # no arguments: the guided TUI
    p = argparse.ArgumentParser(prog="masquer", description=__doc__)
    p.add_argument("--version", action="version", version=f"masquer {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("synth", help="write synthetic Defender exports (test data only)")
    s.add_argument("--out", help="output folder")
    s.add_argument("--table", action="append", help="table name; repeat for several (default: all)")
    s.add_argument("--rows", type=int, default=50, help="rows per table (default 50)")
    s.add_argument("--seed", type=int, default=1, help="random seed (default 1)")
    s.add_argument("--format", choices=["csv", "json"], default="csv")
    s.add_argument("--encoding", choices=["utf-8", "utf-16"], default="utf-8",
                   help="CSV encoding, both with BOM (default utf-8)")
    s.add_argument("--dup-rate", type=float, default=0.1,
                   help="share of rows repeated with only the timestamp changed (default 0.1)")
    s.add_argument("--no-injection", action="store_true",
                   help="leave out the planted prompt-injection strings")
    s.add_argument("--list", action="store_true", help="list the known tables and exit")
    s.set_defaults(func=cmd_synth)

    c = sub.add_parser("case", help="create a case folder")
    c.add_argument("action", choices=["new"])
    c.add_argument("dir")
    c.set_defaults(func=cmd_case)

    i = sub.add_parser("import", help="tokenise, defang and collapse Defender exports into a case")
    i.add_argument("case")
    i.add_argument("files", nargs="+", help="CSV or JSON exports")
    i.add_argument("--gap", type=int, default=3600, help="collapse repeats less than this many seconds apart")
    i.add_argument("--ner-model", help="GLiNER model folder (default: ~/.local/share/masquer/models/gliner-pii)")
    i.add_argument("--ner-threshold", type=float, default=0.4, help="model confidence threshold (default 0.4)")
    i.add_argument("--no-ner", action="store_true", help="skip the name-detection stage")
    i.set_defaults(func=cmd_import)

    o = sub.add_parser("outbox", help="write the paste-ready outbox (egress gate runs first)")
    o.add_argument("case")
    o.add_argument("--prompt", help="file with your own prompt (default: built-in generic prompt)")
    o.add_argument("--max-chars", type=int, default=150_000, help="split into parts above this size")
    o.add_argument("--allow-without-ner", action="store_true",
                   help="write the outbox although the name-detection stage isn't installed")
    o.add_argument("--neutralise-injection", action="store_true",
                   help="replace instruction-like text with «INJECTION_n» tokens (restored in the report)")
    o.set_defaults(func=cmd_outbox)

    r = sub.add_parser("restore", help="put the original values back into a saved answer")
    r.add_argument("case")
    r.add_argument("inbox", nargs="?", help="the saved cloud answer (default: newest CASE/inbox-N.md)")
    r.set_defaults(func=cmd_restore)

    t = sub.add_parser("tui", help="guided full-screen flow (also: masquer with no arguments)")
    t.add_argument("--cases", help="folder holding the cases (default: $MASQUER_CASES or ~/masquer-cases)")
    t.set_defaults(func=cmd_tui)

    a = p.parse_args(argv)
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
