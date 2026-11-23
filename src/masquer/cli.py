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
    res = generate(Path(a.out), a.table or None, a.rows, a.seed, a.format, a.encoding, a.dup_rate)
    print(f"{len(res['tables'])} tables, {sum(res['tables'].values())} rows, "
          f"{res['canaries']} canaries -> {a.out}")
    return 0


def main(argv: list[str] | None = None) -> int:
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
    s.add_argument("--list", action="store_true", help="list the known tables and exit")
    s.set_defaults(func=cmd_synth)

    a = p.parse_args(argv)
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
