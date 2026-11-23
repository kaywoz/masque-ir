"""Build src/masquer/schema/defender_tables.json from the Advanced Hunting docs.

Usage: python3 -I tools/extract_schema.py DOCS_DIR SOURCE_COMMIT

DOCS_DIR holds the `advanced-hunting-*-table.md` pages (Microsoft Learn,
Defender XDR). Only column names, data types and ActionType values seen in
the pages are kept: no description text.
"""
import json
import re
import sys
from pathlib import Path

TYPE_MAP = {
    "string": "string", "enum": "string",
    "datetime": "datetime",
    "int": "int", "integer": "int", "long": "int",
    "real": "float",
    "bool": "bool", "boolean": "bool", "nullablebool": "bool",
    "guid": "guid",
    "dynamic": "dynamic", "object": "dynamic",
}
CELL = re.compile(r"[`*]")
ACTION_EQ = re.compile(r'ActionType\s*(?:==|=~|has|contains)\s*"([A-Za-z][A-Za-z0-9_]+)"')
ACTION_IN = re.compile(r"ActionType\s+in\s*\(([^)]*)\)")
QUOTED = re.compile(r'"([A-Za-z][A-Za-z0-9_]+)"')


def cells(line):
    return [CELL.sub("", c).strip() for c in line.strip().strip("|").split("|")]


def parse_page(text):
    lines = text.splitlines()
    cols = []
    for i, line in enumerate(lines):
        if line.startswith("|") and cells(line)[:2] == ["Column name", "Data type"]:
            for row in lines[i + 2:]:
                if not row.startswith("|"):
                    break
                c = cells(row)
                if len(c) >= 2 and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", c[0]):
                    cols.append({"name": c[0], "type": TYPE_MAP.get(c[1].lower(), "string")})
            break
    actions = set(ACTION_EQ.findall(text))
    for group in ACTION_IN.findall(text):
        actions.update(QUOTED.findall(group))
    for i, line in enumerate(lines):  # "| Action | Description |" tables
        if line.startswith("|") and cells(line)[:1] == ["Action"]:
            for row in lines[i + 2:]:
                if not row.startswith("|"):
                    break
                v = cells(row)[0]
                if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]+", v):
                    actions.add(v)
    return cols, sorted(actions)


def main(docs_dir, commit):
    tables = {}
    for page in sorted(Path(docs_dir).glob("advanced-hunting-*-table.md")):
        text = page.read_text(encoding="utf-8")
        title = re.search(r"^#\s+(\w+)", text, re.M)
        cols, actions = parse_page(text)
        if not cols or not title:
            print(f"skip {page.name}: no column table", file=sys.stderr)
            continue
        tables[title.group(1)] = {"columns": cols, "action_types": actions}
    out = {
        "source": "Microsoft Learn, Defender XDR advanced hunting schema "
                  "(learn.microsoft.com/defender-xdr/advanced-hunting-schema-tables), "
                  "via github.com/merill/defender-docs-mirror",
        "source_commit": commit,
        "tables": tables,
    }
    dest = Path(__file__).resolve().parent.parent / "src/masquer/schema/defender_tables.json"
    dest.write_text(json.dumps(out, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    n = sum(len(t["columns"]) for t in tables.values())
    print(f"{len(tables)} tables, {n} columns -> {dest}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
