import csv
import json

from masquer.cli import main
from masquer.synth import generate, load_schema


def read_csv(p, encoding="utf-8-sig"):
    with open(p, encoding=encoding, newline="") as fh:
        return list(csv.DictReader(fh))


def test_all_tables_written(tmp_path):
    res = generate(tmp_path, rows=10)
    schema = load_schema()["tables"]
    assert set(res["tables"]) == set(schema)
    for name, spec in schema.items():
        rows = read_csv(tmp_path / f"{name}.csv")
        assert len(rows) == 10
        assert list(rows[0]) == [c["name"] for c in spec["columns"]]


def test_csv_is_bom_crlf(tmp_path):
    generate(tmp_path, tables=["DeviceProcessEvents"], rows=3)
    raw = (tmp_path / "DeviceProcessEvents.csv").read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf") and b"\r\n" in raw


def test_utf16(tmp_path):
    generate(tmp_path, tables=["DeviceLogonEvents"], rows=3, encoding="utf-16")
    raw = (tmp_path / "DeviceLogonEvents.csv").read_bytes()
    assert raw[:2] in (b"\xff\xfe", b"\xfe\xff")
    assert len(read_csv(tmp_path / "DeviceLogonEvents.csv", "utf-16")) == 3


def test_deterministic(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    generate(a, tables=["DeviceNetworkEvents"], rows=20, seed=5)
    generate(b, tables=["DeviceNetworkEvents"], rows=20, seed=5)
    assert (a / "DeviceNetworkEvents.csv").read_bytes() == (b / "DeviceNetworkEvents.csv").read_bytes()


def test_canaries_appear_in_data(tmp_path):
    generate(tmp_path, tables=["DeviceProcessEvents", "EmailEvents", "IdentityInfo"], rows=40)
    meta = json.loads((tmp_path / "canaries.json").read_text("utf-8"))
    data = "".join(p.read_text("utf-8-sig") for p in tmp_path.glob("*.csv"))
    planted = [v for vals in meta["canaries"].values() for v in vals]
    assert planted
    # Every value that was planted shows up somewhere (CSV may quote or escape).
    missing = [v for v in planted if v not in data and json.dumps(v)[1:-1] not in data]
    assert not missing, missing[:5]
    for kind in ["device", "upn", "email", "national_id", "ip_private"]:
        assert meta["canaries"].get(kind), kind


def test_exact_duplicates_present(tmp_path):
    generate(tmp_path, tables=["DeviceNetworkEvents"], rows=200, dup_rate=0.3)
    rows = read_csv(tmp_path / "DeviceNetworkEvents.csv")
    from masquer.masker import EVENT_FIELDS
    keys = [tuple(v for k, v in r.items() if k not in EVENT_FIELDS) for r in rows]
    assert len(set(keys)) < len(keys)


def test_cli_list_and_run(tmp_path, capsys):
    assert main(["synth", "--list"]) == 0
    assert "DeviceProcessEvents" in capsys.readouterr().out
    assert main(["synth", "--out", str(tmp_path), "--table", "AlertInfo", "--rows", "5", "--format", "json"]) == 0
    assert len(json.loads((tmp_path / "AlertInfo.json").read_text("utf-8"))) == 5
