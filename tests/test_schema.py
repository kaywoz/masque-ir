from masquer.synth import load_schema


def test_schema_has_all_tables():
    s = load_schema()
    assert len(s["tables"]) >= 60
    assert s["source_commit"]
    for name in ["DeviceProcessEvents", "DeviceNetworkEvents", "DeviceLogonEvents",
                 "DeviceFileEvents", "AlertInfo", "AlertEvidence", "EmailEvents",
                 "IdentityLogonEvents", "CloudAppEvents"]:
        assert name in s["tables"], name


def test_columns_are_typed():
    allowed = {"string", "int", "float", "bool", "datetime", "dynamic", "guid"}
    for name, spec in load_schema()["tables"].items():
        assert spec["columns"], name
        for c in spec["columns"]:
            assert c["type"] in allowed, (name, c)
