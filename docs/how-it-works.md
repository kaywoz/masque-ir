# How masquer works

This page is for contributors and for anyone who wants to check what leaves
the machine. Design decisions and the reasons for them are in
[../PLAN.md](../PLAN.md).

## Pipeline

```
import:  parse ─► column rules ─► free-text detectors ─► name model (optional) ─► sweep known values ─► defang ─► collapse ─► CASE/masked/*.json
outbox:  render tables + prompt ─► egress gate ─► CASE/outbox-N.md
restore: token lookup ─► CASE/report-N.md
```

Tokens look like `«KIND_NNNN»` and are numbered per case. The mapping lives in
`CASE/map.sqlite` (mode 600) and nothing links tokens across cases.

## import

1. **Parse.** Reads CSV (UTF-8 or UTF-16 with BOM, CRLF) and JSON, including JSON inside cells such as `AdditionalFields`.
2. **Column rules.** Identity columns are tokenised by kind: `DeviceName` → `HOST`, `AccountUpn` → `UPN`, `AccountSid` → `SID`, IPs → `IP_PRIV` or `IP_PUB`, and so on.
3. **Free-text detectors** run over command lines, URLs, subjects and other free text:
   - emails;
   - private and public IPs, MACs;
   - URLs, and domains (aware of TLDs);
   - SIDs, GUIDs;
   - national IDs with checksums: SE personnummer and organisationsnummer, NO, DK, FI, UK, US;
   - IBANs (mod 97), phone numbers;
   - `DOMAIN\account` (upper-case NETBIOS names only), `net user` and `/user:` arguments, `first.last`;
   - user profile paths, UNC hosts.
4. **Name model** (optional). A local GLiNER model (`knowledgator/gliner-pii-edge-v1.0`, Apache-2.0, 185 MB, pinned by revision and SHA256) finds person names. It can only add tokens.
   - Threshold 0.4; a single word needs 0.6.
   - Spans with digits and a stop-list of product and folder words are never names.
5. **Sweep.** Every value already in the store is replaced wherever it occurs, using one trie-shaped regex (`triere.py`) built once per import. The cost is O(text length).
6. **Kept as is:**
   - built-in Windows principals (`SYSTEM`, `NT AUTHORITY`, `BUILTIN`, …) and well-known SIDs (`S-1-5-18`, `S-1-5-32-*`, …);
   - vendor domains from the allow-list;
   - hashes, paths and timestamps.
7. **Defang.**
   - URL schemes become `hxxp`, `hxxps` and `fxp`; kept domains get `[.]`.
   - Base64 runs of 64+ characters and hex runs of 129+ characters become `«BLOB sha256=… len=…»`. BLOBs are not restored.
8. **Collapse.** Rows that are equal apart from the fields Defender sets per event are merged when they are less than `--gap` apart (default 1 h). The per-event fields are `Timestamp`, `ReportId`, `ProcessId`, `ProcessCreationTime`, `ProcessUniqueId`, `LocalPort`, `NetworkMessageId`, `InternetMessageId`, `LogonId` and `EventId`. The merged row keeps the first event's values and gains `FirstSeen`, `LastSeen` and `Count`.

## outbox and the egress gate

- The outbox is rendered as the prompt, then the rules, then one tab-separated block per table. Parts stay within `--max-chars`. A table bigger than a part is cut by `split_block()` into whole-row chunks, each repeating the heading (`rows a-b of n`) and the column row. Every row appears exactly once.
- **Injection.** Rows with instruction-like text ("ignore previous instructions", `</data>`, `system:` …) are counted and noted in the header. `--neutralise-injection` replaces them with tokens.
- **Egress gate.** This is the last step before the file is written. It blocks the outbox if:
  - any original value from the store is still in the text; or
  - any detector finds a new hit. These hits are collected in a scratch store, so the case is untouched.
- The gate is deterministic. The name model can flag spans but never decides what leaves.

## restore

- The answer's outer ```` ```markdown ```` fence is removed, and inner `~~~` fences become ```` ``` ```` again.
- Exact tokens are replaced by their originals.
- Tokens missing only their `« »` (`HOST_0003`) are restored without a marker and counted as `restored_bare`.
- Tokens altered in any other way (different zero padding) are matched, restored and marked `⚠(was …)`.
- Tokens that aren't in the case are left as they are and marked `⚠ unknown token`.
- A `«…»` that looks like a token with stray characters inside (`«A*COUNT_0003»`) is never guessed. It's marked `⚠ damaged token, copy the answer again`.

## Synthetic data (`masquer synth`)

- **Tables.** All 66 advanced-hunting tables and 1659 columns, taken from the Microsoft Learn schema docs (`src/masquer/schema/defender_tables.json`, built by `tools/extract_schema.py`).
- **Output.** CSV (UTF-8 or UTF-16 with BOM, CRLF, as the portal exports it) or JSON.
- **Fake values only.** Domains use `.example` and `.test`, IPs use documentation ranges, and phone numbers are fictional.
- **Valid checksums.** National IDs, IBANs and organisation numbers carry valid checksums so the detectors can be tested.
- **A consistent world.** Devices, users and binaries keep their names, IDs, SIDs, signers, paths and sizes across rows and tables, and process trees are in time order.
- **One storyline per victim, with fixed step times shared by all tables:**
  1. phishing mail;
  2. `.docm` opened from Outlook;
  3. hidden PowerShell with a real UTF-16LE `-enc`;
  4. `certutil` download;
  5. `a.exe` from `Temp`;
  6. domain discovery, scheduled task, SMB copy, `curl` exfiltration, SMTP.
- **Campaign realism.**
  - Victims are workstations.
  - The dropped `a.exe` is one build, with the same hashes and size on every host.
  - A storyline process is created once, so every table shows the same PID, creation time and parent for it.
  - Columns the generator doesn't model get plain values (adapter facts, JSON IP lists). Registry fields are filled mostly in registry events.
  - Planted PII and injection strings go only into free-text columns (subjects, descriptions, command lines, `AdditionalFields`).
- **Repeats** differ only in the per-event fields, to test collapsing.
- **Leak tests.** Every planted sensitive value is listed in `canaries.json`, and the CI leak tests fail if any of them reaches an outbox.
- **Injection strings.** Planted prompt-injection strings are included unless you pass `--no-injection`.
