# masque-(i)r

`masquer` pseudonymises and defangs Microsoft Defender exports on your own
machine, writes a file you paste into a cloud LLM chat, and fills the answer
back in with the original values, locally.

**MASQUER**: Map, Anonymise, Summarise, Quote, Unlink (defang), Export, Restore.

Status: early build. See [`PLAN.md`](PLAN.md).

## Install

Linux, WSL2 or macOS, as your normal user (no sudo). Download, check it's not
empty, then run: the script checks the prerequisites, installs `uv` (pinned
version from GitHub, SHA256 checked) if it's missing, then installs `masquer`
into `~/.local/bin`.

```bash
T=$(mktemp) && curl -fsSL https://raw.githubusercontent.com/kaywoz/masque-ir/main/install.sh -o "$T" && [ -s "$T" ] && bash "$T"; rm -f "$T"
```

Only check, change nothing: add `--check`. Other modes: `--dry-run`,
`--verify`, `--ref TAG`. Any `FAIL` stops the install.

Needs github.com and codeload.github.com. If
release-assets.githubusercontent.com is blocked or TLS-inspected, `uv` comes
from its PyPI wheel instead (same pinned version, SHA256 checked); a Python
3.11+ must then already be installed. PyPI (pypi.org, files.pythonhosted.org) is only needed to
build from source: when it's blocked, the installer uses the release's
prebuilt wheel instead (checked against the release's `SHA256SUMS`). The wheel
is pure Python, so the same file installs on Linux, WSL2 and macOS.

Fully offline (no GitHub, no PyPI): copy `uv` into `~/.local/bin` and a
release wheel onto the machine, then:

```bash
bash install.sh --wheel masquer-VERSION-py3-none-any.whl
```

Models (later) also need huggingface.co, or `--models-from DIR`.

## Use

```bash
# local machine (shell); CASE is a folder name you choose
masquer case new CASE
masquer import CASE DeviceProcessEvents.csv DeviceNetworkEvents.csv
masquer outbox CASE --allow-without-ner        # writes CASE/outbox-1.md
# paste outbox-1.md into the chat, save the answer as CASE/inbox-1.md
masquer restore CASE CASE/inbox-1.md           # writes CASE/report-1.md
```

- **import**: identity columns become tokens (`«HOST_0001»`, `«UPN_0003»`,
  `«IP_PUB_0002»`), free text is scanned (emails, IPs, URLs, SIDs, GUIDs,
  national IDs with checksums, IBANs, phone numbers, MACs, user paths, UNC
  hosts, domains), then swept for every value already known; URLs are
  defanged, long blobs replaced by their hash; exact repeats less than 1 h
  apart are collapsed (`FirstSeen`, `LastSeen`, `Count`).
- **outbox**: built-in prompt or `--prompt FILE`; split into parts above
  `--max-chars`. The **egress gate** runs first and blocks the outbox if any
  known original or any new detector hit is left.
- **restore**: tokens back to originals; tokens the model altered are restored
  and marked `⚠(was …)`, unknown tokens marked `⚠ unknown token`.
- Deny-lists (always tokenised) and allow-lists (provably not the customer's):
  `~/.config/masquer/deny.txt`, `allow.txt`, and `deny.txt`/`allow.txt` in the
  case folder. One value per line.
- **Not yet:** names that appear only in free text (not in any identity column)
  need the detection stage (local model). Until it lands, `outbox` refuses to
  run without `--allow-without-ner`; check the outbox by hand.

## Synthetic test data

`masquer synth` writes fake Defender advanced-hunting exports: all 66 tables
from the Microsoft Learn schema, every column, as CSV (UTF-8 or UTF-16 with
BOM, CRLF, like a portal export) or JSON. Values are fake and use reserved
ranges (`.example` domains, documentation IPs, fiction phone numbers);
national IDs, IBANs and organisation numbers carry valid checksums so the
detectors can be tested. Every planted sensitive value is listed in
`canaries.json` for leak tests. Exact repeats (only the timestamp differs)
test event collapsing.

```bash
# any host with uv (shell), from a checkout
uv run masquer synth --out ./synth --rows 200
uv run masquer synth --list
```

