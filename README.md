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

Needs: github.com, release-assets.githubusercontent.com, codeload.github.com,
pypi.org and files.pythonhosted.org. Models (later) also need huggingface.co,
or `--models-from DIR`.

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

