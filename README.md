# masque-(i)r

`masquer` pseudonymises and defangs Microsoft Defender exports on your own
machine, writes a file you paste into a cloud LLM chat, and fills the answer
back in with the original values, locally.

**MASQUER**: Map, Anonymise, Summarise, Quote, Unlink (defang), Export, Restore.

Status: early build. See [`PLAN.md`](PLAN.md).

## Check your machine

Linux, WSL2 or macOS, as your normal user (no sudo):

```bash
T=$(mktemp) && curl -fsSL https://raw.githubusercontent.com/kaywoz/masque-ir/main/install.sh -o "$T" && [ -s "$T" ] && bash "$T" --check; rm -f "$T"
```

One line per check: `PASS`, `WARN`, `FAIL` or `INFO`. Any `FAIL` exits 1.
The install itself isn't available yet.

Targets: Linux (including WSL2 on Windows 11) and macOS, CPU only, no network.

Licence: [MIT](LICENSE).
