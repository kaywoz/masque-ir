# MISTAKES.md

A log of mistakes made while planning, building or PR'ing changes here.
Read it in full before starting new work. Add an entry whenever something
turns out to have been based on a misunderstanding.

## Entry format

```markdown
### YYYY-MM-DD — <area/slug>

- **Trigger:** wrong assumption / CI failed / PR rejected / misunderstood request
- **What happened:** one or two sentences, factual
- **Root cause:** why it happened
- **Fix applied:** what was changed
- **Rule going forward:** one concrete, checkable rule (or a pointer to CLAUDE.md)
```

## Carried over from kaywoz/home0ps

- Place a workload by what it executes or handles, not by its topic (log analysis without code execution or malware isn't "risky"). *(home0ps 2026-11-22)*
- Every step for kaywoz is a copy-paste command or a checked click path; say so when a UI path is unconfirmed. *(home0ps 2026-11-20)*
- Check an app's issue tracker as well as its docs before relying on a flag's behaviour. *(home0ps 2026-11-22)*

---

## New entries

### 2026-11-23 — install (RAM check rounded down)

- **Trigger:** wrong result on a host
- **What happened:** `install.sh --check` on WSL2 reported `FAIL ram 7 GB total; need 8 GB`. The RAM figure was `MemTotal` floored to whole GiB, and the kernel reserves memory, so an 8 GB machine or WSL VM reports about 7.6-7.9 GiB and always floored to 7.
- **Root cause:** compared a floored, reserved-memory figure against a nominal size without checking what `MemTotal` reports on a machine of that size.
- **Fix applied:** RAM compared in MiB with 0.5 GiB slack (fail under 7.5 GiB, warn under 11.5 GiB), shown with one decimal.
- **Rule going forward:** size checks against nominal hardware sizes allow for kernel-reserved memory and never floor before comparing.

### 2026-11-23 — chat (checkout assumed to exist)

- **Trigger:** command failed on the host
- **What happened:** the release-tag command started with `cd masque-ir` in kaywoz's `github` folder; there was no masque-ir checkout there, so `cd` failed. A clone was only mentioned as an afterthought.
- **Root cause:** assumed a local checkout existed instead of making the command create or find it (repeat of home0ps 2026-11-23, guessed checkout path).
- **Fix applied:** the command clones into a temporary folder when no checkout is given.
- **Rule going forward:** commands for kaywoz's machines never assume a checkout or folder exists; they clone into `mktemp -d`, or test for the path first and say what to do if it's missing.

### 2026-11-23 — chat (manual step inside a command block)

- **Trigger:** command failed on the host
- **What happened:** the walkthrough's command block had the manual step (paste into chat, save the answer) as a comment between commands. Pasted whole, `masquer restore` ran before `inbox-1.md` existed and printed a Python traceback.
- **Root cause:** wrote one block for a flow with a human step in the middle; the CLI had no friendly error for a missing inbox.
- **Fix applied:** `restore` defaults to the newest `inbox-N.md` and exits 2 with a clear message (and how to save the clipboard) when none exists.
- **Rule going forward:** a command block handed to kaywoz stops at the first manual step; the commands after it go in a separate block.

### 2026-11-23 — pipeline (accounts tokenised as domains; NETBIOS left in clear)

- **Trigger:** found by the cloud model's review of a synthetic outbox
- **What happened:** dotted account names (`anna.lindqvist`) matched the domain detector and became `«DOMAIN_…»`; the store's one-token-per-original rule then made the same account a DOMAIN everywhere (`C:\Users\«DOMAIN_0043»`). A NETBIOS domain before `\` (`/ru NORDVIND\user`) was only tokenised when already known from another column.
- **Root cause:** the domain regex accepted any last label of 2-24 letters as a TLD; no detector for `DOMAIN\account`; leak tests passed because over-matching still hid the values, so the wrong kind went unnoticed.
- **Fix applied:** domains need a real or internal TLD; new detectors for `DOMAIN\account` (also after an already-tokenised domain), `net user NAME` / `/user:NAME`, and standalone `first.last` names as ACCOUNT; tests per case.
- **Rule going forward:** leak tests check that a value is hidden *and* tests check the token kind for each detector; a detector change runs the full synthetic leak check before the PR.

### 2026-11-23 — synth (ActionType in the wrong table)

- **Trigger:** found by the cloud model's review of a synthetic outbox
- **What happened:** the generator put `OpenProcessApiCall` in `DeviceProcessEvents`; it's a `DeviceEvents` ActionType.
- **Root cause:** the hand-kept "common ActionType" list was written from memory, not checked against the schema reference.
- **Fix applied:** moved to `DeviceEvents`.
- **Rule going forward:** hand-kept schema facts in the generator get a source or are marked unverified in the code.

### 2026-11-23 — docs (logo edited without asking)

- **Trigger:** misunderstood request
- **What happened:** kaywoz shared a logo image for the README. The copy that reached the session was an RGB WebP with no alpha channel and a grey checkerboard baked into the pixels. Claude keyed the checkerboard out and committed its own cleaned version. kaywoz: "it should be transparent already".
- **Root cause:** Claude edited the asset to fit what it received instead of reporting that the received copy had lost its transparency.
- **Fix applied:** none to the logo; kaywoz's original file can replace `docs/logo.png`.
- **Rule going forward:** if a supplied asset doesn't match what it should be (no alpha, wrong size or format), report what was received (`mode`, `format`) and ask for the original file before editing it.

### 2026-11-23 — tui (export folder chosen for kaywoz)

- **Trigger:** correction from kaywoz
- **What happened:** the TUI listed exports from `~/Downloads` and accepted any typed path, a default Claude chose and only noted as an assumption in the PR. kaywoz: "the tui should only look in a designated folder decided on when you run masquer with a flag".
- **Root cause:** Claude picked a convenient default for where real exports are read from, instead of asking. That's a data-handling decision.
- **Fix applied:** `masquer --exports DIR` (or `$MASQUER_EXPORTS`) is the only folder the TUI reads. Without it, Import is disabled. Typed paths outside it are refused, `..` and symlinks included.
- **Rule going forward:** where the tool reads real data from, or writes it to, is kaywoz's decision. Propose it, don't default it.

### 2026-11-26 — chat (lint finding read from its title)

- **Trigger:** wrong assumption
- **What happened:** reviewing compose-lint on home0ps, Claude said its 20 CL-0026 findings ("no resource limits") conflicted with the house `mem_limit` rule. The findings' messages say "no CPU limit"; every flagged service sets `mem_limit`.
- **Root cause:** summarised findings by rule title and count without reading one finding's message.
- **Fix applied:** corrected in chat; CL-0026 there is a missing `cpus` setting, which the house standard doesn't require.
- **Rule going forward:** before calling a tool's finding drift, read at least one full finding message and the source line it points to.
