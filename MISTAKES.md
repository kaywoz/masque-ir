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
