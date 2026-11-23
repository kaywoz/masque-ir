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
