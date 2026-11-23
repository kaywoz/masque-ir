# masque-ir: plan (draft, not approved)

Repository `kaywoz/masque-ir` (reads "masquer"; IR = incident response). Command: `masquer`.
MASQUER = Map, Anonymise, Summarise, Quote, Unlink (defang), Export, Restore.

## Goal
Pseudonymise and defang Microsoft Defender exports locally, write a file kaywoz
pastes into a cloud LLM chat by hand, then fill the cloud answer back in with
the original values, locally.

## Decisions (kaywoz, 2026-11-22)
- Not a risky workload: no code execution, no malware. Runs at home / on the work device.
- No API: the tool writes `outbox.md`; kaywoz pastes it into chat and saves the answer as `inbox.md`.
- Input: Defender exports (Advanced Hunting CSV/JSON, alert/incident exports).
- Own repository (to be created by kaywoz).
- Targets: Linux (incl. WSL2 on Windows 11, allowed by IT) and macOS. Native Windows parked.
- CPU only; up to 16 GB RAM.
- Dev host: the Mac mini workstation.
- Real exports may be processed on both the corp laptop (WSL) and the Mac mini (FileVault on).
- Licence: MIT.
- Public repository; one-line installer (`install.sh --check`, then install).
- Paste size: collapse repeats while under 1 h apart, as `first -> last, count`; then split into parts. Repeats are rows equal except the per-event fields Defender sets (Timestamp, ReportId, process id/creation time, NetworkMessageId, LocalPort) — kaywoz 2026-11-23, "make it like real Defender data" (was: equal except Timestamp).
- Prompt: `--prompt FILE` for a custom prompt; otherwise a built-in generic prompt with no case or customer context (triage summary, timeline, ATT&CK mapping, IOCs, follow-up KQL; KQL comes back runnable after restore).
- Follow-up rounds: `masquer ask` -> `outbox-N.md` / `inbox-N.md`, same case tokens.
- Claude Project: repo ships `project-instructions.md`, pasted once by kaywoz.
- Anything belonging to a customer or tenant (resources, assets, public IPs, public domains) is always tokenised, public or not. The allow-list only covers values that are provably not the customer's (vendor domains such as Microsoft's, system paths).
- National identifiers of any country (personal and company IDs, with checksums), international phone numbers and IBANs are detected; candidate libraries `python-stdnum` and `phonenumbers` (unverified here).
- Deny-lists: global + per customer, local only (`~/.config/masquer/`), never in git.
- Tokens per case; nothing links across cases.
- Installer pins the latest tagged release; `uv.lock` with hashes; models pinned by SHA256.
- CI: leak tests with planted canaries, Linux + macOS (check `workflow` token scope first).
- v1 input: Advanced Hunting CSV/JSON, alert and incident exports. Investigation package (zip) parked.
- Retention: warn on cases older than 30 days, offer `masquer case wipe`.
- Repo gets its own CLAUDE.md and MISTAKES.md (PII, reply style, verify-first carried over).
- Packaging: native `uv` install first; container as an option for portability (OCI image on GHCR, Docker or Podman; models mounted from the host; wrapper runs it with `--network none`, `--read-only`, `--cap-drop ALL`, case folder bind-mounted). Docker Desktop licence: use Docker Engine or rootless Podman inside WSL.
- Speed test before v1: native vs container, on the Mac mini (native Metal vs Podman libkrun/krunkit with GPU via Vulkan; the container image needs a llama.cpp Vulkan build) and the corp laptop (WSL native vs container), same synthetic export; results in the PR.
- Name: repository `masque-ir`, command `masquer` (kaywoz, 2026-11-22).

## Pipeline
1. Ingest: copy the export into the case folder (inside WSL, not /mnt/c); parse per column; handle BOM/UTF-16, CRLF, JSON-in-cell (`AdditionalFields`).
2. Tokenise by column: device, account name/UPN/SID/object ID, IPs, URLs, tenant ID, user paths -> `«TYPE_NNNN»`. Keep hashes, ActionType, file names, timestamps, MITRE IDs.
3. Free-text pass: GLiNER-PII (ONNX Runtime, CPU) flags leftover identities; flagged spans are tokenised as in step 2.
4. Optional recheck: Qwen3.5 4B Q4 via llama-cpp-python (flag-enabled), on flagged/uncertain spans only.
5. Defang: URLs/domains (`hxxp`, `[.]`), long blobs -> hash + length.
6. Egress gate: regex + local deny-list scan of the output; any hit blocks writing `outbox.md`.
7. `outbox.md`: paste-ready prompt + data; tells the model to keep `«…»` tokens verbatim.
8. Re-hydrate: `inbox.md` -> `report.md` with originals filled in; unknown/altered tokens flagged, never guessed. `report.redacted.md` and `outbox.md` kept for audit.

## Security
- Mapping store (SQLite) per case, folder 700 / files 600, on an encrypted disk; deleted or archived with the case.
- No network: no HTTP client in the code; `--verify` checks for no sockets.
- Models in `models/` with SHA256 checksums; never downloaded by the tool.
- Deny-list (own names, tenant names, known secrets) lives on the device only, never in git.
- Input is untrusted data (prompt injection in command lines): the local model only flags, it never decides what leaves; step 6 is the final gate.

## Install
`uv` in the user profile (no admin); wheel install; `models/` copied in once.
WSL: raise `memory=` in `.wslconfig` if WSL sees under ~8 GB.

## Open

- Column headers (no rows) of 2-3 real exports, to build the synthetic generator.
- Model licences, sizes, Swedish support, GLiNER ONNX export: unverified (Hugging Face / Ollama blocked in the planning session).
- CPU speed of the 4B model: measure on the first test.

## Built so far
- `install.sh --check/--dry-run/--verify` (#2); install mode: uv pinned from GitHub with SHA256, masquer via `uv tool install` (kaywoz 2026-11-23: uv is a prerequisite the installer adds when missing).
- `masquer synth`: synthetic exports for all advanced-hunting tables from the Microsoft Learn schema (kaywoz 2026-11-23: build from the schema docs, as much as possible). Real export headers can still correct column order or format later.

- Core pipeline: import (column rules, detectors, known-values sweep, defang, collapse), outbox with egress gate, restore; leak tests against `canaries.json` in CI (Linux, macOS). Full synthetic run (66 tables, 13,200 rows, 78,373 canaries): import 25 s, outbox and gate 21 s; only `person_name` and `file_pii` leak, by design until the detection stage.

## Next
- Detection stage (GLiNER-PII, then optional Qwen recheck) for names in free text; drop `--allow-without-ner` once leak tests pass for all kinds.
- Outbox size: a full 66-table export is 7 MB (53 parts); add per-table summaries and a `--tables`/time-window filter for chat-sized outboxes.

## Parked
Native Windows build, API mode, other input sources, MDE investigation package.
- Web UI (later, kaywoz 2026-11-23): local import/export: drop an export in, copy the outbox, paste the answer, download the report. Loopback only, with a per-run token; native mode first. Container mode needs a way to publish a port without outbound network (e.g. an internal network with no route out), to be designed then.
