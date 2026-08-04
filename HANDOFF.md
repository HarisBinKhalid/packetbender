# Handoff: PacketBender

This document exists so another AI agent (or a human) can pick up this project
with zero prior context. Read this first, then the code — it's small enough
to read in full (~2,500 lines across `packetbender/` + `tests/`).

## What this is

A desktop GUI (PyQt6 + Scapy) for viewing and editing packets inside PCAP
files, aimed at SIP/RTP telecom debugging but general enough to edit any
packet's L2-L4 fields. Think "Wireshark, but you can actually edit and save."

The user is testing this against **real production SIP/RTP call captures**
(one specific file referenced throughout development:
`~/Work/Pcaps/AMR_320/2022-05-23_11-23-21__971547939795_0564140364__ID218241490.pcap`,
2333 packets, AMR voice call signaling). When adding features or fixing bugs,
prefer verifying against a real capture like this over synthetic test
packets alone — several real bugs (see "Bugs found and fixed" below) only
showed up against real captured data, not hand-built Scapy packets.

## Current state

Fully working, 71 passing tests, 15 commits, actively iterating based on
direct user testing/feedback (not a spec handed down up front — the whole
history is "try it, report what's broken or missing, fix it"). Not yet
pushed to a GitHub remote (see "Immediate next step" below).

Read `CHANGELOG.md` top to bottom for the full feature/fix history — it's
kept genuinely up to date, not an afterthought. `README.md` covers user-facing
usage. This file covers what those two don't: internal design reasoning,
traps for the next editor, and workflow/process notes.

## Directory name situation (read this before doing anything filesystem-related)

The repo currently lives at `/home/haris/development/PacketChanger` even
though the project itself is named **PacketBender** everywhere else (package
name, window title, pyproject.toml, README). The user asked for the folder
to be renamed to match, it *was* renamed successfully mid-session, and then
at some point silently reverted back to `PacketChanger` on disk (most likely
the IDE's workspace binding restored its original root path — this wasn't a
git operation, git history is untouched). If asked to rename it again, do it,
verify with `ls`, but don't be surprised if it doesn't stick across
IDE/session boundaries — that's environment behavior outside this repo's
control, not a bug to chase.

## Architecture

```
packetbender/
  core/                    # No PyQt imports anywhere in here - all unit-testable headless
    sip_message.py         # SIP parse/serialize (text protocol, treated as HTTP-like headers+body)
    sdp_message.py         # SDP parse/serialize (ordered type=value lines, no semantic modeling)
    rtp_message.py         # Minimal RTP fixed-header dissector (scapy has NO built-in RTP layer)
    xml_message.py         # XML detect/validate/pretty-print (xml.dom.minidom)
    layer_fields.py         # Generic L2-L4 field introspection for ANY scapy packet
    bulk_edit.py             # Apply one field change across every matching packet at once
    pcap_model.py             # PcapModel (load/save) + PacketRecord (per-packet state + edits)
  gui/
    main_window.py            # Single QMainWindow: packet list + tabbed editor panel
    bulk_edit_dialog.py        # Bulk Edit modal dialog
  app.py                       # QApplication entry point
tests/                          # Mirrors core/ + a few GUI-level test files
main.py                          # `python main.py` launcher (no install needed)
build.sh, packetbender.spec       # PyInstaller standalone executable build
```

### Data model

`PcapModel.load(path)` produces a list of `PacketRecord`, one per packet.
Each `PacketRecord` holds:
- `packet` — the actual Scapy `Packet` object (mutated in place for edits)
- `sip` / `rtp` / `sdp` / `xml` — parsed protocol-specific view, `None` if not
  detected. **SIP body containing SDP/XML does NOT set `record.sdp`/`record.xml`**
  — that's a GUI-level concern (the SIP tab's body sub-tabs parse/serialize
  `sip.body` on the fly). `record.sdp`/`record.xml` are only for *standalone*
  non-SIP payloads.
- `manual_fields` — set of `(layer_name, field_name)` the user explicitly
  pinned via the Layers tab's "Auto" checkbox, so length/checksum recompute
  skips them.

`PacketRecord.apply_edits()` is the single choke point for "make the in-memory
packet consistent after any edit": re-serializes sip/rtp/sdp/xml payload if
present, deletes computed length/checksum fields (unless manually pinned) to
force Scapy to recompute them, then calls `finalize_packet()` to clear
Scapy's dissection cache. **Every mutation path (single-packet edit, bulk
edit) must go through this** — don't hand-roll a parallel path.

### GUI structure

One `QMainWindow`. Left: packet list (`QTableWidget`, sortable/filterable,
columns toggle via header right-click). Right: tabbed editor panel, closed by
default, opens via double-click on a row or reopens via double-click after
being closed with the "✕" button. Tabs shown depend on what the selected
packet is: Layers (always) + one of SIP/RTP/SDP/XML/Raw Payload depending on
detection. The SIP tab nests SDP Fields / XML sub-tabs inside its Body
section when `Content-Type` calls for it.

**Selection is not row-index based.** Once sorting/filtering exist, "visual
row N" and "`model.records[N]`" are different things. Every row's column-0
item carries the record's real index in `Qt.ItemDataRole.UserRole`
(`_record_index_at_row` / `_visual_row_for_index` in `main_window.py`). If
you add new code that touches `self.current_index` or reselects a row after
mutating data, use those helpers — don't assume row position.

## Bugs found and fixed (read before touching related code)

These were real, user-reported bugs against the actual capture file, not
hypotheticals — worth understanding before changing nearby code, since the
underlying traps are non-obvious and easy to reintroduce.

1. **Scapy's `raw_packet_cache`**: after clearing a length/checksum field
   from `layer.fields` to force recompute, Scapy can still silently replay
   the *original captured bytes* for that layer unless you also clear
   `layer.raw_packet_cache` / `raw_packet_cache_fields`. `finalize_packet()`
   in `layer_fields.py` does this. If you ever bypass `apply_edits()`, you
   will hit this again.

2. **PcapNgReader has no `.linktype` attribute** (unlike classic `PcapReader`
   — pcapng stores link-layer type per-interface). `PcapModel.load()` uses
   `getattr(reader, "linktype", None)`.

3. **Unrecognized/misdissected link-layer type → everything shows as opaque
   `Raw`.** `PcapModel.load()` retries as Ethernet, then bare IP, before
   giving up, and surfaces a warning naming the link-layer type.

4. **The big one — field-corruption bug**: the Layers tab used to reapply
   *every displayed field's text* on Apply, not just the one the user
   edited. Fields that don't round-trip through `str()` → `parse_field_value()`
   unchanged (notably `IP.options`, a list, displayed as `"[]"`) got
   reapplied as the literal 2-character string `"[]"`, which Scapy encodes
   as real header bytes — desyncing the header from its own length/IHL
   field and shifting everything after it. Symptom: editing just an IP
   address corrupted the packet, Wireshark reported a length error on
   reopen. Fixed in `_apply_layers_tab` (`main_window.py`): only touch a
   field if its displayed text actually changed from what was loaded.
   **Any new bulk/generic field-editing code must preserve this "only touch
   what changed" discipline**, or must restrict itself to known-scalar
   fields the way `bulk_edit.py`'s `SAFE_BULK_FIELDS` does.

5. **PyInstaller + Scapy**: Scapy loads its protocol layer modules dynamically
   at runtime, not via top-level imports PyInstaller's static analysis can
   see. Without `collect_submodules('scapy')` in `packetbender.spec`, the
   packaged binary launches fine but silently fails to dissect almost
   everything. Already handled — just don't remove it.

6. **Qt reentrancy in `BulkEditDialog`**: repopulating a `QComboBox` (`clear()`
   + `addItems()`) fires `currentTextChanged` synchronously and reentrantly,
   which crashed the whole process (native abort, not a catchable Python
   exception) when that signal was wired to the live-preview updater. Fixed
   by blocking signals during repopulation and updating the preview once,
   explicitly, afterward. **Watch for this pattern anywhere a combo box
   repopulate is wired to another live-updating signal.**

7. **Qt header default sort order is `Descending`**, not `Ascending`, before
   any column is clicked — an undocumented Qt quirk, confirmed by testing.
   `main_window.py` explicitly sets `header.setSortIndicator(0, Qt.SortOrder.AscendingOrder)`
   on startup to override it.

## Design decisions worth knowing (so you don't relitigate them)

- **RTP detection is a heuristic** (`version` bits == 2 in the first byte).
  Scapy has no RTP layer at all, and RTP has no fixed signature to detect it
  by. False positives on arbitrary binary UDP payloads are possible and
  accepted as a tradeoff — documented in the RTP tab's own label text.
- **Bulk edit only touches "safe" scalar fields** (`SAFE_BULK_FIELDS` in
  `bulk_edit.py`) — addresses/ports/TTL, deliberately excluding
  non-scalar fields like `IP.options`/flags for the same reason as bug #4
  above. Don't widen this list without re-checking the round-trip safety of
  whatever field you're adding.
- **Filter bar only applies on Enter**, not on every keystroke — this was a
  direct user request (avoid re-scanning the list mid-word). Don't wire it
  back to `textChanged`.
- **The Bulk Edit dialog has a live match-count preview** ("This will change
  N packets") that recomputes on every relevant field change. This exists
  specifically because the user reported "bulk edit only changed 1 packet"
  and it couldn't be reproduced via the actual code path — the preview was
  added so future instances of that class of confusion are visible
  immediately rather than requiring a bug report to diagnose.
- **CHANGELOG versioning became loose partway through**: early commits bump
  `__version__`/`pyproject.toml` per feature (0.1.0 → 0.4.0), but several
  recent fix/feature commits were folded into an ongoing "Unreleased"
  section without a version bump. This was a deliberate choice to match
  established pattern rather than bump on every single commit — continue
  accumulating under Unreleased unless the user asks for a release cut.

## Testing conventions

- `tests/` mirrors `core/` module-for-module, headless (no Qt event loop
  needed) — these are fast and should cover all business logic.
- GUI tests (`test_gui_*.py`) construct a real `QApplication`/`MainWindow`
  and exercise widget state directly (not through `dialog.exec()`, which
  blocks — for dialogs, either call the underlying core function directly
  after reading dialog widget state, or monkeypatch `.exec()` to auto-accept
  with preset field values, per the pattern in `test_gui_bulk_edit.py`).
- A `$DISPLAY` is available in this environment so real `QApplication`
  instances work in tests without needing `QT_QPA_PLATFORM=offscreen`.
- Run everything: `.venv/bin/python -m pytest -q` (venv already has
  scapy/PyQt6/pytest installed — don't recreate it unless it's missing).
- **When fixing a reported bug, reproduce it first against the real
  capture file** (or a synthetic packet crafted to match the exact failure
  mode) before touching code, and add a regression test that fails without
  the fix and passes with it — every bug fix in this project's history
  followed that pattern (see commit messages for `git log`).

## Immediate next step (in progress, interrupted)

The user asked how to publish this to their GitHub. `gh` CLI is installed
and authenticated as **HarisBinKhalid** (repo/workflow scopes available). No
git remote is configured yet (`git remote -v` is empty) — this repo has
never been pushed anywhere. I asked the user to confirm repo name
(`packetbender` recommended, matching the actual project name — NOT
`PacketChanger`, the current stale folder name) and visibility
(public/private) via `AskUserQuestion`, but the tool call errored out
(`AbortError: Tool permission stream closed`) before an answer came back,
and the conversation moved on to the folder-rename request instead. **This
question was never actually answered by the user** — re-ask it, then run
something like:

```bash
gh repo create <name> --public   # or --private
git remote add origin git@github.com:HarisBinKhalid/<name>.git   # or https, matching `gh` config (currently https)
git push -u origin master
```

(`gh repo create` can also do the push directly with `--source=. --push` —
check current `gh` flags since these evolve.) Confirm before pushing, per
standing instructions about actions visible to others / affecting shared
state.

## Standing user preferences observed this session

- Wants direct, working code over discussion — task requests have been
  terse ("add support for X", "fix Y") and the expected response is
  implementation + verification, not a design proposal to review first.
- Wants bugs *reproduced against real data* before being called fixed, not
  just "should work" reasoning from reading the code.
- Comfortable with git commits happening per logical change without asking
  each time (this session made ~15 commits, one per feature/fix, all with
  descriptive bodies) — but has NOT been asked about / hasn't approved a
  `git push` yet. Don't push without confirming remote target + visibility
  first (see above).
