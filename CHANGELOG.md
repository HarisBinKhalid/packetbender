# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- The packet list defaulted to sorted by packet number *descending* instead of ascending - Qt's header defaults to a descending sort indicator on column 0 before any column has been clicked, which this now overrides explicitly on startup.
- The filter bar applied on every keystroke; it now only filters when Enter is pressed (or the Clear button is used), so typing doesn't repeatedly re-scan the packet list mid-word.

### Planned
- Windows packaging (PyInstaller build) and CI build matrix.
- Syntax highlighting for the raw SIP body/header editor.
- Dissection of RTP CSRC lists and header extensions (currently passed through as opaque payload).

## [0.4.0] - 2026-08-03

### Added
- **Sortable packet list columns**: click a header to sort ascending/descending; numeric columns (#, Time, Length, Src/Dst Port, TTL) sort by value rather than as text, so "2" sorts before "10".
- **Show/hide columns**: right-click the packet list header for a checklist of available columns. Two new optional columns (Src Port, Dst Port, TTL) are added, hidden by default to match the previous look.
- **Filter bar** above the packet list: searches both the visible column text and deeper packet content that isn't shown in any column (SIP headers/body, SDP lines, RTP fields, XML text) via `PacketRecord.searchable_text()`.

### Changed
- Packet list protocol column now shows plain `SIP` (matching Wireshark) instead of `SIP/UDP`/`SIP/TCP`, and `SIP/SDP` specifically when the body's `Content-Type` is `application/sdp`.

### Fixed
- The editor panel could be dragged fully closed via the splitter with no way to reopen it. The splitter no longer allows collapsing it to zero, and double-clicking any packet row now also snaps the panel back to a usable size as a fallback.
- Selecting a packet row after sorting or filtering the list previously assumed visual row position matched the packet's underlying record index - now broken by design once sorting/filtering exist. Row selection now resolves the actual record via a stable identity stored per row, independent of visual position.

## [0.3.0] - 2026-07-31

### Added
- **SDP editing**: a structured table of `type=value` lines (`v=`, `o=`, `c=`, `m=`, `a=`, ...), preserving line order (`packetbender.core.sdp_message`). Offered as an "SDP Fields" sub-tab nested in the SIP tab whenever the body's `Content-Type` is `application/sdp` (or the body looks like SDP with no Content-Type present), and as a standalone top-level "SDP" tab for packets carrying SDP outside of SIP.
- **XML editing**: a text editor with a "Validate / Pretty-print" button that reformats via `xml.dom.minidom` and reports parse errors instead of silently mangling malformed input (`packetbender.core.xml_message`). Offered as an "XML" sub-tab nested in the SIP tab for XML-typed bodies (PIDF presence documents, MESSAGE/REFER bodies, etc.), and as a standalone top-level "XML" tab for other packets.
- `SipMessage.content_type()` helper reading (and normalizing) the `Content-Type` header, with a fallback to the SIP compact form `c`.
- Packet list protocol column now shows `SDP` / `XML` for standalone payloads of those types, matching the existing `SIP`/`RTP` labels.

### Fixed
- Packets whose capture link-layer type Scapy couldn't dissect (or that crashed mid-dissection) were silently shown as opaque `Raw` bytes with no Ethernet/IP/UDP/TCP fields — the Layers tab was empty and Source/Destination were blank for every packet. Loading now retries such packets as Ethernet, then as bare IP, before giving up, and surfaces a warning dialog naming the offending link-layer type when packets remain undissectable instead of failing silently.
- Opening a **pcapng** file (as opposed to classic pcap) crashed with `'PcapNgReader' object has no attribute 'linktype'` before a single packet was read — pcapng stores link-layer type per-interface rather than as one top-level value, which the loader wasn't accounting for.

## [0.2.0] - 2026-07-31

### Changed
- **Project renamed from SIPEdit to PacketBender**, reflecting scope beyond SIP: the tool now edits any packet's L2-L4 header fields, not just SIP payloads. Package import path changed from `sipedit` to `packetbender`; console script changed from `sipedit` to `packetbender`.

### Added
- **Layers tab**: generic L2-L4 header field editor available for every packet (Ethernet, IP/IPv6, UDP, TCP), not just ones with a recognized application payload. Length/checksum fields default to automatic recalculation on save, with a per-field "Auto" checkbox to pin an explicit value instead (`packetbender.core.layer_fields`).
- **RTP tab**: minimal RTP (RFC 3550) fixed-header dissector and editor covering version, padding, extension, marker, payload type, sequence number, timestamp, and SSRC (`packetbender.core.rtp_message`). Detection is heuristic (RTP has no fixed signature); CSRC list and header extensions are preserved untouched as part of the media payload.
- **Raw Payload tab**: fallback editor for any packet payload not recognized as SIP or RTP, shown as Latin-1 text for lossless byte-level editing.
- Manual field pinning: edits to computed length/checksum fields made via the Layers tab persist through save instead of being silently overwritten.

## [0.1.0] - 2026-07-31

### Added
- Initial release: PyQt6 GUI for browsing packets in a PCAP file, Wireshark-style.
- Automatic SIP payload detection (INVITE, ACK, BYE, REGISTER, and other standard methods/responses).
- Header table editor supporting add/edit/remove of arbitrary SIP headers (From, To, Call-ID, Contact, Via, etc.), including duplicate headers such as multiple `Via` lines.
- Raw body editor with automatic `Content-Length` recalculation on save.
- Automatic recalculation of IP/UDP/TCP length and checksum fields via Scapy when a packet's payload is edited.
- Save edited packets to a new PCAP file.
- Core SIP parsing/serialization (`sipedit.core.sip_message`) and PCAP load/save (`sipedit.core.pcap_model`), unit tested independently of the GUI.
- Linux support via PyQt6 + Scapy (pure Python, no native raw-capture dependency required for offline file editing).
