# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- Packets whose capture link-layer type Scapy couldn't dissect (or that crashed mid-dissection) were silently shown as opaque `Raw` bytes with no Ethernet/IP/UDP/TCP fields — the Layers tab was empty and Source/Destination were blank for every packet. Loading now retries such packets as Ethernet, then as bare IP, before giving up, and surfaces a warning dialog naming the offending link-layer type when packets remain undissectable instead of failing silently.
- Opening a **pcapng** file (as opposed to classic pcap) crashed with `'PcapNgReader' object has no attribute 'linktype'` before a single packet was read — pcapng stores link-layer type per-interface rather than as one top-level value, which the loader wasn't accounting for.

### Planned
- Windows packaging (PyInstaller build) and CI build matrix.
- Filter/search bar for the packet list.
- Syntax highlighting for the raw SIP body/header editor.
- Dissection of RTP CSRC lists and header extensions (currently passed through as opaque payload).

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
