# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- Windows packaging (PyInstaller build) and CI build matrix.
- Filter/search bar for the packet list.
- Syntax highlighting for the raw SIP body/header editor.

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
