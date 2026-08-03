# PacketBender

A small desktop GUI, built on [Scapy](https://scapy.net/) and PyQt6, for
viewing and editing packets inside PCAP files — without hand-editing bytes
or breaking lengths and checksums.

Open a capture, click a packet, and edit it at whatever level makes sense:

- **Every packet**: L2-L4 header fields (Ethernet MACs, IP addresses/TTL,
  UDP/TCP ports, flags, ...) in a generic field table.
- **SIP packets**: headers (`From`, `To`, `Call-ID`, `Contact`, `Via`, ...)
  and the message body as plain text — with a structured **SDP** or
  **XML** editor automatically offered alongside when the body's
  `Content-Type` calls for it.
- **RTP packets**: fixed header fields (sequence number, timestamp, SSRC,
  payload type, marker bit).
- **Standalone SDP or XML payloads**: the same structured editors, for
  packets carrying them outside of a SIP body.
- **Anything else**: the raw payload as text.

Save a new PCAP and `Content-Length`, IP/UDP/TCP length fields, and
checksums are recalculated automatically, unless you explicitly pin a
value.

## Features

- Wireshark-like packet list (index, time, source, destination, protocol,
  length, info, plus optional source/destination port and TTL columns);
  packets with a recognized payload (SIP, RTP, SDP, XML) are highlighted.
  - **Sortable columns**: click a header to sort ascending/descending
    (numeric columns sort by value, not lexicographically).
  - **Show/hide columns**: right-click any column header for a checklist
    of available columns (Src Port, Dst Port, TTL are hidden by default).
  - **Filter bar**: search across visible columns *and* deeper packet
    content not shown in any column — SIP headers/body, SDP lines, RTP
    fields, XML text — so e.g. searching an SDP attribute or a Call-ID
    finds the packet even though that text isn't in the table.
- **Layers tab** (every packet): edit any L2-L4 header field for Ethernet,
  IP/IPv6, UDP, and TCP. Length/checksum fields default to "Auto"
  (recalculated on save) but can be unchecked to pin an explicit value.
- **SIP tab**: edit the start line, add/remove/edit any header (including
  duplicates like multiple `Via` lines), and the message body. The body
  section gets an extra **SDP Fields** or **XML** sub-tab when
  `Content-Type` is `application/sdp` or an XML type — editing there
  regenerates the underlying body text (and `Content-Length`) on apply.
- **RTP tab**: edit the fixed 12-byte RTP header (version, padding,
  extension, marker, payload type, sequence number, timestamp, SSRC).
  RTP has no fixed signature, so detection is a best-effort heuristic
  (version bits == 2); CSRC lists and header extensions are treated as
  opaque and passed through untouched.
- **SDP tab** (standalone, non-SIP payload): every `type=value` line
  (`v=`, `o=`, `c=`, `m=`, `a=`, ...) in an editable table, in order.
- **XML tab** (standalone, non-SIP payload): edit as text, with a
  "Validate / Pretty-print" button that reformats and reports parse
  errors via `xml.dom.minidom`.
- **Raw payload tab**: for anything not recognized above, edit the
  payload as Latin-1 text (a lossless byte <-> text mapping).
- Save edits to a new PCAP file, leaving the original untouched.

## Status

Linux is supported today. Windows support is planned (see
[CHANGELOG.md](CHANGELOG.md)) — the codebase is pure Python (PyQt6 + Scapy),
so no Linux-specific code paths exist; Windows mainly needs
[Npcap](https://npcap.com/) if live capture is added later. Offline PCAP
editing (this tool's current scope) has no platform-specific dependencies.

## Installation

Requires Python 3.10+.

```bash
git clone https://github.com/<your-username>/packetbender.git
cd packetbender
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python main.py
```

Or, after installing the package (`pip install .`):

```bash
packetbender
```

1. **Open PCAP...** and select a capture file.
2. Click a packet in the list.
3. Use the **Layers** tab to edit L2-L4 header fields, and the **SIP**,
   **RTP**, **SDP**, **XML**, or **Raw Payload** tab (whichever applies)
   to edit the payload.
4. Click **Apply changes to packet** to write the edits back into the
   in-memory packet (lengths/checksums are recalculated at this point,
   unless pinned via the Layers tab's "Auto" checkbox).
5. **Save As...** to write out a new PCAP file.

## Running tests

```bash
pip install -r requirements.txt pytest
pytest
```

Core parsing/serialization (SIP, SDP, RTP, XML, generic layer fields) and
PCAP load/save logic are unit tested independently of the GUI (`tests/`).

## Project layout

```
packetbender/
  core/
    sip_message.py    # SIP header/body parsing and serialization
    sdp_message.py      # SDP session-description line parsing/serialization
    rtp_message.py       # Minimal RTP fixed-header dissector + detection heuristic
    xml_message.py        # XML detection, validation, and pretty-printing
    layer_fields.py         # Generic L2-L4 field introspection/editing for any packet
    pcap_model.py           # PCAP load/save + checksum/length recalculation via Scapy
  gui/
    main_window.py          # PyQt6 main window: packet list + Layers/SIP/RTP/SDP/XML/Raw tabs
  app.py                    # Application entry point
tests/                      # Unit tests for the core (non-GUI) logic
main.py                     # Convenience launcher (python main.py)
```

## License

[MIT](LICENSE)
