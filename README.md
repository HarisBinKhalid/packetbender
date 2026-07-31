# PacketBender

A small desktop GUI, built on [Scapy](https://scapy.net/) and PyQt6, for
viewing and editing packets inside PCAP files — without hand-editing bytes
or breaking lengths and checksums.

Open a capture, click a packet, and edit it at whatever level makes sense:

- **Every packet**: L2-L4 header fields (Ethernet MACs, IP addresses/TTL,
  UDP/TCP ports, flags, ...) in a generic field table.
- **SIP packets**: headers (`From`, `To`, `Call-ID`, `Contact`, `Via`, ...)
  and the message body as plain text.
- **RTP packets**: fixed header fields (sequence number, timestamp, SSRC,
  payload type, marker bit).
- **Anything else**: the raw payload as text.

Save a new PCAP and `Content-Length`, IP/UDP/TCP length fields, and
checksums are recalculated automatically, unless you explicitly pin a
value.

## Features

- Wireshark-like packet list (index, time, source, destination, protocol,
  length, info); packets with a recognized SIP or RTP payload are
  highlighted.
- **Layers tab** (every packet): edit any L2-L4 header field for Ethernet,
  IP/IPv6, UDP, and TCP. Length/checksum fields default to "Auto"
  (recalculated on save) but can be unchecked to pin an explicit value.
- **SIP tab**: edit the start line, add/remove/edit any header (including
  duplicates like multiple `Via` lines), and the message body.
- **RTP tab**: edit the fixed 12-byte RTP header (version, padding,
  extension, marker, payload type, sequence number, timestamp, SSRC).
  RTP has no fixed signature, so detection is a best-effort heuristic
  (version bits == 2); CSRC lists and header extensions are treated as
  opaque and passed through untouched.
- **Raw payload tab**: for anything not recognized as SIP or RTP, edit the
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
   **RTP**, or **Raw Payload** tab (whichever applies) to edit the
   payload.
4. Click **Apply changes to packet** to write the edits back into the
   in-memory packet (lengths/checksums are recalculated at this point,
   unless pinned via the Layers tab's "Auto" checkbox).
5. **Save As...** to write out a new PCAP file.

## Running tests

```bash
pip install -r requirements.txt pytest
pytest
```

Core parsing/serialization (SIP, RTP, generic layer fields) and PCAP
load/save logic are unit tested independently of the GUI (`tests/`).

## Project layout

```
packetbender/
  core/
    sip_message.py    # SIP header/body parsing and serialization
    rtp_message.py     # Minimal RTP fixed-header dissector + detection heuristic
    layer_fields.py     # Generic L2-L4 field introspection/editing for any packet
    pcap_model.py       # PCAP load/save + checksum/length recalculation via Scapy
  gui/
    main_window.py      # PyQt6 main window: packet list + Layers/SIP/RTP/Raw tabs
  app.py                # Application entry point
tests/                  # Unit tests for the core (non-GUI) logic
main.py                 # Convenience launcher (python main.py)
```

## License

[MIT](LICENSE)
