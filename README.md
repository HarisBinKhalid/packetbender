# SIPEdit

A small desktop GUI, built on [Scapy](https://scapy.net/) and PyQt6, for
viewing and editing SIP packets inside PCAP files — without hand-editing
bytes or breaking checksums.

Open a capture, click a packet, edit SIP headers (`From`, `To`, `Call-ID`,
`Contact`, `Via`, ...) or the message body in plain text fields, and save a
new PCAP. `Content-Length`, IP/UDP length fields, and checksums are
recalculated automatically.

## Features

- Wireshark-like packet list (index, time, source, destination, protocol,
  length, info) with SIP packets auto-detected and highlighted.
- Edit the SIP start line, any header (including duplicates like multiple
  `Via` lines), and the message body.
- Automatic recalculation on save:
  - `Content-Length` header
  - IP total length and header checksum
  - UDP/TCP length and checksum
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
git clone https://github.com/<your-username>/sipedit.git
cd sipedit
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
sipedit
```

1. **Open PCAP...** and select a capture file.
2. Click a packet in the list — packets with a detected SIP payload are
   highlighted in green.
3. Edit the start line, add/edit/remove headers in the table, or edit the
   body text.
4. Click **Apply changes to packet** to write the edit back into the
   in-memory packet (lengths/checksums are recalculated at this point).
5. **Save As...** to write out a new PCAP file.

## Running tests

```bash
pip install -r requirements.txt pytest
pytest
```

Core SIP parsing/serialization and PCAP load/save logic are unit tested
independently of the GUI (`tests/`).

## Project layout

```
sipedit/
  core/
    sip_message.py   # SIP header/body parsing and serialization
    pcap_model.py     # PCAP load/save + checksum/length recalculation via Scapy
  gui/
    main_window.py    # PyQt6 main window: packet list + editor
  app.py              # Application entry point
tests/                # Unit tests for the core (non-GUI) logic
main.py               # Convenience launcher (python main.py)
```

## License

[MIT](LICENSE)
