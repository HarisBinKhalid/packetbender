"""Parsing and re-serialization of SDP (RFC 4566) session descriptions.

SDP is line-oriented, ``type=value`` pairs (e.g. ``v=0``, ``c=IN IP4
10.0.0.1``, ``m=audio 30000 RTP/AVP 0``). This treats it generically as an
ordered list of lines rather than modeling session/media-level structure,
since editing individual field values (an IP in a ``c=`` line, a port in
an ``m=`` line, a codec in an ``a=rtpmap`` line) doesn't require deeper
semantics - line order is preserved on round-trip either way.
"""

from __future__ import annotations

from dataclasses import dataclass, field

_LINE_SEP = b"\r\n"


@dataclass
class SdpLine:
    type: str
    value: str


@dataclass
class SdpMessage:
    lines: list[SdpLine] = field(default_factory=list)

    @classmethod
    def parse(cls, payload: bytes) -> "SdpMessage | None":
        if not looks_like_sdp(payload):
            return None

        text = payload.replace(b"\r\n", b"\n").decode("utf-8", errors="replace")
        lines: list[SdpLine] = []
        for raw_line in text.split("\n"):
            raw_line = raw_line.strip("\r").strip()
            if not raw_line or "=" not in raw_line:
                continue
            line_type, _, value = raw_line.partition("=")
            lines.append(SdpLine(type=line_type.strip(), value=value.strip()))

        return cls(lines=lines)

    def serialize(self) -> bytes:
        if not self.lines:
            return b""
        rendered = [f"{line.type}={line.value}".encode("utf-8") for line in self.lines]
        return _LINE_SEP.join(rendered) + _LINE_SEP


def looks_like_sdp(payload: bytes) -> bool:
    stripped = payload.lstrip()
    if not stripped:
        return False
    first_line = stripped.split(b"\n", 1)[0].rstrip(b"\r").strip()
    # Every SDP message opens with a protocol-version line ("v=0").
    return first_line[:2] == b"v=" and first_line[2:].isdigit()
