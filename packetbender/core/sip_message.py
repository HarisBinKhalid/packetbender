"""Parsing and re-serialization of SIP messages carried in UDP/TCP payloads.

SIP is a plain-text, HTTP-like protocol, so we treat it as text rather than
depending on a full SIP stack. Header order and duplicate headers (e.g.
multiple ``Via`` lines) are preserved on round-trip.
"""

from __future__ import annotations

from dataclasses import dataclass, field

_LINE_SEP = b"\r\n"
_KNOWN_METHODS = (
    b"INVITE", b"ACK", b"BYE", b"CANCEL", b"OPTIONS", b"REGISTER",
    b"PRACK", b"SUBSCRIBE", b"NOTIFY", b"PUBLISH", b"INFO", b"REFER",
    b"MESSAGE", b"UPDATE", b"SIP/2.0",
)


@dataclass
class SipHeader:
    name: str
    value: str


@dataclass
class SipMessage:
    start_line: str
    headers: list[SipHeader] = field(default_factory=list)
    body: bytes = b""

    @classmethod
    def parse(cls, payload: bytes) -> "SipMessage | None":
        if not looks_like_sip(payload):
            return None

        normalized = payload.replace(b"\r\n", b"\n")
        if b"\n\n" in normalized:
            head, _, body = normalized.partition(b"\n\n")
        else:
            head, body = normalized, b""

        lines = head.split(b"\n")
        start_line = lines[0].decode("utf-8", errors="replace")

        headers: list[SipHeader] = []
        for line in lines[1:]:
            if not line.strip():
                continue
            if b":" not in line:
                continue
            name, _, value = line.partition(b":")
            headers.append(SipHeader(
                name=name.decode("utf-8", errors="replace").strip(),
                value=value.decode("utf-8", errors="replace").strip(),
            ))

        return cls(start_line=start_line, headers=headers, body=body)

    def get(self, name: str) -> str | None:
        name_lower = name.lower()
        for h in self.headers:
            if h.name.lower() == name_lower:
                return h.value
        return None

    def set(self, name: str, value: str) -> None:
        name_lower = name.lower()
        for h in self.headers:
            if h.name.lower() == name_lower:
                h.value = value
                return
        self.headers.append(SipHeader(name=name, value=value))

    def is_response(self) -> bool:
        return self.start_line.startswith("SIP/2.0")

    def cseq_method(self) -> str | None:
        """The method from the CSeq header (e.g. "INVITE" from
        "CSeq: 314159 INVITE"). Responses carry the method of the request
        they're replying to here - it's the only place a response line
        itself doesn't say what it's responding to."""
        value = self.get("CSeq")
        if not value:
            return None
        parts = value.split()
        return parts[-1] if parts else None

    def content_type(self) -> str:
        """The body's MIME type (e.g. ``application/sdp``), lower-cased and
        stripped of parameters, or "" if absent. Falls back to the SIP
        compact header form ``c`` when the long form isn't present."""
        value = self.get("Content-Type") or self.get("c")
        if not value:
            return ""
        return value.split(";", 1)[0].strip().lower()

    def serialize(self, fix_content_length: bool = True) -> bytes:
        if fix_content_length:
            self.set("Content-Length", str(len(self.body)))

        lines = [self.start_line.encode("utf-8")]
        for h in self.headers:
            lines.append(f"{h.name}: {h.value}".encode("utf-8"))

        return _LINE_SEP.join(lines) + _LINE_SEP + _LINE_SEP + self.body


def looks_like_sip(payload: bytes) -> bool:
    if not payload:
        return False
    stripped = payload.lstrip()
    return any(stripped.startswith(m) for m in _KNOWN_METHODS)
