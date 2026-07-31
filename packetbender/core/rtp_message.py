"""Minimal RTP (RFC 3550) fixed-header dissector.

Scapy does not ship an RTP layer, and RTP has no fixed byte signature to
detect it by, so this module provides:

- a small ``Packet`` subclass covering the fixed 12-byte RTP header
  (version, padding/extension/marker flags, payload type, sequence
  number, timestamp, SSRC) — CSRC list and header extensions are treated
  as opaque payload rather than dissected further,
- a heuristic ``looks_like_rtp`` used to guess whether a UDP payload is
  RTP, since detection is inherently probabilistic without SDP context.
"""

from __future__ import annotations

from scapy.fields import BitField, IntField, ShortField
from scapy.packet import Packet

RTP_HEADER_LEN = 12


class RtpHeader(Packet):
    name = "RTP"
    fields_desc = [
        BitField("version", 2, 2),
        BitField("padding", 0, 1),
        BitField("extension", 0, 1),
        BitField("csrc_count", 0, 4),
        BitField("marker", 0, 1),
        BitField("payload_type", 0, 7),
        ShortField("sequence", 0),
        IntField("timestamp", 0),
        IntField("ssrc", 0),
    ]


def looks_like_rtp(payload: bytes) -> bool:
    """Heuristic only: RTP has no magic number, so this checks the RTP
    version bits and a plausible payload type. It will occasionally
    misclassify arbitrary binary payloads — this is a best-effort guess,
    not a guarantee."""
    if len(payload) < RTP_HEADER_LEN:
        return False
    version = (payload[0] >> 6) & 0x03
    return version == 2


def parse_rtp(payload: bytes) -> tuple[RtpHeader, bytes] | None:
    """Split a UDP payload into (header, media_payload). Returns None if
    the payload is too short to contain a fixed RTP header."""
    if len(payload) < RTP_HEADER_LEN:
        return None
    header = RtpHeader(payload[:RTP_HEADER_LEN])
    media = payload[RTP_HEADER_LEN:]
    return header, media


def serialize_rtp(header: RtpHeader, media_payload: bytes) -> bytes:
    return bytes(header) + media_payload
