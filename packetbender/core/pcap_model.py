"""Loading, editing, and saving PCAP files with Scapy.

Every packet exposes its L2-L4 headers for generic editing (see
``layer_fields``), plus a protocol-specific view of its payload when one
is recognized (SIP or RTP today). Length and checksum fields are
recomputed automatically on save unless the user explicitly pinned a
value via the generic field editor.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from scapy.packet import Raw
from scapy.utils import PcapReader, wrpcap

from .layer_fields import COMPUTED_FIELDS, finalize_packet
from .rtp_message import RtpHeader, looks_like_rtp, parse_rtp, serialize_rtp
from .sip_message import SipMessage, looks_like_sip


@dataclass
class PacketRecord:
    index: int
    packet: object  # scapy.packet.Packet
    sip: SipMessage | None = None
    rtp: RtpHeader | None = None
    rtp_media: bytes = b""
    # (layer_class_name, field_name) pairs the user explicitly pinned via
    # the generic field editor - these are left alone on save instead of
    # being recomputed.
    manual_fields: set = field(default_factory=set)

    @property
    def has_sip(self) -> bool:
        return self.sip is not None

    @property
    def has_rtp(self) -> bool:
        return self.rtp is not None

    def summary(self) -> dict:
        pkt = self.packet
        src = dst = proto = info = ""
        length = len(pkt)
        timestamp = float(getattr(pkt, "time", 0.0))

        if pkt.haslayer("IP"):
            ip = pkt["IP"]
            src, dst = ip.src, ip.dst
        elif pkt.haslayer("IPv6"):
            ip6 = pkt["IPv6"]
            src, dst = ip6.src, ip6.dst

        if self.has_sip:
            proto = "SIP/UDP" if pkt.haslayer("UDP") else "SIP/TCP"
        elif self.has_rtp:
            proto = "RTP"
        elif pkt.haslayer("UDP"):
            proto = "UDP"
        elif pkt.haslayer("TCP"):
            proto = "TCP"
        else:
            proto = pkt.__class__.__name__

        if self.sip is not None:
            info = self.sip.start_line
        elif self.rtp is not None:
            info = (
                f"PT={self.rtp.payload_type} Seq={self.rtp.sequence} "
                f"TS={self.rtp.timestamp} SSRC=0x{self.rtp.ssrc:08x}"
            )

        return {
            "index": self.index,
            "time": timestamp,
            "src": src,
            "dst": dst,
            "proto": proto,
            "length": length,
            "info": info,
        }

    def apply_edits(self) -> None:
        """Write payload-level edits (SIP/RTP) back into the packet, then
        recompute length/checksum fields that weren't manually pinned."""
        pkt = self.packet

        if self.sip is not None:
            new_payload = self.sip.serialize(fix_content_length=True)
            self._set_raw_payload(new_payload)
        elif self.rtp is not None:
            new_payload = serialize_rtp(self.rtp, self.rtp_media)
            self._set_raw_payload(new_payload)

        pkt = self.packet
        for layer_name, fields in COMPUTED_FIELDS.items():
            if not pkt.haslayer(layer_name):
                continue
            layer = pkt[layer_name]
            for f in fields:
                if (layer_name, f) in self.manual_fields:
                    continue
                if f in layer.fields:
                    del layer.fields[f]

        finalize_packet(pkt)

    def _set_raw_payload(self, payload: bytes) -> None:
        pkt = self.packet
        if pkt.haslayer(Raw):
            pkt[Raw].load = payload
        else:
            self.packet = pkt / Raw(load=payload)


class PcapModel:
    def __init__(self) -> None:
        self.records: list[PacketRecord] = []
        self.path: str | None = None

    def load(self, path: str) -> None:
        records: list[PacketRecord] = []
        with PcapReader(path) as reader:
            for i, pkt in enumerate(reader):
                sip = None
                rtp = None
                rtp_media = b""

                if pkt.haslayer(Raw):
                    payload = bytes(pkt[Raw].load)
                    if looks_like_sip(payload):
                        sip = SipMessage.parse(payload)
                    elif pkt.haslayer("UDP") and looks_like_rtp(payload):
                        parsed = parse_rtp(payload)
                        if parsed is not None:
                            rtp, rtp_media = parsed

                records.append(PacketRecord(
                    index=i, packet=pkt, sip=sip, rtp=rtp, rtp_media=rtp_media,
                ))

        self.records = records
        self.path = path

    def save(self, path: str) -> None:
        for record in self.records:
            record.apply_edits()

        packets = [r.packet for r in self.records]
        wrpcap(path, packets)
        self.path = path
