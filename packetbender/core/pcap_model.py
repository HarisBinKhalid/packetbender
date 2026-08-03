"""Loading, editing, and saving PCAP files with Scapy.

Every packet exposes its L2-L4 headers for generic editing (see
``layer_fields``), plus a protocol-specific view of its payload when one
is recognized (SIP, RTP, standalone SDP, or standalone XML today). Length
and checksum fields are recomputed automatically on save unless the user
explicitly pinned a value via the generic field editor.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from scapy.config import conf
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import PcapReader, wrpcap

from .layer_fields import COMPUTED_FIELDS, finalize_packet
from .rtp_message import RtpHeader, looks_like_rtp, parse_rtp, serialize_rtp
from .sdp_message import SdpMessage, looks_like_sdp
from .sip_message import SipMessage, looks_like_sip
from .xml_message import looks_like_xml


@dataclass
class PacketRecord:
    index: int
    packet: object  # scapy.packet.Packet
    sip: SipMessage | None = None
    rtp: RtpHeader | None = None
    rtp_media: bytes = b""
    # Standalone SDP/XML payloads (not carried inside a SIP body - that
    # case is handled by the GUI parsing/serializing `sip.body` on the
    # fly, since SDP/XML-in-SIP doesn't change how the packet is loaded).
    sdp: SdpMessage | None = None
    xml: str | None = None
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

    @property
    def has_sdp(self) -> bool:
        return self.sdp is not None

    @property
    def has_xml(self) -> bool:
        return self.xml is not None

    def summary(self) -> dict:
        pkt = self.packet
        src = dst = proto = info = ""
        src_port = dst_port = ttl = None
        length = len(pkt)
        timestamp = float(getattr(pkt, "time", 0.0))

        if pkt.haslayer("IP"):
            ip = pkt["IP"]
            src, dst = ip.src, ip.dst
            ttl = ip.ttl
        elif pkt.haslayer("IPv6"):
            ip6 = pkt["IPv6"]
            src, dst = ip6.src, ip6.dst
            ttl = ip6.hlim

        if pkt.haslayer("UDP"):
            src_port, dst_port = pkt["UDP"].sport, pkt["UDP"].dport
        elif pkt.haslayer("TCP"):
            src_port, dst_port = pkt["TCP"].sport, pkt["TCP"].dport

        if self.has_sip:
            proto = "SIP/SDP" if self.sip.content_type() == "application/sdp" else "SIP"
        elif self.has_rtp:
            proto = "RTP"
        elif self.has_sdp:
            proto = "SDP"
        elif self.has_xml:
            proto = "XML"
        elif pkt.haslayer("UDP"):
            proto = "UDP"
        elif pkt.haslayer("TCP"):
            proto = "TCP"
        else:
            proto = pkt.__class__.__name__

        if self.sip is not None:
            info = self.sip.start_line
            if self.sip.is_response():
                method = self.sip.cseq_method()
                if method:
                    info = f"{info} ({method})"
        elif self.rtp is not None:
            info = (
                f"PT={self.rtp.payload_type} Seq={self.rtp.sequence} "
                f"TS={self.rtp.timestamp} SSRC=0x{self.rtp.ssrc:08x}"
            )
        elif self.sdp is not None:
            session_name = next((l.value for l in self.sdp.lines if l.type == "s"), "")
            info = f"SDP {session_name}".strip()
        elif self.xml is not None:
            stripped = self.xml.lstrip()
            info = stripped[:80].split("\n", 1)[0]

        return {
            "index": self.index,
            "time": timestamp,
            "src": src,
            "dst": dst,
            "src_port": src_port,
            "dst_port": dst_port,
            "ttl": ttl,
            "proto": proto,
            "length": length,
            "info": info,
        }

    def searchable_text(self) -> str:
        """Every piece of text worth matching against a filter string,
        beyond what's already shown in the packet list columns - SIP
        headers/body, RTP fields, SDP lines, XML content."""
        parts = [self.summary()["info"]]

        if self.sip is not None:
            parts.append(self.sip.start_line)
            for header in self.sip.headers:
                parts.append(header.name)
                parts.append(header.value)
            parts.append(self.sip.body.decode("utf-8", errors="replace"))
        if self.rtp is not None:
            parts.append(f"{self.rtp.payload_type} {self.rtp.sequence} "
                          f"{self.rtp.timestamp} {self.rtp.ssrc:08x}")
        if self.sdp is not None:
            for line in self.sdp.lines:
                parts.append(f"{line.type}={line.value}")
        if self.xml is not None:
            parts.append(self.xml)

        return " ".join(parts).lower()

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
        elif self.sdp is not None:
            self._set_raw_payload(self.sdp.serialize())
        elif self.xml is not None:
            self._set_raw_payload(self.xml.encode("utf-8"))

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


def _try_redissect(raw_bytes: bytes):
    """A packet that dissected as bare Raw means Scapy either didn't
    recognize the capture's link-layer type or crashed while dissecting
    it. Most real-world captures are Ethernet even when metadata says
    otherwise (e.g. tools that mislabel the linktype), so retry as
    Ethernet, then as a bare IP packet, before giving up."""
    for cls in (Ether, IP):
        try:
            candidate = cls(raw_bytes)
        except Exception:
            continue
        if candidate.haslayer("IP") or candidate.haslayer("IPv6") or candidate.haslayer("ARP"):
            return candidate
    return None


class PcapModel:
    def __init__(self) -> None:
        self.records: list[PacketRecord] = []
        self.path: str | None = None
        self.linktype: int | None = None
        # Set when the capture's link-layer type isn't one Scapy has a
        # dissector for, so every packet loaded as opaque bytes instead of
        # being parsed into Ethernet/IP/etc. Surfaced by the GUI so this
        # isn't a silent failure.
        self.unrecognized_linktype_warning: str | None = None

    def load(self, path: str) -> None:
        records: list[PacketRecord] = []
        unrecognized_count = 0

        with PcapReader(path) as reader:
            # Classic pcap readers expose a single top-level `linktype`;
            # pcapng readers store one per interface (and may not populate
            # `interfaces` until the file is fully read), so there's no
            # single reliable value to report there - `None` just means
            # "not applicable" rather than a real failure.
            self.linktype = getattr(reader, "linktype", None)
            for i, pkt in enumerate(reader):
                if type(pkt) is Raw:
                    resolved = _try_redissect(bytes(pkt))
                    if resolved is not None:
                        pkt = resolved
                    else:
                        unrecognized_count += 1

                sip = None
                rtp = None
                rtp_media = b""
                sdp = None
                xml = None

                if pkt.haslayer(Raw):
                    payload = bytes(pkt[Raw].load)
                    if looks_like_sip(payload):
                        sip = SipMessage.parse(payload)
                    elif pkt.haslayer("UDP") and looks_like_rtp(payload):
                        parsed = parse_rtp(payload)
                        if parsed is not None:
                            rtp, rtp_media = parsed
                    elif looks_like_sdp(payload):
                        sdp = SdpMessage.parse(payload)
                    elif looks_like_xml(payload):
                        xml = payload.decode("utf-8", errors="replace")

                records.append(PacketRecord(
                    index=i, packet=pkt, sip=sip, rtp=rtp, rtp_media=rtp_media,
                    sdp=sdp, xml=xml,
                ))

        self.records = records
        self.path = path

        if unrecognized_count:
            if self.linktype is None:
                linktype_desc = "This capture's link-layer type"
            else:
                known_cls = conf.l2types.num2layer.get(self.linktype)
                suffix = "" if known_cls is None else f" ({known_cls.__name__})"
                linktype_desc = f"Link-layer type {self.linktype}{suffix}"
            self.unrecognized_linktype_warning = (
                f"{linktype_desc} could not be dissected for "
                f"{unrecognized_count} of {len(records)} packets; "
                f"they are shown as raw bytes."
            )
        else:
            self.unrecognized_linktype_warning = None

    def save(self, path: str) -> None:
        for record in self.records:
            record.apply_edits()

        packets = [r.packet for r in self.records]
        wrpcap(path, packets)
        self.path = path
