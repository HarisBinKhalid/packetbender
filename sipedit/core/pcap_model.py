"""Loading, editing, and saving PCAP files with Scapy.

Length and checksum fields (IP header checksum, IP total length,
UDP/TCP length, UDP checksum) are recomputed automatically whenever a
packet's payload changes, by deleting the cached field values before
Scapy re-serializes the packet.
"""

from __future__ import annotations

from dataclasses import dataclass

from scapy.packet import Raw
from scapy.utils import PcapReader, wrpcap

from .sip_message import SipMessage, looks_like_sip


@dataclass
class PacketRecord:
    index: int
    packet: object  # scapy.packet.Packet
    sip: SipMessage | None

    @property
    def has_sip(self) -> bool:
        return self.sip is not None

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

        if pkt.haslayer("UDP"):
            proto = "SIP/UDP" if self.has_sip else "UDP"
        elif pkt.haslayer("TCP"):
            proto = "SIP/TCP" if self.has_sip else "TCP"
        else:
            proto = pkt.__class__.__name__

        if self.sip is not None:
            info = self.sip.start_line

        return {
            "index": self.index,
            "time": timestamp,
            "src": src,
            "dst": dst,
            "proto": proto,
            "length": length,
            "info": info,
        }

    def apply_sip_edits(self) -> None:
        """Write the (possibly edited) SIP message back into the packet
        payload and clear cached length/checksum fields so Scapy
        recomputes them on save."""
        if self.sip is None:
            return

        new_payload = self.sip.serialize(fix_content_length=True)
        pkt = self.packet

        if pkt.haslayer(Raw):
            pkt[Raw].load = new_payload
        else:
            pkt = pkt / Raw(load=new_payload)
            self.packet = pkt

        for layer_name, fields in (
            ("IP", ("len", "chksum")),
            ("IPv6", ("plen",)),
            ("UDP", ("len", "chksum")),
            ("TCP", ("chksum",)),
        ):
            if pkt.haslayer(layer_name):
                layer = pkt[layer_name]
                for f in fields:
                    if f in layer.fields:
                        del layer.fields[f]
                # Scapy caches the originally-dissected raw bytes on each
                # layer and will silently reuse them unless invalidated,
                # which would resurrect the stale length/checksum values
                # we just cleared above.
                layer.raw_packet_cache = None
                layer.raw_packet_cache_fields = None


class PcapModel:
    def __init__(self) -> None:
        self.records: list[PacketRecord] = []
        self.path: str | None = None

    def load(self, path: str) -> None:
        records: list[PacketRecord] = []
        with PcapReader(path) as reader:
            for i, pkt in enumerate(reader):
                sip = None
                if pkt.haslayer(Raw):
                    payload = bytes(pkt[Raw].load)
                    if looks_like_sip(payload):
                        sip = SipMessage.parse(payload)
                records.append(PacketRecord(index=i, packet=pkt, sip=sip))

        self.records = records
        self.path = path

    def save(self, path: str) -> None:
        for record in self.records:
            record.apply_sip_edits()

        packets = [r.packet for r in self.records]
        wrpcap(path, packets)
        self.path = path
