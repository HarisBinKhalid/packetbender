from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import RawPcapWriter

from packetbender.core.pcap_model import PcapModel


def _write_pcap_with_linktype(path, pkt, linktype):
    raw = bytes(pkt)
    writer = RawPcapWriter(path, linktype=linktype)
    writer._write_header(None)
    writer._write_packet(raw, linktype=linktype)
    writer.close()


def test_unrecognized_linktype_falls_back_to_ethernet_dissection(tmp_path):
    pcap_path = str(tmp_path / "weird.pcap")
    pkt = (
        Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb")
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / UDP(sport=1111, dport=2222)
        / Raw(load=b"hello world")
    )
    # 9999 is not a real DLT value Scapy's registry knows about, which
    # reproduces the "unknown LL type ... Using Raw packets" fallback.
    _write_pcap_with_linktype(pcap_path, pkt, linktype=9999)

    model = PcapModel()
    model.load(pcap_path)

    assert len(model.records) == 1
    record = model.records[0]
    assert record.packet.haslayer("IP")
    assert record.packet.haslayer("UDP")
    assert record.packet["IP"].src == "10.0.0.1"
    assert record.packet["UDP"].dport == 2222
    assert model.unrecognized_linktype_warning is None


def test_truly_undissectable_payload_sets_warning(tmp_path):
    pcap_path = str(tmp_path / "garbage.pcap")
    garbage = Raw(load=b"\x00" * 8)  # too short to look like Ether or IP
    _write_pcap_with_linktype(pcap_path, garbage, linktype=9999)

    model = PcapModel()
    model.load(pcap_path)

    assert len(model.records) == 1
    assert model.unrecognized_linktype_warning is not None
    assert "9999" in model.unrecognized_linktype_warning
