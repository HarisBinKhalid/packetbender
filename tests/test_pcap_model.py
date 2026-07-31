import os

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from sipedit.core.pcap_model import PcapModel

INVITE = (
    b"INVITE sip:bob@biloxi.example.com SIP/2.0\r\n"
    b"Via: SIP/2.0/UDP client.atlanta.example.com:5060\r\n"
    b"From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n"
    b"To: Bob <sip:bob@biloxi.example.com>\r\n"
    b"Call-ID: a84b4c76e66710@client.atlanta.example.com\r\n"
    b"CSeq: 314159 INVITE\r\n"
    b"Content-Length: 4\r\n"
    b"\r\n"
    b"abcd"
)


def _make_pcap(path):
    sip_pkt = (
        Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb")
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / UDP(sport=5060, dport=5060)
        / Raw(load=INVITE)
    )
    plain_pkt = (
        Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb")
        / IP(src="10.0.0.3", dst="10.0.0.4")
        / UDP(sport=1234, dport=5678)
        / Raw(load=b"not sip")
    )
    wrpcap(path, [sip_pkt, plain_pkt])


def test_load_detects_sip_packets(tmp_path):
    pcap_path = str(tmp_path / "in.pcap")
    _make_pcap(pcap_path)

    model = PcapModel()
    model.load(pcap_path)

    assert len(model.records) == 2
    assert model.records[0].has_sip
    assert model.records[0].sip.get("Call-ID") == "a84b4c76e66710@client.atlanta.example.com"
    assert not model.records[1].has_sip


def test_edit_and_save_recomputes_lengths_and_checksums(tmp_path):
    pcap_path = str(tmp_path / "in.pcap")
    out_path = str(tmp_path / "out.pcap")
    _make_pcap(pcap_path)

    model = PcapModel()
    model.load(pcap_path)

    record = model.records[0]
    record.sip.set("To", "Carol <sip:carol@biloxi.example.com>")
    record.sip.body = b"a much longer body than before"

    model.save(out_path)
    assert os.path.exists(out_path)

    reloaded = PcapModel()
    reloaded.load(out_path)

    edited = reloaded.records[0]
    assert edited.sip.get("To") == "Carol <sip:carol@biloxi.example.com>"
    assert edited.sip.body == b"a much longer body than before"
    assert edited.sip.get("Content-Length") == str(len(b"a much longer body than before"))

    pkt = edited.packet
    expected_udp_len = len(bytes(pkt[UDP]))
    assert pkt[UDP].len == expected_udp_len
