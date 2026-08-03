import os

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from packetbender.core.pcap_model import PcapModel

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


def test_sip_response_info_shows_which_request_it_answers(tmp_path):
    ok_200 = (
        b"SIP/2.0 200 OK\r\n"
        b"Via: SIP/2.0/UDP client.atlanta.example.com:5060\r\n"
        b"CSeq: 314159 INVITE\r\n"
        b"Content-Length: 0\r\n"
        b"\r\n"
    )
    pcap_path = str(tmp_path / "response.pcap")
    pkt = (
        Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb")
        / IP(src="10.0.0.2", dst="10.0.0.1")
        / UDP(sport=5060, dport=5060)
        / Raw(load=ok_200)
    )
    wrpcap(pcap_path, [pkt])

    model = PcapModel()
    model.load(pcap_path)

    assert model.records[0].summary()["info"] == "SIP/2.0 200 OK (INVITE)"


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


def _make_rtp_pcap(path):
    rtp_payload = (
        bytes([0x80, 0x00, 0x00, 0x01]) + (160).to_bytes(4, "big")
        + bytes.fromhex("11223344") + b"\x00" * 20
    )
    rtp_pkt = (
        Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb")
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / UDP(sport=30000, dport=30002)
        / Raw(load=rtp_payload)
    )
    wrpcap(path, [rtp_pkt])


def test_load_detects_rtp_packets(tmp_path):
    pcap_path = str(tmp_path / "rtp.pcap")
    _make_rtp_pcap(pcap_path)

    model = PcapModel()
    model.load(pcap_path)

    record = model.records[0]
    assert record.has_rtp
    assert not record.has_sip
    assert record.rtp.sequence == 1
    assert record.rtp.ssrc == 0x11223344


def test_edit_rtp_header_and_save(tmp_path):
    pcap_path = str(tmp_path / "rtp.pcap")
    out_path = str(tmp_path / "out.pcap")
    _make_rtp_pcap(pcap_path)

    model = PcapModel()
    model.load(pcap_path)
    record = model.records[0]
    record.rtp.sequence = 999
    record.rtp.marker = 1

    model.save(out_path)

    reloaded = PcapModel()
    reloaded.load(out_path)
    edited = reloaded.records[0]
    assert edited.rtp.sequence == 999
    assert edited.rtp.marker == 1
    assert edited.rtp_media == b"\x00" * 20


def test_manual_field_pin_is_preserved_on_save(tmp_path):
    pcap_path = str(tmp_path / "in.pcap")
    out_path = str(tmp_path / "out.pcap")
    _make_pcap(pcap_path)

    model = PcapModel()
    model.load(pcap_path)
    record = model.records[0]

    # Editing a generic L2-L4 field (TTL) as a real editor UI would.
    record.packet["IP"].ttl = 5
    # Pin IP.len to a deliberately wrong value instead of letting it recompute.
    record.packet["IP"].len = 12345
    record.manual_fields.add(("IP", "len"))

    model.save(out_path)

    reloaded = PcapModel()
    reloaded.load(out_path)
    edited = reloaded.records[0]
    assert edited.packet["IP"].ttl == 5
    assert edited.packet["IP"].len == 12345
