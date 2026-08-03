from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from packetbender.core.pcap_model import PcapModel

INVITE_WITH_SDP = (
    b"INVITE sip:bob@biloxi.example.com SIP/2.0\r\n"
    b"Via: SIP/2.0/UDP client.atlanta.example.com:5060\r\n"
    b"From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n"
    b"To: Bob <sip:bob@biloxi.example.com>\r\n"
    b"Call-ID: a84b4c76e66710@client.atlanta.example.com\r\n"
    b"CSeq: 314159 INVITE\r\n"
    b"Content-Type: application/sdp\r\n"
    b"Content-Length: 66\r\n"
    b"\r\n"
    b"v=0\r\n"
    b"o=alice 123 456 IN IP4 10.0.0.1\r\n"
    b"c=IN IP4 10.0.0.1\r\n"
    b"m=audio 4000 RTP/AVP 0\r\n"
)

STANDALONE_SDP = (
    b"v=0\r\n"
    b"o=- 0 0 IN IP4 10.0.0.5\r\n"
    b"s=-\r\n"
    b"c=IN IP4 10.0.0.5\r\n"
    b"t=0 0\r\n"
)

STANDALONE_XML = b'<?xml version="1.0"?><config><item>1</item></config>'


def _pkt(src, dst, sport, dport, payload):
    return (
        Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb")
        / IP(src=src, dst=dst)
        / UDP(sport=sport, dport=dport)
        / Raw(load=payload)
    )


def test_sip_body_with_sdp_content_type(tmp_path):
    path = str(tmp_path / "in.pcap")
    wrpcap(path, [_pkt("10.0.0.1", "10.0.0.2", 5060, 5060, INVITE_WITH_SDP)])

    model = PcapModel()
    model.load(path)

    record = model.records[0]
    assert record.has_sip
    assert record.sip.content_type() == "application/sdp"
    assert not record.has_sdp  # SDP-in-SIP is a GUI-level concern, not a separate record kind
    assert record.summary()["proto"] == "SIP/SDP"


def test_plain_sip_packet_shows_bare_sip_protocol_label(tmp_path):
    plain_invite = (
        b"INVITE sip:bob@biloxi.example.com SIP/2.0\r\n"
        b"Via: SIP/2.0/UDP client.atlanta.example.com:5060\r\n"
        b"From: Alice <sip:alice@atlanta.example.com>;tag=1\r\n"
        b"To: Bob <sip:bob@biloxi.example.com>\r\n"
        b"Call-ID: abc@atlanta.example.com\r\n"
        b"CSeq: 1 INVITE\r\n"
        b"Content-Length: 0\r\n"
        b"\r\n"
    )
    path = str(tmp_path / "plain.pcap")
    wrpcap(path, [_pkt("10.0.0.1", "10.0.0.2", 5060, 5060, plain_invite)])

    model = PcapModel()
    model.load(path)

    record = model.records[0]
    assert record.has_sip
    assert record.summary()["proto"] == "SIP"


def test_standalone_sdp_packet_detected(tmp_path):
    path = str(tmp_path / "sdp.pcap")
    wrpcap(path, [_pkt("10.0.0.1", "10.0.0.2", 9999, 9999, STANDALONE_SDP)])

    model = PcapModel()
    model.load(path)

    record = model.records[0]
    assert record.has_sdp
    assert not record.has_sip
    c_line = next(l for l in record.sdp.lines if l.type == "c")
    assert c_line.value == "IN IP4 10.0.0.5"
    assert record.summary()["proto"] == "SDP"


def test_standalone_xml_packet_detected_and_round_trips(tmp_path):
    path = str(tmp_path / "xml.pcap")
    out_path = str(tmp_path / "out.pcap")
    wrpcap(path, [_pkt("10.0.0.1", "10.0.0.2", 8888, 8888, STANDALONE_XML)])

    model = PcapModel()
    model.load(path)

    record = model.records[0]
    assert record.has_xml
    assert not record.has_sip and not record.has_sdp
    assert "<config>" in record.xml
    assert record.summary()["proto"] == "XML"

    record.xml = record.xml.replace("<item>1</item>", "<item>2</item>")
    model.save(out_path)

    reloaded = PcapModel()
    reloaded.load(out_path)
    assert "<item>2</item>" in reloaded.records[0].xml


def test_edit_standalone_sdp_and_save(tmp_path):
    path = str(tmp_path / "sdp.pcap")
    out_path = str(tmp_path / "out.pcap")
    wrpcap(path, [_pkt("10.0.0.1", "10.0.0.2", 9999, 9999, STANDALONE_SDP)])

    model = PcapModel()
    model.load(path)
    record = model.records[0]
    for line in record.sdp.lines:
        if line.type == "c":
            line.value = "IN IP4 192.168.1.1"

    model.save(out_path)

    reloaded = PcapModel()
    reloaded.load(out_path)
    c_line = next(l for l in reloaded.records[0].sdp.lines if l.type == "c")
    assert c_line.value == "IN IP4 192.168.1.1"
