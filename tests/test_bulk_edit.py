from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from packetbender.core.bulk_edit import bulk_set_layer_field, bulk_set_sip_header
from packetbender.core.pcap_model import PcapModel


def _sip_message(call_id: str, method: str = "INVITE") -> bytes:
    return (
        f"{method} sip:bob@biloxi.example.com SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP client.atlanta.example.com:5060\r\n"
        f"From: Alice <sip:alice@atlanta.example.com>;tag=1\r\n"
        f"To: Bob <sip:bob@biloxi.example.com>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: 1 {method}\r\n"
        f"Content-Length: 0\r\n"
        f"\r\n"
    ).encode()


def _make_pcap(path, payloads_and_ips):
    packets = []
    for payload, src, dst in payloads_and_ips:
        packets.append(
            Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb")
            / IP(src=src, dst=dst)
            / UDP(sport=5060, dport=5060)
            / Raw(load=payload)
        )
    wrpcap(path, packets)


def test_bulk_set_sip_header_changes_every_matching_packet(tmp_path):
    path = str(tmp_path / "in.pcap")
    _make_pcap(path, [
        (_sip_message("call-1", "INVITE"), "10.0.0.1", "10.0.0.2"),
        (_sip_message("call-1", "ACK"), "10.0.0.1", "10.0.0.2"),
        (_sip_message("call-2", "INVITE"), "10.0.0.3", "10.0.0.4"),
    ])

    model = PcapModel()
    model.load(path)

    changed = bulk_set_sip_header(model.records, "Call-ID", "call-1", "NEW-CALL-ID")

    assert changed == 2
    assert model.records[0].sip.get("Call-ID") == "NEW-CALL-ID"
    assert model.records[1].sip.get("Call-ID") == "NEW-CALL-ID"
    assert model.records[2].sip.get("Call-ID") == "call-2"  # untouched


def test_bulk_set_sip_header_without_old_value_matches_everything(tmp_path):
    path = str(tmp_path / "in.pcap")
    _make_pcap(path, [
        (_sip_message("call-1"), "10.0.0.1", "10.0.0.2"),
        (_sip_message("call-2"), "10.0.0.3", "10.0.0.4"),
    ])

    model = PcapModel()
    model.load(path)

    changed = bulk_set_sip_header(model.records, "Call-ID", "", "SAME-FOR-ALL")

    assert changed == 2
    assert all(r.sip.get("Call-ID") == "SAME-FOR-ALL" for r in model.records)


def test_bulk_set_sip_header_persists_through_save(tmp_path):
    path = str(tmp_path / "in.pcap")
    out_path = str(tmp_path / "out.pcap")
    _make_pcap(path, [(_sip_message("call-1"), "10.0.0.1", "10.0.0.2")])

    model = PcapModel()
    model.load(path)
    bulk_set_sip_header(model.records, "Call-ID", "call-1", "PERSISTED-ID")
    model.save(out_path)

    reloaded = PcapModel()
    reloaded.load(out_path)
    assert reloaded.records[0].sip.get("Call-ID") == "PERSISTED-ID"


def test_bulk_set_layer_field_changes_matching_source_ip(tmp_path):
    path = str(tmp_path / "in.pcap")
    _make_pcap(path, [
        (_sip_message("call-1"), "10.0.0.1", "10.0.0.2"),
        (_sip_message("call-2"), "10.0.0.1", "10.0.0.3"),
        (_sip_message("call-3"), "10.0.0.9", "10.0.0.4"),
    ])

    model = PcapModel()
    model.load(path)

    changed = bulk_set_layer_field(model.records, "IP", "src", "10.0.0.1", "203.0.113.9")

    assert changed == 2
    assert model.records[0].packet["IP"].src == "203.0.113.9"
    assert model.records[1].packet["IP"].src == "203.0.113.9"
    assert model.records[2].packet["IP"].src == "10.0.0.9"  # untouched


def test_bulk_set_layer_field_without_old_value_matches_everything(tmp_path):
    path = str(tmp_path / "in.pcap")
    _make_pcap(path, [
        (_sip_message("call-1"), "10.0.0.1", "10.0.0.2"),
        (_sip_message("call-2"), "10.0.0.9", "10.0.0.4"),
    ])

    model = PcapModel()
    model.load(path)

    changed = bulk_set_layer_field(model.records, "IP", "dst", "", "192.0.2.1")

    assert changed == 2
    assert all(r.packet["IP"].dst == "192.0.2.1" for r in model.records)


def test_bulk_set_layer_field_preserves_length_integrity_after_save(tmp_path):
    path = str(tmp_path / "in.pcap")
    out_path = str(tmp_path / "out.pcap")
    _make_pcap(path, [(_sip_message("call-1"), "10.0.0.1", "10.0.0.2")])

    model = PcapModel()
    model.load(path)
    bulk_set_layer_field(model.records, "IP", "dst", "", "192.0.2.1")
    model.save(out_path)

    reloaded = PcapModel()
    reloaded.load(out_path)
    pkt = reloaded.records[0].packet
    assert pkt["IP"].dst == "192.0.2.1"
    assert pkt["IP"].len == len(bytes(pkt["IP"]))
    assert pkt["UDP"].len == len(bytes(pkt["UDP"]))


def test_bulk_set_layer_field_skips_packets_without_the_layer(tmp_path):
    path = str(tmp_path / "in.pcap")
    # A TCP-less field query against UDP-only packets should match nothing.
    _make_pcap(path, [(_sip_message("call-1"), "10.0.0.1", "10.0.0.2")])

    model = PcapModel()
    model.load(path)

    changed = bulk_set_layer_field(model.records, "TCP", "sport", "", "1234")
    assert changed == 0
