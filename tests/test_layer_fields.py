from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from packetbender.core.layer_fields import field_rows, parse_field_value


def _make_packet():
    return (
        Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb")
        / IP(src="10.0.0.1", dst="10.0.0.2", ttl=64)
        / UDP(sport=1234, dport=5678)
        / Raw(load=b"hello")
    )


def test_field_rows_covers_every_header_layer_but_not_raw():
    pkt = _make_packet()
    rows = field_rows(pkt)
    layer_names = {r.layer_name for r in rows}
    assert layer_names == {"Ether", "IP", "UDP"}
    assert not any(r.layer_name == "Raw" for r in rows)


def test_field_rows_flags_computed_fields():
    pkt = _make_packet()
    rows = field_rows(pkt)
    computed = {(r.layer_name, r.field_name) for r in rows if r.is_computed}
    assert ("IP", "len") in computed
    assert ("IP", "chksum") in computed
    assert ("UDP", "len") in computed
    assert ("IP", "ttl") not in computed


def test_field_rows_reflects_current_value():
    pkt = _make_packet()
    rows = field_rows(pkt)
    ttl_row = next(r for r in rows if r.layer_name == "IP" and r.field_name == "ttl")
    assert ttl_row.value == "64"


def test_parse_field_value_prefers_int():
    assert parse_field_value("42") == 42
    assert parse_field_value("0x2a") == 42
    assert parse_field_value("10.0.0.1") == "10.0.0.1"
