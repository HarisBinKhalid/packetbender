import pytest
from PyQt6.QtWidgets import QApplication
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from packetbender.gui.bulk_edit_dialog import BulkEditDialog
from packetbender.gui.main_window import MainWindow

INVITE = (
    b"INVITE sip:bob@biloxi.example.com SIP/2.0\r\n"
    b"Via: SIP/2.0/UDP client.atlanta.example.com:5060\r\n"
    b"From: Alice <sip:alice@atlanta.example.com>;tag=1\r\n"
    b"To: Bob <sip:bob@biloxi.example.com>\r\n"
    b"Call-ID: shared-call-id\r\n"
    b"CSeq: 1 INVITE\r\n"
    b"Content-Length: 0\r\n"
    b"\r\n"
)
ACK = INVITE.replace(b"INVITE sip", b"ACK sip").replace(b"1 INVITE", b"1 ACK")


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def window(app, tmp_path):
    packets = [
        Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb")
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / UDP(sport=5060, dport=5060)
        / Raw(load=INVITE),
        Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb")
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / UDP(sport=5061, dport=5060)
        / Raw(load=ACK),
        Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb")
        / IP(src="10.0.0.9", dst="10.0.0.4")
        / UDP(sport=5062, dport=5060)
        / Raw(load=b"not sip"),
    ]
    path = str(tmp_path / "test.pcap")
    wrpcap(path, packets)

    w = MainWindow()
    w.model.load(path)
    w._populate_packet_table()
    return w


def test_bulk_edit_target_records_all_scope(window):
    records = window._bulk_edit_target_records("all")
    assert len(records) == 3


def test_bulk_edit_target_records_filtered_scope(window):
    window.filter_edit.setText("shared-call-id")
    window.filter_edit.returnPressed.emit()

    records = window._bulk_edit_target_records("filtered")
    assert len(records) == 2
    assert all(r.has_sip for r in records)


def test_bulk_edit_dialog_sip_header_flow_end_to_end(window):
    records = window._bulk_edit_target_records("all")

    dialog = BulkEditDialog(window, filter_active=False)
    dialog.header_name_edit.setText("Call-ID")
    dialog.header_old_value_edit.setText("shared-call-id")
    dialog.header_new_value_edit.setText("renamed-call-id")

    from packetbender.core.bulk_edit import bulk_set_sip_header
    header_name, old_value, new_value = dialog.sip_header_params()
    changed = bulk_set_sip_header(records, header_name, old_value, new_value)

    assert changed == 2
    assert window.model.records[0].sip.get("Call-ID") == "renamed-call-id"
    assert window.model.records[1].sip.get("Call-ID") == "renamed-call-id"


def test_bulk_edit_dialog_layer_field_flow_end_to_end(window):
    records = window._bulk_edit_target_records("all")

    dialog = BulkEditDialog(window, filter_active=False)
    dialog.target_combo.setCurrentIndex(1)
    dialog.layer_combo.setCurrentText("IP")
    dialog.field_combo.setCurrentText("src")
    dialog.layer_old_value_edit.setText("10.0.0.1")
    dialog.layer_new_value_edit.setText("203.0.113.1")

    from packetbender.core.bulk_edit import bulk_set_layer_field
    layer_name, field_name, old_value, new_value = dialog.layer_field_params()
    changed = bulk_set_layer_field(records, layer_name, field_name, old_value, new_value)

    assert changed == 2
    assert window.model.records[0].packet["IP"].src == "203.0.113.1"
    assert window.model.records[1].packet["IP"].src == "203.0.113.1"
    assert window.model.records[2].packet["IP"].src == "10.0.0.9"


def test_bulk_edit_reselects_current_packet_after_edit(window):
    window.packet_table.selectRow(0)
    assert window.current_index == 0

    records = window._bulk_edit_target_records("all")
    from packetbender.core.bulk_edit import bulk_set_sip_header
    bulk_set_sip_header(records, "Call-ID", "", "post-edit-id")

    window._populate_packet_table()
    visual_row = window._visual_row_for_index(window.current_index)
    if visual_row is not None:
        window.packet_table.selectRow(visual_row)

    assert window.current_index == 0
    assert window.model.records[0].sip.get("Call-ID") == "post-edit-id"
