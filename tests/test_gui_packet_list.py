import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from packetbender.gui.main_window import COLUMN_DEFS, MainWindow

INVITE = (
    b"INVITE sip:bob@biloxi.example.com SIP/2.0\r\n"
    b"Via: SIP/2.0/UDP client.atlanta.example.com:5060\r\n"
    b"From: Alice <sip:alice@atlanta.example.com>;tag=1\r\n"
    b"To: Bob <sip:bob@biloxi.example.com>\r\n"
    b"Call-ID: abc@atlanta.example.com\r\n"
    b"CSeq: 1 INVITE\r\n"
    b"Content-Type: application/sdp\r\n"
    b"Content-Length: 40\r\n"
    b"\r\n"
    b"v=0\r\no=- 0 0 IN IP4 10.0.0.1\r\nm=audio 4000 RTP/AVP 0\r\n"
)


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def window(app, tmp_path):
    packets = []
    lengths = [61, 2265, 115, 1827]
    for i, length in enumerate(lengths):
        payload = INVITE if i == 0 else (b"x" * (length - 42))
        pkt = (
            Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb")
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / UDP(sport=5060 + i, dport=5060)
            / Raw(load=payload)
        )
        packets.append(pkt)

    path = str(tmp_path / "test.pcap")
    wrpcap(path, packets)

    w = MainWindow()
    w.model.load(path)
    w._populate_packet_table()
    return w


def test_default_column_visibility(window):
    default_hidden = {"Src Port", "Dst Port", "TTL"}
    for col, (_key, label, _default, _kind) in enumerate(COLUMN_DEFS):
        assert window.packet_table.isColumnHidden(col) == (label in default_hidden)


def test_column_can_be_shown_and_hidden(window):
    src_port_col = next(i for i, c in enumerate(COLUMN_DEFS) if c[0] == "src_port")
    assert window.packet_table.isColumnHidden(src_port_col)
    window.packet_table.setColumnHidden(src_port_col, False)
    assert not window.packet_table.isColumnHidden(src_port_col)


def test_length_column_sorts_numerically_not_lexicographically(window):
    length_col = next(i for i, c in enumerate(COLUMN_DEFS) if c[0] == "length")

    window.packet_table.sortByColumn(length_col, Qt.SortOrder.AscendingOrder)
    asc = [int(window.packet_table.item(r, length_col).text())
           for r in range(window.packet_table.rowCount())]
    assert asc == sorted(asc)

    window.packet_table.sortByColumn(length_col, Qt.SortOrder.DescendingOrder)
    desc = [int(window.packet_table.item(r, length_col).text())
            for r in range(window.packet_table.rowCount())]
    assert desc == sorted(desc, reverse=True)


def test_selection_tracks_correct_record_after_sorting(window):
    length_col = next(i for i, c in enumerate(COLUMN_DEFS) if c[0] == "length")
    window.packet_table.sortByColumn(length_col, Qt.SortOrder.DescendingOrder)

    window.packet_table.selectRow(0)
    # The largest packet (2265 bytes) should now be row 0 after a
    # descending sort, and selecting it must resolve to its real record,
    # not whatever happens to be at index 0 in model.records.
    assert len(window.model.records[window.current_index].packet) == 2265


def test_filter_does_not_apply_until_enter_is_pressed(window):
    window.filter_edit.setText("2265")
    visible = [r for r in range(window.packet_table.rowCount())
               if not window.packet_table.isRowHidden(r)]
    assert len(visible) == window.packet_table.rowCount()


def test_filter_matches_visible_column_text(window):
    window.filter_edit.setText("2265")
    window.filter_edit.returnPressed.emit()
    visible = [r for r in range(window.packet_table.rowCount())
               if not window.packet_table.isRowHidden(r)]
    assert len(visible) == 1


def test_filter_matches_deep_sip_content_not_shown_in_columns(window):
    # "sdp" via Content-Type isn't shown in any visible column directly,
    # but should still be found via searchable_text().
    window.filter_edit.setText("application/sdp")
    window.filter_edit.returnPressed.emit()
    visible = [r for r in range(window.packet_table.rowCount())
               if not window.packet_table.isRowHidden(r)]
    assert len(visible) == 1
    idx = window._record_index_at_row(visible[0])
    assert window.model.records[idx].has_sip


def test_clearing_filter_shows_all_rows(window):
    window.filter_edit.setText("2265")
    window.filter_edit.returnPressed.emit()
    window._clear_filter()
    visible = [r for r in range(window.packet_table.rowCount())
               if not window.packet_table.isRowHidden(r)]
    assert len(visible) == window.packet_table.rowCount()


def test_default_sort_is_ascending_by_packet_number(window):
    numbers = [int(window.packet_table.item(r, 0).text())
               for r in range(window.packet_table.rowCount())]
    assert numbers == sorted(numbers)


def test_editor_panel_can_be_closed_and_reopened_via_double_click(window, app):
    # isVisible() reflects actual on-screen state, which requires the
    # window to actually be shown - not just constructed.
    window.show()
    app.processEvents()

    assert window.editor_panel.isVisible()

    window._close_editor_panel()
    assert not window.editor_panel.isVisible()

    window._on_row_double_clicked(1, 0)
    assert window.editor_panel.isVisible()
    assert window.current_index == window._record_index_at_row(1)
