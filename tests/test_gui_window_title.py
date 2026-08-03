from unittest.mock import patch

import pytest
from PyQt6.QtWidgets import QApplication
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from packetbender.gui.main_window import BASE_TITLE, MainWindow


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def test_window_title_shows_opened_filename(app, tmp_path):
    pkt = (
        Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb")
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / UDP(sport=1234, dport=5678)
        / Raw(load=b"hello")
    )
    path = str(tmp_path / "my_capture.pcap")
    wrpcap(path, [pkt])

    w = MainWindow()
    assert w.windowTitle() == BASE_TITLE

    with patch("packetbender.gui.main_window.QFileDialog.getOpenFileName", return_value=(path, "")):
        w._open_pcap()

    assert w.windowTitle() == f"{BASE_TITLE} — my_capture.pcap"


def test_window_title_unchanged_if_open_dialog_cancelled(app, tmp_path):
    w = MainWindow()
    with patch("packetbender.gui.main_window.QFileDialog.getOpenFileName", return_value=("", "")):
        w._open_pcap()

    assert w.windowTitle() == BASE_TITLE
