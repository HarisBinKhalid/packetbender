"""Main application window: packet list + per-packet field editors.

Every packet gets a generic "Layers" tab for editing L2-L4 header fields
(Ethernet/IP/UDP/TCP/...). Packets with a recognized application payload
additionally get a protocol-specific tab (SIP or RTP today); anything
else falls back to a raw-bytes text editor.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QAction, QKeySequence
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QToolBar,
    QVBoxLayout,
    QWidget,
)
from scapy.packet import Raw

from packetbender.core.layer_fields import field_rows, parse_field_value
from packetbender.core.pcap_model import PcapModel
from packetbender.core.sip_message import SipHeader, SipMessage

PACKET_COLUMNS = ("#", "Time", "Source", "Destination", "Protocol", "Length", "Info")
HEADER_COLUMNS = ("Header", "Value")
LAYER_COLUMNS = ("Layer", "Field", "Value", "Auto")

RTP_FIELDS = (
    "version", "padding", "extension", "csrc_count",
    "marker", "payload_type", "sequence", "timestamp", "ssrc",
)


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("PacketBender — Packet Editor")
        self.resize(1300, 760)

        self.model = PcapModel()
        self.current_index: int | None = None
        self.layer_rows = []
        self.dirty = False

        self._build_ui()
        self._build_toolbar()
        self._set_editor_enabled(False)

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.setCentralWidget(splitter)

        self.packet_table = QTableWidget(0, len(PACKET_COLUMNS))
        self.packet_table.setHorizontalHeaderLabels(PACKET_COLUMNS)
        self.packet_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.packet_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.packet_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.packet_table.horizontalHeader().setSectionResizeMode(
            len(PACKET_COLUMNS) - 1, QHeaderView.ResizeMode.Stretch
        )
        self.packet_table.itemSelectionChanged.connect(self._on_row_selected)
        splitter.addWidget(self.packet_table)

        editor = QWidget()
        editor_layout = QVBoxLayout(editor)

        self.tabs = QTabWidget()
        editor_layout.addWidget(self.tabs)

        self.layers_tab = self._build_layers_tab()
        self.sip_tab = self._build_sip_tab()
        self.rtp_tab = self._build_rtp_tab()
        self.raw_tab = self._build_raw_tab()

        self.tabs.addTab(self.layers_tab, "Layers")
        # SIP/RTP/Raw tabs are added/removed dynamically per packet.

        apply_row = QHBoxLayout()
        self.apply_btn = QPushButton("Apply changes to packet")
        self.apply_btn.clicked.connect(self._apply_editor_to_record)
        apply_row.addStretch()
        apply_row.addWidget(self.apply_btn)
        editor_layout.addLayout(apply_row)

        splitter.addWidget(editor)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

        self.status = self.statusBar()

    def _build_layers_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.addWidget(QLabel(
            "L2-L4 header fields for this packet. \"Auto\" fields "
            "(lengths/checksums) are recalculated on Apply unless unchecked."
        ))
        self.layer_table = QTableWidget(0, len(LAYER_COLUMNS))
        self.layer_table.setHorizontalHeaderLabels(LAYER_COLUMNS)
        self.layer_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.Stretch
        )
        layout.addWidget(self.layer_table)
        return widget

    def _build_sip_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)

        start_line_row = QHBoxLayout()
        start_line_row.addWidget(QLabel("Start line:"))
        self.start_line_edit = QLineEdit()
        self.start_line_edit.textEdited.connect(self._mark_dirty)
        start_line_row.addWidget(self.start_line_edit)
        layout.addLayout(start_line_row)

        layout.addWidget(QLabel("Headers:"))
        self.header_table = QTableWidget(0, len(HEADER_COLUMNS))
        self.header_table.setHorizontalHeaderLabels(HEADER_COLUMNS)
        self.header_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch
        )
        self.header_table.itemChanged.connect(self._mark_dirty)
        layout.addWidget(self.header_table)

        header_btn_row = QHBoxLayout()
        add_header_btn = QPushButton("Add header")
        add_header_btn.clicked.connect(self._add_header_row)
        remove_header_btn = QPushButton("Remove selected")
        remove_header_btn.clicked.connect(self._remove_header_row)
        header_btn_row.addWidget(add_header_btn)
        header_btn_row.addWidget(remove_header_btn)
        header_btn_row.addStretch()
        layout.addLayout(header_btn_row)

        layout.addWidget(QLabel("Body (Content-Length is recalculated automatically):"))
        self.body_edit = QPlainTextEdit()
        self.body_edit.textChanged.connect(self._mark_dirty)
        layout.addWidget(self.body_edit)

        return widget

    def _build_rtp_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.addWidget(QLabel(
            "RTP fixed header. CSRC list and header extensions are not "
            "dissected and are kept as part of the media payload."
        ))

        self.rtp_edits: dict[str, QLineEdit] = {}
        for name in RTP_FIELDS:
            row = QHBoxLayout()
            row.addWidget(QLabel(name.replace("_", " ").title() + ":"))
            edit = QLineEdit()
            edit.textEdited.connect(self._mark_dirty)
            self.rtp_edits[name] = edit
            row.addWidget(edit)
            layout.addLayout(row)

        self.rtp_media_label = QLabel("Media payload: 0 bytes (not shown/edited here)")
        layout.addWidget(self.rtp_media_label)
        layout.addStretch()
        return widget

    def _build_raw_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.addWidget(QLabel(
            "Unrecognized payload, shown as Latin-1 text so every byte "
            "value round-trips losslessly. Non-printable bytes may look odd."
        ))
        self.raw_edit = QPlainTextEdit()
        self.raw_edit.textChanged.connect(self._mark_dirty)
        layout.addWidget(self.raw_edit)
        return widget

    def _build_toolbar(self) -> None:
        toolbar = QToolBar("Main")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        open_action = QAction("Open PCAP...", self)
        open_action.setShortcut(QKeySequence.StandardKey.Open)
        open_action.triggered.connect(self._open_pcap)
        toolbar.addAction(open_action)

        save_action = QAction("Save As...", self)
        save_action.setShortcut(QKeySequence.StandardKey.SaveAs)
        save_action.triggered.connect(self._save_pcap_as)
        toolbar.addAction(save_action)

    # ------------------------------------------------------------------
    # File operations
    # ------------------------------------------------------------------
    def _open_pcap(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open PCAP", "", "PCAP files (*.pcap *.pcapng);;All files (*)"
        )
        if not path:
            return

        try:
            self.model.load(path)
        except Exception as exc:  # noqa: BLE001 - surface any parse error to the user
            QMessageBox.critical(self, "Failed to open file", str(exc))
            return

        self.current_index = None
        self._populate_packet_table()
        self._set_editor_enabled(False)

        if self.model.unrecognized_linktype_warning:
            QMessageBox.warning(
                self, "Some packets could not be parsed",
                self.model.unrecognized_linktype_warning,
            )
            self.status.showMessage(self.model.unrecognized_linktype_warning)
        else:
            self.status.showMessage(f"Loaded {len(self.model.records)} packets from {path}")

    def _save_pcap_as(self) -> None:
        if not self.model.records:
            QMessageBox.information(self, "Nothing to save", "Open a PCAP file first.")
            return

        if self.dirty and self.current_index is not None:
            self._apply_editor_to_record()

        path, _ = QFileDialog.getSaveFileName(
            self, "Save PCAP As", "", "PCAP files (*.pcap);;All files (*)"
        )
        if not path:
            return

        try:
            self.model.save(path)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Failed to save file", str(exc))
            return

        self.status.showMessage(f"Saved {len(self.model.records)} packets to {path}")

    # ------------------------------------------------------------------
    # Packet list
    # ------------------------------------------------------------------
    def _populate_packet_table(self) -> None:
        self.packet_table.setRowCount(len(self.model.records))
        for row, record in enumerate(self.model.records):
            summary = record.summary()
            values = (
                summary["index"],
                f"{summary['time']:.6f}",
                summary["src"],
                summary["dst"],
                summary["proto"],
                summary["length"],
                summary["info"],
            )
            for col, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if record.has_sip or record.has_rtp:
                    item.setForeground(Qt.GlobalColor.darkGreen)
                self.packet_table.setItem(row, col, item)

    def _on_row_selected(self) -> None:
        rows = self.packet_table.selectionModel().selectedRows()
        if not rows:
            return

        if self.dirty and self.current_index is not None:
            self._apply_editor_to_record()

        row = rows[0].row()
        self.current_index = row
        record = self.model.records[row]

        self._load_layers_tab(record)
        self._configure_payload_tabs(record)
        self._set_editor_enabled(True)
        self.status.showMessage(f"Editing packet {row}")
        self.dirty = False

    # ------------------------------------------------------------------
    # Layers tab (generic L2-L4 fields, always available)
    # ------------------------------------------------------------------
    def _load_layers_tab(self, record) -> None:
        self.layer_table.blockSignals(True)
        self.layer_rows = field_rows(record.packet)
        self.layer_table.setRowCount(len(self.layer_rows))

        for row, frow in enumerate(self.layer_rows):
            self.layer_table.setItem(row, 0, QTableWidgetItem(frow.layer_name))
            name_item = QTableWidgetItem(frow.field_name)
            name_item.setFlags(name_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.layer_table.setItem(row, 1, name_item)
            self.layer_table.setItem(row, 2, QTableWidgetItem(frow.value))

            auto_item = QTableWidgetItem()
            if frow.is_computed:
                is_manual = (frow.layer_name, frow.field_name) in record.manual_fields
                auto_item.setFlags(
                    Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled
                )
                auto_item.setCheckState(
                    Qt.CheckState.Unchecked if is_manual else Qt.CheckState.Checked
                )
            else:
                auto_item.setFlags(Qt.ItemFlag.NoItemFlags)
            self.layer_table.setItem(row, 3, auto_item)

        self.layer_table.blockSignals(False)

    def _apply_layers_tab(self, record) -> None:
        for row, frow in enumerate(self.layer_rows):
            value_item = self.layer_table.item(row, 2)
            auto_item = self.layer_table.item(row, 3)
            key = (frow.layer_name, frow.field_name)

            if frow.is_computed:
                if auto_item.checkState() == Qt.CheckState.Checked:
                    record.manual_fields.discard(key)
                    continue
                record.manual_fields.add(key)

            parsed = parse_field_value(value_item.text())
            setattr(frow.layer, frow.field_name, parsed)

    # ------------------------------------------------------------------
    # Protocol-specific tabs
    # ------------------------------------------------------------------
    def _configure_payload_tabs(self, record) -> None:
        for tab in (self.sip_tab, self.rtp_tab, self.raw_tab):
            idx = self.tabs.indexOf(tab)
            if idx != -1:
                self.tabs.removeTab(idx)

        if record.has_sip:
            self.tabs.addTab(self.sip_tab, "SIP")
            self._load_sip_tab(record.sip)
        elif record.has_rtp:
            self.tabs.addTab(self.rtp_tab, "RTP")
            self._load_rtp_tab(record)
        elif record.packet.haslayer(Raw):
            self.tabs.addTab(self.raw_tab, "Raw Payload")
            self._load_raw_tab(record)

    def _load_sip_tab(self, sip: SipMessage) -> None:
        self.header_table.blockSignals(True)
        self.start_line_edit.blockSignals(True)
        self.body_edit.blockSignals(True)

        self.start_line_edit.setText(sip.start_line)
        self.header_table.setRowCount(len(sip.headers))
        for row, header in enumerate(sip.headers):
            self.header_table.setItem(row, 0, QTableWidgetItem(header.name))
            self.header_table.setItem(row, 1, QTableWidgetItem(header.value))
        self.body_edit.setPlainText(sip.body.decode("utf-8", errors="replace"))

        self.header_table.blockSignals(False)
        self.start_line_edit.blockSignals(False)
        self.body_edit.blockSignals(False)

    def _apply_sip_tab(self, record) -> None:
        headers = []
        for row in range(self.header_table.rowCount()):
            name_item = self.header_table.item(row, 0)
            value_item = self.header_table.item(row, 1)
            if name_item is None or not name_item.text().strip():
                continue
            headers.append(SipHeader(
                name=name_item.text().strip(),
                value=value_item.text().strip() if value_item else "",
            ))

        record.sip.start_line = self.start_line_edit.text()
        record.sip.headers = headers
        record.sip.body = self.body_edit.toPlainText().encode("utf-8")

    def _load_rtp_tab(self, record) -> None:
        for name in RTP_FIELDS:
            self.rtp_edits[name].blockSignals(True)
            value = getattr(record.rtp, name)
            if name == "ssrc":
                self.rtp_edits[name].setText(f"0x{value:08x}")
            else:
                self.rtp_edits[name].setText(str(value))
            self.rtp_edits[name].blockSignals(False)
        self.rtp_media_label.setText(
            f"Media payload: {len(record.rtp_media)} bytes (not shown/edited here)"
        )

    def _apply_rtp_tab(self, record) -> None:
        for name in RTP_FIELDS:
            text = self.rtp_edits[name].text().strip()
            setattr(record.rtp, name, int(text, 0))

    def _load_raw_tab(self, record) -> None:
        self.raw_edit.blockSignals(True)
        payload = bytes(record.packet[Raw].load)
        self.raw_edit.setPlainText(payload.decode("latin-1"))
        self.raw_edit.blockSignals(False)

    def _apply_raw_tab(self, record) -> None:
        record.packet[Raw].load = self.raw_edit.toPlainText().encode("latin-1")

    # ------------------------------------------------------------------
    # Apply / dirty tracking
    # ------------------------------------------------------------------
    def _apply_editor_to_record(self) -> None:
        if self.current_index is None:
            return

        record = self.model.records[self.current_index]

        self._apply_layers_tab(record)
        if record.has_sip:
            self._apply_sip_tab(record)
        elif record.has_rtp:
            self._apply_rtp_tab(record)
        elif record.packet.haslayer(Raw):
            self._apply_raw_tab(record)

        record.apply_edits()

        self._populate_packet_table()
        self.packet_table.selectRow(self.current_index)
        self.dirty = False
        self.status.showMessage(f"Applied edits to packet {self.current_index}")

    def _add_header_row(self) -> None:
        row = self.header_table.rowCount()
        self.header_table.insertRow(row)
        self.header_table.setItem(row, 0, QTableWidgetItem(""))
        self.header_table.setItem(row, 1, QTableWidgetItem(""))
        self._mark_dirty()

    def _remove_header_row(self) -> None:
        rows = sorted({idx.row() for idx in self.header_table.selectedIndexes()}, reverse=True)
        for row in rows:
            self.header_table.removeRow(row)
        if rows:
            self._mark_dirty()

    def _mark_dirty(self, *_args) -> None:
        self.dirty = True

    def _set_editor_enabled(self, enabled: bool) -> None:
        self.tabs.setEnabled(enabled)
        self.apply_btn.setEnabled(enabled)
        if not enabled:
            self.layer_table.setRowCount(0)
            self.layer_rows = []
            for tab in (self.sip_tab, self.rtp_tab, self.raw_tab):
                idx = self.tabs.indexOf(tab)
                if idx != -1:
                    self.tabs.removeTab(idx)
