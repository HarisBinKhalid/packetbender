"""Main application window: packet list + SIP header/body editor."""

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
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from sipedit.core.pcap_model import PcapModel
from sipedit.core.sip_message import SipHeader, SipMessage

PACKET_COLUMNS = ("#", "Time", "Source", "Destination", "Protocol", "Length", "Info")
HEADER_COLUMNS = ("Header", "Value")


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("SIPEdit — SIP Packet Editor")
        self.resize(1200, 720)

        self.model = PcapModel()
        self.current_index: int | None = None
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

        start_line_row = QHBoxLayout()
        start_line_row.addWidget(QLabel("Start line:"))
        self.start_line_edit = QLineEdit()
        self.start_line_edit.textEdited.connect(self._mark_dirty)
        start_line_row.addWidget(self.start_line_edit)
        editor_layout.addLayout(start_line_row)

        editor_layout.addWidget(QLabel("Headers:"))
        self.header_table = QTableWidget(0, len(HEADER_COLUMNS))
        self.header_table.setHorizontalHeaderLabels(HEADER_COLUMNS)
        self.header_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch
        )
        self.header_table.itemChanged.connect(self._mark_dirty)
        editor_layout.addWidget(self.header_table)

        header_btn_row = QHBoxLayout()
        add_header_btn = QPushButton("Add header")
        add_header_btn.clicked.connect(self._add_header_row)
        remove_header_btn = QPushButton("Remove selected")
        remove_header_btn.clicked.connect(self._remove_header_row)
        header_btn_row.addWidget(add_header_btn)
        header_btn_row.addWidget(remove_header_btn)
        header_btn_row.addStretch()
        editor_layout.addLayout(header_btn_row)

        editor_layout.addWidget(QLabel("Body (Content-Length is recalculated automatically):"))
        self.body_edit = QPlainTextEdit()
        self.body_edit.textChanged.connect(self._mark_dirty)
        editor_layout.addWidget(self.body_edit)

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
                if record.has_sip:
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

        if not record.has_sip:
            self._set_editor_enabled(False)
            self.status.showMessage(f"Packet {row}: no SIP payload detected")
            return

        self._load_record_into_editor(record.sip)
        self._set_editor_enabled(True)
        self.status.showMessage(f"Editing packet {row}: {record.sip.start_line}")

    # ------------------------------------------------------------------
    # Editor <-> SipMessage
    # ------------------------------------------------------------------
    def _load_record_into_editor(self, sip: SipMessage) -> None:
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
        self.dirty = False

    def _apply_editor_to_record(self) -> None:
        if self.current_index is None:
            return

        record = self.model.records[self.current_index]
        if not record.has_sip:
            return

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

        record.apply_sip_edits()
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
        for widget in (
            self.start_line_edit,
            self.header_table,
            self.body_edit,
            self.apply_btn,
        ):
            widget.setEnabled(enabled)
        if not enabled:
            self.start_line_edit.clear()
            self.header_table.setRowCount(0)
            self.body_edit.clear()
