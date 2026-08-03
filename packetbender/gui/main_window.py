"""Main application window: packet list + per-packet field editors.

Every packet gets a generic "Layers" tab for editing L2-L4 header fields
(Ethernet/IP/UDP/TCP/...). Packets with a recognized application payload
additionally get a protocol-specific tab (SIP, RTP, SDP, or XML today);
anything else falls back to a raw-bytes text editor. SDP/XML carried as a
SIP body get the same structured editors nested inside the SIP tab.
"""

from __future__ import annotations

from xml.parsers.expat import ExpatError

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
    QMenu,
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
from packetbender.core.sdp_message import SdpLine, SdpMessage, looks_like_sdp
from packetbender.core.sip_message import SipHeader, SipMessage
from packetbender.core.xml_message import looks_like_xml, pretty_print

# (summary dict key, header label, visible by default, sort kind).
# Column position here is fixed; visibility is toggled via the header's
# right-click menu rather than by adding/removing actual columns, so a
# hidden column's data still exists (for filtering/sorting) - it's just
# not shown.
COLUMN_DEFS = (
    ("index", "#", True, "int"),
    ("time", "Time", True, "float"),
    ("src", "Source", True, "str"),
    ("dst", "Destination", True, "str"),
    ("src_port", "Src Port", False, "int"),
    ("dst_port", "Dst Port", False, "int"),
    ("ttl", "TTL", False, "int"),
    ("proto", "Protocol", True, "str"),
    ("length", "Length", True, "int"),
    ("info", "Info", True, "str"),
)

HEADER_COLUMNS = ("Header", "Value")
LAYER_COLUMNS = ("Layer", "Field", "Value", "Auto")
SDP_COLUMNS = ("Type", "Value")

RTP_FIELDS = (
    "version", "padding", "extension", "csrc_count",
    "marker", "payload_type", "sequence", "timestamp", "ssrc",
)

SDP_CONTENT_TYPES = ("application/sdp",)


def _is_xml_content_type(content_type: str) -> bool:
    return content_type in ("application/xml", "text/xml") or content_type.endswith("+xml")


class NumericTableWidgetItem(QTableWidgetItem):
    """QTableWidgetItem sorts by comparing display text by default, which
    orders "115" before "86" lexicographically. This compares the actual
    numeric value instead, while keeping whatever text is shown."""

    def __init__(self, text: str, sort_value: float) -> None:
        super().__init__(text)
        self.sort_value = sort_value

    def __lt__(self, other: object) -> bool:
        if isinstance(other, NumericTableWidgetItem):
            return self.sort_value < other.sort_value
        return super().__lt__(other)


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
        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self.setCentralWidget(self.splitter)

        list_panel = QWidget()
        list_layout = QVBoxLayout(list_panel)
        list_layout.setContentsMargins(0, 0, 0, 0)

        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("Filter:"))
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText(
            "Search packets - IP, port, protocol, SIP/SDP/XML content, RTP fields..."
        )
        self.filter_edit.textChanged.connect(self._apply_filter)
        filter_row.addWidget(self.filter_edit)
        clear_filter_btn = QPushButton("Clear")
        clear_filter_btn.clicked.connect(self.filter_edit.clear)
        filter_row.addWidget(clear_filter_btn)
        list_layout.addLayout(filter_row)

        self.packet_table = QTableWidget(0, len(COLUMN_DEFS))
        self.packet_table.setHorizontalHeaderLabels([c[1] for c in COLUMN_DEFS])
        self.packet_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.packet_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.packet_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.packet_table.setSortingEnabled(True)

        header = self.packet_table.horizontalHeader()
        header.setSectionResizeMode(len(COLUMN_DEFS) - 1, QHeaderView.ResizeMode.Stretch)
        header.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        header.customContextMenuRequested.connect(self._show_column_menu)

        for col, (_key, _label, default_visible, _kind) in enumerate(COLUMN_DEFS):
            self.packet_table.setColumnHidden(col, not default_visible)

        self.packet_table.itemSelectionChanged.connect(self._on_row_selected)
        self.packet_table.cellDoubleClicked.connect(self._on_row_double_clicked)
        list_layout.addWidget(self.packet_table)

        self.splitter.addWidget(list_panel)

        editor = QWidget()
        editor_layout = QVBoxLayout(editor)

        self.tabs = QTabWidget()
        editor_layout.addWidget(self.tabs)

        self.layers_tab = self._build_layers_tab()
        self.sip_tab = self._build_sip_tab()
        self.rtp_tab = self._build_rtp_tab()
        self.sdp_tab, self.sdp_table = self._build_sdp_table_widget()
        self.xml_tab, self.xml_edit = self._build_xml_editor_widget()
        self.raw_tab = self._build_raw_tab()

        self.tabs.addTab(self.layers_tab, "Layers")
        # SIP/RTP/SDP/XML/Raw tabs are added/removed dynamically per packet.

        apply_row = QHBoxLayout()
        self.apply_btn = QPushButton("Apply changes to packet")
        self.apply_btn.clicked.connect(self._apply_editor_to_record)
        apply_row.addStretch()
        apply_row.addWidget(self.apply_btn)
        editor_layout.addLayout(apply_row)

        self.editor_panel = editor
        self.splitter.addWidget(editor)
        self.splitter.setStretchFactor(0, 3)
        self.splitter.setStretchFactor(1, 2)
        self.splitter.setCollapsible(1, False)

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
        self.sip_body_tabs = QTabWidget()

        text_tab = QWidget()
        text_layout = QVBoxLayout(text_tab)
        self.body_edit = QPlainTextEdit()
        self.body_edit.textChanged.connect(self._mark_dirty)
        text_layout.addWidget(self.body_edit)
        self.sip_body_tabs.addTab(text_tab, "Text")

        self.sip_sdp_tab, self.sip_sdp_table = self._build_sdp_table_widget()
        self.sip_xml_tab, self.sip_xml_edit = self._build_xml_editor_widget()
        # SDP Fields / XML sub-tabs are added/removed dynamically based on
        # the body's Content-Type; the Text tab above is always the
        # canonical source applied back to the packet.

        layout.addWidget(self.sip_body_tabs)

        return widget

    def _build_sdp_table_widget(self) -> tuple[QWidget, QTableWidget]:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.addWidget(QLabel("SDP session description lines (type=value), in order."))

        table = QTableWidget(0, len(SDP_COLUMNS))
        table.setHorizontalHeaderLabels(SDP_COLUMNS)
        table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        table.itemChanged.connect(self._mark_dirty)
        layout.addWidget(table)

        btn_row = QHBoxLayout()
        add_btn = QPushButton("Add line")
        add_btn.clicked.connect(lambda: self._add_table_row(table))
        remove_btn = QPushButton("Remove selected")
        remove_btn.clicked.connect(lambda: self._remove_table_rows(table))
        btn_row.addWidget(add_btn)
        btn_row.addWidget(remove_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        return widget, table

    def _build_xml_editor_widget(self) -> tuple[QWidget, QPlainTextEdit]:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.addWidget(QLabel("XML payload."))

        edit = QPlainTextEdit()
        edit.textChanged.connect(self._mark_dirty)
        layout.addWidget(edit)

        btn_row = QHBoxLayout()
        pretty_btn = QPushButton("Validate / Pretty-print")
        pretty_btn.clicked.connect(lambda: self._pretty_print_xml(edit))
        btn_row.addStretch()
        btn_row.addWidget(pretty_btn)
        layout.addLayout(btn_row)

        return widget, edit

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
        # Column 0 always carries the record's stable identity (its
        # position in model.records) in UserRole, since sorting/filtering
        # mean a row's visual position no longer matches that index.
        header = self.packet_table.horizontalHeader()
        sort_section, sort_order = header.sortIndicatorSection(), header.sortIndicatorOrder()

        self.packet_table.setSortingEnabled(False)
        self.packet_table.setRowCount(len(self.model.records))
        for row, record in enumerate(self.model.records):
            summary = record.summary()
            highlighted = record.has_sip or record.has_rtp or record.has_sdp or record.has_xml

            for col, (key, _label, _default, kind) in enumerate(COLUMN_DEFS):
                value = summary.get(key)
                if key == "time":
                    text = f"{value:.6f}"
                else:
                    text = "" if value is None else str(value)

                if kind in ("int", "float"):
                    sort_value = value if value is not None else float("-inf")
                    item = NumericTableWidgetItem(text, sort_value)
                else:
                    item = QTableWidgetItem(text)
                if col == 0:
                    item.setData(Qt.ItemDataRole.UserRole, record.index)
                if highlighted:
                    item.setForeground(Qt.GlobalColor.darkGreen)
                self.packet_table.setItem(row, col, item)

        self.packet_table.setSortingEnabled(True)
        self.packet_table.sortByColumn(sort_section, sort_order)
        self._apply_filter()

    def _show_column_menu(self, pos) -> None:
        menu = QMenu(self)
        for col, (_key, label, _default, _kind) in enumerate(COLUMN_DEFS):
            action = QAction(label, menu)
            action.setCheckable(True)
            action.setChecked(not self.packet_table.isColumnHidden(col))
            action.toggled.connect(
                lambda checked, c=col: self.packet_table.setColumnHidden(c, not checked)
            )
            menu.addAction(action)
        menu.exec(self.packet_table.horizontalHeader().mapToGlobal(pos))

    def _apply_filter(self) -> None:
        needle = self.filter_edit.text().strip().lower()
        for row in range(self.packet_table.rowCount()):
            if not needle:
                self.packet_table.setRowHidden(row, False)
                continue

            record = self.model.records[self._record_index_at_row(row)]
            column_text = " ".join(
                self.packet_table.item(row, col).text().lower()
                for col in range(self.packet_table.columnCount())
            )
            matches = needle in column_text or needle in record.searchable_text()
            self.packet_table.setRowHidden(row, not matches)

    def _record_index_at_row(self, row: int) -> int:
        return self.packet_table.item(row, 0).data(Qt.ItemDataRole.UserRole)

    def _visual_row_for_index(self, record_index: int) -> int | None:
        for row in range(self.packet_table.rowCount()):
            if self._record_index_at_row(row) == record_index:
                return row
        return None

    def _on_row_selected(self) -> None:
        rows = self.packet_table.selectionModel().selectedRows()
        if not rows:
            return

        if self.dirty and self.current_index is not None:
            self._apply_editor_to_record()

        record_index = self._record_index_at_row(rows[0].row())
        self.current_index = record_index
        record = self.model.records[record_index]

        self._load_layers_tab(record)
        self._configure_payload_tabs(record)
        self._set_editor_enabled(True)
        self.status.showMessage(f"Editing packet {record_index}")
        self.dirty = False

    def _on_row_double_clicked(self, row: int, _column: int) -> None:
        """Guarantee the editor panel is visible and showing this packet,
        even if the splitter was previously dragged down to a sliver -
        double-clicking a row is the escape hatch to get it back."""
        self.packet_table.selectRow(row)
        sizes = self.splitter.sizes()
        if len(sizes) == 2 and sizes[1] < 100:
            total = sum(sizes) or self.splitter.width() or 1300
            self.splitter.setSizes([int(total * 3 / 5), int(total * 2 / 5)])

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
        for tab in (self.sip_tab, self.rtp_tab, self.sdp_tab, self.xml_tab, self.raw_tab):
            idx = self.tabs.indexOf(tab)
            if idx != -1:
                self.tabs.removeTab(idx)

        if record.has_sip:
            self.tabs.addTab(self.sip_tab, "SIP")
            self._load_sip_tab(record.sip)
        elif record.has_rtp:
            self.tabs.addTab(self.rtp_tab, "RTP")
            self._load_rtp_tab(record)
        elif record.has_sdp:
            self.tabs.addTab(self.sdp_tab, "SDP")
            self._load_sdp_table(self.sdp_table, record.sdp)
        elif record.has_xml:
            self.tabs.addTab(self.xml_tab, "XML")
            self.xml_edit.blockSignals(True)
            self.xml_edit.setPlainText(record.xml)
            self.xml_edit.blockSignals(False)
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

        for tab in (self.sip_sdp_tab, self.sip_xml_tab):
            idx = self.sip_body_tabs.indexOf(tab)
            if idx != -1:
                self.sip_body_tabs.removeTab(idx)

        content_type = sip.content_type()
        if content_type in SDP_CONTENT_TYPES or (not content_type and looks_like_sdp(sip.body)):
            sdp = SdpMessage.parse(sip.body) or SdpMessage(lines=[])
            self._load_sdp_table(self.sip_sdp_table, sdp)
            self.sip_body_tabs.addTab(self.sip_sdp_tab, "SDP Fields")
        elif _is_xml_content_type(content_type) or (not content_type and looks_like_xml(sip.body)):
            self.sip_xml_edit.blockSignals(True)
            self.sip_xml_edit.setPlainText(sip.body.decode("utf-8", errors="replace"))
            self.sip_xml_edit.blockSignals(False)
            self.sip_body_tabs.addTab(self.sip_xml_tab, "XML")

        self.sip_body_tabs.setCurrentIndex(0)

    def _apply_sip_tab(self, record) -> None:
        # The Text tab is the canonical body source; if the user was
        # editing the structured SDP/XML view instead, sync it back to
        # Text first so headers like Content-Length are computed from
        # what they actually see there.
        current_sub_tab = self.sip_body_tabs.currentWidget()
        if current_sub_tab is self.sip_sdp_tab:
            sdp = self._apply_sdp_table(self.sip_sdp_table)
            self.body_edit.blockSignals(True)
            self.body_edit.setPlainText(sdp.serialize().decode("utf-8", errors="replace"))
            self.body_edit.blockSignals(False)
        elif current_sub_tab is self.sip_xml_tab:
            self.body_edit.blockSignals(True)
            self.body_edit.setPlainText(self.sip_xml_edit.toPlainText())
            self.body_edit.blockSignals(False)

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

    def _load_sdp_table(self, table: QTableWidget, sdp: SdpMessage) -> None:
        table.blockSignals(True)
        table.setRowCount(len(sdp.lines))
        for row, line in enumerate(sdp.lines):
            table.setItem(row, 0, QTableWidgetItem(line.type))
            table.setItem(row, 1, QTableWidgetItem(line.value))
        table.blockSignals(False)

    def _apply_sdp_table(self, table: QTableWidget) -> SdpMessage:
        lines = []
        for row in range(table.rowCount()):
            type_item = table.item(row, 0)
            value_item = table.item(row, 1)
            if type_item is None or not type_item.text().strip():
                continue
            lines.append(SdpLine(
                type=type_item.text().strip(),
                value=value_item.text().strip() if value_item else "",
            ))
        return SdpMessage(lines=lines)

    def _pretty_print_xml(self, edit: QPlainTextEdit) -> None:
        try:
            formatted = pretty_print(edit.toPlainText())
        except ExpatError as exc:
            QMessageBox.warning(self, "Invalid XML", f"Could not parse XML: {exc}")
            return
        edit.setPlainText(formatted)
        self._mark_dirty()

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
        elif record.has_sdp:
            record.sdp = self._apply_sdp_table(self.sdp_table)
        elif record.has_xml:
            record.xml = self.xml_edit.toPlainText()
        elif record.packet.haslayer(Raw):
            self._apply_raw_tab(record)

        record.apply_edits()

        self._populate_packet_table()
        visual_row = self._visual_row_for_index(self.current_index)
        if visual_row is not None:
            self.packet_table.selectRow(visual_row)
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

    def _add_table_row(self, table: QTableWidget) -> None:
        row = table.rowCount()
        table.insertRow(row)
        table.setItem(row, 0, QTableWidgetItem(""))
        table.setItem(row, 1, QTableWidgetItem(""))
        self._mark_dirty()

    def _remove_table_rows(self, table: QTableWidget) -> None:
        rows = sorted({idx.row() for idx in table.selectedIndexes()}, reverse=True)
        for row in rows:
            table.removeRow(row)
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
            for tab in (self.sip_tab, self.rtp_tab, self.sdp_tab, self.xml_tab, self.raw_tab):
                idx = self.tabs.indexOf(tab)
                if idx != -1:
                    self.tabs.removeTab(idx)
