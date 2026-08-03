"""Dialog for applying one field edit across every matching packet at
once, instead of editing packets one at a time."""

from __future__ import annotations

from PyQt6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from packetbender.core.bulk_edit import (
    SAFE_BULK_FIELDS,
    count_layer_field_matches,
    count_sip_header_matches,
)


class BulkEditDialog(QDialog):
    def __init__(self, parent, filter_active: bool, records_provider) -> None:
        """``records_provider(scope: str) -> list[PacketRecord]`` resolves
        the current scope selection to the records it covers, letting the
        dialog show a live "N packets match" count as the user edits
        fields - not just after the fact."""
        super().__init__(parent)
        self._records_provider = records_provider
        self.setWindowTitle("Bulk Edit")
        self.setMinimumWidth(440)

        layout = QVBoxLayout(self)

        form = QFormLayout()

        self.scope_combo = QComboBox()
        self.scope_combo.addItem("All packets", "all")
        self.scope_combo.addItem("Currently filtered packets only", "filtered")
        if not filter_active:
            self.scope_combo.model().item(1).setEnabled(False)
        self.scope_combo.currentIndexChanged.connect(self._update_preview)
        form.addRow("Apply to:", self.scope_combo)

        self.target_combo = QComboBox()
        self.target_combo.addItem("SIP Header", "sip_header")
        self.target_combo.addItem("Generic Field (Ethernet/IP/UDP/TCP)", "layer_field")
        self.target_combo.currentIndexChanged.connect(self._on_target_changed)
        form.addRow("Change:", self.target_combo)

        layout.addLayout(form)

        # Created before the pages below, since building the layer-field
        # page triggers an initial _update_preview() call that needs it
        # to already exist.
        self.preview_label = QLabel()
        self.preview_label.setStyleSheet("font-weight: bold;")

        self.stack = QStackedWidget()
        self.stack.addWidget(self._build_sip_header_page())
        self.stack.addWidget(self._build_layer_field_page())
        layout.addWidget(self.stack)

        hint = QLabel(
            'Leave "Old value" blank to change every matching packet '
            "regardless of its current value."
        )
        hint.setWordWrap(True)
        layout.addWidget(hint)

        layout.addWidget(self.preview_label)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self._update_preview()

    def _build_sip_header_page(self) -> QWidget:
        widget = QWidget()
        form = QFormLayout(widget)
        self.header_name_edit = QLineEdit()
        self.header_name_edit.setPlaceholderText("e.g. Call-ID")
        self.header_name_edit.textChanged.connect(self._update_preview)
        self.header_old_value_edit = QLineEdit()
        self.header_old_value_edit.setPlaceholderText("optional")
        self.header_old_value_edit.textChanged.connect(self._update_preview)
        self.header_new_value_edit = QLineEdit()
        form.addRow("Header name:", self.header_name_edit)
        form.addRow("Old value:", self.header_old_value_edit)
        form.addRow("New value:", self.header_new_value_edit)
        return widget

    def _build_layer_field_page(self) -> QWidget:
        widget = QWidget()
        form = QFormLayout(widget)

        self.layer_combo = QComboBox()
        self.layer_combo.addItems(SAFE_BULK_FIELDS.keys())
        self.layer_combo.currentTextChanged.connect(self._on_layer_changed)

        self.field_combo = QComboBox()
        self._on_layer_changed(self.layer_combo.currentText())
        self.field_combo.currentTextChanged.connect(self._update_preview)

        self.layer_old_value_edit = QLineEdit()
        self.layer_old_value_edit.setPlaceholderText("optional")
        self.layer_old_value_edit.textChanged.connect(self._update_preview)
        self.layer_new_value_edit = QLineEdit()

        form.addRow("Layer:", self.layer_combo)
        form.addRow("Field:", self.field_combo)
        form.addRow("Old value:", self.layer_old_value_edit)
        form.addRow("New value:", self.layer_new_value_edit)
        return widget

    def _on_target_changed(self, index: int) -> None:
        self.stack.setCurrentIndex(index)
        self._update_preview()

    def _on_layer_changed(self, layer_name: str) -> None:
        self.field_combo.blockSignals(True)
        self.field_combo.clear()
        self.field_combo.addItems(SAFE_BULK_FIELDS.get(layer_name, ()))
        self.field_combo.blockSignals(False)
        self._update_preview()

    def _update_preview(self) -> None:
        records = self._records_provider(self.scope())

        if self.target_type() == "sip_header":
            header_name, old_value, _new_value = self.sip_header_params()
            count = count_sip_header_matches(records, header_name, old_value) if header_name else 0
        else:
            layer_name, field_name, old_value, _new_value = self.layer_field_params()
            count = count_layer_field_matches(records, layer_name, field_name, old_value)

        noun = "packet" if count == 1 else "packets"
        self.preview_label.setText(f"This will change {count} {noun}.")

    def scope(self) -> str:
        return self.scope_combo.currentData()

    def target_type(self) -> str:
        return self.target_combo.currentData()

    def sip_header_params(self) -> tuple[str, str, str]:
        return (
            self.header_name_edit.text().strip(),
            self.header_old_value_edit.text(),
            self.header_new_value_edit.text(),
        )

    def layer_field_params(self) -> tuple[str, str, str, str]:
        return (
            self.layer_combo.currentText(),
            self.field_combo.currentText(),
            self.layer_old_value_edit.text(),
            self.layer_new_value_edit.text(),
        )
