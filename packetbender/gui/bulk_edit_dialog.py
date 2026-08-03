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

from packetbender.core.bulk_edit import SAFE_BULK_FIELDS


class BulkEditDialog(QDialog):
    def __init__(self, parent, filter_active: bool) -> None:
        super().__init__(parent)
        self.setWindowTitle("Bulk Edit")
        self.setMinimumWidth(440)

        layout = QVBoxLayout(self)

        form = QFormLayout()

        self.scope_combo = QComboBox()
        self.scope_combo.addItem("All packets", "all")
        self.scope_combo.addItem("Currently filtered packets only", "filtered")
        if not filter_active:
            self.scope_combo.model().item(1).setEnabled(False)
        form.addRow("Apply to:", self.scope_combo)

        self.target_combo = QComboBox()
        self.target_combo.addItem("SIP Header", "sip_header")
        self.target_combo.addItem("Generic Field (Ethernet/IP/UDP/TCP)", "layer_field")
        self.target_combo.currentIndexChanged.connect(self._on_target_changed)
        form.addRow("Change:", self.target_combo)

        layout.addLayout(form)

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

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _build_sip_header_page(self) -> QWidget:
        widget = QWidget()
        form = QFormLayout(widget)
        self.header_name_edit = QLineEdit()
        self.header_name_edit.setPlaceholderText("e.g. Call-ID")
        self.header_old_value_edit = QLineEdit()
        self.header_old_value_edit.setPlaceholderText("optional")
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

        self.layer_old_value_edit = QLineEdit()
        self.layer_old_value_edit.setPlaceholderText("optional")
        self.layer_new_value_edit = QLineEdit()

        form.addRow("Layer:", self.layer_combo)
        form.addRow("Field:", self.field_combo)
        form.addRow("Old value:", self.layer_old_value_edit)
        form.addRow("New value:", self.layer_new_value_edit)
        return widget

    def _on_target_changed(self, index: int) -> None:
        self.stack.setCurrentIndex(index)

    def _on_layer_changed(self, layer_name: str) -> None:
        self.field_combo.clear()
        self.field_combo.addItems(SAFE_BULK_FIELDS.get(layer_name, ()))

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
