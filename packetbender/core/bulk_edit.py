"""Bulk field edits across every matching packet in a capture.

Editing a Call-ID or a source IP one packet at a time doesn't scale once
it's repeated across dozens of SIP messages or an entire capture - these
functions apply one change across every record that qualifies, reusing
the same per-record ``apply_edits()`` (and therefore the same
length/checksum recalculation) as a single-packet edit.
"""

from __future__ import annotations

from .layer_fields import parse_field_value

# Only scalar fields are safe to blindly overwrite here. Complex fields
# (IP.options, flags, ...) don't round-trip through plain text unchanged
# - see the Layers tab's per-field apply logic for the same concern that
# motivates leaving them out.
SAFE_BULK_FIELDS = {
    "Ether": ("src", "dst"),
    "IP": ("src", "dst", "ttl", "tos", "id"),
    "IPv6": ("src", "dst", "hlim"),
    "UDP": ("sport", "dport"),
    "TCP": ("sport", "dport"),
}


def _sip_header_matches(record, name_lower: str, old_value: str) -> bool:
    if not record.has_sip:
        return False
    return any(
        header.name.lower() == name_lower and (not old_value or header.value == old_value)
        for header in record.sip.headers
    )


def count_sip_header_matches(records, header_name: str, old_value: str) -> int:
    """How many packets a ``bulk_set_sip_header`` call with these
    parameters would change, without changing anything - lets the UI
    show a live preview before the user commits to an edit."""
    name_lower = header_name.strip().lower()
    return sum(1 for r in records if _sip_header_matches(r, name_lower, old_value))


def bulk_set_sip_header(records, header_name: str, old_value: str, new_value: str) -> int:
    """Set a SIP header's value across every record that carries it -
    and whose current value matches ``old_value``, if one is given.
    Returns the number of packets changed."""
    name_lower = header_name.strip().lower()
    changed = 0
    for record in records:
        if not _sip_header_matches(record, name_lower, old_value):
            continue
        for header in record.sip.headers:
            if header.name.lower() == name_lower and (not old_value or header.value == old_value):
                header.value = new_value
        record.apply_edits()
        changed += 1
    return changed


def _layer_field_matches(record, layer_name: str, field_name: str, old_value: str) -> bool:
    pkt = record.packet
    if not pkt.haslayer(layer_name):
        return False
    current = pkt[layer_name].getfieldval(field_name)
    current_text = "" if current is None else str(current)
    return not old_value or current_text == old_value


def count_layer_field_matches(records, layer_name: str, field_name: str, old_value: str) -> int:
    """How many packets a ``bulk_set_layer_field`` call with these
    parameters would change, without changing anything."""
    return sum(1 for r in records if _layer_field_matches(r, layer_name, field_name, old_value))


def bulk_set_layer_field(
    records, layer_name: str, field_name: str, old_value: str, new_value: str
) -> int:
    """Set an L2-L4 field's value across every record whose packet has
    that layer - and whose current value matches ``old_value``, if one
    is given. Returns the number of packets changed."""
    changed = 0
    for record in records:
        if not _layer_field_matches(record, layer_name, field_name, old_value):
            continue
        setattr(record.packet[layer_name], field_name, parse_field_value(new_value))
        record.apply_edits()
        changed += 1
    return changed
