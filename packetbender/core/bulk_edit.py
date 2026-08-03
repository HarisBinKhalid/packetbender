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


def bulk_set_sip_header(records, header_name: str, old_value: str, new_value: str) -> int:
    """Set a SIP header's value across every record that carries it -
    and whose current value matches ``old_value``, if one is given.
    Returns the number of packets changed."""
    name_lower = header_name.strip().lower()
    changed = 0
    for record in records:
        if not record.has_sip:
            continue
        touched = False
        for header in record.sip.headers:
            if header.name.lower() != name_lower:
                continue
            if old_value and header.value != old_value:
                continue
            header.value = new_value
            touched = True
        if touched:
            record.apply_edits()
            changed += 1
    return changed


def bulk_set_layer_field(
    records, layer_name: str, field_name: str, old_value: str, new_value: str
) -> int:
    """Set an L2-L4 field's value across every record whose packet has
    that layer - and whose current value matches ``old_value``, if one
    is given. Returns the number of packets changed."""
    changed = 0
    for record in records:
        pkt = record.packet
        if not pkt.haslayer(layer_name):
            continue
        layer = pkt[layer_name]
        current = layer.getfieldval(field_name)
        current_text = "" if current is None else str(current)
        if old_value and current_text != old_value:
            continue
        setattr(layer, field_name, parse_field_value(new_value))
        record.apply_edits()
        changed += 1
    return changed
