"""Generic per-layer field introspection/editing for any Scapy packet.

This lets the GUI show and edit L2-L4 fields (Ethernet, IP/IPv6, UDP/TCP,
...) for *any* packet, not just ones carrying a recognized application
payload. Length and checksum fields are flagged as "computed" — the GUI
defaults to recalculating them on save, but allows the user to pin an
explicit value instead.
"""

from __future__ import annotations

from dataclasses import dataclass

from scapy.packet import NoPayload, Packet, Raw

# Fields that Scapy normally computes at build time. These are safe to
# delete (letting Scapy recompute them) after any edit; the GUI defaults
# to doing so, but a user can uncheck "auto" to keep an explicit value.
COMPUTED_FIELDS = {
    "IP": ("len", "chksum"),
    "IPv6": ("plen",),
    "UDP": ("len", "chksum"),
    "TCP": ("chksum",),
}


@dataclass
class FieldRow:
    layer: Packet
    layer_name: str
    field_name: str
    value: str
    is_computed: bool


def editable_layers(pkt: Packet) -> list[Packet]:
    """Return every layer up to (but excluding) the first Raw/opaque
    payload — i.e. the L2-L4 headers a user would want to tweak."""
    layers: list[Packet] = []
    layer = pkt
    while layer is not None and not isinstance(layer, NoPayload):
        if isinstance(layer, Raw):
            break
        layers.append(layer)
        nxt = layer.payload
        layer = nxt if not isinstance(nxt, NoPayload) else None
    return layers


def field_rows(pkt: Packet) -> list[FieldRow]:
    rows: list[FieldRow] = []
    for layer in editable_layers(pkt):
        layer_name = layer.__class__.__name__
        computed = COMPUTED_FIELDS.get(layer_name, ())
        for fdesc in layer.fields_desc:
            value = layer.getfieldval(fdesc.name)
            rows.append(FieldRow(
                layer=layer,
                layer_name=layer_name,
                field_name=fdesc.name,
                value="" if value is None else str(value),
                is_computed=fdesc.name in computed,
            ))
    return rows


def parse_field_value(raw_text: str):
    """Best-effort text -> Python value conversion for setattr() on a
    Scapy field. Scapy's own field classes accept both native types and,
    for address/flag fields, strings - so falling back to the raw string
    is safe when it isn't a plain integer."""
    text = raw_text.strip()
    try:
        return int(text, 0)
    except ValueError:
        return text


def finalize_packet(pkt: Packet) -> None:
    """Clear Scapy's dissection cache on every layer so edited fields are
    actually re-serialized instead of the original captured bytes being
    replayed verbatim."""
    layer = pkt
    while layer is not None:
        if hasattr(layer, "raw_packet_cache"):
            layer.raw_packet_cache = None
        if hasattr(layer, "raw_packet_cache_fields"):
            layer.raw_packet_cache_fields = None
        nxt = getattr(layer, "payload", None)
        layer = nxt if not isinstance(nxt, NoPayload) else None
