"""Detection, validation, and pretty-printing for XML payloads.

Covers both XML carried as a SIP body (e.g. PIDF presence documents,
MESSAGE/REFER bodies) and XML sent as a standalone UDP/TCP payload. No
structural editing is offered - XML nesting varies too much for a
generic field table - just validation and reformatting around a plain
text editor.
"""

from __future__ import annotations

import xml.dom.minidom as minidom
from xml.parsers.expat import ExpatError


def looks_like_xml(payload: bytes) -> bool:
    stripped = payload.strip()
    if not stripped:
        return False
    return stripped.startswith(b"<?xml") or (
        stripped.startswith(b"<") and stripped.endswith(b">")
    )


def is_well_formed(text: str) -> bool:
    try:
        minidom.parseString(text.encode("utf-8"))
        return True
    except (ExpatError, UnicodeEncodeError, ValueError):
        return False


def pretty_print(text: str) -> str:
    """Reformat XML with indentation. Raises ExpatError on malformed XML -
    callers should catch it and surface a message rather than losing the
    user's in-progress edit."""
    dom = minidom.parseString(text.encode("utf-8"))
    rough = dom.toprettyxml(indent="  ")
    return "\n".join(line for line in rough.split("\n") if line.strip())
