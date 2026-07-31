import pytest
from xml.parsers.expat import ExpatError

from packetbender.core.xml_message import is_well_formed, looks_like_xml, pretty_print

PIDF_XML = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b'<presence xmlns="urn:ietf:params:xml:ns:pidf" entity="sip:alice@example.com">'
    b"<tuple id=\"t1\"><status><basic>open</basic></status></tuple>"
    b"</presence>"
)


def test_looks_like_xml_accepts_declaration_and_bare_tags():
    assert looks_like_xml(PIDF_XML)
    assert looks_like_xml(b"<root><child/></root>")


def test_looks_like_xml_rejects_non_xml():
    assert not looks_like_xml(b"not xml")
    assert not looks_like_xml(b"")


def test_is_well_formed():
    assert is_well_formed(PIDF_XML.decode())
    assert not is_well_formed("<root><unclosed></root>")


def test_pretty_print_produces_indented_output():
    formatted = pretty_print(PIDF_XML.decode())
    assert "presence" in formatted
    assert "\n" in formatted


def test_pretty_print_raises_on_malformed_xml():
    with pytest.raises(ExpatError):
        pretty_print("<root><unclosed></root>")
