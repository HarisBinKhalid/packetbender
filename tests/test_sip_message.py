from packetbender.core.sip_message import SipMessage, looks_like_sip

INVITE = (
    b"INVITE sip:bob@biloxi.example.com SIP/2.0\r\n"
    b"Via: SIP/2.0/UDP client.atlanta.example.com:5060\r\n"
    b"From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n"
    b"To: Bob <sip:bob@biloxi.example.com>\r\n"
    b"Call-ID: a84b4c76e66710@client.atlanta.example.com\r\n"
    b"CSeq: 314159 INVITE\r\n"
    b"Content-Length: 4\r\n"
    b"\r\n"
    b"abcd"
)


def test_looks_like_sip_detects_invite():
    assert looks_like_sip(INVITE)


def test_looks_like_sip_rejects_non_sip():
    assert not looks_like_sip(b"\x00\x01\x02not sip")
    assert not looks_like_sip(b"")


def test_parse_extracts_start_line_headers_and_body():
    msg = SipMessage.parse(INVITE)
    assert msg is not None
    assert msg.start_line == "INVITE sip:bob@biloxi.example.com SIP/2.0"
    assert msg.get("Call-ID") == "a84b4c76e66710@client.atlanta.example.com"
    assert msg.get("CSeq") == "314159 INVITE"
    assert msg.body == b"abcd"


def test_get_is_case_insensitive():
    msg = SipMessage.parse(INVITE)
    assert msg.get("call-id") == msg.get("Call-ID")


def test_set_updates_existing_header():
    msg = SipMessage.parse(INVITE)
    msg.set("From", "Carol <sip:carol@atlanta.example.com>")
    assert msg.get("From") == "Carol <sip:carol@atlanta.example.com>"
    assert len(msg.headers) == 6  # unchanged count


def test_set_appends_new_header():
    msg = SipMessage.parse(INVITE)
    msg.set("X-Custom", "hello")
    assert msg.get("X-Custom") == "hello"


def test_serialize_recomputes_content_length():
    msg = SipMessage.parse(INVITE)
    msg.body = b"a longer body than before"
    serialized = msg.serialize()
    assert b"Content-Length: 25" in serialized
    assert serialized.endswith(b"a longer body than before")


def test_round_trip_preserves_header_order():
    msg = SipMessage.parse(INVITE)
    serialized = msg.serialize()
    reparsed = SipMessage.parse(serialized)
    assert [h.name for h in reparsed.headers] == [h.name for h in msg.headers]
