from packetbender.core.sdp_message import SdpMessage, looks_like_sdp

SDP_BODY = (
    b"v=0\r\n"
    b"o=alice 2890844526 2890844526 IN IP4 host.atlanta.example.com\r\n"
    b"s=-\r\n"
    b"c=IN IP4 host.atlanta.example.com\r\n"
    b"t=0 0\r\n"
    b"m=audio 49170 RTP/AVP 0\r\n"
    b"a=rtpmap:0 PCMU/8000\r\n"
)


def test_looks_like_sdp_requires_version_line():
    assert looks_like_sdp(SDP_BODY)
    assert not looks_like_sdp(b"not sdp at all")
    assert not looks_like_sdp(b"")


def test_parse_preserves_line_order():
    sdp = SdpMessage.parse(SDP_BODY)
    assert sdp is not None
    assert [line.type for line in sdp.lines] == ["v", "o", "s", "c", "t", "m", "a"]


def test_parse_extracts_values():
    sdp = SdpMessage.parse(SDP_BODY)
    c_line = next(l for l in sdp.lines if l.type == "c")
    assert c_line.value == "IN IP4 host.atlanta.example.com"


def test_serialize_round_trips():
    sdp = SdpMessage.parse(SDP_BODY)
    serialized = sdp.serialize()
    reparsed = SdpMessage.parse(serialized)
    assert [l.value for l in reparsed.lines] == [l.value for l in sdp.lines]


def test_editing_a_line_value_reflects_in_serialization():
    sdp = SdpMessage.parse(SDP_BODY)
    for line in sdp.lines:
        if line.type == "c":
            line.value = "IN IP4 9.9.9.9"
    serialized = sdp.serialize()
    assert b"c=IN IP4 9.9.9.9" in serialized
