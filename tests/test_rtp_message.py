from packetbender.core.rtp_message import looks_like_rtp, parse_rtp, serialize_rtp

# version=2, no padding/extension/CSRC, marker=0, PT=0 (PCMU), seq=1, ts=160, ssrc=0x11223344
RTP_PACKET = bytes([0x80, 0x00, 0x00, 0x01]) + (160).to_bytes(4, "big") + bytes.fromhex("11223344")
RTP_PACKET += b"\x00" * 20  # fake media payload


def test_looks_like_rtp_accepts_version_2():
    assert looks_like_rtp(RTP_PACKET)


def test_looks_like_rtp_rejects_short_payload():
    assert not looks_like_rtp(b"\x80\x00")


def test_parse_rtp_splits_header_and_media():
    result = parse_rtp(RTP_PACKET)
    assert result is not None
    header, media = result
    assert header.version == 2
    assert header.payload_type == 0
    assert header.sequence == 1
    assert header.timestamp == 160
    assert header.ssrc == 0x11223344
    assert media == b"\x00" * 20


def test_serialize_rtp_round_trips_edited_fields():
    header, media = parse_rtp(RTP_PACKET)
    header.sequence = 42
    header.marker = 1
    rebuilt = serialize_rtp(header, media)

    reparsed_header, reparsed_media = parse_rtp(rebuilt)
    assert reparsed_header.sequence == 42
    assert reparsed_header.marker == 1
    assert reparsed_media == media
