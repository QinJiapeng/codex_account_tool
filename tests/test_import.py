from app.service import parse_four_segment_line, parse_import_text


def test_only_four_segments_are_accepted():
    valid = "User@example.com----pw----client-id----abcdefghijklmnopqrst"
    record = parse_four_segment_line(valid)
    assert record and record["email"] == "user@example.com"
    assert parse_four_segment_line("user@example.com") is None
    assert parse_four_segment_line(valid + "----extra") is None


def test_five_segments_accept_a_normalized_totp_secret():
    record = parse_four_segment_line(
        "User@example.com----pw----client-id----abcdefghijklmnopqrst----jbsw y3dp ehpk 3pxp=="
    )
    assert record and record["totp_secret"] == "JBSWY3DPEHPK3PXP"
    assert parse_four_segment_line(
        "user@example.com----pw----client-id----abcdefghijklmnopqrst----not-a-totp-key"
    ) is None


def test_three_segments_accept_password_and_totp_without_outlook_credentials():
    record = parse_four_segment_line("User@example.com----pw----jbsw y3dp ehpk 3pxp==")
    assert record == {
        "email": "user@example.com",
        "password": "pw",
        "client_id": "",
        "mailbox_refresh_token": "",
        "totp_secret": "JBSWY3DPEHPK3PXP",
    }


def test_import_deduplicates_and_counts_invalid():
    text = "\n".join([
        "a@example.com----pw----cid----abcdefghijklmnopqrst",
        "A@example.com----pw2----cid2----abcdefghijklmnopqrstuv",
        "bad line",
    ])
    records, invalid, duplicates = parse_import_text(text)
    assert len(records) == 1
    assert invalid == 1
    assert duplicates == 1

