import pytest

from app.db import Database
from app.proxy import ProxyPool, normalize_proxy, redact_proxy


def test_proxy_credentials_are_redacted():
    value = normalize_proxy("http://user:secret@example.com:8080")
    assert value.startswith("http://user:secret@")
    assert redact_proxy(value) == "http://example.com:8080"


@pytest.mark.parametrize(
    ("value", "expected_prefix"),
    [
        ("example.com:8080", "http://example.com:8080"),
        ("user:secret@example.com:8080", "http://user:secret@example.com:8080"),
        ("https://example.com:8080", "https://example.com:8080"),
        ("socks4://example.com:1080", "socks4://example.com:1080"),
        ("socks5://user:secret@example.com:1080", "socks5://user:secret@example.com:1080"),
        ("socks5h://example.com:1080", "socks5h://example.com:1080"),
    ],
)
def test_documented_proxy_formats_are_supported(value: str, expected_prefix: str):
    assert normalize_proxy(value) == expected_prefix


def test_proxy_claims_rotate_in_round_robin_order(tmp_path):
    database = Database(tmp_path / "proxy.db")
    database.initialize()
    pool = ProxyPool(database, lease_seconds=60, cooldown_seconds=5)
    pool.import_text("one.example:8001\ntwo.example:8002\nthree.example:8003")

    first = pool.claim("first")
    pool.complete(first, success=True)
    second = pool.claim("second")
    pool.complete(second, success=True)
    third = pool.claim("third")
    pool.complete(third, success=True)
    fourth = pool.claim("fourth")

    assert [first.url, second.url, third.url, fourth.url] == [
        "http://one.example:8001",
        "http://two.example:8002",
        "http://three.example:8003",
        "http://one.example:8001",
    ]


def test_proxy_public_listing_supports_pagination(tmp_path):
    database = Database(tmp_path / "proxy.db")
    database.initialize()
    pool = ProxyPool(database)
    pool.import_text("one.example:8001\ntwo.example:8002\nthree.example:8003")

    first = pool.list_public(limit=2, offset=0)
    second = pool.list_public(limit=2, offset=2)

    assert len(first) == 2
    assert len(second) == 1
    assert {item["id"] for item in first}.isdisjoint({item["id"] for item in second})
