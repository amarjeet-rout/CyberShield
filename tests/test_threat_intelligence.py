import base64

import pytest

from modules import threat_intelligence as ti


def test_validate_ip():
    assert ti.validate_indicator("ip", "8.8.8.8") == "8.8.8.8"


def test_invalid_ip():
    with pytest.raises(ValueError):
        ti.validate_indicator("ip", "999.999.999.999")


def test_validate_domain():
    assert (
        ti.validate_indicator("domain", "Example.COM.")
        == "example.com"
    )


def test_reject_url_as_domain():
    with pytest.raises(ValueError):
        ti.validate_indicator("domain", "https://example.com")


def test_validate_hash():
    value = "A" * 64
    assert ti.validate_indicator("hash", value) == value.lower()


def test_invalid_hash():
    with pytest.raises(ValueError):
        ti.validate_indicator("hash", "not-a-hash")


def test_url_endpoint_encoding():
    url = "https://example.com/login"
    encoded = base64.urlsafe_b64encode(
        url.encode()
    ).decode().rstrip("=")

    endpoint = ti.get_virustotal_endpoint("url", url)

    assert endpoint.endswith("/urls/" + encoded)


def test_virustotal_not_configured(monkeypatch):
    monkeypatch.setattr(ti, "VT_API_KEY", None)

    result = ti.lookup_virustotal("domain", "example.com")

    assert result["status"] == "not_configured"


def test_urlhaus_not_configured(monkeypatch):
    monkeypatch.setattr(ti, "URLHAUS_AUTH_KEY", None)

    result = ti.lookup_urlhaus("https://example.com")

    assert result["status"] == "not_configured"


def test_lookup_indicator_offline(monkeypatch):
    monkeypatch.setattr(ti, "VT_API_KEY", None)
    monkeypatch.setattr(ti, "URLHAUS_AUTH_KEY", None)

    result = ti.lookup_indicator("url", "https://example.com")

    assert result["indicator"] == "https://example.com"
    assert len(result["providers"]) == 2
    assert all(
        provider["status"] == "not_configured"
        for provider in result["providers"]
    )


def test_unsupported_indicator():
    with pytest.raises(ValueError):
        ti.validate_indicator("email", "person@example.com")
