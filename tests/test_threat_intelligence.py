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
def test_abuseipdb_not_configured(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)

    result = ti.lookup_abuseipdb("8.8.8.8")

    assert result["provider"] == "AbuseIPDB"
    assert result["status"] == "not_configured"


def test_abuseipdb_success(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")

    class MockResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {
                "data": {
                    "ipAddress": "8.8.8.8",
                    "abuseConfidenceScore": 25,
                    "totalReports": 10,
                    "numDistinctUsers": 5,
                    "countryCode": "US",
                    "isTor": False,
                }
            }

    def mock_get(*args, **kwargs):
        assert args[0].endswith("/api/v2/check")
        assert kwargs["headers"]["Key"] == "test-key"
        assert kwargs["params"]["ipAddress"] == "8.8.8.8"
        return MockResponse()

    monkeypatch.setattr(ti.requests, "get", mock_get)

    result = ti.lookup_abuseipdb("8.8.8.8")

    assert result["status"] == "success"
    assert result["abuse_confidence_score"] == 25
    assert result["total_reports"] == 10
    assert result["distinct_users"] == 5


def test_abuseipdb_rejects_private_ip(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")

    def unexpected_request(*args, **kwargs):
        raise AssertionError("Private IP must not be submitted.")

    monkeypatch.setattr(ti.requests, "get", unexpected_request)

    result = ti.lookup_abuseipdb("192.168.1.1")

    assert result["status"] == "skipped"


def test_lookup_indicator_skips_non_public_ip(monkeypatch):
    def unexpected_request(*args, **kwargs):
        raise AssertionError("No external lookup should occur.")

    monkeypatch.setattr(ti.requests, "get", unexpected_request)

    result = ti.lookup_indicator("ip", "127.0.0.1")

    assert len(result["providers"]) == 2
    assert all(
        provider["status"] == "skipped"
        for provider in result["providers"]
    )


def test_lookup_indicator_includes_abuseipdb(monkeypatch):
    monkeypatch.setattr(ti, "VT_API_KEY", None)
    monkeypatch.setattr(
        ti,
        "lookup_abuseipdb",
        lambda value: {
            "provider": "AbuseIPDB",
            "status": "success",
        },
    )

    result = ti.lookup_indicator("ip", "8.8.8.8")

    assert len(result["providers"]) == 2
    assert result["providers"][1]["provider"] == "AbuseIPDB"


def test_abuseipdb_timeout(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")

    def mock_timeout(*args, **kwargs):
        raise ti.requests.Timeout()

    monkeypatch.setattr(ti.requests, "get", mock_timeout)

    result = ti.lookup_abuseipdb("8.8.8.8")

    assert result["status"] == "error"
    assert "timed out" in result["message"].lower()
