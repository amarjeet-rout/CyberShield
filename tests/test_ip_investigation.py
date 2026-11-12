
import pytest

from modules.ip_investigation import (
    classify_ip,
    investigate_ip,
)


def test_public_ipv4_classification():
    result = classify_ip("8.8.8.8")

    assert result["classification"] == "Public"
    assert result["is_global"] is True
    assert result["version"] == 4


def test_private_ipv4_classification():
    result = classify_ip("192.168.1.1")

    assert result["classification"] == "Private"
    assert result["is_global"] is False


def test_loopback_classification():
    result = classify_ip("127.0.0.1")

    assert result["classification"] == "Loopback"


def test_ipv6_classification():
    result = classify_ip("2001:4860:4860::8888")

    assert result["version"] == 6
    assert result["classification"] == "Public"


def test_invalid_ip_rejected():
    with pytest.raises(ValueError):
        investigate_ip("999.999.999.999")


def test_ip_input_normalized():
    result = investigate_ip("8.8.8.8")

    assert result["input"] == "8.8.8.8"
    assert result["investigation_type"] == "IP Address"


def test_standalone_ip_added_to_iocs():
    result = investigate_ip("8.8.8.8")

    assert "8.8.8.8" in result["ioc_extraction"]["ip_addresses"]


def test_no_external_lookup_by_default(monkeypatch):
    import modules.ip_investigation as ip_module

    def unexpected_lookup(*args, **kwargs):
        raise AssertionError("External lookup should not run.")

    monkeypatch.setattr(
        ip_module,
        "lookup_indicator",
        unexpected_lookup,
    )

    result = investigate_ip("8.8.8.8")

    assert result["threat_intelligence"] == []


def test_private_ip_never_queried(monkeypatch):
    import modules.ip_investigation as ip_module

    def unexpected_lookup(*args, **kwargs):
        raise AssertionError("Private IP must not be queried.")

    monkeypatch.setattr(
        ip_module,
        "lookup_indicator",
        unexpected_lookup,
    )

    result = investigate_ip(
        "192.168.1.1",
        selected_lookups=[
            {"type": "ip", "value": "192.168.1.1"}
        ],
    )

    assert result["threat_intelligence"] == []


def test_explicit_public_ip_lookup(monkeypatch):
    import modules.ip_investigation as ip_module

    def fake_lookup(indicator_type, value):
        assert indicator_type == "ip"
        assert value == "8.8.8.8"

        return {
            "providers": [
                {
                    "provider": "AbuseIPDB",
                    "status": "success",
                    "abuse_confidence_score": 20,
                }
            ]
        }

    monkeypatch.setattr(
        ip_module,
        "lookup_indicator",
        fake_lookup,
    )

    result = investigate_ip(
        "8.8.8.8",
        selected_lookups=[
            {"type": "ip", "value": "8.8.8.8"}
        ],
    )

    assert len(result["threat_intelligence"]) == 1
    assert result["threat_intelligence"][0]["provider"] == "AbuseIPDB"


def test_wrong_lookup_type_rejected():
    with pytest.raises(ValueError):
        investigate_ip(
            "8.8.8.8",
            selected_lookups=[
                {"type": "domain", "value": "example.com"}
            ],
        )


def test_mismatched_lookup_ip_rejected():
    with pytest.raises(ValueError):
        investigate_ip(
            "8.8.8.8",
            selected_lookups=[
                {"type": "ip", "value": "1.1.1.1"}
            ],
        )
