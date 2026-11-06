
import pytest

from modules.url_investigation import investigate_url


def test_suspicious_url_investigation():
    result = investigate_url("http://paypa1.com/login")

    assert result["investigation_type"] == "URL"
    assert result["risk_assessment"]["risk_score"] > 0
    assert result["risk_assessment"]["risk_level"] == "Medium"
    assert len(result["url_analysis"]["findings"]) > 0


def test_brand_impersonation_detection():
    result = investigate_url("http://paypa1.com/login")

    matches = result["brand_analysis"][0]["brand_matches"]

    assert len(matches) > 0
    assert any(match["brand"] == "PayPal" for match in matches)


def test_legitimate_url_investigation():
    result = investigate_url("https://example.com")

    assert result["investigation_type"] == "URL"
    assert result["risk_assessment"]["risk_score"] == 0
    assert result["risk_assessment"]["risk_level"] == "Low"
    assert result["brand_analysis"][0]["brand_matches"] == []


def test_invalid_url_rejected():
    with pytest.raises(ValueError):
        investigate_url("ftp://example.com")


def test_empty_url_rejected():
    with pytest.raises(ValueError):
        investigate_url("")


def test_ioc_extraction():
    result = investigate_url("http://paypa1.com/login")

    iocs = result["ioc_extraction"]

    assert "http://paypa1.com/login" in iocs["urls"]
    assert "paypa1.com" in iocs["domains"]


def test_ioc_correlation():
    result = investigate_url("http://paypa1.com/login")

    correlation = result["ioc_correlation"]

    assert correlation["node_count"] >= 2
    assert correlation["edge_count"] >= 1


def test_no_external_lookup_by_default(monkeypatch):
    import modules.url_investigation as url_module

    def unexpected_lookup(*args, **kwargs):
        raise AssertionError(
            "External lookup should not run automatically."
        )

    monkeypatch.setattr(
        url_module,
        "lookup_indicator",
        unexpected_lookup,
    )

    result = investigate_url("http://paypa1.com/login")

    assert result["threat_intelligence"] == []


def test_explicit_threat_intelligence_lookup(monkeypatch):
    import modules.url_investigation as url_module

    def fake_lookup(indicator_type, value):
        assert indicator_type == "url"
        assert value == "http://paypa1.com/login"

        return {
            "providers": [
                {
                    "provider": "TestProvider",
                    "status": "not_found",
                }
            ]
        }

    monkeypatch.setattr(
        url_module,
        "lookup_indicator",
        fake_lookup,
    )

    result = investigate_url(
        "http://paypa1.com/login",
        selected_lookups=[
            {
                "type": "url",
                "value": "http://paypa1.com/login",
            }
        ],
    )

    assert len(result["threat_intelligence"]) == 1
    assert result["threat_intelligence"][0]["provider"] == "TestProvider"
