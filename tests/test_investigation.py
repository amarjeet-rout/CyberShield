import pytest

from modules.investigation import investigate_email


def load_email(filename):
    with open(filename, "r", encoding="utf-8") as file:
        return file.read()


def test_phishing_email_investigation():
    raw_email = load_email("data/sample_phishing.eml")
    result = investigate_email(raw_email)

    assert result["email_analysis"]["risk_level"] == "High"
    assert result["risk_assessment"]["risk_score"] > 0
    assert len(result["ioc_extraction"]["urls"]) > 0
    assert len(result["url_analysis"]) > 0


def test_legitimate_email_investigation():
    raw_email = load_email("data/sample_legitimate.eml")
    result = investigate_email(raw_email)

    assert result["ioc_extraction"]["counts"]["urls"] == 0
    assert result["url_analysis"] == []
    assert result["risk_assessment"]["risk_level"] == "Low"


def test_pipeline_does_not_call_external_providers_by_default():
    raw_email = load_email("data/sample_phishing.eml")
    result = investigate_email(raw_email)

    assert result["threat_intelligence"] == []


def test_pipeline_returns_all_analysis_sections():
    raw_email = load_email("data/sample_phishing.eml")
    result = investigate_email(raw_email)

    expected_sections = {
        "email_analysis",
        "header_analysis",
        "ioc_extraction",
        "url_analysis",
        "brand_analysis",
        "ioc_correlation",
        "threat_intelligence",
        "category_findings",
        "risk_assessment",
    }

    assert expected_sections.issubset(result.keys())


def test_explicit_lookup_selection(monkeypatch):
    import modules.investigation as investigation

    def fake_lookup(indicator_type, value):
        return {
            "providers": [
                {
                    "provider": "TestProvider",
                    "status": "not_found",
                }
            ]
        }

    monkeypatch.setattr(
        investigation,
        "lookup_indicator",
        fake_lookup,
    )

    raw_email = load_email("data/sample_legitimate.eml")

    result = investigation.investigate_email(
        raw_email,
        selected_lookups=[
            {"type": "domain", "value": "example.com"}
        ],
    )

    assert len(result["threat_intelligence"]) == 1
    assert result["threat_intelligence"][0]["provider"] == "TestProvider"


def test_empty_email_rejected():
    with pytest.raises(ValueError):
        investigate_email("")
def test_phishing_email_final_risk_is_high():
    raw_email = load_email("data/sample_phishing.eml")
    result = investigate_email(raw_email)

    assert result["risk_assessment"]["risk_level"] == "High"
    assert result["risk_assessment"]["risk_score"] >= 45


def test_legitimate_email_final_risk_is_low():
    raw_email = load_email("data/sample_legitimate.eml")
    result = investigate_email(raw_email)

    assert result["risk_assessment"]["risk_level"] == "Low"
    assert result["risk_assessment"]["risk_score"] < 20
