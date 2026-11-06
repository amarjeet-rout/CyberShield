import pytest

from modules.domain_investigation import investigate_domain


def test_domain_investigation_returns_expected_structure(monkeypatch):
    from modules import domain_investigation

    monkeypatch.setattr(
        domain_investigation,
        "analyze_domain",
        lambda domain: {
            "domain": "example.com",
            "dns_records": {
                "A": ["192.0.2.1"],
                "AAAA": [],
                "MX": [],
                "NS": ["ns1.example.com"],
                "TXT": [],
            },
            "dns_errors": {},
            "findings": [],
            "analysis_summary": {
                "total_findings": 0,
                "dns_record_types_checked": [
                    "A", "AAAA", "MX", "NS", "TXT"
                ],
                "dns_record_types_found": ["A", "NS"],
            },
        },
    )

    result = investigate_domain("example.com")

    assert result["investigation_type"] == "Domain"
    assert result["input"] == "example.com"
    assert "domain_analysis" in result
    assert "ioc_extraction" in result
    assert "ioc_correlation" in result
    assert "threat_intelligence" in result
    assert "risk_assessment" in result


def test_standalone_domain_is_added_to_iocs(monkeypatch):
    from modules import domain_investigation

    monkeypatch.setattr(
        domain_investigation,
        "analyze_domain",
        lambda domain: {
            "domain": "example.com",
            "dns_records": {},
            "dns_errors": {},
            "findings": [],
            "analysis_summary": {},
        },
    )

    result = investigate_domain("example.com")

    assert "example.com" in result["ioc_extraction"]["domains"]
    assert result["ioc_extraction"]["counts"]["domains"] == 1


def test_domain_is_present_in_correlation_graph(monkeypatch):
    from modules import domain_investigation

    monkeypatch.setattr(
        domain_investigation,
        "analyze_domain",
        lambda domain: {
            "domain": "example.com",
            "dns_records": {},
            "dns_errors": {},
            "findings": [],
            "analysis_summary": {},
        },
    )

    result = investigate_domain("example.com")

    node_values = [
        node["value"]
        for node in result["ioc_correlation"]["nodes"]
    ]

    assert "example.com" in node_values


def test_domain_findings_contribute_to_risk_score(monkeypatch):
    from modules import domain_investigation

    monkeypatch.setattr(
        domain_investigation,
        "analyze_domain",
        lambda domain: {
            "domain": "example.com",
            "dns_records": {},
            "dns_errors": {},
            "findings": [
                {
                    "type": "Suspicious domain keyword",
                    "severity": "High",
                    "evidence": "Domain contains login keyword.",
                }
            ],
            "analysis_summary": {},
        },
    )

    result = investigate_domain("example.com")

    assert (
        result["risk_assessment"]["categories"]
        ["domain_analysis"]["score"] == 10
    )
    assert result["risk_assessment"]["risk_score"] > 0


def test_domain_risk_score_uses_only_applicable_categories(monkeypatch):
    from modules import domain_investigation

    monkeypatch.setattr(
        domain_investigation,
        "analyze_domain",
        lambda domain: {
            "domain": "example.com",
            "dns_records": {},
            "dns_errors": {},
            "findings": [],
            "analysis_summary": {},
        },
    )

    result = investigate_domain("example.com")

    assessment = result["risk_assessment"]

    assert assessment["maximum_category_total"] == 35
    assert set(assessment["categories"]) == {
        "domain_analysis",
        "threat_intelligence",
    }


def test_external_lookup_is_not_performed_automatically(monkeypatch):
    from modules import domain_investigation

    monkeypatch.setattr(
        domain_investigation,
        "analyze_domain",
        lambda domain: {
            "domain": "example.com",
            "dns_records": {},
            "dns_errors": {},
            "findings": [],
            "analysis_summary": {},
        },
    )

    def unexpected_lookup(*args, **kwargs):
        raise AssertionError("External lookup should not run.")

    monkeypatch.setattr(
        domain_investigation,
        "lookup_indicator",
        unexpected_lookup,
    )

    result = investigate_domain("example.com")

    assert result["threat_intelligence"] == []


def test_invalid_domain_is_rejected():
    with pytest.raises(ValueError):
        investigate_domain("")


def test_domain_input_is_normalized(monkeypatch):
    from modules import domain_investigation

    monkeypatch.setattr(
        domain_investigation,
        "analyze_domain",
        lambda domain: {
            "domain": "example.com",
            "dns_records": {},
            "dns_errors": {},
            "findings": [],
            "analysis_summary": {},
        },
    )

    result = investigate_domain("EXAMPLE.COM")

    assert result["input"] == "example.com"
