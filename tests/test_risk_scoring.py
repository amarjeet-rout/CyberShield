import pytest

from modules.risk_scoring import (
    calculate_risk_score,
    score_findings,
    score_threat_intelligence,
)


def test_empty_findings_have_zero_score():
    result = calculate_risk_score({})

    assert result["risk_score"] == 0
    assert result["risk_level"] == "Low"


def test_high_severity_finding_scores_more():
    low = score_findings(
        [{"type": "Warning", "severity": "Low", "evidence": "A"}],
        "email_content",
    )

    high = score_findings(
        [{"type": "Warning", "severity": "High", "evidence": "A"}],
        "email_content",
    )

    assert high["score"] > low["score"]


def test_category_score_is_capped():
    findings = [
        {
            "type": f"Finding {i}",
            "severity": "High",
            "evidence": f"Evidence {i}",
        }
        for i in range(10)
    ]

    result = score_findings(findings, "email_content")

    assert result["score"] == 35
    assert result["cap"] == 35


def test_duplicate_findings_are_not_counted_twice():
    finding = {
        "type": "Suspicious link",
        "severity": "High",
        "evidence": "http://example.test",
    }

    result = score_findings(
        [finding, finding],
        "url_structure",
    )

    assert result["finding_count"] == 1
    assert result["score"] == 10


def test_unknown_category_rejected():
    with pytest.raises(ValueError):
        score_findings([], "unknown_category")


def test_virustotal_malicious_result():
    result = score_threat_intelligence([
        {
            "provider": "VirusTotal",
            "status": "success",
            "malicious": 5,
            "suspicious": 2,
        }
    ])

    assert result["score"] == 10
    assert len(result["evidence"]) == 1


def test_virustotal_suspicious_result():
    result = score_threat_intelligence([
        {
            "provider": "VirusTotal",
            "status": "success",
            "malicious": 0,
            "suspicious": 2,
        }
    ])

    assert result["score"] == 5


def test_urlhaus_listed_result():
    result = score_threat_intelligence([
        {
            "provider": "URLhaus",
            "status": "listed",
        }
    ])

    assert result["score"] == 10


def test_no_external_results_means_zero():
    result = score_threat_intelligence([
        {
            "provider": "VirusTotal",
            "status": "not_found",
        },
        {
            "provider": "URLhaus",
            "status": "not_configured",
        },
    ])

    assert result["score"] == 0


def test_multiple_providers_do_not_double_count():
    result = score_threat_intelligence([
        {
            "provider": "VirusTotal",
            "status": "success",
            "malicious": 4,
            "suspicious": 1,
        },
        {
            "provider": "URLhaus",
            "status": "listed",
        },
    ])

    assert result["score"] == 10


def test_risk_score_is_bounded():
    result = calculate_risk_score({
        "email_content": [
            {
                "type": "Urgent",
                "severity": "High",
                "evidence": "Urgent request",
            }
        ],
        "email_headers": [
            {
                "type": "SPF failure",
                "severity": "High",
                "evidence": "SPF failed",
            }
        ],
    })

    assert 0 <= result["risk_score"] <= 100
    assert result["is_probability"] is False


def test_risk_level_high():
    findings = {
        category: [
            {
                "type": f"Finding {category} {i}",
                "severity": "High",
                "evidence": f"Evidence {category} {i}",
            }
            for i in range(3)
        ]
        for category in (
            "email_content",
            "email_headers",
            "url_structure",
            "brand_impersonation",
        )
    }

    result = calculate_risk_score(findings)

    assert result["risk_level"] == "High"
    assert result["risk_score"] >= 70
def test_ip_analysis_category():
    result = score_findings(
        [
            {
                "type": "Suspicious IP",
                "severity": "High",
                "evidence": "IP has suspicious characteristics.",
            }
        ],
        "ip_analysis",
    )

    assert result["category"] == "ip_analysis"
    assert result["score"] == 10


def test_abuseipdb_high_confidence():
    result = score_threat_intelligence([
        {
            "provider": "AbuseIPDB",
            "status": "success",
            "abuse_confidence_score": 85,
            "total_reports": 20,
        }
    ])

    assert result["score"] == 10
    assert len(result["evidence"]) == 1


def test_abuseipdb_medium_confidence():
    result = score_threat_intelligence([
        {
            "provider": "AbuseIPDB",
            "status": "success",
            "abuse_confidence_score": 40,
            "total_reports": 5,
        }
    ])

    assert result["score"] == 5
