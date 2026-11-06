
import pytest

from modules.domain_reputation import (
    normalize_domain,
    analyze_domain_characteristics,
    analyze_dns_findings,
)


# --------------------------------------------------
# DOMAIN VALIDATION TESTS
# --------------------------------------------------

def test_normalize_domain():
    assert normalize_domain("Example.COM") == "example.com"


def test_normalize_domain_with_trailing_dot():
    assert normalize_domain("example.com.") == "example.com"


def test_empty_domain():
    with pytest.raises(ValueError):
        normalize_domain("")


def test_url_is_rejected():
    with pytest.raises(ValueError):
        normalize_domain("https://example.com/login")


def test_ip_address_is_rejected():
    with pytest.raises(ValueError):
        normalize_domain("8.8.8.8")


def test_invalid_domain_label():
    with pytest.raises(ValueError):
        normalize_domain("bad_domain.com")


# --------------------------------------------------
# DOMAIN CHARACTERISTIC TESTS
# --------------------------------------------------

def test_punycode_detection():

    findings = analyze_domain_characteristics(
        "xn--example-abc.com"
    )

    assert any(
        item["type"] == "Punycode domain"
        for item in findings
    )


def test_sensitive_keyword_detection():

    findings = analyze_domain_characteristics(
        "secure-login-example.com"
    )

    assert any(
        item["type"] == "Sensitive keyword in domain"
        for item in findings
    )


def test_long_domain_detection():

    domain = "verylongdomainnameexample123456789012345678901234567890.com"

    findings = analyze_domain_characteristics(domain)

    assert any(
        item["type"] == "Long domain name"
        for item in findings
    )


# --------------------------------------------------
# DNS FINDING TESTS
# --------------------------------------------------

def test_missing_dns_records():

    dns_result = {
        "records": {
            "A": [],
            "AAAA": [],
            "MX": [],
            "NS": [],
            "TXT": [],
        },
        "errors": {},
    }

    findings = analyze_dns_findings(dns_result)

    finding_types = [
        item["type"] for item in findings
    ]

    assert "No address records" in finding_types
    assert "No mail exchange record" in finding_types
    assert "No nameserver record" in finding_types


def test_dns_errors_do_not_create_false_missing_record_findings():

    dns_result = {
        "records": {
            "A": [],
            "AAAA": [],
            "MX": [],
            "NS": [],
            "TXT": [],
        },
        "errors": {
            "A": "DNS query timed out.",
            "AAAA": "DNS query timed out.",
            "MX": "DNS query timed out.",
            "NS": "DNS query timed out.",
        },
    }

    findings = analyze_dns_findings(dns_result)

    finding_types = [
        item["type"] for item in findings
    ]

    assert "No address records" not in finding_types
    assert "No mail exchange record" not in finding_types
    assert "No nameserver record" not in finding_types
