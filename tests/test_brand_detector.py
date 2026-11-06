import pytest

from modules.brand_detector import analyze_brand_impersonation


def test_typo_brand_detection():
    result = analyze_brand_impersonation("paypa1.com")

    assert result["possible_impersonation"] is True
    assert any(
        match["brand"] == "PayPal"
        for match in result["brand_matches"]
    )


def test_brand_name_inside_suspicious_domain():
    result = analyze_brand_impersonation(
        "paypal-login.example.com"
    )

    assert result["possible_impersonation"] is True


def test_suspicious_keywords():
    result = analyze_brand_impersonation(
        "secure-login.example.com"
    )

    assert "secure" in result["suspicious_keywords"]
    assert "login" in result["suspicious_keywords"]


def test_official_domain_not_flagged():
    result = analyze_brand_impersonation("https://www.paypal.com")

    assert result["possible_impersonation"] is False
    assert result["brand_matches"] == []


def test_punycode_detection():
    result = analyze_brand_impersonation("xn--pple-43d.com")

    assert result["is_punycode"] is True


def test_empty_domain_rejected():
    with pytest.raises(ValueError):
        analyze_brand_impersonation("")
