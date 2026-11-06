import pytest

from modules.url_analyzer import analyze_url


def test_http_detection():
    result = analyze_url("http://example.com")
    assert any(
        item["type"] == "Insecure HTTP"
        for item in result["findings"]
    )


def test_ip_address_detection():
    result = analyze_url("http://192.168.1.10/login")
    assert result["is_ip_address"] is True


def test_url_shortener_detection():
    result = analyze_url("https://bit.ly/example")
    assert any(
        item["type"] == "URL shortener"
        for item in result["findings"]
    )


def test_suspicious_path_detection():
    result = analyze_url("https://example.com/account/verify")
    assert any(
        item["type"] == "Suspicious URL path keywords"
        for item in result["findings"]
    )


def test_dangerous_extension_detection():
    result = analyze_url("https://example.com/download/file.exe")
    assert any(
        item["type"] == "Potentially dangerous file extension"
        for item in result["findings"]
    )


def test_punycode_detection():
    result = analyze_url("https://xn--pple-43d.com")
    assert any(
        item["type"] == "Punycode hostname"
        for item in result["findings"]
    )


def test_https_normal_url():
    result = analyze_url("https://example.com/about")
    assert result["scheme"] == "https"
    assert result["hostname"] == "example.com"
    assert result["indicator_count"] == 0


def test_empty_url_rejected():
    with pytest.raises(ValueError):
        analyze_url("")


def test_invalid_scheme_rejected():
    with pytest.raises(ValueError):
        analyze_url("ftp://example.com")
