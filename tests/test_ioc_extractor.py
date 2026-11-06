from modules.ioc_extractor import extract_iocs


def test_extract_url_and_domain():
    text = "Visit https://example.com/login"
    result = extract_iocs(text)

    assert "https://example.com/login" in result["urls"]
    assert "example.com" in result["domains"]


def test_extract_ip_address():
    result = extract_iocs("Suspicious server: 192.168.1.20")

    assert "192.168.1.20" in result["ip_addresses"]


def test_reject_invalid_ip_address():
    result = extract_iocs("Invalid address: 999.999.999.999")

    assert result["ip_addresses"] == []


def test_extract_hashes():
    md5 = "a" * 32
    sha1 = "b" * 40
    sha256 = "c" * 64

    result = extract_iocs(f"Files: {md5} {sha1} {sha256}")

    assert md5 in result["hashes"]
    assert sha1 in result["hashes"]
    assert sha256 in result["hashes"]


def test_extract_email_domain():
    result = extract_iocs("Contact admin@suspicious-example.com")

    assert "suspicious-example.com" in result["domains"]


def test_empty_input():
    result = extract_iocs("")

    assert result["counts"]["urls"] == 0
    assert result["counts"]["domains"] == 0
    assert result["counts"]["ip_addresses"] == 0
    assert result["counts"]["hashes"] == 0
