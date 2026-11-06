
from modules.header_analyzer import analyze_headers


def test_authentication_failures():

    email = """From: Security <security@example.com>
To: user@example.net
Subject: Account Notice
Authentication-Results: mx.example.net; spf=fail; dkim=fail; dmarc=fail
Received: from mail.example.net by mx.example.net
"""

    result = analyze_headers(email)

    assert result["authentication"]["spf"] == "fail"
    assert result["authentication"]["dkim"] == "fail"
    assert result["authentication"]["dmarc"] == "fail"

    assert len(result["findings"]) == 3


def test_reply_to_mismatch():

    email = """From: Security <security@example.com>
Reply-To: attacker@unknown.com
Subject: Account Notice
"""

    result = analyze_headers(email)

    assert result["sender_domain"] == "example.com"
    assert result["reply_domain"] == "unknown.com"

    assert any(
        finding["type"] == "Reply-To mismatch"
        for finding in result["findings"]
    )


def test_missing_authentication():

    email = """From: User <user@example.com>
To: customer@example.net
Subject: Meeting
"""

    result = analyze_headers(email)

    assert result["authentication"]["spf"] == "unknown"
    assert result["authentication"]["dkim"] == "unknown"
    assert result["authentication"]["dmarc"] == "unknown"

    assert len(result["missing_authentication"]) == 3


def test_empty_email():

    try:
        analyze_headers("")
        assert False, "Expected ValueError"
    except ValueError:
        pass
