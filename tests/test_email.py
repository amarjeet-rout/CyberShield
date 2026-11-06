from modules.email_analyzer import analyze_email


def load_email(filename):
    with open(filename, "r", encoding="utf-8") as file:
        return file.read()


def test_phishing_email():
    email = load_email("data/sample_phishing.eml")
    result = analyze_email(email)

    assert result["risk_score"] >= 70
    assert result["risk_level"] == "High"
    assert len(result["indicators"]) > 0


def test_legitimate_email():
    email = load_email("data/sample_legitimate.eml")
    result = analyze_email(email)

    assert result["risk_score"] == 0
    assert result["risk_level"] == "Low"
    assert len(result["indicators"]) == 0


def test_url_extraction():
    email = load_email("data/sample_phishing.eml")
    result = analyze_email(email)

    assert "http://bit.ly/account-verification" in result["urls"]
