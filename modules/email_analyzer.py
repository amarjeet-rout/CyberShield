
import re
from email import policy
from email.parser import Parser
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlsplit


# Suspicious phrases commonly found in phishing emails
SUSPICIOUS_PHRASES = {
    "urgent": 10,
    "immediately": 10,
    "account suspended": 15,
    "verify your account": 15,
    "verify your identity": 15,
    "click here": 5,
    "password expired": 15,
    "unusual activity": 10,
    "payment failed": 10,
    "limited time": 5,
    "claim your reward": 15,
    "confirm your password": 20,
    "avoid account closure": 15,
}

SHORTENED_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "rb.gy",
}

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1",
    ".vbs", ".js", ".jar", ".hta"
}


class EmailHTMLParser(HTMLParser):
    """Extract readable text and links from HTML email bodies."""

    def __init__(self):
        super().__init__()
        self.text_parts = []
        self.links = []

    def handle_data(self, data):
        text = data.strip()
        if text:
            self.text_parts.append(text)

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            for key, value in attrs:
                if key.lower() == "href" and value:
                    self.links.append(value)


def extract_email_body(message):
    """Extract plain-text and HTML content from an email."""

    plain_parts = []
    html_parts = []

    for part in message.walk():
        if part.get_content_disposition() == "attachment":
            continue

        content_type = part.get_content_type()

        if content_type not in ("text/plain", "text/html"):
            continue

        try:
            content = part.get_content()
        except Exception:
            continue

        if content_type == "text/plain":
            plain_parts.append(str(content))
        else:
            parser = EmailHTMLParser()
            parser.feed(str(content))

            html_parts.append(" ".join(parser.text_parts))
            html_parts.extend(parser.links)

    return "\n".join(plain_parts + html_parts)


def extract_urls(text):
    """Extract HTTP and HTTPS URLs from email content."""

    pattern = r'https?://[^\s<>"\'\]\[{}]+'

    found = re.findall(pattern, text, re.IGNORECASE)

    urls = []

    for url in found:
        url = url.rstrip(".,;:!?)]}")

        if url not in urls:
            urls.append(url)

    return urls


def get_domain(address):
    """Extract the domain from an email address."""

    _, parsed_address = parseaddr(address)

    if "@" not in parsed_address:
        return None

    domain = parsed_address.rsplit("@", 1)[1].lower().strip()

    if not domain or "." not in domain:
        return None

    return domain.rstrip(".")


def analyze_urls(urls):
    """Perform basic structural analysis of extracted URLs."""

    findings = []

    for url in urls:
        try:
            parsed = urlsplit(url)
            domain = (parsed.hostname or "").lower()

            if not domain:
                continue

            reasons = []

            if parsed.scheme == "http":
                reasons.append("Uses unencrypted HTTP")

            if domain in SHORTENED_DOMAINS:
                reasons.append("Uses a URL shortening service")

            try:
                import ipaddress
                ipaddress.ip_address(domain)
                reasons.append("Uses an IP address instead of a domain")
            except ValueError:
                pass

            if "@" in parsed.netloc:
                reasons.append("Contains URL user-information syntax")

            findings.append({
                "url": url,
                "domain": domain,
                "findings": reasons
            })

        except ValueError:
            continue

    return findings


def analyze_email(raw_email):
    """
    Analyse an email and return structured phishing indicators.

    Input:
        raw_email: Raw email content as a string.

    Output:
        Dictionary containing email metadata, findings and risk score.
    """

    if not isinstance(raw_email, str) or not raw_email.strip():
        raise ValueError("Email content cannot be empty.")

    # Step 1: Parse the email
    message = Parser(policy=policy.default).parsestr(raw_email)

    sender = str(message.get("From", ""))
    recipient = str(message.get("To", ""))
    reply_to = str(message.get("Reply-To", ""))
    subject = str(message.get("Subject", ""))

    body = extract_email_body(message)

    sender_domain = get_domain(sender)
    reply_domain = get_domain(reply_to) if reply_to else None

    indicators = []
    risk_score = 0

    # Step 2: Check sender and Reply-To mismatch
    if sender_domain and reply_domain:
        if sender_domain != reply_domain:
            indicators.append({
                "type": "Sender mismatch",
                "severity": "Medium",
                "evidence": (
                    f"Sender domain: {sender_domain}; "
                    f"Reply-To domain: {reply_domain}"
                ),
                "score": 20
            })
            risk_score += 20

    # Step 3: Analyse suspicious language
    searchable_text = f"{subject}\n{body}".lower()

    for phrase, score in SUSPICIOUS_PHRASES.items():
        if phrase in searchable_text:
            indicators.append({
                "type": "Suspicious language",
                "severity": "Medium",
                "evidence": f"Detected phrase: '{phrase}'",
                "score": score
            })

            risk_score += score

    # Step 4: Extract URLs
    urls = extract_urls(body)
    url_analysis = analyze_urls(urls)

    for item in url_analysis:
        for finding in item["findings"]:
            score = 10

            if "shortening service" in finding:
                score = 15

            if "IP address" in finding:
                score = 20

            indicators.append({
                "type": "Suspicious URL structure",
                "severity": "Medium",
                "evidence": f"{item['url']} - {finding}",
                "score": score
            })

            risk_score += score

    # Step 5: Inspect attachment filenames
    attachments = []

    for part in message.walk():
        if part.get_content_disposition() == "attachment":
            filename = part.get_filename()

            if filename:
                filename = str(filename)
                attachments.append(filename)

                extension = (
                    "." + filename.rsplit(".", 1)[-1].lower()
                    if "." in filename else ""
                )

                if extension in SUSPICIOUS_EXTENSIONS:
                    indicators.append({
                        "type": "Suspicious attachment",
                        "severity": "High",
                        "evidence": f"Potentially dangerous file: {filename}",
                        "score": 25
                    })

                    risk_score += 25

    # Step 6: Collect email authentication results
    authentication_results = message.get_all(
        "Authentication-Results", []
    )

    # Step 7: Calculate risk score
    risk_score = min(risk_score, 100)

    if risk_score >= 70:
        risk_level = "High"
    elif risk_score >= 35:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    # Step 8: Return structured analysis
    return {
        "email": {
            "sender": sender,
            "recipient": recipient,
            "reply_to": reply_to,
            "subject": subject,
            "sender_domain": sender_domain,
            "reply_domain": reply_domain
        },
        "urls": urls,
        "url_analysis": url_analysis,
        "attachments": attachments,
        "authentication_results": [
            str(result) for result in authentication_results
        ],
        "indicators": indicators,
        "risk_score": risk_score,
        "risk_level": risk_level
    }
