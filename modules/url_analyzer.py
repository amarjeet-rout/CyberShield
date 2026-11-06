import ipaddress
import math
import re
from collections import Counter
from urllib.parse import unquote, urlsplit


SHORTENED_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd",
    "cutt.ly", "rb.gy", "shorturl.at",
}

SUSPICIOUS_PATH_WORDS = {
    "login", "signin", "verify", "verification",
    "account", "update", "password", "secure",
    "billing", "confirm", "webscr",
}

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1",
    ".vbs", ".js", ".jar", ".hta",
}


def calculate_entropy(value):
    """Calculate Shannon entropy of a string."""
    if not value:
        return 0.0

    counts = Counter(value)
    length = len(value)

    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )

    return round(entropy, 2)


def analyze_url(url):
    """Analyze URL structure without making a network request."""
    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL cannot be empty.")

    url = url.strip()

    if not re.match(r"^https?://", url, re.IGNORECASE):
        raise ValueError("URL must start with http:// or https://")

    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise ValueError(f"Invalid URL: {error}")

    if not hostname:
        raise ValueError("URL does not contain a hostname.")

    hostname = hostname.lower().rstrip(".")
    findings = []

    def add_finding(name, severity, evidence):
        findings.append({
            "type": name,
            "severity": severity,
            "evidence": evidence,
        })

    # 1. Insecure HTTP
    if parsed.scheme.lower() == "http":
        add_finding(
            "Insecure HTTP",
            "Low",
            "The URL uses HTTP instead of HTTPS."
        )

    # 2. IP address instead of domain name
    is_ip_address = False

    try:
        ipaddress.ip_address(hostname)
        is_ip_address = True
        add_finding(
            "IP address hostname",
            "Medium",
            f"The URL uses an IP address: {hostname}"
        )
    except ValueError:
        pass

    # 3. URL credentials / user information
    if parsed.username is not None or parsed.password is not None:
        add_finding(
            "Embedded URL credentials",
            "High",
            "The URL contains username or password information."
        )

    # 4. At symbol in authority section
    if "@" in parsed.netloc:
        add_finding(
            "At-sign in URL authority",
            "Medium",
            "The URL contains @ in its authority section."
        )

    # 5. Known URL shortener
    if hostname in SHORTENED_DOMAINS:
        add_finding(
            "URL shortener",
            "Medium",
            f"The hostname belongs to a known shortener: {hostname}"
        )

    # 6. Punycode / internationalized domain
    if "xn--" in hostname:
        add_finding(
            "Punycode hostname",
            "Medium",
            "The hostname contains an internationalized domain label."
        )

    # 7. Unusual port
    if port is not None and port not in (80, 443):
        add_finding(
            "Unusual port",
            "Low",
            f"The URL uses port {port}."
        )

    # 8. Excessive subdomains
    labels = hostname.split(".")
    if len(labels) >= 5:
        add_finding(
            "Excessive subdomains",
            "Low",
            f"The hostname contains {len(labels)} labels."
        )

    # 9. Suspicious path keywords
    decoded_path = unquote(parsed.path).lower()
    path_words = sorted(
        word for word in SUSPICIOUS_PATH_WORDS
        if re.search(rf"(?<![a-z0-9]){re.escape(word)}(?![a-z0-9])",
                     decoded_path)
    )

    if path_words:
        add_finding(
            "Suspicious URL path keywords",
            "Low",
            ", ".join(path_words)
        )

    # 10. Potentially dangerous file extension
    path_lower = decoded_path.lower()

    if any(path_lower.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
        add_finding(
            "Potentially dangerous file extension",
            "High",
            path_lower.rsplit("/", 1)[-1]
        )

    # 11. Long URL
    if len(url) > 200:
        add_finding(
            "Unusually long URL",
            "Low",
            f"The URL contains {len(url)} characters."
        )

    # 12. High entropy query string
    query_entropy = calculate_entropy(parsed.query)

    if len(parsed.query) >= 30 and query_entropy >= 4.0:
        add_finding(
            "High-entropy query string",
            "Low",
            f"Query string entropy is {query_entropy}."
        )

    return {
        "url": url,
        "scheme": parsed.scheme.lower(),
        "hostname": hostname,
        "port": port,
        "path": parsed.path,
        "query": parsed.query,
        "is_ip_address": is_ip_address,
        "url_length": len(url),
        "query_entropy": query_entropy,
        "findings": findings,
        "indicator_count": len(findings),
    }
