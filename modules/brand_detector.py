import re
import unicodedata
from urllib.parse import urlsplit

import tldextract
from rapidfuzz import fuzz


# Demo watchlist. These are reference domains, not a live threat feed.
BRAND_WATCHLIST = {
    "PayPal": "paypal.com",
    "Microsoft": "microsoft.com",
    "Google": "google.com",
    "Amazon": "amazon.com",
    "Apple": "apple.com",
    "Netflix": "netflix.com",
    "BP": "bp.com",
    "Shell": "shell.com",
    "ExxonMobil": "exxonmobil.com",
    "Chevron": "chevron.com",
    "TotalEnergies": "totalenergies.com",
}

SUSPICIOUS_KEYWORDS = {
    "login", "secure", "verify", "verification",
    "account", "update", "signin", "support",
    "password", "billing", "confirm",
}

extractor = tldextract.TLDExtract(suffix_list_urls=())


def normalize_hostname(value):
    """Extract and normalize a hostname from a URL or domain."""
    value = value.strip()

    if not value:
        raise ValueError("Domain or URL cannot be empty.")

    if "://" not in value:
        value = "//" + value

    parsed = urlsplit(value)
    hostname = parsed.hostname

    if not hostname:
        raise ValueError("Could not extract a valid hostname.")

    hostname = hostname.lower().rstrip(".")

    return hostname


def decode_idn(hostname):
    """Convert internationalized domain labels into readable Unicode."""
    decoded_labels = []

    for label in hostname.split("."):
        try:
            decoded_labels.append(label.encode("ascii").decode("idna"))
        except (UnicodeError, UnicodeEncodeError):
            decoded_labels.append(label)

    return ".".join(decoded_labels)


def get_registered_domain(hostname):
    """Return the registrable domain, such as example.co.uk."""
    result = extractor(hostname)

    if result.domain and result.suffix:
        return f"{result.domain}.{result.suffix}"

    return hostname


def analyze_brand_impersonation(domain_or_url):
    hostname = normalize_hostname(domain_or_url)
    readable_hostname = decode_idn(hostname)
    registered_domain = get_registered_domain(hostname)

    extracted = extractor(registered_domain)
    candidate_name = extracted.domain.lower()

    labels = set(re.split(r"[^a-z0-9]+", readable_hostname.lower()))
    keywords_found = sorted(labels.intersection(SUSPICIOUS_KEYWORDS))

    is_punycode = "xn--" in hostname
    findings = []
    matches = []

    if is_punycode:
        findings.append({
            "type": "Internationalized domain",
            "severity": "Medium",
            "evidence": "The hostname contains an xn-- punycode label."
        })

    for brand, official_domain in BRAND_WATCHLIST.items():
        official_host = normalize_hostname(official_domain)
        official_registered = get_registered_domain(official_host)
        official_name = extractor(official_registered).domain.lower()

        # Exact official domain and its subdomains are not treated as
        # impersonation by this basic detector.
        if hostname == official_host or hostname.endswith("." + official_host):
            continue

        similarity = round(
            fuzz.ratio(candidate_name, official_name), 2
        )

        brand_token_found = (
            brand.lower() in labels
            or official_name in labels
        )

        # Short brand names are excluded from fuzzy matching because
        # they produce too many false positives.
        fuzzy_match = (
            len(official_name) >= 5
            and similarity >= 80
        )

        if brand_token_found or fuzzy_match:
            reasons = []

            if brand_token_found:
                reasons.append("Brand name appears in hostname")

            if fuzzy_match:
                reasons.append(
                    f"Domain similarity is {similarity}%"
                )

            matches.append({
                "brand": brand,
                "official_domain": official_domain,
                "candidate_domain": registered_domain,
                "similarity": similarity,
                "reasons": reasons,
            })

    if matches:
        findings.append({
            "type": "Possible brand impersonation",
            "severity": "High",
            "evidence": matches
        })

    if keywords_found:
        findings.append({
            "type": "Suspicious domain keywords",
            "severity": "Low",
            "evidence": keywords_found
        })

    return {
        "input": domain_or_url,
        "hostname": hostname,
        "readable_hostname": readable_hostname,
        "registered_domain": registered_domain,
        "is_punycode": is_punycode,
        "suspicious_keywords": keywords_found,
        "brand_matches": matches,
        "findings": findings,
        "possible_impersonation": bool(matches),
    }
