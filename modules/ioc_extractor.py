import hashlib
import ipaddress
import re
from urllib.parse import urlsplit

from modules.url_analyzer import analyze_url


URL_PATTERN = re.compile(
    r"https?://[^\s<>\"']+",
    re.IGNORECASE
)

HASH_PATTERN = re.compile(
    r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b"
)

EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b"
)


def extract_iocs(text):
    """Extract URLs, domains, IPv4 addresses and file hashes."""
    if not isinstance(text, str):
        raise ValueError("Input must be text.")

    urls = set()
    domains = set()
    ip_addresses = set()
    hashes = set()

    # Extract URLs first, then inspect their hostnames.
    for match in URL_PATTERN.findall(text):
        url = match.rstrip(".,;:!?)]}")

        try:
            result = analyze_url(url)
            urls.add(url)

            hostname = result["hostname"]

            try:
                ipaddress.ip_address(hostname)
                ip_addresses.add(hostname)
            except ValueError:
                domains.add(hostname)

        except ValueError:
            continue

    # Extract domains from email addresses.
    for domain in EMAIL_PATTERN.findall(text):
        domains.add(domain.lower().rstrip("."))

    # Extract IPv4 addresses and validate them.
    ipv4_pattern = (
        r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"
    )

    for candidate in re.findall(ipv4_pattern, text):
        try:
            validated_ip = str(ipaddress.IPv4Address(candidate))
            ip_addresses.add(validated_ip)
        except ipaddress.AddressValueError:
            continue

    # Extract MD5, SHA-1 and SHA-256-looking values.
    for match in HASH_PATTERN.findall(text):
        hashes.add(match.lower())

    return {
        "urls": sorted(urls),
        "domains": sorted(domains),
        "ip_addresses": sorted(ip_addresses),
        "hashes": sorted(hashes),
        "counts": {
            "urls": len(urls),
            "domains": len(domains),
            "ip_addresses": len(ip_addresses),
            "hashes": len(hashes),
        },
    }
