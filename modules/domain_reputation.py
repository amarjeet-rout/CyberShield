
import ipaddress
import re

import dns.exception
import dns.resolver

from modules.threat_intelligence import validate_indicator


# --------------------------------------------------
# DNS CONFIGURATION
# --------------------------------------------------

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT"]

DNS_TIMEOUT = 3.0

SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "password",
    "wallet",
    "banking",
]


# --------------------------------------------------
# DOMAIN VALIDATION
# --------------------------------------------------

def normalize_domain(domain):
    """
    Validate and normalize a domain name.

    Accepts a domain only, not a complete URL or IP address.
    """
    if not isinstance(domain, str) or not domain.strip():
        raise ValueError("Domain cannot be empty.")

    domain = domain.strip().lower().rstrip(".")

    if "://" in domain or "/" in domain or "@" in domain:
        raise ValueError("Enter a domain name, not a URL.")

    try:
        ipaddress.ip_address(domain)
        raise ValueError("IP addresses are not accepted as domains.")
    except ValueError as error:
        if str(error) == "IP addresses are not accepted as domains.":
            raise

    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("Invalid internationalized domain name.")

    domain = validate_indicator("domain", domain)

    if len(domain) > 253:
        raise ValueError("Domain name is too long.")

    labels = domain.split(".")

    if len(labels) < 2:
        raise ValueError("Domain must contain at least two labels.")

    label_pattern = re.compile(
        r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
    )

    for label in labels:

        if not label or not label_pattern.fullmatch(label):
            raise ValueError("Domain contains an invalid label.")

    return domain


# --------------------------------------------------
# DNS RECORD LOOKUP
# --------------------------------------------------

def lookup_dns_records(domain):
    """
    Retrieve common DNS records.

    This function performs DNS queries only.
    It does not contact threat intelligence providers.
    """

    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT
    resolver.timeout = DNS_TIMEOUT

    records = {}
    errors = {}

    for record_type in DNS_RECORD_TYPES:

        try:
            answer = resolver.resolve(
                domain,
                record_type,
                raise_on_no_answer=False,
            )

            if answer.rrset is None:
                records[record_type] = []
            else:
                records[record_type] = [
                    str(record).strip()
                    for record in answer
                ]

        except dns.resolver.NXDOMAIN:
            records[record_type] = []
            errors[record_type] = "Domain does not exist."
            break

        except dns.resolver.NoAnswer:
            records[record_type] = []

        except dns.resolver.NoNameservers:
            records[record_type] = []
            errors[record_type] = "No responding DNS nameservers."

        except dns.exception.Timeout:
            records[record_type] = []
            errors[record_type] = "DNS query timed out."

        except dns.exception.DNSException as error:
            records[record_type] = []
            errors[record_type] = (
                f"DNS lookup failed: {type(error).__name__}"
            )

    return {
        "records": records,
        "errors": errors,
    }


# --------------------------------------------------
# DOMAIN CHARACTERISTICS
# --------------------------------------------------

def analyze_domain_characteristics(domain):
    """Identify suspicious structural domain characteristics."""

    findings = []

    labels = domain.split(".")
    registered_label = labels[-2] if len(labels) >= 2 else labels[0]

    if len(domain) > 50:

        findings.append({
            "type": "Long domain name",
            "severity": "Low",
            "evidence": (
                f"Domain contains {len(domain)} characters."
            ),
        })

    if len(labels) > 4:

        findings.append({
            "type": "Excessive subdomains",
            "severity": "Medium",
            "evidence": (
                f"Domain contains {len(labels) - 2} "
                "subdomain labels."
            ),
        })

    if "xn--" in domain:

        findings.append({
            "type": "Punycode domain",
            "severity": "Medium",
            "evidence": (
                "Domain contains an internationalized "
                "punycode label."
            ),
        })

    if re.search(r"\d{4,}", registered_label):

        findings.append({
            "type": "Unusual numeric sequence",
            "severity": "Low",
            "evidence": (
                "The registered domain label contains "
                "four or more consecutive digits."
            ),
        })

    if registered_label.count("-") >= 2:

        findings.append({
            "type": "Multiple hyphens",
            "severity": "Low",
            "evidence": (
                "The registered domain label contains "
                "multiple hyphens."
            ),
        })

    matched_keywords = [
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in registered_label
    ]

    if matched_keywords:

        findings.append({
            "type": "Sensitive keyword in domain",
            "severity": "Medium",
            "evidence": (
                "Domain contains these potentially sensitive "
                f"keywords: {', '.join(matched_keywords)}."
            ),
        })

    return findings


# --------------------------------------------------
# DNS FINDINGS
# --------------------------------------------------

def analyze_dns_findings(dns_result):
    """Generate findings from DNS lookup results."""

    findings = []

    records = dns_result["records"]
    errors = dns_result["errors"]

    if not records.get("A") and not records.get("AAAA"):

        if (
            "A" not in errors
            and "AAAA" not in errors
        ):

            findings.append({
                "type": "No address records",
                "severity": "Low",
                "evidence": (
                    "No IPv4 or IPv6 address records were found."
                ),
            })

    if not records.get("MX") and "MX" not in errors:

        findings.append({
            "type": "No mail exchange record",
            "severity": "Informational",
            "evidence": (
                "No MX record was found. This does not "
                "indicate malicious activity."
            ),
        })

    if not records.get("NS") and "NS" not in errors:

        findings.append({
            "type": "No nameserver record",
            "severity": "Low",
            "evidence": (
                "No NS records were returned by the DNS lookup."
            ),
        })

    return findings


# --------------------------------------------------
# COMPLETE DOMAIN ANALYSIS
# --------------------------------------------------

def analyze_domain(domain):
    """
    Perform local domain investigation.

    Includes:
    1. Domain validation
    2. DNS record lookup
    3. Domain characteristic analysis
    4. DNS finding analysis

    External threat intelligence is not performed here.
    """

    normalized_domain = normalize_domain(domain)

    dns_result = lookup_dns_records(normalized_domain)

    characteristic_findings = (
        analyze_domain_characteristics(normalized_domain)
    )

    dns_findings = analyze_dns_findings(dns_result)

    findings = characteristic_findings + dns_findings

    return {
        "domain": normalized_domain,
        "dns_records": dns_result["records"],
        "dns_errors": dns_result["errors"],
        "findings": findings,
        "analysis_summary": {
            "total_findings": len(findings),
            "dns_record_types_checked": DNS_RECORD_TYPES,
            "dns_record_types_found": [
                record_type
                for record_type, values
                in dns_result["records"].items()
                if values
            ],
        },
    }
