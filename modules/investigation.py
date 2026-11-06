from modules.email_analyzer import analyze_email
from modules.header_analyzer import analyze_headers
from modules.brand_detector import analyze_brand_impersonation
from modules.url_analyzer import analyze_url
from modules.ioc_extractor import extract_iocs
from modules.ioc_correlator import correlate_iocs
from modules.threat_intelligence import lookup_indicator
from modules.risk_scoring import calculate_risk_score


def normalize_finding(finding, default_severity="Low"):
    if isinstance(finding, dict):
        return {
            "type": finding.get("type", "Unspecified finding"),
            "severity": finding.get("severity", default_severity),
            "evidence": finding.get("evidence", ""),
        }

    return {
        "type": "Detected indicator",
        "severity": default_severity,
        "evidence": str(finding),
    }


def classify_email_indicators(indicators):
    """
    Preserve structured email findings and their original scores.

    Sender mismatches are scored in the header category.
    URL structure findings are scored in the URL category.
    This prevents counting the same evidence twice.
    """
    findings = []

    for indicator in indicators:
        if not isinstance(indicator, dict):
            continue

        finding_type = indicator.get("type", "")

        # These are analyzed in separate categories.
        if finding_type in (
            "Sender mismatch",
            "Suspicious URL structure",
        ):
            continue

        findings.append({
            "type": finding_type or "Email content indicator",
            "severity": indicator.get("severity", "Low"),
            "evidence": indicator.get("evidence", ""),
            "score": indicator.get("score", 0),
        })

    return findings


def investigate_email(raw_email, selected_lookups=None):
    if not isinstance(raw_email, str) or not raw_email.strip():
        raise ValueError("Email content cannot be empty.")

    selected_lookups = selected_lookups or []

    email_result = analyze_email(raw_email)
    header_result = analyze_headers(raw_email)
    ioc_result = extract_iocs(raw_email)

    url_results = []

    for url in ioc_result["urls"]:
        try:
            url_results.append(analyze_url(url))
        except ValueError:
            continue

    brand_results = []

    for domain in ioc_result["domains"]:
        try:
            brand_results.append(
                analyze_brand_impersonation(domain)
            )
        except ValueError:
            continue

    correlation_result = correlate_iocs(ioc_result)

    provider_results = []

    for item in selected_lookups:
        if not isinstance(item, dict):
            raise ValueError(
                "Each selected lookup must be a dictionary."
            )

        lookup_result = lookup_indicator(
            item.get("type"),
            item.get("value"),
        )
        provider_results.extend(lookup_result["providers"])

    category_findings = {
        "email_content": classify_email_indicators(
            email_result.get("indicators", [])
        ),
        "email_headers": [
            normalize_finding(item)
            for item in header_result.get("findings", [])
        ],
        "url_structure": [
            normalize_finding(item)
            for result in url_results
            for item in result.get("findings", [])
        ],
        "brand_impersonation": [
            normalize_finding(item)
            for result in brand_results
            for item in result.get("findings", [])
        ],
    }

    risk_result = calculate_risk_score(
        category_findings,
        provider_results,
    )

    return {
        "email_analysis": email_result,
        "header_analysis": header_result,
        "ioc_extraction": ioc_result,
        "url_analysis": url_results,
        "brand_analysis": brand_results,
        "ioc_correlation": correlation_result,
        "threat_intelligence": provider_results,
        "category_findings": category_findings,
        "risk_assessment": risk_result,
    }
