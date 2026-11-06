
from modules.url_analyzer import analyze_url
from modules.brand_detector import analyze_brand_impersonation
from modules.ioc_extractor import extract_iocs
from modules.ioc_correlator import correlate_iocs
from modules.threat_intelligence import lookup_indicator
from modules.risk_scoring import calculate_risk_score


def normalize_finding(finding):
    """Convert detector output into a consistent finding structure."""
    return {
        "type": finding.get("type", "Unspecified finding"),
        "severity": finding.get("severity", "Low"),
        "evidence": finding.get("evidence", ""),
    }


def investigate_url(url, selected_lookups=None):
    """
    Investigate a standalone URL.

    Performs:
    1. URL structural analysis
    2. Brand impersonation detection
    3. IOC extraction
    4. IOC correlation
    5. Optional external threat intelligence
    6. URL-specific risk scoring

    External lookups are performed only for explicitly
    selected indicators.
    """

    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL cannot be empty.")

    selected_lookups = selected_lookups or []

    # 1. Structural URL analysis
    url_result = analyze_url(url)

    # 2. Brand impersonation analysis
    brand_result = analyze_brand_impersonation(
        url_result["hostname"]
    )

    # 3. Extract indicators of compromise
    ioc_result = extract_iocs(url_result["url"])

    # 4. Correlate extracted indicators
    correlation_result = correlate_iocs(ioc_result)

    # 5. Optional external threat intelligence
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

        provider_results.extend(
            lookup_result["providers"]
        )

    # 6. Prepare category findings
    category_findings = {
        "email_content": [],
        "email_headers": [],

        "url_structure": [
            normalize_finding(item)
            for item in url_result.get("findings", [])
        ],

        "brand_impersonation": [
            normalize_finding(item)
            for item in brand_result.get("findings", [])
        ],
    }

    # 7. Calculate scores using the shared scoring engine
    risk_result = calculate_risk_score(
        category_findings,
        provider_results,
    )

    # 8. Normalize against categories applicable to URL analysis
    applicable_categories = [
        "url_structure",
        "brand_impersonation",
        "threat_intelligence",
    ]

    applicable_score = sum(
        risk_result["categories"][category]["score"]
        for category in applicable_categories
    )

    applicable_maximum = sum(
        risk_result["categories"][category]["cap"]
        for category in applicable_categories
    )

    url_risk_score = (
        round(
            (applicable_score / applicable_maximum) * 100
        )
        if applicable_maximum
        else 0
    )

    # 9. Determine URL-specific risk level
    if url_risk_score >= 45:
        risk_level = "High"
    elif url_risk_score >= 20:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    # 10. Update risk assessment
    risk_result["risk_score"] = url_risk_score
    risk_result["risk_level"] = risk_level
    risk_result["raw_category_total"] = applicable_score
    risk_result["maximum_category_total"] = applicable_maximum

    risk_result["explanation"] = (
        "URL-specific heuristic risk score normalized against "
        "the applicable URL structure, brand impersonation, and "
        "threat intelligence categories. This score is not a "
        "probability of malicious activity."
    )

    # 11. Return complete investigation
    return {
        "investigation_type": "URL",
        "input": url_result["url"],

        "url_analysis": url_result,

        "brand_analysis": [brand_result],

        "ioc_extraction": ioc_result,

        "ioc_correlation": correlation_result,

        "threat_intelligence": provider_results,

        "category_findings": category_findings,

        "risk_assessment": risk_result,
    }

