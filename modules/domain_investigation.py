from modules.domain_reputation import analyze_domain
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


def investigate_domain(domain, selected_lookups=None):
    """
    Investigate a standalone domain.

    Performs:
    1. Domain validation and DNS analysis
    2. Domain characteristic analysis
    3. IOC extraction
    4. IOC correlation
    5. Optional external threat intelligence
    6. Domain-specific risk scoring

    External lookups are performed only for explicitly
    selected indicators.
    """

    selected_lookups = selected_lookups or []

    # 1. Domain validation and analysis
    domain_result = analyze_domain(domain)
    normalized_domain = domain_result["domain"]

    # 2. Extract indicators from the standalone domain
    ioc_result = extract_iocs(normalized_domain)

    # extract_iocs does not extract standalone domains.
    # Add the validated domain explicitly.
    if normalized_domain not in ioc_result["domains"]:
        ioc_result["domains"].append(normalized_domain)
        ioc_result["domains"].sort()
        ioc_result["counts"]["domains"] = len(
            ioc_result["domains"]
        )

    # 3. Correlate extracted indicators
    correlation_result = correlate_iocs(ioc_result)

    # 4. Optional external threat intelligence
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

    # 5. Prepare domain-specific category findings
    category_findings = {
        "domain_analysis": [
            normalize_finding(item)
            for item in domain_result.get("findings", [])
        ]
    }

    # 6. Calculate risk using only applicable categories
    risk_result = calculate_risk_score(
        category_findings,
        provider_results,
        selected_categories=[
            "domain_analysis",
            "threat_intelligence",
        ],
    )

    # 7. Return complete investigation
    return {
        "investigation_type": "Domain",
        "input": normalized_domain,

        "domain_analysis": domain_result,

        "ioc_extraction": ioc_result,

        "ioc_correlation": correlation_result,

        "threat_intelligence": provider_results,

        "category_findings": category_findings,

        "risk_assessment": risk_result,
    }
