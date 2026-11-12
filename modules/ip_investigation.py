
import ipaddress

from modules.ioc_extractor import extract_iocs
from modules.ioc_correlator import correlate_iocs
from modules.threat_intelligence import (
    lookup_indicator,
    validate_indicator,
)
from modules.risk_scoring import calculate_risk_score


def classify_ip(address):
    """Classify an IP address without making external requests."""
    ip = ipaddress.ip_address(address)

    if ip.is_loopback:
        classification = "Loopback"
    elif ip.is_private:
        classification = "Private"
    elif ip.is_link_local:
        classification = "Link-local"
    elif ip.is_multicast:
        classification = "Multicast"
    elif ip.is_reserved:
        classification = "Reserved"
    elif ip.is_unspecified:
        classification = "Unspecified"
    elif ip.is_global:
        classification = "Public"
    else:
        classification = "Special-purpose"

    return {
        "address": str(ip),
        "version": ip.version,
        "classification": classification,
        "is_global": ip.is_global,
        "is_private": ip.is_private,
        "is_loopback": ip.is_loopback,
        "is_reserved": ip.is_reserved,
        "is_link_local": ip.is_link_local,
    }


def investigate_ip(ip_address, selected_lookups=None):
    """
    Investigate an IPv4 or IPv6 address.

    Performs local IP classification, IOC extraction,
    IOC correlation, optional threat intelligence,
    and IP-specific risk assessment.
    """

    selected_lookups = selected_lookups or []

    # 1. Validate and normalize the IP address.
    normalized_ip = validate_indicator("ip", ip_address)

    # 2. Perform local classification.
    ip_result = classify_ip(normalized_ip)

    # 3. Extract IOCs from the standalone IP.
    ioc_result = extract_iocs(normalized_ip)

    # Ensure the validated input appears in extracted IPs.
    if normalized_ip not in ioc_result["ip_addresses"]:
        ioc_result["ip_addresses"].append(normalized_ip)
        ioc_result["ip_addresses"].sort()
        ioc_result["counts"]["ip_addresses"] = len(
            ioc_result["ip_addresses"]
        )

    # 4. Build the IOC correlation graph.
    correlation_result = correlate_iocs(ioc_result)

    # 5. Perform explicitly selected external lookups.
    provider_results = []

    if not isinstance(selected_lookups, list):
        raise ValueError("Selected lookups must be a list.")

    for item in selected_lookups:
        if not isinstance(item, dict):
            raise ValueError(
                "Each selected lookup must be a dictionary."
            )

        if item.get("type") != "ip":
            raise ValueError(
                "IP investigations accept only IP address lookups."
            )

        lookup_value = validate_indicator(
            "ip",
            item.get("value"),
        )

        if lookup_value != normalized_ip:
            raise ValueError(
                "Selected lookup must match the investigated IP."
            )

        if not ip_result["is_global"]:
            continue

        lookup_result = lookup_indicator(
            "ip",
            normalized_ip,
        )

        provider_results.extend(
            lookup_result["providers"]
        )

    # 6. Prepare IP-specific findings.
    category_findings = {
        "ip_analysis": [],
    }

    # Classification is informational, not malicious evidence.

    # 7. Calculate IP-specific risk.
    risk_result = calculate_risk_score(
        category_findings,
        provider_results,
        selected_categories=[
            "ip_analysis",
            "threat_intelligence",
        ],
    )

    # 8. Return the standard investigation structure.
    return {
        "investigation_type": "IP Address",
        "input": normalized_ip,
        "ip_analysis": ip_result,
        "ioc_extraction": ioc_result,
        "ioc_correlation": correlation_result,
        "threat_intelligence": provider_results,
        "category_findings": category_findings,
        "risk_assessment": risk_result,
    }
