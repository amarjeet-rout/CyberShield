from collections import defaultdict

CATEGORY_CAPS = {
    "email_content": 35,
    "email_headers": 20,
    "url_structure": 25,
    "brand_impersonation": 10,
    "domain_analysis": 25,
    "threat_intelligence": 10,
}

SEVERITY_WEIGHTS = {
    "Critical": 15,
    "High": 10,
    "Medium": 5,
    "Low": 2,
    "Informational": 0,
}


def score_findings(findings, category):
    if category not in CATEGORY_CAPS:
        raise ValueError(f"Unknown scoring category: {category}")

    unique_findings = {}

    for finding in findings:
        key = (
            finding.get("type", "Unknown"),
            str(finding.get("evidence", "")),
        )
        unique_findings[key] = finding

    raw_score = 0

    for finding in unique_findings.values():
        supplied_score = finding.get("score")

        if (
            isinstance(supplied_score, (int, float))
            and not isinstance(supplied_score, bool)
            and supplied_score >= 0
        ):
            raw_score += supplied_score
        else:
            raw_score += SEVERITY_WEIGHTS.get(
                finding.get("severity", "Low"), 0
            )

    score = min(round(raw_score), CATEGORY_CAPS[category])

    return {
        "category": category,
        "raw_score": raw_score,
        "score": score,
        "cap": CATEGORY_CAPS[category],
        "finding_count": len(unique_findings),
        "evidence": list(unique_findings.values()),
    }


def score_threat_intelligence(provider_results):
    scores = []
    evidence = []

    for result in provider_results:
        provider = result.get("provider", "Unknown")
        status = result.get("status")

        if provider == "VirusTotal" and status == "success":
            malicious = result.get("malicious", 0)
            suspicious = result.get("suspicious", 0)

            if malicious > 0:
                scores.append(10)
                evidence.append({
                    "provider": provider,
                    "severity": "High",
                    "evidence": (
                        f"{malicious} engines marked the indicator malicious."
                    ),
                })
            elif suspicious > 0:
                scores.append(5)
                evidence.append({
                    "provider": provider,
                    "severity": "Medium",
                    "evidence": (
                        f"{suspicious} engines marked the indicator suspicious."
                    ),
                })

        elif provider == "URLhaus" and status == "listed":
            scores.append(10)
            evidence.append({
                "provider": provider,
                "severity": "High",
                "evidence": "The URL is listed in URLhaus.",
            })

    return {
        "category": "threat_intelligence",
        "score": max(scores, default=0),
        "cap": CATEGORY_CAPS["threat_intelligence"],
        "evidence": evidence,
    }


def calculate_risk_score(
    category_findings,
    provider_results=None,
    selected_categories=None,
):
    provider_results = provider_results or []

    # Preserve the original scoring behavior for existing investigations.
    if selected_categories is None:
        selected_categories = [
            "email_content",
            "email_headers",
            "url_structure",
            "brand_impersonation",
            "threat_intelligence",
        ]
        normalize_score = False
    else:
        normalize_score = True

    for category in selected_categories:
        if category not in CATEGORY_CAPS:
            raise ValueError(f"Unknown scoring category: {category}")

    category_scores = {}

    for category in selected_categories:
        if category == "threat_intelligence":
            category_scores[category] = score_threat_intelligence(
                provider_results
            )
        else:
            category_scores[category] = score_findings(
                category_findings.get(category, []),
                category,
            )

    total_score = sum(
        item["score"] for item in category_scores.values()
    )

    maximum_score = sum(
        CATEGORY_CAPS[category]
        for category in selected_categories
    )

    if normalize_score and maximum_score:
        risk_score = round((total_score / maximum_score) * 100)
    else:
        risk_score = total_score

    if risk_score >= 45:
        level = "High"
    elif risk_score >= 20:
        level = "Medium"
    else:
        level = "Low"

    return {
        "risk_score": min(100, risk_score),
        "risk_level": level,
        "raw_category_total": total_score,
        "maximum_category_total": maximum_score,
        "categories": category_scores,
        "is_probability": False,
        "explanation": (
            "Heuristic risk score from observed evidence. "
            "Category contributions are capped. "
            "Selected investigation categories are normalized "
            "when applicable. This score is not a probability "
            "of malicious activity."
        ),
    }
