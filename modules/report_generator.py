
import json
from datetime import datetime, timezone
from pathlib import Path

from modules.mitre_mapping import map_mitre_techniques


def build_incident_report(investigation):
    """Create a JSON-serializable incident report."""
    risk = investigation.get("risk_assessment", {})
    iocs = investigation.get("ioc_extraction", {})
    correlation = investigation.get("ioc_correlation", {})

    mitre = map_mitre_techniques(investigation)

    categories = {}

    for name, details in risk.get("categories", {}).items():
        categories[name] = {
            "score": details.get("score", 0),
            "cap": details.get("cap", 0),
            "evidence": details.get("evidence", []),
        }

    return {
        "report_title": "CyberShield Incident Investigation Report",
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "risk_assessment": {
            "score": risk.get("risk_score", 0),
            "level": risk.get("risk_level", "Unknown"),
            "explanation": risk.get("explanation", ""),
            "categories": categories,
        },
        "indicators_of_compromise": {
            "urls": iocs.get("urls", []),
            "domains": iocs.get("domains", []),
            "ip_addresses": iocs.get("ip_addresses", []),
            "hashes": iocs.get("hashes", []),
        },
        "correlation": {
            "nodes": correlation.get("nodes", []),
            "edges": correlation.get("edges", []),
            "node_count": correlation.get("node_count", 0),
            "edge_count": correlation.get("edge_count", 0),
        },
        "mitre_attack": mitre,
        "threat_intelligence": investigation.get(
            "threat_intelligence", []
        ),
        "limitations": [
            "Risk scores are heuristic, not probabilities.",
            "Missing threat intelligence does not imply safety.",
            "Authentication-Results headers are parsed, not independently verified.",
            "ATT&CK mappings are hypotheses requiring analyst review.",
            "Graph edges describe observed relationships, not a proven attack sequence.",
        ],
    }

def report_to_markdown(report):
    """Convert a structured report into readable Markdown."""
    risk = report["risk_assessment"]
    iocs = report["indicators_of_compromise"]
    mitre = report["mitre_attack"]

    lines = [
        "# CyberShield Incident Investigation Report",
        "",
        f"Generated: {report['generated_at']}",
        "",
        "## Executive Summary",
        "",
        f"**Risk score:** {risk['score']}/100",
        f"**Risk level:** {risk['level']}",
        "",
        risk["explanation"],
        "",
        "## Risk Breakdown",
        "",
    ]

    for category, details in risk["categories"].items():
        lines.append(
            f"### {category.replace('_', ' ').title()} "
            f"({details['score']}/{details['cap']})"
        )

        if not details["evidence"]:
            lines.append("- No scored findings")
        else:
            for item in details["evidence"]:
                if not isinstance(item, dict):
                    lines.append(f"- {item}")
                    continue

                label = item.get(
                    "type", item.get("provider", "Finding")
                )
                severity = item.get("severity", "Unspecified")
                evidence = item.get("evidence", "")
                score = item.get("score")

                lines.append(f"- **{label}** [{severity}]")

                if isinstance(evidence, list):
                    for detail in evidence:
                        lines.append(f"  - {detail}")
                elif evidence:
                    lines.append(f"  - Evidence: {evidence}")

                if score is not None:
                    lines.append(f"  - Evidence score: {score}")

        lines.append("")

    lines.extend(["## Extracted Indicators", ""])

    for indicator_type, values in iocs.items():
        lines.append(
            f"### {indicator_type.replace('_', ' ').title()}"
        )

        if values:
            for value in values:
                lines.append(f"- `{value}`")
        else:
            lines.append("- None extracted")

        lines.append("")

    lines.extend([
        "## IOC Correlation",
        "",
        f"Nodes: {report['correlation']['node_count']}",
        f"Edges: {report['correlation']['edge_count']}",
        "",
    ])

    for edge in report["correlation"]["edges"]:
        lines.append(
            f"- `{edge['source']}` → `{edge['target']}` "
            f"({edge.get('relationship', 'related')})"
        )

    lines.extend(["", "## MITRE ATT&CK Mapping", ""])

    if not mitre["mappings"]:
        lines.append("- No techniques mapped from available evidence.")
    else:
        for item in mitre["mappings"]:
            lines.extend([
                f"### {item['technique_id']} — {item['name']}",
                f"- Tactic: {item['tactic']}",
                f"- Confidence: {item['confidence']}",
                f"- Status: {item['status']}",
                f"- Reference: {item['url']}",
                f"- Limitation: {item['limitation']}",
                "",
            ])

            for evidence in item["evidence"]:
                lines.append(f"- Evidence: {evidence}")

            lines.append("")

    lines.extend(["## Threat Intelligence", ""])

    providers = report["threat_intelligence"]

    if not providers:
        lines.append("- No external lookups were requested.")
    else:
        for provider in providers:
            lines.append(
                f"- {provider.get('provider', 'Unknown')}: "
                f"{provider.get('status', 'unknown')}"
            )

    lines.extend(["", "## Limitations", ""])

    for limitation in report["limitations"]:
        lines.append(f"- {limitation}")

    return "\n".join(lines) + "\n"

def export_report(report, output_directory="reports"):
    """Save JSON and Markdown versions of an investigation report."""
    directory = Path(output_directory)
    directory.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime(
        "%Y%m%d_%H%M%S_%f"
    )

    json_path = directory / f"cybershield_{timestamp}.json"
    markdown_path = directory / f"cybershield_{timestamp}.md"

    json_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    markdown_path.write_text(
        report_to_markdown(report),
        encoding="utf-8",
    )

    return {
        "json_path": str(json_path),
        "markdown_path": str(markdown_path),
    }

