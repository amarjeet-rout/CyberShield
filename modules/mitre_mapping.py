
MITRE_TECHNIQUES = {
    "T1566.002": {
        "name": "Spearphishing Link",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1566/002/",
    },
    "T1566.001": {
        "name": "Spearphishing Attachment",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1566/001/",
    },
}


def map_mitre_techniques(investigation):
    """
    Map observed email evidence to possible ATT&CK techniques.

    These are hypotheses for analyst review, not confirmation
    of successful exploitation or compromise.
    """
    mappings = []

    email = investigation.get("email_analysis", {})
    urls = email.get("urls", [])
    attachments = email.get("attachments", [])

    if urls:
        mappings.append({
            "technique_id": "T1566.002",
            **MITRE_TECHNIQUES["T1566.002"],
            "confidence": "Low",
            "status": "Potential technique",
            "evidence": [
                f"Email contains URL: {url}" for url in urls
            ],
            "limitation": (
                "A link in an email alone does not prove spearphishing, "
                "user interaction, or compromise."
            ),
        })

    suspicious_extensions = (
        ".exe", ".scr", ".bat", ".cmd",
        ".ps1", ".vbs", ".js", ".jar", ".hta"
    )

    suspicious_attachments = [
        attachment for attachment in attachments
        if str(attachment).lower().endswith(suspicious_extensions)
    ]

    if suspicious_attachments:
        mappings.append({
            "technique_id": "T1566.001",
            **MITRE_TECHNIQUES["T1566.001"],
            "confidence": "Low",
            "status": "Potential technique",
            "evidence": [
                f"Suspicious attachment: {name}"
                for name in suspicious_attachments
            ],
            "limitation": (
                "Attachment extension alone does not establish "
                "malicious content or successful execution."
            ),
        })

    return {
        "framework": "MITRE ATT&CK Enterprise",
        "mappings": mappings,
        "technique_count": len(mappings),
        "disclaimer": (
            "Mappings indicate possible attacker techniques "
            "and require analyst validation."
        ),
    }
