
import re
from email import policy
from email.parser import Parser
from email.utils import parseaddr


AUTH_METHODS = ("spf", "dkim", "dmarc")

VALID_RESULTS = {
    "pass",
    "fail",
    "softfail",
    "neutral",
    "none",
    "temperror",
    "permerror"
}


def extract_domain(address):
    """Extract domain from an email address."""

    _, parsed = parseaddr(address)

    if "@" not in parsed:
        return None

    return parsed.rsplit("@", 1)[1].lower().strip().rstrip(".")


def parse_authentication_results(headers):
    """
    Extract SPF, DKIM and DMARC results from
    Authentication-Results headers.
    """

    results = {
        method: "unknown"
        for method in AUTH_METHODS
    }

    evidence = []

    for header in headers:
        header_text = str(header)

        for method in AUTH_METHODS:
            pattern = (
                rf"(?<![\w-]){method}\s*=\s*"
                rf"(pass|fail|softfail|neutral|none|"
                rf"temperror|permerror)\b"
            )

            matches = re.findall(
                pattern,
                header_text,
                re.IGNORECASE
            )

            if matches:
                value = matches[0].lower()

                results[method] = value

                evidence.append({
                    "method": method.upper(),
                    "result": value
                })

    return results, evidence


def extract_received_information(received_headers):
    """Extract basic routing information from Received headers."""

    routing = []

    for header in received_headers:

        header_text = str(header)

        from_match = re.search(
            r"\bfrom\s+([^\s;(]+)",
            header_text,
            re.IGNORECASE
        )

        by_match = re.search(
            r"\bby\s+([^\s;(]+)",
            header_text,
            re.IGNORECASE
        )

        routing.append({
            "from": from_match.group(1) if from_match else None,
            "by": by_match.group(1) if by_match else None
        })

    return routing


def analyze_headers(raw_email):
    """
    Analyse email headers and authentication evidence.

    Note: Authentication results are read from the supplied
    message. They are not independently verified.
    """

    if not isinstance(raw_email, str) or not raw_email.strip():
        raise ValueError("Email content cannot be empty.")

    message = Parser(policy=policy.default).parsestr(raw_email)

    sender = str(message.get("From", ""))
    reply_to = str(message.get("Reply-To", ""))
    return_path = str(message.get("Return-Path", ""))

    sender_domain = extract_domain(sender)
    reply_domain = extract_domain(reply_to) if reply_to else None
    return_domain = extract_domain(return_path) if return_path else None

    findings = []

    # 1. Sender and Reply-To comparison
    if sender_domain and reply_domain:
        if sender_domain != reply_domain:
            findings.append({
                "type": "Reply-To mismatch",
                "severity": "Medium",
                "evidence": (
                    f"From: {sender_domain}; "
                    f"Reply-To: {reply_domain}"
                )
            })

    # 2. Return-Path comparison
    if sender_domain and return_domain:
        if sender_domain != return_domain:
            findings.append({
                "type": "Return-Path mismatch",
                "severity": "Low",
                "evidence": (
                    f"From: {sender_domain}; "
                    f"Return-Path: {return_domain}"
                )
            })

    # 3. Authentication analysis
    auth_headers = message.get_all(
        "Authentication-Results", []
    )

    authentication, auth_evidence = (
        parse_authentication_results(auth_headers)
    )

    for method, result in authentication.items():

        if result == "fail":
            findings.append({
                "type": f"{method.upper()} failure",
                "severity": "High",
                "evidence": (
                    f"{method.upper()} authentication failed"
                )
            })

        elif result in ("softfail", "permerror"):
            findings.append({
                "type": f"{method.upper()} warning",
                "severity": "Medium",
                "evidence": (
                    f"{method.upper()} result: {result}"
                )
            })

        elif result == "temperror":
            findings.append({
                "type": f"{method.upper()} temporary error",
                "severity": "Low",
                "evidence": (
                    f"{method.upper()} result: {result}"
                )
            })

    # 4. Received headers
    received_headers = message.get_all("Received", [])

    routing_information = extract_received_information(
        received_headers
    )

    if not received_headers:
        findings.append({
            "type": "Missing Received headers",
            "severity": "Informational",
            "evidence": "No Received headers were supplied."
        })

    # 5. Missing authentication evidence
    missing_authentication = [
        method.upper()
        for method, result in authentication.items()
        if result == "unknown"
    ]

    return {
        "sender_domain": sender_domain,
        "reply_domain": reply_domain,
        "return_path_domain": return_domain,
        "authentication": authentication,
        "authentication_evidence": auth_evidence,
        "missing_authentication": missing_authentication,
        "received_header_count": len(received_headers),
        "routing_information": routing_information,
        "findings": findings
    }
