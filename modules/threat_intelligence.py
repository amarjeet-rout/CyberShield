import base64
import ipaddress
import os

import requests
from dotenv import load_dotenv


load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY")

VT_BASE_URL = "https://www.virustotal.com/api/v3"
URLHAUS_URL_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"

TIMEOUT = 10


def validate_indicator(indicator_type, value):
    """Validate and normalize an indicator before external lookup."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Indicator cannot be empty.")

    value = value.strip()

    if indicator_type == "ip":
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            raise ValueError("Invalid IP address.")

    if indicator_type == "domain":
        if "://" in value or "/" in value or "@" in value:
            raise ValueError("Enter a domain, not a URL.")

        value = value.lower().rstrip(".")

        if not value or "." not in value:
            raise ValueError("Invalid domain.")

        return value

    if indicator_type == "url":
        if not value.lower().startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")

        return value

    if indicator_type == "hash":
        value = value.lower()

        if len(value) not in (32, 40, 64):
            raise ValueError("Hash must be MD5, SHA-1 or SHA-256.")

        if any(char not in "0123456789abcdef" for char in value):
            raise ValueError("Hash contains invalid characters.")

        return value

    raise ValueError("Unsupported indicator type.")


def get_virustotal_endpoint(indicator_type, value):
    """Build the VirusTotal report endpoint."""
    if indicator_type == "url":
        encoded = base64.urlsafe_b64encode(
            value.encode("utf-8")
        ).decode("ascii").rstrip("=")

        return f"{VT_BASE_URL}/urls/{encoded}"

    endpoint_types = {
        "domain": "domains",
        "ip": "ip_addresses",
        "hash": "files",
    }

    return f"{VT_BASE_URL}/{endpoint_types[indicator_type]}/{value}"


def summarize_virustotal(data):
    """Extract a small, consistent summary from a VT report."""
    attributes = data.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})

    return {
        "provider": "VirusTotal",
        "status": "success",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": attributes.get("reputation"),
        "last_analysis_date": attributes.get("last_analysis_date"),
    }


def lookup_virustotal(indicator_type, value):
    """Retrieve an existing VirusTotal report. Does not submit scans."""
    if not VT_API_KEY:
        return {
            "provider": "VirusTotal",
            "status": "not_configured",
            "message": "VT_API_KEY is not configured.",
        }

    endpoint = get_virustotal_endpoint(indicator_type, value)

    headers = {
        "x-apikey": VT_API_KEY,
        "accept": "application/json",
    }

    try:
        response = requests.get(
            endpoint,
            headers=headers,
            timeout=TIMEOUT,
        )

        if response.status_code == 404:
            return {
                "provider": "VirusTotal",
                "status": "not_found",
                "message": "No existing report was found.",
            }

        response.raise_for_status()

        return summarize_virustotal(response.json())

    except requests.Timeout:
        return {
            "provider": "VirusTotal",
            "status": "error",
            "message": "The request timed out.",
        }

    except requests.RequestException as error:
        return {
            "provider": "VirusTotal",
            "status": "error",
            "message": f"Request failed: {error}",
        }

    except (ValueError, TypeError, AttributeError):
        return {
            "provider": "VirusTotal",
            "status": "error",
            "message": "The provider returned an invalid response.",
        }


def lookup_urlhaus(value):
    """Check a URL against URLhaus."""
    if not URLHAUS_AUTH_KEY:
        return {
            "provider": "URLhaus",
            "status": "not_configured",
            "message": "URLHAUS_AUTH_KEY is not configured.",
        }

    headers = {
        "Auth-Key": URLHAUS_AUTH_KEY,
    }

    try:
        response = requests.post(
            URLHAUS_URL_ENDPOINT,
            data={"url": value},
            headers=headers,
            timeout=TIMEOUT,
        )

        response.raise_for_status()
        data = response.json()

        query_status = data.get("query_status")

        if query_status == "no_results":
            return {
                "provider": "URLhaus",
                "status": "not_found",
                "message": "URL was not found in the URLhaus database.",
            }

        if query_status != "ok":
            return {
                "provider": "URLhaus",
                "status": "error",
                "message": f"URLhaus query status: {query_status}",
            }

        return {
            "provider": "URLhaus",
            "status": "listed",
            "threat": data.get("threat"),
            "url_status": data.get("url_status"),
            "tags": data.get("tags", []),
            "date_added": data.get("date_added"),
            "message": "URL is listed in URLhaus.",
        }

    except requests.Timeout:
        return {
            "provider": "URLhaus",
            "status": "error",
            "message": "The request timed out.",
        }

    except requests.RequestException as error:
        return {
            "provider": "URLhaus",
            "status": "error",
            "message": f"Request failed: {error}",
        }

    except (ValueError, TypeError, AttributeError):
        return {
            "provider": "URLhaus",
            "status": "error",
            "message": "The provider returned an invalid response.",
        }


def lookup_indicator(indicator_type, value):
    """
    Perform optional reputation lookups for a user-selected indicator.

    Only the explicitly supplied indicator is sent to external providers.
    """
    normalized = validate_indicator(indicator_type, value)

    results = {
        "indicator_type": indicator_type,
        "indicator": normalized,
        "providers": [],
    }

    results["providers"].append(
        lookup_virustotal(indicator_type, normalized)
    )

    if indicator_type == "url":
        results["providers"].append(
            lookup_urlhaus(normalized)
        )

    return results
