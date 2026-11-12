import base64
import ipaddress
import os

import requests
import streamlit as st
from dotenv import load_dotenv


load_dotenv()

def get_api_key(name):
    """Load an API key from environment variables or Streamlit secrets."""
    value = os.getenv(name)

    if value:
        return value

    try:
        return st.secrets.get(name)
    except Exception:
        return None


VT_API_KEY = get_api_key("VT_API_KEY")
URLHAUS_AUTH_KEY = get_api_key("URLHAUS_AUTH_KEY")

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
    Perform optional reputation lookups for a selected indicator.

    External lookups are performed only for explicitly
    selected indicators.
    """
    normalized = validate_indicator(indicator_type, value)

    results = {
        "indicator_type": indicator_type,
        "indicator": normalized,
        "providers": [],
    }

    # For IPs, never submit non-public addresses externally.
    if indicator_type == "ip":
        address = ipaddress.ip_address(normalized)

        if not address.is_global:
            results["providers"].extend([
                {
                    "provider": "VirusTotal",
                    "status": "skipped",
                    "message": "External lookup skipped for non-public IP.",
                },
                {
                    "provider": "AbuseIPDB",
                    "status": "skipped",
                    "message": "External lookup skipped for non-public IP.",
                },
            ])
            return results

    # Existing VirusTotal integration.
    results["providers"].append(
        lookup_virustotal(indicator_type, normalized)
    )

    # New AbuseIPDB integration for public IPs.
    if indicator_type == "ip":
        results["providers"].append(
            lookup_abuseipdb(normalized)
        )

    # Existing URLhaus integration.
    if indicator_type == "url":
        results["providers"].append(
            lookup_urlhaus(normalized)
        )

    return results
def lookup_abuseipdb(value):
    """Check a public IP address against AbuseIPDB."""

    api_key = get_api_key("ABUSEIPDB_API_KEY")

    if not api_key:
        return {
            "provider": "AbuseIPDB",
            "status": "not_configured",
            "message": "ABUSEIPDB_API_KEY is not configured.",
        }

    try:
        address = ipaddress.ip_address(value)

        if not address.is_global:
            return {
                "provider": "AbuseIPDB",
                "status": "skipped",
                "message": "External lookup skipped for non-public IP.",
            }

    except ValueError:
        return {
            "provider": "AbuseIPDB",
            "status": "error",
            "message": "Invalid IP address.",
        }

    headers = {
        "Key": api_key,
        "Accept": "application/json",
    }

    params = {
        "ipAddress": str(address),
        "maxAgeInDays": 90,
    }

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params=params,
            timeout=TIMEOUT,
        )

        response.raise_for_status()
        data = response.json().get("data", {})

        return {
            "provider": "AbuseIPDB",
            "status": "success",
            "ip_address": data.get("ipAddress"),
            "abuse_confidence_score": data.get(
                "abuseConfidenceScore", 0
            ),
            "total_reports": data.get("totalReports", 0),
            "distinct_users": data.get("numDistinctUsers", 0),
            "last_reported_at": data.get("lastReportedAt"),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "usage_type": data.get("usageType"),
            "is_tor": data.get("isTor", False),
            "is_whitelisted": data.get("isWhitelisted"),
        }

    except requests.Timeout:
        return {
            "provider": "AbuseIPDB",
            "status": "error",
            "message": "The request timed out.",
        }

    except requests.RequestException as error:
        return {
            "provider": "AbuseIPDB",
            "status": "error",
            "message": f"Request failed: {error}",
        }

    except (ValueError, TypeError, AttributeError):
        return {
            "provider": "AbuseIPDB",
            "status": "error",
            "message": "The provider returned an invalid response.",
        }
