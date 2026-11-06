
import json

from modules.investigation import investigate_email
from modules.mitre_mapping import map_mitre_techniques
from modules.report_generator import (
    build_incident_report,
    report_to_markdown,
    export_report,
)


def load_sample(name):
    with open(f"data/{name}", encoding="utf-8") as file:
        return file.read()


def test_phishing_link_mitre_mapping():
    investigation = investigate_email(
        load_sample("sample_phishing.eml")
    )
    result = map_mitre_techniques(investigation)

    assert any(
        item["technique_id"] == "T1566.002"
        for item in result["mappings"]
    )


def test_legitimate_email_has_no_mitre_mapping():
    investigation = investigate_email(
        load_sample("sample_legitimate.eml")
    )
    result = map_mitre_techniques(investigation)

    assert result["technique_count"] == 0


def test_report_contains_risk_and_iocs():
    investigation = investigate_email(
        load_sample("sample_phishing.eml")
    )
    report = build_incident_report(investigation)

    assert 0 <= report["risk_assessment"]["score"] <= 100
    assert len(report["indicators_of_compromise"]["urls"]) > 0
    assert "mitre_attack" in report


def test_report_is_json_serializable():
    investigation = investigate_email(
        load_sample("sample_phishing.eml")
    )
    report = build_incident_report(investigation)

    encoded = json.dumps(report)
    assert "CyberShield" in encoded


def test_markdown_report():
    investigation = investigate_email(
        load_sample("sample_phishing.eml")
    )
    report = build_incident_report(investigation)

    markdown = report_to_markdown(report)

    assert "# CyberShield Incident Investigation Report" in markdown
    assert "## MITRE ATT&CK Mapping" in markdown
    assert "T1566.002" in markdown


def test_export_report(tmp_path):
    investigation = investigate_email(
        load_sample("sample_phishing.eml")
    )
    report = build_incident_report(investigation)

    paths = export_report(report, output_directory=tmp_path)

    with open(paths["json_path"], encoding="utf-8") as file:
        saved = json.load(file)

    assert saved["report_title"] == report["report_title"]

    with open(paths["markdown_path"], encoding="utf-8") as file:
        markdown = file.read()

    assert "Risk Breakdown" in markdown
