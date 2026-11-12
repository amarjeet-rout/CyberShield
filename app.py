
import json

import networkx as nx
import plotly.graph_objects as go
import streamlit as st

from modules.ip_investigation import investigate_ip
from modules.investigation import investigate_email
from modules.url_investigation import investigate_url
from modules.domain_investigation import investigate_domain
from modules.report_generator import (
    build_incident_report,
    report_to_markdown,
)


# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="CyberShield | Security Investigation",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ CyberShield")
st.caption(
    "Context-Aware Phishing Investigation & Threat Intelligence Platform"
)

st.markdown(
    """
    Investigate suspicious emails, URLs and domains, identify
    potentially malicious indicators, correlate indicators of
    compromise, and generate incident reports.
    """
)


# --------------------------------------------------
# SESSION STATE
# --------------------------------------------------

if "investigation" not in st.session_state:
    st.session_state.investigation = None

if "investigation_mode" not in st.session_state:
    st.session_state.investigation_mode = None

if "investigation_input" not in st.session_state:
    st.session_state.investigation_input = ""


# --------------------------------------------------
# INVESTIGATION MODE
# --------------------------------------------------

mode = st.radio(
    "Select investigation type",
    [
        "Email Investigation",
        "URL Investigation",
        "Domain Investigation",
	"IP Address Investigation",
    ],
    horizontal=True,
)

is_email = mode == "Email Investigation"
is_url = mode == "URL Investigation"
is_domain = mode == "Domain Investigation"
is_ip = mode == "IP Address Investigation"


# --------------------------------------------------
# EMAIL INPUT
# --------------------------------------------------

if is_email:

    st.header("1. Email Investigation")

    with st.form("email_investigation_form"):

        uploaded_file = st.file_uploader(
            "Upload an email file (.eml or .txt)",
            type=["eml", "txt"],
        )

        pasted_email = st.text_area(
            "Or paste the raw email content",
            height=250,
            placeholder="Paste the complete email, including its headers...",
        )

        analyze_button = st.form_submit_button(
            "Analyze Email",
            type="primary",
            use_container_width=True,
        )

    if analyze_button:

        try:
            if uploaded_file is not None:
                raw_email = uploaded_file.getvalue().decode(
                    "utf-8",
                    errors="replace",
                )
            else:
                raw_email = pasted_email

            if not raw_email.strip():
                st.error("Please upload an email or paste email content.")

            else:
                with st.spinner("Investigating email..."):

                    result = investigate_email(raw_email)

                    st.session_state.investigation = result
                    st.session_state.investigation_mode = mode
                    st.session_state.investigation_input = raw_email

                st.success("Email investigation completed.")

        except Exception as error:
            st.error(f"Investigation failed: {error}")


# --------------------------------------------------
# URL INPUT
# --------------------------------------------------

elif is_url:

    st.header("1. URL Investigation")

    with st.form("url_investigation_form"):

        submitted_url = st.text_input(
            "Enter the suspicious URL",
            placeholder="https://example.com/login",
        )

        analyze_url_button = st.form_submit_button(
            "Analyze URL",
            type="primary",
            use_container_width=True,
        )

    if analyze_url_button:

        try:
            if not submitted_url.strip():
                st.error("Please enter a URL.")

            else:
                with st.spinner("Investigating URL..."):

                    result = investigate_url(submitted_url)

                    st.session_state.investigation = result
                    st.session_state.investigation_mode = mode
                    st.session_state.investigation_input = submitted_url

                st.success("URL investigation completed.")

        except Exception as error:
            st.error(f"Investigation failed: {error}")


# --------------------------------------------------
# DOMAIN INPUT
# --------------------------------------------------

elif is_domain:

    st.header("1. Domain Investigation")

    st.markdown(
        """
        Investigate domain characteristics and DNS records.
        External threat intelligence is optional and requires
        explicitly selecting indicators.
        """
    )

    with st.form("domain_investigation_form"):

        submitted_domain = st.text_input(
            "Enter the domain name",
            placeholder="example.com",
        )

        analyze_domain_button = st.form_submit_button(
            "Analyze Domain",
            type="primary",
            use_container_width=True,
        )

    if analyze_domain_button:

        try:
            if not submitted_domain.strip():
                st.error("Please enter a domain.")

            else:
                with st.spinner("Investigating domain and DNS records..."):

                    result = investigate_domain(submitted_domain)

                    st.session_state.investigation = result
                    st.session_state.investigation_mode = mode
                    st.session_state.investigation_input = submitted_domain

                st.success("Domain investigation completed.")

        except Exception as error:
            st.error(f"Investigation failed: {error}")
# --------------------------------------------------
# IP ADDRESS INPUT
# --------------------------------------------------

elif is_ip:

    st.header("1. IP Address Investigation")

    st.markdown(
        """
        Investigate IPv4 and IPv6 addresses, identify their
        network classification, and optionally check public IP
        reputation using threat intelligence providers.
        """
    )

    with st.form("ip_investigation_form"):

        submitted_ip = st.text_input(
            "Enter the IP address",
            placeholder="8.8.8.8",
        )

        analyze_ip_button = st.form_submit_button(
            "Analyze IP Address",
            type="primary",
            use_container_width=True,
        )

    if analyze_ip_button:

        try:
            if not submitted_ip.strip():
                st.error("Please enter an IP address.")

            else:
                with st.spinner("Investigating IP address..."):

                    result = investigate_ip(submitted_ip)

                    st.session_state.investigation = result
                    st.session_state.investigation_mode = mode
                    st.session_state.investigation_input = submitted_ip

                st.success("IP address investigation completed.")

        except Exception as error:
            st.error(f"Investigation failed: {error}")

# --------------------------------------------------
# DISPLAY INVESTIGATION RESULTS
# --------------------------------------------------

investigation = st.session_state.investigation

if (
    investigation is not None
    and st.session_state.investigation_mode == mode
):

    risk = investigation["risk_assessment"]
    iocs = investigation["ioc_extraction"]
    correlation = investigation["ioc_correlation"]

    ioc_keys = [
        "urls",
        "domains",
        "ip_addresses",
        "hashes",
    ]

    total_iocs = sum(
        len(iocs.get(key, []))
        for key in ioc_keys
    )

    # --------------------------------------------------
    # RISK SUMMARY
    # --------------------------------------------------

    st.divider()
    st.header("2. Investigation Results")

    score = risk["risk_score"]
    level = risk["risk_level"]

    col1, col2, col3 = st.columns(3)

    col1.metric("Risk Score", f"{score}/100")
    col2.metric("Risk Level", level)
    col3.metric("Total IOC Count", total_iocs)

    if level == "High":
        st.error(
            "High risk: Significant suspicious indicators detected."
        )

    elif level == "Medium":
        st.warning(
            "Medium risk: Suspicious indicators require review."
        )

    else:
        st.success(
            "Low risk: Few or no suspicious indicators detected."
        )

    st.progress(score / 100)

    st.info(risk.get("explanation", ""))
    # --------------------------------------------------
    # RISK BREAKDOWN
    # --------------------------------------------------

    st.subheader("Risk Breakdown")

    category_names = {
        "email_content": "Email Content",
        "email_headers": "Email Headers",
        "url_structure": "URL Structure",
        "brand_impersonation": "Brand Impersonation",
        "domain_analysis": "Domain Analysis",
        "ip_analysis": "IP Analysis",
        "threat_intelligence": "Threat Intelligence",
    }

    if is_email:

        visible_categories = [
            "email_content",
            "email_headers",
            "url_structure",
            "brand_impersonation",
            "threat_intelligence",
        ]

    elif is_url:

        visible_categories = [
            "url_structure",
            "brand_impersonation",
            "threat_intelligence",
        ]

    elif is_domain:

        visible_categories = [
            "domain_analysis",
            "threat_intelligence",
        ]

    else:

        visible_categories = [
            "ip_analysis",
            "threat_intelligence",
        ]

    for category in visible_categories:

        details = risk.get("categories", {}).get(category)

        if details is None:
            continue

        display_name = category_names[category]

        st.markdown(
            f"**{display_name}: "
            f"{details['score']}/{details['cap']}**"
        )

        st.progress(
            details["score"] / details["cap"]
            if details["cap"] else 0
        )

        evidence = details.get("evidence", [])

        with st.expander(
            f"View {display_name} evidence ({len(evidence)} findings)"
        ):

            if not evidence:
                st.write("No findings in this category.")

            for finding in evidence:

                if not isinstance(finding, dict):
                    st.write(finding)
                    continue

                st.markdown(
                    f"**{finding.get('type', finding.get('provider', 'Finding'))}**"
                )

                st.write(
                    "Severity:",
                    finding.get("severity", "Unspecified"),
                )

                evidence_text = finding.get("evidence", "")

                if isinstance(evidence_text, list):

                    for item in evidence_text:
                        st.write(f"- {item}")

                elif evidence_text:
                    st.write(evidence_text)

                if "score" in finding:
                    st.caption(
                        f"Finding score: {finding['score']}"
                    )

    # --------------------------------------------------
    # EMAIL-SPECIFIC ANALYSIS
    # --------------------------------------------------

    if is_email:

        st.divider()
        st.header("3. Email and Header Analysis")

        with st.expander("Email analysis details"):
            st.json(investigation.get("email_analysis", {}))

        with st.expander("Email authentication and header analysis"):
            st.json(investigation.get("header_analysis", {}))

    # --------------------------------------------------
    # URL ANALYSIS
    # --------------------------------------------------

    elif is_url:

        st.divider()
        st.header("3. URL Structure Analysis")

        url_result = investigation.get("url_analysis", {})

        with st.expander("URL analysis details", expanded=True):
            st.json(url_result)

        st.write("**Investigated URL:**")
        st.code(investigation.get("input", ""), language=None)

    # --------------------------------------------------
    # DOMAIN ANALYSIS
    # --------------------------------------------------

    elif is_domain:

        st.divider()
        st.header("3. Domain and DNS Analysis")

        domain_result = investigation.get("domain_analysis", {})

        st.write("**Investigated domain:**")
        st.code(investigation.get("input", ""), language=None)

        dns_records = domain_result.get("dns_records", {})
        dns_errors = domain_result.get("dns_errors", {})

        st.subheader("DNS Records")

        record_columns = st.columns(5)

        for column, record_type in zip(
            record_columns,
            ["A", "AAAA", "MX", "NS", "TXT"],
        ):
            column.metric(
                f"{record_type} Records",
                len(dns_records.get(record_type, [])),
            )

        for record_type in ["A", "AAAA", "MX", "NS", "TXT"]:

            records = dns_records.get(record_type, [])

            with st.expander(
                f"{record_type} Records ({len(records)})"
            ):

                if records:
                    for record in records:
                        st.code(record, language=None)

                elif record_type in dns_errors:
                    st.warning(dns_errors[record_type])

                else:
                    st.write("No records returned.")

        if dns_errors:
            with st.expander("DNS Lookup Errors"):
                st.json(dns_errors)

        st.subheader("Domain Analysis Findings")

        domain_findings = domain_result.get("findings", [])

        if domain_findings:

            for finding in domain_findings:

                st.markdown(
                    f"**{finding.get('type', 'Finding')}**"
                )

                st.write(
                    "Severity:",
                    finding.get("severity", "Unspecified"),
                )

                st.write(finding.get("evidence", ""))
                st.divider()

        else:
            st.success("No domain-characteristic findings detected.")

        with st.expander("Domain analysis summary"):
            st.json(domain_result.get("analysis_summary", {}))

        st.caption(
            "DNS records and domain characteristics are contextual "
            "evidence. Their absence or presence alone does not prove "
            "that a domain is malicious."
        )

    # --------------------------------------------------
    # IP ADDRESS ANALYSIS
    # --------------------------------------------------

    else:

        st.divider()
        st.header("3. IP Address Analysis")

        ip_result = investigation.get("ip_analysis", {})

        st.write("**Investigated IP address:**")
        st.code(investigation.get("input", ""), language=None)

        st.subheader("IP Address Properties")

        col1, col2, col3 = st.columns(3)

        col1.metric(
            "IP Version",
            f"IPv{ip_result.get('version', 'Unknown')}",
        )

        col2.metric(
            "Classification",
            ip_result.get("classification", "Unknown"),
        )

        col3.metric(
            "Global Address",
            "Yes" if ip_result.get("is_global") else "No",
        )

        property_columns = st.columns(3)

        properties = [
            ("Private", "is_private"),
            ("Loopback", "is_loopback"),
            ("Reserved", "is_reserved"),
            ("Link-local", "is_link_local"),
        ]

        for index, (label, key) in enumerate(properties):
            property_columns[index % 3].write(
                f"**{label}:** "
                f"{'Yes' if ip_result.get(key) else 'No'}"
            )

        with st.expander("Complete IP analysis details"):
            st.json(ip_result)

        st.caption(
            "IP classification describes network address properties. "
            "A public IP address is not necessarily malicious, and "
            "a private IP address is not externally reputation-checked."
        )

    # --------------------------------------------------
    # IOC EXTRACTION
    # --------------------------------------------------

    st.divider()
    st.header("4. Indicators of Compromise (IOCs)")

    ioc_columns = st.columns(4)

    ioc_types = [
        ("URLs", "urls"),
        ("Domains", "domains"),
        ("IP Addresses", "ip_addresses"),
        ("Hashes", "hashes"),
    ]

    for column, (label, key) in zip(ioc_columns, ioc_types):

        values = iocs.get(key, [])
        column.metric(label, len(values))

    for label, key in ioc_types:

        values = iocs.get(key, [])

        with st.expander(f"{label} ({len(values)})"):

            if values:

                for value in values:
                    st.code(value, language=None)

            else:
                st.write(f"No {label.lower()} extracted.")

    # --------------------------------------------------
    # BRAND IMPERSONATION
    # --------------------------------------------------

    if not is_domain:

        st.divider()
        st.header("5. Brand Impersonation Analysis")

        brand_results = investigation.get("brand_analysis", [])

        if brand_results:

            for index, result in enumerate(brand_results, start=1):

                with st.expander(f"Brand analysis {index}"):
                    st.json(result)

        else:
            st.info("No brand analysis results are available.")

    # --------------------------------------------------
    # IOC CORRELATION GRAPH
    # --------------------------------------------------

    st.divider()
    st.header("6. IOC Correlation Graph")

    st.write(
        f"**Nodes:** {correlation['node_count']}  |  "
        f"**Edges:** {correlation['edge_count']}  |  "
        f"**Connected components:** "
        f"{correlation['connected_components']}"
    )

    graph = correlation["graph"]

    if graph.number_of_nodes() > 0:

        positions = nx.spring_layout(
            graph,
            seed=42,
            k=1.2,
        )

        edge_x = []
        edge_y = []

        for source, target in graph.edges():

            x0, y0 = positions[source]
            x1, y1 = positions[target]

            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])

        edge_trace = go.Scatter(
            x=edge_x,
            y=edge_y,
            mode="lines",
            hoverinfo="none",
            line=dict(width=1.5),
        )

        node_x = []
        node_y = []
        node_text = []
        node_colors = []

        color_map = {
            "URL": "#e74c3c",
            "Domain": "#3498db",
            "IP Address": "#2ecc71",
            "File Hash": "#9b59b6",
        }

        for node, attributes in graph.nodes(data=True):

            x, y = positions[node]

            node_x.append(x)
            node_y.append(y)

            node_type = attributes.get("type", "Unknown")
            node_value = attributes.get("value", node)

            node_text.append(
                f"{node_type}: {node_value}"
            )

            node_colors.append(
                color_map.get(node_type, "#95a5a6")
            )

        node_trace = go.Scatter(
            x=node_x,
            y=node_y,
            mode="markers+text",
            text=[
                graph.nodes[node].get("type", "IOC")
                for node in graph.nodes()
            ],
            textposition="bottom center",
            hovertext=node_text,
            hoverinfo="text",
            marker=dict(
                size=18,
                color=node_colors,
                line=dict(width=1, color="white"),
            ),
        )

        figure = go.Figure(
            data=[edge_trace, node_trace]
        )

        figure.update_layout(
            showlegend=False,
            height=500,
            margin=dict(l=10, r=10, t=20, b=20),
            xaxis=dict(visible=False),
            yaxis=dict(visible=False),
            hovermode="closest",
        )

        st.plotly_chart(
            figure,
            use_container_width=True,
        )

        with st.expander("View relationship details"):

            if correlation["edges"]:
                st.json(correlation["edges"])

            else:
                st.write("No direct relationships identified.")

    else:
        st.info("No IOCs available to visualize.")

    # --------------------------------------------------
    # MITRE ATT&CK MAPPING
    # --------------------------------------------------

    st.divider()
    st.header("7. MITRE ATT&CK Mapping")

    report = build_incident_report(investigation)
    mitre = report["mitre_attack"]
    mappings = mitre.get("mappings", [])

    if mappings:

        for mapping in mappings:

            with st.expander(
                f"{mapping['technique_id']} - {mapping['name']}"
            ):

                st.write("**Tactic:**", mapping["tactic"])
                st.write("**Confidence:**", mapping["confidence"])
                st.write("**Status:**", mapping["status"])

                st.write("**Evidence:**")

                for evidence in mapping.get("evidence", []):
                    st.write(f"- {evidence}")

                st.write("**Limitation:**", mapping["limitation"])

                st.markdown(
                    f"[MITRE ATT&CK Reference]({mapping['url']})"
                )

    else:

        st.info(
            "No ATT&CK techniques were mapped from the available "
            "evidence. Domain and standalone URL findings do not "
            "automatically establish a specific ATT&CK technique."
        )

    st.caption(
        "ATT&CK mappings are potential techniques based on available "
        "evidence, not confirmation of an attack."
    )


    # --------------------------------------------------
    # OPTIONAL THREAT INTELLIGENCE
    # --------------------------------------------------

    st.divider()
    st.header("8. External Threat Intelligence")

    st.warning(
        "External lookups send selected indicators to third-party "
        "services. Do not submit sensitive or confidential indicators "
        "without authorization. No external lookup is performed "
        "automatically."
    )

    available_iocs = []

    for key, indicator_type in [
        ("urls", "url"),
        ("domains", "domain"),
        ("ip_addresses", "ip"),
        ("hashes", "hash"),
    ]:

        for value in iocs.get(key, []):

            available_iocs.append(
                (
                    f"{indicator_type.upper()} | {value}",
                    {
                        "type": indicator_type,
                        "value": value,
                    },
                )
            )

    if available_iocs:

        selected_labels = st.multiselect(
            "Select indicators for external lookup",
            options=[item[0] for item in available_iocs],
            key=f"lookup_selection_{mode}",
        )

        if st.button("Run Selected Threat Intelligence Lookups"):

            selected_lookups = [
                item[1]
                for item in available_iocs
                if item[0] in selected_labels
            ]

            if not selected_lookups:
                st.warning("Select at least one indicator.")

            else:

                try:

                    with st.spinner(
                        "Contacting threat intelligence providers..."
                    ):

                        if is_email:

                            updated_investigation = investigate_email(
                                st.session_state.investigation_input,
                                selected_lookups=selected_lookups,
                            )

                        elif is_url:

                            updated_investigation = investigate_url(
                                st.session_state.investigation_input,
                                selected_lookups=selected_lookups,
                            )

                        elif is_domain:

                            updated_investigation = investigate_domain(
                                st.session_state.investigation_input,
                                selected_lookups=selected_lookups,
                            )

                        else:

                            updated_investigation = investigate_ip(
                                st.session_state.investigation_input,
                                selected_lookups=selected_lookups,
                            )

                        st.session_state.investigation = (
                            updated_investigation
                        )

                    st.success(
                        "Threat intelligence lookup completed."
                    )

                    st.rerun()

                except Exception as error:
                    st.error(f"Lookup failed: {error}")

    else:
        st.info("No indicators are available for external lookup.")

    # --------------------------------------------------
    # DISPLAY THREAT INTELLIGENCE RESULTS
    # --------------------------------------------------

    providers = investigation.get("threat_intelligence", [])

    if providers:

        with st.expander("External lookup results", expanded=True):

            for provider in providers:

                provider_name = provider.get(
                    "provider",
                    "Unknown Provider",
                )

                status = provider.get("status", "unknown")

                st.markdown(f"### {provider_name}")

                st.write("**Status:**", status)

                if provider_name == "AbuseIPDB" and status == "success":

                    col1, col2, col3 = st.columns(3)

                    col1.metric(
                        "Abuse Confidence",
                        f"{provider.get('abuse_confidence_score', 0)}%",
                    )

                    col2.metric(
                        "Total Reports",
                        provider.get("total_reports", 0),
                    )

                    col3.metric(
                        "Distinct Reporters",
                        provider.get("distinct_users", 0),
                    )

                    st.write(
                        "**Country:**",
                        provider.get("country_code") or "Unknown",
                    )

                    st.write(
                        "**ISP:**",
                        provider.get("isp") or "Unknown",
                    )

                    st.write(
                        "**Domain:**",
                        provider.get("domain") or "Unknown",
                    )

                    st.write(
                        "**Usage Type:**",
                        provider.get("usage_type") or "Unknown",
                    )

                    st.write(
                        "**Last Reported:**",
                        provider.get("last_reported_at") or "Unknown",
                    )

                    st.write(
                        "**Tor Exit Node:**",
                        "Yes" if provider.get("is_tor") else "No",
                    )

                    st.write(
                        "**Whitelisted:**",
                        "Yes" if provider.get("is_whitelisted") else "No",
                    )

                else:

                    st.json(provider)

                st.divider()

    # --------------------------------------------------
    # INCIDENT REPORT DOWNLOADS
    # --------------------------------------------------

    st.divider()
    st.header("9. Download Incident Report")

    report = build_incident_report(investigation)

    json_report = json.dumps(
        report,
        indent=2,
        ensure_ascii=False,
    )

    markdown_report = report_to_markdown(report)

    download_col1, download_col2 = st.columns(2)

    with download_col1:

        st.download_button(
            label="Download JSON Report",
            data=json_report,
            file_name="cybershield_incident_report.json",
            mime="application/json",
            use_container_width=True,
        )

    with download_col2:

        st.download_button(
            label="Download Markdown Report",
            data=markdown_report,
            file_name="cybershield_incident_report.md",
            mime="text/markdown",
            use_container_width=True,
        )

    # --------------------------------------------------
    # LIMITATIONS
    # --------------------------------------------------

    st.divider()
    st.subheader("Investigation Limitations")

    for limitation in report["limitations"]:
        st.write(f"- {limitation}")

elif investigation is None:

    st.info(
        "Select an investigation type, provide the required input, "
        "and start the investigation."
    )

else:

    st.info(
        f"A previous {st.session_state.investigation_mode} result is stored. "
        "Run an investigation in the currently selected mode to view its results."
    )


# --------------------------------------------------
# FOOTER
# --------------------------------------------------

st.divider()

st.caption(
    "CyberShield | Defensive Security Research Project | "
    "Heuristic analysis requires human verification."
)
