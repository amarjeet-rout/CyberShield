# 🛡️ CyberShield

### Context-Aware Phishing Investigation & Threat Intelligence Platform

CyberShield is a Python-based defensive security platform designed to investigate suspicious emails, URLs, and domains. It combines heuristic analysis, DNS intelligence, IOC extraction, threat intelligence lookups, and explainable risk scoring in a Streamlit dashboard.

The project is being developed as a cybersecurity portfolio project.

## Features

### 1. Email Investigation
- Parse raw emails and `.eml` files.
- Analyze email headers and authentication results.
- Identify suspicious sender and reply-to mismatches.
- Detect suspicious phrases, URLs, and attachments.
- Analyze SPF, DKIM, and DMARC results when present.

### 2. URL Investigation
- Analyze URL structure and suspicious patterns.
- Detect suspicious URL components and HTTP usage.
- Identify potential brand impersonation.
- Extract indicators of compromise.

### 3. Domain Investigation
- Validate and normalize domain names.
- Perform DNS record lookups.
- Analyze A, AAAA, MX, NS, and TXT records.
- Identify potentially suspicious domain characteristics.
- Generate domain-specific risk assessments.

### 4. Threat Intelligence
- Optional VirusTotal lookups.
- Optional URLhaus lookups.
- Explicit selection of indicators before external lookup.
- Support for URLs, domains, IP addresses, and file hashes.

### 5. IOC Extraction and Correlation
- Extract URLs, domains, IPv4 addresses, and file hashes.
- Build IOC relationship graphs using NetworkX.
- Visualize relationships using Plotly.

### 6. Risk Assessment
- Evidence-based heuristic scoring.
- Category-specific score limits.
- Explainable findings and severity levels.
- Risk classification: Low, Medium, and High.

### 7. Incident Reporting
- Generate JSON incident reports.
- Generate Markdown incident reports.
- Include investigation evidence and IOC information.
- Provide potential MITRE ATT&CK technique mappings where supported by evidence.

## Technology Stack

| Component | Technology |
|---|---|
| Programming language | Python |
| Dashboard | Streamlit |
| Data processing | Pandas |
| DNS analysis | dnspython |
| Domain parsing | tldextract |
| IOC correlation | NetworkX |
| Visualization | Plotly |
| HTTP requests | Requests |
| Fuzzy matching | RapidFuzz |
| Environment configuration | python-dotenv |
| Testing | Pytest |

## Project Structure

```text
CyberShield/
├── app.py
├── requirements.txt
├── README.md
├── .env.example
├── modules/
│   ├── email_analyzer.py
│   ├── header_analyzer.py
│   ├── brand_detector.py
│   ├── url_analyzer.py
│   ├── url_investigation.py
│   ├── domain_reputation.py
│   ├── domain_investigation.py
│   ├── ioc_extractor.py
│   ├── ioc_correlator.py
│   ├── threat_intelligence.py
│   ├── risk_scoring.py
│   ├── investigation.py
│   ├── mitre_mapping.py
│   └── report_generator.py
├── data/
│   ├── sample_phishing.eml
│   └── sample_legitimate.eml
├── tests/
└── reports/
```

## Installation

### Prerequisites
- Python 3.10 or later
- Git
- Internet connection for DNS and optional external intelligence lookups

### 1. Clone the repository

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd CyberShield
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

Activate it on Linux:

```bash
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure optional API credentials

Create a `.env` file using the example:

```bash
cp .env.example .env
```

Add your API credentials:

```env
VT_API_KEY=your_virustotal_api_key
URLHAUS_AUTH_KEY=your_urlhaus_auth_key
```

These integrations are optional. Never commit your `.env` file or expose API credentials publicly.

### 5. Run CyberShield

```bash
python -m streamlit run app.py
```

Open the local address displayed in your terminal, usually:

```text
http://localhost:8501
```

## Running Tests

Run the complete test suite:

```bash
python -m pytest -v
```

The current development version has **97 passing automated tests**.

## Security and Limitations

- CyberShield is intended for defensive security research and investigation.
- Heuristic findings are indicators for analyst review, not definitive proof of malicious activity.
- A low risk score does not guarantee that an indicator is safe.
- DNS records and domain characteristics provide context but cannot independently establish malicious intent.
- External intelligence lookups are optional and performed only for explicitly selected indicators.
- VirusTotal lookups retrieve existing intelligence reports; the platform does not submit new files or scans.
- MITRE ATT&CK mappings represent potential techniques based on available evidence, not confirmed attacker behavior.
- Do not submit confidential or sensitive indicators to third-party services without authorization.

## Current Development Status

| Investigation capability | Status |
|---|---|
| Email Investigation | Implemented |
| URL Investigation | Implemented |
| Domain Investigation | Implemented |
| IP Address Investigation | Planned |
| File Hash Investigation | Planned |

## Future Enhancements

- IP address investigation and reputation analysis.
- File hash investigation.
- Improved threat intelligence correlation.
- Investigation history and case management.
- Batch indicator analysis.
- Enhanced reporting and visualization.

## Disclaimer

CyberShield is an educational and defensive security research project. Its findings should be validated by a qualified security analyst before making operational security decisions.
