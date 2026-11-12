# 🛡️ CyberShield

### Context-Aware Phishing Investigation & Threat Intelligence Platform

CyberShield is a Python-based defensive cybersecurity platform designed to investigate suspicious emails, URLs, domains, and IP addresses.

It combines heuristic analysis, DNS intelligence, IOC extraction and correlation, external threat intelligence, and explainable risk scoring in an interactive Streamlit dashboard.

The platform helps security analysts investigate potentially malicious indicators, understand their relationships, assess associated risks, and generate structured incident reports.

---

## 🚀 Key Features

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
- Generate URL-specific risk assessments.

### 3. Domain Investigation
- Validate and normalize domain names.
- Perform DNS record lookups.
- Analyze A, AAAA, MX, NS, and TXT records.
- Identify potentially suspicious domain characteristics.
- Generate domain-specific risk assessments.

### 4. IP Address Investigation
- Support IPv4 and IPv6 addresses.
- Classify public, private, loopback, reserved, and link-local addresses.
- Validate and normalize IP addresses.
- Perform optional IP reputation checks.
- Integrate VirusTotal and AbuseIPDB.
- Analyze abuse confidence scores and report counts.
- Incorporate threat intelligence findings into risk assessment.

### 5. Threat Intelligence Integration
- **VirusTotal:** Retrieve existing threat intelligence reports for supported indicators.
- **URLhaus:** Check URLs against URLhaus intelligence.
- **AbuseIPDB:** Retrieve IP reputation and abuse-report information.
- Explicitly select indicators before performing external lookups.
- Support URLs, domains, IP addresses, and file hashes where supported by the provider.

### 6. IOC Extraction and Correlation
- Extract URLs, domains, IPv4 addresses, and file hashes.
- Identify relationships between extracted indicators.
- Build IOC relationship graphs using NetworkX.
- Visualize relationships using Plotly.

### 7. Risk Assessment
- Evidence-based heuristic scoring.
- Category-specific score limits.
- Threat intelligence-based scoring.
- Explainable findings and severity levels.
- Risk classification: Low, Medium, and High.

### 8. MITRE ATT&CK Mapping
- Map supported investigation evidence to relevant MITRE ATT&CK techniques.
- Display technique IDs, tactics, confidence, and supporting evidence.
- Avoid automatically assigning techniques without sufficient evidence.

### 9. Incident Reporting
- Generate JSON incident reports.
- Generate Markdown incident reports.
- Include investigation evidence and IOC information.
- Include risk assessments and potential MITRE ATT&CK mappings.

---

## 🛠️ Technology Stack

| Component | Technology |
|---|---|
| Programming Language | Python |
| Dashboard | Streamlit |
| Data Processing | Pandas |
| DNS Analysis | dnspython |
| Domain Parsing | tldextract |
| IOC Correlation | NetworkX |
| Visualization | Plotly |
| HTTP Requests | Requests |
| Fuzzy Matching | RapidFuzz |
| Environment Configuration | python-dotenv |
| IP Validation | Python ipaddress |
| Testing | Pytest |
| Version Control | Git and GitHub |

---

## 📁 Project Structure

```text
CyberShield/
│
├── app.py
├── requirements.txt
├── README.md
├── .env.example
├── .gitignore
│
├── modules/
│   ├── investigation.py
│   ├── email_analyzer.py
│   ├── header_analyzer.py
│   ├── brand_detector.py
│   ├── url_analyzer.py
│   ├── url_investigation.py
│   ├── domain_reputation.py
│   ├── domain_investigation.py
│   ├── ip_investigation.py
│   ├── ioc_extractor.py
│   ├── ioc_correlator.py
│   ├── threat_intelligence.py
│   ├── risk_scoring.py
│   ├── mitre_mapping.py
│   └── report_generator.py
│
├── data/
│   ├── sample_phishing.eml
│   └── sample_legitimate.eml
│
├── tests/
│   ├── test_threat_intelligence.py
│   ├── test_risk_scoring.py
│   ├── test_ip_investigation.py
│   └── ...
│
└── reports/
```

---

## ⚙️ Installation and Setup

### Prerequisites

- Python 3.10 or later
- Git
- Internet connection for DNS and optional external intelligence lookups

### 1. Clone the repository

```bash
git clone https://github.com/amarjeet-rout/CyberShield.git
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

### 4. Configure API credentials

Create your local environment file:

```bash
cp .env.example .env
```

Add your API credentials to `.env`:

```env
VT_API_KEY=your_virustotal_api_key
URLHAUS_AUTH_KEY=your_urlhaus_auth_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
```

API integrations are optional. Configure only the providers you intend to use.

**Security note:** Never commit `.env` or expose API credentials publicly. The `.env.example` file contains placeholders only.

### 5. Run CyberShield

```bash
python -m streamlit run app.py
```

Open the local address displayed in your terminal, usually:

```text
http://localhost:8501
```

---

## 🧪 Running Tests

Run the complete automated test suite:

```bash
python -m pytest -v
```

Alternatively:

```bash
python -m pytest -q
```

**Current test status: 118 tests passed.**

The test suite covers investigation logic, IP classification, threat intelligence integration, and risk scoring.

---

## 🔐 Security and Limitations

- CyberShield is intended for defensive security research and investigation.
- Heuristic findings are indicators for analyst review, not definitive proof of malicious activity.
- A low risk score does not guarantee that an indicator is safe.
- DNS records and domain characteristics provide context but cannot independently establish malicious intent.
- External intelligence lookups are optional and performed only for explicitly selected indicators.
- VirusTotal lookups retrieve existing intelligence reports; the platform does not submit new files or scans.
- Private and non-global IP addresses are not sent to external IP reputation providers.
- MITRE ATT&CK mappings represent potential techniques based on available evidence, not confirmed attacker behavior.
- Do not submit confidential or sensitive indicators to third-party services without authorization.

---

## 📊 Development Status

| Investigation Capability | Status |
|---|---|
| Email Investigation | Implemented |
| URL Investigation | Implemented |
| Domain Investigation | Implemented |
| IP Address Investigation | Implemented |
| VirusTotal Integration | Implemented |
| URLhaus Integration | Implemented |
| AbuseIPDB Integration | Implemented |
| IOC Extraction and Correlation | Implemented |
| Risk Assessment | Implemented |
| MITRE ATT&CK Mapping | Implemented |
| Incident Reporting | Implemented |

---

## 🔮 Future Enhancements

- Standalone file hash investigation.
- Investigation history and case management.
- Batch indicator analysis.
- Enhanced threat intelligence correlation.
- Advanced reporting and visualization.
- Improved investigation workflows.

---

## ⚠️ Disclaimer

CyberShield is an educational and defensive security research project. Its findings should be validated by a qualified security analyst before making operational security decisions.

---

**Developed as a cybersecurity portfolio project.**
