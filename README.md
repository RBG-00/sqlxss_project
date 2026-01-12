# SQLi & XSS Vulnerability Scanner

A **Python-based modular web vulnerability scanner** designed to detect, verify, and classify  
**SQL Injection (SQLi)** and **Cross-Site Scripting (XSS)** vulnerabilities.

The scanner emphasizes **verification and response consistency analysis** in order to reduce false positives and produce reliable, high-confidence findings.  
This project is intended for **educational, academic, and authorized testing environments only**.

---

## Project Overview

Web applications are frequently exposed to security vulnerabilities due to improper input validation and insecure coding practices.  
Among the most critical vulnerabilities are **SQL Injection (SQLi)** and **Cross-Site Scripting (XSS)**, both ranked in the **OWASP Top 10**.

This project presents a structured and extensible vulnerability scanner that focuses not only on detection, but also on **automatic verification mechanisms**.  
By analyzing response stability, similarity, timing behavior, and execution context, the scanner reduces false positives commonly found in traditional scanners.

---

## Key Features

### SQL Injection (SQLi)
- Error-based SQL Injection detection with DBMS fingerprinting
- Boolean-based Blind SQL Injection detection
- Time-based SQL Injection with statistical verification
- UNION-based SQL Injection detection and metadata extraction
- Response stability and consistency verification

### Cross-Site Scripting (XSS)
- Context-aware reflected XSS detection (HTML / Attribute / JavaScript / URL)
- Advanced reflected XSS with decode-aware verification
- DOM-based XSS detection using static source-to-sink analysis
- Stored XSS detection using marker-based persistence checks
- Content Security Policy (CSP) and security header analysis

### Reporting
- Structured JSON vulnerability report
- Human-readable text summary
- Detailed HTML reports (full report + SQLi/XSS specific reports)

---

## Repository Structure

sqlxss-scanner/
├── scanner.py # Main scanner orchestrator
├── sqli_part.py # SQL Injection detection and verification engine
├── xss_part.py # XSS detection and analysis engine
├── requirements.txt # Python dependencies
├── tests/ # Testing and validation modules
├── reports/ # Generated reports (optional)
├── report.json
├── report.txt
├── full_report.html
└── .gitignore

yaml
Copy code

> Note: Report files are generated outputs and are included only as examples of scanner results.

---

## System Architecture

The scanner follows a **modular architecture** with clear separation of responsibilities:

- **scanner.py**  
  Acts as the central controller responsible for request handling, crawling, invoking detection phases, aggregating findings, and generating reports.

- **sqli_part.py**  
  Contains all SQL Injection detection logic, DBMS fingerprinting, verification engines, and SQLi-specific reporting helpers.

- **xss_part.py**  
  Implements XSS detection logic including context-aware payload selection, DOM analysis, stored XSS workflows, CSP analysis, and verification helpers.

This architecture allows independent development and testing of SQLi and XSS components.

---

## Installation

```bash
pip install -r requirements.txt
Usage Example
Scan a target web application:

bash
Copy code
python3 scanner.py -u http://127.0.0.1:3000
Scan a specific endpoint:

bash
Copy code
python3 scanner.py -u "http://127.0.0.1:3000/rest/products/search?q=test"
Verification Strategy
Unlike basic scanners, this project applies multiple verification techniques, including:

Response length and similarity comparison

Multi-sample consistency checks

Median-based timing analysis for time-based SQLi

Token-based reflection verification for XSS

Decode-aware payload inspection

These mechanisms significantly reduce false positives and increase confidence in reported vulnerabilities.

Recommended Testing Environment
This scanner must be used only in controlled and authorized environments, such as:

Local Docker-based vulnerable applications

Educational security laboratories

Self-hosted test servers

Example using OWASP Juice Shop:

bash
Copy code
docker run --rm -p 3000:3000 bkimminich/juice-shop
Limitations
DOM XSS detection is static and does not execute JavaScript

Stored XSS detection depends on discoverable forms and view pages

Advanced WAF bypass techniques are intentionally excluded

Future Improvements
Headless browser integration for DOM XSS confirmation

Enhanced crawling and form discovery

Advanced SQL Injection bypass techniques

Unified vulnerability report dashboard

Legal Disclaimer
⚠️ Important Notice

This project is developed for educational and authorized security testing purposes only.
Scanning systems without explicit permission is strictly prohibited.

The author is not responsible for any misuse of this tool.

Author
Mohammad Samada
Cybersecurity Student | Web Application Security
SQL Injection & XSS Detection and Verification

markdown
Copy code
