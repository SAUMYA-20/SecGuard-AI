# SecGuard AI — Autonomous Security Auditing Platform (Developer Pro Edition)

SecGuard AI is a distributed, multi-vector security auditing platform designed for developers and DevSecOps teams. It evaluates web surfaces across transport-layer cryptography, HTTP security headers, and client-side AST structures, combining objective deterministic scoring with **Google Gemini 3.6** dynamic contextual reasoning.

---

## 🎯 How to Use the Platform

1. **Enter Target URL**: Type any domain or URL (e.g. `https://github.com`, `cloudflare.com`, or your application endpoint) or click a quick preset.
2. **Dispatch Audit**: Click **Dispatch Audit 🚀**. SecGuard immediately initiates asynchronous multi-vector telemetry probes.
3. **Inspect Real-Time Pipeline**: Watch the 6-stage telemetry probe execute across TLS handshakes, Cheerio DOM AST extraction, and scoring.
4. **Review Deterministic Score**: An objective 0-100 rubric detailing exact point deductions for verified vulnerabilities.
5. **Read Dynamic Gemini 3.6 AI Reasoning**: Plain-English executive summaries and tailored code snippets generated specifically for the detected flaws (HTML form fixes, script updates, or server directives).
6. **Track Drift & Export**: Visualize historical score drift across time and export high-resolution Executive Security Audit Reports in PDF format with visual charts and tables.

---

## ⚙️ How SecGuard Works (Under the Hood)

```
Target URL ──► Express API Gateway ──► Asynchronous BullMQ / Queue Broker
                                                    │
        ┌───────────────────────────────────────────┴───────────────────────────────────────────┐
        ▼                                           ▼                                           ▼
 [TLS 1.3 & Ciphers]                      [Cheerio DOM AST Parse]                    [HTTP Security Headers]
  - Protocol version                       - Inline script density                    - CSP Level 3
  - Cipher suites                          - Legacy jQuery CVEs                       - Strict-Transport-Security
  - Certificate validity                   - Cleartext form actions                   - X-Frame-Options (XFO)
        │                                           │                                           │
        └───────────────────────────────────────────┬───────────────────────────────────────────┘
                                                    ▼
                               [Deterministic 100-Point Scoring Engine]
                                                    ▼
                                [Google Gemini 3.6 Reasoning Layer]
                              (Plain-English + Tailored Fix Snippets)
                                                    ▼
                                  [MongoDB Atlas Time-Series Drift]
```

---

## 🛡️ Evaluated Security Vectors

- **Content-Security-Policy (CSP)**: Blocks Cross-Site Scripting (XSS) and data injection.
- **Strict-Transport-Security (HSTS)**: Enforces HTTPS and blocks Man-in-the-Middle (MITM) downgrade attacks.
- **X-Frame-Options (XFO)**: Blocks UI Redressing and Clickjacking attacks.
- **X-Content-Type-Options**: Enforces `nosniff` to stop MIME confusion exploits.
- **Referrer-Policy**: Controls sensitive referrer URL parameter leakage.
- **Permissions-Policy**: Restricts unauthorized hardware API access (camera, microphone, geolocation).
- **TLS 1.3 Ciphers**: Audits active cipher suites and Perfect Forward Secrecy (PFS).
- **DOM AST & Script Hazards**: Detects outdated libraries (e.g. jQuery 1.x/2.x CVEs) and cleartext HTTP form actions.

---

## 🚀 Execution & Quickstart

```bash
# 1. Install dependencies
npm install

# 2. Start platform
npm start
```
Open **[http://localhost:4000](http://localhost:4000)** in your browser.
