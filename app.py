import whois
import tldextract
import requests
import re
import socket
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)


# --- HELPER: Analyze Security Headers ---
def analyze_security_headers(url, checks_dict, check_clickjacking=True):
    header_score_penalty = 0
    # Use a browser-like User-Agent to avoid blocks
    headers_request = {"User-Agent": "Mozilla/5.0"}
    try:
        # Fetch only headers for speed
        response = requests.head(
            url, headers=headers_request, allow_redirects=True, timeout=5
        )
        headers = response.headers

        # 1. HSTS Check
        if "Strict-Transport-Security" not in headers:
            header_score_penalty += 15
            checks_dict["hsts"] = {"name": "HSTS Policy", "status": "fail", "message": "MISSING HSTS", "penalty": 15}
        else:
            checks_dict["hsts"] = {"name": "HSTS Policy", "status": "pass", "message": "HSTS CONFIGURED", "penalty": 0}

        # 2. CSP Check (Standard + Report-Only)
        csp_exists = (
            "Content-Security-Policy" in headers
            or "Content-Security-Policy-Report-Only" in headers
        )
        if not csp_exists:
            header_score_penalty += 15
            checks_dict["csp"] = {"name": "Content Security Policy", "status": "fail", "message": "MISSING CSP", "penalty": 15}
        else:
            checks_dict["csp"] = {"name": "Content Security Policy", "status": "pass", "message": "CSP CONFIGURED", "penalty": 0}

        # 3. X-Frame-Options (Clickjacking Protection)
        if not check_clickjacking:
            checks_dict["xframe"] = {"name": "Clickjacking Protection", "status": "warning", "message": "CHECK DISABLED", "penalty": 0}
        else:
            if (
                "X-Frame-Options" not in headers
                and "frame-ancestors"
                not in headers.get("Content-Security-Policy", "").lower()
            ):
                header_score_penalty += 10
                checks_dict["xframe"] = {"name": "Clickjacking Protection", "status": "fail", "message": "MISSING X-FRAME-OPTIONS", "penalty": 10}
            else:
                checks_dict["xframe"] = {"name": "Clickjacking Protection", "status": "pass", "message": "X-FRAME-OPTIONS SECURE", "penalty": 0}

        return header_score_penalty
    except Exception:
        checks_dict["hsts"] = {"name": "HSTS Policy", "status": "warning", "message": "COULD NOT FETCH", "penalty": 0}
        checks_dict["csp"] = {"name": "Content Security Policy", "status": "warning", "message": "COULD NOT FETCH", "penalty": 0}
        checks_dict["xframe"] = {"name": "Clickjacking Protection", "status": "warning", "message": "COULD NOT FETCH", "penalty": 0}
        return 0


# --- HELPER: Analyze HTML DOM for Phishing Indicators ---
def analyze_html_content(url, checks_dict):
    html_penalty_score = 0
    headers_request = {"User-Agent": "Mozilla/5.0"}
    content_issues = []
    try:
        response = requests.get(url, headers=headers_request, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # 1. Hidden inputs often used to steal credentials
        hidden_inputs = soup.find_all('input', type='hidden')
        if len(hidden_inputs) > 5:
            html_penalty_score += 15
            content_issues.append("EXCESSIVE HIDDEN INPUTS")
            
        # 2. Page has password field but no HTTPS 
        password_fields = soup.find_all('input', type='password')
        if password_fields and not url.startswith("https://"):
            html_penalty_score += 30
            content_issues.append("INSECURE PASSWORD FIELD")
            
        # 3. Forms that submit to completely different domains
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action', '')
            if action.startswith('http'):
                form_domain = urlparse(action).netloc
                page_domain = urlparse(url).netloc
                if form_domain != page_domain and form_domain:
                    html_penalty_score += 25
                    content_issues.append("EXTERNAL FORM")
                    break # Penalize once for external form
                    
        # 4. Empty or Suspicious Title
        title = soup.title
        if not title or not title.string or title.string.strip() == "":
            html_penalty_score += 10
            content_issues.append("MISSING TITLE")
            
        if content_issues:
            checks_dict["content"] = {"name": "Page DOM Content", "status": "fail", "message": ", ".join(content_issues), "penalty": html_penalty_score}
        else:
            checks_dict["content"] = {"name": "Page DOM Content", "status": "pass", "message": "CLEAN DOM CONTENT", "penalty": 0}

        return html_penalty_score
    except Exception:
        # Fails securely; if page unreadable, might just be bot protection or dead
        checks_dict["content"] = {"name": "Page DOM Content", "status": "warning", "message": "UNABLE TO READ DOM", "penalty": 0}
        return 0


def get_domain_age(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if not creation_date:
            return 0
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(creation_date, datetime):
            return (datetime.now() - creation_date).days
        return 0
    except Exception:
        return 0


@app.route("/analyze", methods=["POST"])
def analyze_url():
    try:
        data = request.get_json()
        if not data or "url" not in data:
            return jsonify({"error": "No URL provided"}), 400

        url = data.get("url", "").lower().strip()
        
        heuristics = data.get("heuristics", {})
        check_clickjacking = heuristics.get("clickjacking", True)
        check_domain_age = heuristics.get("domainAge", True)
        
        # Ensure URL has a scheme for requests to work
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "https://" + url

        # --- 1. WHITELIST ---
        whitelist = [
            "google.com",
            "wikipedia.org",
            "github.com",
            "amazon.com",
            "microsoft.com",
            "apple.com",
            "youtube.com",
        ]
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}"

        if domain in whitelist:
            checks = [
                {"name": "SSL Certificate", "status": "pass", "message": "SSL CERTIFIED (HTTPS)", "penalty": 0},
                {"name": "DNS Resolution", "status": "pass", "message": "DOMAIN REACHABLE", "penalty": 0},
                {"name": "Domain Age", "status": "pass", "message": "ESTABLISHED TRUSTED DOMAIN", "penalty": 0},
                {"name": "URL Structure", "status": "pass", "message": "CLEAN URL FORMAT", "penalty": 0},
                {"name": "HSTS Policy", "status": "pass", "message": "HSTS CONFIGURED", "penalty": 0},
                {"name": "Content Security Policy", "status": "pass", "message": "CSP CONFIGURED", "penalty": 0},
                {"name": "Clickjacking Protection", "status": "pass", "message": "X-FRAME-OPTIONS SECURE", "penalty": 0},
                {"name": "Page DOM Content", "status": "pass", "message": "CLEAN DOM CONTENT", "penalty": 0}
            ]
            return jsonify({
                "status": "success",
                "risk_score": 0,
                "reasons": [],
                "checks": checks,
                "domain": domain,
            })

        # --- 2. SCORING LOGIC ---
        score = 0
        checks_dict = {}

        # SSL Check
        if url.startswith("http://"):
            score += 30
            checks_dict["ssl"] = {"name": "SSL Certificate", "status": "fail", "message": "SSL NOT CERTIFIED (HTTP)", "penalty": 30}
        else:
            checks_dict["ssl"] = {"name": "SSL Certificate", "status": "pass", "message": "SSL CERTIFIED (HTTPS)", "penalty": 0}

        # Keywords Check  
        keywords = ["login", "verify", "secure", "bank", "update", "account", "signin"]
        url_issues = []
        url_penalty = 0
        
        if any(key in url for key in keywords):
            score += 20
            url_penalty += 20
            url_issues.append("SUSPICIOUS KEYWORDS")

        # URL Structure
        if "@" in url or url.count(".") > 3:
            score += 20
            url_penalty += 20
            url_issues.append("COMPLEX FORMAT")
            
        if len(url) > 75:
            score += 15
            url_penalty += 15
            url_issues.append("TOO LONG")

        # Check for raw IP address in URL
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
            score += 40
            url_penalty += 40
            url_issues.append("IP BASED DOMAIN")

        # Further URL Parsing Checks
        try:
            parsed = urlparse(url)
            if parsed.port and parsed.port not in (80, 443):
                score += 15
                url_penalty += 15
                url_issues.append("NON-STANDARD PORT")
        except Exception:
            pass
            
        if url_issues:
            checks_dict["url_format"] = {"name": "URL Structure", "status": "fail", "message": ", ".join(url_issues), "penalty": url_penalty}
        else:
            checks_dict["url_format"] = {"name": "URL Structure", "status": "pass", "message": "CLEAN URL FORMAT", "penalty": 0}

        # DNS Resolution (Liveness)
        try:
            socket.gethostbyname(domain)
            checks_dict["dns"] = {"name": "DNS Resolution", "status": "pass", "message": "DOMAIN REACHABLE", "penalty": 0}
        except socket.gaierror:
            score += 25
            checks_dict["dns"] = {"name": "DNS Resolution", "status": "fail", "message": "RESOLUTION FAILED", "penalty": 25}

        # Domain Age
        if not check_domain_age:
            checks_dict["domain_age"] = {"name": "Domain Age", "status": "warning", "message": "CHECK DISABLED", "penalty": 0}
        else:
            age = get_domain_age(domain)
            if 0 < age < 365:
                score += 40
                checks_dict["domain_age"] = {"name": "Domain Age", "status": "fail", "message": f"LESS THAN 1 YEAR ({age} DAYS)", "penalty": 40}
            elif age == 0:
                score += 40
                checks_dict["domain_age"] = {"name": "Domain Age", "status": "warning", "message": "AGE UNKNOWN", "penalty": 40}
            else:
                checks_dict["domain_age"] = {"name": "Domain Age", "status": "pass", "message": f"ESTABLISHED ({age} DAYS)", "penalty": 0}

        # --- 3. HEADERS LOGIC ---
        score += analyze_security_headers(url, checks_dict, check_clickjacking)

        # --- 4. HTML DOM LOGIC ---
        score += analyze_html_content(url, checks_dict)
        
        # Build strict ordered list
        checks_list = [
            checks_dict.get("ssl"),
            checks_dict.get("dns"),
            checks_dict.get("domain_age"),
            checks_dict.get("url_format"),
            checks_dict.get("hsts"),
            checks_dict.get("csp"),
            checks_dict.get("xframe"),
            checks_dict.get("content")
        ]
        checks_list = [c for c in checks_list if c]

        # FINAL CALCULATION
        final_score = min(score, 100)
        if final_score == 0:
            final_score = 1

        print(f"--- SCAN: {url} | Score: {final_score}% ---")

        return jsonify({
            "status": "success",
            "risk_score": final_score,
            "reasons": [],
            "checks": checks_list,
            "domain": domain,
        })

    except Exception as e:
        print(f"Server Error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == "__main__":
    print("Neutral Guard AI Backend Online - Port 5000")
    app.run(host="127.0.0.1", port=5000, debug=True)
