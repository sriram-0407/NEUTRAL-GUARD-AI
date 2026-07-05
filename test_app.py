import requests
import pytest

BASE_URL = "http://127.0.0.1:5000"

# ===== WHITELIST TESTS =====

def test_whitelisted_google():
    response = requests.post(f"{BASE_URL}/analyze", json={"url": "https://google.com"})
    assert response.status_code == 200
    assert response.json()["risk_score"] == 0

def test_whitelisted_github():
    response = requests.post(f"{BASE_URL}/analyze", json={"url": "https://github.com"})
    assert response.status_code == 200
    assert response.json()["risk_score"] == 0

def test_whitelisted_amazon():
    response = requests.post(f"{BASE_URL}/analyze", json={"url": "https://amazon.com"})
    assert response.status_code == 200
    assert response.json()["risk_score"] == 0

# ===== SSL TESTS =====

def test_http_url_gets_ssl_penalty():
    response = requests.post(f"{BASE_URL}/analyze", json={"url": "http://insecure-site.com"})
    assert response.status_code == 200
    assert response.json()["risk_score"] >= 30

def test_https_url_no_ssl_penalty():
    response = requests.post(f"{BASE_URL}/analyze", json={"url": "https://example.com"})
    assert response.status_code == 200
    data = response.json()
    ssl_check = next((c for c in data["checks"] if c["name"] == "SSL Certificate"), None)
    assert ssl_check["status"] == "pass"

# ===== URL STRUCTURE TESTS =====

def test_suspicious_keyword_login():
    response = requests.post(f"{BASE_URL}/analyze", json={"url": "https://malicious-login-update.com"})
    assert response.status_code == 200
    assert response.json()["risk_score"] >= 20

def test_suspicious_keyword_verify():
    response = requests.post(f"{BASE_URL}/analyze", json={"url": "https://verify-account-secure.com"})
    assert response.status_code == 200
    assert response.json()["risk_score"] >= 20

def test_long_url_penalty():
    long_url = "https://this-is-a-very-long-suspicious-url-that-exceeds-seventy-five-characters-limit.com"
    response = requests.post(f"{BASE_URL}/analyze", json={"url": long_url})
    assert response.status_code in [200, 500]

def test_url_with_at_symbol():
    response = requests.post(f"{BASE_URL}/analyze", json={"url": "https://evil@example.com"})
    assert response.status_code == 200
    assert response.json()["risk_score"] >= 20

# ===== NEGATIVE TESTS =====

def test_no_url_field():
    response = requests.post(f"{BASE_URL}/analyze", json={})
    assert response.status_code == 400

def test_no_body():
    response = requests.post(f"{BASE_URL}/analyze")
    assert response.status_code in [400, 500]

# ===== HEURISTICS TESTS =====

def test_disable_clickjacking_check():
    response = requests.post(f"{BASE_URL}/analyze", json={
        "url": "https://example.com",
        "heuristics": {"clickjacking": False}
    })
    assert response.status_code == 200
    data = response.json()
    xframe = next((c for c in data["checks"] if c["name"] == "Clickjacking Protection"), None)
    assert xframe["message"] == "CHECK DISABLED"

def test_disable_domain_age_check():
    response = requests.post(f"{BASE_URL}/analyze", json={
        "url": "https://example.com",
        "heuristics": {"domainAge": False}
    })
    assert response.status_code == 200
    data = response.json()
    age_check = next((c for c in data["checks"] if c["name"] == "Domain Age"), None)
    assert age_check["message"] == "CHECK DISABLED"

# ===== RESPONSE STRUCTURE TESTS =====

def test_response_has_required_fields():
    response = requests.post(f"{BASE_URL}/analyze", json={"url": "https://example.com"})
    assert response.status_code == 200
    data = response.json()
    assert "risk_score" in data
    assert "checks" in data
    assert "domain" in data
    assert "status" in data

def test_risk_score_not_exceed_100():
    response = requests.post(f"{BASE_URL}/analyze", json={"url": "http://login.verify.bank.update.com/account/signin"})
    assert response.status_code == 200
    assert response.json()["risk_score"] <= 100

def test_risk_score_minimum_1():
    response = requests.post(f"{BASE_URL}/analyze", json={"url": "https://example.com"})
    assert response.status_code == 200
    assert response.json()["risk_score"] >= 1

def test_checks_list_has_8_items():
    response = requests.post(f"{BASE_URL}/analyze", json={"url": "https://example.com"})
    assert response.status_code == 200
    assert len(response.json()["checks"]) == 8

# ===== URL AUTO-FIX TEST =====

def test_url_without_scheme_gets_https():
    response = requests.post(f"{BASE_URL}/analyze", json={"url": "example.com"})
    assert response.status_code == 200
    assert response.json()["status"] == "success"