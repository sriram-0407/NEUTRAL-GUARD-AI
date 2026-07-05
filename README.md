# Neutral Guard AI — Phishing Detection Browser Extension

A Chrome browser extension that detects phishing and malicious websites
using AI-powered security analysis. Built with Python Flask backend
and JavaScript frontend.

## Project Overview
This project demonstrates QA testing skills on a real-world security tool
including API testing, automated testing, and security analysis testing.

## Tech Stack
- Python, Flask (Backend API)
- JavaScript, HTML, CSS (Chrome Extension Frontend)
- Pytest + Requests (Automated Testing)
- Postman (Manual API Testing)

## How It Works
1. User visits any website
2. Extension scans the page automatically
3. Flask backend analyzes 8 security parameters
4. Risk score (0-100) is returned and displayed

## Security Checks Performed
| Check | Description |
|---|---|
| SSL Certificate | Verifies HTTPS vs HTTP |
| DNS Resolution | Confirms domain is reachable |
| Domain Age | Flags newly created domains |
| URL Structure | Detects suspicious keywords and patterns |
| HSTS Policy | Checks
