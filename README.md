# 🔐 GoSecScan

**GoSecScan** is a web vulnerability scanner written in Go. It helps penetration testers perform quick reconaissance on web targets by checking for missing HTTP security headers, following redirects, examining TLS certificates, and brute-forcing common directories.

---

## 🚀 Features

- ✅ Detects missing HTTP security headers:
  - `Content-Security-Policy`
  - `X-Frame-Options`
  - `Strict-Transport-Security`
  - and more
- 🌐 Checks for redirects (3xx responses)
- 🔐 Parses TLS certificate issuer, subject, and expiration date
- 📁 Brute-forces directories using a custom or downloaded wordlist
- ⚡ Fast scanning with Go’s built-in concurrency
- 🧪 CLI-based (easy to use)

---
Used like 

./gosecscan <url> <wordlist>

Example Input

./gosecscan https://example.com dirst.txt

Example Output 

🔍 Security Header & TLS Check for: https://example.com
[+] TLS Cert Subject: example.com
[+] TLS Cert Issuer: Let's Encrypt
[+] TLS Cert Expiry: 2025-10-01
[-] Missing header: X-Frame-Options
[-] Missing header: Content-Security-Policy

📁 Directory Bruteforce Results:
[+] https://example.com/admin [200]
[+] https://example.com/.git [403]

✅ Scan Complete.




