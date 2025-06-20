# 🔐 GoSecScan

**GoSecScan** is a web vulnerability scanner written in Go. It helps mainly penetration testers perform quick reconaissance  on web targets by checking for missing HTTP security headers, following redirects, examining TLS certificates, and brute-forcing common directories.

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

## 📦 Installation

```bash
git clone https://github.com/yourusername/gosecscan.git
cd gosecscan
go build -o gosecscan
