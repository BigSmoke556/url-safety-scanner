![Go Version](https://img.shields.io/badge/Go-1.21-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/build-passing-brightgreen)

# 🌐 URL Safety Scanner (USS)

A professional tool to analyze the security of URLs by checking for malware threats, forced downloads, cookies, and tracking mechanisms.  
Built in Go (Golang) for maximum performance and portability.

---

## ✨ Features

- Google Safe Browsing API malware checks
- Automatic download detection
- Cookies and trackers detection
- Risk score evaluation
- Proxy and timeout configuration
- Progress bar for batch scanning
- Report generation in **CSV** and **JSON**
- Lightweight and fast (compiled Go binary)
- Cross-platform: Windows, Linux, macOS

---

## 📥 Installation

First, clone the repository:

```bash
git clone https://github.com/BigSmoke556/url-safety-scanner.git
cd url-safety-scanner
go build -o url-safety-scanner ./cmd
```
