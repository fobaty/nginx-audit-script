# Nginx Server Security Audit Script

![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)
![Bash](https://img.shields.io/badge/language-Bash-4EAA25.svg)
![Security Audit](https://img.shields.io/badge/category-Security%20Audit-red.svg)

A robust Bash script designed to perform a basic security audit of Nginx web servers. It checks common configuration pitfalls, sensitive file exposures, firewall status, HTTP security headers, and essential SSL/TLS settings to help identify potential vulnerabilities and ensure adherence to security best practices.

---

## 🌟 Features

* **Sensitive Path Scanning:** Probes for common sensitive files (`.env`, `.git`, `.htpasswd`, backup files, `phpinfo.php`, database dumps, etc.) and known administrative interfaces (`/admin`, `/wp-admin`, `/phpmyadmin`, etc.).
* **Firewall Status Check (UFW):** Verifies if UFW is active and lists its rules.
* **File Permissions Audit:** Checks critical Nginx configuration files and the web root directory for optimal permissions and ownership.
* **HTTP to HTTPS Redirect Verification:** Ensures all HTTP traffic is correctly redirected to HTTPS.
* **Nginx Version Hiding:** Confirms `server_tokens off;` is configured to prevent Nginx version disclosure.
* **HTTP Security Header Analysis:** Validates the presence and optimal configuration of key security headers (HSTS, X-Content-Type-Options, X-Frame-Options, X-XSS-Protection).
* **Basic SSL/TLS Configuration Check:** Assesses support for TLSv1.3 and flags the presence of outdated TLSv1.0/1.1 protocols.
* **Open Port Scan (Listening):** Identifies actively listening network ports and highlights non-standard ones.

---

## 🚀 Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

* A Linux-based server (e.g., Ubuntu, Debian, CentOS).
* `bash` (usually pre-installed).
* `curl` (for HTTP requests).
* `sudo` privileges (required for many checks).
* `ufw` (for firewall checks, optional but recommended).
* `openssl` (for TLS checks).
* `ss` (from `iproute2` package, for port checks).

```bash
# Install required tools if not present (for Debian/Ubuntu)
sudo apt update
sudo apt install curl ufw openssl iproute2 -y
