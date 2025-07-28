# Nginx Server Security Audit Script

![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)
![Bash](https://img.shields.io/badge/language-Bash-4EAA25.svg)
![Security Audit](https://img.shields.io/badge/category-Security%20Audit-red.svg)

A robust Bash script designed to perform a basic security audit of Nginx web servers. It checks common configuration pitfalls, sensitive file exposures, firewall status, HTTP security headers, and essential SSL/TLS settings to help identify potential vulnerabilities and ensure adherence to security best practices.

---

## 🌟 Features

- **Sensitive Path Scanning:** Probes for common sensitive files (`.env`, `.git`, `.htpasswd`, backup files, `phpinfo.php`, database dumps, etc.) and known administrative interfaces (`/admin`, `/wp-admin`, `/phpmyadmin`, etc.).
- **Firewall Status Check (UFW):** Verifies if UFW is active and lists its rules.
- **File Permissions Audit:** Checks critical Nginx configuration files and the web root directory for optimal permissions and ownership.
- **HTTP to HTTPS Redirect Verification:** Ensures all HTTP traffic is correctly redirected to HTTPS.
- **Nginx Version Hiding:** Confirms `server_tokens off;` is configured to prevent Nginx version disclosure.
- **HTTP Security Header Analysis:** Validates the presence and optimal configuration of key security headers (HSTS, X-Content-Type-Options, X-Frame-Options, X-XSS-Protection).
- **Basic SSL/TLS Configuration Check:** Assesses support for TLSv1.3 and flags the presence of outdated TLSv1.0/1.1 protocols.
- **Open Port Scan (Listening):** Identifies actively listening network ports and highlights non-standard ones.

---

## 🚀 Getting Started

These instructions will help you get a copy of the project up and running on your local machine for development and testing.

### Prerequisites

- A Linux-based server (e.g., Ubuntu, Debian, CentOS)
- `bash` (usually pre-installed)
- `curl` (for HTTP requests)
- `sudo` privileges (required for many checks)
- `ufw` (for firewall checks – optional but recommended)
- `openssl` (for TLS checks)
- `ss` (from `iproute2` package, for port checks)

Install required tools (for Debian/Ubuntu):

```bash
sudo apt update
sudo apt install curl ufw openssl iproute2 -y
```

---

## 📦 Installation

Clone the repository:

```bash
git clone https://github.com/fobaty/nginx-audit-script.git
cd nginx-audit-script
```

Make the script executable:

```bash
chmod +x server_security_audit.sh
```

---

## 🛠️ Usage

Before running, open `server_security_audit.sh` and configure the `DOMAIN` and `WEB_ROOT` variables to match your server's settings:

```bash
# --- CONFIGURATION ---
DOMAIN="your-domain.com"                # Your domain name (e.g., example.com)
WEB_ROOT="/var/www/your-domain.com/html"  # Root directory of your website
# ... other configurations
```

Run the script with sudo:

```bash
sudo ./server_security_audit.sh
```

The script will output findings directly to your terminal, indicating `[OK]`, `[WARNING!]`, `[CRITICAL!]`, or `[INFO]` statuses for each check.

---

## ⚠️ Important Notes

- This script performs **read-only** checks and does not modify your server's configuration.
- Always review the script's code before running it on a production server.
- The `SENSITIVE_PATHS` list is extensive but not exhaustive. Update it regularly based on new vulnerabilities and specific applications.
- Some checks (e.g., HTTP Security Headers, SSL/TLS) are performed against `https://${DOMAIN}`. Ensure your domain is accessible via HTTPS.
- The `HTPASSWD_FILE` variable refers to a general `.htpasswd` file. Adjust it if your file is named differently or located elsewhere.

---

## 🤝 Contributing

Contributions are welcome! If you have suggestions for improvements, new checks, or bug fixes, feel free to open an issue or submit a pull request.

1. Fork the repository
2. Create your feature branch  
   ```bash
   git checkout -b feature/AmazingFeature
   ```
3. Commit your changes  
   ```bash
   git commit -m 'Add some AmazingFeature'
   ```
4. Push to the branch  
   ```bash
   git push origin feature/AmazingFeature
   ```
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.

---

## 📞 Contact

**Oleksii Shataliuk**  
GitHub: [fobaty](https://github.com/fobaty)  
Project Link: [https://github.com/fobaty/nginx-audit-script](https://github.com/fobaty/nginx-audit-script)

