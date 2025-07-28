#!/bin/bash

# ==============================================================================
# Server Security Audit Script
# Version: 1.1
# Author: Oleksii Shataliuk
# Date: July 28, 2025
# Description: This script performs a basic security audit of a web server
#              (specifically Nginx) and its common configurations and files.
#              It checks for common vulnerabilities and adherence to best practices.
#
# Usage: sudo ./server_security_audit.sh
# ==============================================================================

# --- CONFIGURATION ---
# Your domain name (e.g., your-domain.com)
DOMAIN="your-domain.com"
# Root directory of your website (e.g., /var/www/html or /var/www/your-domain.com/html)
WEB_ROOT="/var/www/your-domain.com/html"
# Nginx configuration directory
NGINX_CONF_DIR="/etc/nginx"
# Path to your Nginx site-specific configuration file
NGINX_SITES_AVAILABLE="/etc/nginx/sites-available/${DOMAIN}"
# Path to your htpasswd file for basic authentication (if used for admin interfaces etc.)
HTPASSWD_FILE="/etc/nginx/.htpasswd_admin" # Renamed to be more general if not specifically for GoAccess
# Path to the openssl executable (for SSL/TLS checks)
OPENSSL_PATH="/usr/bin/openssl"

# List of potentially sensitive URLs/paths to check for web accessibility.
# These paths are commonly scanned by bots and may indicate vulnerabilities or data leaks.
SENSITIVE_PATHS=(
    # --- Configuration and Backup Files ---
    "/.env"                     # Environment variables (PHP, Node.js, Python frameworks)
    "/api/.env"                 # .env in api subdirectory
    "/backend/.env"             # .env in backend subdirectory
    "/.env.example"             # Example .env file
    "/.env.bak"                 # Backup .env file
    "/.env.old"
    "/.env.dist"
    "/.git/config"              # Git repository configuration
    "/.git/HEAD"                # Git HEAD pointer
    "/.svn/entries"             # SVN repository entries
    "/.htaccess"                # Apache configuration file (may contain sensitive info)
    "/.htaccess.bak"
    "/.htpasswd"                # Password file for HTTP Basic Auth
    "/web.config"               # ASP.NET configuration
    "/web.config.bak"
    "/sitemap.xml.bak"          # Backup sitemap (can disclose site structure)
    "/phpinfo.php"              # PHP info (often reveals too many server details)
    "/info.php"
    "/test.php"
    "/dump.sql"                 # Database dump
    "/db_backup.zip"            # Database/site archives
    "/backup.zip"
    "/old.tar.gz"
    "/config.php.bak"
    "/config.json.bak"
    "/wp-config.php.bak"        # WordPress config backup
    "/index.php.bak"            # Main file backup

    # --- Admin Panels and Content Management Systems (CMS) Paths ---
    "/admin"                    # Common admin panel path
    "/administrator"            # For Joomla!
    "/wp-admin"                 # For WordPress
    "/wp-login.php"             # WordPress login page
    "/login"                    # General login page
    "/cpanel"                   # Hosting control panel
    "/whm"                      # WebHost Manager
    "/phpmyadmin"               # MySQL management interface
    "/adminer"                  # phpMyAdmin alternative
    "/pma"
    "/user/login"               # For Drupal
    "/umbraco"                  # For Umbraco CMS
    "/typo3"                    # For TYPO3 CMS
    "/bitrix/admin/"            # For 1C-Bitrix

    # --- Paths to Known Vulnerabilities or Specific Services ---
    "/boaform/form_loid_burning" # Vulnerabilities in IoT device firmware (Boa/Realtek)
    "/webui/"                   # Common path for various web management interfaces
    "/geoserver/web/"           # GeoServer web interface
    "/manager/html"             # Tomcat Manager
    "/jmx-console"              # JBoss JMX Console
    "/console"                  # Various management consoles (e.g., Jenkins, WildFly)
    "/solr/"                    # Apache Solr
    "/drupal/CHANGELOG.txt"     # Drupal (helps determine version)
    "/joomla/CHANGELOG.php"     # Joomla!
    "/readme.html"              # WordPress (can reveal version)
    "/robots.txt"               # robots.txt itself (scanners often check it first)
    "/sitemap.xml"              # Sitemap (discloses site structure)
    "/server-status"            # Apache server status (if enabled)
    "/_ignition/health-check"   # Laravel debugbar endpoint
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" # Known RCE in old PHPUnit
    "/wp-includes/wlwmanifest.xml" # WordPress discovery
    "/wp-json/"                 # WordPress REST API
    "/admin.php"                # Common path for admin scripts
    "/xmlrpc.php"               # WordPress XML-RPC API (often used for brute-forcing)
    "/assets/php-connector/php/connector.php" # Vulnerabilities in some file managers
    "/fmi/admin/"               # FileMaker Admin Console
    "/admin/config/"            # Some CMS/frameworks
    "/etc/passwd"               # Attempt for direct file injection
    "/proc/self/cmdline"        # Attempt to get process information
)

# --- START AUDIT ---
echo "=== Extended Server Security Audit ($DOMAIN) ==="
echo "Audit started at: $(date)"
echo "----------------------------------------"

# 1. Check accessibility of known sensitive files and admin panels via web
echo "1. Checking accessibility of known sensitive paths and admin panels..."
for path in "${SENSITIVE_PATHS[@]}"; do
    TARGET_URL="https://${DOMAIN}${path}"
    HTTP_CODE_PATH=$(curl -s -L -o /dev/null -w "%{http_code}" "$TARGET_URL")
    if [ "$HTTP_CODE_PATH" -eq 403 ] || [ "$HTTP_CODE_PATH" -eq 404 ]; then
        echo "   [OK] Path ${TARGET_URL} is not directly accessible (HTTP ${HTTP_CODE_PATH})."
    elif [ "$HTTP_CODE_PATH" -eq 200 ]; then
        echo "   [CRITICAL!] Path ${TARGET_URL} is accessible (HTTP ${HTTP_CODE_PATH}). Secure it immediately!"
    elif [ "$HTTP_CODE_PATH" -eq 301 ] || [ "$HTTP_CODE_PATH" -eq 302 ]; then
         echo "   [WARNING] Path ${TARGET_URL} redirects (HTTP ${HTTP_CODE_PATH}). Check where it redirects to."
    else
        echo "   [WARNING] Unexpected HTTP code for ${TARGET_URL}: ${HTTP_CODE_PATH}. Manual check recommended."
    fi
done
echo ""

# 2. Check UFW (firewall) status
echo "2. Checking UFW (firewall) status..."
UFW_STATUS=$(sudo ufw status | grep Status | awk '{print $2}')
if [ "$UFW_STATUS" == "active" ]; then
    echo "   [OK] UFW is active."
    echo "   UFW Rules:"
    sudo ufw status verbose | while IFS= read -r line; do
        if [[ "$line" != *"Status"* ]]; then
            echo "     $line"
        fi
    done
else
    echo "   [CRITICAL!] UFW is inactive. It is highly recommended to enable it (sudo ufw enable)."
fi
echo ""

# 3. Check file permissions for critical Nginx files and web root
echo "3. Checking file permissions for Nginx files and web root..."
CRITICAL_FILES=(
    "$NGINX_CONF_DIR/nginx.conf"
    "$NGINX_SITES_AVAILABLE"
    "$HTPASSWD_FILE"
)

for file in "${CRITICAL_FILES[@]}"; do
    if [ -f "$file" ]; then
        PERMS=$(stat -c "%a" "$file")
        OWNER_USER=$(stat -c "%U" "$file")
        OWNER_GROUP=$(stat -c "%G" "$file")
        
        echo "   File: $file"
        echo "     Permissions (Octal): $PERMS"
        echo "     Owner: $OWNER_USER:$OWNER_GROUP"

        if [[ "$file" == *".htpasswd"* ]]; then
            if [ "$PERMS" == "640" ] || [ "$PERMS" == "600" ]; then
                echo "     [OK] .htpasswd permissions (${PERMS}) are secure."
            else
                echo "     [WARNING!] .htpasswd permissions (${PERMS}) are NOT optimal. Recommended: 600 or 640."
            fi
        elif [ "$PERMS" == "644" ]; then
            echo "     [OK] File permissions (${PERMS}) are correct."
        else
            echo "     [WARNING!] File permissions (${PERMS}) are NOT optimal. Recommended: 644."
        fi

        if [ "$OWNER_USER" != "root" ]; then
            echo "     [WARNING!] File owner is NOT root. Recommended: root."
        fi
    else
        echo "   [INFO] File not found: $file (might be normal if not used)."
    fi
done

# Check permissions for the web root directory
if [ -d "$WEB_ROOT" ]; then
    echo "   Directory: $WEB_ROOT"
    PERMS=$(stat -c "%a" "$WEB_ROOT")
    OWNER_USER=$(stat -c "%U" "$WEB_ROOT")
    OWNER_GROUP=$(stat -c "%G" "$WEB_ROOT")
    echo "     Permissions (Octal): $PERMS"
    echo "     Owner: $OWNER_USER:$OWNER_GROUP"
    # Recommended permissions: 755 for directories. Nginx user needs read access.
    if [ "$PERMS" == "755" ] || [ "$PERMS" == "775" ] || [ "$PERMS" == "705" ]; then # 775 if multiple users write
        echo "     [OK] Directory permissions (${PERMS}) are correct."
    else
        echo "     [WARNING!] Directory permissions (${PERMS}) are NOT optimal. Recommended: 755 or 775."
    fi
    if [ "$OWNER_USER" != "root" ] && [ "$OWNER_USER" != "www-data" ]; then # root or www-data or other web server user
        echo "     [WARNING!] Directory owner is NOT root or www-data. Verify owner."
    fi
else
    echo "   [ERROR!] Web root directory not found: $WEB_ROOT. Check WEB_ROOT variable."
fi
echo ""

# 4. Check HTTP to HTTPS redirect
echo "4. Checking HTTP to HTTPS redirect..."
HTTP_URL="http://${DOMAIN}"
HTTPS_REDIRECT_CODE=$(curl -s -L -o /dev/null -w "%{http_code}" "$HTTP_URL")
FINAL_URL=$(curl -s -L -o /dev/null -w "%{url_effective}" "$HTTP_URL")

if [ "$HTTPS_REDIRECT_CODE" -ge 300 ] && [ "$HTTPS_REDIRECT_CODE" -lt 400 ] && [[ "$FINAL_URL" == https* ]]; then
    echo "   [OK] HTTP traffic redirects to HTTPS (${FINAL_URL}, HTTP ${HTTPS_REDIRECT_CODE})."
else
    echo "   [WARNING!] HTTP traffic is NOT redirecting to HTTPS or redirects incorrectly. Current HTTP Code: ${HTTPS_REDIRECT_CODE}, Final URL: ${FINAL_URL}."
fi
echo ""

# 5. Check for server_tokens off in Nginx
echo "5. Checking for Nginx version hiding (server_tokens off)..."
if sudo grep -q "server_tokens off;" "$NGINX_CONF_DIR/nginx.conf" || sudo grep -q "server_tokens off;" "$NGINX_SITES_AVAILABLE"; then
    echo "   [OK] 'server_tokens off;' found in Nginx configuration. Server version is hidden."
else
    echo "   [WARNING!] 'server_tokens off;' NOT found. Nginx version might be visible in HTTP headers. Recommended to add to http {} or server {} block."
fi
echo ""

# 6. Check HTTP Security Headers (for the main domain)
echo "6. Checking HTTP Security Headers for https://${DOMAIN} (first 100 characters of headers)..."
# Fetch headers, limit to first 100 lines for efficiency, convert CRLF to LF
HEADERS=$(curl -s -D - -o /dev/null "https://${DOMAIN}" | head -n 100 | tr '\r' '\n')

# Helper function to check for a specific header
function check_header() {
    local header_name="$1"
    local recommended_value_regex="$2"
    local status="[WARNING!]"
    local found_value=$(echo "$HEADERS" | grep -i "^${header_name}:")

    if [ -z "$found_value" ]; then
        echo "   [$status] Header '$header_name' is MISSING."
    elif echo "$found_value" | grep -iqE "$recommended_value_regex"; then
        status="[OK]"
        echo "   [$status] Header '$header_name' found: $found_value"
    else
        echo "   [$status] Header '$header_name' found, but value is NOT optimal: $found_value"
    fi
}

check_header "Strict-Transport-Security" "max-age=[0-9]+;.*includeSubDomains"
check_header "X-Content-Type-Options" "nosniff"
check_header "X-Frame-Options" "SAMEORIGIN|DENY"
check_header "X-XSS-Protection" "1; mode=block"
# Content-Security-Policy is complex and highly site-specific for automated checks.
# Manual verification is highly recommended for CSP.
# check_header "Content-Security-Policy" "default-src 'self'"

echo ""

# 7. Basic SSL/TLS Configuration Check (TLSv1.3 support, no TLSv1.0/1.1)
echo "7. Basic SSL/TLS configuration check for Nginx..."
if command -v $OPENSSL_PATH &> /dev/null; then
    echo "   Checking for TLSv1.3 support..."
    TLS13_TEST=$($OPENSSL_PATH s_client -connect ${DOMAIN}:443 -tls1_3 2>&1 | grep "Protocol" | awk '{print $2}')
    if [ "$TLS13_TEST" == "TLSv1.3" ]; then
        echo "   [OK] TLSv1.3 is supported."
    else
        echo "   [WARNING!] TLSv1.3 is NOT supported or not used by default. Recommended to enable."
    fi

    echo "   Checking for TLSv1.0 presence..."
    TLS10_TEST=$($OPENSSL_PATH s_client -connect ${DOMAIN}:443 -tls1_0 2>&1 | grep "Protocol" | awk '{print $2}')
    if [ -z "$TLS10_TEST" ]; then
        echo "   [OK] TLSv1.0 is NOT supported."
    else
        echo "   [WARNING!] TLSv1.0 is supported. It is highly recommended to disable."
    fi

    echo "   Checking for TLSv1.1 presence..."
    TLS11_TEST=$($OPENSSL_PATH s_client -connect ${DOMAIN}:443 -tls1_1 2>&1 | grep "Protocol" | awk '{print $2}')
    if [ -z "$TLS11_TEST" ]; then
        echo "   [OK] TLSv1.1 is NOT supported."
    else
        echo "   [WARNING!] TLSv1.1 is supported. It is highly recommended to disable."
    fi
else
    echo "   [WARNING!] openssl command not found or not in PATH. Cannot perform TLS checks."
fi
echo ""

# 8. Check Open Ports (basic, only for listening ports)
echo "8. Checking open ports..."
OPEN_PORTS=$(sudo ss -tulpn | grep LISTEN | awk '{print $5}' | sed 's/.*://' | sort -n | uniq | grep -v '127.0.0.1')
if [ -z "$OPEN_PORTS" ]; then
    echo "   [OK] No actively listening non-local ports found."
else
    echo "   [INFO] Found listening ports:"
    for port in $OPEN_PORTS; do
        PROCESS_INFO=$(sudo ss -tulpn | grep LISTEN | grep ":$port" | awk '{$1=$2=$3=$4=$5=$6=""; print $0}' | sed 's/^ *//')
        echo "     Port: $port (Process: $PROCESS_INFO)"
        if [ "$port" -ne 22 ] && [ "$port" -ne 80 ] && [ "$port" -ne 443 ]; then
            echo "     [WARNING!] Non-standard open port: $port. Ensure it is necessary and secured."
        fi
    done
fi
echo ""

echo "=== Audit Completed ==="
