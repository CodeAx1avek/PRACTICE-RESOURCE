# Practice Resource Repository

## Overview
This repository contains detailed notes, resources, and tools for **Penetration Testing**, **Red Teaming**, and preparation for certifications like **eJPT**, **OSCP**, and **CEH Practical**. It is structured to help practitioners organize their knowledge and study efficiently.

The **MAIN FILE** is **ARAMBH X!00**, located at the root directory. This file contains an overview of how to use this repository, and it serves as a quick-start guide.

## Folder Structure

### 📁 **01_Recon_OSINT**  
This folder contains resources for **reconnaissance** and **OSINT** techniques.
- 📁 **Passive Recon**  
  - `google_dorks.md`: Google Dorking techniques.
  - `whois_dns.md`: WHOIS lookups and DNS enumeration.
  - `shodan_censys.md`: Using Shodan and Censys for OSINT.
  - `maltego.md`: Maltego graphing for information gathering.
  - `social_media_osint.md`: OSINT from social media platforms.

- 📁 **Active Recon**  
  - `nmap_commands.md`: Nmap commands for network scanning.
  - `masscan.md`: Using Masscan for faster scanning.
  - `subdomains.md`: Techniques for subdomain enumeration.
  - `dirbusting.md`: Directory brute-forcing with Dirbuster.

### 📁 **02_Scanning_Enumeration**  
This folder includes tools and techniques for **scanning** and **enumerating services**.
- 📁 **Network Scanning**  
  - `nmap_full_scan.md`: Advanced Nmap scanning commands.
  - `arp_snmp_scan.md`: ARP scanning and SNMP enumeration.

- 📁 **Web Enumeration**  
  - `dirb_ffuf_gobuster.md`: Directory brute-forcing with Dirb, FFUF, and Gobuster.
  - `nikto_wpscan.md`: Scanning for web vulnerabilities with Nikto and WPScan.

- 📁 **SMB & Other Services**  
  - `smb_enum.md`: SMB enumeration techniques.
  - `ftp_smtp_scan.md`: Enumerating FTP, SMTP, and SNMP services.

### 📁 **03_Vulnerability_Assessment**  
This folder covers techniques for identifying vulnerabilities.
- 📁 **Automated Scanning**  
  - `nessus_openvas.md`: Using Nessus and OpenVAS for vulnerability scanning.
  - `nmap_vuln_scripts.md`: Nmap Vulnerability scanning scripts.

- 📁 **Manual Analysis**  
  - `cve_exploit_db.md`: Searching and exploiting CVEs from Exploit-DB.
  - `manual_web_vulns.md`: Manual web vulnerability checks such as SQL Injection, XSS, RCE, etc.

### 📁 **04_Exploitation**  
This folder contains notes and techniques for exploiting vulnerabilities.
- 📁 **Windows Exploits**  
  - `msfvenom_payloads.md`: Creating Windows payloads with MSFVenom.
  - `mimikatz_hashdump.md`: Dumping hashes and credentials using Mimikatz.
  - `rce_eternalblue.md`: Exploiting SMB RCE using EternalBlue.

- 📁 **Linux Exploits**  
  - `linux_suid_rootkits.md`: Exploiting SUID binaries for privilege escalation.
  - `dirty_cow_kernel_exploit.md`: Kernel exploit using Dirty COW vulnerability.

- 📁 **Web Exploits**  
  - `sql_injection.md`: Manual SQL injection and using SQLMap.
  - `xss_csrf_rce.md`: Exploiting XSS, CSRF, and Remote Code Execution vulnerabilities.

### 📁 **05_Post_Exploitation**  
This folder contains techniques for maintaining access and escalating privileges.
- 📁 **Windows Privilege Escalation**  
  - `winpeas_powershell_privesc.md`: Privilege escalation using WinPEAS and PowerShell.
  - `juicy_potato.md`: Using Juicy Potato for Windows token impersonation.
  - `schtasks_sam_hashdump.md`: Task Scheduler exploitation and SAM hash dumping.

- 📁 **Linux Privilege Escalation**  
  - `linpeas_capabilities.md`: Using LinPEAS for Linux privilege escalation.
  - `sudo_suid_exploits.md`: Exploiting sudo and SUID misconfigurations.

### 📁 **06_Pivoting_Lateral_Movement**  
This folder focuses on techniques for **pivoting** and **lateral movement**.
- `chisel_socks_tunneling.md`: Tunneling with Chisel and proxying with SSH.
- `psexec_rdp_pivot.md`: Lateral movement using PsExec and RDP.
- `smb_wmi_admin_movement.md`: Lateral movement through SMB and WMI.

### 📁 **07_Red_Team_Techniques**  
This folder contains advanced **Red Teaming** tactics.
- `evasion_amasi_bypass.md`: Techniques for bypassing AV and AMSI.
- `c2_frameworks.md`: Using Cobalt Strike, Empire, and Sliver for C2 communications.
- `malware_analysis_basics.md`: Basic malware analysis techniques.

### 📁 **08_CTF_Labs**  
This folder contains CTF challenges and write-ups for hands-on practice.
- `htb_writeups.md`: Walkthroughs for Hack The Box labs.
- `tryhackme_notes.md`: Notes from TryHackMe modules.
- `vulnhub_oscp_labs.md`: Exploit chains and lessons learned from VulnHub and OSCP labs.

### 📁 **09_Certifications**  
This folder includes certification-specific resources.
- `eJPT.md`: Notes and techniques for eJPT preparation.
- `OSCP.md`: OSCP-related techniques and exam resources.
- `CEH_Practical.md`: Notes for the CEH Practical exam preparation.

### 📁 **10_Tools_Reference**  
This folder contains **cheat sheets** and quick access commands for various tools.
- `linux_cheat_sheet.md`: Common Linux commands for penetration testing.
- `windows_cheat_sheet.md`: Windows commands for penetration testing and privilege escalation.
- `reverse_shells.md`: Different reverse shell techniques (Netcat, Bash, PowerShell, Python).
- `metasploit_cheatsheet.md`: Metasploit command references for payload creation and exploitation.

---

## How to Use This Repository
1. **Clone this repository** to your local machine.
2. Navigate to any of the folders to explore detailed notes and techniques.
3. Refer to the **ARAMBH X!00** file for guidance on how to organize your learning and keep track of your progress.

---

## Contribution
If you want to contribute to this repository, please create a pull request with your changes. You can contribute by adding more **notes**, **write-ups**, **tools**, or **resources** related to penetration testing, red teaming, or certifications.

---

This README structure provides a comprehensive overview of the entire repository without linking to external resources. You can add more details as needed for each folder or adjust the names of the files to fit your needs.

Let me know if you need more changes! 😊
