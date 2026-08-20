# HTB: Sense — Writeup

**Difficulty:** Medium
**OS:** FreeBSD (pfSense)
**Techniques:** Directory brute-forcing, information disclosure via unauthenticated files

---

## Overview

Sense is a pfSense firewall appliance. Nmap shows only the lighttpd-based web UI exposed, presenting a pfSense login page. Directory brute-forcing turns up two unauthenticated files: a changelog admitting a partially-patched vulnerability, and a support-ticket note referencing a new user account.

*(These are the full engagement notes captured for this box — they end at the support-ticket discovery, before any login or exploitation was documented.)*

---

## Recon

### Nmap

```
┌──(darkangel3007㉿kali)-[~/htb/Sense]
└─$ nmap -sCV 10.129.14.53 -oA nmap/Sense
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-22 16:17 GMT
Nmap scan report for 10.129.14.53
Host is up (0.025s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT    STATE SERVICE  VERSION
80/tcp  open  http     lighttpd 1.4.35
|_http-server-header: lighttpd/1.4.35
|_http-title: Did not follow redirect to https://10.129.14.53/
443/tcp open  ssl/http lighttpd 1.4.35
| ssl-cert: Subject: commonName=Common Name (eg, YOUR name)/organizationName=CompanyName/stateOrProvinceName=Somewhere/countryName=US
| Not valid before: 2017-10-14T19:21:35
|_Not valid after:  2023-04-06T19:21:35
|_ssl-date: TLS randomness does not represent time
|_http-title: Login
|_http-server-header: lighttpd/1.4.35

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.14 seconds
```

Only ports 80 and 443 open, both lighttpd. Navigating to `https://10.129.14.53` presents a pfSense login page.

### Directory Brute-Force

```
┌──(darkangel3007㉿kali)-[~/htb/Sense]
└─$ gobuster dir -u https://10.129.14.53 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -k -x txt
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://10.129.14.53
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Extensions:              txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/themes               (Status: 301) [Size: 0] [--> https://10.129.14.53/themes/]
/css                  (Status: 301) [Size: 0] [--> https://10.129.14.53/css/]
/includes             (Status: 301) [Size: 0] [--> https://10.129.14.53/includes/]
/javascript           (Status: 301) [Size: 0] [--> https://10.129.14.53/javascript/]
/changelog.txt        (Status: 200) [Size: 271]
/classes              (Status: 301) [Size: 0] [--> https://10.129.14.53/classes/]
/widgets              (Status: 301) [Size: 0] [--> https://10.129.14.53/widgets/]
/tree                 (Status: 301) [Size: 0] [--> https://10.129.14.53/tree/]
/shortcuts            (Status: 301) [Size: 0] [--> https://10.129.14.53/shortcuts/]
/installer            (Status: 301) [Size: 0] [--> https://10.129.14.53/installer/]
/wizards              (Status: 301) [Size: 0] [--> https://10.129.14.53/wizards/]
/csrf                 (Status: 301) [Size: 0] [--> https://10.129.14.53/csrf/]
/system-users.txt     (Status: 200) [Size: 106]
/filebrowser          (Status: 301) [Size: 0] [--> https://10.129.14.53/filebrowser/]
Progress: 415282 / 415282 (100.00%)
===============================================================
Finished
===============================================================
```

Two unauthenticated text files stood out: `changelog.txt` and `system-users.txt`.

**`changelog.txt`:**

```
# Security Changelog

### Issue
There was a failure in updating the firewall. Manual patching is therefore required

### Mitigated
2 of 3 vulnerabilities have been patched.

### Timeline
The remaining patches will be installed during the next maintenance window
```

This confirms the pfSense install has known, unpatched vulnerabilities — one of three security issues remains unmitigated.

**`system-users.txt`:**

```
####Support ticket###

Please create the following user


username: Rohit
password: company defaults
```

A support ticket referencing a new user, `Rohit`, provisioned with a default password rather than a unique one.

---

## Status

Engagement notes end here — enumeration had identified an unpatched pfSense vulnerability and a username with a hinted-at default password, but exploitation, privilege escalation, and flag capture were not documented for this box.

---

## Summary of Techniques

| Stage | Technique |
|---|---|
| Recon | Nmap identifying a pfSense (lighttpd) web login as the only exposed service |
| Enumeration | Directory brute-forcing (`gobuster`) uncovering unauthenticated `changelog.txt` and `system-users.txt` disclosing a partially-patched CVE status and a username with a guessable default password |

---

## Lessons / Takeaways

- Unauthenticated changelog/support files left on a web root are a common, low-effort source of both vulnerability confirmation and credential hints — always check for them during directory brute-forcing.
- A changelog stating "2 of 3 vulnerabilities patched" is a direct signal to go looking for public CVEs against the identified software version for the one that's still open.
