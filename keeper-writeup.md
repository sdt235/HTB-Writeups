# HTB: Keeper — Writeup

**OS:** Linux
**Difficulty:** Easy
**Techniques:** Default credentials, Request Tracker, CVE-2023-32784 (KeePass memory dump), PuTTY key conversion

---

## Synopsis

Keeper is an Easy Linux machine that runs a [Request Tracker](https://bestpractical.com/request-tracker) (RT) ticketing system behind nginx. The RT instance is left with its well-known default administrator credentials, giving full access to the ticket queue and user administration. A support ticket about a KeePass crash dump leads to a user profile whose comments field still contains the user's initial SSH password. Logging in as that user reveals a KeePass crash dump and database in their home directory; the master password is recovered from the memory dump via CVE-2023-32784. The database holds a PuTTY-format private key for `root`, which is converted to OpenSSH format and used to log in directly as root.

## Skills Required

- Basic port and web enumeration
- Virtual host / `/etc/hosts` handling
- Recognising off-the-shelf software and checking vendor defaults
- Basic familiarity with KeePass and SSH key formats

## Skills Learned

- Exploiting default credentials on Request Tracker
- Recovering a KeePass master password from a process memory dump (CVE-2023-32784) and reasoning out the one character the tool cannot recover
- Converting a PuTTY `.ppk` private key to OpenSSH format with `puttygen`

---

## Enumeration

### Nmap

```
$ nmap -p22,80 -sCV -oA nmap/Keeper 10.129.229.41

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Only two ports: SSH (22) and HTTP (80). With just a web server and SSH, the web app is the way in, and SSH is likely where any credentials we find will be spent.

### HTTP (80)

Browsing to `http://10.129.229.41` returns a near-empty page whose only content is a single hyperlink pointing at `http://tickets.keeper.htb/rt/`.

![Landing page on port 80 with a single hyperlink pointing to tickets.keeper.htb/rt/](images/keeper_landing-page-tickets-link.png)

The link exposes two hostnames the box expects us to resolve — `keeper.htb` and the `tickets.` subdomain — so both are added to `/etc/hosts`:

```
$ echo "10.129.229.41 keeper.htb tickets.keeper.htb" | sudo tee -a /etc/hosts
```

`http://keeper.htb` mirrors the index page, but `http://tickets.keeper.htb/rt/` serves a **Request Tracker** login page. The footer leaks the exact version:

```
»|« RT 4.4.4+dfsg-2ubuntu1 (Debian) Copyright 1996-2019
```

![Request Tracker (RT) login page on tickets.keeper.htb, version shown in the footer](images/keeper_rt-login-page-version.png)

---

## Foothold

### Default credentials on Request Tracker

Before reaching for CVEs against RT 4.4.4, the cheapest thing to try against any known off-the-shelf application is its shipped defaults. Request Tracker's own [security documentation](https://docs.bestpractical.com/rt/4.4.4/security.html) states that a fresh install creates a `root` superuser with the password `password`. Those credentials log straight in as the RT administrator.

> ℹ️ A first login attempt silently looped back to the login page. This turned out to be a stale session cookie — a fresh incognito window logged in on the first try.

The dashboard shows an open ticket in the General queue about a KeePass problem.

![RT admin dashboard listing the open ticket about a KeePass issue](images/keeper_rt-dashboard-keepass-ticket.png)

The ticket describes a KeePass crash and references the user `lnorgaard`, who is said to have shared a crash dump of the KeePass session.

![RT ticket detailing the KeePass problem, referencing user lnorgaard](images/keeper_rt-ticket-keepass-detail.png)

As the RT administrator we can administer every user. Browsing to **Admin → Users → lnorgaard** and opening the **Edit** view reveals that the "Comments about this user" field was never cleaned up — it still records the account's initial password:

```
New user. Initial password set to Welcome2023!
```

![lnorgaard user profile edit view, Comments field revealing the initial password](images/keeper_rt-user-profile-password-comment.png)

That password is reused for SSH:

```
$ ssh lnorgaard@10.129.229.41
lnorgaard@keeper:~$ id
uid=1000(lnorgaard) gid=1000(lnorgaard) groups=1000(lnorgaard)
```

`user.txt` retrieved.

---

## Privilege Escalation

### Recovering the KeePass master password (CVE-2023-32784)

`lnorgaard`'s home directory contains the artifact mentioned in the ticket — an archive named after the ticket number:

```
lnorgaard@keeper:~$ ls -la
...
-rw-r--r-- 1 lnorgaard lnorgaard 87391651 May 24  2023 RT30000.zip
```

Unzipping it yields two files: a KeePass database and a KeePass process **memory dump**:

```
$ unzip RT30000.zip
  inflating: KeePassDumpFull.dmp
  inflating: passcodes.kdbx
```

Both were pulled back to the attacking host with `scp`. The `.kdbx` is encrypted with a master password we don't have — but we also have a dump of the KeePass process's memory from while the database was open. This is exactly the condition for **CVE-2023-32784**: in KeePass before 2.54, the cleartext master password can be reconstructed from a memory dump because KeePass leaves a trail of partial strings in memory as the password is typed (one masked `●` placeholder plus one real character per position). The one character it never recovers is the first.

vdohney's [`keepass-password-dumper`](https://github.com/vdohney/keepass-password-dumper) automates the reconstruction. The tool targets .NET 7 specifically, so rather than install an SDK on the host it was run inside a disposable .NET 7 container with the dump mounted in:

```
$ docker run --rm -it \
    -v $(pwd)/loot:/dump:ro \
    mcr.microsoft.com/dotnet/sdk:7.0 \
    bash -c "git clone https://github.com/vdohney/keepass-password-dumper /tool && cd /tool && dotnet run /dump/KeePassDumpFull.dmp"
```

The output recovers everything after the first character, with an ambiguous set of candidates for the second position:

```
Combined: ●{ø, Ï, ,, l, `, -, ', ], §, A, I, :, =, _, c, M}dgrød med fløde
```

The recovered fragment `dgrød med fløde`, together with the Danish-looking username `lnorgaard` and the `ø` characters, is enough to *reason out* the rest rather than brute-force it. Searching the phrase identifies it as the Danish dessert **rødgrød med fløde** (red berry pudding) — which supplies both missing characters (`r` and `ø`, the `ø` being one of the candidates the tool already offered). The full master password is:

```
rødgrød med fløde
```

### Extracting the root key from the KeePass database

Opening `passcodes.kdbx` with the recovered master password (via `kpcli` / KeePassXC) reveals several groups. The entry for the Keeper ticketing server, under the Network group, carries a `root` login whose **Notes** field contains a private key — in **PuTTY** format, not OpenSSH:

```
PuTTY-User-Key-File-3: ssh-rsa
       Encryption: none
       ...
```

Note the leading whitespace on every line after the first — `kpcli` indents the Notes field. Saving the key and converting it directly fails:

```
$ puttygen root.ppk -O private-openssh -o root.key
puttygen: error loading `root.ppk': file format error
```

The fix is to strip the leading indentation from each line so `puttygen` can parse the PPK, then convert it to an OpenSSH key:

```
$ sed 's/^[[:space:]]*//' root.ppk > root_clean.ppk
$ puttygen root_clean.ppk -O private-openssh -o root.key
$ chmod 600 root.key
$ ssh -i root.key root@10.129.229.41
root@keeper:~# id
uid=0(root) gid=0(root) groups=0(root)
```

`root.txt` retrieved.

---

## Summary of Techniques

| Stage | Technique |
|---|---|
| Enumeration | Nmap service scan; landing-page vhost discovery → `/etc/hosts`; RT version from footer |
| Foothold | Request Tracker default credentials (`root`/`password`); initial password left in user profile comments → SSH as `lnorgaard` |
| Privilege Escalation | CVE-2023-32784 master-password recovery from KeePass memory dump; extract PuTTY key for `root`; `puttygen` conversion → SSH as root |

---

## Lessons / Takeaways

- **Check vendor defaults before anything clever.** RT 4.4.4 had no useful CVE for us; the whole foothold was its published default admin password left unchanged.
- **A stale session cookie can masquerade as "wrong password."** When a login silently loops with no error, test in a clean/incognio session before assuming the credentials are bad.
- **CVE-2023-32784 doesn't hand you the whole password.** The tool loses the first character and may leave an ambiguous second — the missing piece is recovered by *understanding the context* (a Danish username and a half-phrase that searches cleanly), not by brute force.
- **Mind the key format.** A private key in a KeePass Notes field was PuTTY `.ppk`, not OpenSSH, and `kpcli` had indented every line. Recognising the `PuTTY-User-Key-File-3` header and stripping the leading whitespace before `puttygen -O private-openssh` was the difference between a format error and a root shell.
