# HTB Writeups

Writeups for [Hack The Box](https://www.hackthebox.com/) machines I've completed, covering recon through to root/system.

## Machines

| Machine | OS | Difficulty | Techniques |
|---|---|---|---|
| [Blackfield](blackfield-writeup.md) | Windows (AD / DC) | Hard | SMB null session enum, AS-REP roasting, BloodHound DACL abuse, LSASS dump, `SeBackupPrivilege`, VSC `ntds.dit` extraction, pass-the-hash |
| [Blue](blue-writeup.md) | Windows | Easy | MS17-010 (EternalBlue) |
| [Certified](certified-writeup.md) | Windows (AD) | Medium | ACL abuse (WriteOwner → DACL write), Shadow Credentials, ADCS ESC9 (No Security Extension) |
| [Nexus](nexus-writeup.md) | Linux | Easy (rated) / Medium (practice) | Vhost fuzzing, Git history secret mining, authenticated file upload RCE, path traversal via hand-crafted Git objects |
| [PermX](permx-writeup.md) ⚠️ | Linux | Easy | Chamilo LMS unauthenticated big-upload RCE (CVE-2023-4220) |
| [Sense](sense-writeup.md) ⚠️ | FreeBSD (pfSense) | Medium | Directory brute-forcing, information disclosure (enumeration only — see writeup) |
| [Signed](signed-writeup.md) | Windows (AD / DC) | — | MSSQL `xp_dirtree` NTLM coercion, RID brute-forcing, Kerberos silver ticket forgery, `OPENROWSET(BULK)` file-read-as-Domain-Admin via ticket group injection |

⚠️ = incomplete — see note below.

## Challenges

| Challenge | Category | Difficulty | Techniques |
|---|---|---|---|
| [Bypass](bypass-writeup.md) | Reversing | Easy | .NET/Mono binary identification, IL disassembly/reassembly (`monodis`/`ilasm`), IL-level logic patching |

## Structure

Machine writeups generally follow: Overview → Recon → per-service enumeration/exploitation → User → Privilege Escalation → Summary of Techniques → Lessons/Takeaways. Earlier writeups are less formally structured.

## Known Gaps

- **PermX**: the steps between finding the CVE-2023-4220 Chamilo file upload vulnerability and recovering the SSH credential for `mtz` are missing from the write-up and need to be filled in.
- **Sense**: currently enumeration-only — exploitation, privilege escalation, and flag capture still need to be added.
