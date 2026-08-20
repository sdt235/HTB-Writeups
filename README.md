# HTB Writeups

Writeups for [Hack The Box](https://www.hackthebox.com/) machines I've completed, covering recon through to root/system.

## Machines

| Machine | OS | Difficulty | Techniques |
|---|---|---|---|
| [Blackfield](blackfield-writeup.md) | Windows (AD / DC) | Hard | SMB null session enum, AS-REP roasting, BloodHound DACL abuse, LSASS dump, `SeBackupPrivilege`, VSC `ntds.dit` extraction, pass-the-hash |
| [Certified](certified-writeup.md) | Windows (AD) | Medium | ACL abuse (WriteOwner → DACL write), Shadow Credentials, ADCS ESC9 (No Security Extension) |
| [Nexus](nexus-writeup.md) | Linux | Easy (rated) / Medium (practice) | Vhost fuzzing, Git history secret mining, authenticated file upload RCE, path traversal via hand-crafted Git objects |

## Structure

Each writeup follows the same format: Overview → Recon → per-service enumeration/exploitation → User → Privilege Escalation → Summary of Techniques → Lessons/Takeaways.
