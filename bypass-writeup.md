# HTB Challenge: Bypass — Writeup

**Category:** Reversing
**Difficulty:** Easy
**Techniques:** .NET/Mono binary identification, IL disassembly/reassembly (`monodis`/`ilasm`), IL-level logic patching (always-true return, unconditional branch removal)

---

## Overview

Bypass is a small Windows console application gating a flag behind two sequential checks: a username/password prompt, followed by a secret-key prompt. Static decompilation showed the first check was hardcoded to always fail regardless of input, and the second performed a real string comparison against a value that wasn't easily recoverable statically. Both were solved not by finding the correct credentials, but by patching the compiled IL bytecode directly — first to force the always-false check to return `true`, then to strip out the conditional branch on the secret-key comparison so any input is accepted.

---

## Files Provided

A single zip containing `Bypass.exe`.

## Identifying the Binary

```bash
file Bypass.exe
```

```
Bypass.exe: PE32 executable for MS Windows 4.00 (console), Intel i386 Mono/.Net assembly, 3 sections
```

Confirmed as a .NET/Mono assembly rather than native x86 — the right tool here is a .NET decompiler (ILSpy), not a disassembler like Ghidra/IDA.

---

## Static Analysis (ILSpy)

Opening `Bypass.exe` in ILSpy showed a single class with heavily obfuscated (purely numeric) class, method, and field names — no `Main`, no meaningful identifiers anywhere. The entry-point-looking method had this shape:

```csharp
public static void 0()
{
    if (1())
    {
        2();
        return;
    }
    Console.WriteLine(5.0);
    0();
}
```

- Method `1()` — prompts for and reads a username/password, but its return value never actually depends on the input.
- Method `2()` — prompts for a secret key and does depend on the input.

String literals rendered oddly as dotted decimals (e.g. `5.1`, `5.3`) — this turned out to be a decompiler artifact of the obfuscation, not string encryption: the "strings" class was itself named `5`, and its fields were named `0`, `1`, `2`, etc., so field accesses like `5::1` got pretty-printed by ILSpy as `5.1`.

---

## Dynamic Analysis

Running the binary directly confirmed the static read:

```bash
mono Bypass.exe
```

```
Enter a username: test
Enter a password: test
Wrong username and/or password
```

No input combination succeeded — consistent with method `1()`'s return value being unconditional.

---

## Patch 1 — Bypassing the Username/Password Check

Disassembled the binary to IL text:

```bash
monodis Bypass.exe > bypass.il
monodis --mresources Bypass.exe   # extracts the embedded resource ILASM references by filename
```

Method `1()`'s IL tail:

```
IL_0022:  stloc.1
IL_0023:  ldc.i4.0      // loads the constant 0 (false) — always, regardless of input
IL_0024:  stloc.2
IL_0025:  br.s IL_0027
IL_0027:  ldloc.2
IL_0028:  ret
```

`ldc.i4.0` unconditionally pushes `0` (`false`) as the method's return value. Changed to `ldc.i4.1` so the method always returns `true`.

---

## Reassembly Obstacles

`ilasm` (the IL assembler, part of `mono-complete`) refused to reassemble the raw `monodis` output as-is, due to the obfuscation's numeric-only identifiers colliding with `ilasm`'s grammar for raw metadata tokens (e.g. `class 5::0()` was ambiguously parsed). Each bare-digit identifier — class names, method names, field names, and parameter names — had to be wrapped in single quotes (e.g. `class '5'::'0'()`) throughout the `.il` file to disambiguate them as identifiers.

Separately, `monodis` failed to decode one `literal` constant field's value and emitted the placeholder text `not found` in its place — invalid IL syntax on its own. Since the field wasn't referenced anywhere else in the disassembly, it was safely given a dummy value (`int32(0)`).

With both fixed, reassembly succeeded:

```bash
ilasm /exe /output:bypass.exe bypass.il
```

```
Operation completed successfully
```

Testing confirmed the username/password check now always passed, advancing to the secret-key prompt.

---

## Patch 2 — Bypassing the Secret-Key Check

Method `2()`'s IL:

```
IL_0001:  ldsfld string '5'::'3'      // the actual secret, loaded into V_0
...
IL_0012:  call string [...]::ReadLine()   // user input, loaded into V_1
IL_0018:  ldloc.0
IL_0019:  ldloc.1
IL_001a:  call bool string::op_Equality(string, string)
IL_001f:  stloc.2
IL_0020:  ldloc.2
IL_0021:  brfalse.s IL_0041     // if input != secret, jump to the failure branch
IL_0023:  ...                   // success branch (prints the flag) — falls through here otherwise
```

Unlike method `1()`, this comparison was real — `op_Equality` genuinely checked the input against a hardcoded secret. Rather than recover that secret, the conditional branch itself was removed: `brfalse.s IL_0041` was replaced with a plain `pop` (discarding the boolean off the evaluation stack without branching), so execution falls through to the success branch unconditionally, regardless of what's typed at the secret-key prompt.

Reassembled the same way as before, then ran the patched binary and entered arbitrary text at both prompts:

```
$ mono bypass.exe
Enter a username: dark
Enter a password: dark
Please Enter the secret Key: dark
Nice here is the Flag:HTB{SuP3rC00lFL4g}
```

---

## Flag

```
HTB{SuP3rC00lFL4g}
```

---

## Summary of Techniques

| Stage | Technique |
|---|---|
| Recon | `file` to identify a Mono/.NET assembly vs. native PE |
| Static analysis | ILSpy decompilation; recognizing numeric-identifier obfuscation as a decompiler-naming artifact rather than string encryption |
| Dynamic analysis | Running the binary directly (`mono`) to confirm static findings and observe real prompts/behavior |
| Tooling | `monodis`/`ilasm` round-trip (disassemble → hand-edit IL → reassemble) as a Linux-native alternative to a GUI assembly editor (dnSpy) |
| Patch 1 | Flipping a hardcoded `ldc.i4.0` (false) to `ldc.i4.1` (true) to defeat an always-failing check |
| Patch 2 | Replacing a conditional branch (`brfalse.s`) with an unconditional `pop`, removing a genuine string-equality gate entirely rather than recovering the compared secret |

---

## Lessons / Takeaways

- `file` is the fastest way to tell a native PE from a .NET/Mono assembly, and dictates the whole toolchain choice (decompiler vs. disassembler).
- Decompiled identifiers that render as odd tokens (e.g. numbers where strings are expected) are sometimes just obfuscated naming colliding with the decompiler's pretty-printer, not evidence of actual encryption — worth confirming with dynamic analysis before assuming a harder problem exists.
- Not every "auth check" needs its secret recovered — if the check's *outcome* is all that matters, patching the branch that consumes the comparison result is often simpler than deriving the compared value.
- `monodis`/`ilasm` is a fully Linux-native round-trip for .NET IL patching, avoiding the need for a Windows-only GUI tool (dnSpy) or a Wine + wine-mono + 32-bit multiarch setup — useful when a full GUI toolchain isn't readily available.
- Heavily obfuscated (e.g. all-numeric) symbol names can break naive disassemble/reassemble round-trips even when the underlying bytecode edit is trivial; expect to need to disambiguate identifiers from raw metadata tokens by quoting them.
