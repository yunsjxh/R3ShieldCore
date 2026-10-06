# Global Injection and Hooking Demo

A global injection and hooking example. Injects into all processes and hooks
Windows registry APIs to intercept registry behavior. Also hooks the
`CreateProcessInternalW` function to be able to inject into newly created
processes. Refer to the blog post for details:
[Implementing Global Injection and Hooking in
Windows](https://m417z.com/Implementing-Global-Injection-and-Hooking-in-Windows/).

This fork replaces the original `MessageBoxW` demo with **R3ShieldCore**, a
user-mode registry behavior interceptor with four modes: `log`, `block`, `ask`
(interactive prompt), and `block_all`.

> ⚠️ **This README documents only the original registry-interceptor scope.**
> The project has since grown to **18 monitored object classes** (process /
> thread / driver / network / camera+audio / input hooks / screen / DLL load /
> clipboard / process spawn / service ACL / COM hijack / scheduled task / token
> theft / WMI subscription / host hijack / file) — see the repository-root
> [`README.md`](../README.md) for the full, authoritative picture
> (monitored object classes, interception modes, known limits), and
> [`docs/CODE-REVIEW.md`](../docs/CODE-REVIEW.md) for the architecture review.

## Covered APIs

**Key-level writes — interceptor can deny:**

| API | Why it matters |
|---|---|
| `NtCreateKey` | Creating keys (persistence points) |
| `NtOpenKey` / `NtOpenKeyEx` | Open with write intent |
| `NtSetValueKey` | Writing values |
| `NtDeleteKey` / `NtDeleteValueKey` | Deleting keys/values |
| `NtRenameKey` | Renaming keys |
| `NtSetInformationKey` | Timestamp forgery, WOW64 redirection |

**Hive-level operations — interceptor can deny:**

| API | Why it matters |
|---|---|
| `NtLoadKey` / `NtLoadKeyEx` | Mount an arbitrary hive file onto the tree |
| `NtUnloadKey` / `NtUnloadKeyEx` | Detach a hive subtree |
| `NtSaveKey` / `NtSaveKeyEx` | Export keys to a file (e.g. SAM) |
| `NtRestoreKey` | Overwrite an existing key's content from a file |
| `NtReplaceKey` | Atomic replace (the primitive under `NtRestoreKey`) |

**Record-only (never denied; reads are off by default):**

`NtQueryValueKey`, `NtEnumerateKey`, `NtEnumerateValueKey`, `NtFlushKey`.

## Compiling

Use `build.sh` — it drives `cl.exe` / `link.exe` directly. `devenv.com` only
launches the IDE here, and `MSBuild.exe` is blocked by security policy.

```
bash build.sh              # Release, x86 + x64
bash build.sh Debug        # Debug, x86 + x64
bash build.sh Release x64  # x64 only
```

Two constraints are baked into the script:

* All paths passed to the compiler must be **relative** — the project root
  contains non-ASCII characters, so `cd` into it first.
* `-source-charset:utf-8` is required. The sources are UTF-8 but `cl` defaults
  to CP936 on Chinese Windows, and full-width punctuation in comments eats
  newlines (silently swallowing the next line of code).

## Running

Required files next to the executable:

* `R3 ShieldCore.exe` (recommended) or `R3 ShieldCore-x86.exe`
* `32\r3shieldcore-lib.dll`
* `64\r3shieldcore-lib.dll`
* `r3shieldcore.ini` (optional; safe defaults are used if absent)

**Prefer the x64 engine.** A 32-bit engine passes 32-bit pointers to
`VirtualAllocEx`, so it can only get remote addresses below 4 GB. Chromium-based
applications (Chrome, Edge WebView2, Electron apps) fill that range, and
injection fails with `ERROR_NOT_ENOUGH_MEMORY`. Measured: 92 successes / 47
failures with the x86 engine versus 138 successes / 1 failure with x64. The x64
engine still injects 32-bit processes correctly.

## Configuration (`r3shieldcore.ini`)

```ini
mode=ask             ; log | block | ask
prompt_timeout=30    ; seconds, ask mode only
prompt_default=deny  ; deny | allow — used on timeout or when the UI is unreachable
hook_reads=0         ; 1 = also record read operations (very noisy)
log_all_open=0       ; 1 = record every NtOpenKey regardless of access mask
hook_hive=1          ; hive-level APIs (Load/Save/Restore/Replace); default on
hook_set_info=1      ; NtSetInformationKey; default on
log=r3shieldcore-events.log
exclude=D:\Some\Dir  ; repeatable, prefix match
```

**In `ask` mode, popups only appear when all four hold:** the mode is `ask`,
the calling process is not a system program, it is not excluded, and the
operation is a write. Popups do **not** appear in `log` or `block` mode — this
is the most common source of confusion.

## Seeing it in action

```
<仓库根>\tools\regprobe.exe     # key-level probe
<仓库根>\tools\hiveprobe.exe    # hive-level probe
```

Both must live outside `C:\Windows` to be classified as non-system programs.
Run `regprobe.exe` with the engine in `ask` mode for the quickest way to see a
prompt.
