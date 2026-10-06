"""check_env_switch_names.py -- a switch's READER and its SETTER must agree.

WHY THIS EXISTS (v62, real incident, cost a whole debugging session)
-------------------------------------------------------------------
An environment-variable switch has two halves that live in different files:

  * the READER -- GetEnvironmentVariableW(L"NAME", ...) inside the C++ engine
  * the SETTER -- $env:NAME = ... in a probe .ps1, or `set NAME=` in a .bat

If the two disagree by even ONE letter, nothing errors and nothing warns: the
reader simply never sees the variable, so the switch is silently dead.

v62, when the project was still called "RegGuard": the ARK probe set          # rebrand-keep
`REGUARD_START_TAB` (one G) while the GUI module read `REGGUARD_START_TAB`   # rebrand-keep
(two G's).  So g_activeTab stayed 0, DrawArkPage never ran, and the ARK page
looked completely broken.  It was also why `grep REGUARD_` never found the
reader: "REGUARD" is NOT a substring of "REGGUARD".                          # rebrand-keep

★ v65 (2026-10-05) the project was renamed to "R3 ShieldCore":
  * runtime switches  -> `R3SHIELDCORE_*`
  * build-script switch -> `R3SHIELDCORE_NO_UAC`  (was `REGUARD_NO_UAC`)  # rebrand-keep
  So the one-G / two-G trap itself is GONE.  The *lesson* is not: reader and
  setter must still agree letter-for-letter, and this checker is what enforces
  it.  (The v62 paragraph above is kept verbatim as the historical record.)

Naming convention in this repo (verified 2026-10-05, post-rename):
  R3SHIELDCORE_*       -- runtime debug switches (read by the engine, set by probes)
  R3SHIELDCORE_NO_UAC  -- build-script switch only (build.sh)

Usage: python tools/check_env_switch_names.py
Exit code 1 on any setter that no reader recognises.
"""
import os
import re
import sys

READER_RX = re.compile(r'GetEnvironmentVariable[WA]\s*\(\s*L?"([A-Za-z0-9_]+)"')
PS1_SETTER_RX = re.compile(r'\$env:([A-Za-z0-9_]+)\s*=')
BAT_SETTER_RX = re.compile(r'^\s*set\s+([A-Za-z0-9_]+)\s*=', re.M)
SH_SETTER_RX = re.compile(r'^\s*(?:export\s+)?([A-Z][A-Z0-9_]{3,})=', re.M)

SKIP_DIRS = {'.git', 'dist', 'obj', '_t', 'backup', '.workbuddy-ai',
             'Debug', 'Release', 'verification', 'demo', 'docs'}

# Only names that look like this project's switches.  Without this the .bat/.sh
# scanners drown in ordinary local variables (ENGINE, LOG, PID, RC, ...).
PROJECT_SWITCH_RX = re.compile(r'^(?:REG|REGG)UARD_[A-Z0-9_]+$')


def walk(exts):
    for root, dirs, files in os.walk('.'):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            if f.endswith(exts):
                yield os.path.join(root, f)


def read_text(path):
    try:
        return open(path, 'rb').read().decode('utf-8', 'replace')
    except OSError:
        return ''


def shell_reads(text, name):
    """Is the shell variable actually consumed somewhere in this script?"""
    return (('${%s}' % name) in text
            or ('$%s' % name) in text
            or ('%%%s%%' % name) in text
            or ('${%s:-' % name) in text)


def main():
    readers = {}          # name -> {files}   (C++ GetEnvironmentVariable*)
    for path in walk(('.cpp', '.h')):
        for name in READER_RX.findall(read_text(path)):
            readers.setdefault(name, set()).add(path)

    # A build-script switch may be SET in one script and CONSUMED in another
    # (e.g. R3SHIELDCORE_NO_UAC is set by build_ark_probe.sh and read by build.sh),
    # so look for consumption across all shell files, not just the setter.
    shell_files = list(walk(('.bat', '.cmd', '.sh')))
    shell_all = '\n'.join(read_text(p) for p in shell_files)

    setters = {}          # name -> {files}
    shell_consumed = {}   # name -> {files}
    for path in walk(('.ps1',)):
        for name in PS1_SETTER_RX.findall(read_text(path)):
            if PROJECT_SWITCH_RX.match(name):
                setters.setdefault(name, set()).add(path)
    for path in shell_files:
        text = read_text(path)
        for name in set(BAT_SETTER_RX.findall(text)) | set(SH_SETTER_RX.findall(text)):
            if not PROJECT_SWITCH_RX.match(name):
                continue
            setters.setdefault(name, set()).add(path)
            if shell_reads(shell_all, name):
                shell_consumed.setdefault(name, set()).add(path)

    print('=== readers (engine side: GetEnvironmentVariable*) ===')
    for name in sorted(readers):
        print('   %-34s %s' % (name, ', '.join(sorted(readers[name]))))
    print()
    print('=== switches set by the tooling ===')
    for name in sorted(setters):
        if name in readers:
            mark, how = 'ok   ', 'engine'
        elif name in shell_consumed:
            mark, how = 'ok   ', 'shell'
        else:
            mark, how = 'DEAD ', '---'
        print('   [%s %-6s] %-28s %s'
              % (mark, how, name, ', '.join(sorted(setters[name]))))

    dead = {n: f for n, f in setters.items()
            if n not in readers and n not in shell_consumed}
    print()
    if dead:
        print('FAIL: %d env switch(es) are SET but never READ -- they are dead:'
              % len(dead))
        for name, files in sorted(dead.items()):
            print('   %s   set by: %s' % (name, ', '.join(sorted(files))))
            close = [r for r in list(readers) + list(shell_consumed)
                     if r.replace('_', '') == name.replace('_', '')]
            if close:
                print('        did you mean: %s' % ', '.join(sorted(close)))
        print()
        print('   Fix: make the setter use the exact name the engine reads.')
        return 1
    print('PASS: every project env switch set by the tooling is actually read.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
