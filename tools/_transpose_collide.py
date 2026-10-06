names = ["smss","csrss","wininit","winlogon","services","lsass","lsaiso",
         "svchost","explorer","taskhostw","dwm","spoolsv","conhost",
         "runtimebroker","dllhost","fontdrvhost","sihost","audiodg",
         "securityhealthservice","msmpeng","nissrv","wmiprvse","wudfhost",
         "searchindexer","searchhost","startmenuexperiencehost",
         "shellexperiencehost","textinputhost","applicationframehost",
         "useroobebroker","ctfmon","taskmgr"]

out = []
for n in names:
    for i in range(len(n) - 1):
        if n[i] == n[i+1]:
            continue
        v = n[:i] + n[i+1] + n[i] + n[i+2:]
        if v != n:
            out.append((n, v))
print("total variants:", len(out))
for src, v in out:
    print(f"{src:28s} -> {v}")
