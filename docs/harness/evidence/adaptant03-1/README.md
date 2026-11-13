# Regression evidence: ADAPTANT 0.3.1

- Exact HEAD: `dc2e204a0a2dd6527ca34293ca9a2136b2fa2452`
- Branch: `feat/adaptant-03-execution-foundation`
- Initial worktree: clean
- OS: Windows 11 Pro, build 26100
- PowerShell host: 7.6.9
- Child Windows PowerShell: 5.1.26100.8875
- Node.js: v24.16.0
- npm: 11.13.0

The `npm-test.*` and direct test files without `-windowsps` are the untouched-environment run. They preserve the inherited PowerShell 7 `PSModulePath`; `powershell.exe` 5.1 then fails to auto-load `Microsoft.PowerShell.Security` for `Get-Acl`.

The `*-windowsps.*` files are a second run at the same repository SHA. Before invoking npm/Node, the environment was set to:

```text
PSModulePath=C:\Users\gvi\Documents\WindowsPowerShell\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
```

No repository source or test files were modified between the runs. Empty stderr logs are retained to make stream capture explicit. `*.exit-code.txt` contains the process exit status.

Secret-pattern scan over this evidence directory returned no matches. Test-generated public key identifiers in stdout are public identifiers, not private key material.
