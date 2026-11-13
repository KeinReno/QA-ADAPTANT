# Regression evidence: ADAPTANT 0.3.1 final

- Base SHA: `dc2e204a0a2dd6527ca34293ca9a2136b2fa2452`
- Final code SHA: `7ba6ad7cb3efb403752c88e1aa35bfc03c41413d`
- Branch: `feat/adaptant-03-execution-foundation`
- Initial worktree before final gate: clean; only this evidence directory was created during capture.
- OS: Windows 11 Pro, version 10.0.26100, build 26100
- PowerShell host: 7.6.9
- Child Windows PowerShell: 5.1.26100.8875
- Node.js: v24.16.0
- npm: 11.13.0

Environment for the final gate:

```text
PSModulePath=C:\Users\gvi\Documents\WindowsPowerShell\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
```

Captured commands:

```text
npm test
node --test tests/execution.test.mjs
node --test tests/adaptant03-e2e.test.mjs
node --test tests/adaptant03-ui.test.mjs
```

Each command has separate `*.stdout.txt`, `*.stderr.txt`, and `*.exit-code.txt` files. Full gate: 326/326 passed, 0 failed, 0 skipped, exit 0. Individual suites: execution 12/12, E2E 5/5, UI 4/4; each exit 0. All stderr files are empty. Test duration for full gate was 640188 ms.

The Windows PowerShell-compatible module path is required because the repository's ACL checks launch Windows PowerShell 5.1 under a PowerShell 7 host. The separate baseline evidence directory records the failure with the inherited PowerShell 7 module path and the successful retry at the exact base SHA.

The evidence files contain complete process streams without editing or line-ending normalization. A secret-pattern scan was performed before commit. Test-generated public key IDs are public identifiers; no private key bytes are part of the evidence.
