# ADAPTANT 0.3 COMPATIBILITY И ВЫБОР БАЗЫ (M10)

## 1. Решение по базе

Пакет перенесён на **1a510a5** — полную линию 0.2 (продукт, весь Trust Foundation,
все тесты, включая remediation Luna). Обоснование:

| Вариант | Почему не выбран |
|---|---|
| `main` 59d82d4 | не содержит актуальную реализацию 0.2 (баг Qwen: пакет f995733 был на предке) |
| `41043ad` | отклонённый hardening (R5/R7/R8); trust-pin не переносится как защита |
| `1a510a5` | полная продуктовая линия 0.2 без отклонённого механизма — выбрана |

## 2. Фактическая карта публичного Trust API (1a510a5)

Экспорты `apps/control/trusted.mjs`: `startTrusted`, `observeTrusted`, `cancelTrusted`,
`reconcileTrusted`, `verifyWithTrustedWorker`, `createTrustContext`,
`buildVerificationEnv`, `isTrustedRunnerContext`.
Экспорты `packages/trust/identity.mjs`: `loadTrustRoot`, `createTrustRoot`,
`unwrapPrivateKey`, `signTrustedDocument`, `verifyTrustedDocument`, `publicKeyId`,
`verifyAndAssertPrincipal`.
`packages/trust/approval.mjs`: `signApproval`, `commitApproval`, `verifyApproval`,
`readApprovalState`, `revokeApproval`, `consumeDispatch`.

## 3. Фактические вызовы ADAPTANT 0.3.1 (ветка `feat/adaptant-03-execution-foundation` @ eae1131)

| Файл:строка | Вызов | Влияние v2.1 |
|---|---|---|
| `packages/execution/trusted-adapter.mjs:153` | `startTrusted(record.bundle, options)` | options теряют `trustRoot/secretsDir/anchorKeyPath`; адаптер передаёт approval/root |
| `…:164` | `observeTrusted({root, trustRoot, runId, approvalId})` | `trustRoot` удаляется |
| `…:182` | `cancelTrusted({root, trustRoot, runId, subject, approvalId})` | то же |
| `…:188` | `reconcileTrusted({...options, runId})` | то же |
| `apps/verification/trusted-worker.mjs:180` | `loadTrustRoot(trustRoot)` | в v2 Worker получает trust через TAS-канал; прямой loader запрещён |
| `packages/trust/anchor-signer.mjs:230/240/340/347/436` | `loadTrustRoot(resolvedTrust)` | заменяется TAS-контекстом; standalone signer удаляется |
| `packages/trust/approval.mjs:305` | `loadTrustRoot(request.trustRoot)` | fallback убирается |
| `apps/control/run.mjs:22` | allowlist опций: `trustRoot`, `anchorKeyPath`, `signerPipe`, `trust` | набор сокращается |

Вердикт: интеграция 0.3.1 локализована в `packages/execution/trusted-adapter.mjs` и
требует адаптера-шима; feature-ветка 0.3 не меняется этим пакетом.

## 4. Совместимость контрактов

- Схемы 0.1 и форматы документов 0.2 не переписываются; новые поля аддитивны
  (`verificationKeyId`, `verificationAttestationSha256`, `sessionId`, `trustRegistryVersion`).
- `trustRootId` — непрозрачный id реестра, не путь.
- Старые артефакты читаются, но legacy-PASS не выдаётся (M08).

## 5. R-D воспроизводимость

Инструмент и 15 сценариев R-D публикуются в репозиторий (`tests/audit-remediation/`) вместе
с матрицей; отчёт без опубликованного инструмента не засчитывается (INV-19).
