# HARNESS-STATUS — KAIDEN QA ADAPTANT 0.2

Обновлено Lead-оркестратором. Статус `INTEGRATED` не равен внешней приёмке.
Статусы: NOT STARTED / IN PROGRESS / BLOCKED / CODE COMPLETE / INTERNAL REVIEW / FIX REQUIRED / INTERNALLY ACCEPTED / INTEGRATED / READY FOR EXTERNAL REVIEW.

База: `0e7e6c20f7a839ffe16047fa11006b1a9ab6cd31` (WP-01 `2beff57`, WP-02 `0e7e6c2` — ACCEPT внешнего статического ревью, независимый Windows runtime Gate не выполнен).
Интеграционная ветка: `feat/adaptant-02-trust-integration`, worktree `C:\Users\gvi\Desktop\QA-ADAPTANT-harness\integration`.

## Baseline (независимый прогон Lead, 13.11.2026)

| Проверка | Факт |
|---|---|
| `npm test` | 78/78 passed, exit 0 |
| `npm run test:races` | 3/3 passed, exit 0 |
| `npm run schemas` | exit 0 |

## Пакеты

| WP | Исполнитель | Ветка | Исходный SHA | Файлы | SHA результата | Тесты | Внутреннее ревью | Интеграция |
|---|---|---|---|---|---|---|---|---|
| WP-01 Identity | Grok | feat/qa-adaptant-02-trust-foundation | 88fc1d7 | packages/trust/identity.mjs, acl.mjs, dpapi.mjs, keygen.mjs | 2beff57 | — | ACCEPT (внешн. статич.) | в базе |
| WP-02 Approval | Grok | feat/qa-adaptant-02-trust-foundation | 2beff57 | packages/trust/approval.mjs | 0e7e6c2 | — | ACCEPT (внешн. статич.) | в базе |
| WP-03 Policy | Agent C | feat/adaptant-02-wp03-policy | 0e7e6c2 | packages/trust/policy.mjs, tests/trust-policy.test.mjs | — | — | — | NOT STARTED |
| WP-04 Environment | Agent A | feat/adaptant-02-wp04-environment | 0e7e6c2 | packages/trust/environment.mjs, adapters/local/*, tests/trust-environment.test.mjs | — | — | — | NOT STARTED |
| WP-05 Anchor | Agent B | feat/adaptant-02-wp05-anchor | 0e7e6c2 | packages/trust/anchor.mjs, anchor-signer.mjs, tests/trust-anchor.test.mjs | — | — | — | NOT STARTED |
| WP-06 Control Integration | Lead | feat/adaptant-02-trust-integration | 0e7e6c2 | apps/control/run.mjs, trusted.mjs, packages/trust/facts.mjs, windows-sid.mjs | — | — | — | NOT STARTED |
| WP-07 Full Trust Verification | Lead + Red Team | — | — | — | — | — | — | NOT STARTED |
| Red Team | Agent D | test/adaptant-02-trust-verification | 0e7e6c2 | tests/redteam/*, docs/harness/REDTEAM-* | — | — | — | — |

## Известные риски

| ID | Риск | Статус |
|---|---|---|
| R-01 | orphaned `guards/<approvalId>.lock` после crash; fail-closed, без авто-восстановления | перенесён в WP-07 |
| R-02 | `keygen.mjs` не проверяет каталоги прогонов без `runDir` | перенесён в WP-07 |
| R-03 | остаточная TOCTOU-гонка «стенд умер между проверкой pid и POST» | принят как ограничение локальной 0.2 |
| R-04 | DPAPI/ACL одного SID не изолируют Control от кода той же учётной записи | граница локальной 0.2, не для Dev/ЦИЗ |

## Журнал решений Lead

- 13.11.2026 — baseline перепроверен независимо; созданы 5 worktree; заморожены контракты `docs/harness/BASELINE-AND-CONTRACTS.md`; созданы 4 субагента (A/B/C/D).
