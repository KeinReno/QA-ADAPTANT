# 07 — HARNESS STATUS (итоговое состояние пакетов)

Финальная интеграционная ревизия поставки: 520a32c30fda20e10ad9d0bba1e4f7226e8f3a93 (ветка feat/adaptant-02-trust-integration).
Продуктовый код этой ревизии байт-в-байт равен проверенной 21edda60fb9ab2c0815efba775038db52af1f585:
между ними только документы пакета доказательств.
Статус INTEGRATED/INTERNALLY ACCEPTED не равен внешней приёмке WP-08.

| WP | Исполнитель | Ветка | Ревизия | Файлы | Тесты пакета | Внутреннее ревью | Интеграция |
|---|---|---|---|---|---|---|---|
| WP-00 Architecture | Grok + Luna | feat/qa-adaptant-02-trust-foundation | 2815666 | docs/wp-00/ | — | ACCEPT (внешн.) | в базе |
| WP-01 Identity | Grok | feat/qa-adaptant-02-trust-foundation | 2beff57 | packages/trust/identity.mjs, acl.mjs, dpapi.mjs | — | ACCEPT (внешн. статич.) | в базе |
| WP-02 Approval | Grok | feat/qa-adaptant-02-trust-foundation | 0e7e6c2 | packages/trust/approval.mjs | 11 | ACCEPT (внешн. статич.) | в базе |
| WP-03 Policy | Agent C | feat/adaptant-02-wp03-policy | 0731f8f | packages/trust/policy.mjs | 106 | ACCEPT (Agent A, повторно) | INTEGRATED, INTERNALLY ACCEPTED |
| WP-04 Environment | Agent A | feat/adaptant-02-wp04-environment | 9fc9de4 | packages/trust/environment.mjs, adapters/local/server.mjs | 32 | ACCEPT (Agent C, повторно) | INTEGRATED, INTERNALLY ACCEPTED |
| WP-05 Anchor | Agent B | feat/adaptant-02-wp05-anchor | 5c02063 | packages/trust/anchor.mjs, anchor-signer.mjs | 22 | ACCEPT (Agent C, повторно) | INTEGRATED, INTERNALLY ACCEPTED |
| WP-06 Integration | Lead | feat/adaptant-02-trust-integration | 21edda6 | apps/control/run.mjs, trusted.mjs, packages/trust/facts.mjs, windows-sid.mjs | 13 E2E | ACCEPT (Agent B, дельта на 21edda6) | INTEGRATED, INTERNALLY ACCEPTED |
| WP-07 Verification | Lead + Red Team | test/adaptant-02-trust-verification | 216fc02 | tests/redteam/, docs/harness/ | 24 атаки + матрица 34 | — | выполнено на 21edda6 |
| Red Team | Agent D | test/adaptant-02-trust-verification | 216fc02 | tests/redteam/ (волны 1 и 2) | 16 + 24 атаки | — | INTEGRATED |

## Ревью-цепочка (кто кого проверял)

- Agent A (WP-04) ревьюил WP-03: FIX REQUIRED (D-1…D-5) → Agent C исправил → повторно ACCEPT.
- Agent C (WP-03) ревьюил WP-04 и WP-05: FIX REQUIRED (D-01 HIGH в каждом) → авторы исправили → повторно ACCEPT.
- Agent B (WP-05) ревьюил WP-06: FIX REQUIRED (F-01 HIGH — PASS без анкера через adopt/потерю анкера) → Lead исправил → ACCEPT, затем дельта-ACCEPT на финальной ревизии.
- Agent D (Red Team) независимо атаковал базу и интеграцию: волна 1 (16 атак) и волна 2 (24 атаки + матрица 34 строки).
- Ни один автор не принимал собственный пакет.

## Исправленные дефекты высокой важности

| Дефект | Пакет | Суть | Как закрыт |
|---|---|---|---|
| D-01 (WP-05) | WP-05 | publishTerminalVerdict писал PASS без проверки анкера | проверка loadAnchor+verifyAnchorStatement+связки до записи и в existing-ветке; регрессии A/B/C |
| D-01 (WP-04) | WP-04 | нет пути отзыва и смены поколения среды | поколенческая раскладка environments/<envId>/<generation>.json (docs/changes/005) |
| F-01 (WP-06) | WP-06 | startTrusted/reconcileTrusted возвращали PASS из терминального 0.1-результата без анкера | guard assertTrustedPass + регрессии T-11/T-12 |
| D-02 (WP-04) | WP-04 | битая подпись аттестации давала CONTRACT_INVALID | ENVIRONMENT_ATTESTATION_FAILED |
| D-1 (WP-03) | WP-03 | роль проверялась раньше SID | порядок восстановлен + 3 регрессии |
| E-05 (WP-06) | WP-06 | повреждённый реестр сред проецировался в CONTRACT_INVALID | недоступность trust root → INDETERMINATE → BLOCKED AUTH_UNAVAILABLE |
| R-02 | WP-01 (WP-07) | keygen мог писать секреты в каталог прогонов | отказ на путь с сегментом runs + тесты |

## Остаточные риски

Открытых P0 нет. P2: R-01 (fail-closed lock), R-03 (TOCTOU), R-04 (граница одного Windows SID),
R-05 (неподписанный профиль бюджета), R-06/R-07 (границы подписанта). P3: R-08, R-09.
Подробно — 05-KNOWN-RISKS.md.

## Что осталось внешней приёмке (WP-08)

1. Независимый прогон на Windows: npm test, test:races, schemas, сквозной доверенный сценарий.
2. Повтор негативных проб: ложный PASS, второй POST, второй verdict, обход approval, подмена среды,
   adopt старого PASS, потеря анкера.
3. Закрыть 10 TODO-строк матрицы, перечисленных в 03-NEGATIVE-TEST-REPORT.md и REDTEAM-REPORT §9.2.
4. Решение владельца о merge в main (в этой работе merge не выполнялся).