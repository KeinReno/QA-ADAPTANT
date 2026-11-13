# HARNESS-STATUS — KAIDEN QA ADAPTANT 0.2

Обновлено Lead-оркестратором 13.11.2026. INTEGRATED не равен внешней приёмке.
База: 0e7e6c20f7a839ffe16047fa11006b1a9ab6cd31. Интеграционная ветка: feat/adaptant-02-trust-integration.

## Пакеты

| WP | Исполнитель | Ветка | SHA результата | Тесты пакета | Внутреннее ревью | Интеграция |
|---|---|---|---|---|---|---|
| WP-01 Identity | Grok | feat/qa-adaptant-02-trust-foundation | 2beff57 | — | ACCEPT внешн. статич. | в базе |
| WP-02 Approval | Grok | feat/qa-adaptant-02-trust-foundation | 0e7e6c2 | — | ACCEPT внешн. статич. | в базе |
| WP-03 Policy | Agent C | feat/adaptant-02-wp03-policy | 0731f8f (fix 104ae7c) | 106/106 | ACCEPT (Agent A, повторно) | INTEGRATED |
| WP-04 Environment | Agent A | feat/adaptant-02-wp04-environment | 9fc9de4 (fix 648a2f2) | 32/32 | ACCEPT (Agent C, повторно) | INTEGRATED |
| WP-05 Anchor | Agent B | feat/adaptant-02-wp05-anchor | 5c02063 (fix c168465) | 22/22 | ACCEPT (Agent C, повторно) | INTEGRATED |
| WP-06 Control Integration | Lead | feat/adaptant-02-trust-integration | HEAD ветки | E2E 10/10 | Agent B (в работе) | IN PROGRESS |
| WP-07 Full Trust Verification | Lead + Red Team | — | — | — | — | в работе |
| Red Team | Agent D | test/adaptant-02-trust-verification | 81171a8 (волна 1) | 16 атак + матрица | — | волна 2 в работе |

## Ревью-цепочка

- WP-01/WP-02: внешнее статическое ревью Luna — ACCEPT; независимый Windows runtime Gate не выполнялся (проверяет WP-08).
- WP-03: ревью Agent A → FIX REQUIRED (D-1…D-5) → исправление Agent C → повторно ACCEPT.
- WP-04: ревью Agent C → FIX REQUIRED (D-01 HIGH, D-02…D-04) → исправление Agent A → повторно ACCEPT.
- WP-05: ревью Agent C → FIX REQUIRED (D-01 HIGH — PASS без анкера) → исправление Agent B → повторно ACCEPT.
- WP-06: ревью Agent B, в работе.

## Исправленные дефекты

P0/P1-класса: PASS без проверки анкера при публикации (WP-05 D-01); PASS доверенного входа без анкера через start/reconcile (закрыто в WP-06).

## Известные риски

См. docs/harness/05-KNOWN-RISKS.md. Открытых P0 нет; P2: R-01 (fail-closed lock), R-03 (TOCTOU), R-04 (граница одного SID), R-05 (неподписанный профиль бюджета), R-06/R-07 (границы подписанта). R-02 устранён.

## Решения, требующие внимания владельца

1. Отзыв среды запрещает и новое доверенное чтение (docs/changes/007) — строгий вариант 0.2.
2. Анкер удостоверяет связку и неизменность candidate, но не бизнес-истину (docs/changes/006).
3. Профиль бюджета анкера не подписан (R-05) — нужен отдельный домен подписи после 0.2.
4. Merge в main не выполнялся и требует решения владельца.
