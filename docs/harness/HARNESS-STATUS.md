# HARNESS-STATUS — KAIDEN QA ADAPTANT 0.2

Обновлено Lead-оркестратором 13.11.2026. Статус INTEGRATED не равен внешней приёмке.
База: `0e7e6c20f7a839ffe16047fa11006b1a9ab6cd31` (WP-01 `2beff57`, WP-02 `0e7e6c2` — ACCEPT внешнего статического ревью).
Интеграционная ветка: `feat/adaptant-02-trust-integration`, worktree `C:\Users\gvi\Desktop\QA-ADAPTANT-harness\integration`.
Независимый baseline Lead: `npm test` 78/78, `npm run test:races` 3/3, `npm run schemas` exit 0.

## Пакеты

| WP | Исполнитель | Ветка | SHA результата | Тесты | Внутреннее ревью | Интеграция |
|---|---|---|---|---|---|---|
| WP-01 Identity | Grok | feat/qa-adaptant-02-trust-foundation | 2beff57 | — | ACCEPT внешн. статич. | в базе |
| WP-02 Approval | Grok | feat/qa-adaptant-02-trust-foundation | 0e7e6c2 | — | ACCEPT внешн. статич. | в базе |
| WP-03 Policy | Agent C | feat/adaptant-02-wp03-policy | fc2a593 (реализация 0099653) | 99/99 | Lead: принято; Red Team волна 2 | INTEGRATED (e220847-предшествующий merge) |
| WP-04 Environment | Agent A | feat/adaptant-02-wp04-environment | e76d79d | 24/24 | Agent C: FIX REQUIRED (D-01 HIGH, D-02 MEDIUM) | INTEGRATED, идёт исправление |
| WP-05 Anchor | Agent B | feat/adaptant-02-wp05-anchor | 03655e0 | 19/19 | Agent C: в работе | INTEGRATED |
| WP-06 Control Integration | Lead | feat/adaptant-02-trust-integration | текущий HEAD ветки | E2E 9 сценариев | Agent B: в работе | IN PROGRESS |
| WP-07 Full Trust Verification | Lead + Red Team | — | — | — | — | NOT STARTED |
| Red Team волна 1 | Agent D | test/adaptant-02-trust-verification | 81171a8 | 16 атак: 12 PASS / 4 INCONCLUSIVE; матрица 34 строки | — | принято в работу |

## Факты интеграции (по ходу)

- Точки T-A…T-D врезаны в `apps/control/run.mjs`; старый вход отвергает аргументы доверия (L-08).
- Сквозной доверенный прогон: живой стенд 127.0.0.1, реальный Chromium, один POST, независимый GET, анкер в named pipe, PASS только с анкером; без подписанта — единственный INCONCLUSIVE/EVIDENCE_MISSING и один POST.
- Форма facts PDP — ровно 11 ключей §5.3; расхождение даёт DENY CONTRACT_INVALID, а не пропуск.
- Подписант анкера проверяет связку сам (approval, consumption, снапшоты, журнал, candidate) и не принимает хеш от вызывающего.
- docs/changes/004 (раскладка trust), docs/changes/005 (поколения и отзыв среды).

## Известные риски

| ID | Риск | Severity | Статус |
|---|---|---|---|
| R-01 | orphaned `guards/<approvalId>.lock` после SIGKILL; fail-closed, без авто-восстановления | P2 (подтверждён Red Team) | WP-07: проверка + фиксация ограничения |
| R-02 | `keygen.mjs` позволяет `--secrets <runDir>\secrets` | P2 (подтверждён Red Team) | WP-07: минимальное исправление |
| R-03 | остаточная TOCTOU-гонка «стенд умер между проверкой pid и POST» | ограничение локальной 0.2 | зафиксировано |
| R-04 | DPAPI/ACL одного SID не изолируют Control от кода той же учётной записи | граница локальной 0.2 | зафиксировано |
| R-05 | `trustRoot/profile.json` (anchorBudgetMs) не подписан криптографически | P2 | docs/changes/004 §2.6 |
| D-01 | нет пути отзыва/смены поколения среды | HIGH → исправляется | docs/changes/005, Agent A |
| D-02 | прямой `verifyEnvironmentAttestation` на битую подпись даёт CONTRACT_INVALID | MEDIUM → исправляется | Agent A |

## Журнал

- 13.11.2026 — baseline перепроверен; 5 worktree; контракты заморожены; 4 субагента.
- 13.11.2026 — WP-03 принят Lead (99/99), интегрирован.
- 13.11.2026 — WP-04 интегрирован, ревью Agent C дало FIX REQUIRED, исправление D-01/D-02 запущено.
- 13.11.2026 — WP-05 интегрирован, ушёл на ревью Agent C.
- 13.11.2026 — WP-06: первый сквозной доверенный PASS с анкером и один POST получен; E2E-набор дописывается.
- 13.11.2026 — Red Team волна 1: R-01/R-02 подтверждены фактически, GAP-01/GAP-02 назначены к проверке на интеграции.
