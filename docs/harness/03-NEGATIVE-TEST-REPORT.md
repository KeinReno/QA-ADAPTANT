# 03 — NEGATIVE TEST REPORT

Негативные сценарии выполнялись внутренним Red Team (Agent D) и Lead; продуктовый код под проверкой — финальная
интеграционная ревизия. Матрица: docs/wp-00/06-ACCEPTANCE-MATRIX.md (E-01…E-08, V-01…V-12, L-01…L-09, B-01…B-05).

## Итог по матрице

| Группа | Строк | PASS | TODO | FAIL |
|---|---|---|---|---|
| E (среда) | 8 | E-01,E-02,E-03,E-05,E-06,E-07,E-08 | E-04 | 0 |
| V (evidence/анкер) | 12 | V-01,V-02,V-03,V-04,V-07,V-08,V-09,V-11 | V-05,V-06,V-10,V-12 | 0 |
| L (жизненный цикл) | 9 | L-03,L-06,L-07,L-08,L-09 | L-01,L-02,L-04,L-05 | 0 |
| B (бизнес-ограничения) | 5 | B-01,B-03,B-04,B-05 | B-02 | 0 |
| **Итого** | **34** | **24** | **10** | **0** |

Каждая PASS-строка подтверждена отдельным воспроизводимым скриптом tests/redteam/rt2-*.mjs с JSON-вердиктом
и exit code; каркас run-matrix.mjs запускает скрипты и переносит вердикт.

TODO — это «нечем проверить в текущем каркасе», а не «всё хорошо». Причины и что нужно для проверки —
docs/harness/REDTEAM-REPORT.md §9.2. Внешняя приёмка должна закрыть эти строки отдельными сценариями
(crash-точки, выдача credentialRef, идемпотентная публикация анкера, подложный candidate → signer,
неполный terminal-choice, две одновременные доверенные попытки, cancel до INTENT, падение после POST
на доверенном пути, повторный reconcile терминального, тот же fixture).

## Ключевые разрывы 0.2 на базе и их закрытие

| ID | Суть | Статус |
|---|---|---|
| GAP-01 | Ложный PASS без POST/approval/анкера принимался старым входом | **Закрыт**: без подписанта — INCONCLUSIVE/EVIDENCE_MISSING и observeTrusted.passed=false; подделанный terminal-choice, чужой анкер, подмена verdict/терминального коммита и полностью сфабрикованная цепочка PASS без POST → observeTrusted inconsistent/INTEGRITY_ERROR; start/reconcile доверенного входа выбрасывают INTEGRITY_ERROR (T-11, T-12) |
| GAP-02 | Подмена среды копией environmentId/fingerprint на другом сокете | **Закрыт**: зеркало с копией полей, сервер без ключа, подмена на другой реальный стенд на том же origin → BLOCKED ENVIRONMENT_CHANGED, rogue mutationCount=0, POST/intent нет |
| GAP-03 | «Секрет не выдан до ALLOW» на базе проверить нечем | **Закрыт**: на T-A отказе Browser не стартует (событий READY нет, browser.pid нет), Bearer и ключи в runDir отсутствуют (T-10) |
| L-08 | Старый вход мог обойти Policy | **Закрыт**: start() отвергает approvalId/approval/trustRoot/adapter/adapterId/standPublicKey/signerPipe кодом CONTRACT_INVALID, мутаций 0 |

## Атаки на доверенный путь (WP-06)

| Атака | Факт |
|---|---|
| ACK без расхода approval | невозможно: T-B без durable consumption не выдаёт ACK, POST=0 |
| Второй POST / повторная мутация | невозможно: intent ровно один, request ровно один, второй POST отсутствует |
| Второй терминальный verdict | невозможно: журнал evidence запрещает второй verdict; повторный reconcile не пишет |
| Секрет/Bearer до ALLOW | Browser не стартует на отказе; в снапшотах и evidence секретов нет |
| Чужой SID | BLOCKED AUTH_UNAVAILABLE, мутаций 0 |
| Чужой standPublicKey / подмена среды | BLOCKED ENVIRONMENT_CHANGED, мутаций 0 |
| approval на другие входы/операцию/fixture/эффекты | BLOCKED CONTRACT_INVALID, мутаций 0 |
| Просроченный/отозванный approval | BLOCKED, мутаций 0 |
| Повторное использование approvalId на другом runId | BLOCKED, расход не создаётся |
| Подложный PASS через adopt/старый вход | INTEGRITY_ERROR, PASS не показывается |
| Потеря анкера после публикации | start/reconcile → INTEGRITY_ERROR, observeTrusted.passed=false |
| Повреждённый реестр сред | BLOCKED AUTH_UNAVAILABLE (E-05), мутаций 0 |

## Подтверждённые остаточные риски

- R-01 (P2): SIGKILL внутри withGuard оставляет guards/<approvalId>.lock; revoke/consume по этому approval
  отказывают через ~5 с; второго ACK/POST и расхода нет. Слепое удаление lock запрещено (открывает окно
  второго dispatch). Проверено tests/trust-r01.test.mjs и rt-16/rt2-r01.
- R-02 устранён (keygen отвергает пути с сегментом runs).
- R-03, R-04, R-05, R-06, R-07 — принятые P2/P3-границы, см. 05-KNOWN-RISKS.md.

## Открытые P0/P1

По состоянию финальной ревизии подтверждённых P0/P1 нет.
