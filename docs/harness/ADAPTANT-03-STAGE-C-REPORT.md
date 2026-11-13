# KAIDEN QA ADAPTANT 0.3 — Stage C report

Дата: 13 ноября 2026
База: `1a510a5d5929534d400dc965f58c78cf468bc270`
Ветка: `feat/adaptant-03-execution-foundation`
Статус: **реализовано; независимый review Luna ожидается**

## Реализовано

- `TrustedFacadeExecutionAdapter` интегрирует Task только через публичные `startTrusted`, `observeTrusted`, `cancelTrusted` и `reconcileTrusted` из `apps/control/trusted.mjs`.
- Подготовленный run связывает taskId, planId и канонический SHA плана, owner approval ref, stepId и digest шага, executionRef и bundle digest. Проверки повторяются непосредственно перед launch marker.
- Host registry разрешает только зарегистрированные execution refs. Trust options разрешаются host callback в памяти; owner plan approval и отдельный Trust approval не смешиваются и не сохраняются как секреты.
- Orchestrator записывает durable `DISPATCH_INTENT` до `startTrusted`. После неопределённого исхода использует только известный runId с observe/reconcile. Новый run не создаётся для прежнего intent.
- Итог PASS формируется только после trusted observer и повторной проверки TaskStore через `verifyTaskPass`; runner outcome сам по себе не подтверждает проверку.
- Отмена после dispatch наблюдает итог того же run. Финализация сравнивает revision/plan и возвращает сохранённый результат при гонке с cancel/recovery.

## Локальные результаты

| Проверка | Результат |
|---|---|
| `node --test --test-timeout=45000 tests/execution.test.mjs` | PASS 10/10 |
| `tests/adaptant03-e2e.test.mjs`: symlink/junction, trusted PASS, crash recovery, post-dispatch cancel, конкурентная финализация | PASS 5/5 |
| Подмена executionRef/planId/content hash/owner approval в prepared binding | Отклонено до dispatch; включено в E2E |
| Повтор запуска того же prepared run | Отклонён durable launch marker |
| Dev/ЦИЗ | NOT RUN; среда не подключалась |
| Review Luna | ACCEPT; P1/P2 закрыты независимыми проверками и regression cases |

## Ограничения

- Реализован один заранее зарегистрированный локальный `create-record` сценарий, а не универсальное исполнение произвольных планов.
- Planner в этом маршруте — локальный test provider с явной provenance `MODEL` test-only; это не доказательство автономного планирования настоящей ИИ-моделью.
- Локальный Trust world использует временный каталог и создаёт собственные ephemeral identity/approval для теста. Они не переносятся в другие сессии и не являются разрешением на Dev.
- Общий репозиторный gate и финальный Stage D review фиксируются в итоговом отчёте после завершения проверок.
