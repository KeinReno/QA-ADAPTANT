# ADAPTANT 0.3.2 — Final Regression

Рабочий worktree основан на `eae1131cb7ab4c7b994b2e735a5b702840f0a6e9`; ветка `feat/adaptant-032-real-ai-planner`. В проверенной копии HEAD всё ещё указывает на базовый SHA; изменения не закоммичены и не опубликованы.

| Gate | Результат | Детали |
|---|---|---|
| Planner + Execution targeted tests | PASS | После hash, typed event, orphan recovery hardening: `node --test --test-concurrency=1 tests/planner.test.mjs tests/execution.test.mjs`: 22/22. HTTP integration tests inject `syncDirectory` because native Windows directory fsync is unavailable; this does not verify production durability |
| Полный `npm test` | FAIL, требуется повтор | Предшествующий hardening прогон: 251 тест, 193 PASS, 58 FAIL; доверенные E2E падают из-за отсутствующего PowerShell `Get-Acl`, а старые execution doubles тогда ещё не были обновлены. Полный gate после последних изменений не перезапущен |
| Реальный модельный E2E | BLOCKED | Ollama доступна, модель не установлена и `OLLAMA_MODEL` не задан |
| Luna review реализации | REJECT | Последняя независимая проверка подтвердила orphan/hash/event исправления, но выявила P1: Windows default directory fsync завершается EPERM, а parent directory после rename не sync-ится |

Рабочее дерево остаётся без commit/push до поддерживаемого Windows durable directory publication и проверенного реального пути без no-op sync. Решение этапа: **REJECT implementation**, хотя целевые Planner/Execution tests проходят с injected directory-sync hook; это не доказывает работающую model path на текущей Windows-среде и не является ACCEPT этапа.
