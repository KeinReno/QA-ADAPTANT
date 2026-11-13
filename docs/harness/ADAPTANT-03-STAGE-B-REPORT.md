# KAIDEN QA ADAPTANT 0.3 — Stage B report

Дата: 13 ноября 2026  
Ветка: `feat/adaptant-03-execution-foundation`  
База: `1a510a5d5929534d400dc965f58c78cf468bc270`  
Статус Stage B: **IMPLEMENTED; Luna ACCEPT; общий репозиторный gate ограничен ошибкой окружения**

## Реализовано

- Строгие Task/Plan/Step/Result/Event схемы, переходы состояния, проверка DAG и топологическая сортировка.
- TaskStore в отдельном namespace: точный оригинальный запрос, версионируемые immutable plans, hash-chained journal с состоянием в каждом событии, write-ahead append и восстановление snapshot из журнала. CAS защищает подтверждение владельца от устаревшей версии плана.
- PlannerProvider с явным `MODEL`/`MOCK` происхождением, недоступным provider без fallback, strict parsing, таймаутом, stream byte limit и отменой по AbortSignal.
- Host-side approval requirements; execution refs допускаются только на пересечении зарегистрированного каталога и `approvedScenarioRefs`. Общие `contextRefs` не считаются утверждёнными сценариями.
- Fail-closed PASS gate: структурные условия проверяются TaskStore, а отдельный `verifyTaskPass` обязан повторно подтвердить run/evidence через trusted observer. Без verifier PASS недоступен. Подключение production verifier к публичному Trust facade остаётся обязательной частью Stage C.
- Recovery изолирует повреждённые журналы, проверяет текущий immutable plan и не делает повторный dispatch. До dispatch повреждённый план блокирует Task; после dispatch сохраняет `INCONCLUSIVE`.
- Проверка capability против конкретного adapter и точного соответствия пар `{ruleId, requirementId}`.
- Архитектурное изменение задокументировано в `docs/changes/010-adaptant-03-result-acceptance-gate.md`; Trust Foundation 0.2 не изменялась.

## Результаты проверок

| Проверка | Результат | Примечание |
|---|---|---|
| Stage B unit/contract/recovery: `node --test --test-timeout=45000 tests/execution.test.mjs` | **PASS 10/10** | Последний запуск после всех правок |
| `git diff --check` | **PASS** | Нет whitespace ошибок |
| Независимый review Luna | **ACCEPT** | Финальный повторный review; замечаний не осталось |
| Полный `npm test` gate | **FAIL / ENVIRONMENT: 184 PASS, 46 FAIL** | Trust тесты не могут загрузить `Microsoft.PowerShell.Security`; PowerShell не предоставляет `Get-Acl` из-за сбоя импорта модуля. Исполнительная причина окружения подтверждалась отдельно. Trust код не менялся. |
| Локальный браузер | **NOT RUN** | Stage B не содержит UI/browser интеграции |
| Настоящий Dev | **NOT RUN** | В этом этапе Dev не использовался |

Полный gate нельзя считать PASS. Его отказ отделён от Stage B целевых тестов; требуется исправное PowerShell окружение и отдельный повтор общего gate.

## Незавершённое

- Stage C: адаптер только через публичный trusted facade; подключить `verifyTaskPass` к независимому trusted observer/evidence verifier; проверить capability/ref/owner и отдельный Trust approval до dispatch; обеспечить recovery без повторной мутации.
- Stage D: минимальный локальный интерфейс и интеграционный/E2E прогон только с безопасным локальным owner-approved fixture. Настоящий Dev не запускался.
- Полный общий test gate требуется повторить после исправления PowerShell Security module в локальном окружении.
