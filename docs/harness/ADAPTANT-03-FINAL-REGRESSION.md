# ADAPTANT 0.3 — регрессия baseline и финального результата

Дата: 2026-11-14

Базовый commit: `dc2e204a0a2dd6527ca34293ca9a2136b2fa2452`

Ветка: `feat/adaptant-03-execution-foundation`
Worktree: `C:\Users\gvi\.codex\worktrees\adaptant-03-execution\QA-ADAPTANT`

## Исходное состояние

Перед запуском regression gate HEAD совпадал с указанным SHA, ветка была синхронизирована с `origin/feat/adaptant-03-execution-foundation`, а worktree был чистым. Во время запуска изменялись только файлы доказательств в `docs/harness/evidence/adaptant03-1/`; файлы приложения и Trust Foundation не менялись.

Среда: Windows 11 Pro build 26100, PowerShell 7.6.9, Windows PowerShell 5.1.26100.8875, Node.js v24.16.0, npm 11.13.0. Команда и параметры исправленного повтора сохранены в [evidence README](evidence/adaptant03-1/README.md).

## Результаты

| Проверка | Окружение | Результат |
|---|---|---|
| `npm test` | исходное окружение без изменений | exit 1; PowerShell 5.1 не смог автоматически загрузить `Microsoft.PowerShell.Security` из `PSModulePath`, унаследованного от PowerShell 7; Trusted ACL/E2E проверки завершились ошибками `TRUST_STORE_UNAVAILABLE` |
| `npm test` | тот же SHA, `PSModulePath` ограничен штатными каталогами Windows PowerShell 5.1 | exit 0; 322/322, 0 failed, 0 skipped |
| `node --test --test-timeout=45000 tests/execution.test.mjs` | исходное окружение | exit 0; 10/10 |
| `node --test --test-timeout=45000 tests/execution.test.mjs` | исправленный `PSModulePath` | exit 0; 10/10 |
| `node --test --test-timeout=180000 tests/adaptant03-e2e.test.mjs` | исходное окружение | exit 1 из-за `TRUST_STORE_UNAVAILABLE` при подготовке Windows ACL |
| `node --test --test-timeout=180000 tests/adaptant03-e2e.test.mjs` | исправленный `PSModulePath` | exit 0; 5/5 |
| `node --test --test-timeout=180000 tests/adaptant03-ui.test.mjs` | исходное окружение | exit 1 из-за `TRUST_STORE_UNAVAILABLE` при подготовке Windows ACL |
| `node --test --test-timeout=180000 tests/adaptant03-ui.test.mjs` | исправленный `PSModulePath` | exit 0; 2/2 |

Полные stdout/stderr, отдельные коды возврата и Windows PowerShell path сохранены в `docs/harness/evidence/adaptant03-1/`. Файлы включают обе последовательности: исходный gate без изменения окружения и явно отделённый повтор с исправленным путём модулей. Повтор менял только окружение процесса, не код или входные данные.

## Вывод и границы

На точном опубликованном snapshot все 322 теста полного gate и три требуемых набора проходят после настройки совместимого `PSModulePath` для дочернего Windows PowerShell 5.1. В исходном пользовательском окружении `npm test` не проходит без такой настройки; это ограничение воспроизводимости окружения должно оставаться видимым при последующих запусках. В ходе gate Trust Foundation не изменялась.

В `npm test` включены `execution`, `adaptant03-e2e`, `adaptant03-ui`, top-level recovery tests и top-level race tests. Отдельные скрипты внутри `tests/redteam/` сам `scripts/run-tests.mjs gate` не перечисляет; дополнительные recovery/race-наборы, относящиеся к gate, были включены.

## Финальный gate после изменений LUNA-03.1

Базовый snapshot gate выше предшествует работе. Для приёмки кода дополнительно выполнен полный gate после provenance и UI исправлений.

- Final code SHA: `7ba6ad7cb3efb403752c88e1aa35bfc03c41413d`.
- Branch: `feat/adaptant-03-execution-foundation`; перед запуском финального gate исходники были закоммичены, worktree чистый. Ветка не объединялась с `main`, WP-08 или remediation.
- OS/Node/npm/PowerShell версии совпадают с таблицей выше. `PSModulePath` ограничен штатными путями Windows PowerShell 5.1 для запуска Windows ACL checks из дочернего `powershell.exe`.
- `npm test`: exit 0; 326/326 passed, 0 failed, 0 skipped; 640188 ms.
- `node --test tests/execution.test.mjs`: exit 0; 12/12 passed.
- `node --test tests/adaptant03-e2e.test.mjs`: exit 0; 5/5 passed.
- `node --test tests/adaptant03-ui.test.mjs`: exit 0; 4/4 passed.

Полные stdout/stderr и отдельные exit code сохранены в [финальных логах](evidence/adaptant03-2/README.md). Все stderr файлы пусты. Исходный сценарий без корректировки `PSModulePath` на финальном коде повторно не запускался: исходная проблема окружения воспроизведена и записана на baseline SHA выше.

## Границы результата

Финальный gate проверяет unit и локальные browser/Trust test worlds. Dev environment не запускалась. Реальный AI backend не подключён, а тесты подтверждают явный `MOCK`/`MODEL` контракт, не автономное планирование. Совместимость с будущей Trust remediation описана как contract test plan; новая remediation не переносилась и независимым аудитом Qwen здесь не принималась. UI защита от другого процесса того же Windows SID не доказана; см. [UI security review](ADAPTANT-03-UI-SECURITY-REVIEW.md).
