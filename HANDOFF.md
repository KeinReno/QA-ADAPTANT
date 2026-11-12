# Передача работы после завершения локального ядра

Путь: `C:/Users/gvi/Desktop/QA-ADAPTANT`. Источник требований: `docs/sources/master-plan.ru.txt`. Старые QA и ЦИЗ — только источники анализа, не менять и не импортировать в runtime.

## Что реально работает

- Автономный Node.js 24 ESM проект без зависимости от старых QA.
- Control Plane, отдельные Browser Worker и Verification Worker, immutable snapshots, hash-chained events/evidence.
- Публичные `start / observe / cancel / reconcile` в `apps/control/run.mjs` и CLI в `apps/control/cli.mjs`.
- Локальный fixture, фабрика bundle, demo и fault injection в `adapters/local/`.
- Один разрешённый POST, durable intent/ACK, request→response→independent-read provenance, bounded polling и fail-closed verdicts.
- Повторный START без Browser, восстановление в новом процессе без повторной мутации, cancel до/после dispatch, fixture lock и явный отказ cleanup.
- Browser сам проверяет frozen bundle/manifest hash до Chromium; Verifier сам перечитывает bytes/hashes и выполняет GET.

## Проверка

Команды на этой машине, Node.js **v24.16.0**, 12 ноября 2026. Исполнитель этой стабилизации — Grok. Результат не является независимой приёмкой.

```powershell
cd C:\Users\gvi\Desktop\QA-ADAPTANT
node --version
node --test --test-timeout=45000 tests/*.test.mjs
node scripts/demo-local.mjs
```

Фактически:

- `node --version` → `v24.16.0`.
- Полный локальный набор → **40 passed, 0 failed**, exit code 0, около 32 с. Состав: прежние контрактные, fault и lifecycle тесты плюс 7 регрессий `tests/review-grok.test.mjs`.
- `node scripts/demo-local.mjs` → exit code 0, вердикт `PASS` / `NONE`, `mutationCount=1`, `independentReadCount=1`. Каталог прогона: `data/demo-1794491933469/runs/demo-1794491933469`.

До исправления на том же Node v24.16.0 Verification Worker печатал `Assertion failed: !(handle->flags & UV_HANDLE_CLOSING), file src\win\async.c, line 94` и завершался ненулевым кодом. Control публиковал `INCONCLUSIVE` / `WORKER_LOST` и не сохранял уже полученный PASS. Это не зависание forged-PASS: проверка обрывалась примерно за 1,8 с на первом `start`. Ненулевой код по-прежнему запрещает PASS. Процесс теперь выставляет `exitCode` и закрывает IPC после доставки сообщения, без `process.exit` внутри завершения IPC.

Подробности и граница приёмки — `ACCEPTANCE-REPORT.md`. Dev не открывался, CIZ Adapter отсутствует, Luna этот runtime не проверяла. Не утверждать независимую приёмку по этому handoff.

## Статус владельца

12 ноября 2026 STELLA зафиксировала локальное ядро как **кандидат на приёмку 0.1**, не как принятый релиз. Архитектуру до независимой приёмки не расширять. Полноценные мутации ЦИЗ остаются закрытыми. CIZ Adapter и Intelligence Worker не начинать, пока независимый проверяющий, не писавший эти исправления, не примет ядро.

Контрольная точка — первый коммит этого репозитория. `data/`, `node_modules/` и `.env` в него не входят.

## Что должен подтвердить независимый проверяющий

Исполнительские 40/40 и demo PASS не заменяют эту проверку.

| Направление | Что подтвердить |
|---|---|
| Повторяемость | Чистая установка, 40 тестов, demo PASS |
| Целостность | Поддельный PASS, повреждённые evidence, повторный START |
| Жизненный цикл | CANCEL, crash/restart, orphan Browser, lock |
| Авторизация | Bearer token, идемпотентность, безопасный reconcile после перезапуска |

Токен локального fixture создаётся в памяти стенда и передаётся дочерним процессам только через `fixtureToken` / `QA_ADAPTANT_FIXTURE_TOKEN`. В snapshot demo его нет: `authorization` там — актор и scope, `credentialRef` равен `local:none`. Тест перезапуска Control передаёт тот же токен новому процессу явно. Из каталога прогона токен не восстанавливается. Проверяющий должен убедиться, что без этого окружения новый Control не публикует PASS и не записывает секрет в evidence, а с тем же токеном независимое чтение остаётся возможным.

## Следующий пакет после приёмки

1. Только read-only исследование Dev и подтверждение environment/version/data.
2. Явно согласовать accounts, fixture namespace и разрешённую операцию создания задания. Склад, платность и закрытие не разрешать этим этапом.
3. Расширить контракт/adapter для CIZ через `docs/changes` и review, затем доказать OP-B независимым чтением.
4. Только после принятого 0.1 готовить Intelligence Worker. Исходный пункт 7 и DRAFT не менять на месте.

Approval владельца на пункт 7 отсутствует. Различать `task_id`, `action_id`, справочную работу, progress, equipment и складскую позицию. GET задания для verifier должен использовать `ack_notifications=false`.
