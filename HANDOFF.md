# Передача работы после независимого REJECT

Путь: `C:/Users/gvi/Desktop/QA-ADAPTANT`. Источник требований: `docs/sources/master-plan.ru.txt`. Старые QA и ЦИЗ — только источники анализа, не менять и не импортировать в runtime.

Независимый аудит зафиксировал **REJECT**. Исполнитель — Grok. Этот документ не является приёмкой. CIZ Adapter и Intelligence Worker не начаты.

## Что закрыто после REJECT

Пакеты WP-A, WP-B и WP-C сделаны без изменения схем 0.1.0. Уточнение: `docs/changes/002-ownership-evidence-trust.md`.

- Владелец пишется в snapshot до журнала и до сетевого preflight. Живой владелец не даёт чужому процессу опубликовать терминальный verdict.
- Привязка `(environmentId, fixtureId) → runId` лежит в `fixtures/` и переживает удаление `locks/` и `leases/`. Новый runId с тем же fixtureId останавливается до POST.
- Локальный стенд не считает повтор того же `fixtureId` новой мутацией и отвечает 400 на POST без `fixtureId`. Это не защита от того, кто может переписать весь каталог.
- Хвост evidence сверяется с `evidence-anchor.json` и с журналом событий. Анкер в том же каталоге ловит частичную подмену, но не полную перезапись каталога.
- Если response есть, independent-read ссылается только на него.
- Локальный доверенный реестр требует операцию `local-create-record` 1.0.0, актёра `local-test-harness` и три эффекта. Хеш сценария не заменяет этот реестр.
- `crashAfterMutation` не затирается кодом 0 и не шлёт DONE. CANCEL во время VERIFYING публикует INCONCLUSIVE / CANCELED. Успешный прогон пишет состояние FINISHED. Одновременный START не отдаёт сырой EEXIST.

Отложено: producer `verification` у вердикта, который записал сам Control, потому что схема 0.1.0 это требует (DS-P2-009). Внешний nonce окружения и анкер вне каталога прогона не сделаны.

## Проверка после исправления

Node.js **v24.16.0**, 12 ноября 2026. Исходные репродукторы аудитора не редактировались.

| Команда | Результат |
|---|---|
| `lead/start-race.mjs` | B вернул RUNNING, A — PASS/NONE, mutationCount=1, журнал читается, OBSERVE и RECONCILE PASS |
| `lead/lock-deletion.mjs` | второй старт BLOCKED / CONTRACT_INVALID, mutationCount=1, recordCount=1 |
| `lead/fixture-reuse.mjs` | второй runId BLOCKED, второй объект не создан |
| `lead/cancel-during-verifier.mjs` | INCONCLUSIVE / CANCELED, POST=1 |
| `lead/crash-flakiness.mjs` | 8/8 INCONCLUSIVE / WORKER_LOST, без BROWSER_DONE; подмена хвоста — INTEGRITY_ERROR |
| `lead/ev07-check.mjs` | OBSERVE и START подменённого хвоста — INTEGRITY_ERROR |
| `lead/simultaneous-start.mjs` | 10/10: один PASS, mutationCount=1, сырого EEXIST нет |
| `evidence-attacks/04-self-approval.mjs` | exit 1: скрипт ищет independent-read, которого нет, потому что прогон остановлен до мутации. Те же входные данные отдельно дают BLOCKED / CONTRACT_INVALID и mutationCount=0 |
| `evidence-attacks/01-attacks.mjs` | не запущен: каталог `pristine-a` у аудитора отсутствует |
| `node --test --test-timeout=45000 tests/*.test.mjs` | пять прогонов подряд, каждый **47 passed, 0 failed**, exit 0 |
| десять отдельных `start` | 10/10 PASS / NONE, каждый с одним POST |
| `npm run schemas` | exit 0, diff схем нет |

Исполнитель свой результат не принимает. Контрольная точка RC2 — `2f327cab4be42cc0215e24bce78aeefb7c469c92`, её повторный аудит дал REJECT. Следующий коммит фиксирует точечные исправления после этого REJECT. Он не является RC3 и не является приёмкой. Приёмка 0.1 остаётся REJECT.

## Граница третьего аудита

Проверять этот коммит, а не начинать новый обзор всей архитектуры. Схемы 0.1.0 не менялись. Уточнение: `docs/changes/003-approval-semantics-and-recovery.md`. Отчёт RC2 сохранён в `INDEPENDENT-ACCEPTANCE-RC2.md`.

- Оригинальные репродукторы RC2, в первую очередь `applieswhen-bypass`, `registry-matrix`, проверки anchor и повреждённого runDir.
- Восстановление после потери Control: отсутствие записи об отправке POST не доказывает, что POST не было. Карантин и освобождение fixture не должны позволять повторить операцию.
- Авария между записью evidence и обновлением anchor: журнал не продолжается поверх неподтверждённых байт и не теряет уже выполненную мутацию. Проверить одновременные START, CANCEL и OBSERVE.
- Несколько полных прогонов набора. Один локальный результат 54/54 недостаточен.
- Локальный реестр задаёт правила проверки `local-create-record`. Совпадение `equals` и `inputs` не означает, что человек разрешил эти входные значения. Перед ЦИЗ нужна внешняя авторизация.

Ожидаемое решение аудитора: ACCEPT, CONDITIONAL ACCEPT или REJECT. Исполнитель его не подменяет.

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

12 ноября 2026 STELLA обозначила эту ревизию как **KAIDEN QA ADAPTANT 0.1 — Release Candidate 2**. Это не принятый релиз. Архитектуру до повторной приёмки не расширять. Полноценные мутации ЦИЗ остаются закрытыми. Локальный реестр `local-create-record` не является авторизацией произвольных операций ЦИЗ: внешнее подтверждение владельца остаётся отдельным условием перед Dev.

Контрольная точка повторного аудита — коммит этой ревизии. Предыдущая точка — первый коммит `1975857123efaabc1c94076e019cc75c1c518a02`. `data/`, `node_modules/` и `.env` в коммиты не входят.

## Граница повторного аудита

Повторный аудит не начинается с нуля. Его граница:

- прежние подтверждённые P0 и обязательные P1, теми же исходными репродукторами;
- `04-self-approval.mjs` должен быть доведён аудитором до вердикта: запрет операции подтверждается только завершённой регрессией, а не падением скрипта на отсутствии independent-read;
- полная матрица `01-attacks.mjs`: утерянный `pristine-a` восстанавливается на новом изолированном наборе и прогоняется заново, а не исключается из приёмки;
- новые окна: авария между записью evidence и обновлением `evidence-anchor.json`; авария между созданием каталога fixture и записью его владельца.

## Что должен подтвердить независимый проверяющий

Исполнительские 47/47 и десять браузерных PASS не заменяют эту проверку.

| Направление | Что подтвердить |
|---|---|
| Повторяемость | Чистая установка, полный набор, настоящий браузерный PASS |
| Целостность | Поддельный PASS, хвост evidence, повторный START, полная матрица атак |
| Жизненный цикл | CANCEL, crash/restart, orphan Browser, владение fixture, новые окна anchor и bind |
| Авторизация | Bearer token, идемпотентность, запрет самоутверждения, безопасный reconcile после перезапуска |

Токен локального fixture создаётся в памяти стенда и передаётся дочерним процессам только через `fixtureToken` / `QA_ADAPTANT_FIXTURE_TOKEN`. В snapshot demo его нет: `authorization` там — актор и scope, `credentialRef` равен `local:none`. Тест перезапуска Control передаёт тот же токен новому процессу явно. Из каталога прогона токен не восстанавливается. Проверяющий должен убедиться, что без этого окружения новый Control не публикует PASS и не записывает секрет в evidence, а с тем же токеном независимое чтение остаётся возможным.

## Следующий пакет после приёмки

1. Только read-only исследование Dev и подтверждение environment/version/data.
2. Явно согласовать accounts, fixture namespace и разрешённую операцию создания задания. Склад, платность и закрытие не разрешать этим этапом.
3. Расширить контракт/adapter для CIZ через `docs/changes` и review, затем доказать OP-B независимым чтением.
4. Только после принятого 0.1 готовить Intelligence Worker. Исходный пункт 7 и DRAFT не менять на месте.

Approval владельца на пункт 7 отсутствует. Различать `task_id`, `action_id`, справочную работу, progress, equipment и складскую позицию. GET задания для verifier должен использовать `ack_notifications=false`.
