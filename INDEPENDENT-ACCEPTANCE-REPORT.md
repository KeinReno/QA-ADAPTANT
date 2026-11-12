# НЕЗАВИСИМЫЙ ОТЧЁТ О ПРИЁМКЕ ЯДРА KAIDEN QA ADAPTANT 0.1

**Исполнитель аудита:** DeepSeek (не участвовал в разработке проверяемого кода)
**Дата:** 12 ноября 2026, Europe/Moscow
**Объект:** локальное ядро 0.1 в рабочей копии `C:\Users\gvi\Desktop\QA-ADAPTANT`
**Режим:** READ-ONLY review + white-box/black-box тестирование, реальный Chromium, локальный стенд 127.0.0.1, fault injection
**Итоговое решение:** **REJECT**

> Код продукта, схемы, контракты и существующие evidence не изменялись. Рабочее дерево Git до и после аудита чистое. Все репро-скрипты и журналы находятся вне дерева проекта: `C:\Users\gvi\AppData\Local\Temp\kaiden-audit\`.

---

## A. Environment

| Параметр | Значение |
|---|---|
| ОС | Microsoft Windows 11 Pro, 10.0.26100, build 26100, 64-bit |
| Node.js | v24.16.0 (единственная установленная пользовательская версия) |
| npm | 11.13.0 |
| Playwright | 1.63.0 (lockfile), Chromium 153.0.8010.12 (revision 1243 в `playwright-core/browsers.json`) |
| Git branch | `master` |
| Commit SHA | `1975857123efaabc1c94076e019cc75c1c518a02` («Зафиксировать рабочее локальное ядро как кандидата на приёмку 0.1») |
| `git status` | пусто (до и после аудита) |
| Зависимости | `node_modules` установлены, lockfile: zod 4.6.7, playwright 1.63.0; импортов старых QA/ЦИЗ нет |
| Сборка | отсутствует; ESM-модули исполняются напрямую, тесты используют текущие исходники |

Фактические команды аудита (полные логи — раздел D):

```powershell
cd C:\Users\gvi\Desktop\QA-ADAPTANT
node --test --test-timeout=45000 tests/*.test.mjs      # прогон 1: 40/40 exit 0; прогон 2: 39/40 exit 1
node scripts/demo-local.mjs                            # PASS/NONE, mutationCount=1, readCount=1, exit 0
node packages/contracts/export.mjs                     # 6 схем, exit 0; git diff пуст
node --test --test-timeout=45000 tests/faults.test.mjs # 3 повтора: fail / pass / pass
```

Дополнительно выполнены собственные репро и матрицы в изолированных временных каталогах (вне проекта); в аудите участвовали три независимых параллельных исполнителя (fixture/verifier, lifecycle/crash, evidence-integrity), чьи сырые логи также сохранены в `...\kaiden-audit\<area>\logs`.

**Ограничение по версиям Node:** требование «проверить минимум Node 24.16.0 и текущую установленную» выполнено частично: установлена только v24.16.0 (nvm отсутствует, `Get-Command node -All` — один путь). Проверка на другой версии Node невозможна на этой машине; это зафиксировано как непроверенное.

---

## B. Test Results

### B.1. Заявленные исполнителем команды

| # | Тест | Ожидание | Фактический результат | Exit |
|---|---|---|---|---|
| 1 | `node --test tests/*.test.mjs` (прогон 1) | 40/40 pass | **40/40 pass**, hidden exceptions нет | 0 |
| 2 | `node --test tests/*.test.mjs` (прогон 2, независимый повтор) | 40/40 pass | **39/40 pass**, `fault crashAfterMutation` дал **PASS** вместо INCONCLUSIVE | **1** |
| 3 | `tests/faults.test.mjs` (3 повтора) | 12/12 каждый | **11/12 + fail**, затем 12/12, 12/12 (тот же crashAfterMutation) | 1 / 0 / 0 |
| 4 | `node scripts/demo-local.mjs` | exit 0, PASS/NONE, POST=1, GET=1 | PASS/NONE, mutationCount=1, readCount=1, 19 событий, цепочка evidence цела | 0 |
| 5 | `node packages/contracts/export.mjs` | схемы 0.1.0 синхронны | 6 схем, `git status` пуст | 0 |
| 6 | 8 последовательных реальных браузерных прогонов (свой скрипт) | PASS/NONE, без libuv assertion | **8/8 PASS**, 1 POST, 1 GET, 1.39–1.54 с, stderr пуст | 0 |

### B.2. Собственные проверки (ожидание → факт)

| # | Проверка | Ожидание | Факт | Вердикт |
|---|---|---|---|---|
| 7 | 10 одновременных идентичных START (два процесса) | один владелец, идемпотентный ответ | 10/10: один процесс PASS, второй — сырой `EEXIST` (exit 1); второй мутации нет, журнал цел | частично (DS-P2-014) |
| 8 | START-гонка при медленном `/environment` (1.5 с) | один владелец, нет терминализации живого прогона | второй процесс публикует INCONCLUSIVE/WORKER_LOST; первый делает POST и падает `INTEGRITY_ERROR: VERDICT_ORDER`; run навсегда нечитаем | **FAIL (DS-P0-001)** |
| 9 | Удаление lock/lease-файлов при активном прогоне после POST | второй бизнес-объект не создаётся | **mutationCount=2, recordCount=2** | **FAIL (DS-P0-002)** |
| 10 | Повторный прогон с новым runId и тем же fixtureId (публичный API) | отказ до мутации | второй POST создаёт второй объект; итог INCONCLUSIVE, но мутация уже произошла | **FAIL (DS-P1-008)** |
| 11 | CANCEL во время VERIFYING (после durable intent) | INCONCLUSIVE/CANCELED | cancel вернул CANCEL_REQUESTED, через 0.39–0.51 с опубликован **PASS** | **FAIL (DS-P1-005)** |
| 12 | Инъекция `crashAfterMutation` (8 повторов) | INCONCLUSIVE каждый раз | **7/8 PASS/NONE**, 1/8 INCONCLUSIVE; в PASS-прогонах есть BROWSER_DONE | **FAIL (DS-P1-003)** |
| 13 | Подмена только последней записи evidence (INCONCLUSIVE→PASS) | отказ PASS | OBSERVE и START принимают **PASS**, стенд закрыт | **FAIL (DS-P1-004)** |
| 14 | Self-approval: `APPROVED` с чужим actor и своими effects, стенд fault wrongExecutor | PASS запрещён/ожидания не подтверждены | **PASS/NONE** при `executorId='operator-wrong'` в durable independent-read | **FAIL (DS-P1-006)** |
| 15 | 20 атак на целостность evidence (несуществующие ID, artifact, producer, chain, manifest, duplicate verdict, evidence после verdict, чужой runId, coverage) | PASS не принимается | 13 групп атак отклонены корректно; 3 обхода подтверждены (EV-07/05/15) | частично |
| 16 | OBSERVE/RECONCILE/повторный START на терминальном PASS | ни одного изменения, без POST | хэши файлов и счётчики стенда не изменились, второго POST нет | PASS |
| 17 | Fixture API: bearer, фильтр, идемпотентность, лимит, методы | соответствует контракту | почти всё PASS; **POST без/с пустым fixtureId создаёт запись и mutationCount++** | FAIL (DS-P2-010) |
| 18 | Fixture API: 10 параллельных POST с одним idempotency-key | 1 мутация | 1×201 + 9×200, один id, mutationCount=1 | PASS |
| 19 | HTTP 503 ×2 на независимом чтении | PASS после восстановления, POST=1 | PASS, readCount=3, POST=1 | PASS |
| 20 | lostResponse / missingEvidence / untrustedId / changedEnvironment | INCONCLUSIVE, PASS нет | INCONCLUSIVE (RESULT_UNCONFIRMED / EVIDENCE_MISSING / ENVIRONMENT_CHANGED), POST=1 | PASS |
| 21 | partialSave / wrongExecutor | FAIL с VIOLATED у нужного effect | FAIL/BUSINESS_INVARIANT_VIOLATED, POST=1 | PASS |
| 22 | Две записи с одинаковым fixtureId до запуска | не выбирать одну | INCONCLUSIVE/RESULT_UNCONFIRMED, ownershipVerified=false | PASS |
| 23 | crash Control в 5 точках (kill -9) | нет повторного POST, журнал цел, reconcile не PASS | POST не повторяется, журнал цел, INCONCLUSIVE/WORKER_LOST; **crash в первые мс snapshot оставляет runId навсегда непригодным (сырой ENOENT)** | частично (DS-P2-013) |
| 24 | Убит только Control (orphan browser) | POST после смерти Control = 0, дети завершаются | браузер завершился ~210 мс, chromium-дерево умерло, POST=0 | PASS |
| 25 | Concurrent RECONCILE во время активного START (3 фазы) | runningView, без второго verdict | 6/6 runningView, seq/цепь целы, POST=1 | PASS |
| 26 | RECONCILE без fixture token после abort | PASS запрещён; секрет из run-dir не восстановим | INCONCLUSIVE/WORKER_LOST, токена в run-dir нет | PASS |
| 27 | Гигиена процессов после штатного PASS | нет сирот | живых node/chromium от прогона нет, leases/locks пусты; остаётся owner.json (ожидаемо) | PASS |

---

## C. Findings

Порядок: P0 → P1 → P2 → наблюдения. Для каждой находки указан статус: CONFIRMED (воспроизведено), INCONCLUSIVE (не удалось воспроизвести, есть основания в коде/логах).

### DS-P0-001. Гонка START/RECONCILE в окне PREFLIGHT→`owner.json`: ложный терминальный вердикт при живой мутации и необратимое повреждение журнала

- **Приоритет:** P0 (блокирующий).
- **Модуль:** `apps/control/run.mjs:151–166` (snapshot → preflight → owner.json), `run.mjs:335–350` (`start`), `run.mjs:371–389` (`reconcile`), `run.mjs:68–72` (`foreignOwnerAlive`), `packages/core/evidence-policy.mjs:70–73` (`VERDICT_ORDER`).
- **Условие:** два независимых процесса Control работают с одним `runId`. `owner.json` записывается только **после** сетевого preflight `/environment` и после `STATE: PREFLIGHT`; в окне между созданием каталога прогона и записью `owner.json` (замерено 6/6: ~77 мс; при медленном preflight — секунды) второй процесс не видит живого владельца, уходит в `reconcile`, не находит `mutation-intent` и **публикует терминальный** `INCONCLUSIVE/WORKER_LOST` с текстом «Control завершился до durable intent; браузер повторно не запускается».
- **Воспроизводимые шаги:** `node C:\Users\gvi\AppData\Local\Temp\kaiden-audit\lead\start-race.mjs` (детерминированный тест-двойник стенда с задержкой `/environment` 1500 мс):
  1. Процесс A: `cli.mjs start --root <root> --bundle <bundle.json>`.
  2. Дождаться появления `runs/<runId>/manifest.json`, убедиться, что `owner.json` ещё нет (A внутри preflight).
  3. Процесс B: тот же `start` (или прямой `reconcile`).
  4. Дождаться завершения A.
  - Независимое подтверждение: `...\kaiden-audit\lifecycle\lc06.mjs` (4/4) и `lc06e.mjs` (2/2); спонтанно 2/8 в `lc01.mjs` с задержкой второго START 50/150 мс.
- **Наблюдаемый результат:**
  - B: exit 0, `INCONCLUSIVE/WORKER_LOST`, ownershipVerified=false.
  - A: exit 1, `INTEGRITY_ERROR: VERDICT_ORDER`; при этом стенд зафиксировал **mutationCount=1** (POST реально отправлен и запись создана).
  - evidence: `[verdict, mutation-intent, request, response]` — терминальный verdict стоит **до** доказательств мутации.
  - `observe`, `reconcile`, повторный `start` → exit 1 `INTEGRITY_ERROR: VERDICT_ORDER`; self-heal отсутствует; runId навсегда непригоден.
- **Нарушенный инвариант/контракт:** RUN-PROTOCOL («После FINISHED новые evidence/actions запрещены»; RECONCILE — только чтение; отмена/неизвестность не должны давать ложный терминальный вывод); требование задания «терминальный результат не может утверждать отсутствие мутации, если браузер ещё способен её отправить»; TEST-LC-01/TEST-LC-06.
- **Риск для реальной ЦИЗ:** при повторном/параллельном запуске Control на один run в Dev возможна реальная бизнес-мутация при уже опубликованном терминальном вердикте «мутации не было», после чего доказательства нечитаемы. Это худший класс дефекта: ложное отрицание мутации + потеря audit trail.
- **Рекомендация:** записывать владение атомарно до любого сетевого/браузерного шага (owner/lease создавать в одной транзакции со snapshot, например через атомарный `mkdir` lock-каталога + manifest.state=OWNED, fsync); в `start`/`reconcile` считать существующий незавершённый run активным, если есть durable владелец **или** состояние PREFLIGHT/RUNNING моложе lease TTL без признаков смерти процесса; перед публикацией любого терминального вердикта и перед каждым append evidence проверять отсутствие терминального verdict (appendEvidence должен отказывать после FINISHED); реализовать восстановление`INTEGRITY_ERROR: VERDICT_ORDER` через карантин/явный отчёт, а не вечную нечитаемость.
- **Статус:** **CONFIRMED** (два независимых исполнителя, детерминированный и спонтанный репро).
- **Артефакты:** `lead\start-race.mjs`, `lead\start-race-result.log`, `lead\concurrent-start-race-run\` (journal, evidence, verdict), `lifecycle\logs\lc06-summary-readable.json`, `lc06e-readable.json`, `lc06e-recovery-after-window-race.json`, `lifecycle\logs\artifacts\lc06d-*, lc06e-*`.

### DS-P0-002. Удаление lock-файлов допускает вторую бизнес-мутацию для того же fixtureId

- **Приоритет:** P0 (нарушен прямо заявленный «главный критерий» приёмки; требуется доступ к каталогу данных, но именно этот fault-сценарий задан заданием как обязательный).
- **Модуль:** `apps/control/run.mjs:57–128` (два независимых «замка»: `locks/<hash>.lock` и `leases/<hash>.json`), `run.mjs:159–161`, `run.mjs:196/213` (`assertLease` только на INTENT/HTTP_REQUEST), `run.mjs:268–269`, `run.mjs:391–404` (`cancel`).
- **Условие:** прогон A уже отправил POST (durable request, ответ задерживается). Вручную удаляются оба файла блокировки. Запускается прогон B с тем же `fixtureId`, но другим `runId`. `createLockMarker` — фактически мёртвый код (его файл нигде не читается для владения); реальный владелец — `leases/*.json`, но после его удаления A уже не перепроверяет владение (assertLease только до POST), поэтому B проходит preflight и делает второй POST.
- **Воспроизводимые шаги:** `node ...\kaiden-audit\lead\lock-deletion.mjs`:
  1. Стенд (fault `delayResponse`) + bundle A (runId1) + bundle B (runId2, **тот же** fixtureId).
  2. Запустить A; дождаться `mutationCount===1`.
  3. Удалить `locks/*.lock` и `leases/*.json`.
  4. Запустить B; дождаться завершения A.
- **Наблюдаемый результат:** `FINAL mutationCount=2 recordCount=2`; оба вердикта INCONCLUSIVE/RESULT_UNCONFIRMED, но **второй бизнес-объект уже создан**.
- **Нарушенный инвариант:** FIXTURE-CONTRACT («fixtureId связан ровно с одним runId/environmentId»; «ни гонка, ни удаление lock-файла не должны приводить ко второй бизнес-мутации для одной и той же авторизованной операции»); ACCEPTANCE-REPORT/Grok-claim «удаление fixture lock не разрешает два POST».
- **Риск для реальной ЦИЗ:** дублирование бизнес-операции (двойное задание/действие) при ручном вмешательстве в lock или при частичной потере lock-файлов; локальная идемпотентность стенда не спасает, т.к. intentId разный.
- **Рекомендация:** один авторитетный механизм владения (атомарный каталог/OS-lock) без дублирующих файлов; проверять владение перед **каждой** попыткой мутации и после dispatch; при потере lease после dispatch — терминализировать как INCONCLUSIVE и запрещать второй прогон; durable реестр `fixtureId→runId` на весь период жизни fixture; защищать замок от удаления (открытый эксклюзивный handle/ACL) либо явно документировать, что ручное удаление данных = компрометация (сейчас же критерий приёмки требует обратного).
- **Статус:** **CONFIRMED**.
- **Артефакты:** `lead\lock-deletion.mjs`, `lead\lock-deletion-result.log`, `lifecycle\logs` (смежные lock-проверки).

### DS-P1-003. Инъекция «Browser crash after mutation» fail-open и нестабильна: один и тот же тест даёт PASS и 40/40 не воспроизводится

- **Приоритет:** P1 (обязательный отказ §13 №6 не доказан; тест не герметичен; ложный PASS при инъекции «краха»).
- **Модуль:** `apps/browser/worker.mjs:12–22` (`exitSoon` меняет только `process.exitCode`), `:105–115` (`crashAfterMutation`), `:185` (DONE), `:197` (`exitSoon(0)`); `apps/control/run.mjs:130–137` (`waitForChild`), `:265` (`browserUncertain`).
- **Условие:** fault `crashAfterMutation`. Обработчик ответа вызывает `exitSoon(86)`, но не прерывает основной поток; далее `DONE` успевает уйти по IPC, а завершающий `exitSoon(0)` перекрывает код 86. Control наблюдает exit code 0 и штатное завершение → PASS. При обратном порядке дисконнекта worker завершается кодом 32 → INCONCLUSIVE.
- **Воспроизводимые шаги:** `node --test tests/faults.test.mjs` (2 из 3 прогонов на текущей машине дали красный тест), `node ...\kaiden-audit\lead\crash-flakiness.mjs` (8 прогонов), `...\kaiden-audit\fixture-verifier\08-crash-repeat.mjs`.
- **Наблюдаемый результат:** 7/8 собственных прогонов и ≥1/3 повторов сюиты — `PASS/NONE`, `reasonCode=NONE`, `ownershipVerified=true`, в событиях `BROWSER_DONE`; полный набор: **39/40, exit 1**.
- **Нарушенный инвариант:** ACCEPTANCE-REPORT («40 passed, 0 failed»), обязательный отказ §13 №6 (Browser crash → INCONCLUSIVE), принцип fail-closed при неизвестном состоянии worker.
- **Риск для реальной ЦИЗ:** тест перестаёт быть доказательством; регрессия «краш после мутации» может маскироваться. Продуктовый риск ниже (настоящий SIGKILL/OOM даёт ненулевой код), но заявление о готовности не подтверждено.
- **Рекомендация:** инъекция должна аварийно завершать процесс (`process.exit(code)`/abort) до отправки DONE и без последующего `exitSoon(0)`; явный признак fault в IPC (например `ERROR/FAULT_INJECTED`) и запрет PASS при активном fault-режиме; отдельный тест на детерминизм (повтор N раз); не считать 40/40 доказательством без N повторов.
- **Статус:** **CONFIRMED** (два независимых исполнителя).

### DS-P1-004. Последняя запись evidence не защищена цепочкой: правка только хвоста переводит INCONCLUSIVE в PASS

- **Приоритет:** P1 (прямое противоречие заявленной защите от частичного изменения; для эксплуатации нужен доступ к каталогу данных).
- **Модуль:** `packages/core/store.mjs:104–159` (`previousSha256` — только обратная ссылка; хэш самого последнего envelope нигде не фиксируется), `store.mjs:128–159` (`readEvidence`), `packages/core/evidence-policy.mjs:70–90` (`assertTerminalEvidence`), `apps/control/run.mjs:289–350`, `ARCHITECTURE.md:17`, `RUN-PROTOCOL.md:3`.
- **Условие:** есть реальный прогон `INCONCLUSIVE/WORKER_LOST` с валидными response+independent-read и checks=SATISFIED (например fault `crashAfterMutation`). Меняются **только последний envelope** (`artifact.sha256`, без пересчёта цепи) и его artifact verdict на `PASS/NONE`; `events.jsonl` не трогается (там остаётся `VERDICT_DURABLE ... INCONCLUSIVE`).
- **Воспроизводимые шаги:** `node ...\kaiden-audit\lead\crash-flakiness.mjs`; независимое подтверждение тем же приёмом на исходном PASS — `node ...\kaiden-audit\lead\ev07-check.mjs`; более полная матрица — `...\kaiden-audit\evidence-attacks\01-attacks.mjs` (EV-07a/b/d/e).
- **Наблюдаемый результат:** `OBSERVE` → `PASS/NONE`; `START` того же bundle (стенд уже закрыт) → `PASS/NONE`. Также OBSERVE принимает правку `observedAt`/расширение `parentEvidenceIds` последнего envelope; правка средней записи корректно даёт INTEGRITY_ERROR (EV-07c).
- **Нарушенный инвариант:** EVIDENCE-SCHEMA (hash-chain и неизменяемость терминала), RUN-PROTOCOL («терминальный результат неизменяем»), ARCHITECTURE («обнаруживает случайное/частичное изменение»), заявление задания «терминальный результат не выбирается по последней записи без семантики» — семантика есть, но целостность последней записи не обеспечена.
- **Риск для реальной ЦИЗ:** подмена итогового вердикта после прогона без полной перезаписи каталога; расхождение evidence и events не обнаруживается.
- **Рекомендация:** анкеровать хвост: отдельный `terminal-anchor.json` (fsync) с SHA последнего envelope/verdict; включать хэш предыдущего envelope в следующий (forward seal) или в events-запись; cross-check verdict из evidence с `VERDICT_DURABLE` и FINISHED-состоянием events; `appendEvidence` должен отказывать после терминального verdict.
- **Статус:** **CONFIRMED** (независимо подтверждено Lead и audit-evidence).

### DS-P1-005. CANCEL во время VERIFYING игнорируется: после CANCEL_REQUESTED публикуется PASS

- **Приоритет:** P1 (нарушение RUN-PROTOCOL; отмена не авторитетна в фазе верификации).
- **Модуль:** `apps/control/run.mjs:262–266` (флаг `canceled` снимается один раз до verifier), `run.mjs:391–404` (`cancel` пишет `cancel.request` и возвращает CANCEL_REQUESTED), `apps/verification/worker.mjs` (не читает cancel-состояние).
- **Условие:** после durable intent/фактического POST, во время работы Verification Worker, из другого процесса вызывается CANCEL.
- **Воспроизводимые шаги:** `node ...\kaiden-audit\lead\cancel-during-verifier.mjs` (fault `transientRead`, cancel после события BROWSER_DONE); `...\kaiden-audit\lifecycle\lc0203.mjs`.
- **Наблюдаемый результат:** cancel: exit 0, `state=CANCEL_REQUESTED`, `verdict=null`, на диске `cancel.request`; через 390–510 мс публикуется `PASS/NONE` (3/3 у lifecycle).
- **Нарушенный инвариант:** RUN-PROTOCOL «Отмена ... после durable intent: INCONCLUSIVE/CANCELED»; API-контракт cancel (вызывающий получает CANCEL_REQUESTED, а прогон завершается PASS без уведомления).
- **Риск:** оператор считает, что остановил прогон; в реальной ЦИЗ возможна поздняя публикация PASS после запроса остановки.
- **Рекомендация:** durable cancel-состояние проверять перед публикацией вердикта и внутри verifier; cancel должен дожидаться терминализации либо возвращать «cancel raced, final state X»; при cancel после dispatch — INCONCLUSIVE/CANCELED.
- **Статус:** **CONFIRMED** (Lead + lifecycle, 3/3).

### DS-P1-006. Approval и fixture — самодекларация через публичный API: PASS определяется входным bundle, а не доверенным утверждением

- **Приоритет:** P1 (ключевая предпосылка «Acceptance получает только APPROVED» технически не обеспечена; критично перед CIZ Adapter).
- **Модуль:** `adapters/local/bundle.mjs:4–41` (approval/actor/effects собирает вызывающий), `packages/contracts/index.mjs:40–44,111,159–169`, `packages/core/canonical.mjs:13–17`, `packages/core/bundle.mjs:14`, `AGENTS.md:7–8`, `SCENARIO-SCHEMA.md`.
- **Условие:** любой, кто может вызвать `start`/`CLI`, формирует bundle: `status=APPROVED`, `approval.actor='audit-attacker (not an owner)'`, `approval.contentSha256` = хэш собственного сценария, и **свой набор effects** (например только ownership marker).
- **Воспроизводимые шаги:** `node ...\kaiden-audit\evidence-attacks\04-self-approval.mjs`.
- **Наблюдаемый результат:** при fault `wrongExecutor` (стенд сохраняет `executorId='operator-wrong'`) START возвращает **PASS/NONE**; независимое чтение содержит неверного исполнителя, но проверка этого не требует. Контрольный прогон с дефолтными effects на том же fault даёт FAIL/BUSINESS_INVARIANT_VIOLATED.
- **Нарушенный инвариант:** AGENTS («утверждение новой версии — отдельное действие владельца»), SCENARIO-SCHEMA («утверждение привязано к hash содержимого» — обеспечивает целостность, но не авторизацию), OPERATION-CONTRACT (значения effects утверждены вместе с operation hash — но кем?).
- **Риск для ЦИЗ:** перед Dev-мутацией это означает, что «утверждённая операция» может быть сгенерирована самим агентом/любым локальным процессом; при подключении CIZ Adapter это прямой путь к непредусмотренной бизнес-операции.
- **Рекомендация:** вынести approval за пределы bundle, который передаёт вызывающий: подписанный/хранимый владельцем артефакт с ключом вне процесса, проверяемый Control; отдельный CR через `docs/changes`; минимум — реестр утверждённых operation/effect IDs, недоступный на запись исполнителю.
- **Статус:** **CONFIRMED**.

### DS-P1-008. Нет глобальной привязки fixtureId→runId: повторный публичный START с тем же fixtureId создаёт второй бизнес-объект

- **Приоритет:** P1.
- **Модуль:** `apps/control/run.mjs:151–166,335–350` (проверяется только per-run bundle), отсутствие preflight-проверки занятости fixtureId; `FIXTURE-CONTRACT.md:3`.
- **Условие:** после терминального PASS прогона run1 запускается bundle run2 с тем же `fixtureId`, тем же environment и теми же inputs, но новым `runId` (валидный по схемам; fixture-контракт заявляет `fixtureId` уникальным для одного runId, но runtime это не проверяет).
- **Воспроизводимые шаги:** `node ...\kaiden-audit\lead\fixture-reuse.mjs`.
- **Наблюдаемый результат:** run1 PASS (1 POST); run2 принят, делает второй POST (mutationCount=2, recordCount=2), затем INCONCLUSIVE/RESULT_UNCONFIRMED (verifier честно не выбирает одну из двух записей).
- **Нарушенный инвариант:** FIXTURE-CONTRACT уникальность `fixtureId`; критерий «одна авторизованная операция — один бизнес-объект».
- **Риск:** дублирование бизнес-объектов при повторном запуске; verifier предотвращает ложный PASS, но мутация уже произошла.
- **Рекомендация:** durable реестр `(environmentId, fixtureId) → runId`; preflight-проверка занятости fixtureId до dispatch; отказ CONTRACT_INVALID/ALREADY_BOUND; для CIZ — серверная проверка ownership/marker до создания.
- **Статус:** **CONFIRMED**.

### DS-P2-007. Перепривязка independent-read с response на request обходит сверку identity (требует пересборки цепи)

- **Приоритет:** P2 (в пределах документированной границы «доступ к каталогу данных»).
- **Модуль:** `packages/core/evidence-policy.mjs:40–44,51` (parent допускает request и response; `READ_IDENTITY` выполняется только при parent=response).
- **Наблюдаемый результат (EV-05/20b):** read parent=request + пересборка цепи → OBSERVE PASS даже при `response.entity != independent-read.entity`; при parent=response защита срабатывает (EV-20a).
- **Рекомендация:** для PASS/FAIL требовать parent=response и всегда сверять entity response↔read; request допускать только как явно «незавершённую» цепь для INCONCLUSIVE.
- **Статус:** **CONFIRMED** (evidence-attacks).

### DS-P2-009. Control публикует verdict с producer='verification' без запуска Verification Worker

- **Приоритет:** P2 (ложное происхождение; PASS этим путём не подделывается).
- **Модуль:** `apps/control/run.mjs:258–263,271–283,421–425`; `EVIDENCE-SCHEMA.md:3,11`; `MODULE-BOUNDARIES.md`.
- **Наблюдаемость:** fault `ambiguousButton` / `tamperSnapshotBeforeBrowser` / `dropIntentAck`: в evidence одна запись `kind=verdict, producer='verification', stepId='verify', parents=[]`, хотя verifier не запускался; events содержат `STATE:VERIFYING` без процесса.
- **Рекомендация:** отдельный вид/производитель для вердиктов Control (с изменением схемы через процедуру review), либо всегда запускать verifier и принимать RESULT только по IPC-каналу с commandId/токеном.
- **Статус:** **CONFIRMED**.

### DS-P2-010. Fixture принимает POST без/с пустым/нестроковым fixtureId и считает это мутацией

- **Приоритет:** P2 (локальный стенд — источник доверия verifier).
- **Модуль:** `adapters/local/server.mjs:60–101` (валидация fixtureId отсутствует до `mutationCount++`/`records.push`); `FIXTURE-CONTRACT.md:3,5`; ACCEPTANCE-REPORT «не считает отклонённое тело мутацией».
- **Факт:** POST без fixtureId → 201 + mutationCount++; fixtureId:"" → 201; fixtureId:12345 (number) → 201; запись-сирота недостижима GET-фильтром.
- **Рекомендация:** валидировать fixtureId (непустая строка, допустимый namespace) до мутации; отклонённое тело не увеличивает счётчик.
- **Статус:** **CONFIRMED** (audit-fixture).

### DS-P2-011. Browser зависает на не-2xx ответе POST: `response.json()` без таймаута → WORKER_LOST через 12 с

- **Приоритет:** P2 (fail-closed, но неточная классификация).
- **Модуль:** `apps/browser/worker.mjs:97–117`; `apps/control/run.mjs:130–137,247`.
- **Факт:** POST 401/500 с телом → response.json() не резолвится, Control ждёт deadline (12 с) → INCONCLUSIVE/WORKER_LOST, response evidence не пишется; mutationCount=0.
- **Рекомендация:** читать тело с таймаутом/по `text()`, классифицировать HTTP-ошибки; не блокировать DONE.
- **Статус:** **CONFIRMED** (audit-fixture).

### DS-P2-012. Идентичность локального environment — самодекларация; «handshake nonce созданного harness» не проверяется

- **Приоритет:** P2 (для 0.1 риск ограничен localhost; критично для CIZ).
- **Модуль:** `apps/control/run.mjs:154–157`, `RUN-PROTOCOL.md:13–15`.
- **Факт:** Control принимает любой сервер `127.0.0.1:<port>`, чей `/environment` повторяет `environmentId/fingerprint` **из манифеста, который передал вызывающий**. Собственный тест-двойник в этом аудите был принят как environment (использовался для P0-001/Lock-репро).
- **Рекомендация:** nonce/token экземпляра должен создавать harness и передавать Control по доверенному каналу (не через bundle); preflight должен проверять знание секрета, а не эхо.
- **Статус:** **CONFIRMED** (конструктивно, использовано в репро).

### DS-P2-013. Crash в первые миллисекунды snapshot оставляет runId навсегда непригодным (сырой ENOENT)

- **Приоритет:** P2.
- **Модуль:** `packages/core/store.mjs:35–52` (snapshot не транзакционен), `run.mjs` (recovery не умеет карантин неполного каталога).
- **Факт (lifecycle LC-04):** kill -9 в момент создания snapshot → каталог без manifest/scenario; `reconcile/observe/start` → сырой `ENOENT: scenario.json`, runId навсегда занят; нет INTEGRITY_ERROR-диагностики и self-heal.
- **Рекомендация:** snapshot в temp-каталог + атомарный rename; при неполном каталоге — карантин/явная ошибка с возможностью нового runId.
- **Статус:** **CONFIRMED**.

### DS-P2-014. Одновременный идентичный START не идемпотентен при гонке: сырой EEXIST

- **Приоритет:** P2.
- **Модуль:** `packages/core/store.mjs:35–52` (`mkdir` без обработки EEXIST), `run.mjs:335–350`.
- **Факт (LC-02 + Lead):** 8/8 и 10/10 попыток: один процесс PASS, второй exit 1 с `EEXIST: file already exists, mkdir ...runs/<runId>` (stderr не JSON). Второй мутации нет, журнал цел; но RUN-PROTOCOL требует идемпотентного существующего запуска.
- **Рекомендация:** на EEXIST переходить к чтению существующего run (как `start` для готового каталога), а не падать сырым исключением.
- **Статус:** **CONFIRMED**.

### DS-P2-015. Состояние observe/финализация: `state=CREATED` после PASS; stale `browser.pid` — риск PID-reuse в cancel

- **Приоритет:** P2/P3.
- **Модуль:** `run.mjs:289–299,361–372,391–404`.
- **Факт:** OBSERVE на завершённом через verifier прогоне возвращает `state=CREATED` (нет `STATE:FINISHED`; FINISHED пишется только в `persistVerdict`-ветке) — рассинхрон с конечным автоматом RUN-PROTOCOL; после crash/орфана остаётся `browser.pid`, и `cancel()` из другого процесса убивает PID из файла без проверки identity (PID-reuse).
- **Рекомендация:** всегда писать STATE:FINISHED при публикации вердикта; хранить в `browser.pid` проверяемую identity (start time/command), проверять её перед killTree; удалять stale-файл при reconcile.
- **Статус:** **CONFIRMED**.

### Дополнительные наблюдения (P3/INFO)

| ID | Наблюдение | Статус |
|---|---|---|
| DS-P3-016 | DRAFT отклоняется не draft-guard'ом, а ошибкой approval hash; неудачный snapshot «отравляет» runId (повторный START с исправленным bundle невозможен). `core/bundle.mjs:14`, `contracts/index.mjs:164`. | CONFIRMED (EV-16) |
| DS-P3-017 | Дописывание evidence после терминального verdict навсегда делает прогон нечитаемым; `appendEvidence` не проверяет FINISHED. RUN-PROTOCOL «после FINISHED запрещено» не enforced. | CONFIRMED (EV-06) |
| DS-P3-018 | Амплификация evidence: до `maxReadAttempts` (100) independent-read артефактов на один вердикт при FAIL/задержках (наблюдалось 20). Рост объёма и стоимости проверки. | CONFIRMED (A-06) |
| DS-P3-019 | Browser не проверяет `durable:true` в EVIDENCE_ACK; при `missingEvidence` Control отвечает `durable:false`. На итог не влияет (INCONCLUSIVE). | CONFIRMED (A-05) |
| DS-P3-020 | Отсутствующий artifact даёт сырой `ENOENT` вместо INTEGRITY_ERROR; несогласованность классификации. | CONFIRMED (EV-12b) |
| DS-P2-021 | Crash между записью artifact и append envelope (CR-13) оставляет orphan; следующий append того же kind/sequence упрётся в «запрещена перезапись evidence» → прогон невосстановим. Окно не поймано kill-тестом. | INCONCLUSIVE (по коду) |

### Модель угроз (по факту испытаний)

| Возможность | Что подтверждено |
|---|---|
| **Только публичный API** (start/observe/cancel/reconcile, bundle, CLI) | Self-approval и произвольные effects (DS-P1-006); повторный run с тем же fixtureId → вторая мутация (DS-P1-008); конкурентный START/RECONCILE → ложный терминальный вердикт и необратимый журнал (DS-P0-001); CANCEL во время verify игнорируется (DS-P1-005); подмена произвольного local environment (DS-P2-012). Подделка PASS без реального браузера/стенда через API **не** подтверждена. |
| **Доступ к каталогу данных** (запись файлов run) | Подмена последней записи evidence → PASS (DS-P1-004); удаление lock/lease → вторая мутация (DS-P0-002); перепривязка read parent (DS-P2-007); self-heal отсутствует (VERDICT_ORDER). |
| **Полный контроль процесса/диска** | Полная пересборка hash-цепи и поддельный PASS без браузера/verifier (EV-14) — подтверждено, соответствует документированной границе ARCHITECTURE.md:5,17; криптографической подписи/внешнего анкера нет. |

---

## D. Evidence

Все артефакты аудита (скрипты, журналы, копии run-каталогов) — вне проекта:
`C:\Users\gvi\AppData\Local\Temp\kaiden-audit\`

| Область | Ключевые файлы |
|---|---|
| Lead | `lead\start-race.mjs`, `lead\start-race-result.log`, `lead\concurrent-start-race-run\`, `lead\lock-deletion.mjs`, `lead\lock-deletion-result.log`, `lead\fixture-reuse.mjs`, `lead\fixture-reuse-result.log`, `lead\cancel-during-verifier.mjs`, `lead\cancel-during-verifier.log`, `lead\producer-check.mjs/.log`, `lead\crash-flakiness.mjs`, `lead\crash-fault-flakiness-and-ev07.log`, `lead\ev07-check.mjs/.log`, `lead\simultaneous-start.mjs`, `lead\simultaneous-start-10.json`, `lead\stress-runs.mjs`, `lead\stress-8-runs.json/.log`, `lead\full-suite-run2.log`, `lead\flake-crash-fault.md`, `lead\verify-trace.mjs/.log`, `lead\orphan-verifier-race.mjs` |
| AUDIT-A (fixture/verifier) | `fixture-verifier\10-FINDINGS.md`, `logs\01-fixture-api.log`, `logs\03-faults.log`, `logs\06-wrong-token.log`, `logs\07-crash-exitcode.log`, `logs\08-crash-repeat.log`, `logs\09-repo-faults-test.log`, repro-скрипты `01..08` |
| AUDIT-B (lifecycle) | `lifecycle\lc01.mjs`, `lc0203.mjs`, `lc04.mjs`, `lc05.mjs`, `lc06.mjs`, `lc06e.mjs`, `lc07.mjs`; `lifecycle\logs\lc01-summary.json`, `probe-window2-readable.json`, `lc02-result.json`, `lc03b-result-1..3.json`, `lc04-summary-readable.json`, `lc05-summary.json`, `lc06-summary-readable.json`, `lc06e-readable.json`, `lc06e-recovery-after-window-race.json`, `lc07-hygiene.json`; 69 копий журналов — `lifecycle\logs\artifacts\` |
| AUDIT-C (evidence) | `evidence-attacks\FINDINGS.md`, `00-baseline.mjs`, `01-attacks.mjs`, `02-provenance-observe.mjs`, `03-full-rewrite.mjs`, `04-self-approval.mjs`, `lib.mjs`, `attack-results-01..04.json`, `logs\00..04-*.log` |

Эталонный demo-прогон, выполненный в этом аудите: `C:\Users\gvi\Desktop\QA-ADAPTANT\data\demo-1794493367607\runs\demo-1794493367607\` (events.jsonl, evidence.jsonl, evidence/000001..000005, PASS/NONE, 19 событий, цепочка intent→request→response→independent-read→verdict).

Повторная проверка ключевых дефектов:
1. `node <TEMP>\kaiden-audit\lead\start-race.mjs` → B: INCONCLUSIVE; A: INTEGRITY_ERROR VERDICT_ORDER; mutationCount=1; observe/reconcile → INTEGRITY_ERROR.
2. `node <TEMP>\kaiden-audit\lead\lock-deletion.mjs` → mutationCount=2.
3. `node <TEMP>\kaiden-audit\lead\fixture-reuse.mjs` → mutationCount=2.
4. `node <TEMP>\kaiden-audit\lead\cancel-during-verifier.mjs` → CANCEL_REQUESTED + итоговый PASS.
5. `node --test tests/faults.test.mjs` (1-3 повтора) → возможен FAIL crashAfterMutation.
6. `node <TEMP>\kaiden-audit\lead\crash-flakiness.mjs` → 7/8 PASS при инъекции «краха»; хвостовая подмена → PASS.

---

## E. Architecture Assessment

**Что сохраняется (подтверждено):**
- Разделение процессов Control Plane / Browser Worker / Verification Worker реально (fork + IPC, отдельные HTTP-клиенты; verifier сам перечитывает артефакты и выполняет GET с bearer; browser не публикует independent-read/verdict).
- Контракты 0.1.0 самостоятельны и версионированы; схемы регенерируются без diff; импортов старых QA/QA-v2/ЦИЗ нет; `maxModelCalls=0`, детерминированное исполнение.
- Локальный fixture отделён от бизнес-системы; allowlist POST, запрет чужого origin/WebSocket; GET-путь верификатора ограничен; секреты не попадают в snapshot/events/evidence (проверено grep-ом).
- Разумная сложность: ~90 КБ исходников на 6 модулей; явные контрактные валидаторы; evidence-store с checksum/sequence/parent; honest-цепочка PASS воспроизводится 8/8.

**Что мешает приёмке и переносу на CIZ Adapter:**
1. **Доверие к входу:** approval, fixture и environment идентичность — самодекларация вызывающего (DS-P1-006/DS-P2-012). Для CIZ нужен внешний доверенный анкер: подписанное approval владельца, fixture-реестр, server-side ownership/marker до мутации.
2. **Владение fixture раздвоено:** `locks/*.lock` — мёртвый код, реальный владелец `leases/*.json`, удаление файлов обходит защиту; нет durable реестра `fixtureId→runId` (DS-P0-002/DS-P1-008).
3. **Терминальное состояние и evidence-хвост не анкерованы:** нет fsync-анкера последнего envelope, evidence не сверяется с events; ложный терминальный вердикт при гонке и необратимый VERDICT_ORDER (DS-P0-001/DS-P1-004).
4. **Двойной писатель:** Control и verifier пишут в один store в разных фазах; нарушение фазового разделителя возможно через гонку recovery; append не проверяет FINISHED.
5. **Отмена и аварийные состояния:** CANCEL не авторитетен в VERIFYING; crash в snapshot отравляет runId; отсутствует карантин/ремонт.
6. **Происхождение вердикта:** Control пишет `producer='verification'` — потребитель не может отличить независимую проверку от Control-решения.

**Вывод:** модульные границы в целом сохранены, «монолита» нет; но ядро **не готово** ни к приёмке 0.1, ни к подключению CIZ Adapter без исправления P0-001/P0-002 и P1-004/P1-005/P1-006 и стабилизации обязательных fault-тестов.

---

## F. Final Acceptance Decision

# REJECT

Основания (воспроизводимые P0 и неподтверждённые обязательные инварианты):
1. **DS-P0-001** — ложный терминальный вердикт «мутации не было» при живой мутации + необратимое повреждение evidence при конкурентном START/RECONCILE (воспроизведено детерминированно двумя независимыми исполнителями; спонтанно 2/8).
2. **DS-P0-002** — удаление lock-файлов приводит ко второй бизнес-мутации для того же fixtureId (2 POST / 2 бизнес-объекта) — прямо нарушает главный критерий задания; собственный тест исполнителя проверяет лишь мёртвый `locks/*.lock` и потому даёт ложное «защищено».
3. **DS-P1-003** — обязательный отказ §13 №6 нестабилен/ fail-open: повторный прогон набора даёт **39/40, exit 1** (crashAfterMutation → PASS); заявление «40/40» не воспроизводится.
4. **DS-P1-004/005/006** — целостность хвоста evidence, семантика CANCEL после intent и доверие к approval не подтверждены.

Заявление предыдущего исполнителя «локальный сценарий PASS / NONE, 1 POST, 1 GET, 40 тестов, устранены forged PASS / cross-process CANCEL / crash / lock / 503» подтверждается **лишь частично**: honest-путь и demo воспроизводятся, но перечисленные защитные механизмы обходятся способами, описанными в C, а набор тестов нестабилен.

### Подтверждено положительно (для протокола)
- Demo и 8/8 независимых браузерных прогонов: PASS/NONE, ровно 1 POST и 1 независимый GET; цепочка Run→Operation→Intent→Request→Response→Entity→IndependentRead→Verdict подтверждена содержимым артефактов.
- Подделка verdict/artifact без пересчёта хэшей, несуществующие evidenceId/checkId, чужой runId/manifest, удаление response, duplicate verdict, evidence после verdict — отклоняются (кроме хвостовой правки, DS-P1-004).
- OBSERVE/RECONCILE на терминальном прогоне ничего не пишут и не запускают браузер; повторный START того же bundle идемпотентен.
- Cross-process CANCEL до intent (POST=0, BLOCKED/CANCELED) и после dispatch (INCONCLUSIVE/CANCELED, POST=1, без повторов) — корректны.
- Crash Control в 4 из 5 точек и orphan-browser: повторного POST нет, дочерние процессы завершаются, reconcile даёт INCONCLUSIVE/WORKER_LOST; отсутствие отказов браузера после dispatch по бизнес-эффекту подтверждается независимым чтением.
- Fixture: bearer, 401 на неверный/отсутствующий токен, фильтр по fixtureId, 400 на пустой параметр GET, 409 на конфликт идемпотентности, replay без второй мутации (в т.ч. 10 параллельных), 413 на >16 КиБ, 404 на неразрешённые методы/пути; секретов в run-каталоге нет.
- Verifier: HTTP 503 с восстановлением → PASS без второго POST; lostResponse/missingEvidence/untrustedId/changedEnvironment → INCONCLUSIVE; partialSave/wrongExecutor → FAIL только после авторитетного GET; дубли fixtureId → INCONCLUSIVE без выбора записи; timeout/hang GET → INCONCLUSIVE; неверный fixture token в Control → нет PASS.
- Схемы 0.1.0 синхронны (`npm run schemas` без diff); `git status` чистый; Dev/ЦИЗ не затрагивались; Node-версия только v24.16.0.

### Что выполнить не удалось / ограничения аудита
- Проверка второй версии Node.js: на машине доступна только v24.16.0; сравнение с иной версией невозможно.
- Настоящий SIGKILL/OOM/crash Chromium (не инъекция): инъекция §13 №6 оказалась несостоятельной (DS-P1-003); поведение реального краша не проверено. До-исправочный Windows-сбой 3221226505 / 0xC0000409 (libuv UV_HANDLE_CLOSING) на текущем коде не воспроизводится (уже исправлен); после исправления 8/8 прогонов завершились кодом 0 без assertion. Проверка «PASS от аварийно завершившегося Verification Worker» выполнена чтением кода (waitForResult + проверка exit code) и штатным прогоном; отдельный тест с принудительным ненулевым exit verifier после отправки RESULT не ставился.
- Windows IPC на уровне ядра (named pipes/job objects) и длительная нагрузка/многопользовательский режим не проверялись.
- Dev ЦИЗ, CIZ Adapter, 23-шаговый сценарий, Intelligence/Workbench — вне рамок и не запускались (запрещено).
- Юридическая неотказуемость/подпись evidence: цепочка локальная, внешнего анкера нет (документированная граница).
- Отдельные микроокна: «intent durable без request»; cancel в промежутке VERIFYING→spawn verifier; конкурентный START с разными bundle для одного runId; прямое снятие chromium-дерева в точках p3/p4 LC-04 — не проверены отдельно (зафиксировано как INCONCLUSIVE/непроверенное).

### Условия повторной приёмки (минимальные)
1. Устранить DS-P0-001 и DS-P0-002 с детерминированными регрессионными тестами (тот же сценарий должен давать отказ без POST и без терминализации активного прогона, журнал — целым).
2. Анкеровать терминальный evidence (DS-P1-004) и сверять verdict с events; запретить append после FINISHED.
3. Сделать CANCEL авторитетным во всех фазах (DS-P1-005).
4. Ввести доверенный approval/fixture/environment-анкер (DS-P1-006/DS-P2-012) — обязательно до CIZ Adapter.
5. Стабилизировать fault-инъекции: §13 №6 должен быть детерминированным; сюита должна проходить N повторов подряд (минимум 3–5) без флака.
6. Повторно подтвердить на независимом Node 24.x и, при возможности, на второй установленной версии.

---

*Отчёт подготовлен по фактическим артефактам аудита 12 ноября 2026. Все репро-скрипты и логи доступны в `C:\Users\gvi\AppData\Local\Temp\kaiden-audit\`; код продукта не изменялся.*
