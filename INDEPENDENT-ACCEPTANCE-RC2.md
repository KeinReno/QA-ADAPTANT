# НЕЗАВИСИМЫЙ ОТЧЁТ О ПРИЁМКЕ KAIDEN QA ADAPTANT 0.1 RC2

**Исполнитель:** DeepSeek (не участвовал в разработке проверяемого кода)
**Дата:** 12 ноября 2026, Europe/Moscow
**Объект:** `C:\Users\gvi\Desktop\QA-ADAPTANT`, HEAD `2f327cab4be42cc0215e24bce78aeefb7c469c92` (master, дерево чистое)
**Предыдущий аудит:** `INDEPENDENT-ACCEPTANCE-REPORT.md`, решение **REJECT**
**Режим:** READ-ONLY code review + black-box / fault-injection, реальный Chromium, локальный стенд 127.0.0.1
**Итоговое решение:** **REJECT**

> Продуктивный код, схемы и контракты не изменялись. В проекте создан только этот отчёт. Все новые репро-скрипты, журналы и артефакты — в `C:\Users\gvi\AppData\Local\Temp\kaiden-audit-rc2\`; артефакты первого аудита (`...\kaiden-audit\`) не перезаписывались.

---

## A. Зафиксированная ревизия исходников

| Параметр | Значение |
|---|---|
| Ветка / HEAD | `master` / `2f327cab4be42cc0215e24bce78aeefb7c469c92` («Зафиксировать Release Candidate 2…») |
| Предыдущая контрольная точка | `1975857123efaabc1c94076e019cc75c1c518a02` |
| `git status` до/после аудита | пусто (кроме созданного отчёта) |
| Контракты | `packages/contracts/index.mjs` и `docs/contract-freeze.json` не менялись; `npm run schemas` → exit 0, `git status` пуст (схемы 0.1.0 синхронны) |
| ОС | Windows 11 Pro 10.0.26100, 64-bit |
| Node.js / npm | v24.16.0 / 11.13.0 (другая версия Node на машине отсутствует) |
| Playwright / Chromium | 1.63.0 / Chromium 153.0.8010.12 (revision 1243) |
| Зависимости | zod 4.6.7, playwright 1.63.0 по lockfile; импортов старых QA/ЦИЗ нет |

Изменения RC2 (коммит `2f327ca`) и их SHA256 в рабочем дереве:

| Файл | SHA256 |
|---|---|
| apps/control/run.mjs | `5583939BD2AE1A27AF55C4C8096BF69D3B99E29757002B6649759CB09B36695F` |
| apps/browser/worker.mjs | `B8C05E7AE0F063237D1E259EE753633FE512F58DEA832BD1B059F98C78963FD2` |
| packages/core/store.mjs | `5DDD2B5D99A8C2FA4651271E11DC8CAE22EA26281CA9BB4864EFBA20C2EEA990` |
| packages/core/evidence-policy.mjs | `955B94489B6A80A3E7BDCC7C264846A720D9FDEAE0400D44AA56746C791B923E` |
| packages/core/approved-registry.mjs | `FF204F6C7686096D5C86692468B99B8774F4FF13ABBA0F7965272DE16AF7CF00` |
| adapters/local/server.mjs | `6F6F4D15480BA99D5CE7DB1B99A39873AC6C3E57EDB43E448593F224AE3B5987` |
| tests/audit-wp.test.mjs | `AC0F7B51827CC9160E8BE74A87977B4D490BD57D62EF33F10BFEAF45B8C36647` |
| docs/changes/002-ownership-evidence-trust.md | `2A2E86BEDCDB40E0CC086ED35275E18EC1587D71C98CD4BBA71DD3BFF476CA9D` |

Заявленные изменения сверены с кодом: owner.json пишется внутри `store.snapshot`; `adoptExisting` обрабатывает EEXIST; `claimFixture` создаёт `fixtures/<digest>/bind.json`; `appendEvidence` пишет `evidence-anchor.json`; `readEvidence` сверяет хвост с анкером; `terminalResult` сверяет verdict с `VERDICT_DURABLE/FINISHED`; `appendEvidence` запрещает запись после verdict; `verifyAndPersist` перечитывает cancel после verifier; `crashAfterMutation` не шлёт DONE и не перезаписывается `exitSoon(0)`; добавлен `approved-registry`; стенд отвечает 400 на POST без строкового `fixtureId` и идемпотентен по `fixtureId`; `state=FINISHED` пишется после вердикта. Все пункты присутствуют.

---

## B. Результаты повторных интеграционных испытаний

### B.1. Пять последовательных полных прогонов набора тестов

Команда: `node --test --test-timeout=45000 tests/*.test.mjs` (лог: `...\kaiden-audit-rc2\lead\full-suite-5x.log`).

| Прогон | Тестов | Pass | Fail | Skip | Exit | Длительность |
|---|---|---|---|---|---|---|
| 1 | 47 | 47 | 0 | 0 | 0 | 40.5 s |
| 2 | 47 | 47 | 0 | 0 | 0 | 40.6 s |
| 3 | 47 | 47 | 0 | 0 | 0 | 41.3 s |
| 4 | 47 | 47 | 0 | 0 | 0 | 48.2 s |
| 5 | 47 | 47 | 0 | 0 | 0 | 43.6 s |

**Заявление Grok «пять прогонов 47/47» подтверждено.** Флак `crashAfterMutation` из первого аудита не воспроизвёлся: 22/22 независимых инъекций дали INCONCLUSIVE/WORKER_LOST (раздел C, DS-P1-003).

### B.2. Десять независимых реальных браузерных прогонов

Скрипт: `...\kaiden-audit-rc2\lead\browser-10-runs.mjs`, результаты: `browser-10-runs.json`. Каждый прогон — новый изолированный стенд, `start()` с реальным Chromium.

| # | Verdict | Reason | POST | Незав. GET | Записей | Evidence kinds | Entity read | State | Exit/ошибка |
|---|---|---|---|---|---|---|---|---|---|
| 1–10 | PASS | NONE | 1 | 1 | 1 | intent→request→response→read→verdict | local-record, совпадает с response | FINISHED | 0 / нет |

Все 10/10: exit 0, PASS/NONE, ровно один разрешённый POST, одно независимое чтение, корректная business entity, полный набор обязательных effect-проверок, целостный журнал evidence, без осиротевших процессов. Длительность одного прогона в RC2 — 2.87–3.50 с (см. P3-наблюдение про задержку shutdown browser worker).

### B.3. Прочие повторные команды

- `node -e` проверки версий — см. A.
- `node packages/contracts/export.mjs` → exit 0, 6 схем, diff отсутствует.
- 12/12 одновременных START (ownership): один PASS + один RUNNING, mutation=1, без сырых EEXIST/ENOENT, журнал читаем.
- 22/22 инъекций `crashAfterMutation`: INCONCLUSIVE/WORKER_LOST, mutation=1, BROWSER_DONE=0, exit code browser worker=86.
- 3/3 SIGKILL Verification Worker: PASS не публикуется, финал INCONCLUSIVE/WORKER_LOST.
- Прямые репро предыдущего аудита (адаптированные копии, оригиналы не изменялись): `start-race`, `lock-deletion`, `fixture-reuse`, `ev07-check`, `cancel-during-verifier` — см. матрицу C.

---

## C. Статус прежних находок

Легенда: FIXED — исходный воспроизводимый дефект закрыт; STILL OPEN — дефект воспроизводится; PARTIAL — исходный сценарий закрыт, остаётся документированный/суженный класс; INCONCLUSIVE — воспроизвести не удалось.

| ID | Статус | Проверка | Фактический результат | Evidence |
|---|---|---|---|---|
| DS-P0-001 START/RECONCILE race | **FIXED** | Оригинальный `start-race` (slowEnvironment 1500 мс): A стартует, B start/reconcile/observe в preflight, после POST, 12 truly simultaneous START | B = `state:RUNNING, verdict:null`; A = PASS/NONE; POST=1; evidence [intent,request,response,read,verdict]; events …VERDICT_DURABLE PASS→FINISHED PASS; OBSERVE/RECONCILE после гонки = PASS; `VERDICT_ORDER` нет; 12/12 без сырых EEXIST/ENOENT | `lead\start-race-result.log`, `ownership\logs\e1-start-race.log`, `e3-simultaneous.log/json`, `e8-postwindow.log` |
| DS-P0-002 удаление locks/leases → второй POST | **FIXED** (заданный сценарий); остаток — W-A-01 (data-dir) | Оригинальный `lock-deletion`: после первого POST удалены `locks/*` и `leases/*`, запущен run2 с тем же fixtureId | B=BLOCKED/CONTRACT_INVALID «Fixture уже связан с другим прогоном» до POST; POST=1; created201=1; recordCount=1; A=PASS. До POST: A=INCONCLUSIVE/WORKER_LOST «Владение fixture потеряно», POST=0 | `lead\lock-deletion-result.log`, `ownership\logs\e4-lock-deletion.log` |
| DS-P1-003 crashAfterMutation fail-open/флак | **FIXED** | 22 независимых прогона fault `crashAfterMutation` (12 последовательных + 10 под параллельной нагрузкой), плюс внешняя фиксация exit code | 22/22 INCONCLUSIVE/WORKER_LOST; mutationCount=1; BROWSER_DONE=0; exit code browser worker=86 во всех 22; evidence-цепочка согласована; повторный START не даёт нового POST; `exitSoon(0)` код аварии не затирает | `lifecycle\logs\01-summary.json`, `01-crash-after-mutation.log`, `01-exit-*.jsonl` |
| DS-P1-004 подмена хвоста evidence | **FIXED** для исходного класса; остаток — DS-P2-024 | Оригинальный `ev07-check`: реальный INCONCLUSIVE, правка только последней строки evidence + artifact sha | OBSERVE/START → `INTEGRITY_ERROR: хвост evidence не совпадает с анкером`; также ловятся: удаление anchor, подмена anchor, рассинхрон anchor/events, правка FINISHED-события без evidence | `lead\ev07-check.log`, `lead\anchor-matrix.log`, `evidence\logs\01-anchor-attacks.log` |
| DS-P1-005 CANCEL during VERIFYING | **FIXED** (основной сценарий); остаточное окно — INCONCLUSIVE; новая гонка anchor — P2 | `cancel-during-verifier` (transientRead, cancel после BROWSER_DONE), cancel до verifier, во время GET, из другого процесса, после опубликованного PASS, повторный cancel; sweep 60+ смещений | cancel во время verifier: CANCEL_REQUESTED → итог **INCONCLUSIVE/CANCELED**, POST=1, без повторов; cancel после PASS возвращает существующий PASS; окно «accepted cancel → PASS» не воспроизведено (0/60+ попыток), остаётся INCONCLUSIVE | `lead\cancel-during-verifier.log`, `lifecycle\logs\02-summary.json`, `02b-summary.json`, `02d-summary.json` |
| DS-P1-006 self-approval / доверие approval | **STILL OPEN** → новая DS-P1-022 | Оригинальные и новые входы: чужой actor, урезанные/лишние effects, подмена operation id/version/mutation/effect.id/field, подмена equals, appliesWhen | Реестр блокирует actor/набор effect.id+field/operation.id/version/mutationName — BLOCKED/CONTRACT_INVALID, POST=0. **НО**: appliesWhen на 2 из 3 эффектов → PASS/NONE при `executorId='operator-wrong'` или `comment=null` в durable чтении; подмена `equals` на фактически сохранённое значение → PASS со всеми SATISFIED при `inputs.executorId='operator-local'`. Registry не фиксирует equals/appliesWhen/required/inputs; actor — просто строка | `lead\applieswhen-bypass.log`, `lead\registry-matrix.log`, `evidence\logs\03-registry.log`, `registry-results.json` |
| DS-P1-008 повторное использование fixtureId | **FIXED** через публичный API; остаток — DS-P2-027 (data-dir) | Оригинальный `fixture-reuse`: run2 с тем же fixtureId и новым runId при активном и завершённом run1; повторный вход того же runId | run2 = BLOCKED/CONTRACT_INVALID до POST; POST delta=0; mutationCount=1; повторный вход того же runId — тот же вердикт без POST. При удалении `fixtures/`+locks+leases второй прогон получает HTTP 200 существующего объекта → PASS на объекте run1 (DS-P2-027) | `lead\fixture-reuse-result.log`, `ownership\logs\e6-fixture-reuse.log`, `e6 reuse-binding-deleted-200` |
| DS-P2-007 independent-read identity | **FIXED** | Перепривязка read parent response→request (+rechain+anchor); подмена entity при parent=response; PASS без response | → `READ_PARENT`; → `READ_IDENTITY`; PASS без response → `VERDICT_CHAIN`; lost-response остаётся INCONCLUSIVE (parent=request допустим только без response) | `lead\read-identity-matrix2.log`, `evidence\logs\02-identity.log` |
| DS-P2-009 producer='verification' у вердикта Control | **STILL OPEN (принято как ограничение)** | Код не менялся; HANDOFF прямо фиксирует отложенность; fault ambiguousButton / tamperSnapshotBeforeBrowser | В evidence `verdict producer='verification'` без процесса verifier; PASS этим путём не публикуется, но provenance-поле ложное; схема 0.1.0 не менялась | `lead\producer-check.log` (RC1), HANDOFF RC2 |
| DS-P2-010 POST без fixtureId считался мутацией | **FIXED** | Прямой POST без/с пустым/нестроковым fixtureId; новый тест репозитория | 400 `fixture_required`, mutationCount=0, recordCount=0; лимит 16 КиБ и 401 сохранены | `tests/audit-wp.test.mjs`, `lead\registry-matrix.log` (0 мутаций в блокировках) |
| DS-P2-011 hang browser на не-2xx | **FIXED** (fail-closed), новая P3-задержка | response.json() ограничен Promise.race 1500 мс | Не-2xx/медленное тело больше не вешает worker до deadline; итог не PASS. Побочно: неочищенный таймер держит event loop до 1.5 с — см. DS-P3-030 | `apps/browser/worker.mjs:103-111`; измерения B.2 |
| DS-P2-012 environment identity — самодекларация | **STILL OPEN (ограничение)** | Код preflight/манифеста не менялся; HANDOFF фиксирует «внешний nonce окружения не сделан» | Control по-прежнему принимает любой localhost-стенд, чей `/environment` повторяет environmentId/fingerprint из переданного манифеста | `apps/control/run.mjs:189-192`, HANDOFF RC2 |
| DS-P2-013 crash при незавершённом snapshot / raw ENOENT | **STILL OPEN** | Детерминированная симуляция: пустой `runs/<id>`, частичный snapshot (только scenario), усечённый evidence.jsonl; живая гонка 12/12 | START/OBSERVE/RECONCILE → exit 1 сырой `ENOENT: scenario.json/operation.json`, без кодового отказа и self-heal; усечённый evidence.jsonl → сырой `Unexpected end of JSON input`. Повторный запуск runId невозможен навсегда | `lead\binding-and-early-window.log`, `ownership\logs\e2-windows.mjs/log`, `lifecycle\logs\03-summary.json` |
| DS-P2-014 одновременный START → сырой EEXIST | **FIXED** | 12 одновременных START с одним runId | 1 PASS + 11 RUNNING, все exit 0, без сырых EEXIST/ENOENT, mutation=1; следующий START → терминальный PASS | `ownership\logs\e3-simultaneous.log/json`, `lifecycle\logs\03-summary.json` |
| DS-P2-015 FINISHED/CREATED, stale browser.pid | **PARTIAL** | observe после PASS; crash до preflight; подложенный чужой PID; процесс-двойник с basename runDir в cmdline | PASS → `state=FINISHED`, CREATED-событий нет (FIXED). Неполный runDir без owner → observe=CREATED (fallback), восстановление даёт INCONCLUSIVE. Чужой процесс без basename не убивается; процесс с basename runDir в cmdline убивается (обход эвристики) — DS-P3-029 | `lifecycle\logs\03-summary.json`, `03-lifecycle.log` |
| DS-P3-016 DRAFT/отравление runId | INCONCLUSIVE (не перепроверялось в RC2) | Не входило в приоритет повторного аудита | — | — |
| DS-P3-017 evidence после FINISHED | **FIXED** | `store.appendEvidence` после терминального verdict | `INTEGRITY_ERROR: после терминального verdict новые evidence запрещены` | `lead\anchor-matrix.log` |
| DS-P3-018 амплификация evidence | STILL OPEN (P3) | Код `maxReadAttempts` не менялся (до 100 чтений) | Не перепроверялось в RC2; ограничение сохраняется | `apps/verification/worker.mjs` |
| DS-P3-019 EVIDENCE_ACK durable=false игнорируется | STILL OPEN (P3) | Код browser не менялся | Ограничение сохраняется | `apps/browser/worker.mjs` |
| DS-P3-020 сырой ENOENT отсутствующего artifact | STILL OPEN (P3) | Удаление anchor/artifact | Сырой ENOENT вместо INTEGRITY_ERROR | `lead\anchor-matrix.log` |
| DS-P2-021 CR-13 (artifact записан, envelope нет) | STILL OPEN (P2) | Код store не менялся; новый anchor добавляет второе окно | Orphan artifact → последующий append того же kind/sequence упирается в no-overwrite; repair отсутствует. Окно envelope→anchor: INTEGRITY_ERROR, repair отсутствует | `lifecycle\logs\03-summary.json` (f) |

---

## D. Новые выявленные дефекты RC2

### DS-P1-022 (P1, БЛОКИРУЮЩИЙ). Доверенный реестр не фиксирует бизнес-семантику: PASS при нарушенных утверждённых эффектах через публичный API

- **Модуль:** `packages/core/approved-registry.mjs` (вся функция `assertApprovedOperation`), `apps/control/run.mjs:185`, `packages/core/evidence-policy.mjs:40-59`, `packages/contracts/index.mjs` (`OperationContract`).
- **Условие:** вызывающий через публичный API (тот же bundle-формат) изменяет `operation.effects[].appliesWhen` и/или `equals`, не меняя id/field. Реестр проверяет только `id/version/mutationName`, actor-строку и набор `effect.id + field`; `appliesWhen`, `equals`, `required`, `inputs` не сверяются.
- **Воспроизводимые шаги:**
  1. `node %TEMP%\kaiden-audit-rc2\lead\applieswhen-bypass.mjs` — fault `wrongExecutor`; для `executor-saved` и `comment-saved` добавлен `appliesWhen={field:'title', equals:'never-matches'}`; пересчитаны operation/scenario/approval/manifest hashes.
  2. `node %TEMP%\kaiden-audit-rc2\lead\registry-matrix.mjs` — варианты: `appliesWhen` на `comment-saved` при fault `partialSave`; подмена `equals` executor-saved на фактически сохранённое значение.
  3. Независимое подтверждение: `%TEMP%\kaiden-audit-rc2\evidence\03-registry.mjs` (R2/R3/R4).
- **Наблюдаемый результат:**
  - appliesWhen: **PASS/NONE**, checks = `[title:SATISFIED, executor:NOT_APPLICABLE, comment:NOT_APPLICABLE]`; durable independent-read содержит `executorId='operator-wrong'` при `inputs.executorId='operator-local'`; mutationCount=1.
  - partialSave: **PASS/NONE**, checks `[SATISFIED, SATISFIED, NOT_APPLICABLE]`, durable read `comment=null`.
  - подмена equals: **PASS/NONE**, все три SATISFIED, durable read `executorId='operator-wrong'` при `inputs.executorId='operator-local'`.
  - Контрольный прогон с исходными (дефолтными) effects на тех же faults даёт FAIL/BUSINESS_INVARIANT_VIOLATED.
- **Нарушенный инвариант:** VERDICT-POLICY («PASS только при всех required и применимых conditional checks»), OPERATION-CONTRACT (эффекты — обязательные проверки), заявленная RC2-гарантия «локальный доверенный реестр фиксирует обязательные эффекты» (CR-002), требование задания «произвольное изменение expected/equals не позволяет обойти утверждённые бизнес-ожидания».
- **Риск:** через публичный API можно получить PASS для утверждённой операции, скрыв фактическое нарушение (неверный исполнитель, отсутствующий комментарий). Для локального стенда это уже ложный PASS; при переносе модели на ЦИЗ — прямой путь к приёмке неверной бизнес-операции.
- **Рекомендация:** реестр должен фиксировать полную семантику утверждённых эффектов: `equals` (или правило `equals == inputs[field]`), отсутствие `appliesWhen` у утверждённых эффектов (либо `appliesWhen` только из утверждённого набора), `required=true`, и сверять `inputs` с утверждённым набором/маркером прогона. Дополнительно — вынести утверждение операции за пределы bundle вызывающего (подписанный/внешний реестр). Добавить регрессионные тесты именно на appliesWhen/equals.
- **Статус:** **CONFIRMED** (Lead + независимо rc2-evidence).

### DS-P2-023 (P2, каталог данных). Реестр не применяется к существующему run-каталогу (observe/start/reconcile)

- **Условие:** каталог прогона уже создан; вызывающий изменяет snapshot (сценарий/операцию с appliesWhen), пересчитывает scenario.operation.sha256/approval/manifest и manifestSha во всех envelope; запускает observe/start/reconcile.
- **Факт:** PASS принимается; `assertApprovedOperation` вызывается только в свежем `run()`.
- **Риск/рекомендация:** закреплять digest утверждённой операции в неизменяемом manifest/owner и проверять его при каждом чтении; либо документировать как границу data-dir (сейчас не документировано).
- **Статус:** CONFIRMED (rc2-evidence, M17).

### DS-P2-024 (P2, каталог данных). Хвост events не анкерован; согласованная правка evidence+anchor+events даёт PASS

- **Условие:** изменить artifact verdict + sha + `evidence-anchor.json` + пересчитать цепочку `events.jsonl` (VERDICT_DURABLE/FINISHED и последующие sha).
- **Факт:** OBSERVE/START → PASS/NONE (подтверждено Lead: `lead\anchor-matrix.log` (partial tamper → INTEGRITY_ERROR), `lead\anchor-full-tamper.log` (evidence+anchor+events → PASS); rc2-evidence X1/X2).
- **Оценка:** защита от одиночной/частичной подмены работает; согласованная правка трёх файлов эквивалентна переписыванию доверенного состояния каталога и не может быть закрыта анкером в том же каталоге. Не блокирует приёмку при явной фиксации ограничения; **в отчёте/документации должно быть сказано прямо**, что анкер не защищает от согласованной правки evidence+anchor+events, а не только от «полной перезаписи диска».
- **Статус:** CONFIRMED.

### DS-P2-025 (P2, новый механизм anchor). Неатомарная пара `evidence.jsonl` + `evidence-anchor.json` даёт ложные INTEGRITY_ERROR у конкурентных читателей/cancel

- **Модуль:** `packages/core/store.mjs:124-128` (append envelope → append anchor отдельными операциями), `store.mjs:153-160` (readEvidence строго сверяет хвост с анкером).
- **Условие:** конкурентный `cancel()`, `observe()`, `start()`/readEvidence в момент между append evidence и записью anchor.
- **Факт (rc2-lifecycle):** 4/56 целевых попыток cancel во время verifier → `INTEGRITY_ERROR: хвост evidence не совпадает с анкером` (3/24, 1/24, 0/8); независимый watcher зафиксировал 108–168 transient anchor-mismatch окон на 4 прогона. Cancel в этих случаях не принят (исключение), прогон штатно публикует PASS; ложного PASS/второй мутации нет.
- **Риск:** операционные сбои cancel/observe/monitor; при совпадении с `start` второй процесс может вместо RUNNING получить INTEGRITY_ERROR.
- **Рекомендация:** сделать коммит журнала атомарным для читателей: писать anchor и envelope как единый commit (например, anchor в отдельном временном файле + rename вместе с append; либо readers при mismatch и живом владельце делают ограниченный retry; либо journal-format с sequence-файлами и анкером, указывающим на последний завершённый commit).
- **Статус:** CONFIRMED (lifecycle, интермиттентный детерминированный repro).

### DS-P2-026 (P2). Fixture binding «отравляется» навсегда: каталог без bind.json, частичный bind, неуспешный preflight, отсутствие release

- **Модуль:** `apps/control/run.mjs:122-137` (`claimFixture`), вызов до preflight (`run.mjs:186`).
- **Факты (Lead + ownership):**
  - `fixtures/<digest>` существует без `bind.json` (crash после mkdir) → все последующие попытки BLOCKED/CONTRACT_INVALID («Fixture уже связан с другим прогоном»), включая тот же runId; фикстура непригодна навсегда.
  - Частичный/битый/пустой `bind.json` → BLOCKED, POST=0.
  - Неуспешный preflight (мёртвый порт/чужой fingerprint) → BLOCKED, привязка сохраняется; новый runId с тем же fixtureId → BLOCKED навсегда; пути освобождения нет.
  - Удаление только `fixtures/` при живом прогоне → bind перезаписывается заблокированной попыткой (durable steal); повторного POST нет, но фикстура закреплена за неуспешным прогоном.
  - Удаление `fixtures/`+locks+leases → второй POST/второй объект (W-A-01); на RC2-стенде с идемпотентностью по fixtureId — HTTP 200 reuse → PASS на объекте run1 (W-A-02/DS-P2-027).
- **Риск:** один транзиентный сбой preflight или crash в микроокне делает fixtureId непригодным; для реального контура потребуется ручная очистка/новый fixture. Безопасность мутаций не нарушена.
- **Рекомендация:** создавать каталог привязки атомарно (temp-dir + bind.json внутри + rename), при неполной привязке давать восстановимую диагностику и карантин; предусмотреть освобождение привязки только при доказанном отсутствии intent/мутации (durable evidence) и с явной командой; документировать release-policy.
- **Статус:** CONFIRMED.

### DS-P2-027 (P2, каталог данных). HTTP 200 идемпотентного reuse принимается как доказательство мутации → PASS на объекте предыдущего прогона

- **Условие:** удалены `fixtures/`, `locks/`, `leases/`; второй runId с тем же fixtureId; стенд отвечает 200 существующего объекта.
- **Факт:** Control/verifier принимают 2xx как ответ мутации; независимое чтение по entity первого объекта; итог **PASS** при 2 POST, 0 новых записей (ownership: reuse-binding-deleted-200).
- **Оценка:** требует записи в каталог данных (удаление durable binding). Тем не менее PASS-цепочка не отличает «создано сейчас» (201) от «уже существовало» (200) и не содержит требования нового business entity.
- **Рекомендация:** для PASS требовать признак создания/уникальности объекта в ответе мутации и/или сверять, что entity не существовало до intent; ввести отдельный reasonCode для idempotent reuse; документировать границу.
- **Статус:** CONFIRMED (ownership).

### DS-P3-028 (P3). Частичный runDir / усечённые журналы дают сырые ошибки парсинга (связано с DS-P2-013)

- Детерминированно: пустой `runs/<id>` → `ENOENT: scenario.json` во всех командах; `evidence.jsonl` без завершающего перевода/усечённый → `Unexpected end of JSON input`; `events.jsonl` усечён → корректный INTEGRITY_ERROR. Нет кодового отказа/self-heal; runId непригоден.
- Рекомендация: единая диагностика `INTEGRITY_ERROR / INCOMPLETE_RUN`, карантин, команда восстановления/нового runId.
- **Статус:** CONFIRMED.

### DS-P3-029 (P3). Эвристика cancel по PID обходится подделкой cmdline

- `recordedBrowserPid` проверяет, что CommandLine процесса-кандидата содержит basename runDir. Процесс-двойник, в чьей cmdline есть basename, будет убит `taskkill /T /F` при cancel (1/1 воспроизведено). Чужой процесс без basename не убивается (защита работает).
- Рекомендация: хранить в `browser.pid` собственный случайный nonce/identity (например, environment/start time + nonce в аргументах worker) и проверять его, а не подстроку пути.
- **Статус:** CONFIRMED (lifecycle).

### DS-P3-030 (P3, наблюдение). Browser Worker задерживает shutdown на ~1.5 с из-за неочищенного таймера body-timeout

- Новый `Promise.race([response.json(), timeout 1500])` не очищает таймер и не `unref`-ает его; процесс worker живёт до срабатывания таймера. Длительность PASS-прогона выросла с 1.39–1.54 с (RC1) до 2.87–3.50 с (RC2, B.2), при том же составе шагов.
- Рекомендация: очищать таймер в `finally`/по завершении race (AbortSignal.timeout/clearTimeout), `unref()` таймер.
- **Статус:** CONFIRMED (измерения).

---

## E. Модель угроз (по факту испытаний)

| Уровень | Что подтверждено |
|---|---|
| **1. Только публичный API** (bundle, CLI start/observe/cancel/reconcile) | **DS-P1-022/DS-P1-006:** PASS при нарушенных утверждённых эффектах через appliesWhen/equals; actor — самодекларация. Остальное закрыто: self-approval с чужим actor/урезанным набором/подменой operation id/version/mutation/effect.id/field → BLOCKED; повторный run с тем же fixtureId → BLOCKED; forged PASS через пересборку evidence недоступен (нет записи в каталог). |
| **2. Частичный доступ на запись в каталог данных** | Подмена только хвоста evidence / anchor / FINISHED-события → INTEGRITY_ERROR (FIXED). **Остаётся:** согласованная правка evidence+anchor+events → PASS (DS-P2-024); registry не применяется к существующему run (DS-P2-023); удаление fixtures/locks/leases → второй POST/ложный PASS (W-A-01/DS-P2-027); частичный runDir → нечитаемость; anchor-гонка при конкурентном чтении; удаление owner.json убивает живой прогон (INCONCLUSIVE, без второго POST). |
| **3. Полный контроль процесса и диска** | Полная пересборка hash-цепи и поддельный PASS без браузера/verifier — принимается; это документированная граница 0.1 (ARCHITECTURE, CR-002), внешнего анкера/подписи нет. |

---

## F. Непроверенные области

- Вторая версия Node.js: доступна только v24.16.0; сравнение невозможно.
- Реальный Dev/ЦИЗ, CIZ Adapter, 23-шаговый сценарий, Intelligence/Workbench — не запускались (запрещено).
- Живое микроокно `mkdir(runDir) → первый snapshot` не поймано в естественной гонке (12/12 одновременных START чистые); доказано детерминированной симуляцией частичного runDir.
- Crash-инъекция Control в момент незавершённого snapshot (kill -9 посреди записи) не выполнялась отдельно; исследованы последствия такого состояния.
- Гонка `accepted CANCEL → PASS`: 0/60+ попыток, точная ширина окна < 1 мс — статус INCONCLUSIVE (отсутствие не доказано).
- Точный exit code Verification Worker при SIGKILL (Windows не вызывает exit-hook) — не снят; по коду и поведению PASS не публикуется.
- Нагрузка >2 одновременных Control-процессов на один runId; headed-режим; иные ОС; длительная (часы) эксплуатация.
- Юридическая неотказуемость/подпись evidence (внешний анкер) — не реализована и не проверялась.

---

## G. Сохранившиеся архитектурные ограничения

1. **Approval остаётся самодекларацией:** actor `local-test-harness` — строка, которую пишет вызывающий; реестр сужает пространство операций до `local-create-record 1.0.0`, но не аутентифицирует владельца и (DS-P1-022) не фиксирует бизнес-ожидания. Для Dev это означает: локальная модель 0.1 **не является** авторизацией операций ЦИЗ; перед Dev обязательны внешнее подтверждение владельца и подписанный/внешний реестр.
2. **Environment identity:** nonce/fingerprint по-прежнему берутся из манифеста вызывающего; любой localhost-стенд, повторяющий их, принимается. Внешний nonce, создаваемый harness, не реализован (зафиксировано в HANDOFF).
3. **Анкер evidence локальный:** защищает от одиночной/частичной подмены, но не от согласованной правки evidence+anchor+events и не от полной перезаписи каталога; внешний анкер не реализован.
4. **Fixture ownership — файловый:** durable bind в `fixtures/` переживает locks/leases, но не удаление каталога привязки; согласованного release-policy нет; «отравление» фикстуры при сбое preflight/crash.
5. **Двойной писатель журнала в разных фазах** (Control/verifier) и неатомарный commit envelope+anchor дают конкурентные INTEGRITY_ERROR; журнал не является транзакционным.
6. **Producer='verification' у вердиктов, которые пишет Control** — известное отложенное ограничение из-за замороженной схемы 0.1.0; потребитель не может отличить независимую проверку от Control-решения.
7. Модульные границы в целом сохранены: Control/Browser/Verification разделены процессами, контракты 0.1.0 не менялись, схемы синхронны, импортов старых QA/ЦИЗ нет, «монолита» нет.

---

## H. Итоговое заключение: **REJECT**

**Подтверждено ФИКСАМИ (положительно):**
- DS-P0-001, DS-P0-002 (заданный сценарий), DS-P1-003 (22/22), DS-P1-004 (исходный класс), DS-P1-005 (основные сценарии), DS-P1-008 (публичный API), DS-P2-007, DS-P2-010, DS-P2-014, DS-P3-017 — закрыты.
- 5/5 полных прогонов: 47/47, exit 0; 10/10 браузерных: PASS/NONE, 1 POST, 1 GET, FINISHED, целостный evidence; 12/12 одновременных START без сырых ошибок; 22/22 crash-инъекций INCONCLUSIVE; 3/3 SIGKILL verifier без PASS; схемы 0.1.0 без diff.

**Почему REJECT (блокирующие основания):**
1. **DS-P1-022 (P1, блокирующий, воспроизведён Lead и независимо rc2-evidence):** доверенный реестр не фиксирует `equals/appliesWhen/required/inputs`; через публичный API получен **PASS/NONE при фактически нарушенном утверждённом эффекте** (неверный исполнитель / отсутствующий комментарий в durable independent-read). Это прямое нарушение обязательного инварианта «PASS только после всех обязательных проверок», поэтому приёмка невозможна. Исходный DS-P1-006 остаётся STILL OPEN в суженном виде.
2. **DS-P2-013 (STILL OPEN):** неполный runDir/усечённые журналы дают сырые ENOENT/parse-ошибки без кодового отказа и self-heal; runId навсегда непригоден (детерминированно; живое окно узкое).
3. **DS-P2-025 (новый P2):** неатомарный commit evidence+anchor даёт интермиттентные ложные INTEGRITY_ERROR у конкурентных cancel/observe/start (4/56; 108–168 transient окон на 4 прогона) — новый механизм сам создал гонку.

**Что должно быть исправлено до повторной приёмки:**
1. Реестр/approval: зафиксировать полную семантику утверждённых эффектов (equals или правило equals==inputs[field], запрет appliesWhen/required=false, утверждённый набор inputs) и вынести проверку за пределы bundle вызывающего; добавить регрессии на appliesWhen/equals. (DS-P1-022)
2. Сделать commit evidence+anchor атомарным для читателей либо добавить безопасный retry при живом владельце; убрать ложные INTEGRITY_ERROR. (DS-P2-025)
3. Обработать частичный/усечённый runDir кодовым INCOMPLETE_RUN/карантином и self-heal; не оставлять runId навсегда непригодным. (DS-P2-013/DS-P3-028)
4. Ввести атомарное создание fixture bind (temp-dir+rename) и политику освобождения при доказанном отсутствии мутации; убрать «отравление» fixture. (DS-P2-026)
5. Для PASS отличать создание от idempotent reuse (200 vs 201 / новый entity), документировать границу data-dir. (DS-P2-027)
6. Зафиксировать в документации реальную гарантию анкера: защита от одиночной/частичной подмены, но не от согласованной правки evidence+anchor+events; при желании — внешний анкер. (DS-P2-024)
7. Устранить P3: raw parse errors, PID-эвристика cancel, задержка shutdown browser worker; закрыть отложенные DS-P2-009/DS-P2-012 или явно ограничить область 0.1.

**Решение:** **REJECT**. RC2 существенно улучшил ядро и подтвердил большинство заявлений Grok (47/47, 10/10, закрытие P0-001/002, crash/cancel/fixture/tail), но новый доверенный реестр обходится через публичный API с получением PASS при нарушенных утверждённых бизнес-ожиданиях, а новые механизмы (anchor, fixture bind) создали как минимум одну воспроизводимую конкурентную ошибку и сохранили проблемы восстановления неполного runDir. До устранения DS-P1-022 и DS-P2-013 приёмка 0.1 Stable невозможна.

---

*Все репро и логи: `C:\Users\gvi\AppData\Local\Temp\kaiden-audit-rc2\` — lead (start-race, lock-deletion, fixture-reuse, ev07, cancel, applieswhen, registry-matrix, anchor-matrix, anchor-full-tamper, read-identity, binding-and-early-window, full-suite-5x.log, browser-10-runs.json), ownership (AUDIT-RC2-WP-A-ownership.md, logs/e1..e8), evidence (REPORT-WP-B.md, logs), lifecycle (logs/01..04-summary.json, artifacts). Код продукта не изменялся; в проекте создан только этот отчёт.*
