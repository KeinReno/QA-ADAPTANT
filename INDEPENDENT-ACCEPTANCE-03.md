# НЕЗАВИСИМЫЙ ОТЧЁТ О ТРЕТЬЕЙ ПРИЁМКЕ KAIDEN QA ADAPTANT 0.1

**Исполнитель:** DeepSeek (не участвовал в разработке проверяемого кода)
**Дата:** 12 ноября 2026, Europe/Moscow
**Объект:** `C:\Users\gvi\Desktop\QA-ADAPTANT`, HEAD `68ca86f805c39d7a410d87d81d4c4af986b4f2cd` («Зафиксировать точечные исправления после REJECT RC2»)
**Предыдущие отчёты:** `INDEPENDENT-ACCEPTANCE-REPORT.md` (REJECT), `INDEPENDENT-ACCEPTANCE-RC2.md` (REJECT)
**Режим:** READ-ONLY + black-box / white-box / fault injection
**Итоговое решение:** **REJECT**

> Продуктивный код, контракты и схемы не изменялись. В проекте создан только этот отчёт. Все репро и журналы — в `C:\Users\gvi\AppData\Local\Temp\kaiden-audit-final03\`. Артефакты предыдущих аудитов сохранены без изменений. Ревизия не менялась во время аудита: SHA256 изменённых файлов после всех испытаний совпадают с зафиксированными до начала.

---

## A. Зафиксированная ревизия

| Параметр | Значение |
|---|---|
| Ветка / HEAD | `master` / `68ca86f805c39d7a410d87d81d4c4af986b4f2cd` |
| Предыдущая точка | `2f327cab4be42cc0215e24bce78aeefb7c469c92` (RC2, REJECT) |
| `git status` | пусто до и после аудита (кроме созданного отчёта) |
| Схемы 0.1.0 | `npm run schemas` → exit 0, diff отсутствует |
| ОС / Node / Playwright / Chromium | Windows 11 Pro 10.0.26100 / v24.16.0 / 1.63.0 / Chromium 153.0.8010.12 (rev 1243) |
| Другая версия Node | отсутствует на машине (nvm не установлен); сравнение невозможно |

Изменённые файлы и их SHA256 (совпали до/после аудита):

| Файл | SHA256 |
|---|---|
| apps/control/run.mjs | `0CBA9542C843496E57E427CD901253C309F26D3C232949E65222DEB0E6106E94` |
| apps/browser/worker.mjs | `33CB82C6F372F169ABFB0EBED5B9B112A19728F9D3451FE1A3F5FA34FD351ABB` |
| apps/verification/worker.mjs | `A53FD5D23AD7727C63F01C58F3F03FEF5C594F8A55973FA94A3A27D95BB9EB14` |
| packages/core/store.mjs | `1A55165CEDC7B891A5A98BA9A7A44AE211869B78926FB2D522F87B3E603509AA` |
| packages/core/approved-registry.mjs | `5E59188027F051FA2530E141DC10AD3D0F59DFFD654E08E7E929FE1B5F66AFB0` |
| docs/changes/003-approval-semantics-and-recovery.md | `101D812D37FF8AA9062A71FCBBBE1524AB540C414C6527E33251F2CEF728F388` |
| tests/audit-wp.test.mjs | `B0A8B42F03647A19E077C617DB12DA25ECE7E6C025CB98F004DB47E2EBA43D32` |
| HANDOFF.md / ACCEPTANCE-REPORT.md | `A10AE01E…` / `DE4A5AF1…` |

Реализация сверена с CR-003: реестр проверяет точный набор inputs, `required=true`, отсутствие `appliesWhen`, `equals === inputs[field]`; `terminalResult` повторно применяет реестр к сохранённым PASS/FAIL; анкер хранит `byteLength`; `appendEvidence` перезаписывает ровно подтверждённый префикс; `INCOMPLETE_RUN`/quarantine; атомарная публикация fixture через temp-dir+rename; release только без mutation evidence; browser nonce; HTTP 200 → INCONCLUSIVE.

---

## B. Матрица утверждённых бизнес-эффектов (DS-P1-022)

Метод: публичный API `start()`/`observe()`; для каждого кейса пересчитаны все локальные SHA (scenario/operation/approval/manifest), чтобы исключить hash-mismatch как причину отказа. Evidence: `lead\approval-matrix.mjs/.json`, `approval\matrix.mjs`, `approval\REPORT-DS-P1-022.md`, `evidence\03-registry*`.

| Кейс | Ожидание | Факт | POST/mutation/record | Итог |
|---|---|---|---|---|
| Контроль без изменений | PASS | PASS/NONE, checks SATISFIED | 1 / 1 / 1 | OK |
| Удалён обязательный эффект | отказ до POST | BLOCKED/CONTRACT_INVALID | 0 / 0 / 0 | FIXED |
| `appliesWhen` «никогда не выполняется» | отказ | BLOCKED «не может быть отключён условием» | 0 / 0 / 0 | FIXED |
| `required=false` | отказ | BLOCKED «обязан оставаться обязательным» | 0 / 0 / 0 | FIXED |
| `equals` = фактически сохранённое неверное значение (wrongExecutor) | отказ | BLOCKED «не совпадает с утверждённым входом» | 0 / 0 / 0 | FIXED |
| Подмена `inputs.executorId/comment` | отказ | BLOCKED (equals ≠ inputs) | 0 / 0 / 0 | FIXED |
| Подмена `operation.id/version/mutationName` | отказ | CONTRACT_INVALID/«Неизвестная мутация» | 0 / 0 / 0 | FIXED |
| Подмена `approval.actor` | отказ | BLOCKED/CONTRACT_INVALID | 0 / 0 / 0 | FIXED |
| Лишний/недостающий input | отказ | BLOCKED «Набор входов…» | 0 / 0 / 0 | FIXED |
| Лишний/подменённый effect.id/field | отказ | BLOCKED «Набор обязательных эффектов…» | 0 / 0 / 0 | FIXED |
| Полная подмена operation + пересчёт всех SHA | отказ | BLOCKED/CONTRACT_INVALID | 0 / 0 / 0 | FIXED |
| Повторный OBSERVE/START сохранённого PASS после правки snapshot | отказ | hash-mismatch / INTEGRITY_ERROR VERDICT_SCOPE; при изменении реестра — CONTRACT_INVALID | 0 / 0 / 0 | FIXED |
| Подмена реестра через входной bundle | игнорируется/отказ | top-level ignored; в operation/scenario — schema reject | 0 / 0 / 0 | FIXED |
| Контроль partialSave (дефолтные effects) | FAIL | FAIL/BUSINESS_INVARIANT_VIOLATED | 1 / 1 / 1 | OK |

**Итог DS-P1-022: FIXED** в границах локального ядра. Повторов: 2 на кейс, контроль и ключевой кейс — 3; exit code репро 0.

**Граница доверия (ответ на п. 4.4):** да, вызывающая сторона по-прежнему может полностью сформировать APPROVED-операцию с произвольными значениями `inputs` (title/executorId/comment), удовлетворяющими реестру, и пересчитать все SHA. Реестр фиксирует **структуру и семантику эффектов** (набор полей, обязательность, отсутствие условий, `equals === inputs`), но **не аутентифицирует владельца** (actor — публичный литерал) и **не авторизует значения входов**. Для локальной 0.1 это допустимый семантический предохранитель; для Dev/ЦИЗ обязательны подписанный approval-артефакт, доверенный реестр из артефакта сборки и авторизация входных значений/ролей/сущностей. Дополнительно: `null` допустим как scalar — до адаптеров, разрешающих null, семантику нужно закрыть.

---

## C. Матрица конкурентного доступа к evidence (DS-P2-025) — блокирующий дефект

### C.1. Что исправлено (read-side)

- Хвост байтов после `anchor.byteLength` игнорируется и не считается повреждением: R3/R3b, crash-window (b/e/f) — OBSERVE/START/RECONCILE корректны.
- Append после терминального verdict через API запрещён.
- `appendEvidence` перезаписывает ровно «подтверждённый префикс + новый envelope»; uncommitted хвост отбрасывается (R12).
- Читатели при наших нагрузках не получали ложных INTEGRITY: 0 ошибок на 2 615 reader-чтений и 213 конкурентных OBSERVE (независимый аудитор), 0 ошибок в наших 800+ observe-вызовах.
- Crash-window матрица (15 кейсов): мутация/intent/request/response в committed prefix не теряются, повторного POST нет; (a) orphan artifact на терминальном PASS не мешает; (b) envelope+старый anchor → хвост игнорируется; (c/d) отсутствие VERDICT_DURABLE/FINISHED восстанавливается по anchor; (e) torn tail; (f) anchor над torn-JSON → INCOMPLETE_RUN; (g) anchor за EOF → INTEGRITY_ERROR; (h–j) SIGKILL после response → INCONCLUSIVE/WORKER_LOST, POST 1→1; (k/m) incomplete без mutation evidence → quarantine + новый прогон ровно с 1 POST; (l) incomplete с mutation evidence → INCOMPLETE_RUN без quarantine и без повторного POST.

### C.2. Новый блокирующий дефект: FINAL03-EV-01 — EPERM rename при конкурентных читателях (P1)

- **Модуль:** `packages/core/store.mjs:9–19` (`atomicWrite`: temp + fsync + `renameSync` поверх целевого файла), `store.mjs:112–118` (`#readAnchor`), `store.mjs:195–206` (`readEvidence`), `store.mjs:168–193` (`appendEvidence`: artifact → evidence → anchor).
- **Условие:** другой процесс читает `evidence.jsonl`/`evidence-anchor.json` (легитимный OBSERVE, мониторинг, второй Control, cancel) в момент, когда writer делает `renameSync` поверх открытого read-handle. На Windows 11 + Node 24 это даёт `EPERM: operation not permitted, rename … -> evidence-anchor.json`. Retry/backoff в `atomicWrite` отсутствует.
- **Минимальное OS-подтверждение (без кода продукта):** rename поверх файла 400 раз: 0 читателей — 400/400 OK; 2 читателя — 0/400; 6 читателей — 0/400 (все EPERM). Читатель только `stat` — 300/300 OK; читатель с `readFileSync` — 1/300 OK, 299 EPERM. Блокирует именно открытый read-handle.
- **Прямой store.appendEvidence под читателями:** 0 читателей — 120/120 OK; 1 читатель — 49/120; 2 читателя — 2/120; 6 читателей — 0/120.
- **Живой прогон (Lead, 2 observer-процесса @5 мс, 8 запусков):** PASS 3/8; EPERM rename `evidence-anchor.json` 2/8 (итог INCONCLUSIVE/WORKER_LOST); INTEGRITY_ERROR 2/8; raw `INTEGRITY_ERROR: запрещена перезапись evidence` 1/8. Наблюдатели: 0 ошибок.
- **Живой прогон (независимый аудитор):** 4 observer-процесса @50 мс + CLI + in-process (213 OBSERVE во время активного прогона) → прогон INCONCLUSIVE/EVIDENCE_MISSING при POST=1 и record=1. 30 запусков с 3 reader-процессами @50 мс: PASS 15/30; EVIDENCE_MISSING 6; WORKER_LOST 3; INCONCLUSIVE/INTEGRITY_ERROR 2; hard `INTEGRITY_ERROR: запрещена перезапись evidence` 4/30. 13/31 run-каталогов с orphan-artifact, 4/31 с uncommitted tail.
- **Последствия:** валидный прогон с реально выполненной и независимо подтверждённой мутацией деградирует в INCONCLUSIVE или падает сырой ошибкой; появляются orphan artifacts и незавершённые хвосты; запуск/мониторинг из второго процесса способен сорвать прогон. Ложного PASS и повторного POST **не** возникает (fail-closed), mutationCount ≤ 1.
- **Нарушенный инвариант:** обязательный сценарий OBSERVE из другого процесса и требование п. 5.2 (100 конкурентных OBSERVE без ложных INTEGRITY, без порчи прогона); «конкурентные операции не искажают бизнес-результат» (правила оценки §13).
- **Рекомендация:** устранить перезапись читаемых файлов через rename либо добавить устойчивый commit-протокол: (1) bounded retry с backoff на EPERM/EBUSY/EACCES для `renameSync` (как минимум 3–5 попыток с задержкой); (2) вернуть append-only запись `evidence.jsonl` (`appendFileSync` + fsync) вместо полной перезаписи через rename; (3) anchor публиковать через `rename` только после успешного append, с retry; (4) либо использовать файловую блокировку/иной способ координации чтения-записи; (5) добавить регрессионные тесты: 1/2/6 конкурентных reader-процессов на активном прогоне (100+ OBSERVE), ожидание — PASS и отсутствие orphan-artifacts.
- **Статус:** **CONFIRMED** (Lead + независимый аудитор; OS-level минимальный repro).
- **Evidence:** `lead\reader-load-batches.json`, `lead\concurrent-observe-impact.json`, `lead\debug-reader*.json/.log`, `lead\debug-loop\it3` (вердикт с EPERM в message, два artifact на sequence 1), `evidence\os-rename-results.json`, `evidence\os-rename2-results.json`, `evidence\write-contention-results.json`, `evidence\live-reader-impact-results.json`, `evidence\concurrency-results.json`, `evidence\REPORT-FINAL03-EVIDENCE.md`.

**Итог DS-P2-025: PARTIAL** — заявленная read-side гонка (ложные INTEGRITY у читателей) FIXED, но общая гарантия конкурентного доступа **STILL OPEN** из-за нового дефекта записи FINAL03-EV-01. Блокирует приёмку.

### C.3. Матрица подмены anchor/evidence

Отклонено (OBSERVE/START/RECONCILE): `byteLength−10` (INCOMPLETE_RUN), `byteLength+10` (INTEGRITY), случайный `envelopeSha256`, `sequence=99`, чужой anchor, правка artifact/envelope в committed prefix, согласованная правка evidence+anchor без events (ловится сверкой verdict↔events), ручная допись после verdict (VERDICT_ORDER), удаление anchor, усечение журнала. Хвост после anchor игнорируется. Согласованная правка evidence+anchor+events принимается — документированная граница каталога (CR-003/ARCHITECTURE:17), не regression. Остатки: **EV-02 (P2)** — anchor rollback (откат на более короткий подтверждённый префикс) OBSERVE принимает: verdict=null/state FINISHED (терминальный verdict скрыт), при этом START/RECONCILE падают fail-closed INTEGRITY_ERROR (меняется только events.jsonl); **DS-P3-020** — удалённый artifact даёт сырой ENOENT вместо INTEGRITY_ERROR (наследственный).

---

## D. Матрица восстановления после crash (DS-P2-013)

Evidence: `lead\recovery-matrix.mjs/.json`, `recovery\recovery-matrix.mjs/.json`, `evidence\crash-window-results.json`.

| Состояние | Ожидание | Факт (Lead) | Повторный POST | Итог |
|---|---|---|---|---|
| Пустой `runs/<id>` | кодовый отказ/quarantine | quarantine + новый прогон PASS, mutation 1 | нет | FIXED |
| Только scenario.json | восстановление | quarantine (через INCOMPLETE_RUN без mutation evidence) + PASS | нет | FIXED |
| Только manifest.json | восстановление | PASS после quarantine | нет | FIXED |
| Нет operation.json | восстановление | PASS после quarantine | нет | FIXED |
| Усечённый evidence.jsonl | структурированный отказ | INTEGRITY_ERROR «хвост evidence не совпадает с анкером»; START/OBSERVE exit 1 | нет | FIXED (fail-closed) |
| Усечённый events.jsonl | структурированный отказ | INTEGRITY_ERROR «неполная запись журнала событий» | нет | FIXED |
| Повреждённый JSON scenario | INCOMPLETE_RUN | INCOMPLETE_RUN; START refuses без retry | нет | FIXED |
| Отсутствующий anchor | отказ | INTEGRITY_ERROR «хвост evidence не совпадает с анкером» | нет | FIXED |
| Snapshot без журналов | восстановление | reconcile → RUNNING (owner жив в симуляции), observe → CREATED | нет | INCONCLUSIVE (симуляция с живым owner) |
| Mutation committed + повреждённый manifest | fail-closed | INCOMPLETE_RUN, quarantine не выполняется, mutation не повторяется | нет | FIXED (ручное вмешательство) |
| Хвост после anchor (torn JSON) | игнорировать | OBSERVE/START → PASS, хвост отброшен | нет | FIXED |
| append после терминального verdict | отказ | INTEGRITY_ERROR | нет | FIXED |

**Итог DS-P2-013: FIXED** — сырые ENOENT/SyntaxError заменены `INCOMPLETE_RUN`/INTEGRITY_ERROR, неполный каталог без mutation evidence уходит в quarantine и перезапускается, с mutation evidence — fail-closed без повторной мутации. Остаётся документированное ограничение: runId с возможно выполненной мутацией и нечитаемым журналом требует ручного вмешательства (INCOMPLETE_RUN), автоматического восстановления нет.

---

## E. Fixture ownership и idempotency (DS-P2-026/027)

Evidence: `recovery\fixture-idempotency-matrix.mjs/.json`, `recovery\custom-stand-matrix.mjs/.json`, `recovery\cancel-nonce-matrix.mjs/.json`.

| Сценарий | Ожидание | Факт | POST/mutation/records | Итог |
|---|---|---|---|---|
| Каталог `fixtures/<digest>` без bind.json | не блокировать навсегда | PASS, старый каталог в quarantine | 1 / 1 / 1 | FIXED |
| Частичный/битый `bind.json` | восстановление | PASS через quarantine | 1 / 1 / 1 | FIXED |
| Валидный пустой `{}` bind | восстановление | PASS | 1 / 1 / 1 | FIXED |
| Остаточный temp-dir `.bind-*` | не мешать | PASS | 1 / 1 / 1 | FIXED |
| Два процесса на один fixtureId | один владелец | A PASS, B BLOCKED/CONTRACT_INVALID | 1 / 1 / 1 | FIXED |
| Неуспешный preflight, затем новый runId | безопасное освобождение | первый BLOCKED, второй PASS после release | 1 / 1 / 1 | FIXED |
| Тот же fixtureId после PASS | отказ | BLOCKED до POST | delta 0 | FIXED |
| Удаление locks/leases при активном прогоне | нет второй мутации | BLOCKED по durable bind | 1 / 1 / 1 | FIXED |
| Удаление fixtures+locks+leases, второй runId, ответ 200 | нет ложного PASS | INCONCLUSIVE/RESULT_UNCONFIRMED «HTTP 200 вернул существующий объект» | 2 POST (по evidence двух прогонов) / 1 / 1 | FIXED |
| Прямой серверный replay (тот же idempotency-key) | 200, без мутации | 201, 200, 200; один id | 1 / 1 / 1 | OK |
| Кастомный стенд: 200 правильная entity | нет PASS | INCONCLUSIVE/RESULT_UNCONFIRMED | 1 / — / 1 | FIXED |
| Кастомный стенд: 200 чужая entity | нет PASS | INCONCLUSIVE (identity/RESULT_UNCONFIRMED) | 1 / — / 0 | FIXED |
| Кастомный стенд: 201 новая entity | PASS | PASS, checks SATISFIED | 1 / 1 / 1 | OK |
| Кастомный стенд: 201 на уже существующую entity | — | **PASS** (status 201 принят как создание) | 1 / — / 1 | Ограничение серверного доверия |

**Итог DS-P2-026: FIXED. DS-P2-027: FIXED** для локального стенда: HTTP 200 reuse → `INCONCLUSIVE / RESULT_UNCONFIRMED`, ложного PASS нет. Сохраняющееся ограничение: если сервер лжёт статусом 201 для уже существующего объекта, локальное ядро не может отличить это от создания — такие гарантии должен давать API ЦИЗ (серверная семантика создания/idempotency/ownership), а не локальный статус. Это явно фиксируется как предусловие Dev/ЦИЗ.

**CANCEL/identity:** decoy-процесс с basename каталога в cmdline (без nonce) не убивается (FIXED); повреждённый/отсутствующий browser.pid не ломает cancel (FIXED); подделанный browser.pid с известным nonce (запись в каталог данных) позволяет убить чужой процесс-двойник — документированная граница «доступ к каталогу данных», не публичный API. CANCEL во время VERIFYING: 10/10 INCONCLUSIVE/CANCELED, POST=1, без повторов.

---

## F. Полные тестовые прогоны (54 теста)

Команда: `node --test --test-timeout=45000 tests/*.test.mjs`. Лог: `lead\full-suite-5x.log`.

| Прогон | Tests | Pass | Fail | Exit | Длительность |
|---|---|---|---|---|---|
| 1 | 54 | 54 | 0 | 0 | 45.5 s |
| 2 | 54 | 54 | 0 | 0 | 49.6 s |
| 3 | 54 | **53** | **1** | **1** | 56.3 s |
| 4 | 54 | 54 | 0 | 0 | 51.0 s |
| 5 | 54 | 54 | 0 | 0 | 55.8 s |

Заявленные 54 теста подтверждены. Прогон 3 упал на `fault duplicateIntent: PASS, POST=1` во время параллельной нагрузки от двух других аудиторских процессов. В изоляции тот же тест — **8/8 pass**; три одновременных прогона `tests/faults.test.mjs` под нагрузкой — **12/12 в каждом**. Причина падения в логе не детализирована (вывод теста усечён), воспроизвести без внешней нагрузки не удалось. Классификация: **P3 — нестабильность набора под внешней нагрузкой**, не воспроизводимый продуктовый дефект; для ACCEPT набор должен быть стабилен 5/5, поэтому это учитывается в решении, но не является главным блокером.

---

## G. Реальные браузерные и интеграционные матрицы

| Матрица | Повторов | Ожидание | Факт |
|---|---|---|---|
| Реальные Chromium PASS | 10 | PASS/NONE, 1 POST, 1 GET, entity, FINISHED, evidence | **10/10 PASS**, mutation=1, read=1, record=1, evidence kinds intent→request→response→read→verdict, state FINISHED |
| crashAfterMutation | 10 | не PASS, нет BROWSER_DONE, POST=1 | **10/10 INCONCLUSIVE/WORKER_LOST**, DONE=0, mutation=1 |
| Concurrent START (два процесса, один bundle) | 10 | один PASS + RUNNING, 1 POST, журнал цел | **10/10** один PASS + второй RUNNING, mutation=1, журнал заканчивается verdict |
| CANCEL во время VERIFIER | 10 | INCONCLUSIVE/CANCELED, POST=1 | **10/10** CANCEL_REQUESTED → INCONCLUSIVE/CANCELED, mutation=1 |
| Старые P0-репро | по 1 | нет регрессий | start-race: B RUNNING, A PASS, журнал цел; lock-deletion: B BLOCKED, POST=1; fixture-reuse: B BLOCKED; ev07: INTEGRITY_ERROR; cancel-verifier: INCONCLUSIVE/CANCELED |

Схемы: `npm run schemas` exit 0, `git status` пуст. Осиротевших Playwright-Chromium/node-процессов после аудита нет.

---

## H. Новые подтверждённые дефекты

| ID | Приоритет | Суть | Статус |
|---|---|---|---|
| **FINAL03-EV-01** | **P1 (блокирующий)** | Конкурентные читатели `evidence.jsonl`/`evidence-anchor.json` вызывают `EPERM` на `renameSync` в `atomicWrite` (Windows), retry нет; валидный прогон деградирует в INCONCLUSIVE/raw INTEGRITY_ERROR; 1 reader — 4/6 non-PASS, 3 readers — 15/30 PASS; orphan artifacts 13/31; повторного POST/ложного PASS нет | CONFIRMED |
| EV-02 | P2 | Anchor rollback: OBSERVE принимает укороченный подтверждённый префикс (terminвердикт скрыт, state FINISHED), START/RECONCILE fail-closed INTEGRITY_ERROR; требует записи в каталог данных | CONFIRMED |
| EV-03 | P3 | Удалённый artifact → сырой ENOENT вместо INTEGRITY_ERROR (наследственный DS-P3-020) | CONFIRMED |
| EV-04 | P3 | `fault duplicateIntent` флейкует под внешней нагрузкой (1/5 полных прогонов; изоляция 8/8, 3×concurrent faults 36/36) | INCONCLUSIVE (не воспроизведён изолированно) |
| EV-05 | Ограничение | 201 на уже существующую entity принимается как создание; 200 reuse корректно отклоняется. Гарантия новизны объекта должна обеспечиваться API ЦИЗ | Документированная граница |

---

## I. Ограничения модели угроз

1. **Публичный API:** обход утверждённых бизнес-эффектов не найден (DS-P1-022 FIXED). Вызывающий по-прежнему задаёт значения inputs, удовлетворяющие реестру; owner-аутентификации и авторизации значений в 0.1 нет (до Dev/ЦИЗ обязательны внешний approval и авторизация входов).
2. **Частичный доступ к каталогу данных:** одиночная/частичная подмена evidence/anchor/events отклоняется; согласованная правка всех трёх файлов принимается — документированная граница локального анкера. Anchor rollback скрывает терминальный verdict от OBSERVE (EV-02). Удаление fixture/locks/leases и подделка browser.pid с nonce — граница каталога.
3. **Полный контроль процесса/диска:** поддельный PASS возможен (внешнего анкера/подписи нет) — заявленная граница 0.1.
4. **Конкурентные читатели** — не «атакующий», а штатный OBSERVE/мониторинг — ломают writer (FINAL03-EV-01). Это не граница злоумышленника, а дефект дизайна commit-протокола на Windows.

---

## J. Итоговое решение: **REJECT**

**Закрыто и подтверждено:** DS-P1-022 (FIXED), DS-P2-013 (FIXED, с ручным вмешательством при mutation evidence), DS-P2-026 (FIXED), DS-P2-027 (FIXED), DS-P1-003/004/005/008, DS-P0-001/002, DS-P2-007 — регрессий нет. 54/54 в 4 из 5 полных прогонов, 10/10 браузерных PASS, 10/10 crash, 10/10 concurrent START, 10/10 cancel, схемы 0.1.0 без diff.

**Блокирующее основание REJECT — FINAL03-EV-01:** штатный конкурентный OBSERVE (обязательный сценарий и прямое требование п. 5.2) способен сорвать активный прогон: `EPERM` при `rename` в `atomicWrite` (Windows), без retry. Подтверждено на трёх уровнях (OS-repro 0/400 rename при 2 читателях; прямой `appendEvidence` 2/120 при 2 читателях; живые прогоны: 15/30 PASS при 3 readers, 3/8 PASS при 2 observers у Lead), независимо двумя аудиторами. Следствия: валидная бизнес-мутация не получает PASS (INCONCLUSIVE/сырая ошибка), появляются orphan-artifacts/uncommitted tail, ломается мониторинг. Ложного PASS и повторного POST нет, но обязательный инвариант «конкурентные операции не искажают бизнес-результат/не дают ложных INTEGRITY» не подтверждён. DS-P2-025 остаётся **PARTIAL**.

**Условия повторной приёмки:**
1. Устранить FINAL03-EV-01: retry/backoff для `renameSync` на EPERM/EBUSY/EACCES; предпочтительно вернуть append-only запись `evidence.jsonl` (append+fsync) и оставить rename только для маленького anchor с retry; либо ввести координацию чтения/записи. Добавить регрессию: 1/2/6 конкурентных reader-процессов на активном прогоне (100+ OBSERVE), ожидание PASS без orphan-artifacts.
2. Устранить EV-02 (anchor rollback скрывает терминальный verdict от OBSERVE) и наследственный DS-P3-020 (raw ENOENT).
3. Добиться стабильности набора 5/5 под умеренной внешней нагрузкой; разобрать `duplicateIntent` флейк.
4. До Dev/ЦИЗ: внешний подписанный approval, авторизация входных значений, внешний append-only анкер evidence, серверная семантика создания (201 vs reuse/ownership).

**Ответ на главный вопрос:** при повреждённом хранилище и при попытке обойти бизнес-проверку ядро ведёт себя в основном fail-closed (восстановление, реестр, forged PASS отклоняются), но при **штатном конкурентном наблюдении** оно недостаточно надёжно: активный прогон может быть сорван, а валидный бизнес-результат — не опубликован. Поэтому локальное ядро KAIDEN QA ADAPTANT 0.1 в текущей ревизии **не принимается**.

---

*Все новые скрипты и логи: `C:\Users\gvi\AppData\Local\Temp\kaiden-audit-final03\` — lead (approval-matrix, recovery-matrix, fixture-idempotency-matrix, custom-stand-matrix, cancel-nonce-matrix, reader-load-batches, concurrent-observe-impact, debug-reader*, integration-matrices, browser/crash/concurrent/cancel матрицы, full-suite-5x.log, revision-manifest.txt), approval (REPORT-DS-P1-022.md), evidence (REPORT-FINAL03-EVIDENCE.md, os-rename*, write-contention, live-reader, concurrency, crash-window, anchor-attack), recovery. Ревизия не менялась; в проекте создан только этот отчёт.*
