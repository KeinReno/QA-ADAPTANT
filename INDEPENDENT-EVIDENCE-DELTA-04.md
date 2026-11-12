# НЕЗАВИСИМАЯ ДЕЛЬТА-ПРИЁМКА EVIDENCE STORE — KAIDEN QA ADAPTANT 0.1 (DS-DELTA-04)

**Исполнитель:** DeepSeek (не участвовал в разработке)
**Дата:** 12 ноября 2026, Europe/Moscow
**Объект:** `C:\Users\gvi\Desktop\QA-ADAPTANT`, HEAD `68ca86f805c39d7a410d87d81d4c4af986b4f2cd` + незакоммиченные правки Evidence Store
**Предыдущий отчёт:** `INDEPENDENT-ACCEPTANCE-03.md` (REJECT)
**Режим:** READ-ONLY + targeted regression + fault injection
**Итоговое решение: CONDITIONAL ACCEPT** (для локального изолированного ядра 0.1; условия в разделе I)

> Продуктивный код и схемы не изменялись. В проекте создан только этот отчёт. Все артефакты — в `C:\Users\gvi\AppData\Local\Temp\kaiden-audit-delta04\`. Итоговые испытания выполнены на стабилизированной ревизии; SHA256 в конце аудита совпали с зафиксированными после стабилизации.

---

## A. Проверенная ревизия

| Параметр | Значение |
|---|---|
| HEAD | `68ca86f805c39d7a410d87d81d4c4af986b4f2cd` (master) |
| Состояние | незакоммиченные изменения Evidence Store + новые тесты (ниже) |
| ОС / Node / Playwright / Chromium | Windows 11 Pro 10.0.26100 / v24.16.0 / 1.63.0 / 153.0.8010.12 (rev 1243) |
| Схемы 0.1.0 | `npm run schemas` → exit 0, diff отсутствует |

**Инцидент воспроизводимости (зафиксирован):** во время аудита, в 21:35:51, продуктивный файл `packages/core/store.mjs`, `docs/changes/003` и `tests/evidence-readers.test.mjs` были изменены внешним процессом. Ревизия «до»: `store.mjs = BE9856F92312…` (257 строк), «после»: `84350421ADB81…` (278 строк). Аудит остановил интерпретацию ранних результатов, зафиксировал стабилизированную ревизию и пере-выполнил все критичные испытания на ней. Финальные SHA256 (совпали в начале и в конце стабилизированного этапа):

| Файл | SHA256 |
|---|---|
| packages/core/store.mjs | `84350421ADB81DC3730AD6E548AC6F6AF0AD2D66F1A85B4F99F276437D100E1C` |
| apps/control/run.mjs | `8520121E3503382E8F30398B9DF4E8FC0C660007D057678B52984B14F85B2063` |
| docs/changes/003-approval-semantics-and-recovery.md | `62BAF4C27A829BB1183E7EF1072AA23EF8BB81DD91EAD341CD6CC19F83BB2B5E` |
| tests/evidence-readers.test.mjs | `D2C004ABA38FBBD8B7E0C50D3EFB77DA220A917FD6030B73357EA0987E6736D3` |
| tests/observe-loop.mjs | `08B051A5187D9C6D05B3D275BE83B57CEA9131F539C384C0AAAF198DDAFB2764` |
| HANDOFF.md / ACCEPTANCE-REPORT.md | `27E5711F…` / `43777A08…` |

Реализация сверена с CR-003: `evidence.jsonl` только дописывается; коммит пишется в `.pending-*.tmp`, fsync, затем `renameSync` в новый `evidence-commits/NNNNNN.json`; существующий коммит не заменяется; читатель принимает только непрерывный префикс; хвост целого конверта подтверждается перед продолжением; `terminalResult` требует INTEGRITY_ERROR, если события объявляют терминальный результат, а подтверждённого verdict нет; отсутствующий artifact → INTEGRITY_ERROR.

---

## B. FINAL03-EV-01: исходные репро и результат

Оригинальные скрипты третьего аудита скопированы в `...\kaiden-audit-delta04\load\` без правок логики; источники истины — только `stores` нового протокола.

### B.1. Store-level contention (writer/reader-loop, 120 append)

| Читателей | Writer OK | Writer errors | Reader calls | Reader errors | EPERM/EBUSY |
|---|---|---|---|---|---|
| 0 | **120/120** | 0 | 0 | 0 | нет |
| 1 | **120/120** | 0 | ~123 | 0 | нет |
| 2 | **120/120** | 0 | ~246 | 0 | нет |
| 6 | **120/120** | 0 | ~897 | 0 | нет |

Writer exit code 0 во всех конфигурациях; commit-файлы создаются без перезаписи; evidence journal только дописывается; **EPERM при rename evidence/anchor больше не воспроизводится** (новый протокол не перезаписывает читаемые файлы журнала). OS-level rename-repro из третьего аудита к Evidence Store больше не применим: журнал и подтверждённые коммиты не заменяются; эквивалентная проверка — writer/reader contention выше.

### B.2. Живой Chromium + 1/2/6 процессов OBSERVE (≥100 OBSERVE на конфигурацию)

| Читателей | Повторов | Verdict | POST | GET | Records | Commits | Цепочка | OBSERVE после |
|---|---|---|---|---|---|---|---|---|
| 1 | 2 | PASS/NONE ×2 | 1 | 1 | 1 | 5, непрерывны | intent→request→response→read→verdict | PASS |
| 2 | 2 | PASS/NONE ×2 | 1 | 1 | 1 | 5, непрерывны | полная | PASS |
| 6 | 2 | PASS/NONE ×2 | 1 | 1 | 1 | 5, непрерывны | полная | PASS |

Все 6/6: 100 OBSERVE каждым процессом (exit code 0, stderr пуст), 0 orphan artifacts, commit byteLength строго монотонен, последний коммит соответствует концу журнала, состояние FINISHED. **Мониторинг не срывает валидную бизнес-операцию.**

### B.3. Ошибка нагрузочного reader (§11)

Наши focus-load тесты: reader-процессы завершились штатно (stats записаны, errorCount=0, exit 0), writer не затронут. Заявленный Grok exit 1 внешнего reader из-за удалённого временного каталога **не воспроизведён** и к Evidence Store не относится. Отдельно найден тестовый эффект: новый observer-скрипт читает транзитные `.pending-*.tmp` и может падать ENOENT — это дефект тестового инструмента (Finding D-01), не store.

---

## C. Evidence Commit Protocol — атомарность, непрерывность, целостность

### C.1. Атомарность публикации

- Коммит сначала пишется в `.pending-<seq>-<uuid>.tmp`, fsync, затем rename в новый `NNNNNN.json`. Финальное имя не появляется до полной записи; существующее имя не перезаписывается (`existsSync` + `rename` в новое имя, при существующем — INTEGRITY).
- Частично записанный `.tmp` читателем игнорируется (regex `^\d{6}\.json$`); в S4 подложенный partial `.pending-*` не нарушает OBSERVE/START/RECONCILE (PASS).
- Краш после `open` временного файла оставляет только `.pending-*`, не влияющий на подтверждённую цепь.
- Окно «commit-файл создан, но частично записан» для финального имени устранено: финальный файл возникает только атомарным rename.

### C.2. Непрерывность и целостность (матрица атак)

Команда: `node ...\protocol\protocol-matrix-stable.mjs`, лог `protocol-matrix-stable.log`, JSON `protocol-matrix-stable.json`.

| Атака | OBSERVE | START | RECONCILE | Итог |
|---|---|---|---|---|
| B1 удалён первый commit | INTEGRITY («терминальный результат в событиях не подтверждён») | INTEGRITY | INTEGRITY | отклонено |
| B2 удалён средний commit | INTEGRITY | INTEGRITY | INTEGRITY | отклонено |
| B3 удалён последний (terminal) commit | INTEGRITY | INTEGRITY | INTEGRITY | отклонено (EV-02) |
| B4 дублирование sequence | INTEGRITY | INTEGRITY | INTEGRITY | отклонено |
| B5 неверный digest commit | INTEGRITY | INTEGRITY | INTEGRITY | отклонено |
| B6 byteLength > EOF | INTEGRITY | INTEGRITY | INTEGRITY | отклонено |
| B7 byteLength в середине строки | INCOMPLETE_RUN | INCOMPLETE_RUN | INCOMPLETE_RUN | отклонено |
| B8 целый envelope без commit (хвост) | PASS (хвост игнорируется, подтверждённый verdict цел) | PASS | PASS | корректно |
| B9 commit без envelope | INTEGRITY | INTEGRITY | INTEGRITY | отклонено |
| B10 подмена artifact | INTEGRITY checksum | INTEGRITY | INTEGRITY | отклонено |
| B11 terminal commit есть, terminal events отсутствуют | PASS (источник истины — подтверждённый коммит) | PASS | PASS | корректно |
| B12 INCONCLUSIVE→PASS правка evidence+commit без events | INTEGRITY (verdict ≠ events) | INTEGRITY | INTEGRITY | отклонено |
| B13 удалён envelope, commit оставлен | INTEGRITY | INTEGRITY | INTEGRITY | отклонено |
| B14–B16 отсутствует/повреждён artifact verdict/response/read | INTEGRITY «файл evidence отсутствует»/checksum | INTEGRITY | INTEGRITY | отклонено (сырого ENOENT нет) |
| B17 изменено FINISHED-событие | INTEGRITY (verdict ≠ events) | INTEGRITY | INTEGRITY | отклонено |
| S13 artifact другого run | INTEGRITY checksum | INTEGRITY | INTEGRITY | отклонено |

**Вывод:** подтверждённая история не уменьшается молча; при повреждении подтверждённой части — fail-closed INTEGRITY/INCOMPLETE_RUN; terminal-commit является источником истины при отсутствии terminal-событий; подмена/удаление terminal-commit при наличии FINISHED даёт INTEGRITY и для OBSERVE (EV-02 закрыт).

### C.3. Восстановление целого неподтверждённого envelope

- S3: подготовлен run с подтверждённым префиксом 4 + целый канонический envelope seq5 без commit; `appendEvidence` подтвердил его (commit5), затем добавил seq6; `readEvidence` вернул 1..6, коммитов 6, ошибок нет. Заявленное поведение «подтвердить целый хвост и продолжить» работает.
- T4: хвост с несуществующим parentEvidenceId → INTEGRITY «неверная ссылка parent evidence», commit не создан.
- T1–T3 (Finding D-02): хвост с чужим `runId` / `manifestSha256` / `fixtureId` и валидными родителями/artifact **подтверждается** (commit создаётся, запись продолжается). Семантическая валидация хвоста неполна: проверяются canonical bytes, sequence/previousSha, artifact checksum, parents и конфликт с terminal events, но не runId/manifestSha/fixtureId/stepId и не дублирование intent. Требует записи в каталог данных; терминальная валидация (evidence-policy) позже даёт EVIDENCE_SCOPE, поэтому ложного PASS это не даёт, но требование §5.3 выполнено не полностью.

### C.4. Запрет перезаписи истории

- Авторитетные `append`: подтверждённые commit-файлы не перезаписываются (INTEGRITY при существующем имени).
- После терминального verdict новые evidence через API запрещены (INTEGRITY).
- Повреждённый хвост не перекрывается: B7/INCOMPLETE_RUN, S2 torn tail в терминальном run игнорируется, append поверх повреждённого хвоста даёт INCOMPLETE_RUN.
- Старый commit нельзя заменить другим с тем же sequence: B4/B5/B9 отклонены.

---

## D. Crash / Recovery

Матрица: `crash\crash-matrix.mjs`, `crash-extra.mjs`; JSON `crash-matrix.json`, `crash-extra.json`; live-fault S6/S7/S8.

| # | Сценарий | OBSERVE | START | RECONCILE | POST | Итог |
|---|---|---|---|---|---|---|
| 1 | artifact создан, envelope нет (терминальный run) | PASS | PASS | PASS | 1→1 | корректно |
| 1b | orphan artifact присутствует | PASS | PASS | PASS | 1→1 | корректно |
| 2 | envelope частично записан (torn tail) | PASS (хвост игнорируется) | PASS | PASS | 1→1 | корректно |
| 3 | envelope цел, commit отсутствует | подтверждение + продолжение (S3) | — | — | нет нового POST | корректно |
| 4 | commit частично записан / `.pending-*` | PASS, reader игнорирует | PASS | PASS | 1→1 | корректно |
| 5 | commit записан, ACK не отправлен | terminal commit без events — PASS (B11-семантика) | PASS | PASS | без повтора | корректно |
| 6 | intent подтверждён, POST нет (dropIntentAck) | INCONCLUSIVE | — | — | **0** | корректно, без повтора |
| 7 | POST отправлен, response потерян | INCONCLUSIVE/RESULT_UNCONFIRMED | — | — | **1**, без повтора | корректно |
| 8 | response записан, read отсутствует (kill Control) | INCONCLUSIVE/WORKER_LOST | — | INCONCLUSIVE/WORKER_LOST | **1**, без повтора | корректно |
| 9 | read записан, verdict нет | — | — | **raw INTEGRITY «запрещена перезапись evidence»** | 1, без повтора | **Finding D-03** |
| 10 | verdict envelope есть, terminal commit нет | INTEGRITY | INTEGRITY | INTEGRITY | без повтора | EV-02 закрыт |
| 11 | terminal commit есть, VERDICT_DURABLE/FINISHED нет | PASS | PASS | PASS | без повтора | корректно |
| 12 | FINISHED есть, terminal commit повреждён/удалён | INTEGRITY | INTEGRITY | INTEGRITY | без повтора | EV-02 закрыт |
| — | artifact другого run | INTEGRITY checksum | INTEGRITY | INTEGRITY | без повтора | корректно |

**Главный инвариант:** ни один сценарий не привёл к автоматическому повторному POST; mutationCount остаётся 1 (или 0 там, где POST не было). Неопределённость трактуется fail-closed. Исключение — S9: восстановление невозможно из-за orphan artifact (Finding D-03), но и там повторного POST нет.

---

## E. Терминальная целостность (EV-02 и др.)

- B3/B10/S12: терминальный commit удалён/повреждён, FINISHED остался → OBSERVE, START и RECONCILE дают **INTEGRITY_ERROR** («терминальный результат в событиях не подтверждён журналом evidence» / checksum). PASS не публикуется.
- B12: правка INCONCLUSIVE→PASS в evidence+commit без изменения events → INTEGRITY (verdict ≠ events).
- B17: изменение FINISHED-события → INTEGRITY.
- B11: terminal commit есть, events потеряны → PASS по подтверждённому коммиту (проверка PASS/FAIL повторяет реестр в `terminalResult`).
- Подмена INCONCLUSIVE→PASS и принятие PASS из неподтверждённого хвоста без terminal commit — не подтверждены; несогласованность events/evidence всегда INTEGRITY.
- Повторная мутация при terminal-восстановлении не выполняется.

---

## F. Короткая перепроверка прежних P0/P1 (регрессии)

Все проверки — на стабилизированной ревизии; оригинальные репро адаптированы только путём копирования.

| ID | Результат |
|---|---|
| DS-P0-001 START/RECONCILE race | **PASS (закрыт)**: B=start в preflight → RUNNING, A=PASS, mutationCount=1, журнал/commit-цепь целы, OBSERVE/RECONCILE после гонки PASS |
| DS-P0-002 lock/lease deletion | **PASS (закрыт)**: после удаления locks/leases второй runId BLOCKED, mutation=1, record=1 |
| DS-P1-003 crashAfterMutation | **PASS (закрыт)**: 10/10 INCONCLUSIVE/WORKER_LOST, no BROWSER_DONE, mutation=1, OBSERVE INCONCLUSIVE |
| DS-P1-004 forged terminal PASS | **PASS (закрыт)**: правка хвоста evidence → INTEGRITY (commit-цепь), START/OBSERVE отклоняют |
| DS-P1-005 CANCEL during VERIFYING | **PASS (закрыт)**: CANCEL_REQUESTED → INCONCLUSIVE/CANCELED, POST=1, без повторов |
| DS-P1-008 fixture reuse | **PASS (закрыт)**: второй runId BLOCKED, mutation=1, record=1 |
| DS-P1-022 appliesWhen/equals | **PASS (закрыт)**: appliesWhen/equals/required/inputs/actor/operation изменения → BLOCKED/CONTRACT_INVALID до POST, mutation=0; контроль PASS |

Схемы: `npm run schemas` exit 0, diff отсутствует.

---

## G. Полные и браузерные прогоны

### G.1. Полный набор тестов

Фактическое количество тестов — **58** (не 57, как в отчёте Grok): 54 прежних + 4 в `tests/evidence-readers.test.mjs`. Состав: audit-wp 14, contract-links 4, contracts 8, evidence-readers 4, faults 12, lifecycle 8, review-grok 7, runtime 1.

Два независимых блока по пять прогонов:

| Блок | RUN1 | RUN2 | RUN3 | RUN4 | RUN5 | Зелёных |
|---|---|---|---|---|---|---|
| 1 (при параллельной аудиторской нагрузке) | 58/58 exit0 | 58/58 exit0 | 57/58 exit1 (`fault ambiguousButton`) | 58/58 exit0 | 57/58 exit1 (`активный прогон… OBSERVE`) | 3/5 |
| 2 (чистый, без внешней нагрузки) | 58/58 exit0 | 57/58 exit1 (OBSERVE, ENOENT `.pending-*`) | 58/58 exit0 | 58/58 exit0 | 57/58 exit1 (OBSERVE) | 3/5 |

Изолированный новый тест OBSERVE: 6 прогонов — 1 fail; 8 — 2 fail; 12 — 2 fail (все — ENOENT `.pending-*.tmp` в `tests/observe-loop.mjs:16`); итого **5/26 падений**, все вызваны тестовым harness, читающим транзитные `.pending-*` файлы. Один из ранних прогонов дополнительно дал INCONCLUSIVE (не воспроизведено). **Набор не является воспроизводимо зелёным**, причина — Finding D-01 (тестовый инструмент, не Evidence Store).

### G.2. Реальные браузерные прогоны

| Блок | Результат |
|---|---|
| 10 независимых Chromium-прогонов | **9/10 PASS/NONE**, 1 INCONCLUSIVE/WORKER_LOST (полная цепочка intent→request→response→read→verdict, mutation=1, read=1, record=1, commits=5; fail-closed, повторного POST нет) |
| 20 дополнительных прогонов | **20/20 PASS/NONE**, 1 POST, 1 GET, commits=5 |
| 30 прогонов с exit-code instrumentation (NODE_OPTIONS hook) | **30/30 PASS/NONE**; browser worker exit 0 ×30, verification worker exit 0 ×30; commits=5, полная цепочка |
| Итого | 59/60 PASS; единственный сбой не воспроизведён в последующих 50 прогонах; ложного PASS/повторной мутации нет |

Все PASS-прогоны: PASS/NONE, ровно 1 POST, 1 независимый GET, корректная business entity, все effect checks SATISFIED, evidence-цепь intent→request→response→independent-read→verdict, commit-цепь непрерывна (5), state FINISHED, сиротских процессов нет.

---

## H. Findings (новые/сохраняющиеся)

### D-01 [P2, тестовый инструмент] Новый observer-тест читает транзитные `.pending-*.tmp` → ENOENT, набор нестабилен

- **Путь:** `tests/observe-loop.mjs:16` — `for (const name of fs.readdirSync(commits)) fs.readFileSync(path.join(commits, name));` без фильтра; продукт пишет коммит как `.pending-<seq>-<uuid>.tmp` → rename в `NNNNNN.json`.
- **Шаги:** `node --test --test-name-pattern="активный прогон выдерживает" tests/evidence-readers.test.mjs` (многократно).
- **Ожидаемо:** observer-процесс не падает; 100 OBSERVE завершаются.
- **Факт:** наблюдатель открывает временный файл в момент rename → `ENOENT …\.pending-3-….tmp`, exit 1; тест падает. 5/26 изолированных повторов; полный набор 6/10 зелёных.
- **Нарушенный инвариант:** требование воспроизводимой зелёной регрессии; сам Evidence Store при этом корректен (readEvidence фильтрует имена).
- **Рекомендация:** в observer использовать `RunStore.readEvidence`/фильтр `/^\d{6}\.json$/` (не читать `.pending-*`), игнорировать ENOENT для файлов, исчезнувших между readdir и read; добавить 5-прогонную стабильность.

### D-02 [P2, граница каталога данных] Подтверждение неподтверждённого хвоста без полной семантической проверки

- **Путь:** `packages/core/store.mjs:181-201` (`#recoverTail`), `#assertRecoverableTail` 153-179.
- **Шаги:** `crash\crash-extra.mjs` (Tforeign), `protocol\protocol-matrix-stable.mjs` (T1–T3).
- **Факт:** хвост с `runId='foreign-run'`, чужим `manifestSha256`, `fixtureId`, валидными canonical bytes/sequence/previousSha/artifact/parents и без terminal events **подтверждается**: создаётся commit, `readEvidence` возвращает запись с чужим runId, журнал продолжается. Termинал-валидация позже даст EVIDENCE_SCOPE (ложного PASS нет), но требование §5.3 «не подтверждать семантически чужой envelope» выполнено не полностью.
- **Нарушенный инвариант:** §5.3 (runId/manifest/fixture/stepId, дублирование intent). Требует записи в каталог данных; документированная граница «согласованная правка каталога» не покрывает именно это подтверждение, поскольку commit создаёт сам продукт.
- **Рекомендация:** в `#assertRecoverableTail` сверять `envelope.runId/manifestSha256/fixtureId/stepId` с frozen bundle, запрещать повтор intent/verdict-kind, проверять допустимость parent refs с учётом типа; при несоответствии — INTEGRITY и не публиковать commit.

### D-03 [P2, восстановление] Orphan artifact при крахе «artifact записан — envelope нет» блокирует восстановление raw INTEGRITY

- **Путь:** `packages/core/store.mjs:256-279` (`appendEvidence`: artifact через `#writeNewFile`, envelope позже), `store.mjs:264` («запрещена перезапись evidence»).
- **Шаги:** `crash\crash-extra.mjs` S9: подтверждён префикс intent/request/response/read; verdict artifact существует, envelope/commit отсутствуют; `reconcile`.
- **Факт:** verifier/Control пытается добавить verdict на той же sequence с тем же kind → `INTEGRITY_ERROR: запрещена перезапись evidence` (сырое исключение, не verdict); run остаётся без терминального вердикта, восстановление невозможно; повторного POST нет.
- **Нарушенный инвариант:** §6 «проверить возможность дальнейшего восстановления»; fail-closed соблюдён, но состояние требует ручного вмешательства и не имеет кодового quarantine.
- **Рекомендация:** писать artifact во временное имя и публиковать/переименовывать после envelope+commit; либо при восстановлении orphan-artifact (не упомянутый в committed prefix и не имеющий envelope) перемещать в `quarantine/` и продолжать; либо вводить `INCOMPLETE_RUN`-карантин с документированной процедурой.

### D-04 [P3, надёжность] Один браузерный прогон из 60 завершился INCONCLUSIVE/WORKER_LOST при полной цепочке evidence

- **Факт:** первый блок 10 прогонов: #3 — INCONCLUSIVE/WORKER_LOST, mutation=1, read=1, record=1, commits=5, kinds полные; последующие 50 прогонов (20 + 30 instrumented) — PASS, worker exit codes 0. Не воспроизведено; fail-closed, без ложного PASS/повтора POST.
- **Рекомендация:** добавить диагностику exit code/причины worker loss в verdict message (сейчас «WORKER_LOST» без деталей); повторить длительный прогон.

### D-05 [P3, документация] Заявлено 57 тестов, фактически 58

- Состав: 54 прежних + 4 новых; отчёт Grok указывает 57. Скорректировать документацию/ожидания CI.

### D-06 [Info] `snapshot` всё ещё создаёт legacy `evidence-anchor.json`

- Файл больше не используется читателем (источник истины — `evidence-commits/`); остаётся безвредным артефактом. Удалить/пометить legacy при следующем изменении.

---

## I. Acceptance Decision

### CONDITIONAL ACCEPT

**Обязательные инварианты подтверждены на стабилизированной ревизии:**

1. **FINAL03-EV-01 закрыт:** 0/1/2/6 конкурентных читателей — writer 120/120 без EPERM/потерь; живые Chromium-прогоны с 1/2/6 процессами OBSERVE (≥100 OBSERVE каждый) — 6/6 PASS, commit-цепь непрерывна, orphan artifacts 0.
2. **Новый commit-протокол не допускает ложного PASS или повторной мутации** в проверенных сценариях: удаление/подмена commit’ов, envelope/artifact, terminal-событий, cross-run — INTEGRITY/INCOMPLETE_RUN; подтверждённая история не теряется молча; terminal commit — источник истины, FINISHED без подтверждённого verdict → INTEGRITY для OBSERVE/START/RECONCILE (EV-02 закрыт).
3. **Отсутствующий artifact** → структурированный INTEGRITY, не сырой ENOENT.
4. **Crash/recovery:** нет автоматического повторного POST; неопределённость fail-closed; целый неподтверждённый envelope безопасно подтверждается и продолжается.
5. **Регрессии:** DS-P0-001/002, DS-P1-003/004/005/008/022 — зелёные.
6. **Схемы 0.1.0** не изменены.

**Условия (не блокируют локальную изолированную эксплуатацию, обязательны до фиксации Stable/Dev):**

1. Исправить D-01 (observer не читает `.pending-*`; корректная обработка исчезнувших файлов) и получить **5/5 последовательных зелёных прогонов 58/58**.
2. Закрыть D-02: семантическая валидация подтверждаемого хвоста (runId/manifest/fixture/stepId, запрет дублирующего intent/verdict).
3. Закрыть D-03: orphan-artifact recovery (quarantine или временное имя artifact до envelope+commit) с регрессией.
4. Разобрать D-04: добавить диагностику worker-loss и подтвердить 10/10 браузерных PASS на стабильной ревизии.
5. Скорректировать D-05/D-06 (58 тестов; legacy anchor).

**Границы:** CONDITIONAL ACCEPT относится только к локальному изолированному ядру 0.1 в пределах настоящего задания. До Dev/ЦИЗ по-прежнему обязательны: доверенная аутентификация/авторизация владельца, утверждение конкретных входных данных, доверенная идентификация внешней среды, внешний/отдельно защищённый анкер evidence, проверяемая серверная семантика создания бизнес-объекта. Официальный статус QA ADAPTANT 0.1 до выполнения условий остаётся **CONDITIONAL**, не ACCEPT.

**Итог:** Evidence Store после перехода на append-only журнал + отдельные commit-файлы устойчив к штатной многопроцессной эксплуатации на Windows в проверенных пределах и закрыл блокирующий FINAL03-EV-01. Остались документированные неблокирующие ограничения (тестовый harness, семантика хвоста, orphan recovery, единичный невоспроизведённый worker-loss), которые необходимо закрыть до закрепления Stable и тем более до Dev.

---

*Артефакты: `C:\Users\gvi\AppData\Local\Temp\kaiden-audit-delta04\` — lead (revision-manifest*.txt, delta-stable.diff, live-observe-stable.json, full-suite-5x*.log, browser-10/20/30*.json/.log, crash-10.json, approval-matrix.json, exit-log.jsonl), load (probe-write-contention*.log/json, reader/writer loops), protocol (protocol-matrix-stable.*, a8-a9-a11, diag*), crash (crash-matrix.*, crash-extra.*), observe-test*. Код продукта не изменялся; в проекте создан только этот отчёт.*
