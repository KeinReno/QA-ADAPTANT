# ФИНАЛЬНЫЙ GATE СТАБИЛЬНОСТИ — KAIDEN QA ADAPTANT 0.1 (DF5C99D)

**Исполнитель:** DeepSeek (не участвовал в разработке)
**Дата:** 12 ноября 2026, Europe/Moscow
**Проверяемый коммит:** `df5c99d9692ded2de7f0c865d1c09d703b28384f`
**Базовая ревизия:** `68ca86f805c39d7a410d87d81d4c4af986b4f2cd`
**Предыдущий отчёт:** `INDEPENDENT-EVIDENCE-DELTA-04.md` (CONDITIONAL ACCEPT)
**Режим:** READ-ONLY + targeted verification + fault injection
**Итоговое решение: CONDITIONAL ACCEPT** (D-01–D-04 закрыты; осталось одно неблокирующее ограничение — воспроизводимость полного набора тестов, см. раздел I)

> Продуктивный код и контракты не изменялись. В проекте создан только этот отчёт. Артефакты — в `C:\Users\gvi\AppData\Local\Temp\kaiden-audit-gate05\`. HEAD и SHA256 проверялись в начале и в конце аудита — совпали.

---

## A. Проверенная ревизия

| Параметр | Значение |
|---|---|
| HEAD | `df5c99d9692ded2de7f0c865d1c09d703b28384f` (master, коммит «Зафиксировать протокол коммитов evidence и условия CONDITIONAL ACCEPT») |
| `git status` | чисто до аудита; после — только созданный отчёт (вне коммита) |
| ОС / Node / Playwright / Chromium | Windows 11 Pro 10.0.26100 / v24.16.0 / 1.63.0 / 153.0.8010.12 (rev 1243) |
| Схемы 0.1.0 | `npm run schemas` → exit 0, diff отсутствует |
| Тестов | **59** (54 прежних + 5 в `tests/evidence-readers.test.mjs`) — соответствует заявлению Grok |

SHA256 ключевых файлов (стабильны до/после испытаний):

| Файл | SHA256 |
|---|---|
| packages/core/store.mjs | `5D3ED51240EC654FC8DF8896DD3D97854F6898F8656FE4CB9B3D25D9D4C1967C` |
| apps/control/run.mjs | `7E435CA087D7CB6EF74089918D85EB84E262BEC579B9C4E635A767D6F82DCFC7` |
| apps/verification/worker.mjs | `6AB817B8AC76F0230A6CAC6F8F3B2E358691801831987ACB5C52E443BBE52B20` |
| tests/observe-loop.mjs | `5C7049406F918B79BC1E3367D33F61EE0BF494110DC940A00970D48E746CC5E1` |
| tests/evidence-readers.test.mjs | `9567FFDF7F606733A892F4F541A9B68C3CEA812E9A3B624EAD08FA006D5179F4` |

Состав изменений `68ca86f..df5c99d`: append-only evidence + `evidence-commits/NNNNNN.json` (temp+fsync+rename), семантическая проверка recoverable tail (scope/parent/duplicate-kind), quarantine orphan artifacts, диагностика worker-loss (exit/signal/phase), observer harness с фильтром `^\d{6}\.json$` и обработкой ENOENT, новые тесты (5).

---

## B. D-01 — Observer Harness: **FIXED**

**Изменение:** `tests/observe-loop.mjs` читает только опубликованные `NNNNNN.json` (фильтр regex), игнорирует `.pending-*`, ловит ENOENT для исчезнувших файлов; не вмешивается в store (только чтение журнала/коммитов и `observe()`).

**Испытание:** ранее нестабильный тест `активный прогон выдерживает 1, 2 и 6 процессов OBSERVE` — **20 последовательных изолированных прогонов**.

| Результат | Значение |
|---|---|
| Pass / Fail | **20 / 0** |
| ENOENT `.pending-*` | **0** |
| EPERM | **0** |
| Случайные падения | 0 |
| В каждом прогоне | 1/2/6 observer-процессов × 100 OBSERVE, активный Chromium-прогон PASS |

Логи: `gate05\d01\iter-1..20.log`. **D-01 FIXED.**

---

## C. D-02 — Recoverable Tail: **FIXED**

**Испытание:** `d02\d02-tail-matrix.mjs`, JSON `d02\d02-tail-matrix.json`. Подтверждённый префикс 4 (intent→request→response→independent-read), затем один целый неподтверждённый envelope; вызов `appendEvidence` (триггер восстановления хвоста).

| Хвост | Результат | Commit создан | Evidence count |
|---|---|---|---|
| Чужой `runId` | INTEGRITY «не принадлежит этому прогону» | **нет** | 4 |
| Чужой `manifestSha256` | INTEGRITY «не принадлежит этому прогону» | **нет** | 4 |
| Другой `fixtureId` | INTEGRITY «не принадлежит этому прогону» | **нет** | 4 |
| Некорректный `stepId` | INTEGRITY «не принадлежит этому прогону» | **нет** | 4 |
| Несогласованные `parentEvidenceIds` | INTEGRITY «неверная ссылка parent evidence» | **нет** | 4 |
| Дублирование `mutation-intent` | INTEGRITY «повторяет уже подтверждённый вид evidence» | **нет** | 4 |
| Дублирование `request` | INCOMPLETE_RUN «хвост повреждён» | **нет** | 4 |
| Дублирование `response` | INCOMPLETE_RUN «хвост повреждён» | **нет** | 4 |
| Дублирование `verdict` (после terminal) | INTEGRITY «повторяет уже подтверждённый вид evidence» | **нет** | 5 (terminal цел) |
| **Корректный observation-хвост** | OK, подтверждён и продолжен | **да** | 6 |
| Корректный verdict-хвост (events отсутствуют) | подтверждён; дальнейшая запись запрещена «после терминального verdict» | да | 5 |

Чужой/конфликтующий envelope не получает commit; корректный восстановимый хвост подтверждается без потери evidence; повторного POST нет (проверка через store, бизнес-мутация не вызывалась). **D-02 FIXED.** Косметика: duplicate request/response даёт общий INCOMPLETE_RUN, а не специализированный код (безопасно, commit не создан).

---

## D. D-03 — Orphan Artifact: **FIXED**

**Испытание:** `d03\d03-orphan.mjs`, `d03\d03-orphan-read.mjs`; JSON `d03-orphan-results.json`, `d03-orphan-read.json`. Сценарий: artifact записан, envelope/commit отсутствуют; `reconcile` с недоступным стендом (мутация уже была).

| Сценарий | Результат |
|---|---|
| Префикс 4 + orphan `000005-verdict.json` | orphan → `quarantine/1794512578319-000005-verdict.json`; reconcile → **INCONCLUSIVE/EVIDENCE_MISSING** (не raw INTEGRITY); evidence 4→5 (verdict), цепочка цела; observe INCONCLUSIVE/FINISHED; **PASS нет** |
| То же повторно (D) | тот же результат, orphan в quarantine |
| Префикс 3 + orphan `000004-independent-read.json` (коллизия read) | orphan перенесён в quarantine; append продолжился (валидация остановила тестовый artifact без entity — не связано с D-03) |
| Neighboring: префикс 2/3 | reconcile → INCONCLUSIVE/EVIDENCE_MISSING, структурировано, без сырых ошибок |

Подтверждённые evidence не потеряны, повторного POST нет (reconcile только независимое чтение), ложного PASS нет; run не блокируется необратимо — получает терминальный INCONCLUSIVE. **D-03 FIXED.**

---

## E. D-04 — WORKER_LOST диагностика: **FIXED**

**Испытание:** `d04\d04.mjs`, JSON `d04\d04-results.json`; индуцированная потеря Browser Worker (`crashAfterMutation`).

Terminal verdict (durable artifact) содержит:
`message: "Browser Worker завершился без подтверждения полного выполнения; мутация не повторяется (exit=86, signal=none, done=false, phase=WORKER_LOST, ipc=Browser завершился с кодом 86)"`, `reasonCode: WORKER_LOST`, checks SATISFIED, ownershipVerified=true. Т.е. exit code, signal, последняя фаза и reasonCode доступны в подтверждённом evidence.

Реальные Chromium-прогоны: **10/10 PASS/NONE**, 1 POST, 1 GET, commits=5, цепочка полная; WORKER_LOST не повторился (нет контекста для анализа). Примечание: exit/signal/phase находятся в terminal verdict/message, а не отдельной строкой `events.jsonl` (там reasonCode FINISHED и факт VERIFYING); если требуется машинное поле в events — это небольшое улучшение, не блокер. **D-04 FIXED.**

---

## F. Короткая перепроверка инвариантов (df5c99d)

| Проверка | Результат |
|---|---|
| START/RECONCILE race | PASS: B=RUNNING, A=PASS, mutation=1, журнал/коммиты целы |
| Отсутствие повторного POST | lock-deletion/fixture-reuse/crash10: POST не повторяется, mutation=1 |
| Fixture ownership | повторный fixtureId → BLOCKED; удаление locks/leases второй мутации не даёт |
| CANCEL во время VERIFYING | CANCEL_REQUESTED → INCONCLUSIVE/CANCELED, POST=1 |
| Запрет forged PASS | правка хвоста evidence → INTEGRITY для OBSERVE/START |
| Approval semantics | appliesWhen/equals/required/inputs/actor/operation → BLOCKED до POST, mutation=0; контроль PASS |
| Evidence commit integrity | D-02/D-03 + 5 новых тестов: пропуск/подмена commit/envelope/artifact → INTEGRITY/INCOMPLETE_RUN; terminal rollback → INTEGRITY |
| Конкурентный OBSERVE | D-01: 20/20 тест PASS; 1/2/6 observers ×100 OBSERVE — PASS, commit-цепь непрерывна |
| `npm run schemas` | exit 0, diff отсутствует |

---

## G. Полный набор тестов и браузер

### G.1. Полные прогоны (59 тестов)

| Блок | RUN1 | RUN2 | RUN3 | RUN4 | RUN5 | Зелёных |
|---|---|---|---|---|---|---|
| A (`full-suite-5x.log`) | 59/59 exit0 | 59/59 exit0 | 59/59 exit0 | **58/59 exit1** (WP-A второй START) | 59/59 exit0 | 4/5 |
| B (`full-suite-5x-b.log`) | 59/59 exit0 | 59/59 exit0 | 59/59 exit0 | **57/59 exit1** (OBSERVE; delayedRead) | 59/59 exit0 | 4/5 |
| Финал (`suite-final`) | **59/59 exit0** | **59/59 exit0** | **59/59 exit0** | **59/59 exit0** | **59/59 exit0** | **5/5** |

Итог: **13/15 зелёных прогонов**, финальный блок — 5/5×59/59 подряд. Оба ранних падения — интермиттентные, затронули разные тесты; изолированно эти тесты проходят (WP-A 12/12; OBSERVE 20/20; faults-набор ранее 12/12). Все падения — fail-closed (INCONCLUSIVE/не PASS), без ложного PASS, повторного POST или потери подтверждённых evidence; причина — чувствительность параллельного тестового прогона (8 файлов, много Chromium) к таймингам, не воспроизводится в изоляции и в финальном блоке.

### G.2. Браузер
10/10 реальных Chromium PASS/NONE (1 POST, 1 GET, commits 5, FINISHED, без сирот); дополнительно D-04 10/10 PASS.

---

## H. Findings

### G-05-01 [P3, тестовая инфраструктура/стабильность] Полный набор не воспроизводимо зелёный: 13/15 блоков, 2 интермиттентных падения в параллельном прогоне

- **Проявление:** RUN4 блока A — `WP-A: второй START во время preflight…`; RUN4 блока B — `активный прогон выдерживает 1,2,6 OBSERVE` + `fault delayedRead: PASS, POST=1`.
- **Изоляция:** WP-A 12/12 PASS; OBSERVE 20/20 PASS; финальный блок 5/5×59/59.
- **Характер:** падения fail-closed; ложного PASS/повторной мутации/потери подтверждённых evidence нет; вероятная причина — нагрузка при параллельном запуске 8 тестовых файлов с Chromium и таймауты/задержки worker’ов.
- **Рекомендация:** стабилизировать тестовый прогон: `--test-concurrency=1` для browser-heavy файлов, увеличить/уточнить deadline-бюджеты в тестах, либо зафиксировать рекомендованный режим CI; выполнить 5/5 контрольный прогон в этом режиме. Не влияет на безопасность продукта, но мешает формальной фиксации Stable.

### G-05-02 [Info] duplicate request/response хвост классифицируется как общий INCOMPLETE_RUN

- **Факт:** D-02, T7/T8 — commit не создаётся (безопасно), но сообщение «неподтверждённый хвост evidence повреждён» вместо «повторяет подтверждённый вид evidence».
- **Рекомендация:** уточнить диагностику (по желанию; на безопасность не влияет).

### G-05-03 [Info] Детали worker-loss — в terminal verdict, не в events

- **Факт:** exit/signal/done/phase/ipc присутствуют в `message` терминального verdict (durable artifact); в `events.jsonl` — только reasonCode/FINISHED.
- **Рекомендация:** при желании добавить машинные поля в событие; текущее требование «журнал содержит…» выполнено через подтверждённый verdict.

---

## I. Итоговое решение: **CONDITIONAL ACCEPT**

**D-01 — FIXED.** Observer harness читает только `NNNNNN.json`, игнорирует `.pending-*` и ENOENT; 20/20 изолированных прогонов без ENOENT/EPERM; конкурентный OBSERVE не ломает PASS.

**D-02 — FIXED.** Чужой runId/manifestSha/fixtureId/stepId, некорректные parentEvidenceIds, дублирование intent/request/response/verdict — commit не получает; корректный целый хвост подтверждается и продолжается без потери evidence и повторного POST.

**D-03 — FIXED.** Orphan artifact переносится в `quarantine/`; подтверждённые evidence сохраняются; run получает структурированный терминальный INCONCLUSIVE/EVIDENCE_MISSING (не raw INTEGRITY), не блокируется навсегда, повторной мутации и ложного PASS нет.

**D-04 — FIXED.** При потере worker доступны exit code, signal, done, phase, ipc и reasonCode в подтверждённом verdict; 10/10 Chromium PASS, повторного WORKER_LOST в 10 прогонах нет.

**Обязательные инварианты подтверждены**, блокирующих P0/P1 нет, ложного PASS/повторной мутации/утраты подтверждённой истории не обнаружено.

**Оставшееся неблокирующее ограничение:** полный набор тестов не воспроизводимо зелёный подряд (13/15 блоков; финальный 5/5) из-за интермиттентных fail-closed падений browser-heavy тестов в параллельном прогоне. Это ограничение не затрагивает безопасность мутаций и достоверность PASS, но формально препятствует фиксации Stable «с чистым 5/5» без настройки тест-раннера. Поэтому статус — **CONDITIONAL ACCEPT**, а не ACCEPT.

**Условие снятия условности (короткое, без нового аудита):**
1. Стабилизировать запуск полного набора (например, `--test-concurrency=1` или эквивалент для browser-heavy файлов; либо документированный CI-режим) и приложить лог **5/5×59/59 exit 0** в этом режиме.
2. (Необязательно) уточнить сообщение duplicate-tail (G-05-02) и добавить worker-loss поля в events (G-05-03).

После этого локальное изолированное ядро KAIDEN QA ADAPTANT 0.1 может быть зафиксировано как **Stable** в границах изолированного стенда. Внешняя авторизация/аутентификация владельца, доверенная идентификация Dev, внешний анкер evidence и серверная семантика бизнес-операций остаются требованиями следующего этапа и не входят в текущую приёмку.

---

*Артефакты: `C:\Users\gvi\AppData\Local\Temp\kaiden-audit-gate05\` — lead (revision-manifest.txt, full-suite-5x*.log, suite-final\, browser checks, regression логи), d01 (iter-1..20), d02 (d02-tail-matrix.json), d03 (d03-orphan-results.json, d03-orphan-read.json), d04 (d04-results.json). Оригинальные репро предыдущих аудитов не изменялись; продуктивный код не изменялся; в проекте создан только этот отчёт.*
