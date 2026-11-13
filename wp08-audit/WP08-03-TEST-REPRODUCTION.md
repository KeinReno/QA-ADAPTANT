> **Lead-примечание:** Lead независимо подтвердил ключевые артефакты: npm test 258/258 (01-npm-test.log), первый W2 23/24 (exit 1, L-06), изолированный L-06 PASS, matrix 24 PASS/10 TODO (exit 0), старые 0.1 — 59/59. Дополнительно Lead перезапустил R-07/R-03 сценарии (см. evidence/r07-forge.log, r03-false-pass-lead.log).

# WP08-03 — TEST INTEGRITY / INDEPENDENT REPRODUCTION

Аудитор: verifier (WP-08, независимая команда).
Проверяемый SHA: `07c21c4db936627df9a3c874015327ea992a335a` (`feat/adaptant-02-trust-integration`; продуктовый код = `21edda6`, diff `21edda6..07c21c4` — только 4 файла docs/harness).
Рабочая директория: `C:\Users\gvi\Desktop\QA-ADAPTANT-WP08-AUDIT` (audit worktree).
Продуктивный код, тесты поставки, схемы и docs не изменялись: все мои действия — чтение, прогоны и запись только в `wp08-audit/**`.

## 1. Окружение

| Параметр | Значение | Артефакт |
|---|---|---|
| ОС | Windows (локальная машина) | `evidence/verifier/00-environment.txt` |
| Node.js | v24.16.0 | там же |
| npm | 11.13.0 | там же |
| git | 2.55.0.windows.2 | там же |
| PowerShell | 5.1.26100.8875 | там же |
| HEAD worktree | 07c21c4 (git status: только untracked `wp08-audit/`) | там же |
| base URL | только 127.0.0.1 / %TEMP%; Dev/ЦИЗ не подключались | `evidence/verifier/*` |

## 2. Обязательные команды: заявлено / факт

Заявление разработчика — `docs/harness/02-TEST-EVIDENCE.md` (строки 19–24).

| # | Команда | Заявлено | Независимо получено | Exit | Вердикт |
|---|---|---|---|---|---|
| 1 | `npm test` | 258 tests, 258 pass, 0 fail | Выполнял Lead: `evidence/01-npm-test.log` — `tests 258, pass 258, fail 0` | 0 | **ПОДТВЕРЖДЕНО** (лог Lead) |
| 2 | `npm run test:races` | 3 tests, 3 pass, 0 fail | 3 tests, 3 pass, 0 fail | 0 | **ПОДТВЕРЖДЕНО** — `evidence/verifier/01-test-races.log` |
| 3 | `npm run schemas` + `git diff schemas/` | 6 схем, диффа нет | exit 0; SHA-256 всех 6 файлов до/после совпали; `git diff -- schemas` пуст, `git status schemas` пуст | 0 | **ПОДТВЕРЖДЕНО** — `evidence/verifier/02-schemas.log` |
| 4 | `node --test tests/trust-integration.test.mjs` | 13 tests, 13 pass | 13 tests, 13 pass, 0 fail | 0 | **ПОДТВЕРЖДЕНО** — `evidence/verifier/03-trust-integration.log` |
| 5 | `node tests/redteam/run-all-w2.mjs --target=.` | 24 атаки: 24 PASS, 0 FAIL | **total 24: 23 PASS, 1 FAIL, 0 INCONCLUSIVE**; FAIL = `rt2-l06-used-approval.mjs`, провалена проверка «первый доверенный прогон PASS» | **1** | **ОПРОВЕРГНУТО (F-WP08-01)** — `evidence/verifier/04-redteam-w2.log` |
| 5a | Повтор `rt2-l06` изолированно | — | тот же скрипт: PASS, 7/7 проверок ok | 0 | `evidence/verifier/05-rt2-l06-single.log` — флейк, не воспроизвелся |
| 6 | `node tests/redteam/run-matrix.mjs .` | 34 строки: 24 PASS, 10 TODO (E-04,V-05,V-06,V-10,V-12,L-01,L-02,L-04,L-05,B-02), 0 FAIL/PARTIAL/UNVERIFIABLE | total 34, `counts {PASS:24, TODO:10}`, 0 FAIL, exit 0; набор TODO совпал с заявленным | 0 | **ПОДТВЕРЖДЕНО** — `evidence/verifier/06-redteam-matrix.log` |
| 7 | Старые регрессии 0.1 отдельно | входят в `npm test` | 8 файлов 0.1-набора: 59 tests, 59 pass, 0 fail | 0 | **ПОДТВЕРЖДЕНО** — `evidence/verifier/08-old-regressions.log` |
| 8 | `node --test tests/trust-identity.test.mjs` (сверка состава) | в доке «(5)» | фактически **8** tests, 8 pass | 0 | **РАСХОЖДЕНИЕ (F-WP08-09)** — `evidence/verifier/07-unit-counts.log` |
| 9 | `node --test tests/trust-policy.test.mjs` | 106 | 106 tests, 106 pass | 0 | подтверждено — `07-unit-counts.log` |

Важно: команду `npm test` я не дублировал (по брифу её выполняет Lead). Exit code и число тестов беру из готового артефакта Lead; отдельно и независимо прогнан старый набор 0.1 (59/59) и trust-integration (13/13).

Арифметика состава `npm test` (проверено): 59 (старые 0.1, `08-old-regressions.log`) + 199 (trust-набор: identity 8 + policy 106 + integration 13 + approval 11 + environment 32 + anchor 22 + r01 3 + keygen 4) = 258. Заявленный в `02-TEST-EVIDENCE.md` состав даёт 196 для trust-части (identity=5) → 255, что не сходится с заявленными 258.

## 3. Что происходило в FAIL-прогоне W2

`run-all-w2` запускает 24 скрипта `rt2-*` последовательно, каждый — отдельным процессом, печатает JSON. Итог первого прогона (10:17:32–10:23:10): 23 PASS, 1 FAIL (`L-06`, 21.7 с, exit 1). Агрегатор сохраняет только имена проваленных проверок (`run-all-w2.mjs:55`), без деталей verdict/reasonCode, поэтому причина по логу не восстанавливается; изолированный повтор того же SHA дал PASS.

Вывод: единичный прогон набора W2 не гарантирует воспроизводимость заявленного «24/24 PASS». Направление фикса: сохранять полный JSON каждого скрипта в артефакт агрегатора и добавить повтор/классификацию флейка; для сквозного доверенного PASS — проверить бюджет анкера/таймауты Chromium под нагрузкой.

## 4. Статический анализ тестов на «искусственно зелёные» результаты

Проверены `scripts/run-tests.mjs`, все `tests/*.test.mjs`, `tests/redteam/*.mjs` (включая оба агрегатора и `_lib.mjs`/`_w2.mjs`).

Положительное (проверено грепом/чтением):
- В тестах `node:test` **нет** `skip/todo`, `assert.ok(true)`, пустых `catch {}`, assertions внутри `if`, проверок вида `length >= 0`; `tests/redteam/run-matrix.mjs:325` `status='TODO'` — это матрица, не тест.
- Подавляющее большинство атак проверяет и вердикт, и отсутствие мутации (`mutationCount`), и отсутствие evidence (`checkNoEvidence`), и отсутствие расхода/анкера; ложный PASS без POST проверяется отдельно (`rt2-attack-false-pass.mjs`).
- Старые тесты 0.1 не редактировались (см. WP08-06), поэтому зелёный старый набор не «подкручен» под новое поведение.

Найденные слабые места (подробные дефекты в §5):
1. `scripts/run-tests.mjs:5,9` — `gate` собирает только `tests/*.test.mjs`: redteam-набор **не входит** в `npm test`, поэтому зелёный `npm test` ничего не говорит о 24 атаках и матрице. `races` выбирает 3 теста по `--test-name-pattern`; при переименовании теста набор молча останется без проверок (exit 0 при 0 совпадений) — хрупкая селекция без guard-а на количество.
2. `tests/review-grok.test.mjs:136` — `assert.ok(mutationCount <= 1)` допускает 0 мутаций, т.е. тест «удаление lock не разрешает два POST» пройдёт и при регрессии, полностью блокирующей легитимный POST; строка 137 ещё ослабляет: достаточно, чтобы PASS не было у одного из двух прогонов.
3. `tests/redteam/rt2-e06-dev-environment.mjs:14` — проверка «исходящих соединений на внешние адреса не было» фактически тавтологична: `new URL(stand.baseUrl).hostname === '127.0.0.1'` истинно по построению `makeWorld`; сетевой изоляции она не доказывает.
4. `tests/redteam/run-all-w2.mjs:53` (и `run-all.mjs:27`) — при нераспарсенном JSON вердикт выводится из exit code: `child.status===0 → 'PASS'`. Скрипт, который печатает не-JSON/JSON без `verdict` и завершается 0, будет засчитан как PASS. Сейчас все скрипты печатают JSON через `caseMain`, но защита от регрессии отсутствует.
5. `tests/redteam/rt2-attack-false-pass.mjs:116` — имя проверки «…POST не было», а assertion — `mutationCount === 1` (POST был в другом прогоне мира). Имя и смысл расходятся; проверка не доказывает отсутствие POST для подделанного прогона.
6. Общая схема `run-matrix.mjs:217-239,248` — вердикт строки матрицы берётся из **общего** вердикта скрипта, а не из строко-специфичной проверки. Один скрипт покрывает несколько строк: `E-01/E-07 → rt2-attack-env-substitution.mjs`, `V-01/V-02 → rt2-attack-false-pass.mjs`, `V-07/V-11 → rt2-v07-anchor-before-verdict.mjs` (строки 222,227,229,235). Это ограничение доказательности (см. F-WP08-05).
7. `packages/contracts/export.mjs:9` — `npm run schemas` всегда печатает фиксированную фразу «Экспортированы шесть структурных схем» и всегда exit 0; дрейф схем ловится только внешним `git diff`, встроенной проверки нет.
8. `tests/redteam/rt-14-old-invariants.mjs:32`, `rt-15-r02-keygen-run-dir.mjs:21`, `rt-08-environment-substitution.mjs:49`, `rt-09-secret-leak.mjs:52` — скрипты волны 1 жёстко привязаны к базе `0e7e6c2` (assert `HEAD==='0e7e6c2'`; ожидание, что `packages/trust/environment.mjs`/`trusted.mjs` отсутствуют, R-02 открыт). На финальном SHA `07c21c4` эти проверки заведомо ложны; `run-all.mjs` не входит ни в `npm test`, ни в отчёт финальных прогонов.

## 5. Дефекты

| ID | Severity | Файл:строка | Инвариант | Факт / воспроизведение | Доказательство |
|---|---|---|---|---|---|
| F-WP08-01 | **P2** | `tests/redteam/run-all-w2.mjs` (агрегатор), `tests/redteam/rt2-l06-used-approval.mjs:12` | «заявленное доказательство воспроизводимо на зафиксированном SHA» | `node tests/redteam/run-all-w2.mjs --target=.` → 23 PASS / 1 FAIL (`L-06`, «первый доверенный прогон PASS»), exit 1. Изолированный повтор L-06 → PASS. Причина по логу невосстановима: агрегатор не пишет детали. Заявление «24/24 PASS» на этом SHA не воспроизведено; надёжность W2-доказательства не гарантирована | `evidence/verifier/04-redteam-w2.log` (EXITCODE:1), `05-rt2-l06-single.log` (EXITCODE:0) |
| F-WP08-02 | P3 | `tests/review-grok.test.mjs:136-137` | тест должен падать при регрессии «POST не выполняется вообще» | `mutationCount <= 1` (0 проходит) + «хотя бы у одного нет PASS»: сценарий с нулём POST и двумя BLOCKED проходит | статическое чтение; воспроизводимый сценарий — сломать исполнение мутации, тест останется зелёным |
| F-WP08-03 | P3 | `tests/redteam/rt2-e06-dev-environment.mjs:14` | «нет исходящих соединений на не-loopback» | Проверка сравнивает hostname локального стенда с `127.0.0.1` — тавтология, сетевой трафик не наблюдается | статическое чтение |
| F-WP08-04 | P3 | `tests/redteam/run-all-w2.mjs:53`; `tests/redteam/run-all.mjs:27` | FAIL-по-умолчанию: нераспознанный вывод не может стать PASS | `parsed?.verdict || (status===0 ? 'PASS' …)` — exit 0 без валидного JSON = PASS | статическое чтение |
| F-WP08-05 | P3 | `tests/redteam/run-matrix.mjs:217-239,248`; `rt2-v07-anchor-before-verdict.mjs:1,42-46` | строка матрицы должна подтверждаться сценарием именно этой строки | V-11 («выбор anchor записан, verdict нет, падение») маппится на V-07-сценарий: падение происходит **до** terminal-choice, выбор дописывается вручную в тесте; V-07/V-11, E-01/E-07, V-01/V-02 делят один вердикт скрипта | `06-redteam-matrix.log` rows V-11/E-01/E-07; статический маппинг |
| F-WP08-06 | P3 | `tests/redteam/rt-14-old-invariants.mjs:32`, `rt-15:21`, `rt-08:49`, `rt-09:52` | доказательство не должно быть привязано к устаревшей ревизии молча | Волна-1 скрипты на HEAD `07c21c4` заведомо FAIL (assert HEAD==0e7e6c2; ожидают отсутствие trust-модулей и открытый R-02). В гейтах не запускаются, но лежат в поставке как «воспроизводимые» | статическое чтение + `git log` (база 0e7e6c2) |
| F-WP08-07 | P3 | `packages/contracts/export.mjs:9` | контроль дрейфа схем | Экспорт всегда exit 0 и печатает фиксированное «шесть схем»; проверка — только ручной `git diff schemas/` | `02-schemas.log`: exit 0, diff пуст (фактически ок, но контроль не встроен) |
| F-WP08-08 | P3 | `wp08-audit/evidence/01-npm-test.log` | evidence должно быть машинно-читаемым | Хвост лога Lead содержит mojibake (UTF-8 байты, повторно закодированные cp1251: «вњ”», «в„№»), имена тестов нечитаемы; счётчики уцелели | сравнение начала и хвоста `01-npm-test.log` |
| F-WP08-09 | P3 | `docs/harness/02-TEST-EVIDENCE.md:35` | состав набора соответствует числам | Заявлено «trust-identity (5)», фактически 8 (`07-unit-counts.log`); per-file сумма даёт 196+59=255 против заявленных 258 | `07-unit-counts.log` |
| F-WP08-10 | P3 | `apps/control/run.mjs:19-22`; `tests/redteam/rt2-l08-old-start-rejects-trust.mjs:11-13` | «старый вход не принимает аргументы доверенного режима» | `assertOldEntryOptions` перечисляет 7 имён (`approvalId, approval, trustRoot, adapter, adapterId, standPublicKey, signerPipe`), но не `trust` — именно `trust` включает доверенный путь в `start()/reconcile()` (его передаёт `startTrusted`). Тест L-08 проверяет только 7 имён. Эскалацией не является (R-04: произвольный код той же учётной записи и так вне границы), но формулировка «старый вход не умеет доверенный режим» шире факта | статическое чтение `run.mjs`, `trusted.mjs:271,315`, тест L-08 |

## 6. TODO-строки матрицы: статус в моём мандате

В моём мандате нет отдельных независимых сценариев для этих строк (они распределены WP-01/02, WP-03/04, WP-05, WP-06). По факту `run-matrix` — их **нет покрытия**:

| Строка | Что проверяет | Статус verifier | Влияние |
|---|---|---|---|
| E-04 | credentialRef чужой среды | **NOT RUN / BLOCKED** (в `run-matrix` — TODO, строки-проверки нет) | доказательство неполно: выдача credentialRef не проверена |
| V-05 | повторная публикация тех же байт анкера | NOT RUN / BLOCKED (TODO) | идемпотентность публикации не доказана |
| V-06 | падение после response до анкера | NOT RUN / BLOCKED (TODO) | crash-точка между response и анкером не проверена |
| V-10 | подложный PASS-candidate подписанту | NOT RUN / BLOCKED (TODO) | подписант не проверен на чужой candidate |
| V-12 | неполный terminal-choice + падение | NOT RUN / BLOCKED (TODO) | неполный terminal-choice не проверен |
| L-01 | два процесса, один approval, разные runId | NOT RUN / BLOCKED (TODO) | гонка двух доверенных стартов не проверена |
| L-02 | cancel до INTENT (доверенный путь) | NOT RUN / BLOCKED (TODO) | 0.1-путь покрыт `lifecycle.test.mjs`, доверенный — нет |
| L-04 | падение после POST, reconcile без второго POST | NOT RUN / BLOCKED (TODO) | доверенный reconcile после POST не проверен |
| L-05 | повторный reconcile терминального | NOT RUN / BLOCKED (TODO) | идемпотентность терминального reconcile не проверена |
| B-02 | повторный POST на уже созданный fixture | NOT RUN / BLOCKED (TODO) | 0.1-путь покрыт, доверенный — нет |

Итог: ни одна TODO-строка мною не закрыта; PASS/FAIL по ним выставлять нельзя. Готовность 0.2 без закрытия этих 10 строк остаётся условной.

## 7. Заявлено / подтверждено / опровергнуто

| Заявление | Статус | Основание |
|---|---|---|
| `npm test` = 258/258, exit 0 | подтверждено | `evidence/01-npm-test.log` (Lead) + 59/59 старых отдельно |
| `test:races` = 3/3, exit 0 | подтверждено | `01-test-races.log` |
| `schemas` без диффа | подтверждено | `02-schemas.log` (SHA до/после + git diff пуст) |
| trust-integration = 13/13 | подтверждено | `03-trust-integration.log` |
| Red Team W2 = 24/24 PASS, exit 0 | **опровергнуто (F-WP08-01, P2)** | 23/24, exit 1; флейк L-06 |
| `run-matrix` = 24 PASS / 10 TODO / 0 FAIL | подтверждено | `06-redteam-matrix.log` |
| Тесты не содержат искусственно зелёных проверок | частично: механизмов skip/only/пустых catch нет, но есть слабые/тавтологичные проверки и fallback-вердикты | §4, F-WP08-02…05 |
| TODO-строки «нечем проверить» | подтверждено как отсутствие покрытия | §6 |
