# REDTEAM-REPORT — независимая проверка 0.2, волна 1

Отчёт Red Team (Agent D). Ревизия: `0e7e6c20f7a839ffe16047fa11006b1a9ab6cd31` (база WP-01 + WP-02).
Все факты ниже получены собственными прогонами на Windows 13.11.2026; продуктовый код не менялся.
Документ не является приёмкой: решение принимает Lead/Luna.

## 1. Итог волны 1

| Вопрос | Ответ |
|---|---|
| Дефекты P0/P1 в принятых WP-01/WP-02 | **не найдены** повторным прогоном (19/19 trust-тестов и 16 атак/проверок Red Team) |
| Подтверждённые остаточные риски | **R-01** и **R-02** воспроизведены фактически (severity P2, fail-closed сохранён) |
| Разрывы 0.2, которые на базе нечем закрыть | ложный PASS без анкера, подмена среды, выдача секрета до разрешения — ожидаемо для базы; P1 только для 0.2-PASS |
| Старые инварианты 0.1 | не нарушены: замороженные файлы относительно `v0.1.0-stable` не менялись |
| Каркас матрицы E/V/L/B | готов: `tests/redteam/run-matrix.mjs` (34 строки), на базе 2 PASS, 1 PARTIAL, 1 TODO, 30 UNVERIFIABLE |
| Второй POST / второй terminal verdict | на реальном прогоне не воспроизводятся (RT-01, RT-11, RT-13) |

Собственный прогон всей волны: `node tests/redteam/run-all.mjs` → **16 скриптов, 12 PASS, 4 INCONCLUSIVE, 0 FAIL, exit 0**.
INCONCLUSIVE — это честные «на базе проверить нечем» (см. §6), а не зелёный результат.

## 2. Дефекты и остаточные риски (формат сдачи)

### R-01 — остаточный `guards/<approvalId>.lock` после аварийного завершения

| Поле | Значение |
|---|---|
| ID | R-01 (подтверждён) |
| Ревизия | `0e7e6c20f7a839ffe16047fa11006b1a9ab6cd31` |
| Воспроизводимый скрипт | `node tests/redteam/rt-16-r01-guard-lock.mjs` (18 проверок, PASS, exit 0) |
| Входные условия | Windows; approval подписан и закреплён; процесс входит в `withGuard` реального `approval.mjs` (lock создаётся самим `openSync(guardFile,'wx')`), затем получает SIGKILL внутри guard; после этого другой процесс делает revoke и consume |
| Ожидаемое (контракт) | fail-closed: последующие revoke/consume не должны открывать ACK/POST; расход не создаётся; восстановление не удаляет lock вслепую |
| Фактическое | lock остаётся (0 байт, без pid/времени); revoke падает через **5003 мс**, consume — через **5009 мс** с `CONSUMPTION_INCOMPLETE`; файлы `revocations/` и `consumption/` не созданы; второго ACK/POST нет; при живом держателе второй dispatch падает через **5013 мс** (fail-closed) |
| Нарушенный инвариант | не нарушает §6-1/3/4, но блокирует штатные отзыв и расход (доступность, не обход approval) |
| Severity | **P2** (отказ в обслуживании отзыва/расхода; не второй POST и не ложный PASS) |
| Кому адресован | пакет **WP-02** (`packages/trust/approval.mjs`); safe recovery — только по отдельному доказательству |
| Почему нельзя удалять lock вслепую | файл пуст: в нём нет pid, времени и владельца; liveness держателя хранится только в его процессе. Удаление lock при живом держателе открывает окно второго dispatch (мы это показали: живой держатель держит lock, второй dispatch ждёт 5 с). Безопасное восстановление обязано опираться на внешний признак (например, отдельный процесс-держатель с проверяемым pid), а не на «старый файл» |

Ограничение доказательства: авария воспроизведена SIGKILL внутри реального guard-кода (не «kill -9» через
taskkill /F, эквивалент на Windows). Это тот же отказ; exit-код процесса-жертвы не используется как доказательство.

### R-02 — `keygen.mjs` не проверяет каталоги прогонов, если `runDir` не передан

| Поле | Значение |
|---|---|
| ID | R-02 (подтверждён) |
| Ревизия | `0e7e6c20f7a839ffe16047fa11006b1a9ab6cd31` |
| Воспроизводимый скрипт | `node tests/redteam/rt-15-r02-keygen-run-dir.mjs` (8 проверок, PASS, exit 0) |
| Входные условия | Windows; каталог прогона вида `%TEMP%\runs\run-rt15` (снапшоты/журналы); вызов `node packages/trust/keygen.mjs --secrets <runDir>\secrets --trust-root <tmp>` |
| Ожидаемое (риск R-02/08-OPEN-QUESTIONS P2) | безопасные корневые каталоги закреплены; секреты не создаются в каталоге прогона |
| Фактическое | exit 0; `owner.key` и `anchor.key` созданы **внутри каталога прогона**; публичные ключи в trust root; файлы — DPAPI-обёртка, не открытый PKCS8 |
| Проверка «в репозиторий нельзя» | `keygen --secrets <repo>\rt15-in-repo-*` → exit 1, `TRUST_STORE_UNAVAILABLE`, каталог в репозитории не создан; в `git status` секретов нет |
| Нарушенный инвариант | §6-7 в узком смысле (секрет оказывается в каталоге, который может архивироваться вместе с evidence); в git утечки нет |
| Severity | **P2** |
| Кому адресован | пакет **WP-01** (`packages/trust/keygen.mjs` + `identity.mjs placeTrustRoot`); закрыть в WP-07 закреплением безопасных корневых каталогов |

### GAP-01 — ложный PASS без анкера (ожидаемый разрыв 0.1, обязательство WP-05/06)

| Поле | Значение |
|---|---|
| ID | GAP-01 |
| Ревизия | `0e7e6c20f7a839ffe16047fa11006b1a9ab6cd31` |
| Воспроизводимый скрипт | `node tests/redteam/rt-10-false-pass.mjs` (8 проверок, INCONCLUSIVE, exit 3) |
| Входные условия | Стенд поднят; напрямую через `RunStore` собирается валидная локальная цепочка `mutation-intent→request→response→independent-read→verdict PASS` с корректными хешами, но **POST не отправлялся** |
| Ожидаемое 0.2 | PASS без годного анкера на `candidateSha256` и `chainHead` невозможен (инвариант §6-2, строки V-01/V-02) |
| Фактическое | `observe()` возвращает PASS: `mutationCount=0`, `recordCount=0`, approval/consumption/анкера нет; 0.1 проверяет только локальные хеши |
| Нарушенный инвариант | §6-2 «ни одного PASS без годного анкера» — на базе защиты нет |
| Severity | **P1 для доверенного PASS 0.2**; на базе это ожидаемый разрыв, не дефект принятых WP-01/WP-02 |
| Кому адресован | **WP-05** (`anchor.mjs`) + **WP-06** (Lead: `observeTrusted`/T-D) |
| Обязательство | повторный прогон этой атаки на SHA интеграции должен дать не PASS, а отказ/INCONCLUSIVE без анкера |

### GAP-02 — подмена среды копированием публичных полей (ожидаемый разрыв WP-04)

| Поле | Значение |
|---|---|
| ID | GAP-02 |
| Ревизия | `0e7e6c20f7a839ffe16047fa11006b1a9ab6cd31` |
| Воспроизводимый скрипт | `node tests/redteam/rt-08-environment-substitution.mjs` (8 проверок, INCONCLUSIVE, exit 3) |
| Входные условия | Два локальных стенда; второй («зеркало») на другом сокете отдаёт те же `environmentId`/`fingerprint` из скопированного ответа `/environment`; на базовом стенде нет `/attest` |
| Ожидаемое 0.2 | DENY `ENVIRONMENT_ATTESTATION_FAILED` (строка E-01): повтор публичных полей не спасает |
| Фактическое | `/environment` не содержит challenge/подписи (ключи: environmentId, fingerprint, sourceRevision); зеркало отдаёт те же значения; `/attest` → 404; база 0.1 сравнивает только `environmentId`+`fingerprint` |
| Severity | **P1 для 0.2** (обход привязки к среде), ожидаемый разрыв до WP-04 |
| Кому адресован | **WP-04** (Agent A) + **WP-06** (T-A/T-B) |
| Частично проверяемое | E-08 (монополия порта): второй bind живого стенда → `EADDRINUSE`, стенд продолжает отвечать — PARTIAL, доверенная аттестация недоступна |

### GAP-03 — «секрет не выдан до разрешения» (T-A) на базе не проверяется

Скрипт `node tests/redteam/rt-09-secret-leak.mjs` (16 проверок, INCONCLUSIVE, exit 3).
Что подтверждено: ключи — DPAPI-обёртка + ACL только текущего SID; в git нет `*.key` и JSON-формата
`wrapped-private-key`; createTrustRoot отвергает secretsDir в репозитории/runDir/вложенном trust root;
любой процесс того же SID может развернуть ключ (граница R-04, принятый остаточный риск).
Чего нет: доверенного входа `apps/control/trusted.mjs`/T-A, поэтому строка «секрет не выдан до ALLOW»
проверяется только на второй волне. Это не дефект базы.

### OBS-01 — коды ошибок ядра 0.1 только в тексте, без `error.code`

| Поле | Значение |
|---|---|
| Ревизия | `0e7e6c20f7a839ffe16047fa11006b1a9ab6cd31` |
| Наблюдение | `packages/core/store.mjs` бросает `new Error('INTEGRITY_ERROR: …')` без свойства `code`, тогда как trust-модули используют `error.code`; `@apps/control/run.mjs` матчит `message` |
| Severity | **P3** (не влияет на решение PASS/FAIL, но усложняет машинную обработку) |
| Кому адресован | Lead/владелец замороженного ядра; менять в 0.1 не требуется — учесть при расширении интерфейсов |

## 3. Результаты атак и проверок (свои прогоны)

| ID | Атака/проверка | Вердикт | Ключевой факт |
|---|---|---|---|
| RT-01 | второй POST, второй verdict, утечка Bearer (реальный прогон 0.1) | PASS | POST=1; reconcile и повторный `start()` не мутируют; второй verdict → INTEGRITY_ERROR; Bearer не найден в runDir |
| RT-02 | POST без approval | INCONCLUSIVE | модуль отказывает (APPROVAL_MISSING/CONTRACT_INVALID); старый `run()` штатно исполняет 0.1 без approval; доверенного пути 0.2 на базе нет |
| RT-03 | POST после отзыва | PASS | APPROVAL_REVOKED, consumption/ACK нет, повторный отзыв не перезаписывает файл |
| RT-04 | POST после истечения/до issuedAt/срок >15 мин | PASS | APPROVAL_EXPIRED / CONTRACT_INVALID, расход не создан, часы процесса |
| RT-05 | подделка/изменение approval, чужой и anchor-ключ | PASS | APPROVAL_SIGNATURE_INVALID; закреплённый документ не перезаписывается |
| RT-06 | повтор approvalId, повтор dispatch, гонка двух процессов | PASS | один ACK; тот же runId → APPROVAL_CONSUMED; другой runId → APPROVAL_REPLAY; файл не изменён |
| RT-07 | несовпадение подписанных входов и фактической мутации | PASS | 9 видов несовпадения → APPROVAL_MISMATCH, consumption нет; точные входы → ACK |
| RT-08 | подмена среды | INCONCLUSIVE | копирование публичных полей не обнаруживается (GAP-02); E-08 PARTIAL |
| RT-09 | утечка секретов | INCONCLUSIVE | DPAPI+ACL подтверждены, git чист; T-A проверить нечем |
| RT-10 | ложный PASS без POST/approval/анкера | INCONCLUSIVE | PASS принят при mutationCount=0 (GAP-01) |
| RT-11 | повторный терминальный verdict | PASS | appendEvidence→INTEGRITY_ERROR; неподтверждённый хвост не становится verdict; коммит не публикуется |
| RT-12 | подмена evidence/конверта/журнала событий | PASS | во всех случаях INTEGRITY_ERROR/не PASS; после восстановления PASS |
| RT-13 | нарушение recovery (потерянный ответ) | PASS | reconcile не повторяет POST, второй request/verdict не появляется |
| RT-14 | старые инварианты 0.1 | PASS | замороженные файлы и старые тесты не изменены относительно `v0.1.0-stable` |
| RT-15 | R-02: keygen кладёт секреты в каталог прогона | PASS (риск подтверждён) | см. R-02 |
| RT-16 | R-01: остаточный guard lock | PASS (риск подтверждён, fail-closed) | см. R-01 |

Команда полного прогона: `node tests/redteam/run-all.mjs` (агрегирует JSON-вердикты, exit 1 только при FAIL).
Каждый скрипт печатает JSON `{id, revision, verdict, checks[], notes}` и имеет собственный exit code:
0 — PASS, 1 — FAIL, 3 — INCONCLUSIVE.

## 4. Инварианты §6 BASELINE-AND-CONTRACTS

| № | Инвариант | Статус волны 1 |
|---|---|---|
| 1 | Ни одного второго POST | подтверждён (RT-01, RT-13) |
| 2 | Ни одного PASS без годного анкера | **на базе не защищён** (GAP-01); закрывается WP-05/06, обязательна проверка на интеграции |
| 3 | Ни одного второго терминального verdict | подтверждён (RT-01, RT-11) |
| 4 | Расход approval не возвращается после падения | подтверждён (RT-16: consumption не создан; L-07: неполный файл не заменяется) |
| 5 | Старый `start()` не принимает approval/trust root/адаптер | на базе аргументов доверенного режима ещё нет; старый вход не выпускает доверенный PASS. Проверить на интеграции |
| 6 | Схемы 0.1 и 78 принятых тестов не меняются | RT-14: diff по замороженным путям пуст; trust-тесты 19/19 |
| 7 | Секреты не в снапшотах/evidence/событиях/отчётах | RT-01 (Bearer не в runDir), RT-09 (DPAPI/ACL, git чист); остаток R-02 — секрет в каталоге прогона при неверном аргументе keygen |

## 5. Каркас матрицы E/V/L/B и что реально нечем проверить

`tests/redteam/run-matrix.mjs <путь-к-worktree>` — принимает путь к любой ветке (не меняет её),
определяет ревизию, проверяет наличие зависимостей, выполняет реализованные проверки, печатает JSON
и сводку; код выхода 1 только при FAIL. Матрица: E-01…E-08, V-01…V-12, L-01…L-09, B-01…B-05 (34 строки).

Прогон на базе: `node tests/redteam/run-matrix.mjs .` →
**PASS: L-07, L-09; PARTIAL: E-08; TODO: L-08; UNVERIFIABLE: 30**, exit 0.

Чего на 0e7e6c2 реально нечем проверить (30 строк, точные причины):

1. **E-01…E-07** — нет `packages/trust/environment.mjs` (реестр сред, аттестация stand key, challenge),
   нет `apps/control/trusted.mjs` и `policy.mjs`: нечего вызывать и нечем ловить DENY/INDETERMINATE.
   E-08 проверен частично: монополия сокета базовым стендом держится (`EADDRINUSE`), аттестации владельца порта нет.
2. **V-01…V-12** — нет `packages/trust/anchor.mjs`/`anchor-signer.mjs`: кандидат, terminal-choice, анкер,
   подписант, бюджет, `observeTrusted` отсутствуют. V-01/V-02 (ложный PASS/подмена вердикта) сейчас
   принципиально не закрыты (GAP-01), а проверяются только после WP-05/06.
3. **L-01…L-06** — нужен доверенный жизненный цикл `apps/control/trusted.mjs` (T-A/T-B/T-E) и `policy.mjs`;
   на базе есть только старый 0.1. L-07 и L-09 проверяемы уже сейчас (модуль approval есть) — PASS.
   L-08 (старый `start()` не принимает approval/trust/адаптер) — TODO каркаса: на базе таких аргументов нет,
   проверка станет осмысленной на интеграции.
4. **B-01…B-05** — нужен доверенный старт + policy; B-05 дополнительно требует сравнения правила «201, не 200»
   в доверенном режиме. Проверять на базе старый 0.1-путь для этих строк бессмысленно.

Smoke каркаса против уже собранной интеграционной ветки (`C:\Users\gvi\Desktop\QA-ADAPTANT-harness\integration`,
ревизия на момент прогона `399d441cfe95f625be986c385ffa32b23b1838ad`):
34 строки, **3 PASS (E-08, L-07, L-09), 31 TODO** — зависимости (environment/anchor/policy/trusted) присутствуют,
поэтому строки сменили статус с UNVERIFIABLE на TODO и ждут проверок волны 2. Это только проверка
работоспособности каркаса, а не приёмка интеграции.

## 6. Что перепроверить на второй волне (по SHA от Lead)

1. Полный набор `node tests/redteam/run-all.mjs` на ветках WP-03/04/05 и интеграции: R-01/R-02 должны быть
   закрыты или явно приняты с изменённой severity; повторять только по фактам, не по словам авторов.
2. Матрицу `run-matrix.mjs <integration>`: сначала реализовать проверки для 31 TODO строки (E-01…E-07,
   V-01…V-12, L-01…L-06, L-08, B-01…B-05) — каркас для этого готов, нужны только тела проверок.
3. Повторить GAP-01 (ложный PASS) и GAP-02 (подмена среды) — они должны дать отказ после WP-04/05/06.
4. Проверить L-08 динамически: старый `start()` с approval/trust root/именем адаптера обязан отвергать
   аргументы и не выпускать доверенный PASS.
5. Проверить R-01 на интеграции: не появился ли безопасный механизм восстановления lock без окна второго dispatch.
6. После закрытия R-02 — повторить `keygen --secrets <runDir>\secrets` и убедиться в отказе.

## 7. Ограничения этой волны

- Проверялась только ревизия 0e7e6c2 (WP-01/WP-02); WP-03/04/05/06 на момент волны ещё не были сданы.
- Не запускался полный `npm test` (шаг Lead на интеграции, ~2 мин, Chromium); Red Team гонял trust-тесты
  пакетов (19/19) и собственные скрипты; реальные прогоны 0.1 — 4 сценария (норма, lostResponse, tampered evidence/verdict).
- R-03 (TOCTOU гибели стенда) и R-04 (изоляция SID) отдельно не атаковались: R-03 требует WP-04/06,
  R-04 — это явная граница локальной 0.2, не дефект.
- Все данные — временные каталоги %TEMP%; секреты в отчёт не попали; ЦИЗ/Dev не подключались.

## 8. SHA и состав

См. итоговый коммит ветки `test/adaptant-02-trust-verification` (SHA сообщается Lead отдельным сообщением
и указан в `git rev-parse HEAD`). Файлы волны 1:

- `tests/redteam/_lib.mjs`, `_run.mjs`, `_guard-victim.mjs`, `_consume-worker.mjs` — общая обвязка;
- `tests/redteam/rt-01…rt-16-*.mjs` — 16 воспроизводимых атак/проверок с JSON-вердиктом и exit code;
- `tests/redteam/run-all.mjs` — агрегатор; `tests/redteam/run-matrix.mjs` — каркас матрицы E/V/L/B;
- `docs/harness/REDTEAM-BASELINE.md`, `docs/harness/REDTEAM-REPORT.md` — этот отчёт и фиксация базы.

## 9. ВОЛНА 2 — проверка интеграции 0.2 (WP-03/04/05/06)

Все факты ниже — собственные прогоны Red Team на Windows. Продуктовый код интеграции не менялся.
Каждый скрипт волны 2 работает на **закреплённом снимке** HEAD+diff целевой ветки (копия в %TEMP%,
junction на node_modules); если дерево меняется в момент снятия снимка — вердикт INCONCLUSIVE, а не PASS.

### 9.1. Ревизия и общее состояние

| Параметр | Значение |
|---|---|
| Закреплённая ревизия интеграции | `98f09ebda1c9af1fde907f79d83f4abebdb8bb39` |
| Снимок | `%TEMP%\qa-rt-matrix-pin-9c429b93758595d2` (tracked diff пуст) |
| Изменения интеграции во время волны | `399d441 → 8be5b7f → 094753b → b57962b → 8674816 → 98f09eb` (результаты привязаны к 98f09eb) |
| `node tests/redteam/run-all-w2.mjs` | **24 из 24 PASS**, exit 0, суммарно ~4 мин |
| `node tests/redteam/run-matrix.mjs <integration>` | 34 строки: **24 PASS, 10 TODO, 0 FAIL, 0 PARTIAL, 0 UNVERIFIABLE** |

Итог: на 98f09eb **подтверждённых P0/P1 нет**. GAP-01 и GAP-02 закрыты фактически; R-02 закрыт;
R-01 остаётся открытым P2; два наблюдения P3 (§9.5).

### 9.2. Матрица E/V/L/B по строкам (PASS / TODO)

**PASS (24 строки).** Для каждой — отдельный воспроизводимый скрипт с JSON-вердиктом и exit code.

| ID | Скрипт | Что подтверждено фактически |
|---|---|---|
| E-01 | rt2-attack-env-substitution | зеркало с копией environmentId/fingerprint и старой аттестации на том же origin → BLOCKED ENVIRONMENT_CHANGED; аттестация запрошена, POST нет |
| E-02 | rt2-e02-unknown-environment | environmentId вне реестра → BLOCKED ENVIRONMENT_CHANGED, 0 POST, нет intent |
| E-03 | rt2-e03-generation-change | поколение реестра 1 против живого 2 → BLOCKED ENVIRONMENT_CHANGED, 0 POST |
| E-05 | rt2-e05-registry-unreadable | повреждённая запись поколения → fail-closed BLOCKED CONTRACT_INVALID, 0 POST; битый owner.pub → TRUST_STORE_UNAVAILABLE до старта (нюанс проекции — OBS-03) |
| E-06 | rt2-e06-dev-environment | kind=dev при active → BLOCKED (PDP ENVIRONMENT_KIND_DENIED), 0 POST, только 127.0.0.1 |
| E-07 | rt2-attack-env-substitution | процесс без ключа стенда (нет /attest) → BLOCKED, route.continue/POST нет |
| E-08 | run-matrix (built-in) | второй bind живого стенда → EADDRINUSE, стенд отвечает; WP-04 аттестация присутствует |
| V-01 | rt2-attack-false-pass | подмена терминального коммита evidence при старом анкере → observeTrusted не PASS |
| V-02 | rt2-attack-false-pass | подмена verdict после публикации → observeTrusted не PASS |
| V-03 | rt2-v03-signer-unavailable | подписант недоступен дольше бюджета → один INCONCLUSIVE EVIDENCE_MISSING, анкера нет, повторное наблюдение не PASS |
| V-04 | rt2-v04-two-anchors | второе заявление на тот же runId → ANCHOR_CONFLICT, первый анкер сохранён, PASS не появляется |
| V-07 | rt2-v07-anchor-before-verdict | анкер+выбор записаны, verdict нет → дописан ровно один verdict, равный candidate; повтор не создаёт второй |
| V-08 | rt2-v08-owner-as-anchor | owner-подпись анкера → ANCHOR_SIGNATURE_INVALID; observeTrusted не PASS; после восстановления PASS |
| V-09 | rt2-v09-budget-race | анкер создан, ответ после бюджета → один INCONCLUSIVE, ANCHOR_UNLINKED, перехода в PASS и ANCHOR_CONFLICT нет |
| V-11 | rt2-v07-anchor-before-verdict | выбор anchor записан, verdict нет → ровно выбранный candidate, бюджет заново не разыгрывается |
| L-03 | rt2-l03-crash-after-consumption | падение после consumption до POST (dropIntentAck): расход есть, POST нет; reconcile без нового dispatch; новая попытка требует нового approval |
| L-06 | rt2-l06-used-approval | повтор использованного approval → APPROVAL_REPLAY; повторное закрепление approvalId отвергнуто; второй старт 0 POST |
| L-07 | run-matrix (built-in) | неполный расход после CREATE_NEW не заменяется, ACK нет |
| L-08 | rt2-l08-old-start-rejects-trust | старый start() отвергает trustRoot/approvalId/approval/standPublicKey/signerPipe/adapter (CONTRACT_INVALID), runDir/consumption не созданы, approval issued |
| L-09 | run-matrix (built-in) | два процесса один approval → один ACK и один полный файл, второй APPROVAL_REPLAY |
| B-01 | rt2-b01-registry | операция вне реестра 0.1 → BLOCKED CONTRACT_INVALID, 0 POST |
| B-03 | rt2-b03-effects-mismatch | набор эффектов approval ≠ операции → BLOCKED CONTRACT_INVALID, 0 POST |
| B-04 | rt2-b04-fixture-mismatch | fixtureId в approval ≠ снимку → BLOCKED CONTRACT_INVALID, объект B не создан |
| B-05 | rt2-b05-http-200-existing | заранее созданный объект, POST 200 → не PASS (INCONCLUSIVE RESULT_UNCONFIRMED), mutationCount не растёт |

**TODO (10 строк) — на 98f09eb не проверены, требуют отдельного harness (не «всё ок»):**

| ID | Почему TODO |
|---|---|
| E-04 | нужен адаптер выдачи секрета по credentialRef и проверка, что секрет другой среды не выдан; путь выдачи на 98f09eb не собран в проверяемый сценарий |
| V-05 | идемпотентная повторная публикация тех же байт анкера — нужен прямой harness подписанта/публикации |
| V-06 | падение после локального response и до анкера + reconcile — нужна crash-injection точка между verifyAndPersist и publish |
| V-10 | подложный PASS-candidate и прямой запрос к anchor-signer — нужен отдельный harness подписанта (L-03/V-04 частично смежны) |
| V-12 | неполный terminal-choice.json после CREATE_NEW — нужен crash сразу после создания файла |
| L-01 | одновременный старт двух доверенных процессов на один approval — гонка уровня Control, не реализована (L-06/L-09 покрывают частично) |
| L-02 | cancel до INTENT на доверенном входе — сценарий отмены не реализован |
| L-04 | падение после POST на доверенном пути — старый 0.1-путь покрыт RT-13, доверенный — нет |
| L-05 | повторный reconcile уже терминального доверенного прогона — частично покрыт L-03; отдельной строки нет |
| B-02 | второй старт на тот же fixture на доверенном пути — привязка fixture 0.1 не воспроизведена в доверенном сценарии |

Строки, которые раньше были UNVERIFIABLE, стали PASS только там, где есть фактический прогон;
остальные честно помечены TODO и вынесены в список внешней приёмки (§9.6).

### 9.3. Отдельно по пяти пунктам

**GAP-01 (ложный PASS без анкера) — ЗАКРЫТ на 98f09eb.** `rt2-attack-false-pass.mjs`, 20 проверок, PASS:
- эталонный доверенный прогон: PASS + observeTrusted `passed=true, anchorStatus=ANCHOR_OK`;
- без подписанта: INCONCLUSIVE EVIDENCE_MISSING, observeTrusted не PASS (mutationCount=1);
- подделанный terminal-choice «anchor» без файла анкера → observeTrusted не PASS (inconsistent, TERMINAL_CHOICE_INCOMPLETE);
- чужой анкер от другого runId → не PASS;
- подмена verdict после публикации и подмена терминального коммита evidence → observeTrusted не PASS;
- полностью сфабрикованная локальная цепочка PASS без POST/approval/анкера → observeTrusted `passed=false, state=inconsistent, INTEGRITY_ERROR`, при этом старый `observe()` показывает PASS — **старый вход не является доказательством доверенного PASS**.

**GAP-02 (подмена среды) — ЗАКРЫТ на 98f09eb.** `rt2-attack-env-substitution.mjs`, PASS:
(A) зеркало с копией публичных полей и старой аттестацией на том же origin → BLOCKED ENVIRONMENT_CHANGED, зеркало получило только /attest, mutationCount=0;
(B) сервер без ключа стенда (/attest=404) → BLOCKED, POST нет;
(C) подмена на другой реальный стенд с другим ключом на том же origin → BLOCKED, mutationCount=0. Ни в одном варианте нет mutation-intent/request.

**L-08 — PASS.** `rt2-l08-old-start-rejects-trust.mjs`: старый start() отвергает каждый из 7 аргументов доверия с CONTRACT_INVALID до snapshot/мутации; каталог прогона и consumption не созданы; approval остаётся issued.

**R-01 — открыт, P2, владелец WP-02.** `rt2-r01-guard-lock.mjs`, PASS (риск подтверждён):
SIGKILL внутри реального withGuard оставляет пустой `guards/<approvalId>.lock`; revoke падает через **5005 мс**, consume — через **5006 мс** (CONSUMPTION_INCOMPLETE); второго ACK/расхода нет. На доверенном входе тот же lock даёт T-B отказ: BLOCKED AUTH_UNAVAILABLE через ~7.4 с, 0 POST, нет mutation-intent, consumption не создан (`rt2-attack-ack-without-consumption.mjs`). Слепое удаление lock недопустимо: файл пуст, владелец/liveness неизвестны; удаление при живом держателе открывает окно второго dispatch. Safe recovery — только по отдельному доказательству.

**R-02 — ЗАКРЫТ на 98f09eb.** `rt2-r02-keygen-run-dir.mjs`: `--secrets <...>\runs\<runId>\secrets` отвергается (exit 1, TRUST_STORE_UNAVAILABLE), ключи в runDir не создаются; сегмент `RUNS` в верхнем регистре тоже отвергается; secretsDir в репозитории отвергается; безопасный путь вне runs/ работает; в git нет *.key. Остаточное замечание: keygen проверяет только сегмент имени `runs` (обход через другой каталог-хранилище с иным именем не покрыт; для RunStore 0.1 раскладка всегда `<root>/runs/<id>`).

### 9.4. Атаки WP-06 (все PASS на 98f09eb)

| Скрипт | Факт |
|---|---|
| rt2-attack-ack-without-consumption | остаточный guard lock → T-B отказ BLOCKED AUTH_UNAVAILABLE, 0 POST, mutation-intent не записан, расхода нет (ACK без расхода невозможен) |
| rt2-attack-second-post | PASS-прогон: reconcile и повторный старт не мутируют (mutationCount=1, request evidence=1); второй terminal verdict → INTEGRITY_ERROR; повторный старт с новым approval не расходует его |
| rt2-attack-secret-before-allow | отказ до T-A: Browser не дошёл до READY/INTENT, browser.pid нет, Bearer и protectedPkcs8 в runDir отсутствуют; в успешном PASS-прогоне Bearer тоже не записан |
| rt2-attack-foreign-sid | чужая карточка с SID другого пользователя → BLOCKED AUTH_UNAVAILABLE, 0 POST |
| rt2-attack-false-pass | см. GAP-01 |

### 9.5. Наблюдения P3 (не блокируют, но зафиксированы)

- **OBS-02 — бюджет анкера берётся из неподписанного `trustRoot/profile.json`.** `loadAnchorBudgetMs` проверяет только `schemaVersion/domain` и диапазон 1…60000, подпись не проверяется, хотя BASELINE §5.2 требует «подписанный профиль». Red Team использовал это в V-03/V-09 (бюджет 500/1500 мс), прогоны прошли. Риск ограничен границей R-04 (тот же SID уже владеет trust root), но формулировке контракта не соответствует. Адресат: WP-05 (Agent B/владелец anchor.mjs).
- **OBS-03 — проекция E-05 не совпала с матрицей.** Повреждённый реестр сред даёт BLOCKED `CONTRACT_INVALID` (PDP DENY), матрица ожидает INDETERMINATE TRUST_STORE_UNAVAILABLE → BLOCKED AUTH_UNAVAILABLE. Fail-closed сохранён (0 POST, нет intent), но reasonCode другой. Адресат: WP-06/Lead (решение о проекции или о матрице).
- **OBS-04 — пояснение, не дефект.** E-06 actual verdictCode `CONTRACT_INVALID`, потому что PDP-код `ENVIRONMENT_KIND_DENIED` входит в contractReasons таблицы проекции (docs/wp-00/03-CONTRACT-PROPOSALS.md); критерий строки (fail-closed, 0 POST) выполнен.

### 9.6. Открытые P0/P1 и что вынести на внешнюю приёмку

**Подтверждённых P0/P1 на 98f09eb нет.** Открыто: R-01 (P2), OBS-02/OBS-03 (P3).
Список для внешней приёмки:
1. Прогнать `run-all-w2` и `run-matrix` на финальном SHA (одна команда, снимок закрепляется автоматически). Ожидание на 98f09eb: 24/24 и 24 PASS/10 TODO.
2. Реализовать/принять 10 TODO строк из §9.2 (E-04, V-05, V-06, V-10, V-12, L-01, L-02, L-04, L-05, B-02).
3. Принять решение по R-01: оставить как P2 fail-closed или ввести safe recovery с отдельным доказательством.
4. Решить OBS-02 (подписывать profile.json или исправить контракт) и OBS-03 (проекция E-05).
5. Зафиксировать, что старый `observe()` не используется как доказательство PASS (GAP-01).
