# WP08-05 — ACCEPTANCE MATRIX (WP-08)

**SHA:** `07c21c4db936627df9a3c874015327ea992a335a`. Матрица: `docs/wp-00/06-ACCEPTANCE-MATRIX.md` (34 строки E/V/L/B).
Статусы: PASS — подтверждено независимым/собственным запуском или прямым чтением кода с проверкой эффекта; FAIL — критерий не выполнен или опровергнут; NOT RUN — сценарий не исполнялся; BLOCKED — окружение недоступно.
**Важно:** зелёные строки не означают безопасного маршрута: два P0 (AUD-P0-01/AUD-P0-02) находятся **вне покрытия 34 строк** и делают доверенный PASS недостоверным (см. WP08-04).

## 1. Позитивные (P)

| ID | Статус | Доказательство | Ограничения |
|---|---|---|---|
| P-01 | **PASS** | `npm test`: 258/258, старые 59 тестов 0.1 — 59/59 (exit 0); старый путь без trust root работает | — |
| P-02 | **PASS (сценарий)** | T-01: живой стенд+Chromium, 1 POST, 1 independent-read, 1 candidate, 1 anchor, terminal PASS; `observeTrusted passed=true` | Гарантия «PASS достоверен» опровергнута P0 (AUD-P0-01/02) |
| P-03 | **PASS** | T-01/T-13: повторный `observeTrusted`/reconcile не делает POST; мутация=1 | — |
| P-04 | **PASS** | wp0102: два consume с одним `runId` → один файл, второй без ACK; L-09 same-runId (2 процесса → 1 ACK) | — |
| P-05 | **PASS** | `tests/trust-anchor.test.mjs` «fail-without-anchor публикует один бизнес-FAIL»; npm test 22/22 | — |

## 2. Авторизация (A)

| ID | Статус | Доказательство | Ограничения |
|---|---|---|---|
| A-01 | PASS | policy role/subject checks; trust-integration T-03/T-06; wp0102 approval 15/15 | — |
| A-02 | PASS | policy нет роли → ROLE_DENIED; trust-policy 106/106 | — |
| A-03 | PASS | approval.mjs assertBindings (resource); trust-approval; wp0102 | — |
| A-04 | PASS | INPUTS mismatch → APPROVAL_MISMATCH; T-06; wp0102 | — |
| A-05 | PASS | operationVersion в подписи/сверке; trust-approval | — |
| A-06 | PASS | expiresAt прошёл → APPROVAL_EXPIRED; T-04 | — |
| A-07 | PASS | отзыв → APPROVAL_REVOKED; T-05 | — |
| A-08 | PASS | чужой ключ/подпись → APPROVAL_SIGNATURE_INVALID; trust-identity/approval | — |
| A-09 | PASS | другой runId → APPROVAL_REPLAY; L-06/rt2-l06 | — |
| A-10 | PASS | повторный dispatch → APPROVAL_CONSUMED, второго POST нет; L-06/wp05 | — |
| A-11 | PASS | чужой SID → BLOCKED AUTH_UNAVAILABLE, POST=0; T-03; wp06 A-11; wp0102 | — |
| A-12 | PASS | ключ anchor не создаёт approval; trust-identity, V-08 | — |

## 3. Среда (E)

| ID | Статус | Доказательство | Ограничения |
|---|---|---|---|
| E-01 | **PASS** | rt2-attack-env-substitution (зеркало/копия полей → BLOCKED ENVIRONMENT_CHANGED, POST=0); wp0304 E-01 (перехваченная аттестация не переигрывается) | **После T-C/после POST среда не перепроверяется — AUD-P0-02** |
| E-02 | **PASS** | rt2-e02: ENVIRONMENT_UNKNOWN → BLOCKED, 0 POST | — |
| E-03 | **PASS** | rt2-e03 + wp0304 E-03: смена поколения до POST → BLOCKED ENVIRONMENT_CHANGED, 0 POST | — |
| E-04 | **FAIL** | wp0304: `credentialRef='prod:foreign-secret-7'` проходит PDP; Browser получает и отправляет стенду секрет другой среды (`foreignSecretDeliveredToStand:true`) | Матрица требует DENY ENVIRONMENT_ATTESTATION_FAILED и отсутствия секрета. Не реализовано |
| E-05 | **PASS** | T-13: повреждённый реестр → INDETERMINATE/BLOCKED AUTH_UNAVAILABLE, 0 POST; rt2-e05; wp0304 E-05 | — |
| E-06 | **PASS** | rt2-e06 + wp0304: kind=dev/production → DENY, соединений нет, 0 POST | Тавтологичность проверки «нет внешних соединений» (P3) |
| E-07 | **PASS (предусловие)** | wp0304 E-07: стенд остановлен до проверки → DENY, route.continue/POST нет | **FAIL в окне после T-C: мутация уходит на новый сокет (AUD-P0-02)** |
| E-08 | **PASS** | wp0304 E-08: второй bind → EADDRINUSE, стенд отвечает; run-matrix E-08 | — |

## 4. Evidence и анкер (V)

| ID | Статус | Доказательство | Ограничения |
|---|---|---|---|
| V-01 | PASS | rt2-attack-false-pass (подмена терминального коммита → не PASS); wp05 | — |
| V-02 | PASS | rt2-attack-false-pass (подмена verdict → не PASS) | — |
| V-03 | PASS | rt2-v03: нет подписанта → один INCONCLUSIVE/EVIDENCE_MISSING, PASS нет | — |
| V-04 | PASS | rt2-v04: второй анкер на runId → ANCHOR_CONFLICT | — |
| V-05 | **PASS** | wp05: повторный `sign` тех же полей идемпотентен, файл байт-в-байт, 0 новых | `publishAnchor` в API отсутствует (P3) |
| V-06 | **FAIL** | wp05: e2e SIGKILL после response → `reconcileTrusted` всегда INCONCLUSIVE/WORKER_LOST; PASS-ветка недостижима; POST=1, request=1, verdict=1 | Безопасное отклонение; контракт строки не выполнен |
| V-07 | **FAIL** | wp05: crash после анкера до choice → новый anchorId → ANCHOR_CONFLICT → INCONCLUSIVE, анкер ANCHOR_UNLINKED; wp06: crash после anchor/candidate → CANDIDATE_CONFLICT, verdict не пишется | Встроенный matrix PASS использует другой crash-point (module-level) |
| V-08 | PASS | rt2-v08: owner-подпись анкера → ANCHOR_SIGNATURE_INVALID | — |
| V-09 | PASS | rt2-v09: поздний анкер → один INCONCLUSIVE, ANCHOR_UNLINKED, перехода в PASS нет | — |
| V-10 | **PASS (узкий)** | wp05: нет approval/чужой runId/подмена inputs → ANCHOR_BINDING_REJECTED, анкера нет | **Не защищает от AUD-P0-01 при валидной связке** |
| V-11 | PASS | rt2-v07 + wp06: choice=anchor записан, verdict нет → дописан ровно candidate; бюджет заново не разыгрывается | — |
| V-12 | PASS | wp05: 0 байт/обрыв JSON → PASS не публикуется, файл не заменён, подписант отказывает; wp06 подтверждает | Side effect: reconcile отвергает необработанной ошибкой (P3) |

## 5. Жизненный цикл (L)

| ID | Статус | Доказательство | Ограничения |
|---|---|---|---|
| L-01 | **PASS (механизм) / E2E NOT RUN** | wp0102: 4 процесса/один approval/разные runId → ровно 1 ACK, 1 полный файл | Полный одновременный `startTrusted` двух Control-процессов не исполнялся |
| L-02 | PASS | wp06: CANCEL до INTENT → BLOCKED/CANCELED, POST=0, approval issued, расхода нет | — |
| L-03 | PASS | rt2-l03: падение после consumption до POST → расход есть, POST нет, reconcile без dispatch | — |
| L-04 | PASS | wp06: падение после POST → reconcile, POST=1, request=1, вердикт INCONCLUSIVE, второго POST нет | V-06 PASS-ветка недостижима |
| L-05 | PASS | wp06: повторный reconcile терминального → тот же verdict, evidence не растёт, 0 POST | — |
| L-06 | PASS | rt2-l06 (изолированно; первый W2-прогон дал флейк) | Флейк под нагрузкой (P3) |
| L-07 | PASS | run-matrix built-in + wp0102: CONSUMPTION_INCOMPLETE, ACK нет, файл не заменён | — |
| L-08 | PASS | rt2-l08: старый start() отвергает 7 аргументов доверия, runDir/consumption не созданы | `trust` не отвергается (AUD-P3-05) |
| L-09 | PASS | run-matrix built-in + wp0102: 2 процесса/один approval → 1 полный файл, ≤1 ACK | — |

## 6. Бизнес-ограничения (B)

| ID | Статус | Доказательство | Ограничения |
|---|---|---|---|
| B-01 | PASS | rt2-b01: операция вне реестра → BLOCKED CONTRACT_INVALID, 0 POST | — |
| B-02 | PASS | wp06: второй startTrusted с тем же fixture + новый approval → отказ привязки, POST=1, approval не израсходован | — |
| B-03 | PASS | rt2-b03: effects mismatch → DENY, 0 POST | — |
| B-04 | PASS | rt2-b04: fixture mismatch → DENY, объект B не создан | — |
| B-05 | PASS | rt2-b05: HTTP 200 существующего → не PASS (INCONCLUSIVE), mutationCount не растёт | — |

## 7. Итог по 34 строкам

| Группа | PASS | FAIL | NOT RUN | Всего |
|---|---|---|---|---|
| E | 7 | 1 (E-04) | 0 | 8 |
| V | 10 | 2 (V-06, V-07) | 0 | 12 |
| L | 9 (L-01 с оговоркой) | 0 | 0 (L-01 E2E — NOT RUN) | 9 |
| B | 5 | 0 | 0 | 5 |
| **Итого** | **31** | **3** | — | **34** |

**Ключевой вывод:** матрица 34 строк **не является достаточным доказательством безопасности доверенного маршрута**: при 31 PASS два независимых P0 (ложный доверенный PASS) находятся вне её покрытия. Три строки (E-04, V-06, V-07) — FAIL. Матрица поставки (24 PASS/10 TODO) не отражает эти результаты: V-07 получает PASS по другому crash-point, E-04/V-06 — TODO, а E-07 проверяется только до T-C.

## 8. Десять ранее незакрытых TODO — независимый разбор

| Строка | Контракт (06-ACCEPTANCE-MATRIX) | Реализация | Независимый тест | Exit | Итог WP-08 | Влияние на 0.2 |
|---|---|---|---|---|---|---|
| **E-04** | credentialRef чужой среды → DENY, секрета в Browser нет | **нет** привязки credentialRef | `wp0304-03-attacks.mjs` (E-04) | 0 | **FAIL** | Секрет чужой среды доставляется стенду; требование не выполнено |
| **V-05** | повторная публикация тех же байт идемпотентна, 0 новых | через подписант/publishTerminalVerdict | `wp05-anchor-independent.test.mjs` | 0 | **PASS** | Документальный дрейф (`publishAnchor` отсутствует) |
| **V-06** | падение после response до анкера; reconcile; PASS только при анкере в срок, иначе INCONCLUSIVE | reconcile всегда INCONCLUSIVE | `wp05-v06-crash-reconcile.mjs` | 0 | **FAIL** | PASS-ветка недостижима; безопасно (0 второго POST) |
| **V-10** | подложный candidate, не подтверждённый approval/consumption → ANCHOR_BINDING_REJECTED | есть | `wp05-anchor-independent.test.mjs` | 0 | **PASS (узкий)** | **Не закрывает AUD-P0-01** при валидной связке |
| **V-12** | неполный terminal-choice блокирует PASS, файл не заменён | есть | `wp05-anchor-independent.test.mjs` | 0 | **PASS** | Side effect публикации (P2) |
| **L-01** | два процесса, один approval, разные runId → один consumption, второй APPROVAL_REPLAY | consumption — есть | `wp0102-approval.test.mjs` | 0 | **PASS (механизм); E2E NOT RUN** | Полный Control-E2E не исполнялся |
| **L-02** | cancel до INTENT → BLOCKED CANCELED, POST=0, approval issued | есть | `wp06-lifecycle.mjs` | 0 | **PASS** | — |
| **L-04** | падение после POST → reconcile без второго POST, request не дублируется | есть (INCONCLUSIVE) | `wp06-lifecycle.mjs` | 0 | **PASS** | V-06 PASS-ветка недостижима |
| **L-05** | повторный reconcile терминального → чтение, тот же verdict, 0 новых | есть | `wp06-lifecycle.mjs` | 0 | **PASS** | — |
| **B-02** | второй старт на тот же fixture → отказ привязки, POST=1 | есть | `wp06-lifecycle.mjs` | 0 | **PASS** | — |

**Итог по 10 TODO:** 7 PASS (V-05, V-10*, V-12, L-02, L-04, L-05, B-02), 1 PASS-механизм/E2E NOT RUN (L-01), 2 FAIL (E-04, V-06). V-10 PASS не означает закрытия R-07.

## 9. P/A-строки (для полноты, вне 34 E/V/L/B)

| ID | Статус | Основание |
|---|---|---|
| P-01…P-05 | PASS (P-02 см. оговорку P0) | npm test, T-01, wp0102, trust-anchor |
| A-01…A-12 | PASS | trust-integration, trust-policy, trust-approval, trust-identity, wp0102, wp05, wp06 |
