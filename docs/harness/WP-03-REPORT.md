# WP-03 — Policy Engine (чистый PDP): отчёт пакета

Исполнитель: Agent C. Worktree: `C:\\Users\\gvi\\Desktop\\QA-ADAPTANT-harness\\wp03`.
Ветка: `feat/adaptant-02-wp03-policy`, база `0e7e6c20f7a839ffe16047fa11006b1a9ab6cd31`.
Статус: FIX ROUND по внутреннему ревью Agent A (`docs/harness/WP-03-INTERNAL-REVIEW.md`, проверенная
ревизия `fc2a5934e26f43034678ceba8fd12dd90d4e7a9b`, вердикт FIX REQUIRED, безопасных обходов не найдено).
Исправлены D-1…D-5; пакет направлен на повторную проверку Agent A/Lead. Пакет не считается принятым.

## 1. Contract review до кода

Прочитаны: `BASELINE-AND-CONTRACTS.md` §3/§5/§6/§9, `02-TRUST-ARCHITECTURE.md` (раздел Policy и
аутентификация вызывающего), `03-CONTRACT-PROPOSALS.md` (TrustDecision, коды, проекция в verdict 0.1),
`05-IMPLEMENTATION-ROADMAP.md` (WP-03), `06-ACCEPTANCE-MATRIX.md`, код `identity.mjs`, `approval.mjs`,
`acl.mjs`, `keygen.mjs`, `core/canonical.mjs`, `core/approved-registry.mjs`, `packages/contracts/index.mjs`.

Зафиксировано:

- `decide(facts) → TrustDecision` — чистая функция. Форма `facts` и форма `TrustDecision` взяты буквально
  из §5.3, новых полей не добавлено.
- PDP не читает диск и сеть, не проверяет подписи, не пишет consumption, не генерирует ключи,
  не исполняет мутаций и не делает повторного dispatch.
- Допустимые эффекты: `ALLOW`, `DENY`, `INDETERMINATE`. Каждый отказ имеет точный `reasonCode`
  из таблицы `03-CONTRACT-PROPOSALS.md`.
- Операция вне реестра 0.1 — `DENY` `CONTRACT_INVALID` (см. §7, явная фиксация расширения).
- Проекция `TrustDecision` в verdict 0.1 реализована чистой функцией `projectToVerdict(decision)`
  по таблице §«Проекция в verdict 0.1».

Собственных изменений в принятых файлах WP-01/WP-02, `packages/core/*`, `packages/contracts/*`,
`schemas/*`, `apps/*` нет.

## 2. Файлы пакета

| Файл | Действие |
|---|---|
| `packages/trust/policy.mjs` | новый, 419 строк: `decide`, `projectToVerdict`, константы фаз/эффектов/obligations |
| `tests/trust-policy.test.mjs` | новый, 582 строки, 106 tests: table-driven матрица решений, проекция, регрессии D-1…D-5, детерминизм, отсутствие побочных эффектов |
| `docs/harness/WP-03-REPORT.md` | этот отчёт |

## 3. Экспорты policy.mjs

```js
export const PHASES;        // ['preflight','dispatch','observe','reconcile','publish']
export const EFFECTS;       // ['ALLOW','DENY','INDETERMINATE']
export const OBLIGATIONS;   // ['consume-dispatch','do-not-dispatch']
export const APPROVAL_STATES;
export function decide(facts);              // → TrustDecision (11 полей §5.3)
export function projectToVerdict(decision); // → { verdict, reasonCode } | null
```

`TrustDecision` содержит ровно: `decisionId, effect, phase, reasonCode, approvalId, inputsHash,
environmentId, environmentGeneration, authenticatedSid, obligations, evaluatedAt`.
`decisionId` — новый `randomUUID()` на каждый вызов; `evaluatedAt` — `facts.now` (UTC ISO-8601).
`inputsHash = digest(facts.expected.inputs)` (при невозможности — `approval.approvedInputsHash`).
`projectToVerdict` возвращает `null` для `ALLOW`: решение PDP не является verdict.

## 4. Порядок правил (первое совпадение)

1. Некорректная форма `facts` → `DENY` `CONTRACT_INVALID` (не `TypeError`).
2. Недоступный trust root (`available !== true` или `code !== null`) → `INDETERMINATE` `TRUST_STORE_UNAVAILABLE`.
3. Субъект: нет карточки/ошибка → `PRINCIPAL_UNKNOWN`; `status=revoked` → `PRINCIPAL_REVOKED`.
4. SID вызывающего (проверяется раньше роли, §5.3): не прочитан, нет `windowsSid` у оператора,
   не совпал с карточкой → `CALLER_UNAUTHENTICATED`.
5. Роль: запрещённая роль, совмещение `owner+runner` / `owner+anchor-signer` → `ROLE_DENIED`.
6. Реестр операций: операция не разрешена → `CONTRACT_INVALID`; эффекты не совпали с реестром → `APPROVAL_MISMATCH`.
7. Approval: ошибка сборщика фактов → её код; нет документа/состояние `missing` → `APPROVAL_MISSING`.
8. Издатель: нет карточки → `PRINCIPAL_UNKNOWN`; отозван → `PRINCIPAL_REVOKED`; не owner → `ROLE_DENIED`;
   чужой `keyId` → `APPROVAL_SIGNATURE_INVALID`. Затем проверка формы тела approval
   (алгоритм/подпись/keyId → `APPROVAL_SIGNATURE_INVALID`, остальная форма → `CONTRACT_INVALID`).
9. Состояние approval: `incomplete` → `CONSUMPTION_INCOMPLETE`; `revoked` (или отзыв без расхода) →
   `APPROVAL_REVOKED`; `expired` → `APPROVAL_EXPIRED`; `not-yet-valid` → `CONTRACT_INVALID`.
10. Связка с замороженными входами (операция, хеш входов, сценарий, fixture, среда и поколение, эффекты,
    ресурс) → при любом расхождении `APPROVAL_MISMATCH`.
11. Расход: неполный/повреждённый файл, включая отсутствие или несовпадение `bodySha256` →
    `CONSUMPTION_INCOMPLETE`; `consumed` для другого `runId` → `APPROVAL_REPLAY`; повторный dispatch
    того же `runId` → `APPROVAL_CONSUMED`.
12. Прогон (только `preflight`/`dispatch`): отмена → `RUN_CANCELED`; уже записан intent →
    `MUTATION_ALREADY_RECORDED`.
13. Среда: нет записи/чужой `environmentId` → `ENVIRONMENT_UNKNOWN`; не `active` → `ENVIRONMENT_REVOKED`
    (включая чтение); `kind != local-stand` → `ENVIRONMENT_KIND_DENIED`; ошибка сборщика
    `ENVIRONMENT_UNAVAILABLE` → `ENVIRONMENT_UNAVAILABLE`. Неизвестный `environment.attestation.error` →
    `CONTRACT_INVALID` во всех фазах. Для `preflight`/`dispatch`: смена поколения или непрошедшая
    аттестация → `ENVIRONMENT_ATTESTATION_FAILED`.
14. Иначе `ALLOW` `TRUST_OK`; `obligations=consume-dispatch` для `preflight`/`dispatch`,
    `do-not-dispatch` для `observe`/`reconcile`/`publish`.

## 5. Таблица решений, закреплённая тестами

Все строки `tests/trust-policy.test.mjs` — table-driven с явным `effect` + `reasonCode`:

- ALLOW: `preflight`, `dispatch`, `observe`, `reconcile`, `publish` — `TRUST_OK`, obligations по фазе;
  чтение по полному consumption, отзыв после расхода не мешает чтению, отмена после dispatch не мешает чтению.
- Principal: `PRINCIPAL_UNKNOWN` (нет карточки / ошибка), `PRINCIPAL_REVOKED`, `ROLE_DENIED` (роль,
  `owner+runner`, чужой субъект approval, издатель не owner).
- SID: `CALLER_UNAUTHENTICATED` (несовпадение, null, отсутствие `windowsSid`), **до** ROLE_DENIED.
- D-2: revoked/disabled среда → `DENY ENVIRONMENT_REVOKED` и в `observe`/`reconcile`/`publish`
  (решение Lead: в 0.2 отзыв запрещает и доверенное чтение).
- Approval: `APPROVAL_MISSING`, `APPROVAL_SIGNATURE_INVALID` (подпись/алгоритм/keyId/издатель),
  `APPROVAL_EXPIRED`, `APPROVAL_REVOKED`, `APPROVAL_REPLAY`, `APPROVAL_CONSUMED`, `CONSUMPTION_INCOMPLETE`
  (неполный, отсутствующий/повреждённый `bodySha256`, `consumed` без файла, чужой `inputsHash`/поколение),
  `APPROVAL_MISMATCH` (входы, операция, эффекты, сценарий, fixture, ресурс, среда, поколение).
- Реестр: `CONTRACT_INVALID` (операция вне реестра 0.1), `APPROVAL_MISMATCH` (эффекты не из реестра).
- Среда: `ENVIRONMENT_UNKNOWN`, `ENVIRONMENT_REVOKED`, `ENVIRONMENT_KIND_DENIED`,
  `ENVIRONMENT_ATTESTATION_FAILED` (ok=false, поколение, keyId, origin), `ENVIRONMENT_UNAVAILABLE`.
- Неопределённость: `INDETERMINATE` `TRUST_STORE_UNAVAILABLE` (в т.ч. ошибка чтения approval).
- Жизненный цикл: `RUN_CANCELED`, `MUTATION_ALREADY_RECORDED`.
- Форма: `CONTRACT_INVALID` для `null`, `{}`, строк, массива, неизвестной фазы, неверного `now`,
  отсутствующих/лишних полей, чужих кодов ошибок сборщика.
- Детерминизм: одинаковые `facts` → одинаковые effect/reasonCode/поля, разные `decisionId`;
  `facts` не мутируются (`Object.freeze`).
- Побочные эффекты: временный каталог до/после вызова не изменяется; статическая проверка исходника
  запрещает импорты `node:fs/net/http/https/tls/child_process` и вызовы подписи/ключей/записи файлов.
- Attestation: неизвестный `environment.attestation.error` → `CONTRACT_INVALID` во всех фазах,
  включая `observe`/`reconcile`/`publish`; известная ошибка аттестации чтение не блокирует.
- Проекция: 25 строк таблицы (включая trust root до/после intent, среду до/после intent,
  `ENVIRONMENT_REVOKED` до/после intent, отмену до/после intent, конфликт/отсутствие анкера,
  неизвестный код, некорректное решение).

## 6. Команды и фактический результат

Все команды выполнены в `C:\\Users\\gvi\\Desktop\\QA-ADAPTANT-harness\\wp03`.

| Команда | Фактический результат |
|---|---|
| `node --check packages/trust/policy.mjs` | exit 0 |
| `node --test tests/trust-policy.test.mjs` | **106 tests, 106 pass, 0 fail**, exit 0, ~0.29 s |
| `node --test tests/trust-*.test.mjs` | **125 tests, 125 pass, 0 fail**, exit 0, ~13.8 s (106 новых + 19 WP-01/WP-02) |
| `npm run schemas` | exit 0, диффа схем 0.1 нет; `git status` показывает только файлы пакета |

CRLF в новых файлах отсутствует (проверено побайтово), `core.autocrlf=false`; строки LF.

## 7. Явные фиксации и решения по контракту

1. **Операция вне реестра 0.1** → `DENY` `CONTRACT_INVALID` (B-01). Это не расширение PDP:
   реестр операций расширяется только отдельным reviewed change через `docs/changes`, делает Lead.
2. **`preflight`** отнесён к dispatch-пути: требует approval/среду/аттестацию, obligations
   `consume-dispatch`. `observe`/`reconcile`/`publish` — чтение: `do-not-dispatch`.
3. **Чтение** требует действительный approval и известную активную `local-stand` запись среды,
   но не требует живой аттестации и не сверяет поколение с текущим реестром: после перезапуска стенда
   уже связанный прогон остаётся читаемым (P-03), а dispatch после смены поколения — нет.
   `revoked`/`disabled` среда запрещает и чтение — решение Lead по D-2 (формулировку `docs/changes/005`
   Lead приводит в соответствие); регрессии в тестах.
4. **Отзыв после расхода**: состояние `consumed` приоритетнее отзыва; read разрешён, dispatch запрещён
   (`APPROVAL_CONSUMED`). Просрочка после расхода чтение не блокирует.
5. **Криптография**: PDP использует только `digest()` (SHA-256 канонического JSON) для сверки уже
   замороженных байтов. Подписи, ключи и `consumption` не проверяются и не создаются.
   `decisionId` — `randomUUID()` как принятое исключение для нового идентификатора (фиксирует Lead,
   `docs/changes/004`).
6. **Источник SID**: PDP сравнивает `facts.authenticatedSid` (читает PEP из токена процесса)
   с `principal.windowsSid`. Строка `subjectPrincipalId` личностью не считается; поля SID в approval нет.
7. **Форма `facts`** проверяется строго по §5.3, включая отсутствие лишних полей; на некорректной
   форме возвращается `CONTRACT_INVALID`, исключений нет.

## 8. Замечания для WP-06 (сборщик фактов, Lead)

- `principal.body`, `issuer.body` — проверенные карточки Principal (как возвращает
  `verifyAndAssertPrincipal`: с `principalId/roles/keyId/windowsSid/status/domain`).
- `approval.body` — проверенный документ approval; `approval.state` — вычисленное состояние
  (`issued/consumed/revoked/expired/not-yet-valid/incomplete/missing`); `approval.consumption` —
  полное тело расхода **обязательно с сходящимся `bodySha256`** (как в `approval.mjs`; без хеша —
  `CONSUMPTION_INCOMPLETE`); `approval.revocation` — проверенный отзыв или `null`.
- `approval.error`, `principal.error`, `issuer.error`, `environment.error`,
  `environment.attestation.error` — `null` либо строка кода из таблицы 0.2, либо объект с полем `code`.
  Неизвестный код даёт `DENY` `CONTRACT_INVALID` (fail-closed), **во всех фазах**, включая чтение.
- `authenticatedSid` — SID, прочитанный PEP у процесса; PDP проверяет его раньше роли и
  не принимает `subjectPrincipalId` как личность.
- `expected.effects` — **проекция** эффектов операции в список `{id, field, equals}` в подписанном порядке,
  а не `operation.effects` с `required/source/deadlineMs`. Именно так `approval.mjs::assertBindings`
  сравнивает хеш с `allowedEffects`.
- `environment.attestation.body` — проверенная аттестация стенда (`domain=environment-attest`,
  `environmentId/generation/origin/keyId/challenge/pid`); при `ok=true` PDP сверяет заявленные поля
  с записью реестра, саму подпись проверяет сборщик фактов.
- `registry.operationAllowed` — операция входит в `packages/core/approved-registry.mjs`;
  `registry.effectsMatch` — эффекты операции совпадают с реестром смыслов.
- Для проекции в verdict 0.1: `projectToVerdict(decision)` возвращает `null` для `ALLOW`;
  для отказа — `{verdict, reasonCode}`; фаза `dispatch/preflight` считается «до intent»,
  `observe/reconcile/publish` — «после intent».

## 9. Риски и ограничения

| ID | Риск/ограничение | Что делать |
|---|---|---|
| P-01 | Форма `facts` заморожена; при расхождении сборщика WP-06 и PDP решение будет `CONTRACT_INVALID` | сборщик собирать строго по §5.3 и §8 этого отчёта; расхождение — дефект интеграции, не PDP |
| P-02 | PDP не проверяет криптографическую подпись approval/аттестации: это делает сборщик фактов | при ошибке проверки сборщик обязан положить код ошибки в `*.error`; иначе доверие переносится на сборщик |
| P-03 | Чтение не требует живой аттестации (P-03); злоумышленник с доступом к trust root может подменить запись среды | граница локальной 0.2, R-04; для Dev/ЦИЗ не применимо |
| P-04 | `decisionId` случайный (недетерминирован); детерминированы effect/reasonCode и остальные поля | при сверке решений исключать `decisionId` |
| P-05 | Для чтения не сверяется текущее поколение среды с ожидаемым после перезапуска стенда | сознательно: чтение связанного `runId` не зависит от нового стенда; dispatch — сверяется |

## 10. Git

- Исходная реализация и тесты: коммит `00996531ec58eeba54ea75e9abe982eac67a4b66`
  («Добавить чистый PDP WP-03: decide, коды причин и проекция в verdict 0.1»).
- Исправления по ревью Agent A (D-1…D-5): коммит `104ae7c9b4dc05233a45dc7708b4af0232cc3d1c`.
- Отчёт fix round: этот коммит ветки; точный HEAD после него передан Lead в сообщении.
- Ветка не мержилась, force push не выполнялся, чужие файлы и worktree не менялись.

## 11. Раунд исправлений по ревью Agent A (13.11.2026)

Ревью: `docs/harness/WP-03-INTERNAL-REVIEW.md` (Agent A, проверенная ревизия `fc2a593`), вердикт
FIX REQUIRED, безопасных обходов не найдено. Решения Lead приняты и выполнены:

| ID | Решение Lead | Что изменено в policy.mjs / тестах |
|---|---|---|
| **D-1 (MEDIUM)** | SID проверяется раньше роли | Блок аутентификации (нет SID / отсутствие windowsSid у оператора / несовпадение) перенесён до проверок роли; порядок: PRINCIPAL_UNKNOWN/REVOKED → CALLER_UNAUTHENTICATED → ROLE_DENIED. Регрессии: bad SID + `roles:['verifier']`, null SID + bad role, bad SID + `owner+runner` → `CALLER_UNAUTHENTICATED`; отзыв Principal по-прежнему раньше SID |
| **D-2 (MEDIUM)** | PDP остаётся строгим: отзыв/disabled запрещает и чтение в 0.2; `docs/changes/005` формулировку правит Lead | Код не менялся (revoked/disabled уже DENY). Добавлены регрессии: observe/reconcile/publish с `record.status=revoked`/`disabled` и с `environment.error=ENVIRONMENT_REVOKED` → `DENY ENVIRONMENT_REVOKED`, не ALLOW |
| **D-3 (LOW)** | consumption без `bodySha256` не полон | `inspectConsumption` требует наличие и сходимость `bodySha256` (как `approval.mjs`); регрессия observe/reconcile (и dispatch) → `CONSUMPTION_INCOMPLETE` |
| **D-4 (LOW)** | неизвестный `environment.attestation.error` отвергать во всех фазах | Добавлена проверка кода ошибки аттестации на всех фазах; неизвестный код → `CONTRACT_INVALID` в dispatch/preflight/observe/reconcile/publish; известная ошибка аттестации чтение не блокирует |
| **D-5 (LOW)** | `ENVIRONMENT_REVOKED` → `ENVIRONMENT_CHANGED` | Код добавлен в `environmentReasons`; проекция: dispatch/preflight → `BLOCKED ENVIRONMENT_CHANGED`, observe/reconcile/publish → `INCONCLUSIVE ENVIRONMENT_CHANGED`; добавлены строки таблицы проекции и тест на реальных решениях `decide` |

Наблюдения Lead O-1…O-4 (randomUUID как принятое исключение, `projectToVerdict` как разрешённый экспорт
сверх §5.3, строка для WP-06 по `MUTATION_ALREADY_RECORDED`/`APPROVAL_CONSUMED` после intent) фиксируются
Lead в `docs/changes/004`; код проекции для O-3 оставлен по текущей таблице 03 (`BLOCKED CONTRACT_INVALID`),
требование к WP-06 — не публиковать второй терминальный verdict.

Фактические прогоны после исправлений (worktree wp03):

| Команда | Факт |
|---|---|
| `node --test tests/trust-policy.test.mjs` | **106 tests / 106 pass / 0 fail**, exit 0, ~0.29 s |
| `node --test tests/trust-*.test.mjs` | **125 tests / 125 pass / 0 fail**, exit 0, ~13.8 s |
| `npm run schemas` | exit 0, диффа схем 0.1 нет |
| `git status --porcelain` после прогонов | пусто; изменены только `packages/trust/policy.mjs` и `tests/trust-policy.test.mjs` |

Пакет готов к повторной проверке Agent A на SHA `104ae7c9b4dc05233a45dc7708b4af0232cc3d1c` (плюс коммит
этого отчёта).
