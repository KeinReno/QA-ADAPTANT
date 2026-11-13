# KAIDEN QA ADAPTANT 0.2 — baseline и замороженные контракты Harness

Документ создан Lead-оркестратором на первой волне миссии 0.2. Он фиксирует **фактическую** базу,
общие интерфейсы новых модулей и правила, по которым субагенты сдают пакеты.
Он не является приёмкой и не расширяет WP-00.

## 1. Зафиксированная база

| Параметр | Значение |
|---|---|
| Исходная ревизия для новой разработки | `0e7e6c20f7a839ffe16047fa11006b1a9ab6cd31` |
| Ветка базы | `feat/qa-adaptant-02-trust-foundation` (PR #1) |
| Stable 0.1 | тег `v0.1.0-stable` = `88fc1d7b46e898b9d1ac85996042798fe55a2619` |
| WP-01 Identity | `2beff571f733028ff85ff241b70a756894862f34` |
| WP-02 Approval | `0e7e6c20f7a839ffe16047fa11006b1a9ab6cd31` |
| Окружение | Windows, Node.js v24.16.0, npm 11.13.0, git 2.55.0 |
| Локальные незакоммиченные правки пользователя | `README.md`, `ACCEPTANCE-REPORT.md`, `docs/ci-test-mode.md` — **не трогать, не коммитить, не перезаписывать** |

### 1.1. Независимо подтверждённый baseline (Lead, 13.11.2026)

| Команда | Результат Lead | Отчёт Grok | Совпадение |
|---|---|---|---|
| `npm test` | 78/78 passed, 0 failed, exit 0, ~115 s | 78/78 | да |
| `npm run test:races` | 3/3 passed, exit 0, ~27 s | 3/3 | да |
| `npm run schemas` | exit 0, диффа схем нет | exit 0 | да |

Примечание по среде: тестовый набор запускает дочерние процессы через piped stdio. В confined-режиме
DSH-песочницы это даёт `spawn EPERM`; прогоны выполняются в режиме полного доступа. Это свойство
инструмента, а не дефект проекта. Числа выше получены реальным прогоном, а не перенесены из отчёта.

Полный `npm test` — самый дорогой шаг (~2 мин, Chromium). Его не запускают параллельно два агента.

## 2. Фактическая карта ядра 0.1 (по коду, а не по документам)

| Узел | Файл | Факт |
|---|---|---|
| Создание прогона | `apps/control/run.mjs` `run()` | Снимки, lease, fixture-bind, GET `/environment`, Browser, INTENT→ACK, POST, Verification |
| Владелец состояния | `RunStore` (`packages/core/store.mjs`) | снапшоты, `events.jsonl`, `evidence.jsonl`, `evidence-commits/NNNNNN.json` |
| Запись intent | `run.mjs`, обработчик `INTENT` | `store.appendEvidence(kind='mutation-intent')` **до** ACK |
| ACK | тот же обработчик | `IntentAck`, повтор идентичного intent возвращает сохранённый ACK |
| POST | `apps/browser/worker.mjs` | только после `EVIDENCE_ACK`, один POST на allowlist |
| Запрет повтора мутации | `store.#assertTailShape` + `run.mjs` | второй `request` / `verdict` запрещён на уровне журнала |
| Бизнес-проверка | `apps/verification/worker.mjs` | собственный GET, `redirect: error`, сверка fingerprint |
| Terminal verdict | `run.mjs` `persistVerdict` / `verifyAndPersist` | ровно один `kind='verdict'` |
| Evidence | `RunStore` | хвост подтверждается коммитом; анкер в каталоге прогона не пишется |
| Recovery | `adoptExisting`, `reconcile`, `terminalResult` | без повторного POST |
| Точки Trust | T-A, T-B, T-C, T-D, T-E, T-F | см. `docs/wp-00/01-CURRENT-STATE-MAP.md` |

Ключевые факты, на которых строятся новые пакеты:

1. **Цепочка evidence**: голова = `{sequence, envelopeSha256: digest(envelope)}` последнего элемента `store.readEvidence(runDir)`.
2. **Артефакт evidence**: файл `runDir/evidence/NNNNNN-kind.json` содержит `canonical(value) + '\n'`; `envelope.artifact.sha256 = digest(bytes)` (с переводом строки).
3. **Канонический хеш объекта**: `digest(obj) = sha256(canonical(obj))` без перевода строки. Все новые `*Sha256` в 0.2 считаются так.
4. `store.appendEvidence` после терминального `verdict` бросает `INTEGRITY_ERROR`. Любой дополнительный `kind` evidence меняет замороженную схему → **запрещён**.
5. `serveLocalFixture()` возвращает `{baseUrl, environmentId, fingerprint, authToken, mutationCount, readCount, recordCount, close}`.
6. `localBundle()` собирает bundle 0.1; для доверенного прогона он не меняется.

## 3. Что запрещено менять всем пакетам

- `packages/contracts/`, `schemas/`, `docs/contract-freeze.json` — заморожены.
- `packages/core/store.mjs`, `canonical.mjs`, `evidence-policy.mjs`, `bundle.mjs`, `approved-registry.mjs` — инварианты 0.1.
- `packages/trust/identity.mjs` и `approval.mjs` — принятая ревизия WP-01/WP-02. Только минимальное исправление реального дефекта с регрессией и отдельным коммитом.
- `apps/control/run.mjs` — **только Lead в WP-06**. Никакой субагент его не правит.
- `apps/browser/worker.mjs`, `apps/verification/worker.mjs` — менять нельзя. Точка T-C реализуется в Control (см. §6).
- Старые тесты 0.1 (`tests/runtime`, `contracts`, `faults`, `lifecycle`, `audit-wp`, `evidence-readers`, `review-grok`) не редактируются ради зелёного результата.
- Запрещено: merge в `main`, force push, reset чужого worktree, подключение ЦИЗ/Dev, запись секретов в репозиторий.

## 4. Организация Git (обязательна)

Рабочие каталоги: `C:\Users\gvi\Desktop\QA-ADAPTANT-harness\<dir>`, `node_modules` — junction на корневой.

| Каталог | Ветка | Владелец |
|---|---|---|
| `wp04` | `feat/adaptant-02-wp04-environment` | Agent A |
| `wp05` | `feat/adaptant-02-wp05-anchor` | Agent B |
| `wp03` | `feat/adaptant-02-wp03-policy` | Agent C |
| `redteam` | `test/adaptant-02-trust-verification` | Agent D |
| `integration` | `feat/adaptant-02-trust-integration` | Lead |

Правила: работать только в своём worktree; коммиты атомарные с осмысленным сообщением на русском;
в отчёте пакета указывать точный `git rev-parse HEAD`; чужую ветку не мержить; интеграцию делает Lead.

## 5. Новые модули 0.2 — замороженные интерфейсы

Общее: `schemaVersion = '0.2.0'`, канонизация — `packages/core/canonical.mjs`, подпись Ed25519 через
`signTrustedDocument`/`verifyTrustedDocument` (`packages/trust/identity.mjs`), домены `domain`
проверяются по таблице `docs/wp-00/02-TRUST-ARCHITECTURE.md`. Неизвестное поле отвергается.

### 5.1. `packages/trust/environment.mjs` (WP-04, Agent A)

Запись реестра сред (`domain='environment-record'`, подпись owner) — точный набор полей:
`schemaVersion, domain, environmentId, generation, kind, status, origin, standKeyId, credentialRef, keyId, signature, signatureAlgorithm`.
`kind ∈ {local-stand, dev, production}`, `status ∈ {active, disabled, revoked}`, `generation` — целое ≥ 1.
`origin` для `local-stand` строго `http://127.0.0.1:<port>/`. `fingerprint` и nonce в запись **не входят**.

Аттестация стенда (`domain='environment-attest'`, подпись ключа стенда):
`schemaVersion, domain, environmentId, generation, origin, pid, challenge, keyId, signature, signatureAlgorithm`.
`challenge` — 32 случайных байта hex, новый на каждую проверку. `keyId === standKeyId`.

Обязательные экспорты:

```js
export function createStandKeys()                       // → {standKeyId, publicKey, privateKey}; ключ только в памяти
export function newChallenge()                          // → 64 hex
export function signEnvironmentRecord(ownerPrivateKey, fields)   // → подписанная запись (без записи на диск)
export function commitEnvironmentRecord(trust, trustRoot, record) // CREATE_NEW trustRoot/environments/<environmentId>.json
export function loadEnvironmentRecord(trust, trustRoot, environmentId) // → body; коды ENVIRONMENT_UNKNOWN / ENVIRONMENT_REVOKED
export function verifyEnvironmentRecord(trust, record)  // → body
export function signEnvironmentAttestation(standPrivateKey, fields) // fields: {environmentId, generation, origin, pid, challenge}
export function verifyEnvironmentAttestation(trust, record, attestation, {challenge}) // → body
export function attestEnvironment({record, trust, challenge, fetchImpl, timeoutMs})   // POST origin + 'attest'
export async function attestLiveEnvironment({trust, record, fetchImpl, timeoutMs})    // attest + проверка pid + порта
export function processAlive(pid)                       // → boolean
export async function portOwnerPid(origin)              // → number|null (владелец слушающего сокета)
export const DEFAULT_ATTEST_TIMEOUT_MS = 2000;
```

Коды ошибок: `ENVIRONMENT_UNKNOWN`, `ENVIRONMENT_REVOKED`, `ENVIRONMENT_KIND_DENIED`, `ENVIRONMENT_ATTESTATION_FAILED`, `ENVIRONMENT_UNAVAILABLE`, `CONTRACT_INVALID`.

Расширение локального стенда (аддитивное, старый контракт сохраняется):
`POST /attest` с телом `{challenge}` → `200` + подписанная аттестация (или `400`);
`GET /environment` не меняется; `serveLocalFixture()` дополнительно возвращает
`standKeyId, standPublicKey, pid, generation`. Редиректы не выпускаются. Ключ стенда только в памяти.

Владеет файлами: `packages/trust/environment.mjs`, `adapters/local/server.mjs`, `adapters/local/bundle.mjs`, `tests/trust-environment.test.mjs`, `docs/harness/WP-04-REPORT.md`.

### 5.2. `packages/trust/anchor.mjs` и `packages/trust/anchor-signer.mjs` (WP-05, Agent B)

Кандидат — **ровно** объект `VerdictPolicy` 0.1, без дополнительных полей:
`schemaVersion, runId, manifestSha256, verdict, reasonCode, message, checks, ownershipVerified, integrityVerified, completedAt`.
`candidateSha256 = digest(candidate)`. Ссылки на анкер в кандидате нет.

Раскладка в каталоге прогона:
- `runDir/trust/candidate.json` = `canonical(candidate) + '\n'`, `CREATE_NEW` + `fsync` + повторное чтение.
- `runDir/trust/terminal-choice.json`, `CREATE_NEW`, поля: `schemaVersion, domain('terminal-choice'), outcome ∈ {anchor, budget-inconclusive, fail-without-anchor}, candidateSha256, discardedCandidateSha256|null, anchorId|null, createdAt`.
- `runDir/trust/decision.json` — `TrustDecision` (пишет WP-06).

Заявление анкера (`domain='anchor-statement'`, подпись anchor-signer):
`schemaVersion, domain, anchorId, runId, manifestSha256, chainHead:{sequence,envelopeSha256}, candidateSha256, verdict, reasonCode, approvalId, inputsHash, environmentId, environmentGeneration, publishedAt, keyId, signature, signatureAlgorithm`.
Хранится в `trustRoot/anchors/<anchorId>.json` (`CREATE_NEW`).

Обязательные экспорты `anchor.mjs`:

```js
export const DEFAULT_ANCHOR_BUDGET_MS = 5000;
export function buildCandidate({frozen, verdict, reasonCode, message, checks, completedAt}) // → объект VerdictPolicy
export function publishCandidate(runDir, candidate)   // → {candidateSha256}; CREATE_NEW + fsync + сверка
export function readCandidate(runDir)                 // → {candidate, candidateSha256} | null
export function evidenceChainHead(store, runDir)      // → {sequence, envelopeSha256} | null
export function publishTerminalChoice(runDir, choice) // CREATE_NEW; при EEXIST → читает существующий
export function readTerminalChoice(runDir)
export function publishTerminalVerdict({store, runDir, frozen}) // ровно один verdict, байты = выбранному кандидату
export function verifyAnchorStatement(trust, statement)         // → body
export function loadAnchor(trustRoot, anchorId)                 // → statement
export function publicationState({store, runDir, trust, trustRoot}) // collecting|candidate-ready|anchor-held|terminal|inconsistent
export function observeTrustedVerdict({store, runDir, frozen, trust, trustRoot}) // PASS только при полной связке
```

`anchor-signer.mjs`: `startAnchorSigner({trustRoot, secretsDir, pipePath})` → `{pipePath, close}`, локальный
канал (named pipe) `\\.\pipe\qa-adaptant-anchor-<hex>`; протокол — строки JSON.
`connectAnchorSigner(pipePath)` → `{sign({runDir, approvalId, anchorId}), close}`.
Подписант **сам** читает trust root, approval, consumption, снапшоты, журнал и кандидат и подписывает только
при полной связке; иначе `ANCHOR_BINDING_REJECTED`. Подписант не подписывает ничего, кроме `anchor-statement`,
и не принимает хеш кандидата от вызывающего.

Владеет файлами: `packages/trust/anchor.mjs`, `packages/trust/anchor-signer.mjs`, `tests/trust-anchor.test.mjs`, `docs/harness/WP-05-REPORT.md`.

### 5.3. `packages/trust/policy.mjs` (WP-03, Agent C)

`decide(facts) → TrustDecision`. Чистая функция: без сети, диска, криптографии, записи consumption и
генерации ключей. Не бросает на корректной форме `facts`.

`TrustDecision`: `{decisionId, effect ∈ {ALLOW,DENY,INDETERMINATE}, phase, reasonCode, approvalId, inputsHash, environmentId, environmentGeneration, authenticatedSid, obligations ∈ {consume-dispatch, do-not-dispatch}, evaluatedAt}`.

Форма `facts` (заморожена; сборщик в WP-06):

```js
{
  phase,                      // 'preflight'|'dispatch'|'observe'|'reconcile'|'publish'
  now,                        // ISO-8601
  authenticatedSid,           // string|null
  trustStore: { available, code },                     // code: null|'TRUST_STORE_UNAVAILABLE'
  principal: { body, error },                          // субъект (owner/operator), как прочитан из trust root
  issuer: { body, error },
  approval: { body, state, error, consumption, revocation }, // state: issued|consumed|revoked|expired|not-yet-valid|incomplete|missing
  expected: { operation, inputs, effects, scenarioContentSha256, fixtureId, environmentId, environmentGeneration, resource:{method,path} },
  environment: { record, error, attestation: { ok, body, error } },
  run: { runId, canceled, mutationRecorded },
  registry: { operationAllowed, effectsMatch }
}
```

Приоритет правил (первое совпадение): недоступный trust root → INDETERMINATE; неизвестный/отозванный principal;
несовпадение SID → `CALLER_UNAUTHENTICATED`; запрещённая роль → `ROLE_DENIED`; операция вне реестра → DENY
`CONTRACT_INVALID`; approval отсутствует/подпись/связка/срок/отзыв/повтор/расход → соответствующий код;
неизвестная/отозванная/чужой вид среды → соответствующий код; провал аттестации → `ENVIRONMENT_ATTESTATION_FAILED`;
иначе ALLOW `TRUST_OK` с `consume-dispatch` для `dispatch` и `do-not-dispatch` для чтения.

Владеет файлами: `packages/trust/policy.mjs`, `tests/trust-policy.test.mjs`, `docs/harness/WP-03-REPORT.md`.

### 5.4. WP-06 (Lead)

`apps/control/run.mjs` + новый `apps/control/trusted.mjs`, `packages/trust/facts.mjs`,
`packages/trust/windows-sid.mjs`, `apps/control/cli.mjs`, `tests/trust-integration.test.mjs`.

## 6. Точки врезки (T-A…T-E) и инварианты доверенного прогона

| Точка | Где | Требование |
|---|---|---|
| T-A | `run()` после заморозки снимка, **до** `spawnWorker(browser)` | DENY → `BLOCKED`, Chromium не запущен, секрет не выдан |
| T-B | обработчик `INTENT`, **до** `appendEvidence('mutation-intent')` | `consumeDispatch` + свежая аттестация + `decide(dispatch)`; без ALLOW ACK нет |
| T-C | обработчик `HTTP_REQUEST`, до `EVIDENCE_ACK` | дескриптор процесса стенда ещё жив, иначе POST не подтверждается |
| T-D | публикация verdict | сначала candidate, затем `terminal-choice`, затем ровно один verdict |
| T-E | `observeTrusted` / `reconcileTrusted` | чтение не расходует; PASS только при полной связке; второй dispatch запрещён |

Защищаемые инварианты (нарушение = REJECT, даже если остальное зелёное):
1. Ни одного второго POST бизнес-мутации.
2. Ни одного PASS без годного анкера.
3. Ни одного второго терминального verdict.
4. Расход approval не возвращается после падения.
5. `start()` (старый вход) не принимает approval/trust root/адаптер и не выпускает доверенный PASS.
6. Схемы 0.1 и 78 принятых тестов не меняются.
7. Секреты (owner.key, anchor.key, stand key, Bearer) не попадают в снапшоты, evidence, события и отчёты.

## 7. Матрица зависимостей и волны

```text
волна 1: WP-04 (env) ‖ WP-05 (anchor) ‖ WP-03 контракты и таблица тестов ‖ Red Team по базе
волна 2: WP-03 реализация (после env-контракта) ‖ локальные исправления WP-04/05
волна 3: WP-06 интеграция (Lead) + сквозной доверенный прогон
волна 4: WP-07 полная матрица, R-01/R-02, исправления
волна 5: финальный SHA, пакет доказательств, READY/NOT READY
```

Пока зависимость не готова, зависимую работу не начинать; независимые пакеты продолжать.

## 8. Известные риски, перенесённые в WP-07

| ID | Риск | Требование |
|---|---|---|
| R-01 | `guards/<approvalId>.lock` остаётся после аварийного завершения; последующие отзыв/расход падают через 5 с | fail-closed сохранить; проверить отсутствие второго ACK/POST; безопасное восстановление не вводить без доказательства |
| R-02 | `packages/trust/keygen.mjs` не проверяет каталоги прогонов, если `runDir` не передан | закрыть минимальным изменением: закрепить безопасные корневые каталоги |
| R-03 | Остаточная TOCTOU-гонка гибели стенда между проверкой pid и `route.continue` | зафиксировать как остаточный риск, не «лечить» повтором POST |
| R-04 | DPAPI/ACL одного SID не изолируют Control от произвольного кода той же учётной записи | явно писать в отчётах как границу локальной 0.2 |

## 9. Правила сдачи пакета (обязательны для каждого агента)

1. **Contract review до кода**: какие интерфейсы, какие коды ошибок, что тестируется — записать в отчёт пакета.
2. Код в своей ветке, владение файлами строго по §5.
3. Тесты пакета + `node --test tests/trust-*.test.mjs` и явный перечень команд с фактическим exit code.
4. Отчёт `docs/harness/WP-XX-REPORT.md`: изменение файлов, команды, фактический результат, новые риски, ограничения, `git rev-parse HEAD`.
5. Не принимать собственный результат: пакет уходит на независимое внутреннее ревью (другой субагент или Lead).
6. Дефект → минимальное исправление + воспроизводимая регрессия.
7. Запрещено писать «всё работает» без вывода команд; HTTP 200 и слова модели не являются доказательством.

## 10. Что Lead делает дальше

1. Создаёт субагентов A/B/C/D по §4.
2. Собирает WP-06 и прогоняет сквозной доверенный сценарий на живом локальном стенде.
3. Ведёт `docs/harness/HARNESS-STATUS.md`, сшивает ветки по проверенным SHA.
4. Готовит WP-07 и пакет доказательств; статус `READY FOR EXTERNAL REVIEW` даёт только при выполнении §17 миссии.
