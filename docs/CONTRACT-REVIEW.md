# Независимый review контрактов 0.1

Решение Luna, повторный review: **ACCEPT для заморозки контрактного слоя 0.1 и начала локальной вертикали WP-01/02.** Проверены исправления по пяти прежним направлениям и P1 guard для FAIL. Runtime отсутствует; тесты контракта не аудировались, их исполнение не является частью этого gate.

Область ядра по запросу: одна мутация на контролируемом localhost fixture и независимый verification worker; линейный сценарий. 1.0 остаётся отдельным объёмом работ.

## Закрытие предыдущего P1

The earlier payload (`FAIL`, one `VIOLATED` check, empty evidence) is now rejected by `VerdictPolicy` (`packages/contracts/index.mjs:136–140`). `validateVerdictCoverage()` requires an independent read for both SATISFIED and VIOLATED, with exact `equals`/`not-equals` semantics (`:173–192`).

## Снятые блокеры и оставшиеся наблюдения

- Закрыто в обновлении: сценарий требует ровно один click mutation=true, запрещает прочие clicks, связывает click operationId/name; `validateBundleLinks()` проверяет operation/fixture/run/environment, роли, inputs и ownership (`packages/contracts/index.mjs:110–123,159–169`; `SCENARIO-SCHEMA.md:9`).
- Закрыто в обновлении: `validateVerdictCoverage()` требует exact набора effect IDs и связывает SATISFIED/VIOLATED с точным независимым read (`packages/contracts/index.mjs:173–192`); VerdictPolicy требует proof для FAIL (`:136–140`). Evidence имеет producer-kind matrix, checkIds и форму IndependentRead (`:74–84,128–135`; `EVIDENCE-SCHEMA.md:11`).
- Закрыто в обновлении: manifest URL ограничен `http://127.0.0.1:<port>/`; network policy ограничивает adapter, origins, methods и redirects (`packages/contracts/index.mjs:124–127`; `RUN-PROTOCOL.md:13`). `environment.id` — случайная identity/nonce harness instance, привязанная к fixture и durable manifest (`RUN-PROTOCOL.md:15`).
- Закрыто в обновлении: экспортированы IntentCommand/Ack; идентичный повтор intent возвращает сохранённый ACK, иной payload для того же intentId отклоняется, потеря ACK/crash ведут к no-click и reconcile (`packages/contracts/index.mjs:144–148`; `MODULE-BOUNDARIES.md:20`).
- Набор Zod schemas строгий по неизвестным полям, но междокументные hash/reference checks остаются задачей runtime/verifier (`ARCHITECTURE.md:15`); implementers должны соблюдать это разделение.
- `OperationContract` явно требует безусловную проверку и ограничивает polling (`packages/contracts/index.mjs:22–31,104–108`); UNKNOWN/NOT_APPLICABLE semantics описаны в `OPERATION-CONTRACT.md:3–7` и `VERDICT-POLICY.md:7–12`.
- Scenario линейность, ровно один mutating click и завершающий verify проверяются (`packages/contracts/index.mjs:109–117`), что соответствует узкому ядру; DAG и полный 1.0 обоснованно отложены (`SCENARIO-SCHEMA.md:7`).
- Versioned scenario, explicit approval/hash, immutable run snapshots и запрет retries заданы в прозе и схеме (`SCENARIO-SCHEMA.md:3–5`, `RUN-PROTOCOL.md:3–11`). Контрактные validators не должны подменять самостоятельную проверку этих hashes.
- В `VERDICT-POLICY.md:12` уже правильно предписан INCONCLUSIVE, если VIOLATED соседствует с UNKNOWN, а отсутствие входа не считать NOT_APPLICABLE.

## Требуемое решение для повторного gate

Контрактный gate принят для узкого localhost scope. Acceptance runtime остаётся отдельным: нужны фактические прогоны local browser, worker separation, durable recovery, fault matrix и evidence/verdict checks. Этот review не означает Dev/CIZ acceptance и не заменяет независимый review реализации.
