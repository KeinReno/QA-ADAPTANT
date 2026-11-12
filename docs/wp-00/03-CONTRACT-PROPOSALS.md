# 03 — предлагаемые контракты 0.2

Статус: предложение. В `packages/contracts` версии 0.1 эти объекты не добавляются. После утверждения WP-00 они описываются в новом `packages/trust` и проверяются своими тестами. `npm run schemas` для файлов 0.1 обязан остаться без diff.

Общая версия новых объектов: `schemaVersion = "0.2.0"`. Идентификатор — строка 1…160, как в 0.1. Хеш — 64 шестнадцатеричных символа в нижнем регистре. Время — ISO-8601 UTC. Неизвестное поле отвергается.

Каноническая подпись считается функцией `digest` от объекта без `signature` и `signatureAlgorithm`. Алгоритм подписи только `Ed25519`. `keyId` — SHA-256 сырого публичного ключа.

## Principal

Нужен.

| Поле | Зачем |
|---|---|
| `principalId` | Стабильное имя. Для владельца фиксируется при создании корня |
| `roles` | Непустой подмножество `owner`, `operator`, `runner`, `verifier`, `agent` |
| `keyId` | Связь с публичным ключом. У `runner`, `verifier` и `agent` ключа подписи нет, поле `null` |
| `status` | `active`, `revoked` |

`displayName` не входит в проверку допуска и в 0.2 не нужен.

Один Principal не совмещает `owner` и `runner`. Процесс Control — всегда `runner`. Человек-владелец — `owner`. Если человек ещё и запускает прогон, у него может быть вторая запись `operator` без права подписи approval. Совмещение `owner` и `operator` на одной записи допускается только вместе с правилом двух актов: подпись approval и вызов `startTrusted` разделяются по времени, подпись не встроена в вызов старта.

## EnvironmentRecord

| Поле | Зачем |
|---|---|
| `environmentId` | Стабильный идентификатор, не порт и не fingerprint |
| `generation` | Целое от 1. Меняется при смене origin, nonce или статуса |
| `kind` | `local-stand`, `dev`, `production` |
| `status` | `active`, `disabled`, `revoked` |
| `origin` | Точный URL. Для local-stand только `http://127.0.0.1:<порт>` |
| `attestationNonceSha256` | Хеш nonce. Сам nonce в запись, которая может лежать рядом с журналами, не кладётся; сверяется в памяти при опросе стенда |
| `credentialRef` | Ссылка, не секрет. Пусто, если мутация этой среды секрет не использует |
| `signature`, `signatureAlgorithm`, `keyId` | Подпись owner |

Поле `fingerprint` в этот контракт не входит. Существующее поле манифеста 0.1 для старого входа сохраняется и доверенным доказательством не считается.

Для 0.2 PDP разрешает `dispatch` только если `kind=local-stand`, `status=active`, поколение совпало с живым ответом и хеш nonce совпал.

## Approval

Подписанное тело:

| Поле | Решение |
|---|---|
| `approvalId` | Нужен. Уникален в trust root |
| `schemaVersion` | `0.2.0` |
| `issuerPrincipalId` | Только Principal с ролью `owner` и `status=active` |
| `subjectPrincipalId` | Кто имеет право вызвать старт. `owner` или `operator` |
| `operationId`, `operationVersion` | Нужны. Подмена операции ломает подпись |
| `scenarioContentSha256` | Существующий `scenarioApprovalHash`. Связывает сценарий 0.1 без нового поля внутри него |
| `operationSha256` | `digest` замороженной операции |
| `approvedInputsHash` | `digest` объекта входов. Подмена любого значения меняет хеш |
| `fixtureId` | Нужен. Разрешение нельзя перенести на другой маркер владения |
| `targetEnvironmentId`, `environmentGeneration` | Нужны |
| `targetResource` | `{method, path}`. Для локального стенда `POST` и `/records` |
| `allowedEffects` | Список `{id, field, equals}` в подписанном порядке массива. Должен совпасть с эффектами операции |
| `issuedAt`, `expiresAt` | Нужны. `expiresAt` не позже `issuedAt` + 15 минут |
| `approvalNonce` | 32 байта hex. Делает два одинаковых по смыслу разрешения разными объектами |
| `signature`, `signatureAlgorithm`, `keyId` | Нужны |

Не входят в подписанное тело и не являются полями approval:

| Поле из черновика задачи | Почему лишнее |
|---|---|
| `manifestHash` полного RunProtocol | В манифесте есть `runId` и `createdAt`, их ещё нет в момент подписи |
| `runId` | Связывается один раз в consumption, иначе человек вынужден утверждать идентификатор, который выбирает процесс |
| `approvalStatus` | Меняется отзывом и расходом. Статус в подписанном теле нельзя отозвать без новой подписи |
| `approvalScope` отдельной строкой | Граница уже задана операцией, fixture, средой, ресурсом и эффектами |
| `allowedEffects` как свободный текст | Только машинный список id/field/equals |

Состояние approval вычисляется, а не хранится внутри подписи:

| Состояние | Условие |
|---|---|
| `issued` | Подпись верна, отзыва нет, срок не прошёл, consumption нет |
| `consumed` | Есть consumption на один `runId` |
| `revoked` | Есть верная подпись отзыва |
| `expired` | `now >= expiresAt` и расхода ещё не было |

После `consumed` наступление `expiresAt` не переводит запись в `expired` для чтения. Для нового `dispatch` запись уже непригодна в любом случае.

## Revocation

`approvalId`, `revokedAt`, `reason` из закрытого списка `owner-revoked`, `environment-revoked`, `principal-revoked`, подпись owner. Отзыв не удаляет файл approval.

## Consumption

`approvalId`, `runId`, `decisionId`, `inputsHash`, `environmentGeneration`, `consumedAt`. Файл создаётся эксклюзивно. В подписи owner не нуждается: это локальный факт исполнителя, а подлинность разрешения проверяется по approval. Подмена consumption без ключа может только запретить мутацию, потому что чужой `runId` не совпадёт с повторным стартом, а отсутствие файла не создаёт PASS. Удаление consumption после успешного прогона ловится анкером: анкер содержит `approvalId` и `runId`, OBSERVE требует совпадения с consumption.

## TrustDecision

| Поле | Значение |
|---|---|
| `decisionId` | Новый идентификатор каждого вызова PDP |
| `effect` | `ALLOW`, `DENY`, `INDETERMINATE` |
| `phase` | `preflight`, `dispatch`, `observe`, `reconcile`, `anchor` |
| `reasonCode` | Код из таблицы ниже |
| `approvalId` | Или `null`, если документа нет |
| `inputsHash` | Хеш фактически замороженных входов |
| `environmentId`, `environmentGeneration` | Что проверялось |
| `obligations` | `consume-dispatch` или `do-not-dispatch` |
| `evaluatedAt` | Время вычисления |

Решение не подменяет `VerdictPolicy`. Оно лежит в `runDir/trust/decision.json` доверенного прогона. В цепочку evidence 0.1 новый `kind` не добавляется: иначе меняется замороженная схема. Связь с прогоном держится через `runId` внутри анкера и через сверку хеша входов со снимком.

## Коды TrustDecision

| Код | Когда |
|---|---|
| `TRUST_OK` | ALLOW |
| `PRINCIPAL_UNKNOWN` | Нет записи или ключ не тот |
| `PRINCIPAL_REVOKED` | Principal отозван |
| `ROLE_DENIED` | Роль не позволяет действие |
| `APPROVAL_MISSING` | Нет документа |
| `APPROVAL_SIGNATURE_INVALID` | Подпись, алгоритм или keyId |
| `APPROVAL_MISMATCH` | Операция, входы, fixture, эффекты, сценарий или ресурс |
| `APPROVAL_EXPIRED` | Срок до расхода |
| `APPROVAL_REVOKED` | Есть отзыв |
| `APPROVAL_REPLAY` | Уже связан с другим `runId` |
| `APPROVAL_CONSUMED` | Повторный dispatch того же права |
| `ENVIRONMENT_UNKNOWN` | Нет записи реестра |
| `ENVIRONMENT_REVOKED` | Статус не `active` |
| `ENVIRONMENT_KIND_DENIED` | Не `local-stand` в выпуске 0.2 |
| `ENVIRONMENT_ATTESTATION_FAILED` | Nonce, origin, редирект, смена поколения |
| `ENVIRONMENT_UNAVAILABLE` | Ответ среды не получен |
| `TRUST_STORE_UNAVAILABLE` | Корень доверия не читается |
| `ANCHOR_MISSING` | Нет заявления |
| `ANCHOR_CONFLICT` | Второе отличное заявление или несовпадение с коммитом |
| `ANCHOR_SIGNATURE_INVALID` | Подпись анкера |
| `RUN_CANCELED` | Отмена до dispatch |
| `MUTATION_ALREADY_RECORDED` | Intent уже есть, новый dispatch не нужен |

## Проекция в verdict 0.1

До записи intent отказ доверенного пути завершается verdict `BLOCKED`. После записи intent неопределённость завершается `INCONCLUSIVE`. PASS не используется как проекция отказа.

| Условие | Verdict 0.1 | reasonCode 0.1 |
|---|---|---|
| Нет ключа, хранилище доверия недоступно, подпись неверна, Principal отозван | `BLOCKED` | `AUTH_UNAVAILABLE` |
| Несовпадение approval, роли, повтор, просрочка, вид среды | `BLOCKED` | `CONTRACT_INVALID` |
| Среда не подтвердилась или поколение сменилось до мутации | `BLOCKED` | `ENVIRONMENT_CHANGED` |
| То же после durable intent | `INCONCLUSIVE` | `ENVIRONMENT_CHANGED` |
| Анкер отсутствует или не подписан при готовом бизнес-PASS | `INCONCLUSIVE` | `EVIDENCE_MISSING` |
| Конфликт анкера или подмена коммита | терминальный отказ | `INTEGRITY_ERROR` |
| Отмена до intent | `BLOCKED` | `CANCELED` |
| Отмена после intent | `INCONCLUSIVE` | `CANCELED` |

`AUTH_UNAVAILABLE` уже есть в enum 0.1 и до сих пор не является результатом проверки личности. Для доверенного входа он получает этот смысл. Старый вход `start()` его по-прежнему не производит из-за отсутствия ключа.

## AnchorStatement

`anchorId`, `runId`, `manifestSha256`, `terminalCommit: {sequence, envelopeSha256}`, `verdict`, `reasonCode`, `approvalId`, `inputsHash`, `environmentId`, `environmentGeneration`, `publishedAt`, подпись owner.

`verdict` здесь — уже принятое значение 0.1: `PASS`, `FAIL`, `BLOCKED`, `INCONCLUSIVE`. Анкер не вводит новый вердикт. Для `PASS` заявление обязательно до публикации. Для `FAIL` и `BLOCKED` заявление тоже публикуется, если trust root доступен, но отсутствие анкера у `FAIL` не превращает его в PASS и не скрывает нарушение эффекта. Если анкер `FAIL` записать не удалось, локальный `FAIL` сохраняется, а `observeTrusted` помечает `ANCHOR_MISSING` как дефект доказательства, не как успех. Для `PASS` такой дефект запрещает публикацию PASS.

## Совместимость

- Объекты 0.1 не получают новых полей.
- Отсутствие каталога `runDir/trust/` означает прогон старого входа.
- `startTrusted` на операции вне `local-create-record` в 0.2 возвращает DENY `CONTRACT_INVALID`, пока отдельным изменением не расширен реестр операций. Trust Layer не является способом обойти реестр смыслов эффектов.
- Первое расширение реестра операций — отдельный reviewed change, не часть WP-01…WP-05.
- Ключ, nonce attestation и Bearer не входят ни в один JSON контракт, который пишется в каталог прогона.
