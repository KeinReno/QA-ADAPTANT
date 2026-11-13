# 03 — предлагаемые контракты 0.2

Статус: предложение. В `packages/contracts` версии 0.1 эти объекты не добавляются. После утверждения WP-00 они описываются в новом `packages/trust` и проверяются своими тестами. `npm run schemas` для файлов 0.1 обязан остаться без diff.

Общая версия новых объектов: `schemaVersion = "0.2.0"`. Идентификатор — строка 1…160, как в 0.1. Хеш — 64 шестнадцатеричных символа в нижнем регистре. Время — ISO-8601 UTC. Неизвестное поле отвергается.

Каноническая подпись считается функцией `digest` от объекта без `signature` и `signatureAlgorithm`. Алгоритм подписи только `Ed25519`. `keyId` — SHA-256 сырого публичного ключа. Поле `domain` входит в подписываемые байты. Проверяющий отвергает объект, если `domain` не совпадает с типом объекта или `keyId` не принадлежит ключу, назначенному этому `domain`.

## Principal

Нужен.

| Поле | Зачем |
|---|---|
| `principalId` | Стабильное имя. Для владельца фиксируется при создании корня |
| `roles` | Непустое подмножество `owner`, `operator`, `runner`, `anchor-signer`, `verifier`, `agent` |
| `keyId` | Связь с публичным ключом. У `runner`, `verifier` и `agent` ключа подписи нет, поле `null`. У `anchor-signer` это ключ анкера, не ключ owner |
| `windowsSid` | Обязателен у `operator` и у человека-`owner`, если он же вызывает старт. У `runner` и `anchor-signer` — `null` |
| `status` | `active`, `revoked` |
| `domain` | Буквально `principal` |

`displayName` не входит в проверку допуска и в 0.2 не нужен.

Один Principal не совмещает `owner` и `runner` и не совмещает `owner` и `anchor-signer`. Процесс Control — всегда `runner`. Процесс подписи анкера — всегда `anchor-signer`. Человек-владелец — `owner`. Для локальной 0.2 ему разрешено иметь роль `operator` на той же или второй записи. Подпись approval и вызов `startTrusted` всё равно два действия. Вызов принимается только если SID процесса совпал с `windowsSid`.

## EnvironmentRecord

| Поле | Зачем |
|---|---|
| `domain` | Буквально `environment-record` |
| `environmentId` | Стабильный идентификатор, не порт и не fingerprint |
| `generation` | Целое от 1. Меняется при смене origin, ключа стенда или статуса |
| `kind` | `local-stand`, `dev`, `production` |
| `status` | `active`, `disabled`, `revoked` |
| `origin` | Точный URL. Для local-stand только `http://127.0.0.1:<порт>` |
| `standKeyId` | SHA-256 публичного ключа стенда. Приватный ключ в запись не входит и на диск не пишется |
| `credentialRef` | Ссылка, не секрет. Пусто, если мутация этой среды секрет не использует |
| `signature`, `signatureAlgorithm`, `keyId` | Подпись owner |

Поле `fingerprint` и публичный nonce в этот контракт не входят. Существующее поле манифеста 0.1 для старого входа сохраняется и доверенным доказательством не считается.

Отдельный объект `environment-attest` подписывает ключ стенда. В нём `environmentId`, `generation`, `origin`, PID процесса стенда и challenge, который прислал Control. Challenge — 32 случайных байта на каждую проверку. Старый ответ на тот же challenge отвергается.

Для 0.2 PDP разрешает `dispatch` только если `kind=local-stand`, `status=active`, поколение совпало, подпись свежего challenge сошлась с `standKeyId` и дескриптор процесса стенда ещё жив.

## Approval

Подписанное тело:

| Поле | Решение |
|---|---|
| `approvalId` | Нужен. Уникален в trust root |
| `schemaVersion` | `0.2.0` |
| `domain` | Буквально `approval` |
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
| `issued` | Подпись верна, отзыва нет, `issuedAt <= часы процесса < expiresAt`, consumption нет |
| `consumed` | Есть consumption на один `runId` |
| `revoked` | Есть верная подпись отзыва |
| `expired` | `now >= expiresAt` и расхода ещё не было |

После `consumed` наступление `expiresAt` не переводит запись в `expired` для чтения. Для нового `dispatch` запись уже непригодна в любом случае.

Закрепление: подписанный документ лежит в `trust-root/approvals/<approvalId>.json`. Имя создаётся через `CREATE_NEW`, затем `fsync` и повторное чтение. Повтор того же `approvalId` с другим каноническим содержимым не перезаписывает файл. Расход и будущий anchor-signer читают этот файл сами. `inputsHash` в consumption равен `approvedInputsHash` именно этого документа, а не копии из запроса. На пути расхода часы берутся у процесса: `issuedAt <= сейчас < expiresAt`. Поле `now` запроса срок не сдвигает. Отзыв и расход одного `approvalId` входят в одну секцию: отзыв, уже прочитанный из `revocations/<approvalId>.json` до создания consumption, ACK не открывает.

## Revocation

`approvalId`, `revokedAt`, `reason` из закрытого списка `owner-revoked`, `environment-revoked`, `principal-revoked`, подпись owner. Отзыв не удаляет файл approval.

## Consumption

Поля тела: `approvalId`, `runId`, `decisionId`, `inputsHash`, `environmentGeneration`, `consumedAt`. Рядом лежит `bodySha256` — `digest` канонического тела без самого `bodySha256`. Запись полная только когда файл читается целиком и хеш сходится.

Публикация — `CREATE_NEW` итогового имени `consumption/<approvalId>.json`, затем `fsync` этого дескриптора и повторное чтение. `rename` поверх существующего файла запрещён. `fsync` каталога на Windows не входит в критерий: `EPERM` на нём не считается ни успехом, ни провалом записи. Неполное занятое имя даёт `CONSUMPTION_INCOMPLETE`, не удаляется и не заменяется. Второй процесс с другим `runId` не получает ACK. В подписи owner запись не нуждается. Удаление полного consumption после прогона расходится с анкером на `observeTrusted`.

Испытание WP-02 на Windows, два процесса и один `approvalId`: ровно один полный файл, не больше одного ACK, не больше одной мутации. Обрыв после `CREATE_NEW` и до полного хеша: ноль ACK и отказ перезаписи. Пока этого прогона нет, контракт считается заданным, а не проверенным.

## TrustDecision

| Поле | Значение |
|---|---|
| `decisionId` | Новый идентификатор каждого вызова PDP |
| `effect` | `ALLOW`, `DENY`, `INDETERMINATE` |
| `phase` | `preflight`, `dispatch`, `observe`, `reconcile`, `publish` |
| `reasonCode` | Код из таблицы ниже |
| `approvalId` | Или `null`, если документа нет |
| `inputsHash` | Хеш фактически замороженных входов |
| `environmentId`, `environmentGeneration` | Что проверялось |
| `authenticatedSid` | SID, прочитанный у процесса. `null` только для старого входа, который сюда не входит |
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
| `CALLER_UNAUTHENTICATED` | SID вызывающего не совпал с `windowsSid` субъекта. Поле `subjectPrincipalId` при этом может быть верным |
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
| `ENVIRONMENT_ATTESTATION_FAILED` | Подпись challenge, origin, PID, поколение или гибель процесса стенда |
| `ENVIRONMENT_UNAVAILABLE` | Ответ среды не получен |
| `TRUST_STORE_UNAVAILABLE` | Корень доверия не читается |
| `CONSUMPTION_INCOMPLETE` | Итог расхода не читается или не синхронизирован. ACK запрещён |
| `PUBLICATION_PENDING` | Candidate есть, терминального verdict ещё нет. Это не PASS |
| `ANCHOR_MISSING` | Нет заявления там, где выбор исхода уже обязан был его иметь |
| `ANCHOR_BINDING_REJECTED` | Подписант не нашёл связку approval, полного consumption, снимков и candidate |
| `ANCHOR_UNLINKED` | Подпись относится к отброшенному candidate и не выбрана в `terminal-choice.json`. Это не PASS и не конфликт |
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
| Анкер отсутствует к концу бюджета при candidate PASS | один раз `INCONCLUSIVE` | `EVIDENCE_MISSING` |
| Вызывающий SID не совпал | `BLOCKED` | `AUTH_UNAVAILABLE` |
| Нечитаемый consumption до ACK | мутации нет | `AUTH_UNAVAILABLE` |
| Конфликт анкера или подмена коммита | терминальный отказ | `INTEGRITY_ERROR` |
| Отмена до intent | `BLOCKED` | `CANCELED` |
| Отмена после intent | `INCONCLUSIVE` | `CANCELED` |

`AUTH_UNAVAILABLE` уже есть в enum 0.1 и до сих пор не является результатом проверки личности. Для доверенного входа он получает этот смысл. Старый вход `start()` его по-прежнему не производит из-за отсутствия ключа.

## VerdictCandidate и terminal-choice

`VerdictCandidate` равен будущему артефакту `VerdictPolicy`. Поля только эти: `schemaVersion`, `runId`, `manifestSha256`, `verdict`, `reasonCode`, `message`, `checks`, `ownershipVerified`, `integrityVerified`, `completedAt`. `candidateSha256 = digest(candidate)`. Ссылки на анкер в этом объекте нет.

`terminal-choice.json` публикуется через `CREATE_NEW`. Поля: `outcome` (`anchor`, `budget-inconclusive`, `fail-without-anchor`), `candidateSha256` тела, которое станет единственным verdict, `discardedCandidateSha256` или `null`, `anchorId` или `null`. Второй выбор поверх первого не пишется.

Если исход `budget-inconclusive`, в evidence попадает новый candidate с `verdict=INCONCLUSIVE` и `reasonCode=EVIDENCE_MISSING`, а не прежний PASS. Анкер прежнего PASS, появившийся в ту же гонку, остаётся `ANCHOR_UNLINKED`: хеш у него другой, конфликт из этого не делается, переход INCONCLUSIVE → PASS запрещён.

## AnchorStatement

`domain` буквально `anchor-statement`. Поля: `anchorId`, `runId`, `manifestSha256`, `chainHead: {sequence, envelopeSha256}` последнего коммита до verdict, `candidateSha256`, `verdict`, `reasonCode`, `approvalId`, `inputsHash`, `environmentId`, `environmentGeneration`, `publishedAt`. Подпись — ключ anchor-signer. Подпись owner для этого `domain` недействительна.

`candidateSha256` внутри заявления — хеш `VerdictCandidate`, а не хеш заявления и не хеш `terminal-choice`. После записи verdict байты артефакта равны этому candidate. Проверяющий сверяет подпись, `chainHead` с коммитом перед verdict и `digest` артефакта с `candidateSha256`. `anchorId` он берёт из выбора исхода, не из тела verdict.

Подписант выпускает заявление только после своей проверки связки. Канал с ACL пользователя сам по себе право на подпись не даёт. Для локального 0.2 любой процесс этого SID может обратиться к каналу; отказ или подпись определяются связкой, не именем программы. Процесс, который меняет только каталог прогона, годный анкер для подложного PASS не получает. Процесс, который под тем же пользователем читает `owner.key`, в эту модель не входит.

## Совместимость

- Объекты 0.1 не получают новых полей.
- Отсутствие каталога `runDir/trust/` означает прогон старого входа.
- `start()` не принимает `approvalId`, путь trust root и идентификатор адаптера. Эти аргументы дают отказ старого контракта и ноль мутаций вне уже принятого локального стенда.
- `startTrusted` на операции вне `local-create-record` в 0.2 возвращает DENY `CONTRACT_INVALID`, пока отдельным изменением не расширен реестр операций. Trust Layer не является способом обойти реестр смыслов эффектов.
- Первое расширение реестра операций — отдельный reviewed change, не часть WP-01…WP-05.
- Оба приватных ключа, ключ стенда и Bearer не входят ни в один JSON, который пишется в каталог прогона.
