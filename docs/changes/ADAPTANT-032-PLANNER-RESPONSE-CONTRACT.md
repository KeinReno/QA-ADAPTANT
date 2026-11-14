# Изменение контракта: durable provenance PlannerResponse для ADAPTANT 0.3.2

Статус: **предложение на независимое review Luna; код не меняет контракт до ACCEPT**  
Scope: MODEL Planner в ADAPTANT 0.3.2. Trust Foundation 0.2, корневые Trust schemas, исходный сценарий из 23 шагов и текущие approval/execution фасады вне scope.

## Причина

Текущий `TaskService.plan()` получает байты `PlannerProvider`, разбирает их и лишь затем передаёт нормализованный черновик в `TaskStore.savePlan()`. Нет durable request intent, отдельного артефакта точного HTTP response body или ссылки на него из `ExecutionPlan`. Поэтому после перезапуска нельзя независимо подтвердить, какие байты backend вернул для конкретного задания и запроса.

## Предлагаемый контракт

### Planner request и provider response

1. Перед сетевым вызовом Orchestrator создаёт криптографически случайный `requestId`, строит семантический `PlannerRequest` и вычисляет `requestSha256` от канонического JSON с SHA-256. Digest охватывает `requestId`, `taskId`, точный исходный запрос (либо его SHA-256), ограниченный host-контекст, `outputSchemaVersion` и лимиты. `AbortSignal` не сериализуется и не хешируется.
2. Orchestrator сохраняет `PLANNER_REQUEST_STARTED` durable event с `requestId`, `requestSha256`, `providerId`, `mode`, временем начала и версией Task, до вызова provider. Для Task допускается только один незакрытый planner request. Только `PLANNER_REQUEST_FINISHED`, `PLANNER_RESPONSE_REJECTED` либо успешный `PLAN_VERSION_CREATED` закрывают request. Timeout/обрыв/ошибка provider записываются как `PLANNER_REQUEST_FINISHED` с bounded reason code и исходом `UNKNOWN`; после recovery повтор inference не выполняется. Владелец может явно запустить новую попытку из BLOCKED с новым requestId.
3. `PlannerProvider.plan()` возвращает строгий `PlannerProviderResponse`, содержащий `requestId`, `providerId`, `configuredModelId` (только значение host config; для MOCK `null`), `mode`, `receivedAt`, content type, точные байты тела backend response и backend response reference, если он есть. Ollama adapter обязан сохранить необработанное тело HTTP response целиком; разбор envelope, извлечение backend-reported `modelId` и `message.content` выполняются только после durable записи этих байтов. Backend-reported modelId записывается в `PLANNER_RESPONSE_VALIDATED`, сверяется с configuredModelId и лишь затем становится `ExecutionPlan.provider.modelId`. Это проверка согласованности, не криптографическая аттестация.
4. Отсутствующий/неподтверждённый model ID, неверный content type, превышение лимита или несоответствие request/provider/config блокируют Task. Никакого fallback или повторного вызова другого provider/model нет. Ошибка, полученная после начала запроса, не стирает `PLANNER_REQUEST_STARTED`.

### PlannerResponse artifact

До JSON parse TaskStore сохраняет в выделенном каталоге Task неизменяемый sidecar и отдельное бинарное тело response. Поле `status` в sidecar — только неизменяемый receipt status `RECEIVED`; parse disposition записывается типизированными append-only событиями с `responseId` и digest, sidecar после publication не меняется. Sidecar содержит:

```text
schemaVersion, responseId, taskId, requestId, requestSha256,
providerId, configuredModelId, mode, receivedAt, contentType,
byteLength, responseSha256, backendReference, status
```

`responseSha256` считается по точным байтам тела backend response, без декодирования/нормализации. `responseId` — уникальная локальная artifact identity; если backend reference отсутствует, так и фиксируется, без утверждения, будто её выдал provider. Sidecar `configuredModelId` означает только локальную настройку, а не подтверждённую идентичность ответа. Фактический `modelId`, полученный из raw response envelope, записывается в `PLANNER_RESPONSE_VALIDATED` лишь после сохранения bytes и парсинга; TaskStore сверяет его с configured model до создания плана. Если фактический ID отсутствует или отличается, response остаётся сохранённым для диагностики, request закрывается как rejected/unknown и Task блокируется. Дополнительно сохраняются exact outbound request body bytes (без auth headers/credentials) либо его явно описанное защищённое представление и digest. Task хранит исходное поручение без изменений; его дублирование не становится новым источником истины. Metadata/bytes immutable; результат разбора хранится только отдельным append-only событием, не изменением sidecar.

### Crash consistency и видимость

1. Для ответа Store создаёт новый случайный staging directory внутри каталога конкретной Task. Записывает body и sidecar во временные файлы с exclusive create, ограниченными правами, flush/fsync обоих файлов и staging directory. После проверки digest/fsync публикует весь каталог одним atomic rename в `planner-responses/<responseId>`. Final directory нельзя перезаписывать.
2. Только после rename Store записывает и fsync'ит `PLANNER_RESPONSE_STORED`. Если процесс упал после rename, но до события, recovery проверяет целостность staging/final data и предшествующий `PLANNER_REQUEST_STARTED`; он либо дописывает ровно одно stored event, либо маркирует Task BLOCKED с integrity error. Ни один не-связанный с durable request артефакт не становится читаемым через публичный Store API.
3. Если процесс упал до rename, оставшийся staging directory не является артефактом; recovery изолирует его, Task блокируется, новый inference автоматически не выполняется.
4. Файл плана пишется атомарно в versioned path, затем `PLAN_VERSION_CREATED` journal event. `getPlan()` и owner approval разрешают только planId/version, присутствующие в проверенной event-chain и указанные текущим Task snapshot. Файл без события — orphan: он не выдаётся, не активируется и не подтверждается.
5. Recovery находит orphan plan file только для текущего незавершённого request. Она проверяет file/schema/hash, связанную response artifact, request digest и повторяет независимую валидацию; при полном совпадении может атомарно завершить единственный `PLAN_VERSION_CREATED` и переход Task по существующему lifecycle. При неполном/противоречивом доказательстве orphan остаётся невидимым, Task становится BLOCKED, без dispatch/approval. Уже committed plan не переписывается.
6. Crash после `PLAN_VERSION_CREATED` восстанавливается из journal/snapshot и не повторяет provider call, plan write или dispatch.

Порядок и проверки:

1. `PLANNER_REQUEST_STARTED` durable event.
2. Вызов ровно одного configured provider.
3. Атомарное сохранение response bytes и sidecar; проверка length/digest; затем `PLANNER_RESPONSE_STORED` event.
4. Только после шага 3 разрешены decode, разбор backend envelope, строгая валидация `PlannerResult` и Plan Draft.
5. Ошибка parse/schema добавляет `PLANNER_RESPONSE_REJECTED` с responseId/digest/reasonCode; исполняемый `ExecutionPlan` не создаётся. Успешная строгая проверка добавляет `PLANNER_RESPONSE_VALIDATED` с responseId/digest.
6. Перед созданием плана TaskStore проверяет единственный active `requestId`, Task/version, `requestSha256`, provider/model/mode и неизменность сохранённого response artifact.
7. `ExecutionPlan` новой версии содержит обязательную ссылку `plannerResponse` с `responseId`, `requestId`, `requestSha256`, `responseSha256` и `byteLength`. Store проверяет ссылку, `PLANNER_RESPONSE_VALIDATED` event и подтверждённый в нём `modelId` перед durable публикацией плана. Сам план продолжает хранить точный validated output и существующую provenance provider/model/mode.
8. Если crash произошёл после `PLANNER_RESPONSE_STORED`, но до decode/parse, recovery выполняет локальную обработку уже сохранённых raw bytes этого responseId; новый inference запрещён. Если текущая версия кода не может обработать/валидировать их, recovery пишет `PLANNER_RESPONSE_REJECTED` либо `PLANNER_REQUEST_FINISHED(UNKNOWN)` и переводит Task в BLOCKED.

Локальные хеши доказывают целостность сохранённых байтов относительно локально записанного digest, но не криптографическую подлинность inference backend.

### Схемы и совместимость

Предлагается отделить `TASK_SCHEMA_VERSION = 0.3.0` от `PLAN_SCHEMA_VERSION = 0.3.1`: Task state/journal envelope остаётся 0.3.0 и продолжает читаться без переписывания; новые plan writes используют только `0.3.1` с обязательным `plannerResponse`. Существующие `0.3.0` планы читаются только через отдельную legacy schema без переписывания истории; новые plan writes с версией 0.3.0 запрещены. Чтение legacy Task/plan не выводит для них modelId или PlannerResponse и не одобряет их автоматически. Trust schemas `schemas/` остаются неизменными. Новые Task события используют существующие journal envelopes, но получают строгие типизированные payload validators для `PLANNER_REQUEST_STARTED`, `PLANNER_RESPONSE_STORED`, `PLANNER_RESPONSE_VALIDATED` (включая backend-reported modelId), `PLANNER_RESPONSE_REJECTED`, `PLANNER_REQUEST_FINISHED` и `PLAN_VERSION_CREATED`. Схема provider response добавляется в `packages/planner/provider.mjs`.

Legacy plan не получает искусственную ссылку/модель. Новое AI планирование создаёт только новую версию; approvals по старому digest не переносятся. Recovery при начатом, но не завершённом запросе не делает повторного inference; Task становится `BLOCKED` с явной причиной и может планироваться только явным новым запросом владельца.

### Хранилище, доступ и retention

PlannerResponse хранится внутри выделенного каталога соответствующей Task, не в общем логе и не в обычном Task API. Store проверяет отсутствие symlink, принадлежность каталогу, regular-file тип, размер, schema и digest. Записи создаются с теми же OS-полномочиями, что и локальное Task store; API/UI не выдают raw request/response bytes. Ошибки/логи содержат только bounded reason code, никогда prompt, response, credentials или headers. До вызова модели и до записи raw artifact host-side guard обязан проверить, что Windows store root принадлежит ожидаемой service/user identity и ACL не предоставляет read/write другим локальным principals. Провал проверки — BLOCKED до inference и до сохранения артефакта; факт проверки/identity ref записывается безопасной метаданной без SID/секретов в публичный API.

Предлагаемая retention policy: артефакты сохраняются столько же, сколько Task data; автоматическая чистка и удаление Task/response в 0.3.2 запрещены до отдельного контрактного изменения. Отдельный API чтения/скачивания сырого артефакта также не добавляется. Удаление/retention не может оставить plan с dangling response reference.

Ограничение: текущий TaskStore не закрепляет и не проверяет Windows ACL/service identity. Перед реальным inference требуется реализовать проверяемый host-side ACL guard и зафиксировать точный проверяемый principal. Если среда не позволяет достоверно проверить отсутствие постороннего доступа, реальный provider должен сообщить UNAVAILABLE/ARTIFACT_ACCESS_UNVERIFIED и не вызывать модель.

### Границы безопасности

- Планировщик получает только точный Task text и ограниченный контекст действий из host registry.
- Модель не получает секреты/credential refs, Trust Root, произвольные файлы, shell или execution API.
- Модельный output остаётся недоверенным. Plan Validator независимо проверяет schema, DAG, IDs, executionRef/adapters/capabilities и ограничения исполнительного контура.
- План не dispatch-ится до owner approval на digest этой версии и отдельного существующего Trust approval.
- Интеграция не меняет Trust Root/resolver и не пытается устранить известную незакреплённую durable binding identity.
- Реальный E2E допускает только локальную временную среду и тестовые credentials.

## Публичные точки изменения

- `packages/planner/provider.mjs`: response schema и exact-byte provider boundary.
- `packages/execution/contracts.mjs`: схема PlannerResponse metadata, версия новых plan и ссылка из ExecutionPlan; legacy read schema.
- `packages/execution/store.mjs`: request intent, атомарный artifact store, digest/integrity checks и savePlan cross-reference.
- `apps/orchestrator/service.mjs`: request correlation, save-before-parse, fail-closed recovery.
- `apps/orchestrator/http.mjs`: только безопасное отображение provider/model/status/error/plan origin; никаких raw bytes.

Никакое изменение перечисленных runtime контрактов не вносится до независимого ACCEPT этого предложения Luna. P0/P1 по контракту закрываются отдельным Luna review до следующего stage.
