# Границы и владельцы

| Путь | Владелец | Разрешённые зависимости | Публичный интерфейс |
|---|---|---|---|
| packages/contracts, schemas | основной агент | zod | schemas, validate, VERSION, reasonCodes |
| packages/core | исполнитель ядра | contracts, node:* | canonical, digest, durable snapshots, evidence journal |
| apps/control | исполнитель ядра | contracts, core, child_process | start/observe/cancel/reconcile |
| apps/browser | исполнитель browser | contracts, playwright | IPC execute / observation / mutation intent handshake |
| apps/verification | независимый исполнитель | contracts, core, read-only adapter | verify immutable bundle → verdict |
| adapters/local | исполнитель стенда | node:http | локальный create/read/faults |
| adapters/ciz | Kimi workpack | contracts, public adapter API | preflight, classify, read, identity |
| packages/intelligence | DeepSeek workpack | contracts, source snapshots | draft + diagnostics + provenance |
| apps/workbench | Kimi workpack | public Control API | наблюдение, сценарии, утверждение |
| tests | владелец соответствующего пакета | публичные API | изолированные временные каталоги |

Нельзя импортировать private реализацию другого процесса или выдавать Browser assertion за Verification. Источник истины — persisted snapshots и журнал; UI не держит жизненный цикл. Схемы изменяются только основным агентом после review Luna. Исполнитель не меняет чужие файлы без передачи владения.

Начальный IPC v1: `{type, commandId, runId, payload}`. Родитель валидирует runId/commandId и разрешённые type. Browser: READY, INTENT, REQUEST, RESPONSE, OBSERVATION, DONE, ERROR. INTENT требует ACK после durable записи. Verification: RESULT, ERROR. Не принимать неизвестные сообщения. HTTP-граф связывается requestId/X-Ciz-Id и явными parentEvidenceIds, не соседством по времени. Verification имеет собственный HTTP-клиент и не принимает body браузера за независимое чтение.

INTENT/ACK: экспортированные IntentCommand/IntentAck. intentId = runId + ':' + stepId, неизменяемый на попытку. Повтор идентичного INTENT возвращает сохранённый ACK, не новую запись/разрешение второго click. При другом payload того же intentId — CONTRACT_INVALID. Browser принимает один ACK только для текущего intentId/commandId и ведёт dispatched=true перед click. ACK loss/time-out/crash → не нажимать, RECONCILE; повтор START никогда не переотправляет ACK новому browser процессу. Persisted intent трактуется как possibly dispatched независимо от получения ACK. Request artifact обязан ссылаться на этот intent. Verification input = {runDirectory, manifestSha256}; operation/scenario/fixture читаются из snapshots, никаких переданных boolean success. RESULT принимается только от назначенного verification child; перед публикацией Control повторяет validateVerdictCoverage.
