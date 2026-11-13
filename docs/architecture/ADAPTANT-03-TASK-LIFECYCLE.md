# ADAPTANT 0.3 — Task lifecycle

Status: **этап A — архитектурное предложение для независимого review**  
База: `1a510a5d5929534d400dc965f58c78cf468bc270`

## Сущности

- **Task** хранит `taskId`, исходный `originalRequest` без нормализации/перезаписи, `normalizedGoal`, `status`, `createdAt`, `updatedAt`, `ownerRef`, refs на контекст и активный `executionPlanId`, `environmentRef`, `policyRef`, `approvalRef`, список `runIds`, `result` и `journalHead`.
- **ExecutionPlan** — неизменяемая версия с `planId`, `taskId`, `version`, `provider` (`providerId`, `modelId`, `mode=MODEL|MOCK`), `steps`, dependency edges, proposed capabilities, risk annotations, approval requirements и validation summary.
- **ExecutionStep** имеет `stepId`, описание, ограниченный `actionType`, dependency refs, конкретный `adapterId`, status, `attemptCount`, связанные `runIds`, evidence refs, `executionOutcome`, `verificationOutcome`, `failureReason`.
- **JournalEvent** связывает taskId и при наличии planId/stepId/runId; append-only sequence/hash chain; секреты и приватные payloads не записываются.

Task status и step status — разные поля. Task `COMPLETED` означает завершение lifecycle; бизнес-успех хранится отдельно в `result.taskOutcome`.

## Task states

```text
DRAFT → PLANNING → PLAN_READY → AWAITING_APPROVAL → READY → RUNNING → VERIFYING → COMPLETED
```

Терминальные альтернативы: `FAILED`, `CANCELED`, `BLOCKED`, `INCONCLUSIVE`. До создания Task ошибки валидации запроса возвращаются клиенту; после сохранения Task ошибки превращаются в event и допустимый terminal state.

| Из | В | Условие |
|---|---|---|
| DRAFT | PLANNING | исходный текст сохранён; единственный активный `planRequestId` |
| PLANNING | PLAN_READY | ответ provider структурно и семантически валиден; версия плана сохранена |
| PLANNING | BLOCKED | provider отсутствует/недоступен, лимит исчерпан, либо контекста недостаточно для допустимого следующего действия |
| PLAN_READY | AWAITING_APPROVAL | план содержит исполнимый шаг или требует подтверждения владельца |
| PLAN_READY | READY | только если локальная policy заранее разрешает все шаги без human approval |
| AWAITING_APPROVAL | READY | owner подтверждает конкретные `planId` и `planSha256`; Trust approval для trusted mutation по-прежнему требуется отдельно |
| AWAITING_APPROVAL | CANCELED | owner отменил задачу до dispatch |
| READY | RUNNING | adapter доступен, refs разрешены, зависимости шага удовлетворены, dispatch intent durable, команда идемпотентна |
| RUNNING | VERIFYING | trusted run сообщил terminal technical outcome; Orchestrator запросил/получил наблюдение |
| RUNNING | BLOCKED | adapter/ref/approval/policy недоступен до dispatch |
| RUNNING | INCONCLUSIVE | после dispatch неизвестно, был ли шаг выполнен; автоматический replay запрещён |
| RUNNING / VERIFYING | CANCELED | cancellation подтверждена adapter; при неизвестном исходе мутации — `INCONCLUSIVE`, не `CANCELED` |
| VERIFYING | COMPLETED | все шаги терминальны; outcome агрегирован; trusted verdict сохранён как прочитанный наблюдением |
| любое нетерминальное | FAILED | доказанная внутренняя ошибка Task/Planner, не неопределённый исход исполнительной мутации |

Переходы проверяются одной чистой функцией с явной таблицей разрешённых рёбер. Повтор идентичной команды с тем же idempotency key возвращает сохранённое состояние; повтор с тем же ID и другим payload отклоняется как conflict. Терминальные состояния неизменяемы, кроме безопасного добавления журнала наблюдения, не меняющего результат.

## Step states и агрегация

Step lifecycle: `PENDING → READY → DISPATCHING → RUNNING → VERIFYING → COMPLETED`; terminal alternatives `FAILED`, `BLOCKED`, `CANCELED`, `INCONCLUSIVE`, `SKIPPED`. `SKIPPED` допустим только для необязательного шага, если валидированный dependency/condition явно исключает его; неизвестность не является пропуском.

- `executionOutcome`: `SUCCEEDED`, `FAILED`, `UNKNOWN`, `NOT_STARTED`.
- `verificationOutcome`: `PASS`, `FAIL`, `BLOCKED`, `INCONCLUSIVE`, `NOT_AVAILABLE` — только данные из trusted observer для соответствующего runId. Для mock/integration-only пути — `NOT_AVAILABLE`.
- `taskOutcome`: `PASS`, `FAIL`, `BLOCKED`, `INCONCLUSIVE`, `CANCELED`, `PARTIAL`.

TaskOutcome `PASS` разрешён только если каждый обязательный step завершён и имеет trusted `verificationOutcome=PASS`, runId и валидные evidence refs. Любой обязательный неразрешённый/неподтверждённый шаг исключает PASS. `COMPLETED` допустим с `FAIL` или `INCONCLUSIVE`, если жизненный цикл завершён и причина видна.

## Запуск и защита от повторного исполнения

Для шага с потенциальной мутацией Orchestrator до внешнего вызова атомарно записывает `DISPATCH_INTENT` с `taskId`, `planId`, `stepId`, стабильным idempotency key, выбранным adapter, executionRef digest и `runId`, закреплённым из единожды созданного bundle. `localBundle()` принимает caller-supplied `runId`, поэтому адаптер обязан назначить его до создания bundle, создать bundle один раз и сохранить точный ref/hash/runId в durable intent до вызова `startTrusted`. Вызов запускается единожды. `DISPATCH_RETURNED` записывает исходный результат runner (без секретов) и тот же runId.

Если процесс упал:

1. До `DISPATCH_INTENT`: step можно вернуть в READY.
2. После intent, до подтверждённого `startTrusted` результата: статус `INCONCLUSIVE`; если точный runId достоверно известен из сохранённого bundle — разрешены `observeTrusted` или ограниченный `reconcileTrusted` по этому runId. `reconcileTrusted` может завершить проверку и публикацию результата, поэтому не является read-only. В любом случае запрещён новый `startTrusted` или новый bundle для прежнего intent.
3. После сохранённого runId: вызвать adapter observe или reconcile; доверенный runtime определяет recovery по своему журналу, без повторной бизнес-мутации.
4. Если trusted runtime не может установить исход, сохранить `INCONCLUSIVE` и требовать новый owner-approved run. Retry в рамках прежнего intent запрещён.

Хотя `localBundle()` по умолчанию генерирует случайный runId, caller может задать его заранее. Адаптер обязан заранее создать bundle один раз и связать его runId и refs с intent. Если процесс погиб до подтверждения вызова, recovery обращается только к тому же runId; при отсутствии записи run результат остаётся неопределённым и требует нового owner-approved intent, а не повтора старого dispatch.

## Отмена

До dispatch отмена идемпотентно переводит Task/step в `CANCELED`. После dispatch Orchestrator вызывает только `cancelTrusted` для известного runId, затем перечитывает результат через `observeTrusted`. Если мутация могла начаться, отмена не откатывает её и не делает повтор. Подтверждённый trusted terminal result сохраняется; потеря соединения/неясный результат даёт `INCONCLUSIVE`. Отмена во время `VERIFYING` не заменяет результат Verification.

## Восстановление

`recover()` проверяет каждый journal, план и активный шаг:

- недействительная/прерванная hash-chain → Task `BLOCKED`, ручное вмешательство;
- `PLANNING` без валидного сохранённого ответа → новая попытка только с новым request ID и лимитом, исходный task текст остаётся неизменным;
- план сохранён, approval отсутствует → `AWAITING_APPROVAL`;
- подтверждённый approval не совпадает с актуальным plan hash → `BLOCKED`, требуется новая версия плана/подтверждение;
- `DISPATCH_INTENT` без `DISPATCH_RETURNED` → `INCONCLUSIVE`; при известном runId допустимы `observeTrusted` и ограниченный `reconcileTrusted` (который может изменить состояние run), но не повторный dispatch;
- есть runId и незаконченный trusted state → `reconcileTrusted`, затем `observeTrusted`;
- terminal result уже сохранён → только `observeTrusted`, никаких запусков.

## Результат

`TaskResult` включает `taskOutcome`, список step outcomes, `executionSummary`, trusted `verificationSummary` по runId, bounded error codes/messages, `evidenceRefs` вида `{runId, evidenceId}` и явный `plannerMode`. Сырые evidence objects не копируются и не пересериализуются в Task journal. Mock planner всегда видим в Task/Plan/result и не может сформировать `verificationOutcome`.

