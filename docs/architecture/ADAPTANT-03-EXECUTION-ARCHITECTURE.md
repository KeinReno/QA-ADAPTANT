# ADAPTANT 0.3 — Execution Foundation architecture

Status: **этап A — архитектурное предложение для независимого review**  
База: `1a510a5d5929534d400dc965f58c78cf468bc270`  
Ветка: `feat/adaptant-03-execution-foundation`

## Цель и границы

Execution Foundation принимает поручение, сохраняет его без изменений, получает структурированный черновой план, проверяет его, проводит через одобрение владельца и передаёт только явно разрешённый исполнимый шаг существующему доверенному runtime. Task и run — разные сущности: Task хранит пользовательский жизненный цикл, а Trust Foundation остаётся единственным владельцем исполнения, evidence, recovery доверенного run и trusted verdict.

Эта архитектура не меняет `packages/contracts`, `schemas`, `docs/contract-freeze.json`, `apps/control/trusted.mjs`, `apps/control/run.mjs`, `packages/trust/**`, browser/verification worker или стенд. Если реализация обнаружит необходимость расширить Trust API или схему, работу этого адаптера следует остановить и оформить отдельное предложение в `docs/changes/`; нельзя подменять этот этап изменением замороженных контрактов.

## Фактическая база 0.2

- Контракты версии `0.1.0` описывают утверждённый Scenario, Operation, Fixture, RunProtocol, Evidence и Verdict. В `validate('ScenarioSchema', …)` DAG фактически ограничен линейной цепью, требуется ровно одна бизнес-мутация и один завершающий `verify`.
- Доверенный публичный фасад находится в `apps/control/trusted.mjs`: `startTrusted(bundle, options)`, `observeTrusted({root, trustRoot, runId, approvalId?})`, `cancelTrusted({root, trustRoot, runId, subject, approvalId?})`, `reconcileTrusted({...})`. `startTrusted` возвращает результат внутреннего runner, прошедший guard `assertTrustedPass`: PASS не возвращается без проверенного анкера, но другие технические/не-PASS результаты требуют отдельного вызова `observeTrusted` для получения trusted verdict. `observeTrusted` сообщает `trusted`, `passed`, `verdict`, `publication`, `reasonCode`, evidence IDs и events. `reconcileTrusted` может завершить проверку/публикацию и менять run state; это не read-only операция. `startTrusted` требует уже утверждённый bundle и approval, идентичности issuer/subject, environment, credentials/fixture token при необходимости, signer и каталоги. Эти параметры не являются данными Task и не сохраняются в его журнале.
- `RunStore` владеет immutable snapshots, журналом run и evidence. Он не является хранилищем пользовательских поручений или планов.
- `adapters/local/bundle.mjs` создаёт локальный `create-record` сценарий: одна операция записи и независимое чтение результата. Это не сценарий проверки авторизации.
- Проверяемая база WP-08 — опубликованный commit `1a510a5…`; аудит DeepSeek остаётся отдельной линией и этим worktree не меняется.

## Компоненты и ответственность

| Компонент | Предлагаемый путь | Ответственность | Зависимости |
|---|---|---|---|
| Task contracts | `packages/execution/contracts.mjs` | Task/Plan/Step/Result schemas, переходы и инварианты нового контура | `zod` |
| Task store | `packages/execution/store.mjs` | Durable task snapshots и hash-chained task journal в локальном каталоге; PASS закрыт до независимой проверки run/evidence | `node:*`, `packages/core/canonical.mjs`, `packages/core/file-mutex.mjs`; собственный namespace отдельно от RunStore |
| Planner API | `packages/planner/provider.mjs` | Типизированный `PlannerProvider`, статусы доступности и ошибки | только Task contracts |
| Planner validation | `packages/planner/validate.mjs` | Проверка формы, ссылок, capability allowlist и зависимостей плана | Task contracts |
| Planner coordinator | `packages/planner/plan.mjs` | Сохранить исходный запрос, вызвать provider, валидировать и версионировать черновик | provider interface, store API |
| Task orchestrator | `apps/orchestrator/service.mjs` | Task lifecycle, сериализация команд, план/approval gate, запуск шагов и агрегация | contracts, store, planner API, adapter interface |
| Execution adapter interface | `packages/execution/adapter.mjs` | Контракт `start/observe/cancel/reconcile` для одного разрешённого шага | Task contracts |
| Trust adapter | `adapters/trust-run/adapter.mjs` | Перевод только владельчески привязанного execution reference в `startTrusted`/`observeTrusted`/`cancelTrusted`/`reconcileTrusted` | публичный фасад `apps/control/trusted.mjs`; resolver trusted refs |
| Minimal CLI | `apps/orchestrator/cli.mjs` (по необходимости) | Ввод Task, просмотр плана/состояния, подтверждение/отмена | Orchestrator API; не вызывает Trust API сам |

Модуль планирования не вызывает адаптер. Orchestrator не интерпретирует свободный текст и не содержит SDK модели. Adapter не меняет план и не назначает разрешения. Verification остаётся частью доверенного run; Task aggregate лишь отображает наблюдаемый verdict с его `runId` и evidence refs.

## Интерфейсы (предложение)

```js
PlannerProvider {
  id: string;
  availability(): Promise<{status: 'AVAILABLE'|'UNAVAILABLE', reasonCode?: string}>;
  plan(input: {originalRequest: string, context: PlannerContext, requestId: string})
    : Promise<{providerId: string, modelId: string|null, mode: 'MODEL'|'MOCK', plan: PlanDraft}>;
}

ExecutionAdapter {
  id: string;
  capabilities(): readonly string[];
  prepare(input: {taskId: string, planId: string, step: ExecutionStep,
                 executionRef: TrustedExecutionRef})
    : Promise<{runId: string, bundleDigest: string, preparedRef: string}>; // no dispatch side effect
  start(input: {taskId: string, planId: string, step: ExecutionStep, prepared: PreparedRun,
               idempotencyKey: string})
    : Promise<{runId: string, runnerResult: unknown, executionOutcome: 'SUCCEEDED'|'FAILED'|'UNKNOWN'}>;
  observe(input: {runId: string}): Promise<TrustedRunObservation>;
  cancel(input: {runId: string, actorRef: string}): Promise<TrustedRunObservation>;
  reconcile(input: {runId: string, executionRef: TrustedExecutionRef}): Promise<TrustedRunObservation>;
}

TaskService {
  create(input: {originalRequest: string, ownerRef: string, contextRefs: string[]}): Promise<Task>;
  plan(taskId: string, providerId: string): Promise<ExecutionPlan>;
  approvePlan(taskId: string, planId: string, approvalRef: string): Promise<Task>; // host verifier + atomic compare-and-transition
  start(taskId: string, planId: string): Promise<Task>;
  observe(taskId: string): Promise<TaskView>;
  cancel(taskId: string, actorRef: string): Promise<Task>;
  recover(): Promise<{recovered: string[], blocked: string[], inconclusive: string[]}>;
}
```

Это внутренние API 0.3, не расширение контрактов Trust Foundation. `TrustedExecutionRef` — ссылка на владельчески разрешённые bundle/environment/approval данные; она не содержит секретов и не может быть создана или расширена моделью. Runtime dependency resolver получает credentials и ключи из локально настроенного доверенного источника только в памяти процесса. Пока такой resolver/context не передан и не проверен, шаг переходит в `BLOCKED`.

## Потоки данных и доверительные границы

1. `create` пишет точный `originalRequest`, owner ref, время и `DRAFT` до вызова любой модели.
2. Planner получает только исходный текст и безопасный контекст. Возвращает PlanDraft с идентификаторами разрешённых типов действий; произвольные команды, JS, URL-ы и locator-ы не являются исполняемыми инструкциями.
3. Validator отклоняет неизвестный adapter/capability, циклические или отсутствующие зависимости, пустые проверки, несовпадающие пары rule/requirement и неподдерживаемый action type. Перед dispatch Orchestrator сверяет capabilities шага с конкретным adapter. Host вычисляет owner-approval и Trust-approval requirements из локальной policy и классификации шага; ответ модели не может снять подтверждение.
4. План хранится как неизменяемая версия. Изменение плана создаёт следующую версию и сбрасывает прежнее подтверждение.
5. Policy/approval решается Orchestrator по локальным правилам и доверенным refs. Execution ref исполним только в пересечении host allowlist и явно переданного каталога `approvedScenarioRefs`. План модели не может объявить действие разрешённым. Owner approval привязывается к точной версии плана и проходит атомарное сравнение revision/planId/hash при переходе; для существующего 0.2 mutation run необходим отдельный Trust approval, связанный с точным approved Scenario/Operation/Fixture/inputs.
6. Adapter разрешает executionRef, фиксирует `dispatch-intent` в Task journal и вызывает только публичный `startTrusted`. До начала вызова повтор dispatch после рестарта запрещён; если исход вызова неизвестен, разрешены только `observeTrusted`/`reconcileTrusted` по известному runId.
7. Adapter сохраняет исходное возвращённое значение `startTrusted` только как технический `runnerResult`, извлекает проверенный `runId` из заранее закреплённого bundle и получает trusted outcome отдельным вызовом `observeTrusted`. Нормализация исключений/ошибок Runner в `executionOutcome` не создаёт verification verdict. Orchestrator сохраняет ссылки evidence и не пересчитывает/не переписывает verdict. `TaskStore` принимает `PASS` только при наличии fail-closed `verifyTaskPass`, который независимо повторно читает trusted run/evidence chain для всех обязательных шагов; булево поле и непустые IDs без этой проверки недостаточны.

## Совместимость и известные ограничения

Полный пример поручения про login, неверный пароль и доступ без полномочий не представим текущим Trust Scenario: текущий контракт требует одну бизнес-мутацию, а local adapter не описывает login и независимые проверки авторизации. Planner может выявить такой запрос и предложить шаги, но валидатор/adapter должны вернуть `BLOCKED` с `UNSUPPORTED_EXECUTION_SHAPE`, если нет заранее зарегистрированного утверждённого сценария, который покрывает все требования. Генерация нового Scenario из ответа модели невозможна без изменения контракта и подписанного approval.

Доступный `localBundle` фиксирует сценарий `create-record` и автоматически формирует локальное approval-подобное поле для harness; оно не является реальным owner-signed Trust approval. Поэтому нельзя использовать его как доказательство полного доверенного E2E. Этап C/D полного trusted E2E остаётся заблокированным до наличия воспроизводимого, owner-approved локального test fixture и полного безопасного trust context. До этого можно завершить этап B и изолированно проверить Task/Planner contracts; отчёт обязан пометить E2E `NOT RUN` или `BLOCKED`, не `PASS`.

## Развёртывание и файлы

Новый контур — отдельные Node ESM пакеты, без базы данных, сервиса или новой UI платформы. Данные Task хранятся в явно указанном локальном root каталоге; планы/effects/events имеют `taskId`, а trusted evidence остаётся в run store. Записи task journal атомарны, последовательны и восстанавливаются при старте. Секреты, bearer, приватные ключи, исходники сессий и локальные account данные не входят в snapshots и отчёты.

## Этапность

- A: этот документ, `ADAPTANT-03-TASK-LIFECYCLE.md`, `ADAPTANT-03-PLANNER-CONTRACT.md`, затем независимое review Luna.
- B: Task contracts/store, PlannerProvider/mock (с явной меткой `MOCK`), validator, Orchestrator; unit/contract/negative/recovery проверки.
- C: адаптер к public trusted facade; безопасное поведение при отсутствии refs/approval — `BLOCKED`; никаких direct imports privileged internals.
- D: минимальный CLI/интерфейс, интеграция и E2E только если стенд и полная owner-approved доверенная конфигурация доступны. Иначе зафиксировать конкретный blocker без имитации.

