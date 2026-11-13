# ADAPTANT 0.3 — PlannerProvider contract

Status: **этап A — архитектурное предложение для независимого review**  
База: `1a510a5d5929534d400dc965f58c78cf468bc270`

## Принципы

Planner — заменяемый модуль предложения плана. Он не исполняет шаги, не открывает браузер/сеть, не читает Trust Root, не выдаёт approval, не выбирает произвольный adapter и не возвращает verdict. Его ответ — `PlanDraft`, не утверждённый Scenario и не факт прогона.

Исходный текст хранится отдельно как точная строка Task. Provider не получает скрытые сессии, аккаунтные секреты, bearer, private keys или произвольные локальные файлы. Контекст ограничен владельчески переданными refs и допустимыми операциями каталога.

## TypeScript-стиль контракта

```ts
type ProviderAvailability =
  | { status: 'AVAILABLE'; providerId: string; modelId: string|null }
  | { status: 'UNAVAILABLE'; providerId: string; reasonCode: 'NOT_CONFIGURED'|'AUTH_REQUIRED'|'RATE_LIMITED'|'NETWORK_ERROR'|'UNSUPPORTED' };

type PlannerContext = {
  allowedActionTypes: readonly string[];   // capability catalog, not grants
  environmentRefs: readonly string[];     // opaque refs; provider cannot resolve them
  approvedScenarioRefs: readonly string[];// host-resolved refs; never copied from arbitrary Task contextRefs
  constraints: readonly string[];
};

type PlannerRequest = {
  requestId: string;
  taskId: string;
  originalRequest: string;
  context: PlannerContext;
  outputSchemaVersion: '0.3.0';
  deadlineMs: number;
  maxOutputBytes: number;
};

type PlanDraft = {
  normalizedGoal: string;
  requirements: Array<{ requirementId: string; statement: string; mandatory: boolean }>;
  missingContext: string[];
  steps: Array<{
    stepId: string;
    description: string;
    actionType: 'trusted-scenario'|'clarification'|'observation';
    prerequisites: string[];
    adapterId: string|null;              // exact registered adapter id
    executionRef: string|null;           // exact host-registered catalog ref
    requiredCapabilities: string[];      // proposals; never authority
    mutating: boolean;                   // host raises risk for trusted-scenario steps
    required: boolean;
    validationRules: Array<{ ruleId: string; requirementId: string }>;
  }>;
  estimatedRisk: 'LOW'|'MEDIUM'|'HIGH'|'UNKNOWN';
  approvalRequirements: Array<'OWNER_PLAN_APPROVAL'|'TRUST_APPROVAL'>; // advisory only
  validationRules: Array<{ ruleId: string; requirementId: string }>;
};

type PlannerResult = {
  providerId: string;
  modelId: string|null;
  mode: 'MODEL'|'MOCK';
  output: PlanDraft;
  usage?: { inputTokens?: number; outputTokens?: number };
};
```

Provider API: `availability(): Promise<ProviderAvailability>` and `plan(request, signal): Promise<Uint8Array>` containing JSON-serialized `PlannerResult`. A transport provider must stream through `readBoundedPlannerBytes()` so response size is capped before parsing or buffering the complete body; the host independently enforces the byte limit before JSON parsing. Provider errors are typed (`PROVIDER_UNAVAILABLE`, `RATE_LIMITED`, `TIMEOUT`, `INVALID_RESPONSE`, `OUTPUT_LIMIT`, `CANCELED`) and must not include credentials, full prompts, or response bodies in public error messages. The host enforces time and signals cancellation to the provider. Retry is bounded/configurable and uses a new request ID; never silently retries execution.

## Проверка ответа

Local validator (not model) enforces:

1. Strict object shape, required types, maximum string/array/byte sizes, unique IDs and bounded step count.
2. Nonempty `originalRequest` is unchanged in Task record; plan carries a digest/reference to that task, not replacement source text.
3. Every requirement has a unique id; each mandatory requirement is linked from one or more validation rules.
4. Every prerequisite points to an existing step; graph is acyclic; topological order is deterministic.
5. `actionType`, `adapterHint`, `executionRef` and `requiredCapabilities` are intersected with host-configured registries. Model cannot add a registry entry, capability grant, credential, environment, owner, approval, risk waiver or validation PASS.
6. `mutating=true` is treated as requiring mutation controls. If false but action type/adapter says mutating or classification is unknown, validator raises it to mutating or rejects the plan; model cannot downgrade policy risk.
7. Any step needing an unsupported operation or mapping to multiple requirements without a supported trusted Scenario returns a non-executable plan with `BLOCKED` reason. The plan may be displayed as a draft, never started.
8. Owner/Trust approval requirements are derived by host policy. Provider-supplied `approvalRequirements` are suggestions only and cannot remove required approvals; a mutating/trusted action always requires owner plan approval and separate Trust approval.
9. No shell, JavaScript, arbitrary URL, raw selector, Browser Worker protocol, internal Control function name, or free-form API path is accepted as executable data.

`ExecutionPlan` stores the validated output, `taskId`, immutable version, provider provenance (`MODEL`/`MOCK`), schema version, creation time and validation findings. Replanning creates a new version; existing owner approvals expire on plan digest mismatch.

## Provider behavior and provenance

- A configurable provider registry selects provider by explicit local configuration. No hidden provider lookup or paid provider is required for local development.
- The initial deterministic mock is opt-in only and returns `mode: 'MOCK'`, `providerId: 'mock-deterministic'`, `modelId: null`. UI, journal and reports preserve this marker.
- Missing real provider returns `UNAVAILABLE/NOT_CONFIGURED`. It does not silently fall back to mock. Callers may explicitly choose mock for tests/demos.
- Model/provider output is untrusted data. Parse with strict schema, validate semantic rules, bound timeout/size, record safe metadata and reject malformed responses. Never include raw provider output in logs by default.
- No provider result is a verification result. `PASS` is only the trusted observer's result associated with a concrete runId/evidence chain.

## Compatibility notes

The existing `ScenarioSchema` is a frozen 0.1.0 contract, not the Planner output schema. Do not serialize `PlanDraft` into a Scenario by shape imitation. Existing validator supports only linear steps, one mutation, one `verify`, and a single local create-record operation. Authentication scenarios involving several independent outcomes cannot be executed by this mapping. A contract extension proposal is required before any implementation claims those plans are executable.

