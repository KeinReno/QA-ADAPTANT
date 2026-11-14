# Agent Provider Layer и мультиагентные роли — замороженный контракт

Статус: **FROZEN; Luna GPT-6: ACCEPT; заморожен после трёх ограниченных корректировок владельца и финального независимого review 14 ноября 2026**
Назначение: дополнить предварительную карту интеграций и пересмотреть старое предложение `ADAPTANT-03-PLANNER-CONTRACT.md` после отмены обязательной Ollama.
Снимок WIP 0.3.2: `wip/adaptant-032-ollama-snapshot` / `d64de8e`; этот документ находится в отдельной worktree-ветке и не изменяет снимок.

## 1. Решение, которое требуется утвердить

0.3.2 подключает существующие внешние CLI/Harness через заменяемый Agent Provider Layer. Ollama не является обязательной зависимостью. Codex — кандидат первого технического опыта, но не обязательный движок. Провайдеры, которые не прошли живой запуск, отображаются как неподтверждённые или недоступные; выбранный провайдер не подменяется MOCK при сбое.

Пользователь задаёт произвольное число назначений агентов и ролей. Начальные роли: `Planner`, `Executor`, `Verifier`; пользовательские роли допустимы. У каждого назначения свои провайдер, модель, режим рассуждения, инструкции, MCP-набор, лимиты и политика сессии/восстановления. Допустимы цепочки и параллельные роли. Возможность конкретного CLI нельзя выводить из общего контракта: UI показывает только возможности, объявленные и проверенные этим адаптером.

Agent Provider Layer обслуживает модельные ходы и преобразует события CLI/Harness. ADAPTANT сохраняет владение `TaskService`, `Execution Foundation`, `TaskStore`, host validation, approvals, recovery, Browser/Verification runtime, provenance и UI. Внешний агент не становится источником полномочий или вердикта.

## 2. Уровни доказанности

- **Код/документация** — возможность описана в исходниках указанного checkout либо в документации владельца CLI.
- **Локальное наличие** — исполняемый файл найден или исходный checkout найден. Это не доказывает login, доступ к модели или рабочий MCP.
- **Живой вызов** — реальный авторизованный агент ответил через выбранный transport; сохраняются безопасные события, код завершения и сведения о фактической модели либо явное `UNREPORTED`. Сам по себе вызов не является E2E.
- **Локальный E2E** — реальный внешний агент проходит полный маршрут с тестовым локальным стендом и MCP, подтверждением плана, исполнением и независимой проверкой факта.
- **Dev E2E** — отдельный маршрут на настоящем Dev. До него подтверждаются environment/account/object refs, разрешённые операции и актуальные данные стенда; отчёт маркируется Dev. Успех локального E2E не доказывает Dev E2E.

На 14 ноября 2026 года этот документ не выполнял живые запросы к перечисленным агентам и не подтверждает E2E.

QA-v2 кодовая карта ниже описывает конкретный локальный checkout `C:\Users\gvi\Desktop\QA_v_2`, HEAD `6bed9b4`. Checkout грязный; в частности, `core/agents/deepseek.ts` и `server/agent/supervisor.ts` в нём не следует считать подтверждёнными частью зафиксированного релиза. Другой checkout `QA_v_2-wt-map` на `a60221c` этих двух файлов не содержит. Следовательно, запись «реализовано в QA-v2» ниже означает наличие в изученном checkout, а не принятую/выпущенную интеграцию.

## 3. Карта провайдеров

| Реестр / клиент | Интерфейс и документированные возможности | Авторизация и модели | Состояние на машине / подтверждение | Решение для ADAPTANT |
|---|---|---|---|---|
| `codex-cli` / Codex | QA-v2 запускает `codex exec --json` с временным workspace, ephemeral ходом и настроенным MCP. JSON события читаются из stdout; stderr ограничивается; остановка убивает дерево процесса. В этом QA-v2 пути сессия не продолжается — задача получает новый ход и контекст. Разрешённые MCP-инструменты должны дополнительно ограничиваться самим ADAPTANT: `--sandbox read-only` не ограничивает побочные эффекты MCP. | Официальный Codex CLI поддерживает вход через ChatGPT account; выбор моделей и reasoning зависит от CLI, аккаунта и workspace. Не предполагать наличие конкретной модели/квоты. | `codex.exe` найден; версия `0.163.0-alpha.10.2`, `codex exec --help` доступен. Авторизация, фактически обслуженная модель, MCP вызов и отмена живого хода не подтверждены. | Первый кандидат на qualification, не default/обязательная зависимость. Для первого вызова — синтетический локальный Task, минимальный MCP allowlist без Dev-мутаций. Не принимать только запуск команды как результат. |
| `cursor-agent` / Cursor Agent | QA-v2 использует headless `-p --output-format stream-json --mode ask`; MCP список ограничивается. Сессия продолжается лишь вместе с принадлежащим задаче сохранённым workspace и проверенным session ID. На Windows CLI sandbox выключен и используется Cursor permission allowlist. Остановка — process-tree kill. | Модельный перечень и auth принадлежат Cursor CLI и аккаунту; reasoning capability в QA-v2 не следует автоматически переносить в UI ADAPTANT. | `cursor-agent.ps1` найден; `cursor-agent` version по независимому отзыву Luna — `2026.11.11-043ef28`. Login, вызов MCP и cancel не подтверждены. | Реальный альтернативный кандидат для qualification. Доступность не означает готовность. |
| `qoder-cli` / Qoder | Команда запуска `qoder`. Официальный CLI: headless prompt, JSON/stream-JSON события, stdin input, session ID/resume, `--model`, `--reasoning-effort`, список моделей, MCP config/allowlist и ACP режим. Headless режим без host approval отклоняет действия, требующие интерактивного подтверждения; MCP allowlist всё равно задаёт ADAPTANT. Отмена конкретного хода должна быть проверена через поддерживаемый ACP или процессное прерывание. | Документированы вход браузером в Qoder account и PAT для headless/CI. Доступные модели/effort должны запрашиваться у CLI. | `qoder` в PATH не найден. Официальная документация подтверждает CLI, но не установку, account entitlement, живой вызов или отмену на этой машине. | Планируемый адаптер. Перед implementation — установка/обнаружение по согласию владельца окружения и безопасная capability/auth qualification. |
| `kimi-code-cli` / Kimi Code | Официальные `kimi -p`/print, stream-JSON, ACP через JSON-RPC stdio, MCP, сохранённые сессии и resume/load. ACP объявляет capabilities, отменяет текущий ход и умеет продолжить сессию; stream-JSON и диагностический stderr различаются. Модели и thinking effort могут зависеть от выбранной модели. | Поддержан OAuth device-code login Kimi Code; также Kimi Platform API key и сторонние провайдеры. Для требования «без обязательного API-ключа» использовать только подтверждённый account OAuth путь, не предполагать его entitlement. | `kimi` в PATH не найден. Проверена документация Kimi Code CLI; старый Kimi CLI архивирован и не поддерживается — не выбирать его вместо Kimi Code. Живой вызов не подтверждён. | Планируемый ACP/CLI адаптер после локальной проверки установки, OAuth статуса, моделей/reasoning, MCP и cancel. |
| `deepseek-http` / DeepSeek API через QA-v2 | Отдельный executor из грязного QA-v2 checkout: HTTP к OpenAI-compatible Chat Completions или Anthropic Messages, собственный tool loop и дочерний stdio QA-v2 MCP client. Аборт через `AbortController`, MCP child закрывается. Нет provider session resume; каждый ход вновь получает контекст. | В конфигурации QA-v2 используется API key или отдельный DSH token. API route не подтверждает наличие/переносимость DeepSeek Harness. | Исторический QA-v2 отчёт от 9 ноября: API запрос и tool calling работали; в одном ходе `task_state` вернул «QA v2 недоступен», второй ход вручную остановлен после `task_state`/`lookup`. Это не полный E2E и не PASS. Текущая авторизация не проверялась. | Сохранить в карте как самостоятельный HTTP/MCP транспорт. Не называть его `DeepSeek Harness` и не считать первым кандидатом без user-confirmed auth. |
| `deepseek-harness` / DSH | Другая система: официальный open-source agent harness `dsh`. В изученном локальном исходном checkout есть `dsh --profile headless`, `dsh --profile acp` и ACP JSON-RPC stdio. ACP поддерживает persistent create/list/resume/close, prompt events, cancellation, model config и stdio/HTTP MCP mounts. В текущем ACP `session/resume` не воспроизводит историю для клиента; свой журнал/артефакты ADAPTANT всё равно нужны. | В DSH отдельно есть browser sign-in DeepSeek Account и `deepseek-account` model route, помимо API-key provider. Это существующий account-auth path, но на этой машине его доступность/entitlement и рабочая модель не проверялись. Также есть иные provider routes, включая OAuth-capable Codex; credentials зависят от конкретного route. | `C:\Users\gvi\Desktop\deepseek-harness` найден, HEAD `aa8262e`; дерево грязное с несвязанными UI изменениями. `dsh` в PATH не найден. Публичный проект обозначен developer preview с возможными breaking changes. Реального запуска не было. | Рассматривать ACP как отдельный интеграционный transport/кандидат после qualification. Не встраивать или переносить runtime Harness в ADAPTANT; запускаемый клиент должен оставаться внешним процессом. |
| `claude-code-cli` / Claude Code | QA-v2 содержит отдельный headless provider с ограниченным filesystem/tool surface, MCP, событиями хода, session ID и kill-tree cancellation. Переносить только поведение контракта, не QA-v2 loop. | Login/model/effort зависит от установленного CLI и доступного аккаунта. | Исполняемый файл в текущем PATH не обнаружен; этот маршрут не запускался в текущем исследовании. | Планируемый provider, статус `NOT_INSTALLED` до проверки окружения. |
| `openai-chatgpt` / GPT или ChatGPT отдельно от Codex | В просмотренной официальной документации OpenAI документирован Codex CLI для terminal agent и вход через ChatGPT account. Самостоятельный официальный ChatGPT/GPT CLI, отдельный от Codex, не найден. OpenAI также публикует CLI для работы с API; это API-поверхность с API-авторизацией, не агент с ChatGPT account auth и не замена Codex. Нельзя объявлять Codex отдельным ChatGPT adapter под другим названием. | ChatGPT subscription auth документирована для Codex CLI. Она не создаёт отдельного ChatGPT CLI транспорта. API key не является допустимой скрытой заменой для account-auth требования. | Отдельный `chatgpt`/`gpt` executable не найден. Рабочего отдельного клиента/сессии/stream/MCP/cancel нет в исследованных официальных источниках. | Добавить в реестр как `PLANNED_UNAVAILABLE` с причиной «нет подтверждённого отдельного официального ChatGPT CLI/Harness». Доступный маршрут `Codex CLI + ChatGPT sign-in` показывать только как `codex-cli`, отдельно от запланированной записи GPT. API CLI учитывать отдельно и только при отдельном решении о API provider. Пересмотреть, если появится отдельный официальный интерфейс. |

### Источники карты

- QA-v2: `core/agents/cli-turn.ts`, `core/agents/provider.ts`, `core/agents/deepseek.ts`, `core/agents/stage-models.ts`, `server/agent/loop.ts`, `server/agent/supervisor.ts`, `docs/DEEPSEEK_PROVIDER.md`, `docs/AGENT_MCP_WORKFLOW.md`, checkout и статусы перечислены выше.
- Qoder: [CLI overview](https://docs.qoder.com/cli/overview), [CLI reference](https://docs.qoder.com/cli/cli-reference), [headless scripts](https://docs.qoder.com/cli/run-in-scripts), [authentication](https://docs.qoder.com/cli/authentication).
- OpenAI: [Codex with a ChatGPT plan](https://help.openai.com/en/articles/11369540-using-codex-with-your-chatgpt-plan), [OpenAI API CLI](https://developers.openai.com/api/docs/libraries/openai-cli).
- Kimi Code: [CLI reference](https://moonshotai.github.io/kimi-code/en/reference/kimi-command.html), [ACP mode](https://moonshotai.github.io/kimi-code/en/reference/kimi-acp.html), [sessions](https://moonshotai.github.io/kimi-code/en/guides/sessions.html), [OAuth getting started](https://moonshotai.github.io/kimi-code/en/guides/getting-started.html).
- DeepSeek Harness: [official project](https://github.com/deepseek-ai/deepseek-harness), [ACP automation contract](https://github.com/deepseek-ai/deepseek-harness/blob/master/.agents/notes/implemented/simplification/2026-07-23-acp-automation-only-protocol.md), [model providers](https://deepseek-harness.github.io/deepseek-harness/en/guide/providers), [DeepSeek Account model route](https://github.com/deepseek-ai/deepseek-harness/blob/master/packages/llm/llm-deepseek-account/README.md), [DeepSeek account login](https://github.com/deepseek-ai/deepseek-harness/blob/master/.agents/notes/implemented/architecture/2026-09-14-deepseek-account-login.md).
- OpenAI: [Using Codex with a ChatGPT plan](https://help.openai.com/en/articles/11369540-using-codex-with-your-chatgpt-plan).

## 4. Минимальный общий контракт Agent Provider Layer

Это предложение интерфейсного минимума. Конкретный CLI adapter может сообщить `false`/`unsupported` для любого необязательного capability. Он не вправе притворяться, что фича работает.

```ts
type Capability<T> = { supported: true; values?: readonly T[]; source: 'cli-probe'|'acp-initialize'|'verified-static' }
                     | { supported: false; reason: string };
// Выбираемые модели/reasoning имеют более строгий источник: только актуальный
// probe/ACP ответ установленного provider version и текущего auth context.
type SelectableCapability<T> = { supported: true; values: readonly T[]; source: 'cli-probe'|'acp-initialize'; observedAt: string }
                              | { supported: false; reason: string; observedAt?: string };

type ProviderDescriptor = {
  providerId: string;                 // стабильный id: codex-cli, kimi-code-cli, dsh-acp…
  version: string|null;
  executable: string;
  transport: 'process-jsonl'|'acp-stdio'|'provider-http';
  auth: 'authenticated'|'login-required'|'unknown'|'not-applicable';
  authMethod: string|null;            // только тип метода; никогда не токен
  models: SelectableCapability<{ id: string; label?: string; reasoningEfforts?: readonly string[] }>;
  reasoningEfforts: SelectableCapability<string>;
  sessionResume: Capability<'native-id'|'replay-context'>;
  eventStream: Capability<'jsonl'|'acp-updates'|'text'>;
  mcp: Capability<'stdio'|'http'>;
  cancellation: Capability<'turn'|'process'>;
  limits: { maxTurns?: number; maxOutputBytes?: number; timeoutMs?: number; usage?: 'reported'|'not-reported' };
};

type AgentAssignment = {
  agentId: string;
  roleId: string;                     // built-in Planner/Executor/Verifier or user-defined
  providerId: string;
  modelId: string|null;               // null means provider's actual default, reported separately
  reasoningEffort: string|null;       // validated against advertised capability
  instructionsRef: string;
  mcpToolIds: readonly string[];      // ADAPTANT host allowlist; not an agent authority grant
  limits: { deadlineMs: number; maxTurns: number; maxOutputBytes: number; maxRetries: number };
  sessionPolicy: 'fresh'|'resume-owned'|'stateless';
};

type AgentTurnRequest = {
  turnId: string; taskId: string; agentId: string; roleId: string;
  prompt: string; artifactRefs: readonly string[]; schemaId: string;
  sessionRef?: string; deadlineAt: string;
};

interface AgentProvider {
  probe(): Promise<ProviderDescriptor>; // fresh non-secret auth/capability status; no model call required
  start(request: AgentTurnRequest, signal: AbortSignal): Promise<RunningAgentTurn>;
}

interface RunningAgentTurn {
  events: AsyncIterable<NormalizedAgentEvent>;
  cancel(reason: 'user'|'deadline'|'shutdown'): Promise<'cancelled'|'already-finished'|'unknown'>;
  completion: Promise<AgentTurnResult>;
}
```

`NormalizedAgentEvent` has monotonic local sequence, event kind, provider timestamp if known, safe payload/ref and stream source (`stdout`, `stderr`, `acp`). Before parsing an agent's final structured response, ADAPTANT persists its exact bounded response bytes as a private task artifact, linked to `taskId`, `agentId`, `roleId`, `turnId`, request digest and provider execution reference. Record artifact SHA-256, byte count, response format, parser/schema version and resulting validated payload digest. The parser reads only those persisted bytes. On recovery, verify the artifact digest and rerun the same parser/version without new inference; if artifact or parser version is unavailable, mark the turn incomplete and require an explicit new turn. Prompts and full transcripts remain disabled by default. Artifacts must not contain credentials/secrets; if a response contains a detected secret, reject persistence and mark the turn failed/incomplete under the secret-handling policy. Raw stdout/stderr outside this final payload is bounded in memory only; persist redacted diagnostics, never auth headers, environment or unredacted stderr. `AgentTurnResult` separates configured model from actual model, session ref, exit/cancel outcome, typed failure (`AUTH_REQUIRED`, `QUOTA`, `RATE_LIMIT`, `TIMEOUT`, `OUTPUT_LIMIT`, `PROVIDER_ERROR`, `PROTOCOL_ERROR`, `CANCEL_UNCONFIRMED`), usage, and safe artifact refs.

The selectable model/reasoning lists must come from a fresh `cli-probe` or `acp-initialize` response for the installed provider version and current auth context. A static documentation entry can describe a provider, but is never a selectable model/effort and never substitutes for a missing live capability. UI must hide/disable model or reasoning selection when the live probe reports unsupported, unavailable, expired, or unknown; it must not synthesize defaults. Cache a successful capability response only for a bounded freshness window and invalidate it on executable/version/auth-context change. `reasoningEffort=null` means provider default only when the live provider capability explicitly supports that default.

### Contract rules

1. **Discovery and auth.** Discover exact executable path/version asynchronously. Probe auth only through a documented CLI/API status or a bounded harmless request; otherwise return `unknown`. Use the existing CLI/Harness credential store. ADAPTANT never reads or copies provider credentials. A missing CLI, unauthenticated account, quota or unsupported capability is a visible state, not MOCK.
2. **Start and events.** Pass prompt over stdin/structured transport when possible; bound input, output, time and turns. Keep stdout protocol and stderr diagnostics separate. Persist only normalized/redacted events and artifact refs. A zero exit code or natural-language answer is not a Plan or PASS.
3. **MCP and provider-native tools.** ADAPTANT owns the MCP server and starts it or exposes a local authenticated endpoint. Each MCP connection is bound to server-held scope `{taskId, agentId, roleId, turnId}`; every call revalidates that the assignment/turn is active, `toolId` belongs to that assignment's allowlist, arguments match the tool schema and host policy, and task revision/approval preconditions still hold. Never trust caller-supplied identity or provider/CLI allowlists as authority. Record each accepted/rejected call and safe result in the ADAPTANT task journal. Planner gets read-only planning tools; Executor gets only approved operations and explicit task-scoped tools; Verifier gets read-only evidence/result tools. Provider-native file, shell, browser, web and other built-in tools must be disabled or reliably restricted for the assigned role, or the agent must run inside a separately bounded environment that enforces those restrictions. MCP allowlisting alone does not isolate a provider. If neither control can be demonstrated for a CLI/version/role, that provider does not pass qualification for the role. A CLI sandbox is defense-in-depth and does not constrain calls to external MCP servers.
4. **Cancellation.** Prefer a provider's turn-level cancel; otherwise terminate the owned process tree. Await an acknowledged terminal state within a bounded grace period. If a tool action may have crossed its dispatch boundary and cancellation is unconfirmed, mark it `UNKNOWN/INCONCLUSIVE` and reconcile before any retry. Never repeat an unknown mutation.
5. **Sessions and recovery.** A provider session ID is an opaque per-task/per-agent reference. Start fresh by default. Resume only the exact session created for that assignment and only when the provider advertises it. Record whether resume restores transcript, just state, or neither. ADAPTANT's own task journal is authoritative; provider conversation history is advisory context. Do not copy sessions between clients or roles automatically.
6. **Models, reasoning and limits.** Capability catalogs are per provider executable/version/account. UI lists only discovered models and supported effort values; actual model used is recorded independently from requested/default model. If the provider omits its actual model, store `actualModelId=null` and `actualModelStatus=UNREPORTED`; a successful real call can qualify transport/auth, but cannot support a model-specific claim or model-specific qualification gate. `auto` means provider default only if the provider documents it. Usage and quotas may be unknown; expose unknown instead of inventing cost or capacity.
7. **Failure policy.** No silent fallback across providers or into MOCK. Changing provider requires explicit user selection (or an explicit persisted routing policy), a fresh availability check, and new provenance. Retries are bounded and only for classified transient failures; no automatic retry after unknown tool/mutation outcome.

## 5. Multi-Agent Role & Model Configuration

- A task has an ordered role graph: sequential edges, optional parallel groups, and required input/output artifact schemas per edge. Arbitrary assignment count is allowed within configured resource limits. Each edge names the upstream assignment and accepted artifact schema IDs. The host publishes an artifact to downstream work only after validating its task ownership, producing turn, schema/version, digest and policy; it then passes those immutable artifact refs in the downstream `AgentTurnRequest`. The receiver must revalidate task ownership and schema before use. Parallel branches exchange artifacts only through the same host-accepted handoff; agents cannot pass unrecorded private outputs directly to each other.
- A user can assign one provider/model to multiple roles or separate providers. The task snapshots the selected configuration version when execution starts; later UI edits affect a new plan/run, not active work.
- Presets are editable named configurations, not provider capabilities. Project/task assignment overrides must be visible and auditable.
- `Planner` returns validated `PlanDraft`; only owner confirmation creates an approved plan. Planner tool access stays read-only.
- `Executor` can call ADAPTANT MCP tools, but host validation, user plan approval for dangerous actions, server-side MCP authorization and Execution Foundation remain mandatory. These controls apply to ordinary QA and optional protected attestation alike. Executor output is a claim plus artifact refs.
- `Verifier` starts with a fresh context and independently reads persisted Task/Execution/evidence through ADAPTANT tools. It may use the same provider/model as Executor; that is not provider independence. It receives criteria and evidence refs, not Executor's unverified conclusion as truth. Agent verifier findings are advisory input. The ordinary QA result is issued by the existing host verification path from independently read facts and required checks; it does not require Trust Foundation or imply attestation. A separate optional protected-attestation mode may produce an attestation label `TRUSTED_PASS` only when an accepted Trust Foundation is available. This label is report metadata/attachment, not a new value in frozen `Verdict` schema 0.1. Never promote ordinary QA `PASS` to `TRUSTED_PASS` automatically.
- For agent-test acceptance, Luna GPT-6 is the requested independent reviewer of the recorded route and evidence. Luna review is an evaluation step, not a runtime provider, model-selection option, or replacement for the external CLI agent and host verification.
- Parallel roles may run only where the host scheduler proves their declared tools and artifacts do not conflict. Mutating operations serialize by resource/fixture/environment. A model cannot declare itself independent or waive an approval.

## 6. Журналы, результаты и восстановление

Использовать существующий `TaskStore` и `TaskService` как владельцев состояния и переходов. Добавить лишь записи назначений, ходов и ссылок на артефакты после отдельного контракта; не вводить новый подписной/криптографический контур.

Минимальная запись события: `taskId`, `seq`, `eventId`, `at`, `agentId`, `roleId`, `providerId`, `providerVersion`, requested/actual `modelId`, `turnId`, `kind`, typed `outcome`, redacted `payload` или `artifactRef`. Отчёт связывает поручение, snapshot команды, версию плана, одобрение, MCP-вызовы, Execution run, независимое чтение и evidence refs.

Артефакты (валидированный план, safe event stream, результат чтения, скриншоты/DOM согласно текущей политике маскирования) сохраняются через существующий TaskStore и его artifact boundary. Текущий `TaskStore` по умолчанию вызывает directory fsync (`syncDirectoryDurably`); в Windows этот путь ранее завершался `EPERM`. Поэтому этот контракт не утверждает, что текущая реализация уже подходит. Предлагается отдельный явно названный режим `process-crash`: запись полного файла и fsync файла, атомарный rename, затем проверка envelope/ссылок после рестарта. Неполную/пропавшую запись считать `INCOMPLETE`; не проигрывать снова ход или мутацию. Этот режим не гарантирует сохранение последнего rename после потери питания, не добавляет обязательный Windows directory fsync и должен пройти отдельный contract review и локальную Windows-проверку до применения. Существующий строгий режим не отключать молча.

Внешний transcript может содержать чувствительные prompts, команды или результаты. По умолчанию сохранять только структурированные события и редактированные diagnostics; raw transcript держать выключенным. Ошибка сохранения результата не превращается в успешную завершённую задачу.

## 7. Минимальный workpack после contract review

### WP-AP-01: один реальный CLI/Harness адаптер

**Кандидат:** Codex CLI; подтверждение выбора только после qualification его текущей авторизации и безопасного MCP вызова. Cursor Agent, Kimi Code ACP, Qoder ACP и DSH ACP остаются заменами-кандидатами, не обязательными зависимостями.

**Владелец:** основной агент интегрирует контракт и TaskService; исполнитель адаптера меняет только новый provider package/tests, назначенный после review; Luna независимо проверяет contract и итоговый путь. Один пакет не меняет `packages/contracts` или Trust API без отдельного change proposal.

**Область:**

- Реализовать только provider discovery/probe, запуск одного Codex хода, bounded JSONL stdout/stderr parser, нормализованные события, turn cancellation, typed errors, provenance фактической модели либо `UNREPORTED` и safe session policy `stateless`.
- Добавить provider selection в UI для доступных/недоступных статусов; MOCK оставить лишь явно выбранным режимом теста, показывать его provenance.
- Подключить к уже существующим `TaskService`/`TaskStore`, `PlanDraft` validation, owner confirmation, host-owned ADAPTANT MCP server и `Execution Foundation`. Не менять существующий Browser/Verification core в этом пакете.
- Не расширять в первом пакете произвольную параллельность; подтвердить схему role assignments, заложенную выше, но первая цепочка — Planner → owner approval → Executor → independent Verification.

**Запреты:** нет Ollama; нет обязательного API key; нет внешнего API собственного клиента; нет QA-v2 runtime; нет безусловного доступа к shell/filesystem; нет MOCK fallback; нет Dev-мутаций без подтверждённых environment/account/object refs.

Обычный локальный QA E2E не зависит от WP-08/TAS и не меняет замороженные схемы 0.1. Owner approval опасных действий, host validation и проверка полномочий MCP остаются обязательными. Protected attestation — отдельный необязательный режим после принятия Trust Foundation; обычный QA `PASS` не означает `TRUSTED_PASS`, а метка аттестации не добавляется в `Verdict` schema 0.1.

**Gate живого qualification:** подтверждённый auth status до/после вызова, version, безопасный запрос на синтетический Task, вызов только тестового MCP read-only инструмента ADAPTANT, раздельные stdout/stderr events и exit result, отмена завершает тот же owned process/turn, повтор после отмены/рестарта не создаёт новую задачу автоматически. Записать фактическую модель либо `UNREPORTED`: во втором случае qualification ограничен проверенными auth/transport/tool/cancel свойствами и не даёт model-specific утверждения.

**Gate первого продукта:** пользователь свободным текстом создаёт Task → внешний Planner создаёт валидируемый draft → пользователь подтверждает → назначенный Executor вызывает настоящие инструменты ADAPTANT → существующий runtime выполняет безопасный локальный business scenario → Verification Worker с новым контекстом независимо читает сохранённые факты → отчет содержит Task/plan approval/run/evidence provenance. Это локальный E2E gate, не Dev E2E и не считается завершённым при одном `codex exec` ответе. Dev E2E может быть заявлен только отдельным прогоном после подтверждения environment/account/object refs и помечается отдельно.

**Отчёт пакета:** изменённые файлы, реальные команды и exit results; отдельно auth, CLI execution, local Browser, Verification; фактическая/неизвестная модель и лимиты; события cancel/recovery; открытые ограничения; независимый verdict Luna. Любая неподтверждённая часть помечается явно.

## 8. Границы контракта

- Не меняет `docs/contract-freeze.json`, Scenario/Operation/Fixture/RunProtocol/Evidence/Verdict schemas, TrustRoot, WP-08/TAS, ЦИЗ или исходный 23-шаговый текст.
- Не признаёт старый PlannerProvider contract принятым для Agent Provider Layer; его методы `availability/plan` слишком узко выражают роли, модели, сессии, события, MCP, отмену и capabilities.
- Не принимает старый 0.3.2 снимок: незакрытое замечание Luna о Windows directory fsync остаётся историческим блокером заявленной durability того снимка. Для TaskStore предложен отдельный `process-crash` режим с более узким обещанием; существующая реализация и её default не меняются без contract review.
- Не использует local MOCK для qualification реального агента.

## 9. Решения, зафиксированные владельцем

1. Единый `AgentProvider` и граница TaskService ↔ MCP ↔ Execution — приняты.
2. `openai-chatgpt = PLANNED_UNAVAILABLE` при отдельной записи `codex-cli` — принято.
3. Произвольные role assignments и DAG — архитектурная цель; первый пакет идёт последовательной цепочкой — принято.
4. `process-crash` — условно принято только как отдельное направление после самостоятельного review и Windows-проверок; реализация и заявление durability не входят в этот этап.
5. Codex CLI — первый кандидат на qualification, но не обязательная продуктовая зависимость — принято.

Владелец принял архитектурное направление и перечисленные решения, потребовав три корректировки перед заморозкой. Luna GPT-6 выдала финальный ACCEPT после внесения корректировок; этот коммит фиксирует замороженную редакцию. `process-crash` остаётся отдельным условным предложением.
