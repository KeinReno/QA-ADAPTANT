# ADAPTANT 0.3 — архитектура следующего этапа Real AI Planner

Дата: 2026-11-14  
Статус: предложение к следующему Workpack; inference backend в этом этапе не подключается.  
Текущий результат планирования остаётся `MOCK`; автономное планирование реальной моделью не реализовано.

## Цель

Подключать inference как реализацию уже существующего `PlannerProvider`, оставляя Task lifecycle, approval, execution adapter и Trust boundary хозяевому приложению. Planner возвращает ограниченный структурированный черновик плана. Он не исполняет действия, не выдаёт полномочия и не выбирает API напрямую.

Контракт сохраняет явные `id`, `mode`, `availability()` и `plan()` из `docs/changes/ADAPTANT-03-PLANNER-PROVENANCE.md`. Для фактического inference требуется `mode: MODEL`, точный `modelId` из конфигурации/ответа backend и сохранённый response reference. Если backend недоступен, модель неизвестна, ответ невалиден или metadata расходится, Task блокируется без fallback в MOCK или другой backend.

## Архитектурная граница

```text
TaskService
  └─ PlannerProvider (MODEL, host-registered)
       └─ InferenceTransport adapter (Ollama | OpenAI-compatible local | optional remote)
            └─ bounded HTTP response bytes + provider/model/request metadata

Raw response artifact ── digest/reference ── immutable ExecutionPlan
                                               └─ approved executionRef catalog only
                                                    └─ owner approval ── trusted adapter
```

Будущий provider adapter получает исходное поручение и ограниченный контекст через текущий `plan()` request. Вызов выполняется только через host-зарегистрированный provider. Provider registry выбирает ровно одну конфигурацию при запуске процесса; `availability()` описывает только её. Нет эвристики выбора по доступности, скрытой смены endpoint, автоматического повтора на другой provider или downgrade в `MOCK`.

Adapter передаёт модели только schema-constrained JSON запрос без tool/function declarations. Приёмная сторона всё равно ограничивает размер и время, разбирает actual response, проверяет точную provenance и применяет `PlannerResultSchema`/`validatePlanDraft`. Structured output — формат, не разрешение и не доказательство безопасности.

Execution refs берутся из host registry. Модель может предложить только ref, полученный как opaque identifier из утверждённого каталога в prompt; каждый ref повторно сверяется после ответа. Модель не может создавать capability, URL, shell command, browser locator API, privileged API или новый adapter. Неизвестное действие, свободный endpoint, отсутствующий ref, неподдержанный required step или неоднозначный объект делает план неисполняемым/Task `BLOCKED`.

## Адаптерный контракт для следующего этапа

Минимальный `InferenceTransport`:

- `id` и endpoint/config фиксируются host registry, не выводятся из prompt или ответа;
- `availability()` возвращает `status`, `providerId`, concrete `modelId`, `mode: MODEL`, а при отказе — явный `reasonCode`;
- `complete({ requestId, messages, responseSchema, signal })` возвращает ограниченный ответ с exact provider model identifier, exact response bytes/text и backend request reference, если backend его выдаёт;
- `plan()` сохраняет raw response до schema parse, затем создаёт normalized `PlannerResult`, добавляя host-known `providerId`, `modelId`, `mode` только из закреплённой конфигурации/проверенного metadata. Нельзя приписывать ответу модель, которую backend не подтвердил;
- timeout, cancellation, maximum response bytes, maximum prompt bytes, content type, JSON nesting/array bounds и отказ при trailing/invalid output обязательны;
- повтор запроса допустим только для той же idempotency/request reference, если транспорт доказывает безопасную идемпотентность. Иначе результат неопределёнен, автоматического повторного inference нет.

## Сохранение поручения и ответа

Исходное поручение уже сохраняется точно в Task journal. Будущий этап должен сохранять точные полученные response bytes до нормализации как отдельный закрытый `PlannerResponse` artifact с `responseId`, `taskId`, `requestId`, `providerId`, `modelId`, `receivedAt`, byte length и digest. В неизменяемом плане и журнале хранятся ссылка и digest; полный ответ не попадает в UI, обычный Task API, диагностический log, stdout/stderr, error message или тестовый snapshot.

Raw response должен быть ограничен по размеру, храниться в Task store с ACL только для текущего владельца/service identity и иметь заданную владельцем retention/deletion policy. Возможное наличие в поручении или ответе credentials, PII или других секретов означает, что для remote provider необходим отдельный opt-in и политика обработки данных до сетевого вызова. Локальная модель должна быть предпочтительным режимом по умолчанию; при отсутствии доступного local backend remote endpoint не вызывается молча.

Сырые байты и digest подтверждают только то, что локальный host сохранил полученное тело без изменения. Они не являются подписью модели и не доказывают, что текст сформирован заявленной моделью. Backend request ID и reported model ID — атрибуты транспорта, не аттестация.

## Способы интеграции

| Вариант | Возможности, подтверждённые первичной документацией | Практическое место |
|---|---|---|
| Ollama local API | `/api/chat` поддерживает JSON Schema через `format`; есть официальные JavaScript/Python библиотеки. [Structured outputs](https://ollama.com/blog/structured-outputs) | Хороший локальный первый backend с нативным API. Требуется проверить фактически загруженный model tag/digest и установленную версию; отдельный Node `fetch` transport избегает дополнительной зависимости. |
| LM Studio local server | Локальный REST и OpenAI-compatible endpoints; `/v1/chat/completions` принимает JSON Schema и может использоваться через стандартный клиент. [Structured output docs](https://lmstudio.ai/docs/developer/openai-compat/structured-output), [local server](https://lmstudio.ai/docs/developer/core/server) | Удобный локальный backend для взаимозаменяемого адаптера; configured model identifier нужно сверять с выбранной сервером моделью. |
| llama.cpp server | Локальный C/C++ сервер поддерживает OpenAI-style chat completions и schema-constrained `response_format`; поддерживает CPU/GPU и quantized models. [Server documentation](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md) | Низкоуровневый/ресурсно гибкий вариант; администратор сам поставляет модель, запускает сервер и обеспечивает доступность. Совместимость endpoint не гарантирует одинаковый prompt/template/JSON enforcement между моделями. |
| Hosted OpenAI-compatible backend | Можно подключить позднее отдельным transport без изменения `PlannerProvider`; concrete service/model/version должны быть явной конфигурацией. | Не включать по умолчанию: требует отдельного решения о передаче исходных поручений/ответов, credentials, стоимости и retention. В этом Workpack и коде не используется. |

По имеющимся фактам локальная машина Windows + Node доступна, но аппаратные характеристики и разрешённые модели не установлены. Поэтому нельзя выбрать корректную модель/quantization или обещать latency/качество. Следующий Workpack должен измерить CPU/GPU/RAM/disk и проверить выбранные кандидаты на реальном backend; документация возможностей не заменяет такой benchmark.

## План проверок следующего Workpack

1. Contract tests для `available MODEL`, concrete model ID, exact result provenance, raw response artifact, request/digest-to-plan binding и сохранения неизменных исходных байтов.
2. Поддельный HTTP backend: structured response, invalid JSON/schema, mismatched reported model ID, oversized body, timeout, connection refused, non-JSON content type, abrupt disconnect, cancellation.
3. Проверить, что все отказные случаи переводят Task в `BLOCKED`/`INCONCLUSIVE` по точке отказа и не делают fallback, повторный inference или `DISPATCH_INTENT`.
4. Тесты на prompt injection в поручении/ответе: неизвестные action types, API URLs, capabilities, adapter IDs и execution refs блокируются; валидный ref всегда сверяется с host catalog.
5. Проверить raw artifact ACL, retention/deletion, API redaction, отсутствие секретов в журнале и logs; провал artifact persistence не сохраняет исполняемый план.
6. Запустить сквозной тест с реально загруженной локальной моделью и проверить `MODEL` + настоящий model ID, exact saved response и plan provenance. Этот тест необходим, прежде чем заявлять о подключённой AI модели.
7. Только после отдельного ACCEPT владельца и независимого reviewer разрешать какие-либо Dev mutation сценарии; модель сама не может утвердить сценарий или вызвать Dev.

## Не входит в этот этап

- подключение модели или provider, установка модели и её benchmark;
- выбор удалённой API-службы, передача туда данных или API key;
- изменение Trust Foundation, API approval, execution registry или privileged browser/tool surface;
- утверждение AI-плана без владельца;
- заявление о production-ready, автономном или доверенном AI планировании.
