# Изменение контракта: однозначная Planner provenance

Статус: **предложение на независимое review Luna**  
Scope: ADAPTANT 0.3 Execution Foundation  
Исходный контракт: `docs/architecture/ADAPTANT-03-PLANNER-CONTRACT.md`  
Основание: Workpack LUNA-03.1, требование устранить неоднозначность `MODEL`/`MOCK`

## Проблема

Текущая координация сверяет `providerId` и `mode` ответа с provider adapter, но не сверяет `PlannerResult.modelId` с `availability.modelId`. Для `MODEL` допустимы `modelId: null`, а конфигурация `mode` может не указываться и молча приниматься за `MODEL`. Это позволяет неверно классифицированному тестовому ответу попасть в сохранённый план.

Исторический Stage C отчёт называл test provider значением `MODEL test-only`, хотя фактический E2E provider был локальным детерминированным test provider. Это исправляется отдельной errata записью; runtime E2E маркируется `MOCK`.

## Предлагаемая норма

`PlannerProvider` обязан иметь явно заданные локальной конфигурацией `id` и `mode` (`MODEL` или `MOCK`), а также реализовать `availability()` и `plan()`.

`availability()` возвращает строгий объект с `status`, `providerId`, `modelId` и `mode`:

- `AVAILABLE + MODEL` требует конкретный непустой `modelId`;
- `AVAILABLE + MOCK` требует `modelId: null`;
- `UNAVAILABLE` требует `reasonCode`, сохраняет локально настроенный `providerId` и `mode` и не вызывает `plan()`;
- `availability.providerId/mode` должны в точности совпадать с локальной конфигурацией provider.

Перед валидацией плана `PlannerResult.providerId`, `.modelId` и `.mode` должны в точности совпасть с локальным provider id/mode и объявленной availability. Несовпадение блокирует Task, не сохраняет исполняемый план и не включает fallback.

Сохранённый `ExecutionPlan.provider` принимает только согласованные пары: `MODEL` с непустым `modelId`, `MOCK` с `modelId: null`. Полная provenance (`providerId`, `modelId`, `mode`) хранится в связанном immutable `ExecutionPlan` и отображается в UI и отчётах. `TaskResult` содержит только `plannerMode`; он не заявляется как полная запись provenance.

Для локальных записей 0.3 до заморозки контракта пара `MODEL + modelId: null` после усиления схемы невалидна и должна fail closed: блокировка и явное перепланирование владельцем. Автоматической миграции, переписывания истории или вывода modelId из других полей нет.

## Доказательство и предел

Проверка обеспечивает согласованность локально настроенного adapter, его availability и структурированного результата. Это не криптографическая аттестация внешнего inference-вызова и не доказательство автономного AI Planner. Такой вывод возможен только после подключения host-зарегистрированного backend, фиксации provider response/request reference и отдельного сквозного испытания реальным inference backend.

Никакой provider fallback не выбирается. `UnavailablePlannerProvider` сообщает `UNAVAILABLE/NOT_CONFIGURED`; Task остаётся `BLOCKED`.

## Проверки

Добавить regression cases для:

1. provider id в availability не совпадает с host-конфигурацией;
2. локальный `MOCK` provider пытается вернуть `MODEL`;
3. `MODEL` availability не объявляет конкретный modelId;
4. mode availability расходится с локальной конфигурацией;
5. `PlannerResult.providerId` расходится с availability;
6. `PlannerResult.modelId` расходится с availability;
7. отсутствующая локальная mode-конфигурация отвергается;
8. unavailable provider не вызывает plan и не включает fallback.

## Вне scope

- Подключение или выбор модели, API-службы, транспорта либо платного backend.
- Изменения Trust Foundation, Task lifecycle, approval и других частей execution contracts вне описанного уточнения `ExecutionPlan.provider` provenance.
- Утверждение настоящего AI планирования.

Luna review: ожидается повторное review после замечаний.
