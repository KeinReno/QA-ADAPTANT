# Этап A — архитектурная подготовка Execution Foundation

Статус: **ACCEPT архитектурного review Luna; код не реализован**  
База: `1a510a5d5929534d400dc965f58c78cf468bc270`  
Ветка: `feat/adaptant-03-execution-foundation`

## Артефакты

- `ADAPTANT-03-EXECUTION-ARCHITECTURE.md` — модули, интерфейсы, границы и ограничения.
- `ADAPTANT-03-TASK-LIFECYCLE.md` — Task/step lifecycle, отмена, recovery и результат.
- `ADAPTANT-03-PLANNER-CONTRACT.md` — PlannerProvider, формат PlanDraft и правила проверки.

## Установленные факты и решения

- Trust Foundation 0.2 экспортирует публичный trusted фасад через `apps/control/trusted.mjs`. Task Orchestrator не импортирует private trust implementation и не принимает бизнес-вердикт из результата Browser Worker.
- RunStore остаётся владельцем trusted run snapshots/evidence; Task Store будет отдельным хранилищем поручений и task journal.
- Planner выдаёт только draft; capabilities и risk — предложения, не полномочия. Owner Task approval не заменяет Trust approval сценария/операции/входов.
- `startTrusted` возвращает технический результат runner; trusted status и verdict отдельно получают через `observeTrusted`. `reconcileTrusted` может менять состояние run при recovery.
- Bundle и стабильный `runId` фиксируются до dispatch. После неопределённого исхода запрещено повторять `startTrusted` или пересоздавать bundle для прежнего intent.
- Полный auth-пример пользователя несовместим с текущим Scenario 0.1.0, который ограничен одной бизнес-мутацией и одной независимой проверкой, а имеющийся local bundle проверяет только `create-record`. Такой запрос должен оставаться `BLOCKED/UNSUPPORTED_EXECUTION_SHAPE`, пока нет отдельного утверждённого сценария.
- Изменения Trust Foundation, frozen contracts и ветки аудитора не нужны для этапа B.

## Независимое review

Reviewer: Luna (отличен от автора документов).  
Первичный результат: `REJECT`, две P1 и одна P2 находки.  
После исправлений: `ACCEPT`, оставшихся архитектурных расхождений нет.  
Review сверял документы с базовым SHA `1a510a5d5929534d400dc965f58c78cf468bc270`. Review не является подтверждением тестов или реализации.

## Проверки

- Архитектурные документы: просмотрены независимым reviewer Luna, результат `ACCEPT`.
- Unit/contract/integration/E2E тесты: **NOT RUN** — этап A изменял только документацию, модулей ещё нет.
- Полный gate Trust Foundation: **NOT RUN** на этом feature-worktree; опубликованные WP-08 результаты относятся к SHA из их отчётов и не приписываются текущему SHA.

