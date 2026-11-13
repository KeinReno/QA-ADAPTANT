# ADAPTANT 0.3 — независимый gate принятия Task PASS

Статус: **ACCEPTED Luna для внутреннего контракта Execution Foundation 0.3; подключение Trust verifier остаётся в Stage C**  
Основание: независимый review Luna Stage B от 13 ноября 2026  
Область: только новый контур `packages/execution/**` и `apps/orchestrator/**`; Trust Foundation 0.2 и его контракты не меняются.

## Изменение

`TaskStore` больше не принимает `taskOutcome=PASS` только на основании caller-supplied полей `trustedVerification`, `runIds` и `evidenceRefs`. Для сохранения PASS требуется настроенный fail-closed callback `verifyTaskPass({task, plan, result})`, который независимо читает trusted outcome и evidence chain для каждого обязательного шага. Ошибка callback, отсутствие проверяющего или несовпадение любой ссылки отклоняет запись с `UNVERIFIED_TASK_PASS`.

Callback вызывается после структурной проверки результата и до записи завершающего journal event. Он получает текущий Task, immutable plan и весь результат; проверка проводится под TaskStore mutex, чтобы результат не был принят для уже сменившейся версии Task/plan.

В том же implementation clarification host разрешает `executionRef` только в пересечении зарегистрированного execution catalog и `approvedScenarioRefs`; `Task.contextRefs` не подменяет этот каталог. Validator сверяет полные пары `{ruleId, requirementId}`. Перед dispatch TaskService проверяет, что adapter поддерживает каждую запрошенную capability шага. Recovery перечисляет результаты по Task: повреждённый journal отражается как integrity-blocked без изменения его содержимого, а ошибка активного immutable plan блокирует pre-dispatch состояние или делает уже dispatch-нутое состояние `INCONCLUSIVE`.

## Совместимость и проверка

- Не меняются Scenario/Run/Evidence/Trust contracts 0.2.
- TaskResult сохраняет текущую схему 0.3; callback является внутренним обязательным gate хранения PASS.
- Этап C должен подключить callback к публичному trusted observer/evidence verifier. До такой интеграции PASS остаётся недоступным в реальной сборке.
- Unit-тест может использовать локальный verifier double только для проверки fail-closed пути; он не является Trusted E2E или доказательством Dev.
