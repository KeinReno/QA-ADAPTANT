# Тестовые данные

Машинная форма: FixtureContract. Уникальный fixtureId связан ровно с одним runId/environmentId. credentialRef — ссылка, не секрет. roles согласованы с operation. selectedEntities разрешены владельцем тестового контура и выбираются до мутации. allowedMutations проверяется against operation.mutation.name. namespace ограничивает область. authorization фиксирует человека/оператора и scope; локальный harness может утверждать только собственные localhost данные, не Dev.

Принадлежность — marker fixtureId, подтверждённый независимым чтением, плюс response/request entity identity. Тестовый marker в названии без независимой связи недостаточен. Очистка только вручную после отдельной проверки владения; production adapter удаления в первой версии отсутствует. Unknown mutation — read-only reconciliation, повтор запрещён.

Склад, клиентские адреса, аккаунты автора/исполнителя/менеджера и платность требуют подтверждённого безопасного набора. Существующие локальные credential locations можно инвентаризировать без значений; перенос выполняется явно и не даёт автоматического разрешения на любые данные Dev.
