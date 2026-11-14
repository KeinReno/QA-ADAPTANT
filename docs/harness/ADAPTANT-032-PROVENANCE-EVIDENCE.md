# ADAPTANT 0.3.2 — Provenance Evidence

Для каждого MODEL вызова создаётся durable intent с taskId/requestId, исходным поручением, его digest, точными байтами inference request и настроенной моделью. Provider response receipt имеет неизменяемый `RECEIVED`, фактические байты, длину и digest, provider/configured model, время получения, status/content type и backend reference. После проверки сохраняются отдельное событие с подтверждённым backend model ID и digest разобранного plan result, затем версия ExecutionPlan связывается с receipt. Изменение байтов обнаруживается при чтении.

Восстановление использует сохранённые байты ответа, не повторяет inference; незавершённый вызов без сохранённого ответа не переигрывается. Секреты не включаются в UI/API поля и события; model request содержит только task/context данные, предусмотренные host контрактом.

Проверки тестами: сохранение до parse, model mismatch rejection, отсутствие fallback, recovery без повторного запроса и tamper detection — PASS в `tests/planner.test.mjs` (10/10).
