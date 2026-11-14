# ADAPTANT 0.3.2 — Planner Implementation

Статус: PARTIAL; код и локальные integration tests подготовлены. Контракт ответа принят независимым reviewer Luna; review реализации ожидается отдельно.

Реализованы: Ollama provider с loopback-only HTTP, явным model ID, availability check, JSON schema, лимитами, AbortSignal и строгим разбором; ограничение ACL PlannerResponse store; staging и durable sidecars для запроса/ответа; append-only provenance события; связь model plan с response receipt; чтение legacy plan; UI статус provider/model и планирования.

Точные байты HTTP response сохраняются до разбора. Plan не публикуется без durable response artifact и проверенного backend model ID. Планы MODEL содержат ссылку на артефакт и проверяются при чтении. MOCK сохраняет отдельный provenance.

Локальная проверка `node --test tests/planner.test.mjs`: 10/10 PASS. Полный regression gate не пройден: см. `ADAPTANT-032-FINAL-REGRESSION.md`.
