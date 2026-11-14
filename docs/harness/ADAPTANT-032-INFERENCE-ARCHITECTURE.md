# ADAPTANT 0.3.2 — Inference Architecture

Статус: PARTIAL. Архитектура и локальная интеграция реализованы; настоящий inference E2E не выполнен.

## Поток

`TaskService` строит ограниченный запрос из поручения и host action catalog. `OllamaPlannerProvider` проверяет loopback endpoint и наличие настроенной модели в `/api/tags`, формирует запрос `/api/chat` со structured JSON schema и без инструментов. Ответные байты сохраняются в `TaskStore` до JSON-разбора. Валидатор затем проверяет план относительно host registry, допустимых refs и execution adapters. Существующие owner approval, Trust approval, Trusted Adapter и независимое Verification остаются границами исполнения.

`PlannerProvider` отделяет transport и provider от Task Orchestrator. `MOCK` выбирается только явно; отсутствие модели Ollama даёт `UNAVAILABLE`, без fallback.

## Ограничения

MVP подключает только локальную Ollama. LM Studio и llama.cpp остаются будущими реализациями того же provider transport-контракта. Архитектурное предложение по неподтверждённому trustRoot остаётся отдельным от этого пакета.
