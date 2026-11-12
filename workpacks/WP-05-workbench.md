# WP-05 — наблюдаемый Workbench

Исполнитель Kimi. apps/workbench + tests/ui*. React Flow и Dockview допустимы после проверки лицензий/зависимостей, старый UI не копировать монолитом. Вход public Control API, contracts, intelligence draft API.

Русский интерфейс, чёрный/графит/белый/приглушённое золото. Разделы Сценарии, Выполнение, История, Настройки. На выполнении одновременно граф и настоящий браузер; детали по выбору, без двух широких постоянных боковых панелей. Docking, resize, maximize, tabs, versioned layout persistence. Удобство при 1280×828 проверить реальным браузером.

Scenario Studio: граф node/edge editing, properties, draft approval/version history, supported actions по compiler capabilities; не изображать unsupported DAG исполняемым. Execution Graph строится из actual journal IDs/parents, технические следования показывать отдельно от causality. Выбор узла synchronizes evidence, historical frame и checks; кадры истории явно помечать. Live Browser — фактический поток, heartbeat age, disconnected state; никакой анимации для имитации действий.

Закрытие UI не останавливает workers. SSE/reconnect с cursor/history. Cancellation идемпотентна. Evidence Inspector redacts, показывает artifact hashes/provenance/independent reads/verdict reasons. Replay — просмотр и отдельный новый run, не запуск mutation при прокрутке истории. Финальная приёмка: открытие, перезагрузка, disconnect/reconnect, stale screenshot, keyboard usability, полный approved scenario. Local UI tests не заменяют Dev бизнес-проверку.
