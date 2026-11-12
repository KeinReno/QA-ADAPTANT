# WP-03 — ЦИЗ adapter и безопасная бизнес-операция

Исполнитель Kimi. Владение adapters/ciz, tests/ciz*, docs/CIZ-*. Источники read-only C:/Users/gvi/Desktop/CIZ/{task_manager_front,tasks_manager,micro_services}; архивные QA — только анализ. Не переносить .env/сессии в документы. Вход: docs/CIZ-SOURCE-AUDIT.md, CIZ-ADAPTER.md, core public API.

1. Подтвердить цепочку public gateway → backend/auth/service и ревизии runtime отдельно от local git.
2. Инвентаризировать имеющиеся credential locations без значений. Автор/исполнитель/менеджер отдельные контексты. Проверить авторизацию /me+UI context, не только token.
3. Подготовить конкретный preflight read-only отчёт: URL, runtime fingerprint и неизвестные части, account roles, разрешённые parentTask/customerAddress/executor/department/type IDs, fixture marker и безопасная область. Для опасных mutations сначала получить отсутствующее подтверждение владельца.
4. OP-B create-action: установить реальный payload/response, X-Ciz-Id, action ID, независимый read по ID. Proof принадлежности должен связывать fixture→request→response→read; отсутствие надёжного marker/контрольного поля не обходить title matching.
5. Добавить read-only проверку формы справочника пункта7 (не спутать с AddProgressModal из пункта14). Сопоставить исходники и фактическую форму, дать ограниченную диагностику.
6. После gate реализовать OP-A/C/D/E/F отдельно: contract JSON, source evidence, fixture constraints, positive/negative tests. Менеджерское задание и комментарий должны причинно ссылаться на исходное action, временное соседство недостаточно.

Выход: доказанный 0.1 OP-B; затем полный 23-шаговый run только после утверждения исправленной версии. Любые missing facts = BLOCKED/INCONCLUSIVE. Отчёт отдельно localhost/source/runtime Dev. Не включать токены/headers/пароли/неотредактированные bodies/screenshots.
