# ЦИЗ — граница следующего адаптера

Текущее состояние: **SOURCE_DISCOVERED**, production adapter не реализован. Подтверждения и ревизии: docs/CIZ-SOURCE-AUDIT.md. runtime 0.1 первоначально допускает только localhost; нельзя просто заменить baseUrl на Dev.

Public frontend HTTP client использует gateway prefix; backend route `/tasks/{taskId}/create-action` не равен полному public URL без проверки baseURL/proxy rewrite. Ответ `{action_id}` — TaskAction ID. GET `/actions/{action_id}?ack_notifications=false` возвращает wrapper task/actions; false обязателен, поскольку default GET подтверждает уведомления (это уже мутация). Не считать любой GET автоматически read-only.

Пункт7: нужная форма `src/components/ReferenceBook/TypeActionsPage.jsx`, не `TaskActions/AddProgressModal.jsx`. Локальная история frontend commit 3ed7969c и backend migration p6e1a3c5d7f9 подтверждают удаление category field. Это сильное source evidence, но не доказательство deployed Dev. Существование категории «Общие» было данными справочника, его ID не выдумывать.

Контракт production adapter должен предоставить: operation classification, разрешённый public origin/path, отдельную авторизацию read client, идентичность окружения, schema validation/normalization body, read-only endpoint, identity/ownership proof, async effect deadlines, allowlisted redaction, безопасные fixture refs. Неполный runtime fingerprint/unknown schema явно диагностируются. Credentials хранятся отдельно; старые аккаунты не копируются автоматически.

Необходимые гарантии до мутации: подтверждённый тестовый scope; фиксированный parentTaskId/departmentId/executorId/customerAddressId/action type; разрешённые побочные эффекты; надёжный fixture marker/корреляция. Если API не поддерживает marker в сохраняемом поле, спроектировать проверяемую привязку через заранее выделенный fixture parent и уникальный creation request, документировать ограничения и получить review. Временная близость/похожее имя не заменяют ownership.

Склад/платность/закрытие отдельно после OP-B. Никаких реальных mutations в текущей исходниковой фазе. Верификация OP-F требует прямой связи generated manager action/comment с completed action; при отсутствии такой связи verdict INCONCLUSIVE, не PASS по соседним датам.
