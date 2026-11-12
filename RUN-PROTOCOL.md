# Протокол

Машинная форма: RunProtocol — manifest команды, не весь журнал. Snapshot сохраняет точные scenario/operation/fixture bytes и hashes. START idempotency: один commandId/runId даёт существующий запуск; другие payload для тех же IDs отклоняются. Повтор START не повторяет действия. OBSERVE — только чтение. CANCEL — идемпотентный переход; терминальный результат неизменяем. RECONCILE — только чтение.

CREATED → PREFLIGHT → RUNNING → VERIFYING → FINISHED.
Неизвестность мутации/worker loss: RUNNING → RECONCILING → FINISHED.
Отмена до мутации: BLOCKED/CANCELED; после durable intent: INCONCLUSIVE/CANCELED, зарегистрированные сущности сохраняются. Ошибка preflight → BLOCKED. После FINISHED новые evidence/actions запрещены.

Смена fingerprint во время запуска → остановка, ENVIRONMENT_CHANGED; после мутации INCONCLUSIVE, до неё BLOCKED. null sourceRevision никогда не означает совпадение с Dev. fingerprint локального стенда — явная revision; промышленный fingerprint требует проверяемого deployment/API/schema свидетельства. Недостаточная идентичность → BLOCKED либо отдельное подтверждённое ограничение, без обещания обнаружить любой backend deploy.

Восстановление читает persisted intent до любого запуска browser. Неполная последняя запись журнала — INTEGRITY_ERROR; не «чинить» её молча. Запись файлов через temp+fsync+rename, последовательный append журнал; завершение сохраняется один раз. process isolation не равна распределённому консенсусу; ядро однопользовательское, один Control Plane.

Network policy 0.1: только http://127.0.0.1:<явный порт>/ и adapter=local, стенд создаётся самим harness. Browser intercept запрещает любой чужой origin, websocket и произвольные POST (единственный allowlist POST /records). Verification GET только /environment и /records; redirect запрещён, cookies/credentials отсутствуют. localhost URL сам по себе не авторизация: preflight требует handshake fingerprint созданного harness, отдельный случайный nonce экземпляра. Нельзя указать произвольный локальный сервер вместо стенда. Production CIZ URL пока отклоняется контрактом; поддержка через новую reviewed версию.

Nonce экземпляра хранится как случайный environment.id, связывает fixture.environmentId и durable manifest. /environment обязан возвращать его вместе с fingerprint. Проверить до запуска и после мутации/чтения. Nonce — идентичность локального стенда, не секрет авторизации и не production fingerprint.
