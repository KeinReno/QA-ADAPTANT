# Обязательные отказы §13 — план проверок

Это список обязательств; фактический результат только в ACCEPTANCE-REPORT и выводе тестов. Каждому кейсу требуется свой временный run directory и уникальный fixtureId.

| № | Инъекция | Ожидаемый результат | Существенная проверка |
|---|---|---|---|
| 1 | Ответ потерян после сохранения | INCONCLUSIVE, объект обнаруживается read-only | mutationCount=1, нет выдуманного response proof |
| 2 | Объект сохранён, comment пропущен | FAIL после deadline при полном authoritative read | main effect SATISFIED, comment VIOLATED |
| 3 | read-model запаздывает | PASS только после подтверждения в пределах budget | bounded reads, ни одного повторного POST |
| 4 | Сохранён чужой executor | FAIL | ownership верно, executor check VIOLATED |
| 5 | Две одинаковые кнопки в нужном контейнере | BLOCKED/ELEMENT_AMBIGUOUS | mutationCount=0 |
| 6 | Browser crash после мутации | INCONCLUSIVE, reconciliation | restart не повторяет POST |
| 7 | Артефакт недоступен/искажён | INCONCLUSIVE/EVIDENCE_MISSING или INTEGRITY_ERROR | PASS запрещён, verifier действительно читает диск |
| 8 | Сценарий изменён после approval/для restart | BLOCKED CONTRACT_INVALID либо исходный frozen snapshot | нельзя принять новые ожидания старым approval |
| 9 | environment revision меняется | BLOCKED до мутации / INCONCLUSIVE после | нет сравнения unknown==unknown как proof |
| 10 | Browser сообщил неподтверждённый ID | INCONCLUSIVE | ID сравнивается request→response→independent read, чужой объект не принимается |
| 11 | Часть обязательных эффектов не завершилась | FAIL если доказано нарушение, иначе INCONCLUSIVE | все effect IDs отражены, ни одного ложного PASS |
| 12 | Очистка получила чужую сущность | Отказ без удаления | объект остаётся, отсутствие delete capability — допустимый первый барьер |

Дополнительные guards: intent ACK потерян, duplicate intent, duplicate START, cancellation до/после dispatch, illegal origin/redirect, wrong input body, cross-run evidence, duplicate checks, conditional unknown, manifest tamper, orphan children, incomplete journal tail, running-lock conflict. Не выдавать pure unit simulation за process-crash integration. Сценарий «restart» должен действительно читать persisted run в новом Control процессе.
