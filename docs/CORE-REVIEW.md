# Независимое review ядра — промежуточные findings

Статус: не финальный gate. Проверены read-only только `packages/core/canonical.mjs`, `packages/core/store.mjs`, `apps/browser/worker.mjs`, `adapters/local/server.mjs` в текущей рабочей копии QA-ADAPTANT. Control/verifier ещё пишутся; фактические тесты не запускались. Не повторяю замечания, уже переданные primary: отсутствующее `inputsSha256`, Map<Request,ID>, лишние body keys, WebSocket, один POST dispatch guard, symlink/no-overwrite/duplicate evidence IDs.

## CR-11 — P1 pending Control: Worker использует snapshot без собственной проверки frozen hashes

**Наблюдение.** `apps/browser/worker.mjs:61–64` напрямую читает `manifest.json`, `scenario.json`, `operation.json`, `fixture.json` из `runDir` в обычные JS-объекты. В worker до начала browser launch/action нет `validate()` и сравнения digest этих байтов с ожидаемыми hashes из manifest/Control. Далее он исполняет scenario nodes (114+), строит URL/body allowlist и inputs hash из прочитанных файлов. Передаваемый в INTENT `inputsSha256` также вычисляется из загруженного operation (131), так что сам по себе не доказывает, что это утверждённый snapshot.

**Black-box атака.** После создания/approval V1 заменить один или несколько snapshot файлов до запуска/restart worker, оставив approval/manifest hash старым; изменить например operation input и согласованное действие/форму, чтобы локальный fixture принял незапланированное значение. Проверить, что Control либо перед spawn проверяет exact persisted snapshot bytes и выдаёт неизменяемый bundle handle/expected hashes, либо worker сравнивает полученные hashes с доверенной Control-стороной. При несоответствии — отказ до navigate/click/POST, ни один mutating request не отправлен.

**Риск/статус.** Если нет независимого binding в будущих Control/verifier путях, принятый snapshot можно заменить, а Worker выполнит новый input под старым run/approval; это ломает frozen version и может привести к неутверждённой мутации. Пока это условный P1 gate: проверить контракт spawn, snapshot checks на Control стороне и отсутствие TOCTOU пути, прежде чем считать находку открытым дефектом. Враждебная полная перезапись владельцем диска сама по себе вне заявленной защиты; проверка требуется для зафиксированного scenario change/restart и повреждения snapshots.

## CR-12 — P1 candidate: event envelope позволяет caller подменить резервные поля и readEvents не проверяет порядок

**Наблюдение.** `packages/core/store.mjs:62–69`: `appendEvent` сначала ставит `{id, seq, at}`, затем делает spread `...event`, поэтому caller может перезаписать эти резервные поля. `readEvents` (`72–77`) JSON-parses строки, но не проверяет, что `seq` равен позиции, что `id` уникален или что event/run относится к конкретному run. Это отличается от `readEvidence`, где отдельные integrity checks есть.

**Black-box атака.** Через публичный event/IPC путь отправить допустимый event payload с поддельными `seq`, `id`, `at` (включая повтор seq/id или будущую дату); затем завершить и перезапустить новый Control на persisted run. Проверить, что данные caller не могут менять envelope metadata и recovery/summary отвергает пропуск/повтор последовательности или связывает запись с проверенными runId. Ожидается refusal/inconclusive до любой новой мутации, а не достоверный state из непроверенного журнала.

**Риск/статус.** Если Control использует events для восстановления lifecycle, recovery может прочитать противоречивую/фальсифицированную последовательность. Пока candidate до проверки будущего Control: если events — только diagnostic log и никакие verdict/replay решения оттуда не принимаются, severity ниже; если журнал участвует в recovery, это P1. Рекомендуемое исправление в коде владельцу store: собирать envelope из allowlisted event fields, удерживать `id/seq/at` только на стороне store и валидировать contiguous sequence/run identity при read. Я код не менял.

## Неподтверждённые интеграционные свойства

- `adapters/local/server.mjs` имеет полезные fault modes для lost response, partial save, wrong executor, foreign fixture и delayed read; сам по себе не доказывает, что Control/Verifier корректно классифицируют эти состояния.
- `worker.mjs` устанавливает один dispatch guard, блокирует неразрешённый origin/метод/path, сравнивает POST fields с operation inputs+fixture marker, требует durable INTENT ACK перед обработкой request; эти участки в текущем чтении выглядят согласованными с контрактом, но без дочерних процессов и black-box теста не принимаются.
- `store.mjs` формирует checksummed evidence artifacts и проверяет checksum/sequence/parents при чтении; межсвязи evidence с frozen manifest/fixture и источником producer должны быть проверены при review Control/Verifier.
- `canonical.mjs` реализует рекурсивную сортировку ключей и порядок массивов, однако соответствие всему домену контрактных значений/approval input без публичных тестов contract layer не объявляю принятым.

## Что остаётся до gate

После готовности Control/Verifier сначала проверить, устраняет ли Control CR-11 на реальной process boundary и использует ли CR-12 для восстановления. Затем выполнить отдельные black-box атаки против public APIs: crash/lost response без replay, tamper/frozen-version, forged/cross-run evidence, stale/unavailable read и coverage. До этих результатов ни одно локальное свойство и ни один P1 candidate выше не считаются принятыми или закрытыми.

## CR-13 — Reliability limitation: crash между записью artifact и envelope

**Наблюдение.** В `packages/core/store.mjs:79–100` `appendEvidence` вычисляет путь artifact из `previous.length + 1`, атомарно создаёт этот файл (`84–87`), после чего валидирует envelope и только затем append-ит его в `evidence.jsonl` (`96–100`). Сбой процесса или ошибка validation после создания artifact, но до envelope оставляет orphan. Следующий вызов с той же длиной journal снова выберет тот же filename и завершится ошибкой no-overwrite (`86`); текущий `readEvidence` проверяет только артефакты, на которые ссылается journal, и не восстанавливает orphan.

**Black-box атака.** Инъецировать exit/failure после durable artifact write, до journal append, при verifier write/read evidence. После нового verification phase повторить только независимое чтение (GET), затем сохранить новое evidence в том же run. Ожидается, что orphan не будет перезаписан и не заблокирует дальнейшую безопасную запись; или run явно остаётся `INCONCLUSIVE`, а recovery документированно требует отдельного нового прогона. Никакого мутационного повторения. Проверить artifact/evidence цепочку с диска.

**Риск/статус.** Verifier single-writer phase устраняет конкурентную запись, но не crash-window. После verifier crash/lost response повторная запись evidence в том же run может упереться в orphan artifact. По уточнению primary, в первом MVP допустим fail-closed `INCONCLUSIVE`; это ограничение восстановления, не повод скрывать результат или ослаблять no-overwrite. Отдельный crash/retry тест нужен, если MVP обещает повтор verification phase в том же run; пока это limitation, не самостоятельный release blocker. Схемы менять не требуется.

## Уточнение single-writer verifier phase: race и provenance gate

Предложенная схема приемлема по race condition, если она реализована как явная per-run verification phase/lease: Control заканчивает и fsync-ит свои записи, после чего не пишет в тот же journal, ждёт завершения verifier child и его durable RESULT, затем перечитывает файлы. Не допускать одновременной записи в тот же `evidence.jsonl`/`events.jsonl`; результат должен зависеть от порядка durable phase boundary, не от тайминга.

Для provenance Control передаёт `{runDir, manifestSha256}` назначенному verifier; verifier должен проверить `manifestSha256` как digest canonical JSON объекта manifest (без завершающего newline) и прочитать scenario/operation/fixture именно из этого persisted bundle. Raw snapshot byte digest из `RunStore.readSnapshot()` — вспомогательное значение, не замена manifestSha256. Verifier child может сохранить `producer=verification` только в пределах назначенной доверенной phase; arbitrary producer из пользовательского payload отвергать. Control после phase заново читает envelope/artifacts и проверяет runId, manifestSha256, fixtureId, stepId, producer и hashes/parents, а coverage/verdict вычисляет или валидирует из persisted evidence. `RESULT.verdict` и `RESULT.reads` сами по себе не являются evidence. При child crash/неполном хвосте — fail closed и `INCONCLUSIVE`; не начинать вторую append одновременно.

Текущие четыре файла не позволяют проверить, что будущие Control и Verifier соблюдают этот протокол. Поэтому это интеграционный gate к окончательному review; никаких изменений шести контрактных схем из него не следует.

