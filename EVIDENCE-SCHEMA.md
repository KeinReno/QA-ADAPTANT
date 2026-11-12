# Доказательства

Машинная форма: EvidenceSchema. Envelope ссылается на собственный JSON artifact (allowlisted fields), runId, manifestSha256, fixtureId, stepId; producer фиксируется доверенным IPC каналом, не полем произвольного входа. sequence и previousSha256 образуют непрерывную цепь. parentEvidenceIds указывают существующие предыдущие свидетельства того же запуска.

Минимальная цепочка PASS: durable mutation-intent → request (fixture marker) → response (тот же requestId, entity ID) → independent-read (тот же kind/ID и marker, отдельно полученные поля) → все обязательные checks. RequestId обязан приходить из реального браузерного request/response соответствия. X-Ciz-Id хранится если получен; его отсутствие не заменяется выдуманным значением. Fixture ownership проверяется данными, не временем или совпадением имени.

Verifier перечитывает artifact bytes, hashes, parent refs и manifests. Путь артефакта — простое имя внутри run/evidence; запрет traversal и symlinks. При missing/tamper/cross-run verdict не PASS. Hash-chain обеспечивает целостность относительно сохранённого manifest, не юридическую неотказуемость.

HTTP headers не сохраняются. Сохранять только явно разрешённые бизнес-поля; не сохранять произвольные error bodies/URL query. Production screenshots/trace требуют маскирования и отдельного доступа; локальный стенд не содержит секретов. Журнал не должен включать credential values.

checkIds допустимы только для verification evidence. IndependentRead машинно задаёт минимальный артефакт: method GET, path /records, fixtureId, entity kind/id, flat fields, environmentFingerprint, собственный requestId, httpStatus 200, время. Проверка полей только из независимо полученного response; не из browser payload. Intent/request содержат operationId, intentId и hash утверждённых inputs; response — matched requestId/entity/fixtureId. Browser не может публиковать independent-read/verdict, verification не может публиковать request мутации. Производитель назначается Control по каналу процесса. validateVerdictCoverage связывает каждый effect ID с точным прочитанным значением; core дополнительно проверяет hashes, identity и цепь.
