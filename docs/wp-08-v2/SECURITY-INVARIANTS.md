# SECURITY INVARIANTS — TRUST FOUNDATION V2.1

Каждый инвариант обязателен для реализации; проверяется отдельным тестом.
«Компонент» — кто обеспечивает; «Проверка» — будущий сценарий (не PASS до исполнения).

| ID | Инвариант | Компонент | Проверка |
|---|---|---|---|
| INV-01 | TAS не принимает trustRoot/secretsDir/anchorKeyPath от клиента | IPC-схема | T18/N10в |
| INV-02 | Доверие определяется только enrolled-записью реестра | TAS Registry | R7/R7'/N17 |
| INV-03 | Registry: запись только SYSTEM+SID службы; Admins не писатели; append-only; монотонный version + HWM | TAS | T15/N18 |
| INV-04 | Enrollment требует подтверждения владельцем из внешнего офлайн-источника; повторный enroll → отказ | admin-CLI | T14/N17 |
| INV-05 | Ротация сверяется с внешним ожидаемым keyId, не с owner.pub из подменяемого каталога | TAS + admin-CLI | R8' |
| INV-06 | Ключ анкера: ACL только SID службы; DPAPI LM — defense-in-depth, не граница | TAS | M07-тест |
| INV-07 | Approval связан approvalId→runId атомарно в TAS; повтор с другим runId → APPROVAL_REPLAY | TAS state | T01/T02/N13 |
| INV-08 | Grant single-use, TTL, audience, sessionId, runId/approvalId/manifest привязаны | TAS state | T06/T07/N14 |
| INV-09 | Grant не записывается в файлы/env/argv/логи/публичный IPC | TAS + Worker | T05 |
| INV-10 | anchor-sign принимается только от сессии Worker, созданной TAS (эфемерный ключ) | TAS-Verifier | T03/T04/T09/T10 |
| INV-11 | TAS пересчитывает readSetSha256 и byte-identity candidate из durable-записей, контролируемых TAS | TAS-Verifier | T09/INV-13 |
| INV-12 | Evidence доверенного прогона пишется в каталог с ACL службы; TAS не читает evidence из A2-зоны как доказательство | TAS | T03/N16 |
| INV-13 | Паритет assertEvidenceRefs/assertTerminalEvidence/validateVerdictCoverage выполняется TAS до подписи | TAS-Verifier | P01/neg |
| INV-14 | Cancel отзывает grant до подписи; после ANCHORED подпись не меняется | TAS state | T08 |
| INV-15 | Recovery идемпотентен, не повторяет POST, не доверяет устаревшим grant | TAS | T11/N07 |
| INV-16 | IPC: клиент проверяет SID сервера и подпись TAS; при провале — fail-closed без fallback | клиент+TAS | T12/N15 |
| INV-17 | Fake-провайдер недоступен в приёмке и не выбирается через env/config | harness | T19/M11 |
| INV-18 | Legacy-артефакты → LEGACY_UNVERIFIED, не trusted PASS; переаттестация только решением владельца | TAS | T16/N20 |
| INV-19 | Все обязательные сценарии исполнены на точном v2-SHA с сырыми журналами; «закрыто проектом» ≠ PASS | процесс | M12 |
| INV-20 | A2 не сужена: дизайн не вводит допущений о «доверенном» пользовательском коде; owner=админ — отдельное условие (M09) | архитектура | ревью |
