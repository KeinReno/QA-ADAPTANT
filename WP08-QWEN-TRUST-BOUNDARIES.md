# WP08-QWEN-TRUST-BOUNDARIES — карта границ доверия

Аудитор: Qoder / Qwen4-Max-Preview (независимый, WP-08).
Ревизия: `1a510a5d5929534d400dc965f58c78cf468bc270` (worktree `qwen-core-audit`, ветка `audit/wp08-qwen-independent-core`).
Модель угроз: A1–A3 (docs/harness/WP08-REMEDIATION-ARCHITECTURE.md §3, утверждена §10) + доверенные базы WP-00 (docs/wp-00/04-THREAT-MODEL.md).
Все ссылки на строки проверены на указанном SHA. Продуктовый код не изменялся.

## 1. Компоненты и каналы

| Компонент | Процесс | Каналы | Секреты в памяти |
|---|---|---|---|
| Control (apps/control/trusted.mjs, run.mjs) | родитель доверенного прогона | fork IPC → Browser Worker, fork IPC → Verification Worker, fork IPC → anchor-signer; HTTP к стенду (preflight) | Bearer стенда (до передачи), session nonce |
| Browser Worker (apps/browser/trusted-worker.mjs) | дочерний, без браузера | fork IPC от Control; унаследованный handle net.Socket (единственный POST) | Bearer (в одном сообщении с handle) |
| Verification Worker (apps/verification/trusted-worker.mjs) | дочерний | fork IPC от Control (SESSION nonce только по IPC); собственное закреплённое соединение к стенду | эфемерная пара Ed25519 (на диск не пишется) |
| anchor-signer (packages/trust/anchor-signer.mjs, fork-топология) | дочерний Control | приватный fork IPC; ключ только в env ребёнка (QA_ANCHOR_KEY_PATH) | anchor.key (DPAPI-развёртка) |
| Локальный стенд (adapters/local/server.mjs) | отдельный | HTTP 127.0.0.1; подписывает ответы только при x-qa-stand-challenge | ключ стенда Ed25519, Bearer, signedChallenges |
| Legacy-входы start/observe/cancel/reconcile (run.mjs) | тот же Control | без доверенных каналов | нет; доверенный PASS не выпускают |

## 2. Границы доверия (что чем подтверждается)

| № | Граница | Механизм | Файлы/строки | Остаток |
|---|---|---|---|---|
| B1 | Вызывающий → Control | SID из токена процесса (PowerShell/whoami, fail-closed); карточка principal с подписью owner; роли | windows-sid.mjs:1-33; identity.mjs:39-51; policy.mjs | cancelTrusted не проверяет роль (QWEN-F6) |
| B2 | Control → разрешение мутации | PDP decide(facts): trust root → principal → SID → роли → реестр → approval → issuer keyId → bindings → consumption → canceled/mutationRecorded → среда; fail-closed | policy.mjs; facts.mjs | фазы чтения не сверяют живую аттестацию/поколение (R-09, принято) |
| B3 | Approval → одноразовый dispatch | consumeDispatch под withGuard; revocation до/после записи; APPROVAL_REPLAY/APPROVAL_CONSUMED; срок ≤15 мин | approval.mjs; file-mutex.mjs | осиротевший guard-lock fail-closed ~5 с (R-01, принят) |
| B4 | Control → Browser Worker | PINNED_JOB + handle сокета + Bearer в ОДНОМ IPC-сообщении; повторный PINNED_JOB запрещён; disconnect → exit 90 | trusted.mjs:334-378; browser/trusted-worker.mjs:177-196 | — |
| B5 | Среда → мутация | закреплённый сокет (createPinnedAgent не открывает новых TCP); переаттестация /attest перед POST на том же сокете; stand-response подпись ответа POST | environment.mjs:463-618; browser/trusted-worker.mjs:130-173; server.mjs | окно гибели стенда между attest и POST — микроскопическое (R-03, принят); POST не повторяется |
| B6 | Стенд → независимые чтения | attestationVerifiedReads: своё закреплённое соединение, свежая аттестация до/после, подпись каждого чтения, pid+portOwnerPid стабильны | environment.mjs:625-715; verification/trusted-worker.mjs:185-207 | fingerprint среды не покрыт подписью stand-response; envBefore/envAfter тавтологичны (QWEN-F2) |
| B7 | Verification → Control | эфемерный ключ; session nonce только по fork IPC; RESULT сверяется с durable evidence (candidateSha256, readSetSha256, chain head, decision) | trusted.mjs:147-246; verification/trusted-worker.mjs:242-298 | expectedKeyId само-referential, компенсирован nonce+регистрацией (QWEN-F7) |
| B8 | Control → anchor-signer | приватный fork IPC; регистрация ключа+pid+nonce только по нему; lease; WMI-происхождение (родитель=Control, образ trusted-worker.mjs, node.exe, живость) | anchor-signer.mjs:155-187, 238-333, 346-440; trusted.mjs:62-70 | WMI — defense-in-depth, не криптография (QWEN-F5); receipt-путь пропускает повторную WMI-проверку (проверена при подготовке) |
| B9 | Подписант → анкер | подписант сам читает approval/consumption/revocation/candidate/evidence; паритет 0.1 (assertEvidenceRefs + validateVerdictCoverage); CREATE_NEW; один анкер на runId; publication.lock + cancel.request | anchor-signer.mjs:346-440; anchor.mjs:816-874 | — |
| B10 | Анкер → наблюдатель | analyze независимо перечитывает durable-файлы, проверяет подпись анкера, аттестацию из trust root, byte-identity candidate, паритет 0.1; ANCHOR_UNLINKED | anchor.mjs:912-1085 | — |
| B11 | Recovery → PASS | recoverPendingPublication: живость прежних процессов, полная проверка подписанного receipt (0.2.2), identity против VERIFICATION_WORKER_STARTED, cancel.request блокирует | trusted.mjs:452-556; anchor-signer.mjs:238-333 | WORKER_STOP_UNCONFIRMED удерживает lease (fail-closed) |
| B12 | Legacy → trusted | WeakSet-брендинг контекстов; run()/start() отвергают trust-ключи и лишние аргументы; assertRunMode запрещает cross-mode adoption; signerPipe отвергается доверенными входами | trusted.mjs:36, 764-790; run.mjs:21-25, 736-739 | legacy pipe-подписант существует для тестов (QWEN-F4) |
| B13 | Корень доверия → всё | owner.pub/anchor.pub/ready.json; ready.json НЕ подписан; ACL текущего пользователя; DPAPI CurrentUser для приватных ключей | identity.mjs:79-98, 162-184 | **подмена публичных ключей до старта = полная компрометация корня (QWEN-F1); принимается WP-00 явно, в A1–A3 не перечислена** |

## 3. Все пути к доверенному PASS

### 3.1 Нормальный путь (startTrusted)
1. assertTrustedOptions + assertSignerConfigured (anchorKeyPath обязателен, signerPipe запрещён) — trusted.mjs:792-794.
2. loadTrustRoot + currentUserSid; брендинг контекста WeakSet — trusted.mjs:795-805.
3. runInternal: snapshot под mutex; preflight PDP (ALLOW); GET /environment fingerprint == манифест — run.mjs:513-522.
4. lease + lock marker; fork Browser Worker; PINNED_JOB (job+socket+Bearer одним сообщением) — run.mjs:524-…, trusted.mjs:334-378.
5. INTENT → consumeDispatch (durable consumption) → ACK → HTTP_REQUEST → beforeRequestAck (pid жив + netstat владелец порта) — run.mjs:572-654.
6. Worker: переаттестация /attest на закреплённом сокете → единственный POST → HTTP_RESPONSE с подписями; Control verifyDispatchResponse (prePostAttestation + stand-response) — browser/trusted-worker.mjs:130-173; trusted.mjs:381-416.
7. trust.publish: fork Verification Worker (nonce по IPC) → RESULT сверен с durable → prepareVerificationReceipt (WMI, lease, подписанный receipt) → worker.close → повторная сверка head цепочки → publishCandidate → anchorWithinBudget/sign (signAndPublish) → terminal-choice под publication.lock с проверкой cancel.request → publishTerminalVerdict — trusted.mjs:629-748.
8. assertTrustedPass: observeTrustedVerdict независимо подтверждает анкер; без него PASS не возвращается — trusted.mjs:777-785.

### 3.2 Ошибки
- Отказ PDP/среды/подписи → BLOCKED/INCONCLUSIVE до мутации; POST не уходит.
- HTTP_FAILED/разрыв сокета после отправки POST → INCONCLUSIVE (WORKER_LOST/RESULT_UNCONFIRMED); POST не повторяется (browser/trusted-worker.mjs:144-151).
- Неподписанный ответ POST → ENVIRONMENT_ATTESTATION_FAILED, PASS запрещён (browser/trusted-worker.mjs:170-173).
- Ошибка Verification → INCONCLUSIVE candidate с reasonCode; аттестация подписывается и над ошибочным решением (verification/trusted-worker.mjs:260-277).
- Ошибка публикации → terminal-choice не создаётся; verdict без terminal-choice в доверенном режиме не показывается как PASS (AUD-P2-04 закрыт; R-D p2-publication-no-choice).

### 3.3 Отмена
- cancelTrusted: principal+SID (без роли) → cancel.request CREATE_NEW под publication.lock; если terminal-choice уже есть → PUBLICATION_PENDING; killTree — trusted.mjs:848-857; run.mjs:982-1016.
- Подписант: withFinalizeLock проверяет cancel.request перед записью анкера; recoverPendingPublication также блокируется cancel.request — anchor-signer.mjs:193-201; trusted.mjs:452-556.
- Verification: canceled/browserUncertain → INCONCLUSIVE поверх любого результата (verification/trusted-worker.mjs:251-259).

### 3.4 Восстановление (reconcileTrusted)
- Без intent → BLOCKED/INCONCLUSIVE без перезапуска браузера; мутация не повторяется — run.mjs:938-970.
- recoverPendingPublication: живость прежних signer/worker; полная валидация подписанного receipt (receiptId digest, candidate digest, chain head, readSet, processIdentity против события VERIFICATION_WORKER_STARTED, lease token ≥16 символов); идемпотентная повторная публикация candidate; тот же anchorId; cancel.request блокирует PASS — trusted.mjs:452-556.
- PUBLICATION_PENDING/WORKER_STOP_UNCONFIRMED — fail-closed, lease удерживается.

### 3.5 Legacy-входы
- start/observe/cancel/reconcile не принимают trust-параметры (assertOldEntryOptions, arity guard), не брендируются WeakSet, не вызывают trust.publish; доверенный PASS через них недостижим (R-D p2-old-entry-trust; rt2-l08).

## 4. Что находится ВНЕ границ (модель A1–A3 + WP-00)

| Риск | Статус в модели | Подтверждение аудитом |
|---|---|---|
| Инъекция/отладка в доверенные процессы того же SID | вне A1–A3 (явный остаток §3) | не проверялось (вне модели) |
| Извлечение DPAPI-ключей | вне A1–A3 | не проверялось; отмечено, что WP-00:65 считает это возможным для того же SID — формулировки расходятся |
| Чтение памяти доверенных процессов (Bearer, nonce, эфемерный ключ) | вне A1–A3 | не проверялось |
| Подмена owner.pub/anchor.pub/ready.json ДО старта | WP-00:18 принимает явно; A2 разрешает запись; в перечне остатков A1–A3 отсутствует | **воспроизведено E2E: repro/r1 (QWEN-F1)** |
| Противник управляет и диском, и процессом подписанта | WP-00:67 неотличимо от владельца | не проверялось |
| Dev/ЦИЗ | отдельная архитектурная проверка, отдельный SID | не подключались |