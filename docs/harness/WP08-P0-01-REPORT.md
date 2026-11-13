# WP-08 P0-01 — отчёт потока «достоверное происхождение Verification»

Ветка: `fix/wp08-p0-01-provenance` (база `07c21c4`). Владелец: Agent R-A.
Финальный SHA на момент отчёта: `4ecc542c90d149ca4eb3553b13d20a22260042bd`
(коммиты `13ad46c` — ядро, `ef237c5` — strict-канал/закреплённое соединение, `4ecc542` — тесты).
Отчёт не объявляет ACCEPT: независимая приёмка — отдельно.

## 1. Что сделано

### 1.1. Домен `verification-attestation` 0.2.1 (packages/trust/anchor.mjs)

Ровно по docs/changes/008 §6.1:

```
{ schemaVersion: '0.2.1', domain: 'verification-attestation',
  runId, manifestSha256, approvalId, candidateSha256, readSetSha256,
  evidenceChainHead: { sequence, envelopeSha256 },
  decision: { verdict, reasonCode },
  verificationKeyId, pid, startedAt, nonce, keyId, signature, signatureAlgorithm }
```

- Подпись Ed25519 эфемерным ключом Verification; `keyId === verificationKeyId = sha256(SPKI)`.
- `readSetSha256` = digest канонического массива пар `{evidenceId, artifact.sha256}` **только**
  `independent-read` в порядке журнала (терминальный verdict в набор не входит).
- Новые экспорты: `buildVerificationAttestation`, `verifyVerificationAttestation`,
  `verificationAttestationSha256`, `computeReadSetSha256`, `verificationPublicKeyRecord`,
  `publishVerificationRecord`, `readVerificationRecord`, `assertVerificationAttestation`.
- `AnchorStatement` расширен `verificationAttestationSha256` и `verificationKeyId` (валидация обязательна).
- Подписант — единственный писатель `trustRoot/verification/<runId>.json` (CREATE_NEW + fsync + перечитывание;
  повтор с другим телом → `ANCHOR_CONFLICT`).

### 1.2. Наблюдатель (packages/trust/anchor.mjs)

`analyze`/`observeTrustedVerdict` теперь независимо:
1) вызывают паритет 0.1: `assertEvidenceRefs` (pre-verdict) / `assertTerminalEvidence` (terminal) +
   `validateVerdictCoverage`;
2) проверяют аттестацию из trust root: подпись, `verificationKeyId`, `runId`, `manifestSha256`, `approvalId`,
   `candidateSha256`, пересчитанный `readSetSha256`, `evidenceChainHead`, `decision`.
При любом расхождении прогон `inconsistent`, PASS не показывается
(`VERIFICATION_ATTESTATION_MISSING` / `VERIFICATION_ATTESTATION_INVALID`).
Публичные сигнатуры `analyze`/`observeTrustedVerdict` не изменены; в конец результата observe добавлено поле
`verification` (по требованию Lead о расширении только добавлением полей).

### 1.3. Топология подписанта (packages/trust/anchor-signer.mjs)

- `spawnAnchorSigner({trustRoot, anchorKeyPath})` — Control запускает подписанта как дочерний процесс с
  приватным fork IPC. Путь к `anchor.key` передаётся только через env ребёнка
  (`QA_ANCHOR_SIGNER_CHILD=1`, `QA_TRUST_ROOT`, `QA_ANCHOR_KEY_PATH`); публичного named pipe доверенный путь
  не использует.
- Регистрация ключа Verification — только по приватному каналу: `register-verification-key {runId, publicKey, verificationPid}`,
  один ключ/pid на runId в сессии подписанта.
- До подписи подписант проверяет происхождение ключа через WMI (абсолютный
  `%SystemRoot%/System32/WindowsPowerShell/v1.0/powershell.exe`): родитель verification-pid === Control
  (родитель подписанта), CommandLine содержит `apps\\verification\\trusted-worker.mjs`, ExecutablePath —
  `node.exe`, процесс жив; ключ из candidate/runDir никогда не принимается.
- Дополнительно: подпись аттестации зарегистрированным ключом, `runId/manifest/approval/candidate`,
  byte-identity candidate, `evidenceChainHead`, `decision`, пересчёт `readSetSha256` по durable evidence,
  паритет `assertEvidenceRefs` + `validateVerdictCoverage` (+ response/reads для PASS/FAIL).
- Legacy `startAnchorSigner/connectAnchorSigner` сохранены только для совместимости существующего
  trust-integration и протокольных тестов; они также требуют регистрацию ключа и валидную аттестацию, «просто
  заявку» подписант больше не принимает. После перехода Lead на `anchorKeyPath` legacy-канал можно удалить.

### 1.4. Доверенный Verification Worker (apps/verification/trusted-worker.mjs, новый)

Замороженный `apps/verification/worker.mjs` 0.1 не изменялся и не импортируется.

- Эфемерная пара Ed25519 создаётся в памяти на процесс; на диск/в IPC приватный ключ не попадает.
- Совместимого режима без подписи стенда НЕТ: при отсутствии `attestationVerifiedReads`/ошибке канала —
  fail-closed (INCONCLUSIVE/ENVIRONMENT_CHANGED), PASS не строится.
- Все независимые чтения — только `attestationVerifiedReads`/`ctx.verifiedRead` с заголовком
  `authorization`; среда берётся из подписанной аттестации (`ctx.environmentId/generation/origin/standKeyId/pid`),
  отдельный `/environment` не читается.
- Сам считает `readSetSha256`, сам подписывает аттестацию вместе с candidate; при
  `QA_ADAPTANT_CANCELED=1`/`QA_ADAPTANT_BROWSER_UNCERTAIN=1` всегда INCONCLUSIVE (PASS запрещён).
- По fork IPC Control получает `{verdict, reads, attestation, verificationPublicKey, verificationPid}`;
  процесс живёт до `STOP` (подписант проверяет живость в момент подписи).

### 1.5. Control (apps/control/trusted.mjs)

- `verifyWithTrustedWorker` запускает Worker дочерним процессом и принимает аттестацию+ключ только по IPC;
  сверяет с durable evidence: `candidateSha256` (digest байтов candidate), `readSetSha256`, `evidenceChainHead`,
  `decision`, `approvalId`, `runId/manifest`, каждый IPC-read с durable evidence; паритет
  `assertEvidenceRefs` + `validateVerdictCoverage`. Расхождение → `INTEGRITY_ERROR`, PASS не публикуется.
- `publish({store, runDir, frozen, canceled, browserUncertain})`: при наличии mutation-intent кандидат берётся
  ТОЛЬКО из подписанной аттестации Worker; PASS анкерится подписантом (регистрация ключа+pid, передача
  аттестации по приватному каналу), иначе исход без анкера. Legacy `verdict` в аргументах принимается для
  совместимости ветки, но при доверенном Worker не используется.
- P0-02 точки для wiring Lead/run.mjs: `preparePinnedDispatch({frozen, token, child})` (открывает закреплённое
  соединение, формирует PINNED_JOB и передаёт handle сокета одним сообщением; ошибка → `{allow:false, denial}`),
  `beforeRequestAck` на закреплённом сокете (`attestPinnedConnection` + `processAlive` + `portOwnerPid`, без
  новой аттестации), `verifyDispatchResponse({payload})` → `{allow, body}` через `verifyStandResponse`,
  `verificationEnv()` с `QA_ADAPTANT_TRUSTED_VERIFIER/…/AUTHORIZATION`, `close()`.

## 2. Интерфейсы и контракты

- Совместимость с R-B зафиксирована: `attestationVerifiedReads({trust, record, standPublicKey, headers, timeoutMs,
  read})` возвращает ровно `read(ctx)`; `ctx.verifiedRead` → `{status, body, headers, bodySha256, attestation}`;
  `openPinnedStandConnection`/`attestPinnedConnection`/`verifyStandResponse`/`processAlive`/`portOwnerPid`.
- Новые ошибки: `VERIFICATION_ATTESTATION_MISSING`, `VERIFICATION_ATTESTATION_INVALID`,
  `ANCHOR_BINDING_REJECTED` (для неподтверждённого происхождения/ключа), `INTEGRITY_ERROR` (расхождение хешей).
- Схемы 0.1 (`packages/contracts`, `schemas/`, `docs/contract-freeze.json`) не менялись.

## 3. Обязательные регрессии (tests/trust-provenance.test.mjs, 7 тестов)

1. Доверенный Worker: PASS только с подписанной аттестацией и полной связкой; анкер содержит
   `verificationAttestationSha256/verificationKeyId`; наблюдатель `trusted=true passed=true`.
2. Подложная цепочка+кандидат без работающего Verification: анкер не выпускается (чужой/незарегистрированный
   ключ, подложный pid, нет регистрации), наблюдатель PASS не показывает.
3. Аттестация от чужого ключа: подпись не сходится с зарегистрированным ключом → отказ; повторная регистрация
   другого ключа на runId → `CONTRACT_INVALID`.
4. Подмена `candidateSha256`/`readSetSha256` в аттестации → подпись ломается; добавление read после аттестации →
   `readSetSha256` не сходится → отказ.
5. Повтор аттестации другого runId → `ANCHOR_BINDING_REJECTED`.
6. Наблюдатель: удаление/подмена `trustRoot/verification/<runId>.json` и подложный прогон → не PASS.
7. Подмена `verificationKeyId/keyId` в аттестации → отказ.

## 4. Команды и фактические результаты

Окружение: Windows, Node v24.16.0, локальный стенд 127.0.0.1, временные каталоги %TEMP%.

Важно: в ветке P0-01 ещё нет R-B (он слит в интеграцию, коммит `f1cd8d9`). Для честного прогона тесты запускались
с read-only наложением `packages/trust/environment.mjs` и `adapters/local/server.mjs` из `f1cd8d9`
(файлы НЕ закоммичены, после прогона восстановлены `git checkout --`). Без наложения ветка ведёт себя fail-closed
(нет `attestationVerifiedReads`) — это ожидаемо до мержа.

| Команда | Результат | Exit |
|---|---|---|
| `node --test tests/trust-anchor.test.mjs` (с R-B) | 22/22 pass, ~74 s | 0 |
| `node --test tests/trust-provenance.test.mjs` (с R-B) | 7/7 pass, ~74 s | 0 |
| `node --test tests/trust-integration.test.mjs` (файл Lead, не менялся) | 13/13 pass, ~86 s | 0 |
| `node --test --test-name-pattern "T-01|T-08|T-12" tests/trust-integration.test.mjs` (с R-B) | 3/3 pass, ~47 s | 0 |
| `node --test tests/trust-{identity,keygen,approval,environment,policy,r01}.test.mjs` | pass (без изменений), exit 0 | 0 |

Полный `npm test` — только Lead на финальном SHA. Атакующий скрипт аудита
`wp08-audit/tests/wp08-r07-forge-candidate.mjs` проверяет Lead/R-D на merged SHA: ожидание —
`SIGNER_RESULT ok:false`, `VERDICT_FALSE_PASS_SHOWN false`.

## 5. Риски и ограничения

1. **R-04 (граница модели)**: подписант проверяет происхождение через WMI, но код того же SID с правами
   инъекции/отладки/запуска доверенных бинарников с выбираемыми входами остаётся вне модели A1–A3. Для Dev/ЦИЗ
   обязателен отдельный Windows SID для Verification/anchor-signer.
2. **WMI-зависимость**: проверка происхождения использует абсолютный powershell.exe; на загруженной машине
   добавляет ~0.5–1 с на подпись. При недоступности WMI — fail-closed (анкера нет).
3. **Legacy named pipe**: оставлен только для совместимости текущего tests/trust-integration (Lead переводит на
   `anchorKeyPath`); подпись по нему возможна лишь с зарегистрированным ключом и валидной аттестацией.
4. **Pinned-socket (P0-02)**: методы контекста реализованы по спецификации Lead; фактический wiring run.mjs и
   сценарий B проверяет Lead/R-B. В этом потоке сквозной P0-02-канал не заявляется как проверенный.
5. **Восстановление (V-07)**: при уже существующей другой аттестации/анкере подписант отказывает
   `ANCHOR_CONFLICT`; повторная recovery-публикация PASS — зона P1-02 (R-C), не этого потока.
6. Тесты trust-anchor/trust-provenance на ветке без R-B-файлов fail-closed; зелёный прогон возможен на
   merged SHA интеграции.

## 6. Изменённые файлы

- `packages/trust/anchor.mjs` — домен аттестации, поля анкера, запись/чтение trustRoot/verification,
  паритет наблюдателя, `anchorWithinBudget(attestation)`.
- `packages/trust/anchor-signer.mjs` — приватный fork-канал, регистрация ключа+pid, WMI-происхождение,
  проверки attestation/readSet/паритета, сохранение аттестации.
- `apps/verification/trusted-worker.mjs` — новый доверенный Verification.
- `apps/control/trusted.mjs` — оркестрация Worker/подписанта, PINNED_JOB точки, publish без verdict.
- `tests/trust-anchor.test.mjs` — перевод 22 тестов на новую топологию и подписанный стенд (без удаления проверок).
- `tests/trust-provenance.test.mjs` — новый набор регрессий P0-01.

## 7. Git

```
git rev-parse HEAD
4ecc542c90d149ca4eb3553b13d20a22260042bd
```

`git status --porcelain` на момент отчёта: см. финальный коммит отчёта; рабочее дерево содержит только этот файл
до коммита отчёта.
