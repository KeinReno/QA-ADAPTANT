# 008 — происхождение Verification и подписанные ответы стенда (0.2.1)

Причина: WP-08 REJECT, AUD-P0-01 и AUD-P0-02. Уточняет WP-00 в части доменов подписи и полей анкера.
Схемы 0.1, `packages/contracts`, `schemas/`, `docs/contract-freeze.json` не меняются.
Версия новых объектов — 0.2.1; 0.2.0-объекты без нового поля остаются валидными.

## 1. Домен verification-attestation

`
{ schemaVersion: '0.2.1', domain: 'verification-attestation',
  runId, manifestSha256, candidateSha256, readSetSha256,
  verificationKeyId, pid, startedAt, nonce,
  keyId, signature, signatureAlgorithm }
`

- Подписывает только Verification Worker доверенного пути своим эфемерным ключом, созданным в памяти процесса
  и никогда не попадающим на диск.
- readSetSha256 — digest канонического массива пар {evidenceId, artifact.sha256} фактически выполненных
  независимых чтений в порядке журнала.
- Ключ передаётся Control по fork IPC вместе с аттестацией и кандидатом; Control сверяет хеши с durable
  evidence и байтами candidate. Аттестация доступна подписанту только по приватному каналу Control→signer.

## 2. Домен stand-response

`
{ schemaVersion: '0.2.1', domain: 'stand-response',
  environmentId, generation, origin, standKeyId, challenge, method, path,
  status, bodySha256, pid, issuedAt, keyId, signature, signatureAlgorithm }
`

- Стенд подписывает ответ на запрос, несущий заголовок с challenge, своим ключом из памяти.
- Verification и Control принимают ответ только с валидной подписью и совпадающим challenge; повтор
  подписи на другой challenge отвергается.
- Ответы без заголовка (путь 0.1) не меняются.

## 3. AnchorStatement 0.2.1

К полям 0.2.0 добавляются `verificationAttestationSha256` и `verificationKeyId`. Подписант обязан
проверить аттестацию и byte-identity candidate до подписи; наблюдатель — до показа PASS.

## 4. Топология подписанта

Anchor-signer запускается Control как дочерний процесс с приватным каналом (fork IPC) и не принимает заявки
из публичного канала. Приватный ключ анкера читается только процессом подписанта из secretsDir, переданного
в его окружение. Это изменение модели доверия фиксируется в WP08-REMEDIATION-ARCHITECTURE.md §3 (A1–A3,
остаточный риск R-04).

## 5. CredentialRef

Секрет среды выдаётся только при совпадении `credentialRef` из записи среды с выданным секретом;
несовпадение — отказ до мутации (E-04).

## 6. Уточнение по условиям владельца (APPROVED WITH MANDATORY CONDITIONS)

### 6.1. Поля verification-attestation 0.2.1 (расширены)

```
{ schemaVersion: '0.2.1', domain: 'verification-attestation',
  runId, manifestSha256, approvalId, candidateSha256, readSetSha256,
  evidenceChainHead: { sequence, envelopeSha256 },
  decision: { verdict, reasonCode },
  verificationKeyId, pid, startedAt, nonce,
  keyId, signature, signatureAlgorithm }
```

Приватный ключ Verification не покидает процесс. По IPC передаются только публичный ключ, аттестация и результаты.

### 6.2. Происхождение публичного ключа

Anchor-signer принимает ключ только при выполнении всех условий:
его собственный родитель — Control этого прогона; зарегистрированный verification-pid — потомок того же Control;
образ процесса — доверенный `apps/verification/trusted-worker.mjs`; процесс жив в момент подписи; ключ совпадает
с зарегистрированным в сессии подписанта для runId. Ключ из candidate/runDir не принимается.

### 6.3. Закреплённое соединение (P0-02, утечка Bearer)

- Control открывает соединение к стенду и выполняет challenge-response **на этом же соединении**;
  соединение закрепляется (pinned keep-alive).
- Сокет передаётся доверенному Browser Worker как handle через fork IPC; единственный POST выполняется только
  по этому сокету. Новых TCP-соединений на origin доверенный путь не открывает.
- Если стенд погиб между T-C и POST, закреплённое соединение разрывается: rogue не получает ни POST, ни Bearer.
- Verification использует собственное закреплённое соединение, аттестует его до и после чтений и принимает
  только подписанные ответы стенда; повтор challenge отвергается стендом.
- Новые процессы доверенного пути: `apps/browser/trusted-worker.mjs`, `apps/verification/trusted-worker.mjs`.
  Замороженные `apps/browser/worker.mjs` и `apps/verification/worker.mjs` 0.1 не меняются.
