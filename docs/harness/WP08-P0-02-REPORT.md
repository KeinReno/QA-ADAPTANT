# WP-08 P0-02 — аутентифицированный канал стенда и закреплённое соединение

Исполнитель: Agent R-B. Ветка `fix/wp08-p0-02-stand-channel`, база `07c21c4`.
Пакет закрывает AUD-P0-02 (ложный доверенный PASS через подмену среды) и утечку Bearer
согласно `docs/harness/WP08-REMEDIATION-ARCHITECTURE.md` §5 и §10.2, `docs/changes/008` §2/§6.3.

## 1. Что сделано

### 1.1. Стенд `adapters/local/server.mjs` (аддитивно)

- Ответы `GET /records`, `POST /records` и `POST /attest` подписываются ключом стенда **только если**
  запрос несёт заголовок `x-qa-stand-challenge: <64 hex lowercase>`.
- Подпись едет отдельным заголовком `x-qa-stand-response: base64url(JSON.stringify(statement))`;
  тело и схема ответа 0.1 не меняются (frozen `worker.mjs` их не видит).
- Домен подписи `stand-response`, `schemaVersion '0.2.1'`, поля:
  `schemaVersion, domain, environmentId, generation, origin, standKeyId, challenge, method, path,
  status, bodySha256, pid, issuedAt, keyId, signature, signatureAlgorithm`.
  `bodySha256 = sha256(canonical(parsedBody))` (канонический хеш объекта, baseline §2.3);
  подпись — Ed25519 по каноническому JSON без `signature`/`signatureAlgorithm`.
- Стенд помнит подписанные challenge в памяти процесса: повтор того же challenge →
  `409 {"error":"replay_challenge"}` без подписи. Невалидный challenge → `400 challenge_invalid`.
- `POST /attest` не закрывает соединение (keep-alive), что позволяет закрепление; ответ аттестации
  дополнительно подписан доменом `stand-response` на тот же challenge и тело.
- Bearer: при наличии `x-qa-run-id: <runId>` токен привязывается к runId; первая принятая мутация
  расходует токен → повторный `POST /records` `403 {"error":"token_revoked"}`; `GET /records` тем же
  токеном продолжает работать (нужен frozen Verification 0.1); чужой runId → `403 run_mismatch`;
  невалидный runId → `400 run_id_invalid`. Без `x-qa-run-id` поведение 0.1 полностью сохранено.

### 1.2. Библиотека `packages/trust/environment.mjs`

Экспорты (точные имена):

```js
STAND_CHALLENGE_HEADER = 'x-qa-stand-challenge'
STAND_RESPONSE_HEADER = 'x-qa-stand-response'

verifyStandResponse({ trust, record, challenge, body, responseBytes?, signature,
                      method?, path?, status?, pid?, standPublicKey? }) -> body (без подписи)
readStandResponseSignature(headers) -> statement | null
createPinnedAgent(socket) -> http.Agent (без новых соединений)
pinnedStandRequest(connection, { method, path, headers, body, timeoutMs }) -> { status, headers, text, body }
attestPinnedConnection(connection, { trust, record, standPublicKey, headers?, timeoutMs? })
  -> { challenge, attestation, response }
openPinnedStandConnection({ record, trust, standPublicKey, headers?, timeoutMs? })
  -> { socket, agent, attestation, portOwnerPid, request(), close() }
attestationVerifiedReads({ trust, record, standPublicKey, headers?, timeoutMs?, read, maxReads? })
  -> { result, before, after, reads }
```

- `verifyStandResponse` сверяет environmentId/generation/origin/standKeyId/challenge/method/path/status/
  bodySha256/pid (если передан)/keyId и Ed25519-подпись; ключ — только `standPublicKey` из доверенной
  регистрации (record подписан owner; сверяется `standKeyId === publicKeyId(key)`). Любое расхождение —
  `ENVIRONMENT_ATTESTATION_FAILED`.
- `openPinnedStandConnection`: одно TCP-соединение на `127.0.0.1:<port>`, аттестация
  (`POST /attest`) и проверка `stand-response` на том же сокете, сверка `pid`, `processAlive` и
  владельца порта (`portOwnerPid`). `http.Agent.createConnection` всегда возвращает закреплённый сокет;
  после разрыва новое TCP не открывается — `ENVIRONMENT_UNAVAILABLE`.
- `attestationVerifiedReads`: Verification открывает **своё** закреплённое соединение, аттестует его
  до и после набора чтений (свежий challenge каждый раз), принимает только подписанные ответы,
  сверяет pid/владельца порта до и после. Ошибки fail-closed: `ENVIRONMENT_ATTESTATION_FAILED` /
  `ENVIRONMENT_UNAVAILABLE`; PASS из них не следует (Control проецирует в `ENVIRONMENT_CHANGED`/INCONCLUSIVE).

### 1.3. Новый `apps/browser/trusted-worker.mjs`

Замороженный `apps/browser/worker.mjs` не изменялся. Доверенный Worker:

- не запускает браузер и не открывает TCP: получает handle `net.Socket` и Bearer одним сообщением
  `PINNED_JOB` через fork IPC (`child.send(message, socket)`);
- проверяет, что handle принадлежит origin среды (`remoteAddress=127.0.0.1`, `remotePort` = порт origin);
- выполняет ровно один `POST /records` по этому сокету (заголовки `authorization`, `idempotency-key=intentId`,
  `x-qa-stand-challenge`), без редиректов и без повторов;
- сохраняет response по схеме 0.1 через Control: `INTENT → ACK → HTTP_REQUEST → EVIDENCE_ACK → POST →
  HTTP_RESPONSE (body, entity, responseSignature, responseChallenge) → EVIDENCE_ACK → DONE`;
- при разрыве/ошибке: `HTTP_FAILED` + `ERROR`, POST не повторяется, DONE не отправляется
  (Control обязан дать INCONCLUSIVE). Ответ без подписи стенда → `ERROR ENVIRONMENT_ATTESTATION_FAILED`
  после фиксации response; PASS запрещён.

### 1.4. Интеграция с Control (зона Lead)

Файлы `apps/control/run.mjs`/`apps/control/trusted.mjs` не мои; для сквозного закрытия P0-02 Lead должен:

1. В доверенном пути на T-C вызвать `openPinnedStandConnection({record, trust, standPublicKey})`
   вместо `attestLiveEnvironment`; передать `connection.socket` в `apps/browser/trusted-worker.mjs`
   сообщением `PINNED_JOB` вместе с Bearer (после `EVIDENCE_ACK` закреплённый сокет не переоткрывать);
2. Обрабатывать `HTTP_RESPONSE.responseSignature/responseChallenge/responseBody` через
   `verifyStandResponse` до записи/публикации; `ERROR`/`HTTP_FAILED` → INCONCLUSIVE, PASS запрещён;
3. В доверенном Verification Worker (R-A) использовать `attestationVerifiedReads` вместо публичных
   `/environment` и `/records`.

## 2. Регрессии (обязательные)

`tests/trust-signed-environment.test.mjs` (15 тестов):

1. подпись `GET /records` проверяется ключом регистрации, bodySha256 по каноническому телу;
2. подпись `POST /records`, status 201/bodySha256;
3. старый путь 0.1: `GET /environment` (3 поля), `POST/GET /records` без challenge не подписаны,
   схема тела не изменена, повторный POST без `x-qa-run-id` работает как раньше;
4. replay challenge → `409 replay_challenge` без подписи (и для GET, и для POST);
5. replay подписи на другой challenge/тело → `ENVIRONMENT_ATTESTATION_FAILED`;
6. подмена тела/challenge/method/path/status/pid/ключа/отсутствие подписи → отказ;
7. сверка с доверенной регистрацией: чужой environmentId/generation/origin/standKeyId → отказ;
8. Bearer: привязка к runId, одноразовая мутация, продолжение чтения, `run_mismatch`, чужой токен 401;
9. `attestationVerifiedReads`: подпись на каждом чтении, свежие аттестации до/после, владелец порта;
10. rogue на том же порту после POST: ответ без подписи отвергается, `/attest` не подтверждается;
11. подмена стенда между чтениями: закреплённый сокет рвётся, **новых TCP нет**, rogue получает
    **0 запросов**;
12. pinned keep-alive: `/attest`, чтения и повторная аттестация идут по одному TCP-сокету
    (`socket.localPort` не меняется);
13. доверенный Browser Worker: единственный POST по закреплённому сокету, evidence-цепочка
    `mutation-intent → request → response`, подпись response проверена Control-стороной, `mutationCount=1`;
14. **сценарий B аудита** (подмена между T-C и POST): DONE нет, POST не подтверждён, **roguePosts=0,
    rogue не получил ни одного HTTP-запроса, Bearer не утёк**, exit code ≠ 0.

## 3. Команды и фактические результаты

Все команды — в `rem-b`, Node v24.16.0, Windows.

| Команда | Результат |
|---|---|
| `node --test tests/trust-signed-environment.test.mjs` | exit 0, 15/15 passed, 0 failed |
| `node --test tests/runtime.test.mjs` | exit 0, 1/1 |
| `node --test tests/faults.test.mjs` | exit 0, 12/12 |
| `node --test tests/evidence-readers.test.mjs` | exit 0, 5/5 |
| `node --test tests/lifecycle.test.mjs` | exit 0, 8/8 |
| `node --test tests/audit-wp.test.mjs` | exit 0, 14/14 |
| `node --test tests/review-grok.test.mjs` | exit 0, 7/7 |
| `node --test tests/contracts.test.mjs tests/contract-links.test.mjs` | exit 0, 12/12 |
| Старые 0.1 наборы вместе (runtime+faults+evidence-readers+lifecycle+audit-wp+review-grok+contracts) | **59/59 exit 0** |
| `node --test tests/trust-*.test.mjs` (9 файлов, включая новый) | exit 0, **214/214 passed** |
| `npm run schemas` | exit 0, диффа схем нет |

Замороженные пути (`packages/contracts`, `schemas`, `docs/contract-freeze.json`,
`apps/browser/worker.mjs`, `apps/verification/worker.mjs`, `adapters/local/bundle.mjs`) не изменялись:
`git status` содержит только четыре перечисленных файла.

## 4. Ограничения и риски

- Сквозное закрытие AUD-P0-02 в `wp0304-06-false-pass.mjs` (и «нет ложного PASS») достигается только
  после интеграции §1.4 в Control (файлы Lead) и доверенного Verification Worker (R-A). Настоящий пакет
  доказывает свойства канала (pin/подпись/replay/одноразовый Bearer) и поведение доверенного Browser
  Worker регрессиями; end-to-end по аудиторскому тесту должен прогнать Lead на интегрированной ревизии.
- Замороженный `apps/browser/worker.mjs` 0.1 не умеет передавать challenge, поэтому подпись ответа POST
  проверяется только в доверенном Browser Worker; старый путь намеренно не изменён (стабильность 0.1).
- Bearer живёт в памяти Control и доверенного Worker и передаётся только по fork IPC; в evidence,
  события и отчёты не пишется. Противник, читающий память доверенных процессов/DPAPI, — вне модели A1–A3
  (§3, R-04); это не признаётся допустимой утечкой канала.
- `attestationVerifiedReads` больше не использует `fetchImpl` (закреплённое соединение — только raw
  socket/http.request); параметр не документирован как обязательный. Для R-A: передавайте
  `headers: { authorization: 'Bearer …' }` для чтений стенда.
- Replay-challenge хранится в памяти процесса стенда; перезапуск стенда сбрасывает множество (у нового
  процесса новый ключ стенда и новая регистрация поколения, подписи старого процесса не пройдут).

## 5. SHA

- База: `07c21c4`.
- Код пакета: `dadd13667e3e8813e459d0104c51d0852246321e` (стенд + библиотека),
  `89f1d38e51400ed7616d66f5f17171afc373faca` (доверенный Browser Worker + регрессии).
- HEAD ветки `fix/wp08-p0-02-stand-channel`: коммит с этим отчётом (см. `git rev-parse HEAD` при сдаче).
