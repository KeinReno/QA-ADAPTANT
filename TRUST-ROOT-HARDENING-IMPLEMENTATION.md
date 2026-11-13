# TRUST-ROOT-HARDENING-IMPLEMENTATION — QWEN-F1 / F2 / F3

## F1 (P0): закрепление корня доверия

Изменены:

| Файл | Изменение |
|---|---|
| `packages/trust/dpapi.mjs` | синхронные `protectSync`/`unprotectSync` (loadTrustRoot исторически синхронен) |
| `packages/trust/identity.mjs` | `trust-pin.json`: создание, проверка, кэш по mtime/size, коды отказа, `resealTrustRootPin` |
| `tests/trust-root-pin.test.mjs` | 7 регрессионных проверок (новый файл) |

Коды отказа: `TRUST_ROOT_UNPINNED`, `TRUST_ROOT_PIN_INVALID`, `TRUST_ROOT_KEY_SUBSTITUTION`.
Проверка выполняется в `loadTrustRoot()`, а через него — во всех доверенных входах:
`startTrusted`, `observeTrusted`, `reconcileTrusted`, cancel и generic-путях с trust.

Кэш: успешная проверка мемоизируется по хэшу пути + mtime/size четырёх файлов; при любом
изменении файлов проверка выполняется заново. Это снимает стоимость DPAPI (≈2 с), не ослабляя
контроль.

## F3 (P1): привязка POST к runId

`apps/browser/trusted-worker.mjs`: в единственный POST добавлен заголовок `x-qa-run-id: job.runId`.
Заголовок не входит в каноническое тело запроса и не участвует в проверке подписи ответа стенда
(подпись связывает challenge/method/path/status/bodySha256), поэтому криптографическая проверка
и pinned-канал не изменены. На стенде это включает one-shot-защиту мутации.

## F2 (P1): fingerprint среды — disposition без изменения криптографии

`manifest.environment.fingerprint` берётся из bundle, собранного из ответа стенда при создании
прогона; подписанная запись среды (`environment-record`) содержит environmentId/generation/origin/
standKeyId/credentialRef, но не fingerprint. Проверка «fingerprint == ответ /environment» сравнивает
значения из одного и того же контекста и **не является независимой аутентификацией**.
Фактические гарантии дают: подписанная запись среды, pinned-соединение, подписанная аттестация
до/после и сверка environmentId/generation. Дополнительный HTTP GET не добавляется.
Контракт скорректирован этим документом (см. QWEN-FINDINGS-DISPOSITION.md, F2).

## Совместимость

- Формат публичных ключей, ready.json, approval, anchor, evidence не изменены.
- Новый файл `trust-pin.json` обязателен для новых корней; старые корни без него отвергаются
  (fail-closed) и требуют санкционированного перезакрепления.
- Stable 0.1 не затрагивался.
