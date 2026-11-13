# WP-04 — Environment Registry и аттестация локального стенда: отчёт пакета

Исполнитель: Agent A. Worktree: `C:\\Users\\gvi\\Desktop\\QA-ADAPTANT-harness\\wp04`.
Ветка: `feat/adaptant-02-wp04-environment`, база `0e7e6c20f7a839ffe16047fa11006b1a9ab6cd31`.
Статус: CODE COMPLETE, направлен Lead и Red Team на независимую проверку. Пакет не считается принятым.

## 1. Contract review до кода

Прочитаны: `integration/docs/harness/BASELINE-AND-CONTRACTS.md` §3/§4/§5.1/§6/§9,
`docs/wp-00/02-TRUST-ARCHITECTURE.md` (раздел «Среда»), `03-CONTRACT-PROPOSALS.md` (EnvironmentRecord,
environment-attest, коды), `05-IMPLEMENTATION-ROADMAP.md` (WP-04), `06-ACCEPTANCE-MATRIX.md` (строки E-01…E-08),
фактический код: `packages/trust/identity.mjs`, `approval.mjs`, `acl.mjs`, `keygen.mjs`,
`packages/core/canonical.mjs`, `adapters/local/server.mjs`, `adapters/local/bundle.mjs`,
`tests/trust-identity.test.mjs`, `tests/trust-approval.test.mjs`, старые 0.1 тесты.

Зафиксировано до реализации:

- Доверенный путь не принимает произвольный HTTP-сервер на loopback за подтверждённый стенд по
  URL/fingerprint/PID/эху открытого ответа. `GET /environment` и строка `fingerprint` в доверенной проверке
  не участвуют вообще; fingerprint и nonce в запись реестра не входят.
- Запись реестра — ровно 12 полей §5.1: `schemaVersion, domain, environmentId, generation, kind, status,
  origin, standKeyId, credentialRef, keyId, signature, signatureAlgorithm`. `kind ∈ {local-stand, dev,
  production}`, `status ∈ {active, disabled, revoked}`, `generation` — целое ≥ 1, `origin` local-stand строго
  `http://127.0.0.1:<port>/`. Неизвестное поле отвергается.
- Аттестация — ровно 10 полей: `schemaVersion, domain, environmentId, generation, origin, pid, challenge,
  keyId, signature, signatureAlgorithm`. `challenge` — 32 случайных байта hex, новый на каждую проверку;
  `keyId === standKeyId` записи.
- Подпись записи — owner (`domain='environment-record'`, уже в таблице доменов `identity.mjs`).
  Подпись аттестации — ключ стенда, домен `environment-attest`; в таблицу доменов `identity.mjs` он не входит
  и не должен: модуль проверяет подпись стенда сам по канонизации `core/canonical.mjs` и Ed25519.
- Приватный ключ стенда создаётся в памяти процесса стенда, на диск не пишется. Публичный ключ — только
  публичные байты; в запись реестра входит только `standKeyId`.
- dev/production непригодны для аттестации даже при `status=active` → `ENVIRONMENT_KIND_DENIED` до сети.
  Внешний origin для `local-stand` невозможен по контракту → `CONTRACT_INVALID` до сети.
- Коды §5.1: `ENVIRONMENT_UNKNOWN`, `ENVIRONMENT_REVOKED`, `ENVIRONMENT_KIND_DENIED`,
  `ENVIRONMENT_ATTESTATION_FAILED`, `ENVIRONMENT_UNAVAILABLE`, `CONTRACT_INVALID`. Ошибки подписи owner
  пробрасываются из `identity.mjs` (`APPROVAL_SIGNATURE_INVALID`), недоступный trust root —
  `TRUST_STORE_UNAVAILABLE`; это замороженные коды 0.2, а не новые коды среды.
- Матрица E-01…E-08: E-01/E-02/E-03/E-05/E-06/E-07/E-08 закрываются тестами WP-04; E-04 (чужой `credentialRef`
  при выдаче секрета) относится к выдаче секрета в WP-06/Policy — WP-04 только валидирует `credentialRef`
  как ссылку и не выдаёт секретов.
- Старый контракт стенда сохраняется: `GET /environment` не меняется, `serveLocalFixture()` только
  дополняется полями `standKeyId, standPublicKey, pid, generation` и маршрутом `POST /attest`.

## 2. Файлы пакета

| Файл | Действие |
|---|---|
| `packages/trust/environment.mjs` | новый, 424 строки: реестр, подпись/проверка записи, challenge-response, lifespan/port |
| `adapters/local/server.mjs` | аддитивно: stand-ключ в памяти, `POST /attest`, новые поля результата, опции `generation/port`; +51/−5 строк |
| `tests/trust-environment.test.mjs` | новый, 726 строк, 24 `test()` |
| `docs/harness/WP-04-REPORT.md` | этот отчёт |

Файлы `packages/contracts/*`, `schemas/*`, `packages/core/*`, `apps/*`, `packages/trust/identity.mjs`,
`packages/trust/approval.mjs`, старые тесты 0.1 не изменялись.

## 3. Экспорты environment.mjs

```js
export const DEFAULT_ATTEST_TIMEOUT_MS; // 2000
export function createStandKeys();                       // → {standKeyId, publicKey, privateKey}; ключ только в памяти
export function newChallenge();                          // → 64 hex (32 байта)
export function signEnvironmentRecord(ownerPrivateKey, fields);      // → подписанный документ, без записи на диск
export function commitEnvironmentRecord(trust, trustRoot, record);   // CREATE_NEW + fsync + повторное чтение
export function loadEnvironmentRecord(trust, trustRoot, environmentId); // → body; UNKNOWN/REVOKED
export function verifyEnvironmentRecord(trust, record);  // → body (с невидимой меткой проверки)
export function signEnvironmentAttestation(standPrivateKey, fields); // fields: {environmentId, generation, origin, pid, challenge}
export function verifyEnvironmentAttestation(trust, record, attestation, {challenge, standPublicKey}); // → body
export async function attestEnvironment({record, trust, challenge, fetchImpl, timeoutMs, standPublicKey}); // → {record, attestation}
export async function attestLiveEnvironment({trust, record, fetchImpl, timeoutMs, standPublicKey}); // → {record, attestation, portOwnerPid}
export function processAlive(pid);                       // → boolean (существование PID)
export async function portOwnerPid(origin);              // → number|null (единственный владелец слушающего сокета)
```

`fields` записи: `{environmentId, generation, kind, status, origin, standKeyId, credentialRef}`; `credentialRef`
по умолчанию `''`. `fields` аттестации: `{environmentId, generation, origin, pid, challenge}`.

Дополнительно (не заморожено, но нужно WP-06): `attestEnvironment`/`attestLiveEnvironment` принимают
`standPublicKey` (KeyObject, PEM, base64 DER SPKI или `{spki}`) либо находят публичный ключ в
`trust.stands[standKeyId]` / `trust.standKeys[standKeyId]`. `verifyEnvironmentAttestation` принимает то же
через опции.

## 4. Решение: где живёт публичный ключ стенда

Замороженная запись реестра содержит только `standKeyId`, поля публичного ключа в ней нет и быть не может
(«неизвестное поле отвергается»). Поэтому публичный ключ стенда передаётся в проверку явно:
в 0.2 установка стенда и регистрация — одна доверенная операция в процессе Control, и `serveLocalFixture()`
возвращает `standPublicKey` вместе с `standKeyId`. Если ключ не передан и не найден в `trust`, проверка
**не проходит** (`ENVIRONMENT_ATTESTATION_FAILED`), а не «пропускается». Постоянного файла публичного ключа
на диск не пишется; потеря регистрационных данных означает отказ, не подмену.

Неподписанное тело записи (результат `loadEnvironmentRecord`/`verifyEnvironmentRecord`) помечается
неперечислимым Symbol-маркером. Аттестовать произвольный объект, собранный вызывающим, нельзя:
копирование объекта маркер теряет и даёт `CONTRACT_INVALID`. Подписанный документ всегда проверяется
подписью owner, маркер не нужен.

## 5. Порядок проверки аттестации

1. Запись среды: точный набор полей, версия/домен 0.2, подпись owner по канонизации, `kind/status/generation`,
   `origin` (для local-stand только `http://127.0.0.1:<port>/`, порт 1…65535), `standKeyId` и `keyId` — SHA-256.
2. `requireAttestable`: `kind !== local-stand` → `ENVIRONMENT_KIND_DENIED`; `revoked` → `ENVIRONMENT_REVOKED`;
   не `active` → `ENVIRONMENT_ATTESTATION_FAILED`. Всё это **до** сети.
3. `POST <origin>attest` с `{challenge}`, `redirect: 'manual'`, `AbortSignal.timeout(timeoutMs)`,
   размер ответа ограничен; 3xx → отказ, сетевая ошибка/таймаут → `ENVIRONMENT_UNAVAILABLE`.
4. Аттестация: точный набор полей; `environmentId`, `generation`, `origin`, `keyId === standKeyId` и
   `challenge` обязаны совпасть с реестром и свежим challenge; подпись Ed25519 ключом стенда.
5. `attestLiveEnvironment`: новый challenge на каждый вызов; после подписи — `processAlive(pid)` и
   `portOwnerPid(origin) === pid`. Порт без единственного владельца или чужой владелец → отказ.

`processAlive` отвечает только «PID существует»; принадлежность endpoint доказывается отдельно —
владельцем слушающего сокета и подписью PID в аттестации. Это различие закрыто отдельным тестом.

## 6. Коды ошибок (фактическое поведение)

| Код | Когда |
|---|---|
| `ENVIRONMENT_UNKNOWN` | файла записи нет |
| `ENVIRONMENT_REVOKED` | `status='revoked'` при загрузке и аттестации |
| `ENVIRONMENT_KIND_DENIED` | попытка аттестовать `dev`/`production`; внешний origin не-локального вида |
| `ENVIRONMENT_ATTESTATION_FAILED` | подпись/поля/challenge, смена поколения, `environmentId`, `origin`, `standKeyId`, PID, владелец порта, редирект, HTTP ≠ 200, мусор вместо аттестации, неизвестный ключ стенда, ответ больше лимита |
| `ENVIRONMENT_UNAVAILABLE` | нет ответа: обрыв сокета, ECONNREFUSED, таймаут |
| `CONTRACT_INVALID` | форма/поля записи и аттестации, внешний origin у local-stand, неподписанное тело без метки проверки, повтор `environmentId` с другим содержимым |
| `APPROVAL_SIGNATURE_INVALID`, `TRUST_STORE_UNAVAILABLE` | пробрасываются из `identity.mjs`: подпись owner не сошлась / trust root недоступен |

## 7. Обязательные тесты и матрица E

Все 24 теста — отдельные `test()` в `tests/trust-environment.test.mjs`.

| Требование | Тест |
|---|---|
| подделка fingerprint | «E-01: копия публичного /environment и поддельный fingerprint…» (доверенный путь не читает `/environment` вовсе) |
| копирование публичного ответа `/environment` | тот же тест: 200 с копией на `/attest` → отказ |
| replay старого challenge | «replay старой аттестации и старого challenge отвергается» (новая подпись на старом ответе) |
| подмена `standKeyId` | «подмена standKeyId и неизвестный ключ стенда отвергаются» |
| подмена `environmentId` | «подмена environmentId отвергается» + чужое имя файла реестра |
| смена generation | «E-03: смена поколения между T-A и T-B отвергается» |
| смена PID | «смена PID: живой чужой PID не подтверждает владение портом» (живой и мёртвый PID) |
| остановка стенда | «остановленный стенд — ENVIRONMENT_UNAVAILABLE, хотя старый PID ещё существует» |
| захват порта чужим процессом без ключа | «E-07: захват порта чужим процессом без ключа стенда не аттестуется» (реальный дочерний процесс) |
| попытка второго bind | «E-08: второй bind на порт живого стенда неуспешен» (`EADDRINUSE`) |
| сетевой обрыв/таймаут | «сетевой обрыв и таймаут аттестации дают ENVIRONMENT_UNAVAILABLE» |
| redirect | «redirect на аттестации отвергается и не преследуется» (цель не получила запрос) |
| запрещённый `kind=dev` | «E-06: kind=dev и production — ENVIRONMENT_KIND_DENIED без исходящего соединения» |
| внешний адрес | «внешний адрес для local-stand отвергается до сети» |
| E-01 (копия открытых полей) | «E-01: …» |
| E-02 | «E-02: environmentId отсутствует в реестре — ENVIRONMENT_UNKNOWN» |
| E-03 | «E-03: …» |
| E-05 (часть WP-04) | «E-05: повреждённый и подменённый реестр сред не читается» + недоступный trust root |
| E-06 | «E-06: …» |
| E-07 | «E-07: …» |
| E-08 | «E-08: …» |
| позитив | «живой локальный стенд проходит attestLiveEnvironment…» (живой стенд, 1 запрос `/attest`, 0 запросов `/environment`, `mutationCount=0`) |
| CREATE_NEW/fsync/повтор | «запись среды ставится CREATE_NEW, повтор с другим содержимым не перезаписывает файл» |
| контракт стенда | «GET /environment не изменён, POST /attest… 400 на мусор», «локальный стенд не выпускает редиректы» |

E-04 в WP-04 не исполняется: выдача секрета среды — T-B/WP-06, здесь только проверяется форма
`credentialRef` (строка-ссылка, не секрет). Это отмечено как ограничение пакета, не PASS.

## 8. Команды и фактический результат

Все команды выполнены в `C:\\Users\\gvi\\Desktop\\QA-ADAPTANT-harness\\wp04`, Node v24.16.0, Windows.

| Команда | Фактический результат |
|---|---|
| `node --check packages/trust/environment.mjs` | exit 0 |
| `node --check adapters/local/server.mjs` | exit 0 |
| `node --check tests/trust-environment.test.mjs` | exit 0 |
| `node --test tests/trust-environment.test.mjs` | **24 tests, 24 pass, 0 fail**, exit 0, ~4.0 s |
| `node --test tests/trust-identity.test.mjs tests/trust-approval.test.mjs tests/trust-environment.test.mjs` | **43 tests, 43 pass, 0 fail**, exit 0, ~8.3 s (24 WP-04 + 19 WP-01/WP-02) |
| `node --test tests/runtime.test.mjs tests/faults.test.mjs tests/lifecycle.test.mjs tests/audit-wp.test.mjs tests/evidence-readers.test.mjs tests/review-grok.test.mjs tests/contracts.test.mjs tests/contract-links.test.mjs` | **59 tests, 59 pass, 0 fail**, exit 0, ~45.3 s (весь старый набор 0.1, включая локальную вертикаль Browser+Verification) |
| `node --test tests/trust-identity.test.mjs tests/trust-approval.test.mjs` (в составе строки выше — 43−24) | 19 tests, 19 pass |
| `git diff --check` | exit 0, пробельных ошибок нет |
| побайтовая проверка новых файлов | CR = 0 (LF); `core.autocrlf=false` |

Итого старый принятый набор: 59 (0.1) + 19 (WP-01/WP-02) = **78 тестов, 78 pass** без правок старых тестов.
Новые тесты WP-04: **24, все зелёные**. Весь полный `npm test` запускает Lead на интеграции.

## 9. Ограничения и остаточные риски

| ID | Ограничение | Следствие / что делать |
|---|---|---|
| W-01 | Публичный ключ стенда не персистится в trust root: запись содержит только `standKeyId` | WP-06 обязан передать `standPublicKey` из доверенной регистрации (возврат `serveLocalFixture`) в `attestEnvironment/attestLiveEnvironment`; без ключа — отказ, не пропуск |
| W-02 | `processAlive` = «PID существует», а не дескриптор процесса | принадлежность endpoint доказывается владельцем порта; окно между проверкой и `route.continue` — остаточная гонка R-03, повтор POST запрещён |
| W-03 | Владелец порта читается `netstat -ano` на Windows (POSIX — `lsof`) | при 0 или >1 слушателях результат `null` → отказ; подмена слушателя при живом стенде дополнительно блокируется монопольным bind (E-08) |
| W-04 | Свежесть challenge — обязанность вызывающего; кэша использованных challenge нет | `attestLiveEnvironment` всегда генерирует новый challenge; `attestEnvironment` с чужим/повторным challenge отвергает старую подпись |
| W-05 | Локальный процесс той же учётной записи может читать trust root и память Control | граница локальной 0.2, R-04; для Dev/ЦИЗ не применимо |
| W-06 | `POST /attest` не требует авторизации (по контракту) | секретов не отдаёт, только подпись challenge; ответ ограничен по размеру |
| W-07 | `kind=disabled` не имеет отдельного кода | аттестация даёт `ENVIRONMENT_ATTESTATION_FAILED`; загрузка возвращает запись, решение о допуске — за PDP |
| W-08 | E-04 (чужой `credentialRef`) не проверяется в WP-04 | закрывается при выдаче секрета в WP-06; здесь только форма ссылки |

## 10. Замечания для WP-06 (сборщик фактов и точки врезки)

- Факты среды: `record = loadEnvironmentRecord(trust, trustRoot, environmentId)`; аттестация на T-A/T-B:
  `const live = await attestLiveEnvironment({trust, record, standPublicKey, fetchImpl, timeoutMs})`.
  Результат: `{record, attestation: {environmentId, generation, origin, pid, challenge, keyId}, portOwnerPid}`.
- Для T-C (перед `route.continue`) достаточно `processAlive(attestation.pid)` + `portOwnerPid(origin) === pid`
  на уже проверенной аттестации; повторный POST аттестации не нужен, мутация не повторяется.
- Коды ошибок класть в `environment.error` / `environment.attestation.error` как есть (строки выше).
  PDP уже знает `ENVIRONMENT_*`; ошибки подписи owner приходят как `APPROVAL_SIGNATURE_INVALID`.
- `environment.attestation.body` — проверенная аттестация; PDP сверяет поколение и origin с записью.
- `origin` записи — канонический URL с завершающим `/`; аттестационный URL = `origin + 'attest'`.

## 11. Git

- Реализация и тесты: коммит `572ceffbae20b892377d26433342ac46f890e405`
  («Добавить реестр сред и аттестацию локального стенда WP-04»).
- Отчёт: следующий коммит ветки; точный HEAD после коммита отчёта передан Lead в сообщении.
- Ветка не мержилась, force push не выполнялся, чужие worktree и файлы не изменялись.
