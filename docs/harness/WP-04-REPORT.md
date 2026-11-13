# WP-04 — Environment Registry и аттестация локального стенда: отчёт пакета

Исполнитель: Agent A. Worktree: C:\\Users\\gvi\\Desktop\\QA-ADAPTANT-harness\\wp04.
Ветка: feat/adaptant-02-wp04-environment, база 0e7e6c20f7a839ffe16047fa11006b1a9ab6cd31.
Статус: FIX ROUND после внутреннего ревью Agent C (docs/harness/WP-04-INTERNAL-REVIEW.md, проверяемый SHA
e76d79df5d2b906c837c46eb3938c4832300a7d4). Закрыты D-01…D-04. Пакет направлен Lead и Red Team на повторную
независимую проверку; не считается принятым.

## 1. Contract review до кода

Прочитаны: integration/docs/harness/BASELINE-AND-CONTRACTS.md §3/§4/§5.1/§6/§9,
docs/wp-00/02-TRUST-ARCHITECTURE.md (раздел «Среда»), 03-CONTRACT-PROPOSALS.md (EnvironmentRecord,
environment-attest, коды), 05-IMPLEMENTATION-ROADMAP.md (WP-04), 06-ACCEPTANCE-MATRIX.md (E-01…E-08),
фактический код: packages/trust/identity.mjs, approval.mjs, acl.mjs, keygen.mjs,
packages/core/canonical.mjs, adapters/local/server.mjs, adapters/local/bundle.mjs,
tests/trust-identity.test.mjs, tests/trust-approval.test.mjs, старые 0.1 тесты.

Дополнительно к первой ревизии прочитаны и приняты: внутреннее ревью WP-04 (D-01…D-04) и решение Lead
integration/docs/changes/005-environment-generations-and-revocation.md (вариант «а»: поколенческая
раскладка реестра). Решение меняет только новый модуль WP-04; схемы 0.1, contract-freeze.json, evidence
и VerdictPolicy не меняются.

Зафиксировано до реализации:

- Доверенный путь не принимает произвольный HTTP-сервер на loopback за подтверждённый стенд по
  URL/fingerprint/PID/эху открытого ответа. GET /environment и строка fingerprint в доверенной проверке
  не участвуют вообще; fingerprint и nonce в запись реестра не входят.
- Запись реестра — ровно 12 полей §5.1: schemaVersion, domain, environmentId, generation, kind, status,
  origin, standKeyId, credentialRef, keyId, signature, signatureAlgorithm. kind ∈ {local-stand, dev,
  production}, status ∈ {active, disabled, revoked}, generation — целое ≥ 1, origin local-stand строго
  http://127.0.0.1:<port>/. Неизвестное поле отвергается.
- Аттестация — ровно 10 полей: schemaVersion, domain, environmentId, generation, origin, pid, challenge,
  keyId, signature, signatureAlgorithm. challenge — 32 случайных байта hex, новый на каждую проверку;
  keyId === standKeyId записи.
- Подпись записи — owner (domain=environment-record, уже в таблице доменов identity.mjs).
  Подпись аттестации — ключ стенда, домен environment-attest; в таблицу доменов identity.mjs он не входит
  и не должен: модуль проверяет подпись стенда сам по канонизации core/canonical.mjs и Ed25519.
- Приватный ключ стенда создаётся в памяти процесса стенда, на диск не пишется. Публичный ключ — только
  публичные байты; в запись реестра входит только standKeyId.
- Раскладка реестра по docs/changes/005: trustRoot/environments/<environmentId>/<generation>.json,
  отдельный CREATE_NEW-файл на поколение; старый путь environments/<environmentId>.json не поддерживается
  (развёрнутых реестров этой ревизии нет — переход описан в §10).
- dev/production непригодны для аттестации даже при status=active → ENVIRONMENT_KIND_DENIED до сети.
  Внешний origin для local-stand невозможен по контракту → CONTRACT_INVALID до сети.
- Коды §5.1: ENVIRONMENT_UNKNOWN, ENVIRONMENT_REVOKED, ENVIRONMENT_KIND_DENIED,
  ENVIRONMENT_ATTESTATION_FAILED, ENVIRONMENT_UNAVAILABLE, CONTRACT_INVALID. Ошибки подписи owner
  пробрасываются из identity.mjs (APPROVAL_SIGNATURE_INVALID), недоступный trust root —
  TRUST_STORE_UNAVAILABLE; это замороженные коды 0.2, а не новые коды среды.
- Матрица E-01…E-08: E-01/E-02/E-03/E-05/E-06/E-07/E-08 закрываются тестами WP-04; E-04 (чужой credentialRef
  при выдаче секрета) относится к выдаче секрета в WP-06/Policy — WP-04 только валидирует credentialRef
  как ссылку и не выдаёт секретов.
- Старый контракт стенда сохраняется: GET /environment не меняется, serveLocalFixture() только
  дополняется полями standKeyId, standPublicKey, pid, generation и маршрутом POST /attest.

## 2. Файлы пакета

| Файл | Действие |
|---|---|
| packages/trust/environment.mjs | новый; 519 строк: поколенческий реестр, подпись/проверка записи, challenge-response, lifespan/port |
| adapters/local/server.mjs | аддитивно: stand-ключ в памяти, POST /attest, поля standKeyId/standPublicKey/pid/generation, опции generation/port; +51/−5 (без изменений в fix round) |
| tests/trust-environment.test.mjs | новый; 872 строки, 32 test() |
| docs/harness/WP-04-REPORT.md | этот отчёт |

Файлы packages/contracts/*, schemas/*, packages/core/*, apps/*, packages/trust/identity.mjs,
packages/trust/approval.mjs, старые тесты 0.1 не изменялись.

## 3. Экспорты environment.mjs

Контракт §5.1 не менялся — обязательный набор экспортов тот же (полный список):

    export const DEFAULT_ATTEST_TIMEOUT_MS; // 2000
    export function createStandKeys();                       // → {standKeyId, publicKey, privateKey}; ключ только в памяти
    export function newChallenge();                          // → 64 hex (32 байта)
    export function signEnvironmentRecord(ownerPrivateKey, fields);      // → подписанный документ, без записи на диск
    export function commitEnvironmentRecord(trust, trustRoot, record);   // CREATE_NEW <generation>.json + fsync + повторное чтение
    export function loadEnvironmentRecord(trust, trustRoot, environmentId); // → body максимального поколения; UNKNOWN/REVOKED
    export function verifyEnvironmentRecord(trust, record);  // → body (идемпотентна для проверенного тела, D-03)
    export function signEnvironmentAttestation(standPrivateKey, fields); // fields: {environmentId, generation, origin, pid, challenge}
    export function verifyEnvironmentAttestation(trust, record, attestation, {challenge, standPublicKey}); // → body
    export async function attestEnvironment({record, trust, challenge, fetchImpl, timeoutMs, standPublicKey}); // → {record, attestation}
    export async function attestLiveEnvironment({trust, record, fetchImpl, timeoutMs, standPublicKey}); // → {record, attestation, portOwnerPid}
    export function processAlive(pid);                       // → boolean (существование PID)
    export async function portOwnerPid(origin);              // → number|null (единственный владелец слушающего сокета)

fields записи: {environmentId, generation, kind, status, origin, standKeyId, credentialRef}; credentialRef
по умолчанию пустая строка. fields аттестации: {environmentId, generation, origin, pid, challenge}.

attestEnvironment/attestLiveEnvironment принимают standPublicKey (KeyObject, PEM, base64 DER SPKI или
{spki}) либо находят публичный ключ в trust.stands[standKeyId] / trust.standKeys[standKeyId].

## 4. Где живёт публичный ключ стенда (без изменений)

Замороженная запись реестра содержит только standKeyId, поля публичного ключа в ней нет и быть не может
(«неизвестное поле отвергается»). Поэтому публичный ключ стенда передаётся в проверку явно: установка стенда
и регистрация — одна доверенная операция в процессе Control, serveLocalFixture() возвращает standPublicKey
вместе с standKeyId. Если ключ не передан и не найден в trust, проверка НЕ проходит
(ENVIRONMENT_ATTESTATION_FAILED), а не «пропускается». Постоянного файла публичного ключа на диск не
пишется; потеря регистрационных данных означает отказ, не подмену.

Неподписанное тело записи (результат loadEnvironmentRecord/verifyEnvironmentRecord) помечается
неперечислимым Symbol-маркером. Проверка такого тела идемпотентна (D-03), а аттестовать произвольный объект,
собранный вызывающим, нельзя: копирование маркер теряет и даёт CONTRACT_INVALID.

## 5. Реестр: поколения, отзыв и публикация (D-01)

Раскладка: trustRoot/environments/<environmentId>/<generation>.json — один CREATE_NEW-файл на поколение.

commitEnvironmentRecord:

1. Проверяет подпись owner и форму записи (как раньше).
2. Если файл этого поколения уже есть: идентичное содержимое — идемпотентный успех; другое содержимое —
   CONTRACT_INVALID.
3. Если поколение ниже текущего максимума в каталоге — CONTRACT_INVALID (назад публиковать нельзя).
4. Иначе CREATE_NEW + fsync + fsync каталога + повторное чтение и сверка байтов. После записи максимум
   перечитывается; если параллельный писатель успел опубликовать большее поколение, только что созданный
   файл удаляется и возвращается CONTRACT_INVALID (сознательно не оставляем «назад» опубликованное поколение).

loadEnvironmentRecord:

1. Перечисляет каталог, отбирает только имена <positive integer>.json, сортирует ЧИСЛОВО.
2. Проверяет каждую запись (подпись owner, точные поля, environmentId каталога и generation имени файла).
   Повреждённая или подменённая любая запись поколения — CONTRACT_INVALID (fail-closed).
3. Выбирает максимальное поколение. status=revoked у последнего → ENVIRONMENT_REVOKED; status=disabled
   возвращается вызывающему, решение о допуске даёт PDP.

Отзыв/инвалидация среды = owner публикует поколение N+1 со status=revoked/disabled; смена ключа стенда,
порта или origin — тоже новое поколение. Старый путь environments/<environmentId>.json не читается:
для него каталога нет → ENVIRONMENT_UNKNOWN.

## 6. Порядок проверки аттестации

1. Запись среды: точный набор полей, версия/домен 0.2, подпись owner, kind/status/generation, origin
   (для local-stand только http://127.0.0.1:<port>/, порт 1…65535), standKeyId и keyId — SHA-256.
2. requireAttestable: kind !== local-stand → ENVIRONMENT_KIND_DENIED; revoked → ENVIRONMENT_REVOKED;
   не active → ENVIRONMENT_ATTESTATION_FAILED. Всё это ДО сети.
3. POST <origin>attest с {challenge}, redirect: 'manual', AbortSignal.timeout(timeoutMs).
   Размер ответа ограничен ДО буферизации: заранее по content-length и по факту потокового чтения
   (кап maxAttestationBytes, D-04). 3xx → отказ; сетевая ошибка/таймаут → ENVIRONMENT_UNAVAILABLE.
4. Аттестация: точный набор полей; environmentId, generation, origin, keyId === standKeyId и
   challenge обязаны совпасть с реестром и свежим challenge; signatureAlgorithm === 'Ed25519' и подпись
   Ed25519 ключом стенда. Неверный алгоритм/пустая/не-hex подпись → ENVIRONMENT_ATTESTATION_FAILED (D-02),
   CONTRACT_INVALID — только для формы документа (нет обязательного поля).
5. attestLiveEnvironment: новый challenge на каждый вызов; после подписи — processAlive(pid) и
   portOwnerPid(origin) === pid. Порт без единственного владельца или чужой владелец → отказ.

processAlive отвечает только «PID существует»; принадлежность endpoint доказывается отдельно —
владельцем слушающего сокета и подписью PID в аттестации. Это различие закрыто отдельным тестом.

## 7. Коды ошибок (фактическое поведение)

| Код | Когда |
|---|---|
| ENVIRONMENT_UNKNOWN | каталога/записей поколений нет; старый путь <environmentId>.json |
| ENVIRONMENT_REVOKED | status=revoked у максимального поколения при загрузке и при аттестации |
| ENVIRONMENT_KIND_DENIED | попытка аттестовать dev/production; внешний origin не-локального вида |
| ENVIRONMENT_ATTESTATION_FAILED | подпись/challenge/алгоритм (D-02), смена поколения, environmentId, origin, standKeyId, PID, владелец порта, редирект, HTTP ≠ 200, мусор вместо аттестации, неизвестный ключ стенда, ответ больше лимита |
| ENVIRONMENT_UNAVAILABLE | нет ответа: обрыв сокета, ECONNREFUSED, таймаут, обрыв потока тела |
| CONTRACT_INVALID | форма/поля записи и аттестации, внешний origin у local-stand, неподписанное тело без метки проверки, то же поколение с другим содержимым, публикация поколения ниже максимума, повреждённая любая запись поколения |
| APPROVAL_SIGNATURE_INVALID, TRUST_STORE_UNAVAILABLE | пробрасываются из identity.mjs: подпись owner не сошлась / trust root недоступен |

## 8. Обязательные тесты и матрица E

32 отдельных test() в tests/trust-environment.test.mjs (24 исходных + 8 новых/обновлённых раундом D-01…D-04).

| Требование | Тест |
|---|---|
| подделка fingerprint / копия /environment | «E-01: копия публичного /environment и поддельный fingerprint не дают аттестации» |
| replay старого challenge | «replay старой аттестации и старого challenge отвергается» |
| подмена standKeyId | «подмена standKeyId и неизвестный ключ стенда отвергаются» |
| подмена environmentId | «подмена environmentId отвергается» + запись с чужим environmentId в чужом каталоге |
| смена generation | «E-03: смена поколения между T-A и T-B отвергается» |
| смена PID | «смена PID: живой чужой PID не подтверждает владение портом» |
| остановка стенда | «остановленный стенд — ENVIRONMENT_UNAVAILABLE, хотя старый PID ещё существует» |
| захват порта чужим процессом | «E-07: захват порта чужим процессом без ключа стенда не аттестуется» (реальный дочерний процесс) |
| второй bind | «E-08: второй bind на порт живого стенда неуспешен» (EADDRINUSE) |
| обрыв/таймаут | «сетевой обрыв и таймаут аттестации дают ENVIRONMENT_UNAVAILABLE» |
| redirect | «redirect на аттестации отвергается и не преследуется» |
| kind=dev/production | «E-06: kind=dev и production — ENVIRONMENT_KIND_DENIED без исходящего соединения» |
| внешний адрес | «внешний адрес для local-stand отвергается до сети» |
| E-01, E-02, E-03, E-05, E-06, E-07, E-08 | одноимённые тесты |
| позитив | «живой локальный стенд проходит attestLiveEnvironment…» (/attest=1, /environment=0, mutationCount=0) |
| CREATE_NEW + повтор | «поколенческая запись среды: CREATE_NEW, идемпотентный повтор, конфликт и запрет публикации назад» |
| D-01 отзыв N+1 | «отзыв среды поколением N+1: загрузка ENVIRONMENT_REVOKED и провал аттестации» |
| D-01 disabled N+1 | «disabled поколение N+1 возвращается загрузкой, аттестация запрещена» |
| D-01 новый ключ | «смена ключа стенда публикуется новым поколением» |
| D-01 числовой максимум | «загрузка выбирает максимальное поколение числово: 10 старше 9» |
| D-01 переход раскладки | «старый путь environments/<environmentId>.json не читается» |
| D-02 код подписи | «D-02: неверная подпись аттестации даёт ENVIRONMENT_ATTESTATION_FAILED» |
| D-03 идемпотентность | «D-03: verifyEnvironmentRecord идемпотентна для проверенного тела» |
| D-04 потоковый кап | «D-04: chunked-ответ без content-length отсекается по размеру» |
| контракт стенда | «GET /environment не изменён, POST /attest… 400 на мусор», «локальный стенд не выпускает редиректы» |

E-04 в WP-04 не исполняется: выдача секрета среды — T-B/WP-06, здесь проверяется только форма
credentialRef. Это ограничение пакета, не PASS.

## 9. Команды и фактический результат (fix round)

Все команды выполнены в C:\\Users\\gvi\\Desktop\\QA-ADAPTANT-harness\\wp04, Node v24.16.0, Windows.

| Команда | Фактический результат |
|---|---|
| node --check packages/trust/environment.mjs | exit 0 |
| node --check adapters/local/server.mjs | exit 0 |
| node --check tests/trust-environment.test.mjs | exit 0 |
| node --test tests/trust-environment.test.mjs | 32 tests, 32 pass, 0 fail, exit 0, ~7.2 s |
| node --test --test-concurrency=1 --test-timeout=45000 tests/trust-identity.test.mjs tests/trust-approval.test.mjs tests/trust-environment.test.mjs | 51 tests, 51 pass, 0 fail, exit 0, ~32.8 s (32 WP-04 + 19 WP-01/WP-02) |
| node --test --test-concurrency=1 --test-timeout=45000 tests/runtime.test.mjs tests/faults.test.mjs tests/lifecycle.test.mjs tests/audit-wp.test.mjs tests/evidence-readers.test.mjs tests/review-grok.test.mjs tests/contracts.test.mjs tests/contract-links.test.mjs | 59 tests, 59 pass, 0 fail, exit 0, ~224 s (режим официального gate) |
| git diff --check | exit 0, пробельных ошибок нет |
| побайтовая проверка новых файлов | CR = 0 (LF); core.autocrlf=false |

Честно о среде прогонов: один параллельный запуск старого набора (8 файлов одновременно, без
--test-concurrency=1) при загрузке CPU 100 % (другие агенты в это время гоняли Chromium) дал 55/59:
4 теста с Browser/OBSERVE завершились INCONCLUSIVE/WORKER_LOST по таймауту. Те же файлы по одному и в
последовательном режиме gate (строка выше) — 59/59 pass; изменений в общем со старым набором коде в этом
раунде нет (правки только в environment.mjs и его тестах), это артефакт нагрузки, а не регрессия.
Итоговый принятый набор: 59 (0.1) + 19 (WP-01/WP-02) = 78/78 pass без правок старых тестов; WP-04 —
32/32 pass. Полный npm test (gate по всем файлам) запускает Lead на интеграции.

## 10. Переход раскладки и замечания для WP-06

- Реестр environments/<environmentId>.json больше не читается. Развёрнутых реестров ревизии 0.2 нет,
  миграция не требуется; в интеграционной ветке старые временные trust root создаются заново.
- loadEnvironmentRecord возвращает МАКСИМАЛЬНОЕ поколение; для T-A/T-B использовать его, а не ранее
  прочитанную запись. status=disabled возвращается — отказ формирует PDP (ENVIRONMENT_REVOKED по статусу,
  WP-03); revoked отвергается уже загрузкой.
- Отзыв среды = owner публикует N+1 revoked/disabled. Старый approval с прежним environmentGeneration
  после смены поколения не проходит (PDP: APPROVAL_MISMATCH/ENVIRONMENT_ATTESTATION_FAILED), новый
  dispatch требует нового approval.
- Аттестация: attestLiveEnvironment({trust, record, standPublicKey, fetchImpl?, timeoutMs?}) →
  {record, attestation: {environmentId, generation, origin, pid, challenge, keyId}, portOwnerPid};
  attestEnvironment → {record, attestation}. На T-C достаточно processAlive(attestation.pid) +
  portOwnerPid(origin) === pid по уже проверенной аттестации; повторный POST аттестации не нужен.
- Коды ошибок класть в environment.error/environment.attestation.error как есть; ошибки подписи owner —
  APPROVAL_SIGNATURE_INVALID, недоступный trust root — TRUST_STORE_UNAVAILABLE.
- origin записи — канонический URL с завершающим /; аттестационный URL = origin + 'attest'.

## 11. Ограничения и остаточные риски

| ID | Ограничение | Следствие / что делать |
|---|---|---|
| W-01 | Публичный ключ стенда не персистится: запись содержит только standKeyId | WP-06 передаёт standPublicKey из доверенной регистрации (serveLocalFixture), не из сети; без ключа — отказ |
| W-02 | processAlive = «PID существует», не дескриптор | принадлежность endpoint доказывается владельцем порта; окно до route.continue — остаточная гонка R-03, повтор POST запрещён |
| W-03 | Владелец порта читается netstat -ano (Windows) / lsof (POSIX) | при 0 или >1 слушателях результат null → отказ; монопольный bind стенда проверяется E-08 |
| W-04 | Свежесть challenge — обязанность вызывающего; журнала challenge нет | attestLiveEnvironment всегда новый challenge; не переиспользовать старую аттестацию |
| W-05 | Локальный процесс той же учётной записи может читать trust root и память Control | граница локальной 0.2, R-04; для Dev/ЦИЗ не применимо |
| W-06 | POST /attest без авторизации по контракту | секретов не отдаёт, только подпись challenge; ответ ограничен по размеру |
| W-07 | disabled не имеет отдельного кода в WP-04 | загрузка возвращает запись, отказ формирует PDP; аттестация — ENVIRONMENT_ATTESTATION_FAILED |
| W-08 | E-04 (чужой credentialRef) не проверяется в WP-04 | закрывается при выдаче секрета в WP-06; здесь только форма ссылки |
| W-09 | Любая повреждённая запись поколения делает загрузку среды ошибочной (CONTRACT_INVALID) | fail-closed: нельзя «пропустить» подменённую историю; восстановление — только owner новым поколением/чистым реестром |
| W-10 | Публикация «назад» при параллельных писателях: после записи максимум перечитывается, свой файл удаляется | в локальной 0.2 писатель один (owner); при гонке — CONTRACT_INVALID, загрузка всё равно выбирает максимум |
| W-11 | Переход раскладки несовместим со старым путём | старые реестры не читаются намеренно; развёртываний нет, WP-06 создаёт trust root заново |

## 12. Git

- Первая ревизия (проверена внутренним ревью): e76d79df5d2b906c837c46eb3938c4832300a7d4.
- Fix round D-01…D-04 (код + тесты): 648a2f2a9568503922c6faac2eeb87bfb71f7c53
  («Закрыть D-01-D-04 WP-04: поколенческий реестр сред и точные коды аттестации»).
- Отчёт: следующий коммит ветки; точный HEAD после коммита отчёта передан Lead в сообщении.
- Ветка не мержилась, force push не выполнялся, чужие worktree и файлы не изменялись.
