# WP-04 — внутреннее независимое ревью: Environment Registry и аттестация стенда

Ревьюер: Agent C (автор WP-03, код WP-04 не писал).
Проверяемая ветка: `feat/adaptant-02-wp04-environment`, worktree `C:\\Users\\gvi\\Desktop\\QA-ADAPTANT-harness\\wp04`.
Проверяемый SHA: `e76d79df5d2b906c837c46eb3938c4832300a7d4` (реализация `572ceffbae20b892377d26433342ac46f890e405`).
Продуктовый код и тесты WP-04 ревьюером **не изменялись**; все прогоны — чтение и временные каталоги.
Дата: 13.11.2026.

## 1. Метод

1. Прочитан реальный код, а не только тесты: `packages/trust/environment.mjs` (424 строки),
   `adapters/local/server.mjs` (169 строк), `adapters/local/bundle.mjs`, `packages/core/canonical.mjs`,
   `packages/trust/identity.mjs`, `adapters/local/server.mjs` в базе `0e7e6c2` (diff +51/−5),
   `tests/trust-environment.test.mjs` (726 строк, 24 теста), отчёт `docs/harness/WP-04-REPORT.md`.
2. Независимо запущены тесты пакета, старый набор 0.1 и trust-набор в wp04 на проверяемом SHA.
3. Выполнены собственные адверсариальные пробы во временных каталогах вне репозитория:
   обновление записи среды, отдельный процесс стенда (PID/владелец порта), коды ошибок,
   повтор аттестации, disabled-среда.
4. Сверены заявленные в отчёте числа с фактическим выводом команд; проверено, что diff не выходит
   за владение файлами §5.1 и что старые тесты не менялись.

## 2. Фактические результаты прогонов (независимо, в wp04)

| Команда | Факт | Совпало с отчётом WP-04 |
|---|---|---|
| `node --test tests/trust-environment.test.mjs` | **24 tests / 24 pass / 0 fail**, exit 0, 3.9 s | да |
| `node --test tests/runtime.test.mjs tests/faults.test.mjs tests/lifecycle.test.mjs tests/audit-wp.test.mjs tests/evidence-readers.test.mjs tests/review-grok.test.mjs tests/contracts.test.mjs tests/contract-links.test.mjs` | **59 tests / 59 pass / 0 fail**, exit 0, 58.4 s | да |
| `node --test tests/trust-identity.test.mjs tests/trust-approval.test.mjs tests/trust-environment.test.mjs` | **43 tests / 43 pass / 0 fail**, exit 0, 12.3 s | да |
| `npm run schemas` | exit 0, диффа схем 0.1 нет | да |
| `git status --porcelain` после прогонов | пусто; CRLF в новых файлах 0 | да |
| Diff `0e7e6c2..HEAD` | только 4 файла: server.mjs, environment.mjs, trust-environment.test.mjs, WP-04-REPORT.md | да |

Старый локальный стенд 0.1 и его тесты не сломаны: 59/59 старых тестов проходят, `GET /environment`
сохраняет прежний контракт (3 поля), новые поля и `POST /attest` аддитивны.

## 3. Проверенные инварианты (существенные для доверия)

| Инвариант | Проверка | Итог |
|---|---|---|
| Свежесть challenge и запрет replay | старая подпись на новом challenge → `ENVIRONMENT_ATTESTATION_FAILED`; копия открытого ответа вместо подписи → отказ (тесты «replay…», «E-01…») | держится |
| Подпись ключом стенда и `standKeyId` записи | подмена `standKeyId`, чужой публичный ключ, неизвестный ключ → отказ; подпись проверяется Ed25519 по канонизации | держится |
| «PID существует» ≠ «владеет endpoint» | отдельный тест с живым чужим PID; `portOwnerPid` читает единственного LISTENING-владельца; при 0/>1 слушателях — `null` → отказ | держится |
| Положительный сценарий на реальном отдельном процессе | проба ревьюера: дочерний процесс-стенд pid 40208, Control pid 19484; `attestLiveEnvironment` вернул `portOwnerPid=40208`, PID/поколение сошлись | держится |
| Смена поколения/идентификатора/ключа/origin | E-03, подмена `environmentId`, чужое имя файла реестра → отказ | держится |
| Запрет redirect | `redirect: 'manual'`, 3xx → отказ, цель редиректа не получила запрос | держится |
| Запрет `kind=dev/production` | `ENVIRONMENT_KIND_DENIED` до сети; `fetchImpl` не вызывается | держится |
| Внешний origin для local-stand | отвергается при подписи и проверке записи, до сети | держится |
| Fail-closed при неопределённости | недоступный/повреждённый trust root, нечитаемая запись, обрыв/таймаут, мусор в ответе → отказ | держится |
| Отсутствие мутаций при аттестации | `mutationCount=0`, `readCount=0` на позитивном и негативных путях | держится |
| `CREATE_NEW` и отсутствие перезаписи | повтор идентичной записи возвращает существующую; другое содержимое → `CONTRACT_INVALID`, байты не меняются | держится |
| Анти-подделка неподписанного тела | Symbol-маркер не переживает копирование; неподписанная запись не аттестуется | держится |
| Секреты/ключи | приватный ключ стенда живёт только в памяти процесса стенда, в запись/ответы не попадает | держится |

**Безопасного обхода, дающего ложный PASS/POST или подмену среды, не найдено.** Основные
криптографические и жизненные инварианты WP-04 реализованы корректно; отказы fail-closed.

## 4. Дефекты

### D-01 — HIGH. Нет пути отзыва и смены поколения существующего `environmentId`

- Где: `packages/trust/environment.mjs:215-244` (`commitEnvironmentRecord`, только `CREATE_NEW` +
  запрет другого содержимого при `EEXIST`), замороженная раскладка §5.1
  `trustRoot/environments/<environmentId>.json`.
- Сценарий (воспроизведён пробой ревьюера): владелец подписывает запись `env-1` с `generation: 2`
  (или `status: 'revoked'`, или `status: 'disabled'`) и вызывает `commitEnvironmentRecord`.
- Ожидалось по `02-TRUST-ARCHITECTURE.md`/03: «поколение меняется при смене origin, ключа стенда или
  статуса», `status ∈ {active, disabled, revoked}`, owner может отозвать среду; коды
  `ENVIRONMENT_REVOKED`/смена поколения должны быть достижимы для уже зарегистрированного `environmentId`.
- Фактически: `CONTRACT_INVALID` («environmentId уже закреплён с другим содержимым»); после попыток
  `loadEnvironmentRecord` по-прежнему возвращает `active / generation 1`. Никакого API перевести
  существующий `environmentId` в `revoked/disabled` или `generation+1` нет; отзыв среды в реестре
  невозможен, `ENVIRONMENT_REVOKED` для ранее зарегистрированной среды недостижим.
- Нарушаемый инвариант: отзыв среды владельцем и смена поколения в реестре; не обход (attestation мёртвого
  стенда всё равно отказывает), но security-relevant: owner не может отозвать скомпрометированный стенд
  через контрактный интерфейс.
- Причина: противоречие внутри замороженного контракта — «стабильный environmentId + меняющиеся
  generation/status» против файла `<environmentId>.json` с `CREATE_NEW` без пути обновления.
  Отчёт WP-04 (§9, W-01…W-08) это ограничение не фиксирует.
- Что нужно: решение Lead через `docs/changes` (один из вариантов): (а) поколенческая раскладка
  `environments/<environmentId>/<generation>.json` через `CREATE_NEW` и загрузка актуальной записи;
  (б) отдельный подписанный документ отзыва/нового поколения; (в) явно заморозить «новый environmentId
  на каждую регистрацию» и убрать обещание смены поколения/отзыва для существующего environmentId.
  После решения — код/тесты/отчёт WP-04.

### D-02 — MEDIUM. Неверный `reasonCode` при неверной подписи аттестации в прямой проверке

- Где: `packages/trust/environment.mjs:285`.
- Сценарий (воспроизведён): `verifyEnvironmentAttestation(trust, record, {...attestation, signatureAlgorithm: 'RSA'}, {challenge, standPublicKey})`
  или с пустой `signature` → `CONTRACT_INVALID`.
- Ожидалось по таблице кодов 0.2: «Подпись challenge…» → `ENVIRONMENT_ATTESTATION_FAILED`
  (сам `attestEnvironment` так и делает, оборачивая любую ошибку проверки).
- Фактически: прямой экспорт возвращает `CONTRACT_INVALID`. `attestEnvironment/attestLiveEnvironment`
  маскируют это в `ENVIRONMENT_ATTESTATION_FAILED`, поэтому продовый путь не затронут; но WP-06 может
  вызвать `verifyEnvironmentAttestation` напрямую (например, на T-C) и спроецировать неверный verdict
  (`CONTRACT_INVALID` вместо `ENVIRONMENT_CHANGED`).
- Severity: Medium (семантика кода/проекция; fail-closed, обхода нет). Фикс: отдельные `fail('ENVIRONMENT_ATTESTATION_FAILED', …)`
  для `signatureAlgorithm/signature`, `CONTRACT_INVALID` оставить только для формы документа; регрессия.

### D-03 — LOW. `verifyEnvironmentRecord` не идемпотентна для уже проверенного тела

- Где: `packages/trust/environment.mjs:174-181` против `recordBody` 183-191.
- Сценарий: `const body = loadEnvironmentRecord(...); verifyEnvironmentRecord(trust, body)` →
  `APPROVAL_SIGNATURE_INVALID` (у проверенного тела уже нет `signature`), хотя `recordBody` такое тело
  принимает по Symbol-маркеру.
- Ожидалось: идемпотентная проверка одного и того же доверенного тела либо явно задокументированная
  асимметрия API (принимать только подписанный документ).
- Фактически: повторная проверка падает; WP-06 при двойной проверке получит ложный отказ.
- Severity: Low (fail-closed, но неудобно/ошибочно). Фикс: внутри `verifyEnvironmentRecord` использовать
  `recordBody`-семантику для маркированного тела или зафиксировать контракт «только подписанный документ».

### D-04 — LOW. Ограничение размера ответа не работает для chunked-ответа

- Где: `packages/trust/environment.mjs:304-312`, предпроверка `content-length` — 337-338.
- Сценарий: локальный сервер отдаёт 200 без `content-length` (chunked) и тело больше `maxAttestationBytes`;
  `response.text()` сначала буферизует всё, и только потом проверяется `Buffer.byteLength`.
- Ожидалось: ограниченное чтение (кап по потоку), как обещает отчёт §5 «размер ответа ограничен».
- Фактически: память ограничена только размером ответа; для локального 0.2 — Low (DoS локального
  недоверенного сервера), но обещание в отчёте неточное. Фикс: читать `response.body` с капом.
- Дополнительно: `response.headers.get('content-length')` вызывается вне try; нестандартный `fetchImpl`
  может бросить не-PDP исключение. Информационно.

## 5. Риски для WP-06 (не дефекты WP-04, но обязательны к учёту)

| ID | Риск | Требование |
|---|---|---|
| R-01 | Публичный ключ стенда не персистится (W-01): запись содержит только `standKeyId` | WP-06 берёт `standPublicKey` только из доверенной регистрации/возврата `serveLocalFixture`; никогда из `/environment`, `/attest` или иного сетевого ответа. Без ключа — отказ |
| R-02 | Свежесть challenge — обязанность вызывающего (W-04); модуль не ведёт журнал использованных challenge | На T-A и T-B использовать `attestLiveEnvironment` (новый challenge каждый раз); не переиспользовать challenge и не хранить старую аттестацию как доказательство |
| R-03 | Остаточная TOCTOU-гонка между проверкой PID/порта и `route.continue` (R-03 baseline) | T-C: повторная проверка `processAlive(attestation.pid)` + `portOwnerPid(origin)===pid`; при сомнении POST не отправлять, второй POST не делать |
| R-04 | Позитивные тесты и, вероятно, WP-06 запускают стенд в том же процессе, что Control: `attestation.pid === process.pid`, приватный ключ стенда в памяти Control; проверка liveness тавтологична | Для доверенного прогона запускать стенд отдельным процессом (ревьюер независимо подтвердил, что out-of-process путь работает: owner=40208, pid совпал); либо явно зафиксировать in-process как ограничение локальной 0.2 |
| R-05 | Владелец порта читается `netstat` из PATH (W-03) | В локальной 0.2 допустимо (та же учётная запись и так за границей модели); при желании — абсолютный путь `%SystemRoot%\\System32\\netstat.exe` |

## 6. Замечания к отчёту WP-04

1. §9 не фиксирует D-01 (невозможность отзыва/смены поколения существующего `environmentId`) — это
   существенное ограничение, его нужно добавить независимо от решения Lead.
2. §5 «размер ответа ограничен» неточно для chunked-ответов (D-04).
3. Остальные заявленные числа и факты (24/59/43, diff по 4 файлам, `mutationCount=0`, LF, отсутствие
   правок старых тестов) подтверждены независимо.

## 7. Вердикт

**FIX REQUIRED** (безопасных обходов не найдено; ядро инвариантов держится).

Обязательно до ACCEPT:
1. **D-01**: Lead фиксирует решение по контракту через `docs/changes` (вариант А/Б/В), затем Agent A
   приводит код/тесты/отчёт в соответствие; либо Lead явно принимает ограничение как замороженное —
   тогда оно обязано быть записано в отчёте WP-04 и в матрице приёмки.
2. **D-02**: исправить `reasonCode` для неверной подписи/алгоритма аттестации на
   `ENVIRONMENT_ATTESTATION_FAILED` + регрессионный тест.

Желательно (не блокирует, но дёшево): D-03 (идемпотентность проверки записи), D-04 (кап на chunked-ответ).
R-01…R-05 передать в WP-06 как входные требования.

После исправления D-01/D-02 пакет можно повторно проверить на новом SHA; повторный прогон —
те же команды из §2 плюс тест на отзыв/смену поколения (D-01) и тест кода D-02.

## 8. Git ревьюера

- Проверяемый SHA WP-04: `e76d79df5d2b906c837c46eb3938c4832300a7d4`; дерево wp04 на момент проверки чистое.
- Ревьюер не менял файлы WP-04. Этот отчёт добавлен отдельным коммитом в ветку ревьюера
  `feat/adaptant-02-wp03-policy` (worktree `wp03`) и не является продуктивным кодом.

## 9. Повторное ревью после fix round (13.11.2026)

Проверяемый SHA: `9fc9de4e60968ed038d6f4f7a6278a4edbfdc69e` (код+тесты `648a2f2`), worktree wp04,
дерево чистое. Diff fix round: `packages/trust/environment.mjs`, `tests/trust-environment.test.mjs`,
`docs/harness/WP-04-REPORT.md` (плюс `docs/harness/WP-03-INTERNAL-REVIEW.md`, добавленный Agent A).
Прочитан `integration/docs/changes/005-environment-generations-and-revocation.md`: решение Lead —
поколенческая раскладка `environments/<environmentId>/<generation>.json`, CREATE_NEW на поколение,
запрет публикации назад, выбор максимального поколения, отзыв поколением N+1.

### 9.1 Независимые прогоны (wp04, проверяемый SHA)

| Команда | Факт |
|---|---|
| `node --test tests/trust-environment.test.mjs` | **32 tests / 32 pass / 0 fail**, exit 0, 9.4 s |
| `node --test tests/trust-*.test.mjs` | **51 tests / 51 pass / 0 fail**, exit 0, 17.7 s |
| полный старый набор 0.1 + trust (10 файлов, `--test-concurrency=1`) | **78 tests / 78 pass / 0 fail**, exit 0, 241 s |
| первый прогон тех же 78 под высокой нагрузкой машины | 76/78: два timing-теста 0.1 (`fault changedEnvironment`, `fault ambiguousButton`) упали по таймауту бюджета; оба **прошли поодиночке на wp04 и на базовой ревизии wp03**, старые тесты не импортируют `environment.mjs`, пакетный прогон 32/32 — это флак от нагрузки, не регрессия WP-04 |
| `git status --porcelain` | пусто |

### 9.2 Закрытие дефектов (собственные пробы ревьюера)

| ID | Проверка | Факт |
|---|---|---|
| D-01 | отзыв поколением N+1 | `loadEnvironmentRecord` → `ENVIRONMENT_REVOKED`; `attestEnvironment`/revoked-запись → `ENVIRONMENT_REVOKED` |
| D-01 | максимум поколения | регистрация 9 и 10 → загрузка вернула `generation 10, origin :2010/` (числовое сравнение, не лексикографическое) |
| D-01 | публикация назад / конфликт | поколение ниже максимума → `CONTRACT_INVALID`; та же generation с другим телом → `CONTRACT_INVALID`, файл не перезаписан |
| D-01 | старый путь | `environments/<envId>.json` → `ENVIRONMENT_UNKNOWN` |
| D-02 | неверная подпись аттестации | RSA-алгоритм, пустая и не-hex подпись → `ENVIRONMENT_ATTESTATION_FAILED` (форма документа по-прежнему `CONTRACT_INVALID`) |
| D-03 | идемпотентность | `verifyEnvironmentRecord(verifyEnvironmentRecord(loaded))` → равно `loaded` |
| D-04 | потоковый кап | chunked-ответ 160 KB без content-length → `ENVIRONMENT_ATTESTATION_FAILED` за 38 мс, без ожидания всего тела |

Для нового dispatch: WP-04-слой отказывает и на загрузке, и на аттестации; WP-06-сборщик обязан
передавать `ENVIRONMENT_REVOKED` в `facts.environment.error`, а PDP (WP-03) маппит его в `DENY ENVIRONMENT_REVOKED`.
Новых обходов/ALLOW при revoked/disabled не найдено.

### 9.3 Остаточные ограничения

- Удаление файла последнего поколения процессом с записью в trust root откатывает реестр на предыдущее
  активное поколение. Это граница R-04 (код того же SID всё равно читает owner.key); API публикации назад
  запрещает, файловая защита не входит в локальную 0.2.
- `loadEnvironmentRecord` проверяет подпись каждого поколения: повреждение старого файла даёт
  `CONTRACT_INVALID` (fail-closed), даже если последнее поколение цело.
- Старый путь реестра не поддерживается — соответствует `docs/changes/005` (развёрнутых реестров нет).
- WP-06: всегда загружать актуальное поколение через `loadEnvironmentRecord`; не кэшировать старую
  active-запись после отзыва.

### 9.4 Вердикт повторного ревью

**ACCEPT.** D-01 (отзыв/смена поколения), D-02 (коды), D-03 (идемпотентность), D-04 (потоковый кап) закрыты;
старый набор подтверждён повторным прогоном 78/78. Остаточные ограничения — в §9.3, не блокируют WP-04.
