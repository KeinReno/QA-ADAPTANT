# WP-03 — внутреннее независимое ревью: Policy Engine (чистый PDP)

Ревьюер: Agent A (автор WP-04, код и тесты WP-03 не писал).
Проверяемая ревизия: ветка feat/adaptant-02-wp03-policy, SHA fc2a5934e26f43034678ceba8fd12dd90d4e7a9b
(реализация 0099653). Проверка выполнена по интеграционному worktree
C:\\Users\\gvi\\Desktop\\QA-ADAPTANT-harness\\integration (только чтение; продуктовый код не изменялся).
Сверка байтов: blob packages/trust/policy.mjs = 68733908859f51378c28bc72e795f411837d6b2b,
blob tests/trust-policy.test.mjs = e7eb45f1c4633c4d4c8215896b1e96d05f53633d — совпадают с fc2a593.
Node v24.16.0, Windows, 13.11.2026.

## 1. Метод

1. Прочитан реальный код, а не только тесты: packages/trust/policy.mjs (411 строк),
   tests/trust-policy.test.mjs (516 строк, 99 test()), docs/harness/WP-03-REPORT.md,
   baseline §5.3 (docs/harness/BASELINE-AND-CONTRACTS.md), docs/wp-00/02-TRUST-ARCHITECTURE.md,
   03-CONTRACT-PROPOSALS.md (коды, приоритет, проекция), 06-ACCEPTANCE-MATRIX.md,
   docs/changes/005-environment-generations-and-revocation.md, поведение packages/trust/approval.mjs
   (для сверки семантики bodySha256), packages/core/canonical.mjs.
2. Независимо запущен пакетный тест в интеграционном worktree (только чтение): 99/99 pass, exit 0.
3. Выполнены собственные адверсариальные пробы во временном каталоге вне репозиториев
   (скрипты импортируют policy.mjs из integration по file://, ничего не пишут в worktree):
   приоритет правил, INDETERMINATE, ALLOW без approval/среды, consumption без bodySha256,
   неизвестные коды ошибок сборщика фактов в фазах чтения, проекция всех наблюдаемых reasonCode,
   детерминизм, отсутствие мутации facts.
4. Статическая проверка чистоты: импорты, запрещённые вызовы (файлы/сеть/процессы/подпись/ключи).
5. git status интеграционного worktree до и после — без изменений (там только Lead-овские коммиты,
   чужих правок не было).

## 2. Фактические результаты прогонов (независимо)

| Команда | Факт |
|---|---|
| node --test --test-concurrency=1 --test-timeout=45000 tests/trust-policy.test.mjs (в integration) | 99 tests / 99 pass / 0 fail, exit 0, ~0.9 s |
| git status --porcelain (integration, до/после) | пусто; worktree не изменён |
| Сверка blob policy.mjs / trust-policy.test.mjs с fc2a593 | совпадает |

## 3. Проверенные инварианты

| Инвариант | Проверка | Итог |
|---|---|---|
| Чистота PDP: нет сети | импорты только node:crypto (randomUUID) и ../core/canonical.mjs; в исходнике нет node:fs/net/http/https/tls/child_process, fetch, http | держится |
| Чистота PDP: нет диска | нет fs/path/require, нет readFileSync/writeFileSync/appendFileSync; проба с временным cwd не создаёт файлов | держится |
| Нет записи consumption | в исходнике нет consumeDispatch и любых вызовов approval.mjs; consumption только читается из facts | держится |
| Нет генерации ключей / подписи / проверки подписи | нет generateKeyPairSync/createPrivateKey/createPublicKey/sign/verify/createHash; digest — только для хеша facts (канонизация core); подпись проверяет сборщик фактов | держится |
| Нет исполнения мутаций | нет вызовов HTTP/адаптеров, нет записи файлов | держится |
| Недоступный trust root → INDETERMINATE | trustStore.available=false или code != null → INDETERMINATE TRUST_STORE_UNAVAILABLE, даже при одновременно испорченном principal | держится (приоритет 1) |
| ALLOW без approval | approval.body=null/state=missing → DENY APPROVAL_MISSING | держится |
| ALLOW без подтверждённой среды | dispatch: attestation.ok != true или расхождение environmentId/generation/origin/keyId → DENY ENVIRONMENT_ATTESTATION_FAILED; record.kind != local-stand → ENVIRONMENT_KIND_DENIED | держится |
| ALLOW при неизвестной/неактивной среде | record=null → ENVIRONMENT_UNKNOWN; status != active → ENVIRONMENT_REVOKED; запись другого environmentId → ENVIRONMENT_UNKNOWN | держится |
| Приоритет: principal/SID/роль/реестр/approval | порядок в основном совпадает с §5.3; исключение — D-1 (SID и роль) | частично |
| Коды причин | таблица 03: PRINCIPAL_UNKNOWN/REVOKED, CALLER_UNAUTHENTICATED, ROLE_DENIED, APPROVAL_MISSING/SIGNATURE_INVALID/MISMATCH/EXPIRED/REVOKED/REPLAY/CONSUMED, CONSUMPTION_INCOMPLETE, ENVIRONMENT_*, CONTRACT_INVALID, RUN_CANCELED, MUTATION_ALREADY_RECORDED | в целом держится (см. D-3, D-4) |
| obligations по фазам | preflight/dispatch → consume-dispatch; observe/reconcile/publish → do-not-dispatch | держится |
| Детерминизм | одинаковые facts → одинаковые effect/reasonCode/поля, разные decisionId; facts не мутируются (Object.freeze) | держится |
| Форма TrustDecision | ровно 11 полей §5.3/03 | держится |
| Некорректная форма facts | не бросает, возвращает DENY CONTRACT_INVALID (null, {}, строки, массивы, лишние/недостающие поля) | держится |
| projectToVerdict: ALLOW → null | probe: decide(ALLOW) → projectToVerdict = null | держится |
| projectToVerdict: enum 0.1 | используются только BLOCKED/INCONCLUSIVE и AUTH_UNAVAILABLE/CONTRACT_INVALID/ENVIRONMENT_CHANGED/CANCELED/EVIDENCE_MISSING/INTEGRITY_ERROR; PASS не появляется | держится |
| Нет подмены Verification/Enforcement | PDP не читает evidence/анкеры, не публикует verdict, не выбирает terminal-choice, не выдаёт permit; projectToVerdict — чистая проекция reasonCode | держится (по коду) |
| Безопасных обходов, дающих ALLOW/PASS при неопределённости | адверсариальные пробы не нашли ALLOW при отсутствии approval/среды/аттестации на dispatch; отказы fail-closed | обходов не найдено |

Проверенная проба позитива: dispatch с корректными facts → ALLOW TRUST_OK consume-dispatch; observe → ALLOW do-not-dispatch;
trustStore unavailable + principal null → INDETERMINATE TRUST_STORE_UNAVAILABLE (INDETERMINATE не превращается в ALLOW).

## 4. Дефекты

### D-1 — MEDIUM. Инверсия приоритета: роль проверяется раньше SID вызывающего

- Где: packages/trust/policy.mjs:278-291. Проверки роли (owner+runner, owner+anchor-signer, «есть owner/operator»)
  выполняются в блоке 2 (строки 284-286), а проверка SID — в блоке 3 (строки 289-291).
- Контракт: BASELINE-AND-CONTRACTS.md §5.3, строки 193-194: «Приоритет правил (первое совпадение):
  ... несовпадение SID → CALLER_UNAUTHENTICATED; запрещённая роль → ROLE_DENIED». SID имеет приоритет
  над ролью.
- Воспроизведение (probe): facts, где authenticatedSid = 'S-other', а principal.roles = ['verifier']
  (роль не допускает доверенный вход), либо principal роли owner+runner.
  - Ожидалось по §5.3: DENY CALLER_UNAUTHENTICATED (проекция BLOCKED AUTH_UNAVAILABLE).
  - Фактически: DENY ROLE_DENIED (проекция BLOCKED CONTRACT_INVALID).
  - Подтверждено для трёх вариантов: чужая роль; null-SID; совмещение owner+runner.
- Влияние: обхода нет (оба исхода — DENY), но нарушен замороженный порядок и меняется reasonCode/verdict
  reasonCode; атрибуция «не тот вызывающий» подменяется «не та роль». Аудит/тесты приёмки A-11
  (CALLER_UNAUTHENTICATED при чужом SID) могут не увидеть ожидаемый код, если в facts одновременно
  недопустимая роль.
- Исправление: перенести SID-блок (289-291) до проверок роли/совмещений (284-286), либо сначала проверить
  SID, затем роль. Регрессия: три комбинации выше + порядок «principal revoked раньше SID» (этот порядок
  верный и должен сохраниться).

### D-2 — MEDIUM. Чтение после отзыва среды: расхождение с docs/changes/005

- Где: packages/trust/policy.mjs:358-360 (любой environment.error, включая ENVIRONMENT_REVOKED, сразу
  возвращает DENY), 366 (record.status !== 'active' → ENVIRONMENT_REVOKED для ВСЕХ фаз, включая
  observe/reconcile/publish).
- Контракт: docs/changes/005-environment-generations-and-revocation.md, строка 31: «Отзыв среды немедленно
  запрещает новый dispatch, но не отменяет чтение уже связанного прогона (T-E)». WP-03-REPORT.md §7.3
  (строка 128) фиксирует обратное: «Чтение требует ... известную активную local-stand запись среды».
  Ревизия WP-03 (fc2a593) старше 005, поэтому это интеграционное расхождение, требующее решения Lead,
  а не молчаливой правки.
- Воспроизведение: observe/reconcile с environment.record.status = 'revoked' (или environment.error =
  'ENVIRONMENT_REVOKED'; generation/attestation при этом не важны).
  - Ожидалось по 005: чтение связанного прогона разрешено (attestation для чтения не требуется; T-E).
  - Фактически: DENY ENVIRONMENT_REVOKED; projectToVerdict → BLOCKED CONTRACT_INVALID (см. D-5), т.е.
    после durable intent может быть опубликован BLOCKED вместо INCONCLUSIVE/чтения.
- Влияние: функциональное — после отзыва/блокировки среды нельзя дочитать уже начатый прогон и
  опубликовать его verdict по сохранённым данным; обхода нет.
- Варианты (решает Lead): (а) поправить 005 (отзыв запрещает и чтение в 0.2) — тогда WP-03-REPORT §7.3
  становится верным, а 005 приводится в соответствие; (б) изменить WP-03: в фазах чтения не требовать
  status=active (только известную local-stand среду), а ENVIRONMENT_REVOKED в чтении трактовать как
  доступ к уже связанному прогону; dispatch остаётся запрещён. В любом варианте — регрессионный тест
  observe/reconcile после revoked/disabled.

### D-3 — LOW. Consumption без bodySha256 считается полным; в чтении это даёт ALLOW

- Где: packages/trust/policy.mjs:189-204, особенно 200-202: bodySha256 проверяется только если поле есть,
  иначе consumption получает статус complete.
- Контракт: 03-CONTRACT-PROPOSALS.md, строка 98: «Рядом лежит bodySha256 ... Запись полная только когда
  файл читается целиком и хеш сходится». В packages/trust/approval.mjs (inspectConsumption) отсутствие
  bodySha256 — incomplete; формат complete включает bodySha256.
- Воспроизведение: facts с approval.state='consumed' и consumption = полное тело из 6 полей без bodySha256,
  phase observe/reconcile.
  - Ожидалось: CONSUMPTION_INCOMPLETE (DENY), как для повреждённого хеша.
  - Фактически: ALLOW TRUST_OK do-not-dispatch (чтение связанного прогона без доказанной полноты расхода).
- Влияние: read-only; dispatch с таким consumption всё равно DENY (APPROVAL_CONSUMED / CONSUMPTION_INCOMPLETE),
  т.е. второй POST невозможен. Но это ALLOW на контрактно неполном расходе и расходится с approval.mjs.
  WP-03-REPORT §8 явно допускает тело «с bodySha256 или без» — это ослабление относительно 03 и
  противоречит инварианту «полное тело расхода».
- Исправление: считать отсутствие bodySha256 статусом incomplete (как approval.mjs) либо, если Lead
  сознательно допускает lenient-режим, зафиксировать это отдельно и добавить тест на отсутствие хеша.
  Регрессия: observe consumed без bodySha256 → DENY CONSUMPTION_INCOMPLETE.

### D-4 — LOW. Неизвестный код attestation.error игнорируется в фазах чтения (ALLOW)

- Где: packages/trust/policy.mjs:217-223 (validateAttestation) вызывается только для dispatch (строки
  368-371); в observe/reconcile/publish environment.attestation.error не проверяется вообще.
- Заявленный инвариант: WP-03-REPORT §5/§8 — «Неизвестный код даёт DENY CONTRACT_INVALID (fail-closed)»;
  тест «неизвестный код ошибки сборщика фактов не даёт ALLOW» проверяет только dispatch-фазу.
- Воспроизведение: observe/reconcile/publish с environment.attestation = {ok:false, body:null,
  error:'SOMETHING_NEW'} → ALLOW TRUST_OK.
- Влияние: read-only, builder по контракту не должен отдавать неизвестные коды; но это fail-open на
  некорректных facts и расхождение с объявленным fail-closed. Живая аттестация для чтения не требуется
  (это корректно), но неизвестный код должен отвергаться и в чтении.
- Исправление: проверять допустимость attestation.error (null/ENVIRONMENT_ATTESTATION_FAILED/
  ENVIRONMENT_UNAVAILABLE или отсутствие) во всех фазах; ok=false/неуспех в чтении не требовать.
  Регрессия на все три фазы чтения.

### D-5 — LOW. projectToVerdict не покрывает ENVIRONMENT_REVOKED: BLOCKED CONTRACT_INVALID вместо ENVIRONMENT_CHANGED

- Где: packages/trust/policy.mjs:37 (environmentReasons = ENVIRONMENT_UNKNOWN, ENVIRONMENT_ATTESTATION_FAILED,
  ENVIRONMENT_UNAVAILABLE — без ENVIRONMENT_REVOKED) и 393-411 (default → BLOCKED CONTRACT_INVALID).
- Контракт: 03, таблица «Проекция в verdict 0.1» (строки 157-168): «Среда не подтвердилась или поколение
  сменилось до мутации → BLOCKED ENVIRONMENT_CHANGED; то же после durable intent → INCONCLUSIVE
  ENVIRONMENT_CHANGED». ENVIRONMENT_REVOKED — отказ среды (03, таблица кодов, строка 138), а не
  «несовпадение approval/роли/вида среды» (вид среды — ENVIRONMENT_KIND_DENIED, он корректно идёт в
  CONTRACT_INVALID).
- Воспроизведение: decide(record.status='disabled'/'revoked') → DENY ENVIRONMENT_REVOKED;
  projectToVerdict → {BLOCKED, CONTRACT_INVALID}. В фазе reconcile то же решение проецируется в BLOCKED,
  хотя после durable intent контракт требует INCONCLUSIVE ENVIRONMENT_CHANGED.
- Влияние: fail-closed по эффекту, но неверный verdict reasonCode и, после intent, неверный verdict
  (BLOCKED вместо INCONCLUSIVE). Тестов проекции на ENVIRONMENT_REVOKED нет.
- Исправление: добавить ENVIRONMENT_REVOKED в environmentReasons (после решения D-2) и тест проекции
  до/после intent. Если Lead считает revoked «контрактным» отказом — явно зафиксировать и покрыть тестом.

## 5. Наблюдения (не дефекты, требуют решения/фиксации)

- O-1. §5.3 говорит «чистая функция: без сети, диска, криптографии». policy.mjs импортирует randomUUID
  из node:crypto (CSPRNG) для decisionId. Иного способа дать новый идентификатор в замороженном
  TrustDecision нет (счётчик — состояние). Это осознанное/приемлемое толкование, но его стоит явно
  зафиксировать в отчёте/матрице как исключение из «без криптографии» (или принимать decisionId извне).
- O-2. projectToVerdict — дополнительный экспорт сверх обязательного списка §5.3 (там только decide).
  Таблица проекции есть в 03 и Lead её проверяет, но расширение стоит отметить в docs/changes, чтобы
  контракт 0.2 не расходился с кодом.
- O-3. MUTATION_ALREADY_RECORDED и APPROVAL_CONSUMED проецируются в BLOCKED CONTRACT_INVALID даже в
  фазах observe/reconcile. В таблице 03 для них отдельной строки нет; для WP-06 это значит, что повторный
  dispatch после intent не должен порождать второй терминальный verdict — проекцию лучше явно
  зафиксировать (тест/строка), чтобы WP-06 не опубликовал BLOCKED после intent.
- O-4. Тестовые пробелы (покрытие идей, не баг): нет строк на приоритет «SID vs роль» (D-1), на
  ENVIRONMENT_REVOKED в проекции (D-5), на consumption без bodySha256 (D-3), на неизвестный
  attestation.error в фазах чтения (D-4), на MUTATION_ALREADY_RECORDED в observe/reconcile (O-3).

## 6. Что проверено отдельно (выборочно, фактические выводы)

- Позитив dispatch: ALLOW TRUST_OK, consume-dispatch; все 11 полей TrustDecision на месте; evaluatedAt = facts.now.
- Позитив observe/reconcile/publish: ALLOW TRUST_OK, do-not-dispatch; record.generation может отличаться
  от expected.environmentGeneration (P-03) — dispatch при этом DENY ENVIRONMENT_ATTESTATION_FAILED.
- trustStore.available=false + principal.body=null: INDETERMINATE TRUST_STORE_UNAVAILABLE (INDETERMINATE
  не превращается в ALLOW; проекция в dispatch BLOCKED AUTH_UNAVAILABLE, в reconcile INCONCLUSIVE
  AUTH_UNAVAILABLE — соответствует таблице).
- Отмена: dispatch → RUN_CANCELED; observe → ALLOW (чтение не блокируется).
- Неполный/повреждённый consumption (bodySha256 не совпал) → CONSUMPTION_INCOMPLETE, в т.ч. в чтении.
- Смена поколения: dispatch → ENVIRONMENT_ATTESTATION_FAILED; observe — ALLOW (P-03).
- Мусорные facts (null, {}, строка, массив, лишнее поле, phase вне списка, now не ISO) → DENY CONTRACT_INVALID
  без исключений; facts не мутируются.
- projectToVerdict: ALLOW → null; неизвестный код → BLOCKED CONTRACT_INVALID; все observed reasonCode
  дают один из enum 0.1, PASS не появляется.
- Ключевой security-вывод: безопасного обхода, дающего ложный ALLOW/PASS, второй POST или подмену среды,
  в пределах проверенной ревизии не найдено; все найденные дефекты fail-closed по эффекту, кроме
  семантики кодов/проекции и read-only ALLOW в D-3.

## 7. Вердикт

FIX REQUIRED (безопасных обходов не найдено; ядро чистоты и запретов держится).

Обязательно до ACCEPT:
1. D-1 — привести порядок «SID раньше роли» к §5.3 (строки 193-194) + регрессия трёх комбинаций.
2. D-2 — Lead фиксирует, что верно для 0.2: 005 («отзыв не отменяет чтение связанного прогона») или
   WP-03-REPORT §7.3 («чтение требует active»); затем согласовать код/док/тест.

Желательно (дёшево, fail-closed-семантика): D-3 (требовать bodySha256), D-4 (проверять неизвестный
attestation.error во всех фазах), D-5 (проекция ENVIRONMENT_REVOKED + тест), O-3/O-4 (зафиксировать
и покрыть тестами).

## 8. Git ревьюера

- Продуктовый код WP-03 не изменялся; интеграционный worktree не изменялся (git status чистый до/после
  прогонов, тесты — чтение и временные каталоги только вне worktree).
- Этот отчёт добавлен отдельным коммитом в ветку ревьюера feat/adaptant-02-wp04-environment
  (worktree wp04) и не является продуктивным кодом WP-03.
- Точный HEAD ветки wp04 после коммита отчёта передан Lead в сообщении.
