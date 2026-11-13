# WP-08 REAUDIT — независимый аудит исправлений (поток R-D)

Ветка: `test/wp08-independent-audit` (worktree `rem-d`). База: `07c21c4db936627df9a3c874015327ea992a335a`.
Роль: независимый аудитор исправлений; продуктовый код не правится. Аудиторская ветка
`audit/wp-08-07c21c4` — только чтение. Все сообщения и документы — на русском.

## 1. Статус

| Этап | Статус |
|---|---|
| Перенос исходных атакующих сценариев в переиспользуемый каталог | DONE |
| Базовое воспроизведение на 07c21c4 (оба P0 + P1/P2) | DONE: 11 FAIL + 2 INCONCLUSIVE, exit 1 |
| Стресс/негатив на агрегатор матрицы | DONE: 5/5, exit 0 |
| Атаки на происхождение ключа Verification (§10.1/§10.3.2) | DONE (сценарий `p0-01b-key-provenance.mjs`); на базе FAIL |
| Replay подписанных ответов, гибель стенда при закреплённом сокете (§10.2) | DONE (`p0-02c-replay-pinned.mjs`); на базе INCONCLUSIVE — нет подписанных ответов |
| Подмена Worker/выхода Verification после подписи (§10.3.2) | DONE (`p1-03-substitution-after-anchor.mjs`); на базе INCONCLUSIVE по attestation-части |
| Обход через старый вход `start()` | DONE (`p2-old-entry-trust.mjs`); на базе FAIL |
| Независимый прогон против финальной интеграционной ревизии | DONE: 15/15 PASS на `1a510a5d5929534d400dc965f58c78cf468bc270`, `targetDirty=false`; R-A/R-B/R-C как отдельные ревизии здесь не заявляются |
| Ранняя проверка R-02 на коммите rem-c `3a51558` | DONE: PASS (keygen отверг junction, exit 1) |

Зелёный результат разработчиков без независимого прогона в этом каталоге закрытием не считается.

## 2. Каталог `tests/audit-remediation/`

Все файлы — самодостаточные `.mjs`; запуск `node <файл> --target=<worktree>`.
Продуктовый код проверяемой ветки не изменяется; временные каталоги — `%TEMP%`.

| Файл | Назначение |
|---|---|
| `audit-lib.mjs` | обвязка: `--target`, динамическая загрузка модулей ревизии, trust root, управляемый стенд (с подписью ответов), rogue, forge-цепочка, JSON-вердикт/exit code |
| `p0-01-forge-candidate.mjs` | AUD-P0-01 + обходы: подмена candidate после анкера, второй анкер, второй verdict |
| `p0-01b-key-provenance.mjs` | чужой ключ Verification, подмена verification-pid, копия trusted-worker, мёртвый Worker, ключ из runDir |
| `p0-02a-swap-after-post.mjs` | AUD-P0-02-A: подмена стенда после POST, replay аттестации, честный контроль |
| `p0-02b-window-swap.mjs` | AUD-P0-02-B: окно T-C→POST; фактические счётчики rogue: `roguePosts`, `bearerLeaked` |
| `p0-02c-replay-pinned.mjs` | гибель стенда при закреплённом сокете; replay подписанных attestation/stand-response на другой challenge |
| `p1-01-weak-observer.mjs` | AUD-P1-01: паритет наблюдателя с 0.1 |
| `p1-02-v07-recovery.mjs` | AUD-P1-02 / V-07: восстановление после анкера без потери PASS |
| `p1-03-substitution-after-anchor.mjs` | подмена candidate/read-set/attestation после подписи |
| `p2-r02-junction.mjs` | AUD-P2-01: R-02 junction |
| `p2-approval-id-only.mjs` | AUD-P2-02: путь «только approvalId» |
| `p2-publication-no-choice.mjs` | AUD-P2-04: публикация без terminal-choice |
| `p2-e04-credential-ref.mjs` | AUD-P2-05: E-04 credentialRef |
| `p2-old-entry-trust.mjs` | старый вход не принимает аргументы доверенного режима |
| `run-matrix.mjs` | агрегатор матрицы: строгий разбор, без fallback-PASS, сверка сценария/ревизии/exit code |
| `matrix-negative.test.mjs` | стресс/негатив на агрегатор |

## 3. Контракт сценария

stdout — один JSON-документ:

    {
      "tool": "WP08-REAUDIT",
      "scenario": "AUD-P0-01",
      "target": { "path": "...", "head": "<git SHA>", "dirty": false, "diffSha256": "..." },
      "expected": "...", "actual": "...",
      "defect": "REPRODUCED" | "NOT_REPRODUCED" | "UNPROVEN",
      "verdict": "PASS" | "FAIL" | "INCONCLUSIVE",
      "exitCode": 0 | 1 | 3,
      "checks": [ { "name": "...", "ok": true } ],
      "evidence": { ... }
    }

Правила: `PASS` = дефект не воспроизводится; `FAIL` = воспроизводится; `INCONCLUSIVE` = атака
не выполнена/обвязка не совместима. Сценарий, у которого сорвался честный контроль доверенного
пути, возвращает `INCONCLUSIVE` и не может дать `PASS`.

В `evidence` каждого сценарного вердикта фиксируются: `target.head/dirty`, счётчики rogue
(`roguePosts`, `bearerLeaked`, `attestGets`/`recordGets`/`replayServed`), `standMutationCount`,
число `verdict`/`request`, наличие анкера, состояние `observeTrusted` и код отказа
подписанта/проверки.

## 4. Фактические результаты на 07c21c4

Команда:

    node tests/audit-remediation/run-matrix.mjs --target=<worktree 07c21c4>

Факт: `verdict=FAIL, exitCode=1, targetDirty=false, counts={FAIL:11, UNVERIFIABLE:2}`.
Подробности — `docs/harness/WP08-REAUDIT-BASE.md`.

| ID | Exit | Ключевые поля |
|---|---|---|
| AUD-P0-01 | 1 | signer: `ok=true, verdict=PASS`; observed: `trusted=true, passed=true, anchorStatus=ANCHOR_OK`; `standMutationCount=0` |
| AUD-P0-01B | 1 | 4 попытки из 4: подписанный анкер + trusted PASS (`anchoredCount=4, trustedPassCount=4`) |
| AUD-P0-02-A | 1 | `verdict=PASS` при `comment=null` у реальной записи; rogue обслужил `/environment` и `/records`; `sawBearer=true` |
| AUD-P0-02-B | 1 | `standMutationCount=0`, `roguePosts=1`, `bearerLeaked=true`, `verdict=PASS` |
| AUD-P0-02C | 3 | гибель стенда без rogue: trusted PASS нет; подписанных ответов стенда на базе нет — replay не проверен |
| AUD-P1-01 | 1 | 0.1-паритет: `Эффект не подтверждён независимым чтением`; trusted observer: `passed=true, PASS` |
| AUD-P1-02 | 1 | reconcile: `CANDIDATE_CONFLICT`; анкерованный PASS не восстановлен |
| AUD-P1-03 | 3 | подмена candidate и артефакта чтения отвергнута; записи аттестации Verification на базе нет — часть не проверена |
| AUD-P2-R02 | 1 | keygen exit 0; `secretsInRunDir=2` |
| AUD-P2-APPROVALID | 1 | `startTrusted({approvalId})` без документа → `BLOCKED` |
| AUD-P2-PUBLICATION | 1 | `publish()` бросил `TERMINAL_CHOICE_INCOMPLETE`, verdict `INCONCLUSIVE` без `terminal-choice` |
| AUD-P2-E04 | 1 | запросы с `Authorization`: 4; секрет доставлен стенду |
| AUD-P2-OLDENTRY | 1 | старый вход принял `trust` и `anchorKeyPath` |

Негатив агрегатора:

    node --test tests/audit-remediation/matrix-negative.test.mjs
    tests 5 / pass 5 / fail 0, exit 0

Проверено: exit 0 без JSON не даёт PASS (`INVALID`); чужой scenario id не даёт PASS
проверяемой строке; чужая ревизия и расхождение exit code дают `INVALID`; таймаут даёт
`UNVERIFIABLE`; честный PASS-вердикт даёт `PASS`.

### 4.1. «Дефект закрыт» и «не проверено из-за интерфейса» — разные вещи

`INCONCLUSIVE` (exit 3) **не считается PASS** и не закрывает строку. На базовой ревизии так
получились две строки: `AUD-P0-02C` (нет подписанных ответов стенда — replay не проверяется) и
`AUD-P1-03` (нет записи аттестации Verification — подмена этой части не проверяется).
На исправленной ревизии эти сценарии обязаны либо дать `PASS` (защита сработала), либо
`FAIL` (дефект), либо остаться `INCONCLUSIVE` с точной причиной отсутствующего интерфейса.

## 5. Условия приёмки владельца (§10.3) — как проверяются

1. Оба P0 воспроизводятся на 07c21c4 и не воспроизводятся на исправленной ревизии:
   `AUD-P0-01`, `AUD-P0-01B`, `AUD-P0-02-A`, `AUD-P0-02-B`, `AUD-P0-02C` — на исправленной
   ревизии ни один не даёт `trusted PASS`.
2. Сценарий B: `roguePosts=0` и `bearerLeaked=false` проверяются фактически по счётчикам
   rogue-процесса (не по тексту лога).
3. Нет ложного PASS, второго POST и второго terminal verdict: счётчики `verdict`/`request`/
   `standMutationCount` в evidence каждого сценария.
4. Попытки подмены Verification Worker и происхождения его ключа: `p0-01b` (чужой ключ,
   подмена pid, копия trusted-worker из другого пути, мёртвый Worker, ключ из runDir/candidate).
5. Replay подписанных ответов на другой challenge/runId и гибель стенда при закреплённом сокете:
   `p0-02c`. Подмена attestation/candidate/read-set после подписи: `p1-03`.
6. Обход через старый вход `start()`: `p2-old-entry-trust`.

## 6. Ограничения и риски

- Прогоны только локальные (локальный стенд/Chromium), Dev/ЦИЗ не использовались.
- Полная матрица из 13 строк на базе идёт около 4–5 минут; параллельно с `npm test` не запускалась.
- Атаки на происхождение ключа Verification выполняются через публичный (legacy) канал подписанта.
  Для доверенной топологии (приватный fork IPC Control→подписант) этот канал недоступен чужому
  процессу; сценарий фиксирует это в `evidence.scope` и при отсутствии канала возвращает `INCONCLUSIVE`.
- Остаточная модель A1–A3: код того же SID с правами инъекции/DPAPI вне модели (R-04);
  аудит не выдаёт ACCEPT — только независимый прогон и факты.
- Известная ранняя проверка: на коммите rem-c `3a51558` сценарий R-02 дал `PASS`
  (keygen отверг физический путь внутрь `runs` через junction, exit 1) — продуктовый код этой
  ветки не менялся, прогон независимый.

## 7. Ревизия

База прогона: `07c21c4db936627df9a3c874015327ea992a335a`.
Коммиты ветки `test/wp08-independent-audit`: `00ec4bf` (базовый комплект), `8d4606b` (сценарии
происхождения ключа, pinned/replay, подмена после подписи, старый вход); SHA отчёта — см.
`git rev-parse HEAD` в финальном сообщении Lead. Продуктовый код не изменялся.

## 8. Финальная независимая проверка remediation-кандидата

Проверяемая ревизия: `1a510a5d5929534d400dc965f58c78cf468bc270`.
Путь worktree: `C:\Users\gvi\Desktop\QA-ADAPTANT-harness\remediation`.
Все результаты ниже относятся к этому точному SHA, кроме Stable 0.1, который проверен на
неизменяемом теге и SHA, указанном отдельно. Проверки локальные; Dev/ЦИЗ не использовались.

| Проверка | Результат | Привязка |
|---|---|---|
| Unit и контрактные проверки в общем `npm test` gate | PASS: входят в 305/305, 0 fail; runner не публикует отдельный подытог только для unit | `1a510a5…`, рабочее дерево чистое |
| Локальный браузер и стенд | PASS: локальные Browser/Verification/trust-flow и WP-сценарии входят в 305/305; отдельный суммарный подытог runner не публикует | `1a510a5…`; Dev/ЦИЗ не использовались |
| `npm run test:races` | PASS: 3/3, 0 fail | `1a510a5…` |
| `npm run schemas` | PASS: экспортированы 6 структурных схем | `1a510a5…` |
| `npm run test:attacks` | PASS: W2 25/25, 0 fail/invalid/inconclusive | target snapshot `1a510a5…`, `targetDirty=false`; команда использует `--target=.` |
| Независимая R-D матрица | PASS: 15/15, `targetDirty=false` | `matrix-1a510a5.json`, revision `1a510a5…` |
| Stable 0.1 | PASS: 59/59 | тег `v0.1.0-stable`, SHA `88fc1d7b46e898b9d1ac85996042798fe55a2619` |
| Настоящий Dev | НЕ ЗАПУСКАЛСЯ | Dev/ЦИЗ не использовались |

JSON отчёт R-D сформирован командой `tests/audit-remediation/run-matrix.mjs` и находится рядом
с этим отчётом: `tests/audit-remediation/matrix-1a510a5.json`. Первый запуск этой матрицы без
системного `PSModulePath` завершился 14 `UNVERIFIABLE` из-за недоступного PowerShell `Get-Acl`;
после передачи `C:\Windows\System32\WindowsPowerShell\v1.0\Modules` матрица была запущена
повторно и дала приведённый выше результат 15/15 PASS. Ошибка окружения не классифицировалась
как дефект или успешное прохождение.

Wave-1 scripts сохранены отдельно как `npm run test:attacks:wave1`. Они загружают модули из
текущего checkout и не фиксируют отдельный baseline SHA. Это отдельная историческая матрица,
не текущий gate WP-08; её результаты не смешиваются с W2. На предыдущем SHA
`fba6aecb8226cf1ee6959eca3263f5007ce24452` наблюдалось 10 PASS, 2 FAIL и 4 INCONCLUSIVE.
В частности, часть Wave-1 сценариев ссылается на интерфейсы до WP-06, а RT-14/RT-15 дают
устаревшие ожидания для интегрированного кода. Wave-1 после этого SHA не запускалась.

Статус ограничен локальным техническим результатом и независимой матрицей. Это не ACCEPT,
не утверждение новой версии сценария владельцем и не результат прогона на настоящем Dev.
