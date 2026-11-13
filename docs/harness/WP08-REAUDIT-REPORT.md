# WP-08 REAUDIT — независимый аудит исправлений (поток R-D)

Ветка: `test/wp08-independent-audit` (worktree `rem-d`). База: `07c21c4db936627df9a3c874015327ea992a335a`.
Роль: независимый аудитор исправлений; продуктовый код не правится. Аудиторская ветка
`audit/wp-08-07c21c4` — только чтение.

## 1. Статус

| Этап | Статус |
|---|---|
| Перенос исходных атакующих сценариев в переиспользуемый каталог | DONE |
| Базовое воспроизведение на 07c21c4 (оба P0 + P1/P2) | DONE: 9/9 FAIL, exit 1 |
| Стресс/негатив на агрегатор матрицы | DONE: 5/5, exit 0 |
| Прогон сценариев против исправленных веток R-A/R-B/R-C | WAITING: Lead передаёт SHA |
| Атаки на происхождение ключа Verification (условие владельца §10.1) | PLANNED: сценарий `p0-01b-key-provenance.mjs` |
| Replay подписанных ответов стенда / pinned-соединение / гибель стенда (условие §10.2) | PLANNED: сценарий `p0-02c-pinned-stand.mjs`; условие `roguePosts=0, bearerLeaked=false` уже проверяется в `p0-02b` |
| Подмена Verification Worker и его выхода после подписи (§10.3.2) | PLANNED: сценарий `p1-03-substitution-after-anchor.mjs` |

Зелёный результат разработчиков без независимого прогона в этом каталоге закрытием не считается.

## 2. Каталог `tests/audit-remediation/`

Все файлы — самодостаточные `.mjs`; запуск `node <файл> --target=<worktree>`.
Продуктовый код проверяемой ветки не изменяется; временные каталоги — `%TEMP%`.

| Файл | Назначение |
|---|---|
| `audit-lib.mjs` | обвязка: `--target`, динамическая загрузка модулей ревизии, trust root, управляемый стенд, rogue, мир прогона, forge-цепочка, JSON-вердикт/exit code |
| `p0-01-forge-candidate.mjs` | AUD-P0-01 + обходы: подмена candidate после анкера, второй анкер, второй verdict |
| `p0-02a-swap-after-post.mjs` | AUD-P0-02-A: подмена стенда после POST, replay аттестации, честный контроль |
| `p0-02b-window-swap.mjs` | AUD-P0-02-B: окно T-C→POST, фактические счётчики rogue: `roguePosts`, `bearerLeaked` |
| `p1-01-weak-observer.mjs` | AUD-P1-01: паритет наблюдателя с 0.1 |
| `p1-02-v07-recovery.mjs` | AUD-P1-02 / V-07: восстановление после анкера без потери PASS |
| `p2-r02-junction.mjs` | AUD-P2-01: R-02 junction |
| `p2-approval-id-only.mjs` | AUD-P2-02: путь «только approvalId» |
| `p2-publication-no-choice.mjs` | AUD-P2-04: публикация без terminal-choice |
| `p2-e04-credential-ref.mjs` | AUD-P2-05: E-04 credentialRef |
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

## 4. Фактические результаты на 07c21c4

Команда:

    node tests/audit-remediation/run-matrix.mjs --target=<worktree 07c21c4>

Факт: `verdict=FAIL, exitCode=1, counts={FAIL:9}`. Все строки матрицы воспроизводят
дефекты исходного REJECT (подробности — `docs/harness/WP08-REAUDIT-BASE.md`):

| ID | Exit | Ключевые поля |
|---|---|---|
| AUD-P0-01 | 1 | signer: `ok=true, verdict=PASS`; observed: `trusted=true, passed=true, anchorStatus=ANCHOR_OK`; `standMutationCount=0` |
| AUD-P0-02-A | 1 | `verdict=PASS` при `comment=null` у реальной записи; rogue обслужил `/environment` и `/records` |
| AUD-P0-02-B | 1 | `standMutationCount=0`, `roguePosts=1`, `bearerLeaked=true`, `verdict=PASS` |
| AUD-P1-01 | 1 | 0.1-паритет: `Эффект не подтверждён независимым чтением`; trusted observer: `passed=true, PASS` |
| AUD-P1-02 | 1 | reconcile: `CANDIDATE_CONFLICT`; анкерованный PASS не восстановлен |
| AUD-P2-R02 | 1 | keygen exit 0; `secretsInRunDir=2` |
| AUD-P2-APPROVALID | 1 | `startTrusted({approvalId})` без документа → `BLOCKED` |
| AUD-P2-PUBLICATION | 1 | `publish()` бросил `TERMINAL_CHOICE_INCOMPLETE`, verdict `INCONCLUSIVE` без `terminal-choice` |
| AUD-P2-E04 | 1 | запросы с `Authorization`: 4; секрет доставлен стенду |

Негатив агрегатора:

    node --test tests/audit-remediation/matrix-negative.test.mjs
    tests 5 / pass 5 / fail 0, exit 0

Проверено: exit 0 без JSON не даёт PASS (`INVALID`); чужой scenario id не даёт PASS
проверяемой строке; чужая ревизия и расхождение exit code дают `INVALID`; таймаут даёт
`UNVERIFIABLE`; честный PASS-вердикт даёт `PASS`.

## 5. Ограничения и риски

- Прогоны только локальные (локальный стенд/Chromium), Dev/ЦИЗ не использовались.
- Сценарии A/B/P1-02/P2 требуют Chromium и идут ~2.5 минуты на полную матрицу; параллельно
  с `npm test` не запускались.
- Сценарии, зависящие от новых интерфейсов исправлений (`trusted-worker.mjs`,
  `registerVerificationKey`, подписанные ответы стенда), требуют адаптации при смене
  интерфейса; при несовместимости сценарий обязан вернуть `INCONCLUSIVE`, а не `PASS`.
- Остаточная модель A1–A3: код того же SID с правами инъекции/DPAPI вне модели (R-04);
  аудит не выдаёт ACCEPT — только независимый прогон и факты.

## 6. Ревизия

База прогона: `07c21c4db936627df9a3c874015327ea992a335a`.
Коммиты ветки `test/wp08-independent-audit` — см. `git rev-parse HEAD` в финальном сообщении Lead.
Продуктовый код не изменялся (`git status --porcelain` на момент сдачи — см. ответ Lead).
