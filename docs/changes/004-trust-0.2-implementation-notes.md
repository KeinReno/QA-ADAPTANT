# 004 — уточнения реализации Trust Foundation 0.2

Статус: запись Lead-оркестратора по ходу WP-03…WP-07. Не меняет замороженные схемы 0.1.
Полные интерфейсы — в `docs/harness/BASELINE-AND-CONTRACTS.md`.

## 1. Новые модули (не затрагивают packages/contracts и schemas)

| Модуль | Пакет | Назначение |
|---|---|---|
| `packages/trust/environment.mjs` | WP-04 | реестр сред, challenge-response аттестация стенда |
| `packages/trust/anchor.mjs` | WP-05 | candidate, terminal-choice, единственный terminal verdict, проверка анкера |
| `packages/trust/anchor-signer.mjs` | WP-05 | отдельный подписант `anchor-statement` в локальном канале |
| `packages/trust/policy.mjs` | WP-03 | чистый PDP `decide(facts)` и проекция в verdict 0.1 |
| `packages/trust/windows-sid.mjs` | WP-06 | SID текущего Windows-токена |
| `packages/trust/facts.mjs` | WP-06 | сборщик фактов для PDP |
| `apps/control/trusted.mjs` | WP-06 | `startTrusted/observeTrusted/cancelTrusted/reconcileTrusted` |

## 2. Точечные уточнения, требующие записи

### 2.1. reasonCode для операции вне реестра 0.1

В таблице кодов `TrustDecision` (`docs/wp-00/03-CONTRACT-PROPOSALS.md`) нет отдельного кода для «операция
не входит в доверенный реестр 0.1». PDP возвращает `DENY` с `reasonCode = CONTRACT_INVALID`. Это код
старого enum 0.1, он не добавляется в схему и наружу проецируется в `CONTRACT_INVALID`. Записано здесь,
чтобы не выглядело молчаливым расширением.

### 2.2. Имена файлов доверенного прогона

`docs/wp-00` задаёт смысл, но не имена. Зафиксировано:

- `runDir/trust/candidate.json` — `canonical(candidate) + '\n'`;
- `runDir/trust/terminal-choice.json` — выбор исхода, `CREATE_NEW`;
- `runDir/trust/decision.json` — последнее `TrustDecision` прогона;
- `trustRoot/environments/<environmentId>.json` — подписанная запись среды;
- `trustRoot/anchors/<anchorId>.json` — `anchor-statement`.

### 2.3. Локальный стенд: аддитивный endpoint

`adapters/local/server.mjs` получает `POST /attest` (challenge → подпись ключа стенда) и дополнительные
поля в объекте, который возвращает `serveLocalFixture()`. `GET /environment` и прежние коды не меняются,
поэтому старые тесты 0.1 остаются валидными.

### 2.4. Точка T-C

`apps/browser/worker.mjs` и `apps/verification/worker.mjs` не меняются. Проверка «процесс стенда ещё жив»
стоит в Control непосредственно перед `EVIDENCE_ACK` на `HTTP_REQUEST` — это последняя точка, которую Control
контролирует до `route.continue` в Browser. Остаточная гонка фиксируется как риск R-03, а не лечится повтором POST.

## 3. Что не меняется

Схемы 0.1, `docs/contract-freeze.json`, формат `evidence-commits`, `VerdictPolicy`, `RunProtocol`,
`EvidenceSchema`, реестр `local-create-record`, старые входы `start/observe/cancel/reconcile`.

### 2.5. Тела кандидатов и четвёртый исход выбора

Доверенный прогон может иметь два кандидата (бизнес-PASS и заменяющий его INCONCLUSIVE по бюджету). Чтобы после падения дописывать ровно выбранные байты, а не пересчитывать их:

- `runDir/trust/candidates/<candidateSha256>.json` — тело каждого опубликованного кандидата, `CREATE_NEW`;
- `publishTerminalVerdict` читает тело выбранного `candidateSha256` из этого каталога.

Принято четвёртое значение `terminal-choice.outcome` — `inconclusive-without-anchor`: для бизнес-вердикта INCONCLUSIVE, который не является PASS и не требует анкера. `anchorId` и `discardedCandidateSha256` равны `null`, байты выбранного кандидата не пересчитываются. Остальные исходы (`anchor`, `budget-inconclusive`, `fail-without-anchor`) остаются как в WP-00.

### 2.6. Бюджет анкера и профиль trust root

WP-00 задаёт `anchorBudgetMs` в подписанном профиле trust root, но в WP-01 нет домена `trust-profile`, поэтому в 0.2 бюджет не проверяется криптографически: по умолчанию 5000 мс, диапазон 1…60000, вызывающий его не меняет. Это зафиксированный остаточный риск R-05: подмена файла профиля может изменить длительность ожидания, но не создаёт PASS без анкера и не открывает второй POST. Подписанный домен профиля — отдельное изменение после 0.2.

### 2.7. Наблюдения внутреннего ревью WP-03

Ревью Agent A (docs/harness/WP-03-INTERNAL-REVIEW.md) зафиксировало три принятых исключения:

- `randomUUID` внутри `decide()` не является криптографией доверия: это идентификатор решения, не ключ и не подпись.
  Требование §5.3 «без криптографии» относится к проверке подписей и генерации ключей.
- `projectToVerdict` экспортируется сверх §5.3. Это разрешённое расширение: функция нужна WP-06 для проекции
  отказа в замороженный enum 0.1 и не влияет на решение PDP.
- `MUTATION_ALREADY_RECORDED` и `APPROVAL_CONSUMED` проецируются в `BLOCKED`/`CONTRACT_INVALID`. Доверенный путь
  обязан не доходить до dispatch при уже записанном intent: T-B вызывается только когда intent ещё не записан,
  поэтому второй dispatch не возникает, а проекция остаётся консервативной.
