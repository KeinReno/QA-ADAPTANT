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
