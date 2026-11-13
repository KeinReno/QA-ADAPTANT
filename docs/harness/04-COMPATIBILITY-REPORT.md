# 04 — COMPATIBILITY REPORT (сохранность Stable 0.1)

Проверено на интеграционной ветке относительно базы 0.2 (0e7e6c2), которая сама является продолжением
тега v0.1.0-stable.

## Структурная неизменность

`git diff 0e7e6c2..<integration HEAD>` по путям законсервированного ядра и контрактов — **пусто**:

- packages/contracts/
- schemas/
- docs/contract-freeze.json
- packages/core/ (store, canonical, evidence-policy, bundle, approved-registry)
- apps/browser/worker.mjs
- apps/verification/worker.mjs
- adapters/local/bundle.mjs

Тег Stable не переносился: `v0.1.0-stable` — аннотированный тег fd722ce, указывает на коммит
88fc1d7b46e898b9d1ac85996042798fe55a2619 (совпадает с зафиксированным в WP-00).

## Изменения продуктового кода

| Файл | Тип | Обоснование |
|---|---|---|
| apps/control/run.mjs | изменён | точки врезки T-A/T-B/T-C/T-D, передача trust-контекста, запрет аргументов доверия на старом входе |
| packages/trust/keygen.mjs | изменён | R-02: отказ от каталогов прогонов |
| adapters/local/server.mjs | изменён аддитивно | POST /attest, ключ стенда в памяти, поля standKeyId/standPublicKey/pid/generation; GET /environment не менялся |
| все остальные файлы | новые | packages/trust/*, apps/control/trusted.mjs, tests/trust-*.test.mjs |

## Поведенческая совместимость

- Старый вход start/observe/cancel/reconcile не требует trust root и работает как в 0.1; при передаче
  аргументов доверия он отвергает вызов кодом CONTRACT_INVALID и не выполняет мутацию (L-08).
- Отсутствие каталога runDir/trust/ означает прогон старого входа; новые поля в VerdictPolicy не добавлялись.
- Формат evidence-коммитов, правило одной мутации, lease и привязка fixture не менялись.
- Схемы 0.1: `npm run schemas` завершается без диффа файлов schemas/.

## Фактические прогоны

Числа берутся из финального прогона на зафиксированном SHA и дублируются в 02-TEST-EVIDENCE.
Старый набор 0.1 входит в общий `npm test` и должен остаться зелёным без правок старых тестов.
