# TRUST-ROOT-HARDENING-TESTS

Ревизия: ветка `fix/wp08-trust-root-hardening` от `1a510a5d5929534d400dc965f58c78cf468bc270`.

## F1 — регрессионный набор `tests/trust-root-pin.test.mjs` (7/7 PASS)

| Проверка | Результат |
|---|---|
| легитимный корень загружается, закрепление присутствует | PASS |
| подмена owner.pub/anchor.pub/ready.json → `TRUST_ROOT_KEY_SUBSTITUTION` | PASS |
| отсутствие trust-pin → `TRUST_ROOT_UNPINNED` | PASS |
| повреждённый конверт → `TRUST_ROOT_PIN_INVALID` | PASS |
| закрепление, скопированное из другого корня → отказ | PASS |
| ротация: `resealTrustRootPin` требует приватный ключ владельца | PASS |
| end-to-end QWEN-F1: подмена корня до запуска → нет POST, нет PASS | PASS |

Сырой журнал: `docs/gates/` (см. журнал gate ниже).

## Полный gate

Статус: выполняется на hardening-SHA; результат будет зафиксирован в
`docs/gates/hardening-npm-test.log`. Неисполненное не объявляется PASS.
