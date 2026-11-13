# TRUST-ROOT-HARDENING-TESTS

Ревизия: ветка `fix/wp08-trust-root-hardening`, база `1a510a5d5929534d400dc965f58c78cf468bc270`.
Проверенный SHA прогонов: **`0fcb9bc976adb690d391f3717b0cb7e578044c7d`** (worktree чистый).

## F1 — `tests/trust-root-pin.test.mjs`: 7/7 PASS

| Проверка | Результат |
|---|---|
| легитимный корень загружается, закрепление присутствует | PASS |
| подмена owner.pub/anchor.pub/ready.json → `TRUST_ROOT_KEY_SUBSTITUTION` | PASS |
| отсутствие trust-pin → `TRUST_ROOT_UNPINNED` | PASS |
| повреждённый конверт → `TRUST_ROOT_PIN_INVALID` | PASS |
| закрепление из другого корня → отказ | PASS |
| ротация требует приватный ключ владельца | PASS |
| end-to-end QWEN-F1: подмена корня до запуска → нет POST, нет PASS | PASS |

Журнал: `docs/gates/f1-tests.log`.

## Обязательные прогоны (SHA 0fcb9bc, clean)

| Гейт | Результат | Журнал |
|---|---|---|
| `npm test` | **312/312 PASS, 0 fail, exit 0** | `docs/gates/hardening-npm-test.log` |
| `npm run test:races` | **3/3, exit 0** | `docs/gates/races.log` |
| `npm run test:attacks` (Wave-2) | **25/25, exit 0** | `docs/gates/attacks.log` |
| `npm run schemas` | exit 0 | `docs/gates/schemas.log` |
| R-D матрица (15 сценариев) | **15/15 PASS**, revision=0fcb9bc, dirty=false | `docs/gates/rd-matrix.log` |
| Stable 0.1 | не запускался повторно; не изменялся | — |

## F3 — эксперимент и откат (доказательство регрессии)

На коммите `70c871e` (с заголовком `x-qa-run-id`) сценарий Wave-2 GAP-01 воспроизводимly падал:
несколько trusted-прогонов на одном стенде, второй получает `run_id_mismatch`, verdict INCONCLUSIVE,
анкер отсутствует. Журнал: `docs/gates/attacks-f3-experiment.log`.
Изменение откатано; итоговый набор зелёный.

## Ограничения

- Исходный `repro/r1-trustroot-substitution.mjs` от Qwen не использован: его аудиторская ветка
  на момент работы не опубликована. Применён эквивалентный e2e-сценарий подмены трёх файлов
  с проверкой отсутствия POST и PASS.
- F-06 (Stable 0.1) остаётся UNVERIFIABLE, решение — за владельцем.
- F2/F3/F4–F7 — см. `QWEN-FINDINGS-DISPOSITION.md`.
