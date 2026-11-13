# 005 — реестр сред: поколения и отзыв

Причина: внутреннее ревью WP-04 (docs/harness/WP-04-INTERNAL-REVIEW.md, D-01 HIGH) установило, что
раскладка `trustRoot/environments/<environmentId>.json` с `CREATE_NEW` не даёт owner'у опубликовать
новое поколение и не позволяет отозвать уже зарегистрированную среду. Контракт WP-00 требует stable
`environmentId` при меняющихся `generation` и `status`; одно имя файла с запретом перезаписи этому
противоречит.

Затрагивает только новый модуль `packages/trust/environment.mjs` (WP-04). Схемы 0.1, `docs/contract-freeze.json`,
формат evidence и VerdictPolicy 0.1 не меняются.

## Решение

- Каталог реестра: `trustRoot/environments/<environmentId>/<generation>.json` — отдельный файл на каждое поколение.
- `commitEnvironmentRecord` пишет `CREATE_NEW` файл поколения:
  - та же запись повторно — идемпотентный успех;
  - та же `generation` с другим содержимым — `CONTRACT_INVALID`;
  - `generation` ниже уже существующего максимума — `CONTRACT_INVALID` (назад публиковать нельзя).
- `loadEnvironmentRecord` перечисляет каталог, проверяет подпись каждой записи, выбирает запись с
  максимальным `generation` (числовое сравнение). `status=revoked` у последнего поколения — `ENVIRONMENT_REVOKED`;
  `status=disabled` возвращается вызывающему, решение даёт PDP (`ENVIRONMENT_REVOKED` по статусу).
- Отзыв среды или блокировка — публикация поколения N+1 со `status=revoked` / `disabled` подписью owner.
  Смена ключа стенда, порта или origin — тоже новое поколение.
- Старый путь `environments/<environmentId>.json` не поддерживается: развёрнутых реестров этой ревизии нет,
  в WP-04-REPORT переход указан явно.

## Следствия

- `environmentGeneration` в approval остаётся обязательным: после смены поколения старое разрешение не проходит
  ни на preflight (PDP: `APPROVAL_MISMATCH` / `ENVIRONMENT_ATTESTATION_FAILED`), ни на dispatch.
- Отзыв среды немедленно запрещает новый dispatch и новое доверенное чтение через PDP; уже записанные доказательства не переписываются. Уточнение — docs/changes/007.
- Код, тесты и отчёт WP-04 обновляются в той же ветке; закрытие D-01 подтверждается тестами на отзыв,
  смену поколения и отказ публикации назад.