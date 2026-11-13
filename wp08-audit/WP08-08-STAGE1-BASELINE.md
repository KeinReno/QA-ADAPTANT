# WP08-08 — ЭТАП I: БАЗОВАЯ ЛИНИЯ И ЦЕЛОСТНОСТЬ ПОСТАВКИ

Аудитор: DeepSeek (self-audit маркирован отдельно, см. WP08-09 §5).
Дата: 2026-11-13. Ветка аудита: `audit/wp-08-07c21c4`.
Работа: worktree `QA-ADAPTANT-harness/remediation`, продукт не изменялся.

## 1. Зафиксированная ревизия

| ref | SHA | Проверка |
|---|---|---|
| `fix/adaptant-02-wp08-remediation` | 1a510a5d5929534d400dc965f58c78cf468bc270 | local HEAD == remote (`git ls-remote`) |
| `test/wp08-independent-audit` | cf1b951f3061b81c7a7f4b300884641c97868b66 | local HEAD == remote |
| `main` | 59d82d49c01442d463ebab5d5f3d661ca550e504 | merge не выполнялся |

База сравнения `07c21c4` — предок HEAD (`merge-base --is-ancestor` = 0).
Worktree remediation: `git status --porcelain` = 0 файлов (чисто до и после запуска тестов).

## 2. Состав изменений относительно 07c21c4

48 файлов, +6837/−581. Продуктовые изменения: `apps/control/trusted.mjs`, `apps/control/run.mjs`,
`apps/browser/trusted-worker.mjs` (новый), `apps/verification/trusted-worker.mjs` (новый),
`packages/trust/{anchor,anchor-signer,approval,environment,facts,identity,keygen}.mjs`,
`packages/core/file-mutex.mjs` (новый), `adapters/local/server.mjs`.
Тестовая часть: 4 новых trust-набора, изменения redteam W2 и run-matrix.
Документы: `docs/changes/008,009`, `docs/harness/WP08-*`.

Полный список: `evidence/stage1/changed-files.txt`, статистика: `diff-stat.txt`.
Stable 0.1 (`master`/тег) в diff не входит — отдельных правок не обнаружено.

## 3. Секреты

Сканирование diff 07c21c4..HEAD по шаблонам приватных ключей, GitHub/Slack/AWS-токенов: совпадений нет.
Два текстовых вхождения «private key» — русскоязычные комментарии документов, не материал ключей.
Полный вывод: `evidence/stage1/secret-hits.txt`. Ограничение: сканирование не заменяет проверку
истории артефактов R-D-ветки; выборочная проверка JSON-артефактов выполнена Luna, повторена в этапе II при разборе evidence.

## 4. Окружение

Windows (NT 10.0.26100), Node v24.16.0, npm 11.13.0 (`evidence/stage1/env.txt`).
Windows Gate технически возможен — отдельный прогон в этапе II.

## 5. Доказательная база

- Сырые логи `npm test`, `test:races`, `schemas`, `Stable 0.1` в опубликованном R-D отсутствуют.
  Классификация: **пробел доказательной базы, не дефект продукта**. Закрывается собственными прогонами (этап II).
- В R-D присутствуют JSON-результаты W2 (25/25) и R-D (15/15) — принимаются только после сверки с кодом тестов.

## 6. Вывод этапа I

Ревизия подтверждена, продуктовая ветка неизменна, посторонних изменений и секретов не обнаружено.
Блокеров для перехода к этапу II нет.

## 7. Ограничения

- Статический разбор: прочитаны ключевые участки `trusted.mjs` (publish, recovery, PEP-границы),
  реестр экспортов `anchor.mjs`, карта входов; полный построчный разбор не заявляется.
- Этап I не подтверждает и не опровергает отсутствие ложного PASS — это этап II.
