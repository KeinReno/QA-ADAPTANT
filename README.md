# KAIDEN QA ADAPTANT

Автономный проект доказательного тестирования. Старые QA, их серверы, базы данных и локальные конфиги для запуска не нужны. ЦИЗ не изменяется.

Текущий результат — реализованное локальное ядро с реальными Browser Worker и Verification Worker, durable evidence и жизненным циклом `START / OBSERVE / CANCEL / RECONCILE`. Это ещё не выпуск 0.1: реальный CIZ Adapter и безопасный Dev-прогон впереди.

## Запуск на Windows

Требуется Node.js 24 и npm. В PowerShell:

```powershell
cd C:\Users\gvi\Desktop\QA-ADAPTANT
npm ci
npx playwright install chromium
npm run schemas
npm test
npm run demo
```

`npm run demo` поднимает изолированный localhost-стенд, выполняет создание записи через настоящий Chromium, независимо читает результат отдельным worker и сохраняет bundle, журнал и доказательства в `data/demo-<id>/`. Стенд после прогона останавливается. Dev и старые QA не используются.

## Просмотр и восстановление

Подставьте идентификатор из вывода demo:

```powershell
node apps/control/cli.mjs observe --root .\data\demo-<id> --run-id demo-<id>
node apps/control/cli.mjs reconcile --root .\data\demo-<id> --run-id demo-<id>
node apps/control/cli.mjs cancel --root .\data\demo-<id> --run-id demo-<id>
```

`observe` только читает и проверяет сохранённый журнал. `reconcile` не запускает Browser и никогда не повторяет мутацию. Повторный `start` с тем же неизменным bundle возвращает сохранённый терминальный результат; bundle с другим содержимым для того же `runId` отклоняется.

Для нового прогона через CLI нужен JSON bundle:

```powershell
node apps/control/cli.mjs start --root .\data\my-run --bundle .\data\my-run\bundle.json
```

## Проверки

- 12 контрактных unit-тестов.
- 13 браузерных проверок: нормальный путь и 12 fault/guard-сценариев.
- 8 lifecycle/integrity-проверок, включая настоящий аварийный перезапуск Control через отдельный процесс.
- Всего: 33/33 в актуальном полном прогоне.

Фактические границы и незакрытые этапы: [ACCEPTANCE-REPORT.md](ACCEPTANCE-REPORT.md). Для продолжения: [HANDOFF.md](HANDOFF.md), [WORKPACKS.md](WORKPACKS.md). Полная цель — мастер-план в `docs/sources`; локальное ядро не считается готовой ЦИЗ-приёмкой.

Исходный 23-шаговый текст сохранён в `docs/sources/scenario-original.ru.txt`. Предложенная правка пункта 7 — только DRAFT в `docs/scenario-proposed.DRAFT.ru.txt`; владелец её не утверждал. Intelligence и Workbench ещё не реализованы.
