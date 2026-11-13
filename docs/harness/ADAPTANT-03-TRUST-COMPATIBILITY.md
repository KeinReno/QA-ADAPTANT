# ADAPTANT 0.3 — совместимость с обновлением Trust Foundation

Дата: 2026-11-14  
База анализа: опубликованный Trust Foundation на `1a510a5d5929534d400dc965f58c78cf468bc270`.  
Статус: карта текущих зависимостей и план контрактных проверок; Trust Foundation не изменялась. Независимый аудит/исправление QWEN-F1 остаётся отдельной работой и не принимается этим документом.

## Публичный фасад и фактические вызовы

`TrustedFacadeExecutionAdapter` динамически импортирует только `apps/control/trusted.mjs` и использует четыре публичные функции:

| Вызов | Использование в адаптере | Текущая роль и последствия |
|---|---|---|
| `startTrusted(bundle, options)` | Только из `adapter.start()` после `READY`, сохранённого owner approval, проверки immutable plan/bundle binding и durable launch marker | Может исполнить один заранее зарегистрированный scenario. Требует Trust approval, issuer/subject, trust root, approval ID и Anchor-Signer. Результат runner не считается Task PASS без повторной проверки анкера. Может менять run, создавать evidence и публикации. |
| `observeTrusted({ root, trustRoot, runId, approvalId? })` | `adapter.observe()` и независимая проверка перед `TaskResult=PASS` | Читает frozen bundle/evidence/events и anchored verdict. Документ approval не требуется. Требуется тот же точный runId. Отсутствие trusted anchored PASS не становится PASS в ADAPTANT. |
| `cancelTrusted({ root, trustRoot, runId, subject, approvalId? })` | `adapter.cancel()` | Проверяет principal `subject` для текущего Windows SID и посылает отмену ровно существующему runId; документа approval не требует. Не создаёт новый run и не должен создавать повторную мутацию. |
| `reconcileTrusted({ root, trustRoot, approvalId, approval?, issuer, subject, ..., runId })` | `adapter.reconcile()` после уже записанного dispatch intent | Восстанавливает/завершает тот же run. Требует контекст для Trust PEP и signer. Это потенциально изменяющий состояние вызов, а не read-only observer; может публиковать verification result. Не повторяет dispatch через `startTrusted`. |

Публичные старые `start`/`observe`/`cancel`/`reconcile` намеренно не вызываются адаптером: они не несут trusted context и не могут выдавать trusted PASS. Другие export'ы `apps/control/trusted.mjs` также не входят в contract ADAPTANT 0.3.

## Контракт опций и root

Для `startTrusted` адаптер передаёт `root`, `trustRoot`, `approvalId`, `approval`, `issuer`, `subject`, `anchorKeyPath` либо signer-конфигурацию, а также `standPublicKey`, `credentials`/fixture token и timeout при наличии. Сейчас `signerPipe` считается legacy и отвергается; обязательный рабочий вариант — Anchor-Signer через `anchorKeyPath`. Чувствительные параметры остаются host resolver/runtime данными и не копируются в Task journal, API или отчёты.

`observeTrusted` получает `root`, `trustRoot`, `runId`, необязательный `approvalId`; `cancelTrusted` дополнительно получает `subject`. `reconcileTrusted` принимает полный Trust context и тот же `runId`. Owner plan approval из Task и Trust approval не взаимозаменяемы: `approvalRef` не подменяет Trust `approvalId`/approval document.

Текущая реализация ADAPTANT закрепляет абсолютный `root` каталога run в конструкторе и перепроверяет его на каждом вызове. `trustRoot` приходит из `resolveTrustOptions`; текущий адаптер не закрепляет его абсолютный путь или Trust identity в durable prepared binding и сам не обнаруживает смену `trustRoot` между фазами. Поэтому до отдельного изменения binding безопасность этой границы зависит от host resolver: он должен выдавать стабильный root между `prepare`, `start`, `observe`, `cancel` и `reconcile`. Формулировка «root switch должен fail closed» — требование будущей границы, не утверждение текущего поведения. Если remediation меняет эту предпосылку, требуется отдельное предложение на расширение prepared binding (Trust root identity/digest + approval identity) с независимым review. Это предложение не является изменением в данной ветке.

Адаптер дополнительно требует точное совпадение run root, `runId`, bundle digest, plan id/digest, owner approval ref, step digest и executionRef. Execution ref должен находиться в host registry. Он не предоставляет модели произвольный Trust API.

## Контрактные проверки для кандидата Trust update

Будущий compatibility suite должен запускаться на исходном и кандидатном Trust root в изолированных worktrees только после независимого ACCEPT соответствующей Trust remediation:

1. **Public facade shape:** four functions exported, signatures/options accepted; legacy untrusted entrypoints не начинают возвращать trusted PASS.
2. **No mutation before guards:** start without approval, wrong subject SID, missing/inactive principal, missing Anchor-Signer, wrong root or changed prepared binding — `BLOCKED`, dispatch count 0, fixture mutation count 0.
3. **Distinct approvals:** Task owner approval не удовлетворяет Trust approval; изменения issuer/subject/approval/run/environment/operation digest fail closed.
4. **Anchored observation:** без проверенной подписи анкера `observeTrusted` не сообщает trusted PASS. Наблюдение read-only: до/после вызова сверить bytes, names и digests журнала, evidence, terminal choice и anchor files.
5. **Same-run recovery:** `reconcileTrusted` работает только с уже существующим intent/runId и ожидаемыми frozen bytes; потерянный/другой run блокируется. Сравнить mutation count до/после и подтвердить, что второй `startTrusted` не вызывается.
6. **Same-run cancellation:** `cancelTrusted` сохраняет runId и привязывает subject к текущему SID; повторная/посторонняя отмена не запускает новый run и не превращает отменённый run в PASS.
7. **Root continuity:** один pinned Trust root на все фазы; неожиданный root/path/identity/digest rollover до формализации migration contract должен блокировать. Если кандидат требует разрешённой ротации, отдельный proposal и тестируют старый и новый root без смешивания artifacts.
8. **QWEN-F1 regression:** точный независимый regression от аудитора должен выполняться вместе с контрактными сценариями, но ownership исправления и его acceptance остаются у WP-08/Qwen.
9. **Evidence binding:** PASS агрегируется только если trusted observer подтверждает тот же runId, полный набор требуемых evidence IDs и связанную executionRef/approved plan.

Каждая проверка должна считать HTTP 200, текст модели, screenshot, runner result или сам факт существования evidence недостаточным для PASS. Результат делится на unit, локальный browser/local Trust world и настоящий Dev. В этом worktree проверяется только локальный Trust world; Dev не затрагивался.

## Граница изменений

- Ни один файл Trust Foundation, публичный Trust API, Trust schema, root, ключ, fixture или Dev environment не изменён.
- Этот отчёт не импортирует и не переносит DeepSeek remediation и не утверждает, что QWEN-F1 исправлен.
- До появления принятого candidate root compatibility проверка остаётся архитектурным тест-планом; фактический API test against update не выполнен.
