# 009 — durable provenance receipt for Verification recovery (draft)

Статус: **DRAFT — дизайн одобрен независимым review Luna; реализация и review реализации не выполнены**.

## Причина

После P0-01 подписант принимает только candidate вместе с аттестацией эфемерного доверенного
Verification Worker, чей ключ зарегистрирован по приватному IPC, nonce совпадает, а процесс жив
и имеет подтверждённое происхождение. При аварии Control после записи candidate эфемерный ключ
теряется. Новый Verification создаёт candidate с другими байтами (`completedAt`), поэтому
P1-02/V-06 recovery завершается `CANDIDATE_CONFLICT`. Переиспользование неподписанного candidate
как источника PASS ослабило бы цепочку происхождения.

## Предлагаемый инвариант

PASS после восстановления возможен только при наличии durable receipt, который Anchor-Signer
создал после полной проверки подписи Verification, происхождения живого процесса и связи с
текущими manifest, approval, evidence-chain и independent reads. Сырой candidate или одна лишь
attestation не дают права на восстановленный PASS.

## Точная форма receipt (предложение)

```js
{
  schemaVersion: '0.2.2', domain: 'verification-recovery-receipt',
  receiptId, runId, manifestSha256, approvalId, anchorId,
  candidate, candidateSha256,
  attestation, verificationPublicKey, verificationPid,
  provenance: { prepareControlPid, prepareLeaseToken, verificationPid, workerCreationTimeUtc, workerImage, verifiedAt },
  evidenceChainHead: { sequence, envelopeSha256 }, readSetSha256,
  createdAt, keyId, signatureAlgorithm, signature
}
```

Подпись охватывает всё тело кроме `keyId`, `signatureAlgorithm` и `signature` по правилам
`signTrustedDocument`. `candidate` — JSON-объект, сериализуемый существующей canonical JSON функцией
в UTF-8; `candidateSha256` равен текущему `digest(candidate)`. `receiptId` равен
`digest({ runId, approvalId, anchorId })` по canonical JSON существующей функции. Файл один на
`runId`, находится в `trustRoot/verification-receipts`
и создаётся без перезаписи; signer public key проверяется по `loadTrustRoot`. Receipt не содержит
секрета среды или Verification private key.

## Предлагаемый порядок публикации

1. Control получает эксклюзивный lease прогона от последнего чтения evidence до terminal choice.
   Durable lease identity — `{ runId, pid, token }`, где token — случайный UUID, уже создаваемый
   `acquireLease()` и записываемый в `leases/<digest({environmentId, fixtureId})>.json`. При prepare
   signer проверяет исходные PID/token с текущим файлом lease и записывает их в подписанную receipt
   как `prepareControlPid`/`prepareLeaseToken`; это историческая provenance, её не сверяют с новым
   lease при recovery. Каждая команда `status`, `finalize` и `cancel` отдельно предъявляет
   `currentCommandLease = { runId, pid, token }` нового Control по приватному IPC; signer сверяет
   его с текущим lease-файлом. На recovery signer parent PID должен совпасть с PID нового Control.
   Stale PID без совпадающего token не даёт права выполнить команду.
   После fork, но до передачи session nonce, Control сохраняет в журнале прогона PID и process
   identity Worker. Identity — `{ pid, creationTimeUtc, parentPid, executablePath, commandLineSha256 }`,
   где creationTimeUtc берётся Control и signer из `Win32_Process.CreationDate` посредством
   `Get-CimInstance`, а hash командной строки — digest её нормализованного значения. Тот же tuple
   сохраняется в journal, signer provenance и receipt; совпадения только PID недостаточно.
   Worker не читает и не дописывает evidence до получения nonce по приватному IPC.
   Поэтому crash до durable записи PID не может оставить Worker, способный менять evidence. Worker
   возвращает verdict, публичный ключ, подписанную verification-attestation, PID и session nonce
   только по fork IPC.
2. До записи candidate Control передаёт подписанту **одним** приватным IPC-запросом runDir,
   approvalId, candidate, заранее созданный anchorId, публичный ключ, PID, nonce и attestation.
   Раздельная регистрация ключа и последующая передача candidate запрещена. У запроса устойчивый
   ключ `(runId, approvalId, anchorId)`.
3. Подписант независимо перепроверяет подпись/домен/nonce аттестации, живость и происхождение
   Verification Worker, runId/manifest/approval, candidate hash, evidence-chain head, read-set,
   effect coverage и обязательные mutation/read evidence, перечитывая frozen bundle, approval,
   consumption и evidence из durable store. Он атомарно и fail-closed сохраняет подписанный
   anchor key receipt с canonical UTF-8 candidate bytes, attestation, ключом Verification и всеми
   связующими хешами. Receipt создаётся атомарно без перезаписи по устойчивому ключу запроса.
   Повтор идентичного запроса идемпотентен; другой candidate, manifest, approval, attestation или
   evidence head для того же runId отклоняется.
4. После durable receipt Control останавливает Worker и ждёт подтверждённого завершения процесса,
   затем перечитывает evidence-chain head. Если голова изменилась или завершение Worker нельзя
   доказать, публикация остаётся pending и PASS запрещён. Только после этого Control записывает
   candidate и продолжает обычный выпуск anchor, terminal-choice и verdict. Anchor id заранее
   закреплён в receipt, поэтому восстановление использует тот же id.
5. `reconcile()` сначала получает тот же эксклюзивный run lease, который удерживает `run()`; все
   prepare/status/finalize запросы проверяют этот lease и родительский Control PID. Подписант
   обрабатывает команды последовательно и прекращает незавершённые команды при потере IPC.
   Recovery допускается, только когда владелец старого lease и записанный signer PID подтверждённо
   завершились; при неизвестной живости остаётся pending. Это сериализует разные Control/signer
   процессы на одном локальном store. Между проверкой evidence head и атомарной записью receipt
   lease не позволяет Control дописать новые evidence; после receipt evidence-chain head frozen.
6. Reconcile запрашивает у подписанта receipt status по устойчивому ключу. Отсутствие ответа не
   доказывает отсутствие receipt. Reconcile сначала сверяет записанные PID и process identity
   Verification Worker: если старый Worker жив или состояние процесса неизвестно, остаётся pending;
   запрещены ответ «receipt отсутствует» и запуск нового Verification. После доказанного завершения
   старого Worker подписант сериализует status с prepare: если prepare уже создал receipt, он
   возвращает её; если receipt точно отсутствует и candidate ещё не опубликован, разрешён новый
   read-only Verification. При наличии receipt Reconcile проверяет её подпись и
   заново сверяет runId, manifest, approval, candidate bytes/hash, evidence-chain head и read-set
   с текущим durable run. Он восстанавливает candidate из receipt, если запись candidate ещё не
   состоялась, и завершает публикацию с тем же anchor id без повторного Verification и без
   повторной бизнес-мутации.
7. После фиксации receipt evidence-chain head неизменен до finalize; запись новых evidence до
   terminal-choice запрещена. Receipt связывает именно голову, проверенную до candidate.
8. Отсутствующий, повреждённый или не совпадающий receipt, неполная evidence chain, конфликт
   candidate/terminal-choice, отсутствующий/отозванный approval или ошибка подписи дают отказ
   fail-closed; PASS не публикуется. Существующий anchor с теми же байтами переиспользуется;
   другой anchor для того же run/candidate запрещён.
9. Если запрос finalize/подписи истёк по бюджету или его исход неизвестен, Control не пишет
   терминальный `INCONCLUSIVE`: он оставляет `PUBLICATION_PENDING`, закрывает/останавливает прежнюю
   signer-сессию и позволяет Reconcile завершить тот же receipt/anchor id. Finalize сериализован
   и идемпотентен по этому ключу: повтор возвращает тот же anchor, конфликт отвергается.
   Терминальный `INCONCLUSIVE` допустим только после durable signer-side cancel/tombstone либо
   эквивалентного сериализованного решения, которое навсегда запрещает finalize. Если signer
   недоступен или исход неоднозначен — публикация остаётся pending. Поздний anchor не может
   появиться после terminal-choice.
10. Receipt validation требует `attestation.pid === verificationPid ===
    provenance.verificationPid`; verification public key record должен иметь `keyId ===
    attestation.verificationKeyId`, а подпись attestation проверяется именно этим ключом.
    При создании receipt signer проверяет исходные `prepareControlPid`/`prepareLeaseToken` по
    durable lease и фиксирует их как историческую provenance. При recovery подписанная receipt
    проверяется без сравнения исходного lease с текущим; каждый новый `status`/`finalize`/`cancel`
    требует отдельный `currentCommandLease`, сверяемый с текущим durable lease, и signer parent
    PID текущего Control. Worker process identity в receipt, журнале и OS query должна совпасть
    целиком, включая OS creation time. `receiptId ===
    digest({ runId, approvalId, anchorId })`; `keyId` и `signatureAlgorithm` receipt входят в
    локальный allowlist. Все идентификаторы и хеши сверяются с текущими durable данными.
11. Terminal `INCONCLUSIVE` не создаётся поверх receipt с PASS. Если потребуется терминально
    отменить такой receipt, signer обязан атомарно записать подписанный tombstone под тем же lease:
    tombstone проигрывает уже durable anchor; если tombstone записан первым, будущий finalize
    навсегда запрещён. Без достоверного signer ответа итог остаётся pending.

## Граница изменения

Это расширение приватного Control→Anchor-Signer протокола и формата доверенного receipt 0.2.x.
Схемы 0.1, `packages/contracts`, экспортируемые JSON Schema и `docs/contract-freeze.json` не
меняются. Файл receipt не содержит токенов среды, ключа Verification или иных секретов;
verification private key остаётся только в памяти исходного Worker. Изменение не затрагивает
Dev/ЦИЗ и не объявляет приёмку WP-08.

## Открытые пункты для review Luna

- Подтвердить, что подпись receipt Anchor-Signer корректно сохраняет доказательство проверки
  происхождения после смерти Worker и не допускает повторного использования между прогонами.
- Проверить atomic-write / CREATE_NEW, идемпотентность, recovery при аварии на каждом шаге,
  конкурирующий reconcile и повторную/конфликтующую публикацию.
- Проверить, что signer при recovery не принимает candidate/attestation из запроса Control вместо
  данных подписанного receipt и не ослабляет текущую проверку `signAndPublish`.
- Утвердить точную форму receipt и минимальные API-команды до реализации.
- Явно проверить, что signer-timeout оставляет публикацию pending и что terminal `INCONCLUSIVE`
  не может конкурировать с завершением подписи; `assertNoTerminalChoice` само по себе недостаточно
  без сериализации, durable cancel/tombstone или доказанного прекращения signer-request.
- Проверить потерянный ответ prepare через устойчивый status/query, атомарную запись receipt и
  сериализацию prepare/status/finalize/cancel на `(runId, approvalId, anchorId)`; после receipt
  evidence-chain head и набор evidence неизменны до finalize.
- Межпроцессная сериализация: все команды идут под эксклюзивным lease `run/reconcile`; prepare
  фиксирует исторический `{runId,pid,token}`, а каждый status/finalize/cancel подтверждает
  актуальный `{runId,pid,token}` по текущему lease-файлу. Для recovery исходный lease не должен
  совпадать с новым; старый Control и signer завершаются до выдачи recovery lease.
  При невозможности доказать завершение — pending, никакого ответа «receipt отсутствует».
- Зафиксировать границу модели угроз для проверки процесса по PID/родителю/командной строке:
  текущая проверка WMI не является аттестацией целостности исполняемого кода.
- Проверить startup handshake: durable PID/process identity предшествуют выдаче session nonce; до
  nonce Worker не вправе читать или записывать evidence. Проверить crash в каждом промежутке
  handshake и невозможность orphan Worker с правом append.
- Проверить порядок prepare → stop/wait Worker → повторная сверка evidence head: receipt не даёт
  PASS, если Worker не завершился или evidence head изменился после подписания.
- Поля process identity (`pid`, OS-observed `creationTimeUtc`, `parentPid`, executable path и
  hash нормализованной command line), `workerImage` и `verifiedAt` входят в durable journal,
  signer provenance и подписанный receipt; creation time читается из `Win32_Process.CreationDate`
  через WMI/CIM, а не сообщается Worker. Отвергать несовпадение полного tuple, signer-parent PID,
  verification PID и attestation PID, verification public key/keyId и attestation keyId,
  algorithm/keyId receipt вне allowlist, подмену исторического prepare lease либо текущего command
  lease и неверный digest tuple.

## Обязательные проверки перед закрытием

- Красно-зелёные SIGKILL-сценарии до receipt, после receipt до candidate, после candidate до
  anchor, после anchor до terminal-choice и после terminal-choice до verdict.
- Подмена каждого поля receipt, candidate, attestation, runId, approvalId, manifest hash, nonce,
  evidence-chain head, read-set и anchorId; во всех случаях PASS запрещён.
- Повтор идентичного и конфликтующего receipt; одновременные reconcile; повторная мутация = 0.
- Сохранение исходных provenance/anchor/signed-environment регрессий и полной Windows Gate.
