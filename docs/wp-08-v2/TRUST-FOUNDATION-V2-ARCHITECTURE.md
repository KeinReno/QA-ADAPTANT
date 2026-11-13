# TRUST FOUNDATION V2.1 — АРХИТЕКТУРА (ревизия после REVISION REQUIRED)

Статус: DRAFT для архитектурной ре-приёмки Qwen. Реализация запрещена до ACCEPT.
База пакета: продуктовая линия **1a510a5** (полный 0.2, без отклонённого trust-pin).
Исходный аудит: **6270128149bc300b85024d5ad21737bfc5680100**; предыдущая архитектура f995733.
Модель A1–A3 сохраняется полностью.

## 0. Что изменено относительно f995733 (кратко)

| Замечание Qwen | Решение в этой ревизии |
|---|---|
| Цепочка A (TAS как оракул подписи) | TAS **сама порождает** доверенное исполнение Verification, принимает анкер только по каналу, созданному TAS, с эфемерной подписью Worker; TAS пересчитывает readSet/candidate из защищённых durable-записей (M01, §4) |
| Цепочка B (поддельная TAS) | Взаимная аутентификация IPC: проверка SID сервера + подпись ответов ключом TAS, закреплённым в установочном каталоге; FIRST_PIPE_INSTANCE; отказ без fallback (M03, §6) |
| Цепочка A, шаг 2 (перехват approval) | Состояние потребления и привязка approvalId→runId — только в TAS; grant выдаётся лишь исполнению, созданному TAS. Остаточный DoS назван явно (§5) |
| M04 (grant на диске) | Grant не покидает TAS/доверенный процесс: доставка по унаследованному handle, без файлов/env/argv/пользовательского IPC (§7) |
| M07 (DPAPI LocalMachine) | DPAPI LM — только defense-in-depth; граница = ACL файла ключа (SID службы) + контекст службы (§8.3) |
| M08 (legacy) | Legacy-анкеры = `legacy-unverified`, автоприёмки PASS нет, только переаттестация владельцем (§9) |
| M09 | Вынесено в OWNER-DECISIONS.md как обязательное условие развёртывания |
| M10 | Пакет перенесён на 1a510a5, карта API/0.3 в ADAPTANT-03-COMPAT.md |
| M11–M12 | Условия будущей реализации/приёмки в IMPLEMENTATION-PLAN §S8 и SECURITY-INVARIANTS INV-18/19 |

## 1. Компоненты и доверительная схема

```
Пользовательский SID (A2, не-админ по условию M09)
  Control / Browser Worker / CLI / tests
      │  IPC v1: mutual auth (server SID + подпись TAS), grant только в памяти
      ▼
┌──────────────────────── TAS (NT SERVICE\KAIDEN-TAS) ───────────────────────────┐
│ Trust Registry (append-only, HWM, подписи владельца/админа)                     │
│ Session/Grant/Approval state (single-writer, журнал, HWM)                       │
│ TAS-Verifier: spawn + эфемерный ключ + приём attestation + паритет проверок     │
│ Anchor key: файл с ACL только SID службы; DPAPI LM = defense-in-depth           │
└──────────┬──────────────────────────────────────────────────────────────────────┘
           │ TAS-owned pipe + эфемерный Ed25519 (передан по handle)
           ▼
   Verification Worker (дочерний процесс TAS; без долгоживущих ключей)
           │  HTTP к локальному стенду (pinned), независимые чтения
           ▼
   runDir (A2-writable) — но каталог evidence доверенного прогона создан TAS
                          с ACL службы; пользователь не пишет туда
```

Доверенные компоненты: TAS, её дочерний Verification Worker (в пределах сессии),
Registry, ключ анкера. Не доверенные: Control, пользовательские процессы, runDir,
trustRoot, публичный IPC-клиент.

## 2. Ключевой принцип

**Ни один факт исполнения, влияющий на PASS, не принимается из пользовательского
процесса или пользовательского каталога как истина.** TAS подписывает только то, что
подтверждено аттестацией процесса, созданного TAS, и пересчитано из durable-записей,
запись в которые контролирует TAS.

## 3. Модель A1–A3 (без сужения)

A1/A2/A3 — как в `docs/harness/WP08-REMEDIATION-ARCHITECTURE.md` (ревизия 1a510a5):
A2 включает процессы того же Windows SID, запись любых файлов runDir/trustRoot, подключение
к публичным локальным каналам, HTTP. Не включает отладку/инъекцию в доверенные процессы и
извлечение приватных ключей через DPAPI. V2.1 не сужает A2; граница обеспечивается тем,
что TAS не принимает решения из данных A2-зоны (см. §4–§9), а не переопределением модели.

## 4. M01 — достоверность Verification (цепочка A)

### 4.1. Создание доверенного исполнения

1. Control запрашивает у TAS `prepare-run` (runId, approval, bundle-хеши). TAS проверяет
   approval-подпись по enrolled ownerKeyId, атомарно связывает approvalId→runId (§5),
   создаёт `trustedRunId` и **каталог evidence** `runDir/trusted/` с ACL: SID службы —
   запись, пользователь — чтение (или без доступа к внутренним файлам).
2. TAS **сама** создаёт Verification Worker (child process под SID службы), генерирует
   эфемерную пару Ed25519 в памяти, передаёт приватный ключ и sessionId только по
   унаследованному handle; публичный ключ регистрирует в состоянии сессии.
3. Worker выполняет независимые чтения и пишет evidence-артефакты в каталог, контролируемый
   TAS; каждый артефакт получает content-hash в append-only цепочке TAS.
4. Worker формирует и подписывает эфемерным ключом `verification-attestation`:
   {schemaVersion, domain, runId, approvalId, manifestSha256, candidateSha256,
    readSetSha256, evidenceHead, verificationKeyId, pid, startedAt, nonce, sessionId, decision}.
5. TAS принимает attestation **только** по каналу этой сессии, проверяет подпись
   зарегистрированным эфемерным ключом, nonce/sessionId/TTL, затем **пересчитывает**:
   - byte-identity candidate: sha256 фактических байтов candidate == candidateSha256;
   - readSetSha256 по durable evidence (evidenceId + artifact.sha256 + kind), записанным
     под контролем TAS;
   - паритет `assertEvidenceRefs`, `assertTerminalEvidence`, `validateVerdictCoverage`;
   - привязку к approval (operation/inputs/fixture/environment/manifest).
6. Только после этого TAS выпускает signed receipt и подписывает anchor-statement
   ключом анкера. В statement добавляются `verificationKeyId`,
   `verificationAttestationSha256`, `sessionId`, `trustRegistryVersion`.

### 4.2. Почему поддельный процесс того же SID не получит анкер

- У него нет эфемерного приватного ключа сессии, созданной TAS (ключ живёт только в памяти
  TAS и дочернего Worker, передан по унаследованному handle; на диск/env/argv не попадает).
- Он не может подключиться к TAS-owned каналу сессии: канал создан TAS с ACL на SID службы,
  дескриптор наследуется только Worker.
- Он может записать согласованные файлы в runDir, но evidence доверенного прогона пишется
  в каталог с ACL службы; TAS не читает evidence из пользовательской зоны как доказательство.
- Даже при валидном публичном approval он получит только отказ/DoS (approval уже связан
  с runId — §5), а не подпись.

## 5. M02 — потребление approval/grant

Всё состояние — в защищённом сторе TAS (append-only журнал + HWM, §8.2), не в файлах:

states: `AVAILABLE → BOUND(runId) → GRANTED(nonce, ttl) → CONSUMED → ANCHORED`;
боковые: `REVOKED` (cancel), `EXPIRED`, `FAILED`. Переходы — single-writer транзакции TAS.
Инварианты: одноразовое потребление; привязка approvalId→runId при первом `prepare-run`;
повторный grant → `APPROVAL_REPLAY`; cancel атомарно отзывает grant до подписи;
подпись после отзыва запрещена; второй POST запрещён (мутация только через подтверждённый
grant + receipt).

**Перехват approval.** Атакующий может успеть первым вызвать `prepare-run` с чужим approval,
создав DoS для легитимного прогона. Это **не ложный PASS**: подписи анкера он не получит
без TAS-исполнения. DoS фиксируется явно; смягчение — owner-visible журнал bind-событий,
revoke/rebind владельцем, отдельная политика (OWNER-DECISIONS D4).

## 6. M03 — аутентификация IPC (цепочка B)

1. Служба создаёт канал с `FILE_FLAG_FIRST_PIPE_INSTANCE` и security descriptor
   (Users: connect; запись/чтение — по протоколу; SID службы — полный доступ).
2. Клиент после connect: `GetNamedPipeServerProcessId` → открыть процесс → токен →
   SID == SID службы KAIDEN-TAS (виртуальная учётная запись, не LocalSystem).
3. Handshake: клиент присылает nonce; TAS отвечает `serverAuth` — подписанный её ключом
   {nonce, sessionId, serverVersion, capabilities}. Клиент проверяет подпись по **ключу
   TAS, закреплённому в установочном каталоге продукта** (не user-writable; ACL: admins/
   service, чтение всем; хеш ключа вшит в код клиента при сборке).
4. Все ответы в сессии подписываются/HMAC ключом сессии (ECDH: эфемерные X25519 TAS+клиент,
   подтверждённые подписями обеих сторон). Повторный запуск службы = новая сессия.
5. Отказ любой проверки → fail-closed, без «тихого» fallback и без выбора канала из
   env/config пользователя. Fake-провайдер в клиенте отсутствует (M11).

## 7. M04 — grant не покидает доверенную зону

- Grant/session key существует только в памяти TAS и дочернего Verification Worker;
  передаётся по унаследованному handle, не через файлы, env, argv, журналы, публичные
  IPC-глаголы.
- Публичный IPC не содержит глаголов, возвращающих grant/ключи. Anchor-sign принимается
  только в канале Worker-сессии (не от пользовательского клиента).
- Grant: audience = TAS-Verifier session; single-use; TTL; привязан к runId/approvalId/
  manifestSha256/nonce/sessionId; отзывается cancel.

## 8. M05–M08 — доверенная конфигурация

### 8.1. M05 Enrollment/Rotation
`kaiden-trust-admin enroll|rotate` — отдельная административная граница (secure desktop UAC,
отдельная учётная запись администратора). Fingerprint owner/anchor вводится владельцем из
внешнего офлайн-источника и сверяется с вычисленным; подтверждение обязательно и не имеет
флага «пропустить». Повторный enroll существующего trustRootId отвергается. Ротация
сверяется с внешним ожидаемым keyId, а не с файлом из подменяемого каталога.

### 8.2. M06 Registry
Append-only; `registryVersion` монотонен; high-water mark хранится в отдельном защищённом
состоянии TAS и сверяется при чтении/восстановлении; rollback/удаление → fail-closed;
backup подписан владельцем и принимается только с версией ≥ HWM. ACL записи: SYSTEM +
SID службы (Admins — не писатели; админ-деградация — M09).

### 8.3. M07 Ключ анкера
Файл ключа: ACL только SID службы (пользователь — без доступа), каталог — вне user-writable.
DPAPI LocalMachine используется как дополнительный слой, но **не заявляется границей**:
любой локальный процесс может распечатать LM-конверт; защита — ACL + контекст службы.

## 9. M08 — исторические анкеры

Анкеры/прогоны до v2 получают статус `legacy-unverified`: они не дают trusted PASS
автоматически; `observeTrusted` возвращает INCONCLUSIVE/LEGACY_UNVERIFIED, а не PASS.
Переаттестация — только явное решение владельца с офлайн-подтверждением fingerprint
исторических ключей; иначе статус остаётся историческим. Старый `trust-pin.json`
(41043ad) не переносится и не считается защитой; `createTrustRoot` создаёт корень,
не доверенный до enrollment.

## 10. Остаточные риски (явно)

- owner=админ → граница не обеспечивается (M09, решение владельца).
- Компрометация административной границы/ядра/самой TAS (вне A2).
- DoS через перехват approval (не ложный PASS, §5).
- TPM/HSM защищает ключ, но не мешает подменить код службы при административной компрометации.
