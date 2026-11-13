# WP-08 REMEDIATION — воспроизведение P0 на 07c21c4 (Lead)

Дата: 13.11.2026. Окружение: Windows, Node v24.16.0, npm 11.13.0.
Аудиторский worktree: C:\Users\gvi\Desktop\QA-ADAPTANT-harness\audit (detached, origin/audit/wp-08-07c21c4 = 7034562).
Аудиторская ветка не изменялась: git status пуст.

## AUD-P0-01 — подделка candidate/evidence и годный анкер

Команда (в аудиторском worktree): `node wp08-audit/tests/wp08-r07-forge-candidate.mjs`

Фактический вывод:

    SIGNER_RESULT {"ok":true,"verdict":"PASS","candidateSha256":"d80553e1..."}
    TRUSTED_OBSERVE {"state":"terminal","trusted":true,"passed":true,"verdict":"PASS","anchorStatus":"ANCHOR_OK"}
    OLD_OBSERVE {"verdict":"PASS","reasonCode":"NONE"}
    PUBLIC_OBSERVE_TRUSTED {"trusted":true,"passed":true,"verdict":"PASS","publication":"terminal","anchorStatus":"ANCHOR_OK"}
    VERDICT_FALSE_PASS_SHOWN true

Exit code: 0. Реальной мутации не было; Verification не выполнял независимых чтений. Дефект воспроизведён.

## AUD-P0-02 — подмена стенда после T-C/после POST

Команда: `node wp08-audit/tests/wp0304-06-false-pass.mjs`

Фактический вывод:

    ✔ A: подмена стенда между POST и независимым чтением Verification даёт ложный доверенный PASS (8282 ms)
    ✔ B: подмена в окне после beforeRequestAck (mutation уходит rogue) — попытка полного PASS (7365 ms)
    tests 2 / pass 2 / fail 0

Exit code: 0. Оба сценария воспроизведены: сценарий A — неполная запись + rogue отдаёт «полную»;
сценарий B — мутаций на настоящем стенде 0, POST ушёл rogue, Bearer утёк, PASS подтверждён.

## Вывод

Оба P0 подтверждены собственным прогоном Lead, а не текстом отчёта аудита. До закрытия этих дефектов
никакая новая ревизия не может называться кандидатом на приёмку.
