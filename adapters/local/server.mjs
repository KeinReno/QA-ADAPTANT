import { createHash, randomUUID } from 'node:crypto';
import http from 'node:http';

const hash = value => createHash('sha256').update(value).digest('hex');
const baseHtml = (ambiguous = false) => `<!doctype html><html lang="ru"><meta charset="utf-8"><title>QA Adaptant local fixture</title>
<main><form aria-label="Создать запись">
<label>Название<input name="title" autocomplete="off"></label>
<label>Исполнитель<input name="executorId" autocomplete="off"></label>
<label>Комментарий<input name="comment" autocomplete="off"></label>
<label>Маркер fixture<input name="fixtureId" autocomplete="off"></label>
<button type="submit">Создать</button>${ambiguous ? '<button type="button">Создать</button>' : ''}
</form><p role="status" aria-live="polite"></p></main>
<script>
const form=document.querySelector('form');
form.addEventListener('submit',async event=>{
 event.preventDefault(); const fields=Object.fromEntries(new FormData(form).entries());
 const status=document.querySelector('[role=status]');
 try { const response=await fetch('/records',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(fields)});
  if(!response.ok) throw new Error('HTTP '+response.status); const data=await response.json(); status.textContent='Создана запись '+data.id;
 } catch { status.textContent='Ответ не получен; состояние требует сверки'; }
});
</script></html>`;

export async function serveLocalFixture({ fault = null, environmentId = randomUUID() } = {}) {
  const records = [];
  const byIdempotency = new Map();
  const authToken = randomUUID();
  let mutationCount = 0;
  let readCount = 0;
  let mutated = false;
  const initialFingerprint = hash('qa-adaptant-local-fixture-v1');
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    const send = (status, body) => {
      const bytes = Buffer.from(JSON.stringify(body));
      res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': bytes.length, 'cache-control': 'no-store' });
      res.end(bytes);
    };
    if (req.method === 'GET' && url.pathname === '/') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
      res.end(baseHtml(fault === 'ambiguousButton'));
      return;
    }
    if (req.method === 'GET' && url.pathname === '/environment') {
      if (fault === 'slowEnvironment') await new Promise(resolve => setTimeout(resolve, 1500));
      send(200, { environmentId, fingerprint: mutated && fault === 'changedEnvironment' ? `${initialFingerprint}-changed` : initialFingerprint, sourceRevision: 'local-fixture-v1' });
      return;
    }
    const authorized = req.headers.authorization === `Bearer ${authToken}`;
    if (req.method === 'GET' && url.pathname === '/records') {
      if (!authorized) { send(401, { error: 'unauthorized' }); return; }
      const fixtureId = url.searchParams.get('fixtureId');
      if (!fixtureId) { send(400, { error: 'fixture_required' }); return; }
      readCount++;
      let matches = records.filter(record => record.fixtureId === fixtureId);
      if (fault === 'delayedRead' && readCount < 3) matches = [];
      if (fault === 'transientRead' && readCount < 3) { send(503, { error: 'temporarily_unavailable' }); return; }
      send(200, { records: matches.map(record => ({ ...record })) });
      return;
    }
    if (req.method === 'POST' && url.pathname === '/records') {
      if (!authorized) { send(401, { error: 'unauthorized' }); return; }
      const chunks = [];
      let size = 0;
      let tooLarge = false;
      for await (const chunk of req) {
        size += chunk.length;
        if (size > 16_384) { tooLarge = true; break; }
        chunks.push(chunk);
      }
      if (tooLarge) { req.resume(); send(413, { error: 'too_large' }); return; }
      const raw = Buffer.concat(chunks).toString('utf8');
      let payload;
      try { payload = JSON.parse(raw); }
      catch { send(400, { error: 'invalid_json' }); return; }
      const idempotencyKey = req.headers['idempotency-key'];
      const bodyHash = hash(raw);
      if (!payload || typeof payload !== 'object' || Array.isArray(payload) || typeof payload.fixtureId !== 'string' || !payload.fixtureId) {
        send(400, { error: 'fixture_required' });
        return;
      }
      if (typeof idempotencyKey === 'string' && idempotencyKey && byIdempotency.has(idempotencyKey)) {
        const existing = byIdempotency.get(idempotencyKey);
        if (existing.bodyHash !== bodyHash) { send(409, { error: 'idempotency_conflict' }); return; }
        send(200, { id: existing.record.id, fixtureId: existing.record.fixtureId });
        return;
      }
      const sameFixture = records.find(record => record.fixtureId === payload.fixtureId);
      if (sameFixture) { send(200, { id: sameFixture.id, fixtureId: sameFixture.fixtureId }); return; }
      mutationCount++;
      mutated = true;
      const record = {
        id: randomUUID(), fixtureId: fault === 'untrustedId' ? `foreign-${payload.fixtureId}` : payload.fixtureId,
        title: String(payload.title || ''), executorId: fault === 'wrongExecutor' ? 'operator-wrong' : String(payload.executorId || ''),
        comment: String(payload.comment || ''), status: 'created'
      };
      if (fault !== 'partialSave') records.push(record);
      else records.push({ ...record, comment: null });
      if (typeof idempotencyKey === 'string' && idempotencyKey) byIdempotency.set(idempotencyKey, { bodyHash, record });
      if (fault === 'lostResponse') {
        res.writeHead(201, { 'content-type': 'application/json; charset=utf-8', 'content-length': 128, 'cache-control': 'no-store' });
        res.flushHeaders();
        req.socket.destroy();
        return;
      }
      const response = { id: record.id, fixtureId: fault === 'untrustedId' ? `foreign-${payload.fixtureId}` : payload.fixtureId };
      if (fault === 'delayResponse') await new Promise(resolve => setTimeout(resolve, 1500));
      send(201, response);
      return;
    }
    send(404, { error: 'not_found' });
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const { port } = server.address();
  const baseUrl = `http://127.0.0.1:${port}/`;
  return {
    baseUrl, environmentId, fingerprint: initialFingerprint, authToken,
    get mutationCount() { return mutationCount; },
    get readCount() { return readCount; },
    get recordCount() { return records.length; },
    close: () => new Promise(resolve => server.close(resolve))
  };
}
