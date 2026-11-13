// RT-08: подмена среды. На базе 0e7e6c2 WP-04 (environment/attest) не реализован.
// Проверяем факты: публичные поля /environment можно скопировать, подписи challenge нет, /attest отсутствует,
// монополия порта локального стенда держится. Матрица E-01..E-08 в доверенном смысле НЕ проверяется.
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { serveLocalFixture } from '../../adapters/local/server.mjs';
import { record, finish, PROJECT_ROOT } from './_lib.mjs';

const checks = [];
const fixture = await serveLocalFixture();
try {
  const environmentUrl = new URL('/environment', fixture.baseUrl);
  const first = await (await fetch(environmentUrl)).json();
  const second = await (await fetch(environmentUrl)).json();
  record(checks, '/environment не содержит challenge/подписи', !('challenge' in first) && !('signature' in first), { keys: Object.keys(first) });
  record(checks, 'публичные поля стабильны и копируемы', JSON.stringify(first) === JSON.stringify(second), { body: first });
  record(checks, '/attest отсутствует на базовом стенде (WP-04 не реализован)', (await fetch(new URL('/attest', fixture.baseUrl), { method: 'POST', body: '{}' })).status === 404);

  // Копирующее зеркало: те же environmentId/fingerprint на другом сокете.
  const mirror = http.createServer((request, response) => {
    if (request.url === '/environment') {
      const bytes = Buffer.from(JSON.stringify(first));
      response.writeHead(200, { 'content-type': 'application/json', 'content-length': bytes.length });
      response.end(bytes);
      return;
    }
    response.writeHead(404); response.end();
  });
  await new Promise(resolve => mirror.listen(0, '127.0.0.1', resolve));
  const mirrorUrl = new URL('/environment', 'http://127.0.0.1:' + mirror.address().port + '/');
  const mirrored = await (await fetch(mirrorUrl)).json();
  record(checks, 'зеркало на другом сокете отдаёт те же environmentId/fingerprint', mirrored.environmentId === first.environmentId && mirrored.fingerprint === first.fingerprint);
  await new Promise(resolve => mirror.close(resolve));

  // Монополия порта (E-08 в части базового стенда).
  const port = Number(new URL(fixture.baseUrl).port);
  const intruder = http.createServer(() => {});
  const bindError = await new Promise(resolve => {
    intruder.once('error', resolve);
    intruder.listen(port, '127.0.0.1', () => resolve(null));
  });
  record(checks, 'второй bind на порт живого стенда отвергнут', Boolean(bindError) && bindError.code === 'EADDRINUSE', { code: bindError?.code || null });
  if (!bindError) await new Promise(resolve => intruder.close(resolve));
  record(checks, 'стенд после попытки подмены отвечает', (await fetch(environmentUrl)).status === 200);

  const serverSource = fs.readFileSync(path.join(PROJECT_ROOT, 'adapters', 'local', 'server.mjs'), 'utf8');
  record(checks, 'в базовом стенде нет проверки challenge/attest', !serverSource.includes('/attest') && !/standKey|attest/i.test(serverSource));
  record(checks, 'модуль environment.mjs на ревизии отсутствует', !fs.existsSync(path.join(PROJECT_ROOT, 'packages', 'trust', 'environment.mjs')));
} catch (error) {
  record(checks, 'скрипт завершился без аварии', false, { message: String(error.message || error), code: error.code || null });
} finally {
  await fixture.close();
}
finish({ id: 'RT-08', title: 'Подмена среды и копирование публичных полей', checks,
  verdict: 'INCONCLUSIVE',
  notes: [
    'E-01/E-02/E-03/E-04/E-05/E-06/E-07 требуют packages/trust/environment.mjs и T-A/T-B (WP-04+WP-06) — на 0e7e6c2 их нет.',
    'E-08 в части монополии сокета базовым стендом подтверждён; доверенная часть (аттестация владельца порта) не проверяется.',
    'Факт: копирование environmentId/fingerprint на другой сокет базой 0.1 не обнаруживается — это ровно тот разрыв, который должен закрыть WP-04.'
  ] });
