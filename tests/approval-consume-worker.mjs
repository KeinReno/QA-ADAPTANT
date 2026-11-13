import fs from 'node:fs';
import { consumeDispatch } from '../packages/trust/approval.mjs';

const request = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
fs.writeFileSync(request.readyFile, 'ready');
while (!fs.existsSync(request.goFile)) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5);
try {
  const result = consumeDispatch(request);
  fs.writeFileSync(request.resultFile, JSON.stringify({ ack: result.ack === true, code: result.code }));
} catch (error) {
  fs.writeFileSync(request.resultFile, JSON.stringify({ ack: false, code: error.code || 'ERROR' }));
}
