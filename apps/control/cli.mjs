import fs from 'node:fs';
import { start, observe, reconcile, cancel } from './run.mjs';

function argument(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

try {
  const command = process.argv[2];
  const root = argument('--root');
  const runId = argument('--run-id');
  const fault = argument('--fault') || null;
  const fixtureToken = process.env.QA_ADAPTANT_FIXTURE_TOKEN || '';
  if (!root) throw new Error('Укажите --root');
  let result;
  if (command === 'start') {
    const bundlePath = argument('--bundle');
    if (!bundlePath) throw new Error('Для start укажите --bundle');
    const bundle = JSON.parse(fs.readFileSync(bundlePath, 'utf8'));
    result = await start(bundle, { root, fault, headed: argument('--headed') === '1', fixtureToken });
  } else if (command === 'observe') {
    result = await observe({ root, runId });
  } else if (command === 'reconcile') {
    result = await reconcile({ root, runId, fault, fixtureToken });
  } else if (command === 'cancel') {
    result = await cancel({ root, runId });
  } else {
    throw new Error('Команда должна быть start, observe, reconcile или cancel');
  }
  process.stdout.write(`${JSON.stringify(result)}\n`);
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
}
