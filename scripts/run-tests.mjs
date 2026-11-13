import fs from 'node:fs';
import { spawnSync } from 'node:child_process';

const mode = process.argv[2] || 'gate';
const files = fs.readdirSync('tests').filter(name => name.endsWith('.test.mjs')).sort().map(name => `tests/${name}`);
// F-WP08-05: селекция races по имени не должна молча становиться пустой.
const RACES_PATTERN = 'второй START во время preflight|append-only evidence выдерживает|активный прогон выдерживает';
const RACES_EXPECTED = Number(process.env.QA_RACES_EXPECTED || 3);
const args = mode === 'parallel'
  ? ['--test', '--test-timeout=45000', ...files]
  : mode === 'races'
    ? ['--test', '--test-concurrency=1', '--test-timeout=120000', '--test-name-pattern', RACES_PATTERN, 'tests/audit-wp.test.mjs', 'tests/evidence-readers.test.mjs']
    : ['--test', '--test-concurrency=1', '--test-timeout=45000', ...files];

if (mode !== 'races') {
  const result = spawnSync(process.execPath, args, { stdio: 'inherit', shell: false });
  process.exit(result.status ?? 1);
}

// Races: перехватываем вывод, печатаем его и проверяем, что селектор нашёл ожидаемое число тестов.
const result = spawnSync(process.execPath, args, { encoding: 'utf8', shell: false });
process.stdout.write(result.stdout || '');
process.stderr.write(result.stderr || '');
const output = String(result.stdout || '');
const match = /(?:^|\n)\s*(?:ℹ|#)\s*tests\s+(\d+)/.exec(output);
const testsRun = match ? Number(match[1]) : 0;
if (testsRun < RACES_EXPECTED) {
  process.stderr.write(`FAIL: races-селектор нашёл ${testsRun} тест(ов), ожидалось не меньше ${RACES_EXPECTED}; проверь --test-name-pattern\n`);
  process.exit(1);
}
const failed = /(?:^|\n)\s*(?:ℹ|#)\s*fail\s+([1-9]\d*)/.test(output);
process.exit(failed || result.status !== 0 ? (result.status ?? 1) : 0);
