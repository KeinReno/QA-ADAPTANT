import fs from 'node:fs';
import { spawnSync } from 'node:child_process';

const mode = process.argv[2] || 'gate';
const files = fs.readdirSync('tests').filter(name => name.endsWith('.test.mjs')).sort().map(name => `tests/${name}`);
const args = mode === 'parallel'
  ? ['--test', '--test-timeout=45000', ...files]
  : mode === 'races'
    ? ['--test', '--test-concurrency=1', '--test-timeout=120000', '--test-name-pattern', 'второй START во время preflight|append-only evidence выдерживает|активный прогон выдерживает', 'tests/audit-wp.test.mjs', 'tests/evidence-readers.test.mjs']
    : ['--test', '--test-concurrency=1', '--test-timeout=45000', ...files];
const result = spawnSync(process.execPath, args, { stdio: 'inherit', shell: false });
process.exit(result.status ?? 1);
