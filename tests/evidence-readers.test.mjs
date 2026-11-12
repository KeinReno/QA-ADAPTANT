import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { start, observe, reconcile } from '../apps/control/run.mjs';
import { serveLocalFixture } from '../adapters/local/server.mjs';
import { localBundle, localFixtureContract } from './helpers.mjs';
import { canonical, digest } from '../packages/core/canonical.mjs';
import { RunStore } from '../packages/core/store.mjs';

function readLoop(file, ms) {
  const child = spawn(process.execPath, ['-e', `const fs=require('fs'); const file=process.argv[1]; const end=Date.now()+Number(process.argv[2]); let n=0; while(Date.now()<end){ try { if (fs.existsSync(file)) fs.readFileSync(file); n++; } catch (error) { if (error.code==='ENOENT') continue; console.error(error); process.exit(1); } } process.stdout.write(String(n));`, file, String(ms)], { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
  let stdout = '', stderr = '';
  child.stdout.on('data', chunk => { stdout += chunk; });
  child.stderr.on('data', chunk => { stderr += chunk; });
  const done = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', code => resolve({ code, stdout, stderr }));
  });
  return { done };
}

test('append-only evidence выдерживает 1, 2 и 6 читателей файла', async () => {
  for (const readers of [1, 2, 6]) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-adaptant-readers-'));
    const store = new RunStore(root);
    const runDir = path.join(root, 'runs', 'reader-run');
    fs.mkdirSync(path.join(runDir, 'evidence'), { recursive: true });
    fs.writeFileSync(path.join(runDir, 'evidence.jsonl'), '');
    const journal = path.join(runDir, 'evidence.jsonl');
    const loops = Array.from({ length: readers }, () => readLoop(journal, 1500));
    await new Promise(resolve => setTimeout(resolve, 50));
    for (let index = 0; index < 40; index++) {
      store.appendEvidence(runDir, {
        runId: 'reader-run', manifestSha256: 'ab'.repeat(32), fixtureId: 'fixture-readers', stepId: 'create',
        producer: 'control', kind: 'mutation-intent', artifact: { index }
      });
    }
    const results = await Promise.all(loops.map(loop => loop.done));
    for (const result of results) assert.equal(result.code, 0, result.stderr);
    assert.equal(store.readEvidence(runDir).length, 40);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

function observeLoop(root, runId, count) {
  const child = spawn(process.execPath, [path.resolve('tests/observe-loop.mjs'), root, runId, String(count)], { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
  let stdout = '', stderr = '';
  child.stdout.on('data', chunk => { stdout += chunk; });
  child.stderr.on('data', chunk => { stderr += chunk; });
  const done = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', code => resolve({ code, stdout, stderr }));
  });
  return { done };
}

test('хвост без коммита не затирается, откат коммита и пропавший артефакт дают INTEGRITY_ERROR', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-adaptant-tail-'));
  const store = new RunStore(root);
  const runDir = path.join(root, 'runs', 'tail-run');
  fs.mkdirSync(path.join(runDir, 'evidence'), { recursive: true });
  fs.writeFileSync(path.join(runDir, 'evidence.jsonl'), '');
  const record = { runId: 'tail-run', manifestSha256: 'ab'.repeat(32), fixtureId: 'fixture-tail', stepId: 'create', producer: 'control', kind: 'mutation-intent' };
  store.appendEvidence(runDir, { ...record, artifact: { index: 1 } });
  store.appendEvidence(runDir, { ...record, kind: 'observation', producer: 'browser', artifact: { index: 2 } });
  const commits = fs.readdirSync(path.join(runDir, 'evidence-commits')).sort();
  fs.rmSync(path.join(runDir, 'evidence-commits', commits.at(-1)));
  assert.equal(store.readEvidence(runDir).length, 1);
  store.appendEvidence(runDir, { ...record, kind: 'observation', producer: 'browser', artifact: { index: 3 } });
  assert.equal(store.readEvidence(runDir).length, 3);
  fs.appendFileSync(path.join(runDir, 'evidence.jsonl'), '{"torn":true}\n');
  assert.throws(() => store.appendEvidence(runDir, { ...record, artifact: { index: 4 } }), /INCOMPLETE_RUN/);
  assert.equal(store.readEvidence(runDir).length, 3);
  const artifact = fs.readdirSync(path.join(runDir, 'evidence'))[0];
  fs.rmSync(path.join(runDir, 'evidence', artifact));
  assert.throws(() => store.readEvidence(runDir), error => /INTEGRITY_ERROR/.test(error.message) && !/ENOENT/.test(error.message));
  fs.rmSync(root, { recursive: true, force: true });
});

test('пропуск, повреждение и чужой хвост не подтверждают последующие записи', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-adaptant-chain-'));
  const store = new RunStore(root);
  const runDir = path.join(root, 'runs', 'chain-run');
  fs.mkdirSync(path.join(runDir, 'evidence'), { recursive: true });
  fs.writeFileSync(path.join(runDir, 'evidence.jsonl'), '');
  const record = { runId: 'chain-run', manifestSha256: 'ab'.repeat(32), fixtureId: 'fixture-chain', stepId: 'create', producer: 'control', kind: 'mutation-intent' };
  const first = store.appendEvidence(runDir, { ...record, artifact: { index: 1 } });
  const second = store.appendEvidence(runDir, { ...record, artifact: { index: 2 } });
  const third = store.appendEvidence(runDir, { ...record, artifact: { index: 3 } });
  const commits = path.join(runDir, 'evidence-commits');
  assert.equal(fs.readdirSync(commits).some(name => name.startsWith('.pending-')), false);
  fs.rmSync(path.join(commits, '000002.json'));
  assert.equal(store.readEvidence(runDir).length, 1);
  fs.writeFileSync(path.join(commits, '000002.json'), '{"sequence":2');
  fs.copyFileSync(path.join(commits, '000001.json'), path.join(commits, '000004.json'));
  assert.equal(store.readEvidence(runDir).length, 1);
  const journal = fs.readFileSync(path.join(runDir, 'evidence.jsonl'));
  const committed = JSON.parse(fs.readFileSync(path.join(commits, '000001.json'), 'utf8')).byteLength;
  const prefix = journal.subarray(0, committed);
  const forged = JSON.parse(journal.subarray(committed).toString('utf8').split('\n').filter(Boolean)[0]);
  forged.parentEvidenceIds = [third.evidenceId];
  fs.writeFileSync(path.join(runDir, 'evidence.jsonl'), Buffer.concat([prefix, Buffer.from(`${canonical(forged)}\n`)]));
  assert.throws(() => store.appendEvidence(runDir, { ...record, artifact: { index: 4 } }), /parent evidence/);
  assert.equal(store.readEvidence(runDir).length, 1);
  assert.equal(fs.existsSync(path.join(commits, '000003.json')), true);
  fs.rmSync(path.join(commits, '000002.json'));
  const artifact = path.join(runDir, 'evidence', second.artifact.path);
  const saved = fs.readFileSync(artifact);
  fs.writeFileSync(artifact, Buffer.from(`${saved.toString('utf8').trim()} `));
  assert.throws(() => store.appendEvidence(runDir, { ...record, artifact: { index: 5 } }), /checksum evidence/);
  assert.equal(store.readEvidence(runDir).length, 1);
  fs.writeFileSync(artifact, saved);
  fs.writeFileSync(path.join(runDir, 'evidence.jsonl'), prefix);
  fs.rmSync(path.join(commits, '000003.json'), { force: true });
  fs.rmSync(path.join(commits, '000004.json'), { force: true });
  fs.writeFileSync(path.join(runDir, 'evidence', '000002-observation.json'), '{}\n');
  store.appendEvidence(runDir, { ...record, kind: 'observation', producer: 'browser', artifact: { index: 6 } });
  assert.equal(store.readEvidence(runDir).length, 2);
  assert.equal(fs.readdirSync(path.join(runDir, 'quarantine')).some(name => name.endsWith('000002-observation.json')), true);
  assert.ok(first.evidenceId);
  fs.rmSync(root, { recursive: true, force: true });
});

test('чужой хвост не подтверждается, а осиротевший artifact не блокирует продолжение', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-adaptant-scope-'));
  const store = new RunStore(root);
  const runDir = path.join(root, 'runs', 'scope-run');
  fs.mkdirSync(path.join(runDir, 'evidence'), { recursive: true });
  fs.writeFileSync(path.join(runDir, 'evidence.jsonl'), '');
  const manifest = { schemaVersion: '0.1.0', runId: 'scope-run' };
  const fixture = { fixtureId: 'fixture-scope' };
  const scenario = { nodes: [{ id: 'create' }] };
  fs.writeFileSync(path.join(runDir, 'manifest.json'), `${canonical(manifest)}\n`);
  fs.writeFileSync(path.join(runDir, 'fixture.json'), `${canonical(fixture)}\n`);
  fs.writeFileSync(path.join(runDir, 'scenario.json'), `${canonical(scenario)}\n`);
  const record = { runId: 'scope-run', manifestSha256: digest(manifest), fixtureId: 'fixture-scope', stepId: 'create', producer: 'control', kind: 'mutation-intent' };
  const first = store.appendEvidence(runDir, { ...record, artifact: { index: 1 } });
  fs.rmSync(path.join(runDir, 'evidence-commits', '000001.json'));
  const raw = fs.readFileSync(path.join(runDir, 'evidence.jsonl'), 'utf8').trim();
  const foreign = JSON.parse(raw);
  foreign.runId = 'foreign-run';
  fs.writeFileSync(path.join(runDir, 'evidence.jsonl'), `${canonical(foreign)}\n`);
  assert.throws(() => store.appendEvidence(runDir, { ...record, kind: 'observation', producer: 'browser', artifact: { index: 2 } }), /не принадлежит этому прогону/);
  assert.equal(fs.existsSync(path.join(runDir, 'evidence-commits', '000001.json')), false);
  fs.writeFileSync(path.join(runDir, 'evidence.jsonl'), `${raw}\n`);
  store.appendEvidence(runDir, { ...record, artifact: { index: 3 } });
  fs.rmSync(path.join(runDir, 'evidence-commits', '000002.json'));
  assert.throws(() => store.appendEvidence(runDir, { ...record, artifact: { index: 4 } }), /повторяет уже подтверждённый/);
  assert.equal(store.readEvidence(runDir).length, 1);
  const committed = JSON.parse(fs.readFileSync(path.join(runDir, 'evidence-commits', '000001.json'), 'utf8')).byteLength;
  fs.writeFileSync(path.join(runDir, 'evidence.jsonl'), fs.readFileSync(path.join(runDir, 'evidence.jsonl')).subarray(0, committed));
  fs.writeFileSync(path.join(runDir, 'evidence', '000002-observation.json'), '{}\n');
  store.appendEvidence(runDir, { ...record, kind: 'observation', producer: 'browser', artifact: { index: 5 } });
  assert.equal(store.readEvidence(runDir).length, 2);
  assert.equal(fs.readdirSync(path.join(runDir, 'quarantine')).some(name => name.endsWith('000002-observation.json')), true);
  fs.rmSync(root, { recursive: true, force: true });
});

test('активный прогон выдерживает 1, 2 и 6 процессов OBSERVE', { timeout: 120000 }, async t => {
  for (const readers of [1, 2, 6]) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-adaptant-observe-'));
    const fixture = await serveLocalFixture();
    t.after(async () => {
      await fixture.close();
      fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    });
    const runId = `observe-readers-${readers}`;
    const contract = localFixtureContract(fixture, runId);
    fixture.fixtureId = contract.fixtureId;
    const bundle = localBundle(fixture, { runId });
    bundle.fixture = contract;
    bundle.manifest.fixtureSha256 = digest(contract);
    const loops = Array.from({ length: readers }, () => observeLoop(root, runId, 100));
    const result = await start(bundle, { root, fixtureToken: fixture.authToken });
    const finished = await Promise.all(loops.map(loop => loop.done));
    assert.equal(result.verdict.verdict, 'PASS', finished.map(item => item.stderr).join('\n'));
    assert.equal(fixture.mutationCount, 1);
    for (const item of finished) {
      assert.equal(item.code, 0, item.stderr);
      assert.ok(Number(item.stdout) >= 100, item.stdout);
    }
    const evidenceDir = path.join(result.runDir, 'evidence');
    const artifacts = fs.readdirSync(evidenceDir);
    const referenced = new Set(fs.readFileSync(path.join(result.runDir, 'evidence.jsonl'), 'utf8').split('\n').filter(Boolean).map(line => JSON.parse(line).artifact.path));
    assert.deepEqual(artifacts.filter(name => !referenced.has(name)), []);
    const viewed = await observe({ root, runId });
    assert.equal(viewed.verdict.verdict, 'PASS');
    assert.equal(viewed.state, 'FINISHED');
    if (readers === 1) {
      const commits = fs.readdirSync(path.join(result.runDir, 'evidence-commits')).sort();
      fs.rmSync(path.join(result.runDir, 'evidence-commits', commits.at(-1)));
      await assert.rejects(observe({ root, runId }), /INTEGRITY_ERROR/);
      await assert.rejects(start(bundle, { root, fixtureToken: fixture.authToken }), /INTEGRITY_ERROR/);
      await assert.rejects(reconcile({ root, runId, fixtureToken: fixture.authToken }), /INTEGRITY_ERROR/);
      const journal = path.join(result.runDir, 'evidence.jsonl');
      const raw = fs.readFileSync(journal, 'utf8').split('\n').filter(Boolean);
      const forged = JSON.parse(raw.at(-1));
      const artifactFile = path.join(result.runDir, 'evidence', forged.artifact.path);
      const artifact = JSON.parse(fs.readFileSync(artifactFile, 'utf8'));
      artifact.verdict = artifact.verdict === 'PASS' ? 'FAIL' : 'PASS';
      const artifactBytes = Buffer.from(`${canonical(artifact)}\n`);
      fs.writeFileSync(artifactFile, artifactBytes);
      forged.artifact.sha256 = digest(artifactBytes);
      fs.writeFileSync(journal, `${raw.slice(0, -1).join('\n')}\n${canonical(forged)}\n`);
      const store = new RunStore(root);
      assert.throws(() => store.appendEvidence(result.runDir, {
        runId, manifestSha256: digest(bundle.manifest), fixtureId: bundle.fixture.fixtureId,
        stepId: 'create', producer: 'verification', kind: 'observation', producer: 'browser', artifact: { late: true }
      }), /терминальным состоянием/);
      assert.equal(fs.readdirSync(path.join(result.runDir, 'evidence-commits')).includes(`${String(forged.sequence).padStart(6, '0')}.json`), false);
      await assert.rejects(observe({ root, runId }), /INTEGRITY_ERROR/);
      assert.equal(fixture.mutationCount, 1);
    }
  }
});
