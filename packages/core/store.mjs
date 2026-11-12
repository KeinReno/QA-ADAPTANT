import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { digest, canonical } from './canonical.mjs';
import { validate } from '../contracts/index.mjs';

const jsonBytes = value => Buffer.from(`${canonical(value)}\n`, 'utf8');

function atomicWrite(file, bytes) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const temp = `${file}.${process.pid}.${randomUUID()}.tmp`;
  const fd = fs.openSync(temp, 'wx', 0o600);
  try { fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.renameSync(temp, file);
  let dir;
  try { dir = fs.openSync(path.dirname(file), 'r'); fs.fsyncSync(dir); }
  catch { /* Windows directory fsync is not available. */ }
  finally { if (dir !== undefined) fs.closeSync(dir); }
}

export class RunStore {
  constructor(root) {
    this.root = path.resolve(root);
    fs.mkdirSync(this.root, { recursive: true });
  }

  runPath(runId) {
    if (!/^[A-Za-z0-9_-]{1,160}$/.test(runId)) throw new Error('Некорректный runId');
    const dir = path.resolve(this.root, 'runs', runId);
    if (!dir.startsWith(`${path.resolve(this.root, 'runs')}${path.sep}`)) throw new Error('Путь прогона вне хранилища');
    if (fs.existsSync(dir) && fs.lstatSync(dir).isSymbolicLink()) throw new Error('INTEGRITY_ERROR: run directory не может быть symlink');
    return dir;
  }

  snapshot(bundle, owner = null) {
    const dir = this.runPath(bundle.manifest.runId);
    fs.mkdirSync(path.join(this.root, 'runs'), { recursive: true });
    fs.mkdirSync(dir, { recursive: false });
    fs.mkdirSync(path.join(dir, 'evidence'), { recursive: false });
    for (const [name, value] of Object.entries({ scenario: bundle.scenario, operation: bundle.operation, fixture: bundle.fixture, manifest: bundle.manifest })) {
      atomicWrite(path.join(dir, `${name}.json`), jsonBytes(value));
    }
    if (owner) atomicWrite(path.join(dir, 'owner.json'), jsonBytes(owner));
    atomicWrite(path.join(dir, 'events.jsonl'), Buffer.alloc(0));
    atomicWrite(path.join(dir, 'evidence.jsonl'), Buffer.alloc(0));
    atomicWrite(path.join(dir, 'evidence-anchor.json'), jsonBytes({ sequence: 0, envelopeSha256: null, byteLength: 0 }));
    return dir;
  }

  readSnapshot(runDir, name) {
    if (!['scenario', 'operation', 'fixture', 'manifest'].includes(name)) throw new Error('Неизвестный snapshot');
    const file = path.join(runDir, `${name}.json`);
    try {
      this.#assertRegularFile(file, runDir);
      const raw = fs.readFileSync(file);
      return { value: JSON.parse(raw.toString('utf8')), sha256: digest(raw) };
    } catch (error) {
      if (String(error.message || '').startsWith('INTEGRITY_ERROR')) throw error;
      throw new Error(`INCOMPLETE_RUN: снимок ${name} недоступен`);
    }
  }

  #assertRegularFile(file, root) {
    const rootStat = fs.lstatSync(root);
    if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) throw new Error('INTEGRITY_ERROR: каталог bundle не является обычным каталогом');
    const rootReal = fs.realpathSync(root);
    const fileReal = fs.realpathSync(file);
    const stat = fs.lstatSync(file);
    if (stat.isSymbolicLink() || !stat.isFile() || !fileReal.startsWith(`${rootReal}${path.sep}`)) throw new Error('INTEGRITY_ERROR: файл вне immutable bundle');
  }

  appendEvent(runDir, event) {
    const file = path.join(runDir, 'events.jsonl');
    if (fs.existsSync(file)) this.#assertRegularFile(file, runDir);
    const previousRecords = this.readEvents(runDir);
    const previous = previousRecords.at(-1);
    const body = { ...event };
    for (const key of ['id', 'seq', 'runId', 'at', 'previousSha256', 'sha256']) delete body[key];
    const unsigned = { ...body, id: randomUUID(), seq: previousRecords.length + 1,
      runId: this.readSnapshot(runDir, 'manifest').value.runId,
      at: new Date().toISOString(), previousSha256: previous?.sha256 || null };
    const record = { ...unsigned, sha256: digest(unsigned) };
    fs.appendFileSync(file, `${canonical(record)}\n`, { mode: 0o600 });
    const fd = fs.openSync(file, 'a'); try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    return record;
  }

  readEvents(runDir) {
    const file = path.join(runDir, 'events.jsonl');
    if (!fs.existsSync(file)) return [];
    this.#assertRegularFile(file, runDir);
    const raw = fs.readFileSync(file, 'utf8');
    if (raw && !raw.endsWith('\n')) throw new Error('INTEGRITY_ERROR: неполная запись журнала событий');
    let records;
    try { records = raw.split('\n').filter(Boolean).map(line => JSON.parse(line)); }
    catch { throw new Error('INCOMPLETE_RUN: журнал событий повреждён'); }
    const runId = this.readSnapshot(runDir, 'manifest').value.runId;
    let previous = null;
    const ids = new Set();
    for (const [index, record] of records.entries()) {
      const { sha256, ...unsigned } = record;
      if (record.seq !== index + 1 || record.runId !== runId || record.previousSha256 !== previous ||
          !record.id || ids.has(record.id) || !/^[a-f0-9]{64}$/.test(sha256 || '') || digest(unsigned) !== sha256) {
        throw new Error('INTEGRITY_ERROR: повреждена цепочка журнала событий');
      }
      ids.add(record.id);
      previous = sha256;
    }
    return records;
  }

  #readAnchor(runDir) {
    const file = path.join(runDir, 'evidence-anchor.json');
    if (!fs.existsSync(file)) return null;
    this.#assertRegularFile(file, runDir);
    try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
    catch { throw new Error('INCOMPLETE_RUN: анкер evidence повреждён'); }
  }

  #parseCommitted(runDir, raw, anchor) {
    if (!anchor) {
      if (raw.length === 0) return [];
      throw new Error('INTEGRITY_ERROR: хвост evidence не совпадает с анкером');
    }
    if (!Number.isInteger(anchor.byteLength) || anchor.byteLength < 0 || anchor.byteLength > raw.length) {
      throw new Error('INTEGRITY_ERROR: хвост evidence не совпадает с анкером');
    }
    if (anchor.byteLength === 0) return [];
    const prefix = raw.subarray(0, anchor.byteLength).toString('utf8');
    if (!prefix.endsWith('\n')) throw new Error('INCOMPLETE_RUN: журнал evidence повреждён');
    let lines;
    try { lines = prefix.split('\n').filter(Boolean).map(line => JSON.parse(line)); }
    catch { throw new Error('INCOMPLETE_RUN: журнал evidence повреждён'); }
    const result = [];
    const ids = new Set();
    let previous = null;
    for (let i = 0; i < lines.length; i++) {
      const envelope = lines[i];
      validate('EvidenceSchema', envelope);
      if (ids.has(envelope.evidenceId)) throw new Error('INTEGRITY_ERROR: повтор evidenceId');
      ids.add(envelope.evidenceId);
      if (envelope.sequence !== i + 1 || envelope.previousSha256 !== previous) throw new Error('INTEGRITY_ERROR: повреждена цепочка evidence');
      const normalized = path.basename(envelope.artifact.path);
      if (normalized !== envelope.artifact.path || normalized.includes('..')) throw new Error('INTEGRITY_ERROR: путь evidence вне каталога');
      const evidenceDir = path.join(runDir, 'evidence');
      const artifactFile = path.join(evidenceDir, normalized);
      this.#assertRegularFile(artifactFile, evidenceDir);
      const bytes = fs.readFileSync(artifactFile);
      if (digest(bytes) !== envelope.artifact.sha256) throw new Error('INTEGRITY_ERROR: checksum evidence не совпадает');
      let artifact;
      try { artifact = JSON.parse(bytes.toString('utf8')); }
      catch { throw new Error('INCOMPLETE_RUN: артефакт evidence повреждён'); }
      result.push({ envelope, artifact });
      previous = digest(envelope);
    }
    const last = result.at(-1)?.envelope;
    if (!last || anchor.sequence !== last.sequence || anchor.envelopeSha256 !== digest(last)) {
      throw new Error('INTEGRITY_ERROR: хвост evidence не совпадает с анкером');
    }
    for (const item of result) {
      if (item.envelope.parentEvidenceIds.some(id => !ids.has(id) || result.find(candidate => candidate.envelope.evidenceId === id).envelope.sequence >= item.envelope.sequence)) {
        throw new Error('INTEGRITY_ERROR: неверная ссылка parent evidence');
      }
    }
    return result;
  }

  appendEvidence(runDir, { runId, manifestSha256, fixtureId, stepId, producer, kind, artifact, requestId = null, cizId = null, entity = null, parentEvidenceIds = [], checkIds = [] }) {
    const file = path.join(runDir, 'evidence.jsonl');
    const previous = this.readEvidence(runDir);
    if (previous.some(item => item.envelope.kind === 'verdict')) throw new Error('INTEGRITY_ERROR: после терминального verdict новые evidence запрещены');
    const artifactPath = `${String(previous.length + 1).padStart(6, '0')}-${kind}.json`;
    const artifactBytes = jsonBytes(artifact);
    const artifactFile = path.join(runDir, 'evidence', artifactPath);
    if (fs.existsSync(artifactFile)) throw new Error('INTEGRITY_ERROR: запрещена перезапись evidence');
    atomicWrite(artifactFile, artifactBytes);
    const envelope = {
      schemaVersion: '0.1.0', evidenceId: randomUUID(), runId, stepId, manifestSha256, fixtureId,
      producer, kind, sequence: previous.length + 1,
      previousSha256: previous.length ? digest(previous.at(-1).envelope) : null,
      parentEvidenceIds, checkIds,
      artifact: { path: artifactPath, sha256: digest(artifactBytes), mediaType: 'application/json' },
      requestId, cizId, entity, observedAt: new Date().toISOString()
    };
    validate('EvidenceSchema', envelope);
    const anchor = this.#readAnchor(runDir);
    const raw = fs.existsSync(file) ? fs.readFileSync(file) : Buffer.alloc(0);
    const prefixLength = anchor?.byteLength || 0;
    const next = Buffer.concat([raw.subarray(0, prefixLength), Buffer.from(`${canonical(envelope)}\n`)]);
    atomicWrite(file, next);
    atomicWrite(path.join(runDir, 'evidence-anchor.json'), jsonBytes({ sequence: envelope.sequence, envelopeSha256: digest(envelope), byteLength: next.length }));
    return envelope;
  }

  readEvidence(runDir) {
    const file = path.join(runDir, 'evidence.jsonl');
    for (let attempt = 0; attempt < 8; attempt++) {
      const before = this.#readAnchor(runDir);
      if (fs.existsSync(file)) this.#assertRegularFile(file, runDir);
      const raw = fs.existsSync(file) ? fs.readFileSync(file) : Buffer.alloc(0);
      const after = this.#readAnchor(runDir);
      if (JSON.stringify(before) !== JSON.stringify(after)) continue;
      return this.#parseCommitted(runDir, raw, before);
    }
    throw new Error('INTEGRITY_ERROR: хвост evidence не совпадает с анкером');
  }
}
