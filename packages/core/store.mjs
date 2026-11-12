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

  #commitDir(runDir) { return path.join(runDir, 'evidence-commits'); }

  #writeNewFile(file, bytes) {
    const fd = fs.openSync(file, 'wx', 0o600);
    try { fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); }
    finally { fs.closeSync(fd); }
  }

  #listCommits(runDir) {
    const dir = this.#commitDir(runDir);
    if (!fs.existsSync(dir)) return [];
    const names = fs.readdirSync(dir).filter(name => /^\d{6}\.json$/.test(name)).sort();
    const commits = [];
    for (const name of names) {
      const sequence = Number(name.slice(0, 6));
      if (sequence !== commits.length + 1) break;
      let parsed;
      try { parsed = JSON.parse(fs.readFileSync(path.join(dir, name), 'utf8')); }
      catch { break; }
      const previousLength = commits.at(-1)?.byteLength ?? 0;
      if (parsed.sequence !== sequence || !Number.isInteger(parsed.byteLength) || parsed.byteLength <= previousLength) break;
      if (typeof parsed.envelopeSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(parsed.envelopeSha256)) break;
      commits.push(parsed);
    }
    return commits;
  }

  #publishCommit(runDir, commit) {
    const dir = this.#commitDir(runDir);
    fs.mkdirSync(dir, { recursive: true });
    const finalFile = path.join(dir, `${String(commit.sequence).padStart(6, '0')}.json`);
    if (fs.existsSync(finalFile)) throw new Error('INTEGRITY_ERROR: запрещена перезапись коммита evidence');
    const temp = path.join(dir, `.pending-${commit.sequence}-${randomUUID()}.tmp`);
    this.#writeNewFile(temp, jsonBytes(commit));
    try { fs.renameSync(temp, finalFile); }
    catch (error) {
      try { fs.rmSync(temp, { force: true }); } catch { /* временный файл не мешает чтению подтверждённых коммитов */ }
      throw error;
    }
  }

  #snapshotScope(runDir) {
    if (!fs.existsSync(path.join(runDir, 'manifest.json'))) return null;
    const manifest = this.readSnapshot(runDir, 'manifest').value;
    const fixture = this.readSnapshot(runDir, 'fixture').value;
    const scenario = this.readSnapshot(runDir, 'scenario').value;
    return {
      runId: manifest.runId,
      manifestSha256: digest(manifest),
      fixtureId: fixture.fixtureId,
      stepIds: new Set((scenario.nodes || []).map(node => node.id))
    };
  }

  #assertTailShape(envelope, prior) {
    const parents = envelope.parentEvidenceIds.map(id => prior.find(item => item.evidenceId === id));
    const parentKind = parents[0]?.kind;
    const kind = envelope.kind;
    if (kind === 'mutation-intent' && parents.length !== 0) throw new Error('INTEGRITY_ERROR: неверная ссылка parent evidence');
    if (kind === 'request' && (parents.length !== 1 || parentKind !== 'mutation-intent')) throw new Error('INTEGRITY_ERROR: неверная ссылка parent evidence');
    if (kind === 'response' && (parents.length !== 1 || parentKind !== 'request')) throw new Error('INTEGRITY_ERROR: неверная ссылка parent evidence');
    if (kind === 'independent-read' && (parents.length !== 1 || !['request', 'response'].includes(parentKind))) throw new Error('INTEGRITY_ERROR: неверная ссылка parent evidence');
    if (['mutation-intent', 'request', 'response', 'verdict'].includes(kind) && prior.some(item => item.kind === kind)) {
      throw new Error('INTEGRITY_ERROR: неподтверждённый хвост повторяет уже подтверждённый вид evidence');
    }
  }

  #releaseOrphanArtifact(runDir, artifactFile, referenced) {
    if (!fs.existsSync(artifactFile)) return;
    if (referenced.has(path.basename(artifactFile))) throw new Error('INTEGRITY_ERROR: запрещена перезапись evidence');
    const destDir = path.join(runDir, 'quarantine');
    fs.mkdirSync(destDir, { recursive: true });
    fs.renameSync(artifactFile, path.join(destDir, `${Date.now()}-${path.basename(artifactFile)}`));
  }

  #assertRecoverableTail(runDir, raw, length, envelope) {
    const normalized = path.basename(envelope.artifact.path);
    if (normalized !== envelope.artifact.path || normalized.includes('..')) throw new Error('INTEGRITY_ERROR: путь evidence вне каталога');
    const artifactFile = path.join(runDir, 'evidence', normalized);
    if (!fs.existsSync(artifactFile)) throw new Error('INTEGRITY_ERROR: файл evidence отсутствует');
    const artifactBytes = fs.readFileSync(artifactFile);
    if (digest(artifactBytes) !== envelope.artifact.sha256) throw new Error('INTEGRITY_ERROR: checksum evidence не совпадает');
    let prior = [];
    if (length > 0) {
      try { prior = raw.subarray(0, length).toString('utf8').split('\n').filter(Boolean).map(line => JSON.parse(line)); }
      catch { throw new Error('INCOMPLETE_RUN: подтверждённый префикс evidence повреждён'); }
    }
    const ids = new Map(prior.map(item => [item.evidenceId, item.sequence]));
    if (envelope.parentEvidenceIds.some(id => !ids.has(id) || ids.get(id) >= envelope.sequence)) {
      throw new Error('INTEGRITY_ERROR: неверная ссылка parent evidence');
    }
    const scope = this.#snapshotScope(runDir);
    if (scope && (envelope.runId !== scope.runId || envelope.manifestSha256 !== scope.manifestSha256 || envelope.fixtureId !== scope.fixtureId || !scope.stepIds.has(envelope.stepId))) {
      throw new Error('INTEGRITY_ERROR: неподтверждённый хвост не принадлежит этому прогону');
    }
    this.#assertTailShape(envelope, prior);
    if (!fs.existsSync(path.join(runDir, 'events.jsonl'))) return;
    const events = this.readEvents(runDir);
    const claimed = [...events].reverse().find(event => event.type === 'VERDICT_DURABLE' || (event.type === 'STATE' && event.state === 'FINISHED'));
    if (!claimed) return;
    let artifact;
    try { artifact = JSON.parse(artifactBytes.toString('utf8')); }
    catch { throw new Error('INCOMPLETE_RUN: артефакт evidence повреждён'); }
    if (envelope.kind !== 'verdict' || (claimed.verdict && artifact.verdict !== claimed.verdict)) {
      throw new Error('INTEGRITY_ERROR: неподтверждённый хвост конфликтует с терминальным состоянием');
    }
  }

  #recoverTail(runDir, file) {
    const raw = fs.existsSync(file) ? fs.readFileSync(file) : Buffer.alloc(0);
    const commits = this.#listCommits(runDir);
    const length = commits.at(-1)?.byteLength ?? 0;
    if (raw.length < length) throw new Error('INTEGRITY_ERROR: журнал evidence короче подтверждённого коммита');
    if (raw.length === length) return;
    const tail = raw.subarray(length).toString('utf8');
    const lines = tail.split('\n').filter(Boolean);
    if (!tail.endsWith('\n') || lines.length !== 1) {
      throw new Error('INCOMPLETE_RUN: неподтверждённый хвост evidence не является целым конвертом; журнал поверх него не продолжается');
    }
    let envelope;
    try { envelope = JSON.parse(lines[0]); validate('EvidenceSchema', envelope); }
    catch { throw new Error('INCOMPLETE_RUN: неподтверждённый хвост evidence повреждён; журнал поверх него не продолжается'); }
    const previousSha = commits.at(-1)?.envelopeSha256 ?? null;
    if (envelope.sequence !== commits.length + 1 || envelope.previousSha256 !== previousSha || lines[0] !== canonical(envelope)) {
      throw new Error('INCOMPLETE_RUN: неподтверждённый хвост evidence не продолжает журнал');
    }
    this.#assertRecoverableTail(runDir, raw, length, envelope);
    this.#publishCommit(runDir, { sequence: envelope.sequence, envelopeSha256: digest(envelope), byteLength: raw.length });
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
      if (!fs.existsSync(artifactFile)) throw new Error('INTEGRITY_ERROR: файл evidence отсутствует');
      try { this.#assertRegularFile(artifactFile, evidenceDir); }
      catch (error) {
        if (error.code === 'ENOENT') throw new Error('INTEGRITY_ERROR: файл evidence отсутствует');
        throw error;
      }
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
    this.#recoverTail(runDir, file);
    const previous = this.readEvidence(runDir);
    if (previous.some(item => item.envelope.kind === 'verdict')) throw new Error('INTEGRITY_ERROR: после терминального verdict новые evidence запрещены');
    const artifactPath = `${String(previous.length + 1).padStart(6, '0')}-${kind}.json`;
    const artifactBytes = jsonBytes(artifact);
    const artifactFile = path.join(runDir, 'evidence', artifactPath);
    this.#releaseOrphanArtifact(runDir, artifactFile, new Set(previous.map(item => item.envelope.artifact.path)));
    this.#writeNewFile(artifactFile, artifactBytes);
    const envelope = {
      schemaVersion: '0.1.0', evidenceId: randomUUID(), runId, stepId, manifestSha256, fixtureId,
      producer, kind, sequence: previous.length + 1,
      previousSha256: previous.length ? digest(previous.at(-1).envelope) : null,
      parentEvidenceIds, checkIds,
      artifact: { path: artifactPath, sha256: digest(artifactBytes), mediaType: 'application/json' },
      requestId, cizId, entity, observedAt: new Date().toISOString()
    };
    validate('EvidenceSchema', envelope);
    const line = Buffer.from(`${canonical(envelope)}\n`);
    const fd = fs.openSync(file, 'a', 0o600);
    try { fs.writeFileSync(fd, line); fs.fsyncSync(fd); }
    finally { fs.closeSync(fd); }
    this.#publishCommit(runDir, { sequence: envelope.sequence, envelopeSha256: digest(envelope), byteLength: fs.statSync(file).size });
    return envelope;
  }

  readEvidence(runDir) {
    const file = path.join(runDir, 'evidence.jsonl');
    if (fs.existsSync(file)) this.#assertRegularFile(file, runDir);
    for (let attempt = 0; attempt < 8; attempt++) {
      const before = this.#listCommits(runDir);
      const raw = fs.existsSync(file) ? fs.readFileSync(file) : Buffer.alloc(0);
      const after = this.#listCommits(runDir);
      if (JSON.stringify(before) !== JSON.stringify(after)) continue;
      if (!after.length) return [];
      return this.#parseCommitted(runDir, raw, after.at(-1));
    }
    throw new Error('INTEGRITY_ERROR: хвост evidence не совпадает с анкером');
  }
}
