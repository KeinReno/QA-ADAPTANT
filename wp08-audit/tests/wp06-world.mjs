// WP-08 independent audit (WP-06): минимальный «мир» доверенного прогона.
// Собственная обвязка аудитора: только чтение продуктивного кода, временные каталоги в %TEMP%.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { createTrustRoot, loadTrustRoot, signTrustedDocument, unwrapPrivateKey } from '../../packages/trust/identity.mjs';
import { signApproval } from '../../packages/trust/approval.mjs';
import { commitEnvironmentRecord, signEnvironmentRecord } from '../../packages/trust/environment.mjs';
import { startAnchorSigner } from '../../packages/trust/anchor-signer.mjs';
import { currentUserSid } from '../../packages/trust/windows-sid.mjs';
import { digest } from '../../packages/core/canonical.mjs';
import { serveLocalFixture } from '../../adapters/local/server.mjs';
import { localBundle, localFixtureContract } from '../../adapters/local/bundle.mjs';
import { RunStore } from '../../packages/core/store.mjs';
import * as trusted from '../../apps/control/trusted.mjs';
import * as run from '../../apps/control/run.mjs';

export { trusted, run };

export const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

export async function waitFor(predicate, timeoutMs = 20000, stepMs = 20) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    let value = null;
    try { value = predicate(); } catch { value = null; }
    if (value) return value;
    if (Date.now() > deadline) throw new Error('WP06_TIMEOUT: условие не наступило за ' + timeoutMs + ' мс');
    await sleep(stepMs);
  }
}

export function readEvents(runDir) {
  const file = path.join(runDir, 'events.jsonl');
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map(line => JSON.parse(line));
}

export async function makeWorld(options = {}) {
  const { generation = 1, recordOverrides = {}, standOptions = {} } = options;
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-wp06-'));
  const rootDir = path.join(base, 'store');
  const secretsDir = path.join(base, 'secrets');
  const trustRoot = path.join(base, 'trust');
  const created = await createTrustRoot({ secretsDir, trustRoot, runDir: rootDir });
  const trust = loadTrustRoot(trustRoot);
  const ownerKey = await unwrapPrivateKey(path.join(secretsDir, 'owner.key'));
  const stand = await serveLocalFixture({ generation, ...standOptions });
  const record = signEnvironmentRecord(ownerKey, {
    environmentId: stand.environmentId,
    generation: stand.generation,
    kind: 'local-stand',
    status: 'active',
    origin: stand.baseUrl,
    standKeyId: stand.standKeyId,
    credentialRef: 'local:fixture-token',
    ...recordOverrides
  });
  commitEnvironmentRecord(trust, trustRoot, record);
  const signer = startAnchorSigner({ trustRoot, secretsDir });
  await signer.ready;
  const sid = currentUserSid();
  const signCard = card => signTrustedDocument(ownerKey, {
    schemaVersion: '0.2.0', domain: 'principal', ...card, keyId: created.ownerKeyId, status: 'active'
  });
  const cards = {
    owner: signCard({ principalId: 'local-owner', roles: ['owner'], windowsSid: sid }),
    operator: signCard({ principalId: 'local-operator', roles: ['operator'], windowsSid: sid })
  };
  const store = new RunStore(rootDir);
  const world = {
    base, root: rootDir, secretsDir, trustRoot, trust, ownerKey, stand, signer, sid, cards, created,
    runDir: runId => store.runPath(runId),
    prepare({ runId, inputs } = {}) {
      const id = runId || 'wp06-' + randomUUID().slice(0, 8);
      const contract = localFixtureContract(stand, id);
      stand.fixtureId = contract.fixtureId;
      const bundle = localBundle(stand, { runId: id, inputs });
      bundle.fixture = contract;
      bundle.manifest.fixtureSha256 = digest(contract);
      bundle.manifest.budget.deadlineMs = 60000;
      return { bundle, contract, runId: id };
    },
    approvalFor({ bundle, contract, overrides = {}, approvalId } = {}) {
      const id = approvalId || 'approval-' + randomUUID().slice(0, 8);
      const issuedAt = new Date().toISOString();
      const fields = {
        approvalId: id,
        issuerPrincipalId: 'local-owner',
        subjectPrincipalId: 'local-operator',
        operationId: bundle.operation.id,
        operationVersion: bundle.operation.version,
        scenarioContentSha256: bundle.scenario.approval.contentSha256,
        operationSha256: digest(bundle.operation),
        approvedInputsHash: digest(bundle.operation.inputs),
        fixtureId: contract.fixtureId,
        targetEnvironmentId: stand.environmentId,
        environmentGeneration: stand.generation,
        targetResource: { method: 'POST', path: '/records' },
        allowedEffects: bundle.operation.effects.map(effect => ({ id: effect.id, field: effect.field, equals: effect.equals })),
        issuedAt,
        expiresAt: new Date(Date.parse(issuedAt) + 10 * 60 * 1000).toISOString(),
        approvalNonce: 'ab'.repeat(32),
        keyId: created.ownerKeyId,
        ...overrides
      };
      return signApproval(ownerKey, fields, trust, trustRoot);
    },
    trustedOptions(approval, extra = {}) {
      return {
        root: rootDir,
        trustRoot,
        approvalId: approval.approvalId,
        approval,
        issuer: cards.owner,
        subject: cards.operator,
        signerPipe: signer.pipePath,
        standPublicKey: stand.standPublicKey,
        fixtureToken: stand.authToken,
        ...extra
      };
    },
    async cleanup() {
      try { await signer.close(); } catch { /* канал закрыт */ }
      try { await stand.close(); } catch { /* стенд закрыт */ }
      try { fs.rmSync(base, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }); } catch { /* временный каталог */ }
    }
  };
  return world;
}

export function writeWorldRequest(world, { bundle, approval, mode, runId, extra = {} }) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-wp06-req-'));
  const files = {
    bundleFile: path.join(dir, 'bundle.json'),
    issuerFile: path.join(dir, 'owner.card.json'),
    subjectFile: path.join(dir, 'operator.card.json'),
    resultFile: path.join(dir, 'result.json'),
    anchorFile: path.join(dir, 'anchor.json'),
    requestFile: path.join(dir, 'request.json')
  };
  fs.writeFileSync(files.bundleFile, JSON.stringify(bundle));
  fs.writeFileSync(files.issuerFile, JSON.stringify(world.cards.owner));
  fs.writeFileSync(files.subjectFile, JSON.stringify(world.cards.operator));
  const request = {
    mode,
    targetDir: path.resolve(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')), '..', '..'),
    root: world.root,
    trustRoot: world.trustRoot,
    approvalId: approval.approvalId,
    runId,
    standPublicKey: world.stand.standPublicKey,
    fixtureToken: world.stand.authToken,
    pipePath: world.signer.pipePath,
    ...files,
    ...extra
  };
  fs.writeFileSync(files.requestFile, JSON.stringify(request));
  return { dir, ...files };
}
