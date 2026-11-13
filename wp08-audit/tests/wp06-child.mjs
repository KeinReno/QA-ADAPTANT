// WP-08 independent audit (WP-06): дочерние процессы для воспроизведения аварий.
// Режимы: crash-after-post (Control гибнет после durable HTTP_RESPONSE), anchor-held
// (анкер записан, процесс гибнет до terminal-choice/verdict), reconcile (обычный reconcileTrusted).
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const request = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const imp = rel => import(pathToFileURL(path.join(request.targetDir, rel)).href);

function finish(code, payload) {
  try { if (payload !== undefined) fs.writeFileSync(request.resultFile, JSON.stringify(payload) + '\n'); } catch {}
  process.exit(code);
}

try {
  const identity = await imp('packages/trust/identity.mjs');
  const trusted = await imp('apps/control/trusted.mjs');
  const runModule = await imp('apps/control/run.mjs');
  const signerModule = await imp('packages/trust/anchor-signer.mjs');

  const trust = identity.loadTrustRoot(request.trustRoot);
  const approval = JSON.parse(fs.readFileSync(path.join(request.trustRoot, 'approvals', request.approvalId + '.json'), 'utf8'));
  const issuer = JSON.parse(fs.readFileSync(request.issuerFile, 'utf8'));
  const subject = JSON.parse(fs.readFileSync(request.subjectFile, 'utf8'));
  const bundle = JSON.parse(fs.readFileSync(request.bundleFile, 'utf8'));
  const sid = identity.loadTrustRoot ? (await imp('packages/trust/windows-sid.mjs')).currentUserSid() : null;

  if (request.mode === 'crash-after-post') {
    // Browser Worker сам убивает этот процесс сразу после durable HTTP_RESPONSE.
    const result = await trusted.startTrusted(bundle, {
      root: request.root, trustRoot: request.trustRoot, approvalId: request.approvalId, approval,
      issuer, subject, signerPipe: request.pipePath, standPublicKey: request.standPublicKey,
      fixtureToken: request.fixtureToken, fault: 'crashControlAfterMutation'
    });
    finish(0, { reached: 'startTrusted-returned', verdict: result?.verdict?.verdict || null });
  }

  if (request.mode === 'anchor-held') {
    const real = signerModule.connectAnchorSigner(request.pipePath);
    const signer = {
      async sign(signRequest) {
        const statement = await real.sign(signRequest);
        fs.writeFileSync(request.anchorFile, JSON.stringify(statement) + '\n');
        process.exit(42); // гибель после записи анкера, до terminal-choice и verdict
      }
    };
    const context = trusted.createTrustContext({
      trust, trustRoot: request.trustRoot, approvalId: request.approvalId, approval, issuer, subject,
      sid, standPublicKey: request.standPublicKey, signer
    });
    const result = await runModule.start(bundle, { root: request.root, trust: context, fixtureToken: request.fixtureToken });
    finish(43, { reached: 'start-returned', verdict: result?.verdict?.verdict || null });
  }

  if (request.mode === 'reconcile') {
    const result = await trusted.reconcileTrusted({
      root: request.root, trustRoot: request.trustRoot, approvalId: request.approvalId, approval,
      issuer, subject, signerPipe: request.pipePath, standPublicKey: request.standPublicKey,
      runId: request.runId
    });
    finish(0, { verdict: result?.verdict?.verdict || null, reasonCode: result?.verdict?.reasonCode || null, evidenceIds: result?.evidenceIds || [] });
  }

  finish(70, { error: 'UNKNOWN_MODE', mode: request.mode });
} catch (error) {
  finish(71, { error: error.code || null, message: String(error.message || error) });
}
