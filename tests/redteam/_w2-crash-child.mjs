// Дочерний Control для V-04/V-07. Тест-родитель завершает process tree сразу
// после появления durable anchor, пока штатный fault hook удерживает выбор/verdict.
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const request = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const imp = rel => import(pathToFileURL(path.join(request.targetDir, rel)).href);
const trusted = await imp('apps/control/trusted.mjs');
const approval = JSON.parse(fs.readFileSync(path.join(request.trustRoot, 'approvals', request.approvalId + '.json'), 'utf8'));
const issuer = JSON.parse(fs.readFileSync(request.issuerFile, 'utf8'));
const subject = JSON.parse(fs.readFileSync(request.subjectFile, 'utf8'));
const bundle = JSON.parse(fs.readFileSync(request.bundleFile, 'utf8'));

try {
  const result = await trusted.startTrusted(bundle, {
    root: request.root,
    trustRoot: request.trustRoot,
    approvalId: request.approvalId,
    approval,
    issuer,
    subject,
    standPublicKey: request.standPublicKey,
    anchorKeyPath: request.anchorKeyPath,
    fixtureToken: request.fixtureToken,
    credentials: request.credentials || null,
    fault: 'afterAnchorBeforeTerminalChoice'
  });
  fs.writeFileSync(request.resultFile, JSON.stringify({ verdict: result?.verdict?.verdict || null, reasonCode: result?.verdict?.reasonCode || null }));
  process.exit(43);
} catch (error) {
  fs.writeFileSync(request.errorFile, JSON.stringify({ code: error.code || null, message: String(error.message || error) }));
  process.exit(44);
}
