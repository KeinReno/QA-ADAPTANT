import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonical } from '../core/canonical.mjs';
import { restrictToCurrentUser } from './acl.mjs';
import { protect, unprotect } from './dpapi.mjs';

const ownerDomains = new Set(['approval', 'revocation', 'principal', 'environment-record']);
const anchorDomains = new Set(['anchor-statement']);
const roles = new Set(['owner', 'operator', 'runner', 'anchor-signer', 'verifier', 'agent']);

function fail(code, message) {
  throw Object.assign(new Error(message), { code });
}

function rawPublic(publicKey) {
  const jwk = publicKey.export({ format: 'jwk' });
  return Buffer.from(jwk.x, 'base64url');
}

export function publicKeyId(publicKey) {
  return createHash('sha256').update(rawPublic(publicKey)).digest('hex');
}

function unsigned(document) {
  const body = { ...document };
  delete body.signature;
  delete body.signatureAlgorithm;
  return body;
}

function purposeForDomain(domain) {
  if (ownerDomains.has(domain)) return 'owner';
  if (anchorDomains.has(domain)) return 'anchor-signer';
  fail('CONTRACT_INVALID', 'Домен подписи не относится к ключам 0.2');
}

function assertPrincipal(principal, { role, domain, windowsSid } = {}) {
  if (!principal || principal.domain !== 'principal' || principal.status !== 'active') fail('PRINCIPAL_REVOKED', 'Principal не активен');
  if (!Array.isArray(principal.roles) || principal.roles.length === 0 || principal.roles.some(item => !roles.has(item))) fail('ROLE_DENIED', 'Роль Principal неизвестна');
  if (principal.roles.includes('owner') && principal.roles.includes('runner')) fail('ROLE_DENIED', 'Owner и runner не совмещаются');
  if (principal.roles.includes('owner') && principal.roles.includes('anchor-signer')) fail('ROLE_DENIED', 'Owner и anchor-signer не совмещаются');
  if (principal.roles.includes('runner') && principal.keyId !== null) fail('ROLE_DENIED', 'Runner не хранит ключ подписи');
  if (principal.roles.includes('owner') && !principal.keyId) fail('ROLE_DENIED', 'Owner без ключа не подписывает');
  if (role && !principal.roles.includes(role)) fail('ROLE_DENIED', 'Роль не позволяет действие');
  if (domain === 'approval' && !principal.roles.includes('owner')) fail('ROLE_DENIED', 'Approval подписывает только owner');
  if (domain === 'anchor-statement' && !principal.roles.includes('anchor-signer')) fail('ROLE_DENIED', 'Анкер подписывает только anchor-signer');
  if (windowsSid !== undefined && principal.windowsSid !== windowsSid) fail('CALLER_UNAUTHENTICATED', 'SID вызывающего не совпал');
  return principal;
}

export function signTrustedDocument(privateKey, document) {
  const body = unsigned(document);
  purposeForDomain(body.domain);
  const derived = publicKeyId(createPublicKey(privateKey));
  if (body.keyId !== derived) fail('APPROVAL_SIGNATURE_INVALID', 'keyId не принадлежит этому приватному ключу');
  const signature = sign(null, Buffer.from(canonical(body), 'utf8'), privateKey);
  return { ...body, signature: signature.toString('hex'), signatureAlgorithm: 'Ed25519' };
}

export function verifyTrustedDocument(trust, document) {
  const purpose = purposeForDomain(document?.domain);
  const key = trust?.[purpose];
  if (!key) fail('TRUST_STORE_UNAVAILABLE', 'Публичный ключ домена не загружен');
  if (document.signatureAlgorithm !== 'Ed25519' || document.keyId !== key.keyId || typeof document.signature !== 'string' || !/^[a-f0-9]+$/i.test(document.signature)) fail('APPROVAL_SIGNATURE_INVALID', 'Подпись не от ключа этого домена');
  const body = unsigned(document);
  const ok = verify(null, Buffer.from(canonical(body), 'utf8'), key.publicKey, Buffer.from(document.signature, 'hex'));
  if (!ok) fail('APPROVAL_SIGNATURE_INVALID', 'Подпись не сошлась');
  return body;
}

export function verifyAndAssertPrincipal(trust, document, constraints = {}) {
  const body = verifyTrustedDocument(trust, document);
  if (body.domain !== 'principal') fail('CONTRACT_INVALID', 'Документ не является карточкой Principal');
  return assertPrincipal(body, constraints);
}

function readPublic(file, purpose) {
  const value = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (value.domain !== 'public-key' || value.purpose !== purpose || value.schemaVersion !== '0.2.0') fail('TRUST_STORE_UNAVAILABLE', 'Публичный ключ повреждён');
  const publicKey = createPublicKey({ key: Buffer.from(value.spki, 'base64'), format: 'der', type: 'spki' });
  if (publicKeyId(publicKey) !== value.keyId) fail('TRUST_STORE_UNAVAILABLE', 'keyId не совпал с публичным ключом');
  return { purpose, keyId: value.keyId, publicKey };
}

export function loadTrustRoot(trustRoot) {
  try {
    const owner = readPublic(path.join(trustRoot, 'owner.pub'), 'owner');
    const anchor = readPublic(path.join(trustRoot, 'anchor.pub'), 'anchor-signer');
    const ready = JSON.parse(fs.readFileSync(path.join(trustRoot, 'ready.json'), 'utf8'));
    if (ready.domain !== 'trust-root-ready' || ready.schemaVersion !== '0.2.0' || ready.ownerKeyId !== owner.keyId || ready.anchorKeyId !== anchor.keyId) fail('TRUST_STORE_UNAVAILABLE', 'Корень доверия не завершён');
    return { owner, 'anchor-signer': anchor };
  } catch (error) {
    if (error.code === 'TRUST_STORE_UNAVAILABLE') throw error;
    fail('TRUST_STORE_UNAVAILABLE', 'Корень доверия не читается');
  }
}

const repoRoot = physicalPath(path.resolve(fileURLToPath(new URL('../..', import.meta.url))));

function physicalPath(input) {
  const resolved = path.resolve(input);
  const missing = [];
  let current = resolved;
  while (!fs.existsSync(current)) {
    const parent = path.dirname(current);
    if (parent === current) break;
    missing.push(path.basename(current));
    current = parent;
  }
  let base;
  try { base = fs.realpathSync(current); }
  catch { fail('TRUST_STORE_UNAVAILABLE', 'Путь хранилища не разрешается'); }
  return path.resolve(base, ...missing.reverse());
}

function contains(parent, child) {
  const left = process.platform === 'win32' ? path.normalize(parent).toLowerCase() : path.normalize(parent);
  const right = process.platform === 'win32' ? path.normalize(child).toLowerCase() : path.normalize(child);
  if (left === right) return true;
  const prefix = left.endsWith(path.sep) ? left : left + path.sep;
  return right.startsWith(prefix);
}

function placeTrustRoot({ secretsDir, trustRoot, runDir }) {
  const secrets = physicalPath(secretsDir);
  const trust = physicalPath(trustRoot);
  if (contains(secrets, trust) || contains(trust, secrets)) fail('TRUST_STORE_UNAVAILABLE', 'Каталоги секретов и trust root совпадают или вложены');
  if (contains(repoRoot, secrets)) fail('TRUST_STORE_UNAVAILABLE', 'Приватные ключи нельзя размещать внутри репозитория');
  if (runDir && contains(physicalPath(runDir), secrets)) fail('TRUST_STORE_UNAVAILABLE', 'Приватные ключи нельзя размещать внутри каталога прогона');
  return { secrets, trust };
}

async function writeKey(secretsDir, trustRoot, purpose, privateName, publicName, createdFiles) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const keyId = publicKeyId(publicKey);
  const protectedPkcs8 = await protect(privateKey.export({ type: 'pkcs8', format: 'der' }));
  const secretFile = path.join(secretsDir, privateName);
  const publicFile = path.join(trustRoot, publicName);
  fs.writeFileSync(secretFile, `${JSON.stringify({
    schemaVersion: '0.2.0',
    domain: 'wrapped-private-key',
    purpose,
    keyId,
    wrapping: 'dpapi-current-user',
    protectedPkcs8: protectedPkcs8.toString('base64')
  })}\n`, { flag: 'wx' });
  createdFiles.push(secretFile);
  fs.writeFileSync(publicFile, `${JSON.stringify({
    schemaVersion: '0.2.0',
    domain: 'public-key',
    purpose,
    keyId,
    spki: publicKey.export({ type: 'spki', format: 'der' }).toString('base64')
  })}\n`, { flag: 'wx' });
  createdFiles.push(publicFile);
  await restrictToCurrentUser(secretFile);
  return keyId;
}

export async function createTrustRoot({ secretsDir, trustRoot, runDir, fault } = {}) {
  const placed = placeTrustRoot({ secretsDir, trustRoot, runDir });
  const targets = ['owner.key', 'anchor.key'].map(name => path.join(placed.secrets, name))
    .concat(['owner.pub', 'anchor.pub', 'ready.json'].map(name => path.join(placed.trust, name)));
  if (targets.some(file => fs.existsSync(file))) fail('TRUST_STORE_UNAVAILABLE', 'Существующие ключи не перезаписываются');
  fs.mkdirSync(placed.secrets, { recursive: true });
  fs.mkdirSync(placed.trust, { recursive: true });
  await restrictToCurrentUser(placed.secrets);
  const createdFiles = [];
  try {
    const ownerKeyId = await writeKey(placed.secrets, placed.trust, 'owner', 'owner.key', 'owner.pub', createdFiles);
    if (fault === 'after-owner') fail('TRUST_STORE_UNAVAILABLE', 'Создание второго ключа прервано');
    const anchorKeyId = await writeKey(placed.secrets, placed.trust, 'anchor-signer', 'anchor.key', 'anchor.pub', createdFiles);
    const ready = path.join(placed.trust, 'ready.json');
    fs.writeFileSync(ready, `${JSON.stringify({ schemaVersion: '0.2.0', domain: 'trust-root-ready', ownerKeyId, anchorKeyId })}\n`, { flag: 'wx' });
    createdFiles.push(ready);
    return { ownerKeyId, anchorKeyId };
  } catch (error) {
    for (const file of createdFiles.reverse()) fs.rmSync(file, { force: true });
    if (error.code) throw error;
    fail('TRUST_STORE_UNAVAILABLE', 'Корень доверия не создан');
  }
}

export async function unwrapPrivateKey(file) {
  const value = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (value.domain !== 'wrapped-private-key' || value.wrapping !== 'dpapi-current-user') fail('TRUST_STORE_UNAVAILABLE', 'Файл ключа не является обёрткой DPAPI');
  const pkcs8 = await unprotect(Buffer.from(value.protectedPkcs8, 'base64'));
  const privateKey = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  if (publicKeyId(createPublicKey(privateKey)) !== value.keyId) fail('APPROVAL_SIGNATURE_INVALID', 'Раскрытый ключ не совпал с keyId');
  return privateKey;
}
