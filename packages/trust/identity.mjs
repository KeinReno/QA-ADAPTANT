import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
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

export function assertPrincipal(principal, { role, domain, windowsSid } = {}) {
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
  if (document.signatureAlgorithm !== 'Ed25519' || document.keyId !== key.keyId) fail('APPROVAL_SIGNATURE_INVALID', 'Подпись не от ключа этого домена');
  const body = unsigned(document);
  const ok = verify(null, Buffer.from(canonical(body), 'utf8'), key.publicKey, Buffer.from(document.signature, 'hex'));
  if (!ok) fail('APPROVAL_SIGNATURE_INVALID', 'Подпись не сошлась');
  return body;
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
    return {
      owner: readPublic(path.join(trustRoot, 'owner.pub'), 'owner'),
      'anchor-signer': readPublic(path.join(trustRoot, 'anchor.pub'), 'anchor-signer')
    };
  } catch (error) {
    if (error.code === 'TRUST_STORE_UNAVAILABLE') throw error;
    fail('TRUST_STORE_UNAVAILABLE', 'Корень доверия не читается');
  }
}

async function writeKey(secretsDir, trustRoot, purpose, privateName, publicName) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const keyId = publicKeyId(publicKey);
  const pkcs8 = privateKey.export({ type: 'pkcs8', format: 'der' });
  const protectedPkcs8 = await protect(pkcs8);
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
  fs.writeFileSync(publicFile, `${JSON.stringify({
    schemaVersion: '0.2.0',
    domain: 'public-key',
    purpose,
    keyId,
    spki: publicKey.export({ type: 'spki', format: 'der' }).toString('base64')
  })}\n`, { flag: 'wx' });
  await restrictToCurrentUser(secretFile);
  return { keyId, privateKey, pkcs8 };
}

export async function createTrustRoot({ secretsDir, trustRoot }) {
  fs.mkdirSync(secretsDir, { recursive: true });
  fs.mkdirSync(trustRoot, { recursive: true });
  await restrictToCurrentUser(secretsDir);
  const owner = await writeKey(secretsDir, trustRoot, 'owner', 'owner.key', 'owner.pub');
  const anchor = await writeKey(secretsDir, trustRoot, 'anchor-signer', 'anchor.key', 'anchor.pub');
  return {
    ownerKeyId: owner.keyId,
    anchorKeyId: anchor.keyId,
    ownerPrivate: owner.privateKey,
    anchorPrivate: anchor.privateKey,
    ownerPkcs8: owner.pkcs8,
    anchorPkcs8: anchor.pkcs8
  };
}

export async function unwrapPrivateKey(file) {
  const value = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (value.domain !== 'wrapped-private-key' || value.wrapping !== 'dpapi-current-user') fail('TRUST_STORE_UNAVAILABLE', 'Файл ключа не является обёрткой DPAPI');
  const pkcs8 = await unprotect(Buffer.from(value.protectedPkcs8, 'base64'));
  const privateKey = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  if (publicKeyId(createPublicKey(privateKey)) !== value.keyId) fail('APPROVAL_SIGNATURE_INVALID', 'Раскрытый ключ не совпал с keyId');
  return privateKey;
}
