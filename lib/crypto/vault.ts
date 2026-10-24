/**
 * Mailbox key vault — runs in the BROWSER (and in tests); never on the server.
 *
 *   password ──Argon2id(salt)──▶ lock key ─┐
 *   recovery phrase (24 words) ──HKDF───▶ recovery key ─┤ AES-256-GCM
 *                                                       ▼
 *                         RSA-3072 private key (PKCS#8) ──▶ two wrapped copies
 *
 * Only the wrapped copies and the public S/MIME certificate leave the device. The
 * mail server encrypts incoming mail to that certificate (S/MIME enveloped data),
 * so only a holder of the password or the recovery phrase can read it.
 */
import { argon2id } from 'hash-wasm';
import forge from 'node-forge';
import { generateMnemonic, mnemonicToEntropy, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import {
  VAULT_VERSION,
  type KdfParams,
  type PasswordSlotUpdate,
  type VaultBundle,
  type WrappedKey,
} from './vault-schema';
import { fromBase64, fromBinaryString, toBase64, toBinaryString } from './encoding';

const subtle = () => globalThis.crypto.subtle;

/** Defaults: OWASP-grade Argon2id (64 MiB, 3 passes). Stored per vault, so they can rise later. */
export interface KdfCost {
  memoryKiB: number;
  iterations: number;
  parallelism: number;
}
export const DEFAULT_KDF: Readonly<KdfCost> = { memoryKiB: 65_536, iterations: 3, parallelism: 1 };

/**
 * The lowest cost a device accepts from the server for the password copy (sign-in
 * and recovery). Kept apart from DEFAULT_KDF on purpose: raising the default for new
 * vaults must not lock out existing ones. Never raise it above any live vault's cost.
 */
export const KDF_FLOOR: Readonly<Pick<KdfCost, 'memoryKiB' | 'iterations'>> = {
  memoryKiB: 65_536,
  iterations: 3,
};

/** Anything below KDF_FLOOR means a server lowering the cost of an offline guess. */
export function meetsKdfFloor(kdf: Pick<KdfCost, 'memoryKiB' | 'iterations'>): boolean {
  return kdf.memoryKiB >= KDF_FLOOR.memoryKiB && kdf.iterations >= KDF_FLOOR.iterations;
}

const RSA_BITS = 3072;
const CERT_YEARS = 10;

function randomBytes(n: number): Uint8Array<ArrayBuffer> {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}

/**
 * Binds a wrapped copy to its vault version, mailbox and slot, so blobs cannot be
 * swapped around. The version is the VAULT's own, so a later format can still
 * open (and migrate) older vaults.
 */
function aad(
  version: number,
  email: string,
  slot: 'password' | 'recovery',
): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(`maildots-vault|v${version}|${email.toLowerCase()}|${slot}`);
}

/**
 * Domain separation for keys derived from the password. The lock key and the
 * future login key (the secret the mail server sees) come from different HKDF
 * contexts, so the server can never obtain the lock key — not even by handing the
 * client this vault's salt as the "login salt".
 */
export const PASSWORD_KEY_CONTEXT = {
  vaultLock: 'maildots/vault-lock/v1',
  login: 'maildots/login/v1',
} as const;

// ── Key derivation ──────────────────────────────────────────────────────────

export function newKdfParams(cost: Partial<KdfCost> = {}): KdfParams {
  return { alg: 'argon2id', ...DEFAULT_KDF, ...cost, salt: toBase64(randomBytes(16)) };
}

/**
 * Prefix of a login key, so the server (and anyone reading logs of a mistake) can
 * tell it from a human password: `md1_` + 32 bytes in base64url.
 */
export const LOGIN_KEY_PREFIX = 'md1_';

function base64Url(bytes: Uint8Array): string {
  return toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function stretch(password: string, kdf: KdfParams): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(
    await argon2id({
      password: password.normalize('NFC'),
      salt: fromBase64(kdf.salt),
      memorySize: kdf.memoryKiB,
      iterations: kdf.iterations,
      parallelism: kdf.parallelism,
      hashLength: 32,
      outputType: 'binary',
    }),
  );
}

function hkdfParams(info: string): HkdfParams {
  return {
    name: 'HKDF',
    hash: 'SHA-256',
    salt: new Uint8Array(32),
    info: new TextEncoder().encode(info),
  };
}

export interface PasswordKeys {
  /** Opens the vault. Non-extractable; never leaves this device. */
  lockKey: CryptoKey;
  /** What the mail server sees instead of the password (`md1_…`). */
  loginKey: string;
}

/**
 * One Argon2id run, two independent keys (Proton-style "the password never reaches
 * the server"): the lock key opens the vault, the login key is the mailbox's
 * secret on the mail server. HKDF contexts differ, so the login key reveals
 * nothing about the lock key; guessing the password from it costs a full Argon2id
 * per guess.
 */
export async function derivePasswordKeys(password: string, kdf: KdfParams): Promise<PasswordKeys> {
  const stretched = await stretch(password, kdf);
  try {
    const ikm = await subtle().importKey('raw', stretched, 'HKDF', false, [
      'deriveKey',
      'deriveBits',
    ]);
    const [lockKey, loginBits] = await Promise.all([
      subtle().deriveKey(
        hkdfParams(PASSWORD_KEY_CONTEXT.vaultLock),
        ikm,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt'],
      ),
      subtle().deriveBits(hkdfParams(PASSWORD_KEY_CONTEXT.login), ikm, 256),
    ]);
    const login = new Uint8Array(loginBits);
    const loginKey = LOGIN_KEY_PREFIX + base64Url(login);
    login.fill(0);
    return { lockKey, loginKey };
  } finally {
    stretched.fill(0);
  }
}

/**
 * Same derivation, with the lock key as raw bytes (for the mobile apps, whose crypto
 * core runs in a separate web view: the key crosses one in-process bridge and is
 * then imported again with importLockKey). Caller wipes `lockKey` after use.
 */
export async function derivePasswordSecrets(
  password: string,
  kdf: KdfParams,
): Promise<{ loginKey: string; lockKey: Uint8Array<ArrayBuffer> }> {
  const stretched = await stretch(password, kdf);
  try {
    const ikm = await subtle().importKey('raw', stretched, 'HKDF', false, ['deriveBits']);
    const [lockBits, loginBits] = await Promise.all([
      subtle().deriveBits(hkdfParams(PASSWORD_KEY_CONTEXT.vaultLock), ikm, 256),
      subtle().deriveBits(hkdfParams(PASSWORD_KEY_CONTEXT.login), ikm, 256),
    ]);
    const login = new Uint8Array(loginBits);
    const loginKey = LOGIN_KEY_PREFIX + base64Url(login);
    login.fill(0);
    return { loginKey, lockKey: new Uint8Array(lockBits) };
  } finally {
    stretched.fill(0);
  }
}

/** A raw lock key (from derivePasswordSecrets) as the non-extractable AES-GCM key. */
export function importLockKey(raw: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  return subtle().importKey('raw', raw, { name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
    'decrypt',
  ]);
}

/** Lock key from the password. Non-extractable: it can wrap/unwrap, never be read. */
export async function deriveLockKey(password: string, kdf: KdfParams): Promise<CryptoKey> {
  return (await derivePasswordKeys(password, kdf)).lockKey;
}

/** The login key alone (sign-in, re-proving the password to the server). */
export async function deriveLoginKey(password: string, kdf: KdfParams): Promise<string> {
  return (await derivePasswordKeys(password, kdf)).loginKey;
}

/** A fresh 24-word recovery phrase (256 bits of entropy). */
export function newRecoveryPhrase(): string {
  return generateMnemonic(wordlist, 256);
}

/** Lower-cases and collapses whitespace so a hand-typed phrase still matches. */
export function normalizeRecoveryPhrase(phrase: string): string {
  return phrase.trim().toLowerCase().split(/\s+/).join(' ');
}

export function isValidRecoveryPhrase(phrase: string): boolean {
  const p = normalizeRecoveryPhrase(phrase);
  return p.split(' ').length === 24 && validateMnemonic(p, wordlist);
}

async function deriveRecoveryKey(phrase: string): Promise<CryptoKey> {
  const p = normalizeRecoveryPhrase(phrase);
  if (!isValidRecoveryPhrase(p)) throw new Error('invalid_recovery_phrase');
  const entropy = new Uint8Array(mnemonicToEntropy(p, wordlist));
  const ikm = await subtle().importKey('raw', entropy, 'HKDF', false, ['deriveKey']);
  entropy.fill(0);
  return subtle().deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(32),
      info: new TextEncoder().encode('maildots/vault/recovery/v1'),
    },
    ikm,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

// ── Wrapping ────────────────────────────────────────────────────────────────

async function wrap(
  key: CryptoKey,
  secret: Uint8Array<ArrayBuffer>,
  ad: Uint8Array<ArrayBuffer>,
): Promise<WrappedKey> {
  const iv = randomBytes(12);
  const ct = await subtle().encrypt({ name: 'AES-GCM', iv, additionalData: ad }, key, secret);
  return { iv: toBase64(iv), ct: toBase64(new Uint8Array(ct)) };
}

async function unwrap(
  key: CryptoKey,
  slot: WrappedKey,
  ad: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  try {
    const pt = await subtle().decrypt(
      { name: 'AES-GCM', iv: fromBase64(slot.iv), additionalData: ad },
      key,
      fromBase64(slot.ct),
    );
    return new Uint8Array(pt);
  } catch {
    // Wrong password / phrase, or a tampered blob: indistinguishable on purpose.
    throw new Error('unlock_failed');
  }
}

// ── Certificate ─────────────────────────────────────────────────────────────

function selfSignedCertificate(email: string, pkcs8: Uint8Array): string {
  const privateKey = forge.pki.privateKeyFromAsn1(
    forge.asn1.fromDer(toBinaryString(pkcs8)),
  ) as forge.pki.rsa.PrivateKey;
  const cert = forge.pki.createCertificate();
  cert.publicKey = forge.pki.setRsaPublicKey(privateKey.n, privateKey.e);
  // Positive, random 128-bit serial.
  cert.serialNumber = '01' + forge.util.bytesToHex(toBinaryString(randomBytes(15)));
  const now = new Date();
  cert.validity.notBefore = new Date(now.getTime() - 24 * 3600 * 1000);
  cert.validity.notAfter = new Date(now.getTime());
  cert.validity.notAfter.setFullYear(now.getFullYear() + CERT_YEARS);
  const subject = [
    { name: 'commonName', value: email },
    { name: 'emailAddress', value: email },
  ];
  cert.setSubject(subject);
  cert.setIssuer(subject);
  cert.setExtensions([
    { name: 'basicConstraints', cA: false, critical: true },
    // Decryption only: this RSA key never signs (no cross-protocol use with v1.5 decryption).
    { name: 'keyUsage', keyEncipherment: true, critical: true },
    { name: 'extKeyUsage', emailProtection: true },
    { name: 'subjectAltName', altNames: [{ type: 1, value: email }] },
    { name: 'subjectKeyIdentifier' },
  ]);
  cert.sign(privateKey, forge.md.sha256.create());
  return forge.pki.certificateToPem(cert);
}

// ── Vault lifecycle ─────────────────────────────────────────────────────────

export interface CreatedVault {
  bundle: VaultBundle;
  /** Shown to the user ONCE; never stored or sent anywhere. */
  recoveryPhrase: string;
  /** The mailbox's new server secret, derived from the same password and salt. */
  loginKey: string;
}

/** Generates the mailbox key pair and both wrapped copies of its private key. */
export async function createVault(
  email: string,
  password: string,
  cost: Partial<KdfCost> = {},
): Promise<CreatedVault> {
  const pair = await subtle().generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: RSA_BITS,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt'],
  );
  const pkcs8 = new Uint8Array(await subtle().exportKey('pkcs8', pair.privateKey));
  try {
    const certificatePem = selfSignedCertificate(email, pkcs8);
    const kdf = newKdfParams(cost);
    const recoveryPhrase = newRecoveryPhrase();
    const keys = await derivePasswordKeys(password, kdf);
    const [passwordSlot, recoverySlot] = await Promise.all([
      wrap(keys.lockKey, pkcs8, aad(VAULT_VERSION, email, 'password')),
      deriveRecoveryKey(recoveryPhrase).then((k) =>
        wrap(k, pkcs8, aad(VAULT_VERSION, email, 'recovery')),
      ),
    ]);
    // Self-check before anything leaves the device: the certificate the mail server
    // will encrypt to must belong to the key we wrapped.
    if (!keyMatchesCertificate(pkcs8, certificatePem)) throw new Error('key_mismatch');
    return {
      bundle: { version: VAULT_VERSION, certificatePem, kdf, passwordSlot, recoverySlot },
      recoveryPhrase,
      loginKey: keys.loginKey,
    };
  } finally {
    pkcs8.fill(0);
  }
}

/** The PKCS#8 private key, or throws `unlock_failed`. Caller must wipe it after use. */
export async function unlockWithPassword(
  bundle: Pick<VaultBundle, 'kdf' | 'passwordSlot'> & { version?: number },
  email: string,
  password: string,
): Promise<Uint8Array<ArrayBuffer>> {
  const key = await deriveLockKey(password, bundle.kdf);
  return unwrap(key, bundle.passwordSlot, aad(bundle.version ?? VAULT_VERSION, email, 'password'));
}

/** Same, with a lock key already derived at sign-in (no second Argon2id run). */
export async function unlockWithLockKey(
  bundle: Pick<VaultBundle, 'passwordSlot'> & { version?: number },
  email: string,
  lockKey: CryptoKey,
): Promise<Uint8Array<ArrayBuffer>> {
  return unwrap(
    lockKey,
    bundle.passwordSlot,
    aad(bundle.version ?? VAULT_VERSION, email, 'password'),
  );
}

export async function unlockWithRecovery(
  bundle: Pick<VaultBundle, 'recoverySlot'> & { version?: number },
  email: string,
  phrase: string,
): Promise<Uint8Array<ArrayBuffer>> {
  let key: CryptoKey;
  try {
    key = await deriveRecoveryKey(phrase);
  } catch {
    throw new Error('unlock_failed');
  }
  return unwrap(key, bundle.recoverySlot, aad(bundle.version ?? VAULT_VERSION, email, 'recovery'));
}

/** Re-wraps the private key under a new password (password change / after recovery). */
export async function rewrapForPassword(
  pkcs8: Uint8Array<ArrayBuffer>,
  email: string,
  newPassword: string,
  cost: Partial<KdfCost> = {},
  version: number = VAULT_VERSION,
): Promise<PasswordSlotUpdate> {
  return (await rewrapWithKeys(pkcs8, email, newPassword, newKdfParams(cost), version)).update;
}

/**
 * Re-wraps under `newPassword` with the GIVEN Argon2id parameters and also returns
 * the matching login key. With login protection the salt stays the same for the
 * vault's life: the sign-in salt can then never disagree with the server secret,
 * even if a password change is cut off halfway.
 */
export async function rewrapWithKeys(
  pkcs8: Uint8Array<ArrayBuffer>,
  email: string,
  newPassword: string,
  kdf: KdfParams,
  version: number = VAULT_VERSION,
): Promise<{ update: PasswordSlotUpdate; loginKey: string }> {
  const keys = await derivePasswordKeys(newPassword, kdf);
  return {
    update: { kdf, passwordSlot: await wrap(keys.lockKey, pkcs8, aad(version, email, 'password')) },
    loginKey: keys.loginKey,
  };
}

/**
 * True when the private key belongs to the certificate (same RSA modulus and
 * exponent). Checked after every unlock: a certificate swapped on the server
 * would otherwise make new mail unreadable without anyone noticing.
 */
export function keyMatchesCertificate(pkcs8: Uint8Array, certificatePem: string): boolean {
  try {
    const key = forge.pki.privateKeyFromAsn1(
      forge.asn1.fromDer(toBinaryString(pkcs8)),
    ) as forge.pki.rsa.PrivateKey;
    const pub = forge.pki.certificateFromPem(certificatePem).publicKey as forge.pki.rsa.PublicKey;
    return key.n.equals(pub.n) && key.e.equals(pub.e);
  } catch {
    return false;
  }
}

/** Random word positions (0-based) to ask back, so the user proves the phrase was written down. */
export function recoveryChallenge(count = 3): number[] {
  const picked = new Set<number>();
  while (picked.size < count) {
    const b = randomBytes(1)[0]!;
    if (b < 240) picked.add(b % 24); // rejection sampling: no modulo bias
  }
  return [...picked].sort((a, b) => a - b);
}

/** Shortest password accepted for an exported key file. */
export const EXPORT_PASSWORD_MIN = 12;

/**
 * The mailbox key as a password-protected PKCS#12 (.p12) file, for installing in
 * Outlook, Apple Mail / iPhone Mail or Thunderbird, which then decrypt the stored
 * S/MIME mail themselves. Built in the browser; the file never touches our server.
 *
 * 3DES + SHA-1 MAC is the one PKCS#12 profile every common importer accepts (older
 * Windows and iOS reject AES/PBES2 files); the strength comes from the export
 * password and a high iteration count.
 */
export function exportPkcs12(
  pkcs8: Uint8Array,
  certificatePem: string,
  exportPassword: string,
  friendlyName: string,
): Uint8Array<ArrayBuffer> {
  if (exportPassword.length < EXPORT_PASSWORD_MIN) throw new Error('weak_export_password');
  const key = forge.pki.privateKeyFromAsn1(forge.asn1.fromDer(toBinaryString(pkcs8)));
  const cert = forge.pki.certificateFromPem(certificatePem);
  const p12 = forge.pkcs12.toPkcs12Asn1(key, [cert], exportPassword, {
    algorithm: '3des',
    count: 100_000,
    saltSize: 16,
    useMac: true,
    generateLocalKeyId: true,
    friendlyName,
  });
  return fromBinaryString(forge.asn1.toDer(p12).getBytes());
}
