/**
 * The MailDots apps' end-to-end crypto core: the SAME code as the webmail's browser
 * crypto (vault, S/MIME, MIME, sanitising), bundled into one file
 * (scripts/build-mobile-core.mjs) and run inside a hidden, network-less web view on
 * the phone. One implementation on every platform — what Proton does with its
 * shared crypto library — instead of a second, separately written one.
 *
 * Protocol: the app calls `MailDotsCore.run(id, method, argsJson?)`; without
 * `argsJson` the arguments are pulled from `MailDotsBridge.args(id)` (Android: large
 * mails would otherwise travel inside a script). The answer goes back through
 * `MailDotsBridge.reply(id, ok, json)` (Android) or the `mailDots` message handler
 * (iOS). Errors carry a stable code only, never key material or content.
 */
import { z } from 'zod';
import { kdfParamsSchema, vaultBundleSchema } from './vault-schema';
import {
  derivePasswordKeys,
  derivePasswordSecrets,
  importLockKey,
  keyMatchesCertificate,
  rewrapForPassword,
  rewrapWithKeys,
  unlockWithLockKey,
} from './vault';
import { openEncryptedMail } from './decrypted-mail';
import { signEntity } from './smime-sign';
import { applyLogPage, EMPTY_KEY_LOG, mismatchedKeys } from './key-log-format';
import {
  buildMimeEntity,
  certificateFingerprint,
  certificateIsFor,
  encryptEntity,
} from './outgoing-mail';
import { openEncryptedDraft } from './open-draft';
import { SmimeError } from './smime';
import { fromBase64, toBase64 } from './encoding';

export const CORE_VERSION = 4; // 2: signatures, 3: key log, 4: protected headers + witness (T4)

const b64 = z.string().max(64_000_000);
const pem = z.string().max(8_000);

const schemas = {
  deriveSecrets: z.object({ password: z.string().min(1).max(512), kdf: kdfParamsSchema }),
  unlock: z.object({
    bundle: vaultBundleSchema.pick({ version: true, certificatePem: true, passwordSlot: true }),
    email: z.string().email().max(320),
    lockKey: b64,
  }),
  decrypt: z.object({ raw: b64, pkcs8: b64, certificatePem: pem }),
  openDraft: z.object({ raw: b64, pkcs8: b64, certificatePem: pem }),
  encrypt: z.object({
    html: z.string().max(20_000_000),
    attachments: z
      .array(
        z.object({
          filename: z.string().max(255),
          contentType: z.string().max(200),
          contentBase64: b64,
        }),
      )
      .max(50)
      .default([]),
    certificates: z.array(pem).min(1).max(200),
    /** The sender's own unlocked key: the message is signed, then encrypted (T4). */
    signer: z.object({ pkcs8: b64, certificatePem: pem }).optional(),
    /** From / To / Subject and the sender's key-log head, signed inside (T4). */
    headers: z
      .object({
        from: z.string().max(320),
        to: z.array(z.string().max(320)).max(200),
        subject: z.string().max(2000),
        keyLog: z
          .object({ seq: z.number().int().min(0), hash: z.string().regex(/^[0-9a-f]{64}$/) })
          .nullable()
          .optional(),
      })
      .optional(),
  }),
  checkCertificate: z.object({ certificatePem: pem, address: z.string().max(320) }),
  // T4: one page of the key transparency log, checked against the app's verified state.
  keyLog: z.object({
    state: z
      .object({
        seq: z.number().int().min(0),
        hash: z.string().regex(/^[0-9a-f]{64}$/),
        keys: z.record(z.string(), z.string()),
        hashes: z.record(z.string(), z.string()).optional(),
      })
      .nullable(),
    page: z.object({
      entries: z
        .array(
          z.object({
            seq: z.number().int().min(1),
            addressHash: z.string().regex(/^[0-9a-f]{64}$/),
            fingerprint: z.string().regex(/^([0-9a-f]{64})?$/),
            action: z.enum(['add', 'remove']),
            at: z.string().max(40),
            prevHash: z.string().regex(/^[0-9a-f]{64}$/),
            hash: z.string().regex(/^[0-9a-f]{64}$/),
          }),
        )
        .max(1000),
      head: z.object({ seq: z.number().int().min(0), hash: z.string().max(64) }),
    }),
    served: z.record(z.string(), z.string()),
  }),
  passwordChange: z.object({
    email: z.string().email().max(320),
    currentPassword: z.string().min(1).max(512),
    newPassword: z.string().min(1).max(512),
    loginMode: z.enum(['password', 'derived', 'switching']),
    bundle: vaultBundleSchema.pick({
      version: true,
      certificatePem: true,
      kdf: true,
      passwordSlot: true,
    }),
  }),
} as const;

type Method = keyof typeof schemas;

/** A Blob's bytes (FileReader fallback for engines without Blob.arrayBuffer). */
function blobBytes(blob: Blob): Promise<Uint8Array> {
  if (typeof blob.arrayBuffer === 'function') {
    return blob.arrayBuffer().then((b) => new Uint8Array(b));
  }
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(new Uint8Array(r.result as ArrayBuffer));
    r.onerror = () => reject(new Error('read_failed'));
    r.readAsArrayBuffer(blob);
  });
}

async function handle(method: Method, input: unknown): Promise<unknown> {
  switch (method) {
    case 'deriveSecrets': {
      const a = schemas.deriveSecrets.parse(input);
      const s = await derivePasswordSecrets(a.password, a.kdf);
      try {
        return { loginKey: s.loginKey, lockKey: toBase64(s.lockKey) };
      } finally {
        s.lockKey.fill(0);
      }
    }
    case 'unlock': {
      const a = schemas.unlock.parse(input);
      const raw = fromBase64(a.lockKey);
      const key = await importLockKey(raw).finally(() => raw.fill(0));
      const pkcs8 = await unlockWithLockKey(a.bundle, a.email, key);
      try {
        // The certificate the server encrypts to must belong to this key.
        if (!keyMatchesCertificate(pkcs8, a.bundle.certificatePem)) throw new Error('key_mismatch');
        return { pkcs8: toBase64(pkcs8) };
      } finally {
        pkcs8.fill(0);
      }
    }
    case 'decrypt': {
      const a = schemas.decrypt.parse(input);
      const pkcs8 = fromBase64(a.pkcs8);
      try {
        const mail = await openEncryptedMail(fromBase64(a.raw), pkcs8, a.certificatePem);
        return {
          html: mail.html,
          hadRemoteContent: mail.hadRemoteContent,
          // Who signed is judged by the app (directory key + pin), as in the webmail.
          signature: mail.signature,
          attachments: await Promise.all(
            mail.attachments.map(async (x) => ({
              filename: x.filename,
              contentType: x.contentType,
              size: x.size,
              data: toBase64(await blobBytes(x.blob)),
            })),
          ),
        };
      } finally {
        pkcs8.fill(0);
      }
    }
    case 'openDraft': {
      const a = schemas.openDraft.parse(input);
      const pkcs8 = fromBase64(a.pkcs8);
      try {
        return await openEncryptedDraft(fromBase64(a.raw), pkcs8, a.certificatePem);
      } finally {
        pkcs8.fill(0);
      }
    }
    case 'encrypt': {
      const a = schemas.encrypt.parse(input);
      let entity = buildMimeEntity({ html: a.html, attachments: a.attachments });
      if (a.signer) {
        const key = fromBase64(a.signer.pkcs8);
        try {
          entity = signEntity(entity, key, a.signer.certificatePem, a.headers);
        } finally {
          key.fill(0);
        }
      }
      return { ciphertext: encryptEntity(entity, a.certificates) };
    }
    case 'passwordChange': {
      // Same as the webmail's preparePasswordChange: the key is re-locked for the new
      // password here; with login protection only login keys go to the server.
      const a = schemas.passwordChange.parse(input);
      const current = await derivePasswordKeys(a.currentPassword, a.bundle.kdf);
      const pkcs8 = await unlockWithLockKey(a.bundle, a.email, current.lockKey).catch(() => {
        throw new Error('locked');
      });
      try {
        if (a.loginMode === 'password') {
          return {
            target: 'password',
            currentSecret: a.currentPassword,
            newSecret: a.newPassword,
            vault: await rewrapForPassword(pkcs8, a.email, a.newPassword),
          };
        }
        const next = await rewrapWithKeys(
          pkcs8,
          a.email,
          a.newPassword,
          a.bundle.kdf,
          a.bundle.version,
        );
        return {
          target: 'derived',
          currentSecret: current.loginKey,
          newSecret: next.loginKey,
          vault: next.update,
        };
      } finally {
        pkcs8.fill(0);
      }
    }
    case 'keyLog': {
      const a = schemas.keyLog.parse(input);
      const applied = await applyLogPage(a.state ?? EMPTY_KEY_LOG, a.page);
      if (!applied.ok) return { ok: false };
      return {
        ok: true,
        state: applied.state,
        complete: applied.complete,
        mismatched: applied.complete ? await mismatchedKeys(applied.state, a.served) : [],
      };
    }
    case 'checkCertificate': {
      const a = schemas.checkCertificate.parse(input);
      if (!certificateIsFor(a.certificatePem, a.address)) return { ok: false };
      return { ok: true, fingerprint: await certificateFingerprint(a.certificatePem) };
    }
  }
}

/** A stable, content-free error code. */
function codeOf(err: unknown): string {
  if (err instanceof SmimeError) return err.code;
  if (err instanceof z.ZodError) return 'invalid_input';
  if (err instanceof Error && /^[a-z_]{3,40}$/.test(err.message)) return err.message;
  return 'core_error';
}

interface Bridge {
  args?(id: string): string;
  reply?(id: string, ok: boolean, payload: string): void;
}
interface CoreWindow {
  MailDotsBridge?: Bridge;
  webkit?: { messageHandlers?: { mailDots?: { postMessage(m: unknown): void } } };
  MailDotsCore?: unknown;
}

function send(id: string, ok: boolean, payload: string): void {
  const w = globalThis as unknown as CoreWindow;
  if (w.MailDotsBridge?.reply) w.MailDotsBridge.reply(id, ok, payload);
  else w.webkit?.messageHandlers?.mailDots?.postMessage({ id, ok, payload });
}

export function installCore(): void {
  const w = globalThis as unknown as CoreWindow;
  w.MailDotsCore = {
    version: CORE_VERSION,
    run(id: string, method: string, argsJson?: string): void {
      void (async () => {
        try {
          if (!(method in schemas)) throw new Error('unknown_method');
          const json = argsJson ?? w.MailDotsBridge?.args?.(id) ?? 'null';
          const result = await handle(method as Method, JSON.parse(json));
          send(id, true, JSON.stringify(result));
        } catch (err) {
          send(id, false, JSON.stringify({ error: codeOf(err) }));
        }
      })();
    },
  };
}
