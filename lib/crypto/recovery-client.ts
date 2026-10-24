'use client';

import { z } from 'zod';
import {
  certificatePemSchema,
  kdfParamsSchema,
  VAULT_VERSION,
  wrappedKeySchema,
} from './vault-schema';

/**
 * Password reset with the recovery phrase, entirely on this device (the server
 * side is lib/server/keys/recovery.ts): the phrase opens the private key, the key
 * decrypts the server's challenge, and the key is re-wrapped under the new
 * password. Only the challenge answer, the new wrapped copy and the login key
 * derived from the new password leave the device — never the phrase, the new
 * password or the private key.
 */

/** Must match the server's RECOVERY_CHALLENGE_LABEL. */
const CHALLENGE_LABEL = 'maildots/recovery-challenge/v1';

const startSchema = z.object({
  challengeId: z.string().uuid(),
  challenge: z
    .string()
    .regex(/^[A-Za-z0-9+/]+={0,2}$/)
    .max(2_000),
  vault: z.object({
    version: z.literal(VAULT_VERSION),
    certificatePem: certificatePemSchema,
    kdf: kdfParamsSchema,
    recoverySlot: wrappedKeySchema,
  }),
});

export type RecoveryResult =
  | { ok: true }
  | {
      ok: false;
      reason:
        | 'unavailable' // no protected vault for this address
        | 'wrong_phrase'
        | 'rate_limited'
        | 'expired'
        | 'partial' // new password set, key copy not saved: run again
        | 'failed';
    };

const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));
const fromB64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

/**
 * The phrase opened this mailbox's key and answered the server's challenge: the
 * new password can be set. Holds the private key in memory until `setPassword`
 * or `discard`; both wipe it.
 */
export interface VerifiedPhrase {
  setPassword(newPassword: string): Promise<RecoveryResult>;
  discard(): void;
}

export type PhraseCheck =
  | { ok: true; verified: VerifiedPhrase }
  | { ok: false; reason: Extract<RecoveryResult, { ok: false }>['reason'] };

const post = (path: string, body: unknown) =>
  fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

/** Step 2 of "forgot password": checks the phrase on this device (nothing is set yet). */
export async function verifyRecoveryPhrase(email: string, phrase: string): Promise<PhraseCheck> {
  const startRes = await post('/api/auth/recover/start', { email });
  if (startRes.status === 429) return { ok: false, reason: 'rate_limited' };
  if (startRes.status === 404) return { ok: false, reason: 'unavailable' };
  if (!startRes.ok) return { ok: false, reason: 'failed' };
  const start = startSchema.safeParse(await startRes.json().catch(() => null));
  if (!start.success) return { ok: false, reason: 'failed' };
  const { vault, challenge, challengeId } = start.data;
  const owner = email.trim().toLowerCase();

  const { unlockWithRecovery, keyMatchesCertificate, rewrapWithKeys, meetsKdfFloor } =
    await import('./vault');
  // The new password copy is wrapped under these parameters: a server handing out a
  // weakened cost would make it cheaper to guess offline.
  if (!meetsKdfFloor(vault.kdf)) return { ok: false, reason: 'failed' };
  let pkcs8: Uint8Array<ArrayBuffer>;
  try {
    pkcs8 = await unlockWithRecovery(vault, owner, phrase);
  } catch {
    return { ok: false, reason: 'wrong_phrase' };
  }
  let answer: Uint8Array;
  try {
    // A certificate swapped on the server would make the reset lock the user out of
    // their own new mail: refuse instead.
    if (!keyMatchesCertificate(pkcs8, vault.certificatePem)) throw new Error('certificate');
    const key = await crypto.subtle.importKey(
      'pkcs8',
      pkcs8,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['decrypt'],
    );
    answer = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: 'RSA-OAEP', label: new TextEncoder().encode(CHALLENGE_LABEL) },
        key,
        fromB64(challenge),
      ),
    );
    if (answer.length !== 32) throw new Error('challenge');
  } catch {
    pkcs8.fill(0);
    return { ok: false, reason: 'failed' };
  }

  let spent = false;
  const wipe = () => {
    spent = true;
    pkcs8.fill(0);
    answer.fill(0);
  };
  return {
    ok: true,
    verified: {
      discard: wipe,
      async setPassword(newPassword) {
        if (spent) return { ok: false, reason: 'expired' };
        try {
          // Same Argon2id salt for the vault's whole life (lib/server/keys/login-mode.ts).
          const { update, loginKey } = await rewrapWithKeys(pkcs8, owner, newPassword, vault.kdf);
          const finishRes = await post('/api/auth/recover/finish', {
            email: owner,
            challengeId,
            answer: b64(answer),
            kdf: update.kdf,
            passwordSlot: update.passwordSlot,
            loginKey,
          });
          if (finishRes.ok) return { ok: true };
          if (finishRes.status === 429) return { ok: false, reason: 'rate_limited' };
          if (finishRes.status === 410) return { ok: false, reason: 'expired' };
          if (finishRes.status === 500) return { ok: false, reason: 'partial' };
          return { ok: false, reason: 'failed' };
        } catch {
          return { ok: false, reason: 'failed' };
        } finally {
          // The challenge is single use: success or not, this key copy is done.
          wipe();
        }
      },
    },
  };
}

/** Both steps at once (tests, scripts). */
export async function recoverWithPhrase(
  email: string,
  phrase: string,
  newPassword: string,
): Promise<RecoveryResult> {
  const check = await verifyRecoveryPhrase(email, phrase);
  if (!check.ok) return check;
  return check.verified.setPassword(newPassword);
}
