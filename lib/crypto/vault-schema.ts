import { z } from 'zod';

/**
 * Wire format of a mailbox key vault (shared by browser and server).
 *
 * The server only ever stores the PUBLIC certificate and the private key wrapped
 * (AES-256-GCM) under keys it never sees: the lock key (Argon2id of the password)
 * and the recovery key (from the 24-word recovery phrase).
 */
export const VAULT_VERSION = 1;

const b64 = (min: number, max: number) =>
  z
    .string()
    .min(min)
    .max(max)
    .regex(/^[A-Za-z0-9+/]+={0,2}$/);

/** Argon2id cost bounds: strong enough to resist guessing, cheap enough for a phone. */
export const kdfParamsSchema = z.object({
  alg: z.literal('argon2id'),
  memoryKiB: z.number().int().min(19_456).max(262_144),
  iterations: z.number().int().min(2).max(10),
  parallelism: z.number().int().min(1).max(4),
  salt: b64(22, 44), // 16–32 bytes
});
export type KdfParams = z.infer<typeof kdfParamsSchema>;

export const wrappedKeySchema = z.object({
  iv: b64(16, 16), // 12 bytes
  ct: b64(1_000, 8_000), // AES-GCM(PKCS#8 RSA private key) + tag
});
export type WrappedKey = z.infer<typeof wrappedKeySchema>;

export const certificatePemSchema = z
  .string()
  .max(8_000)
  .regex(/^-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\r?\n?$/);

export const vaultBundleSchema = z.object({
  version: z.literal(VAULT_VERSION),
  certificatePem: certificatePemSchema,
  kdf: kdfParamsSchema,
  passwordSlot: wrappedKeySchema,
  recoverySlot: wrappedKeySchema,
});
export type VaultBundle = z.infer<typeof vaultBundleSchema>;

/** A new password wrapping of the same private key (password change / recovery). */
export const passwordSlotUpdateSchema = z.object({
  kdf: kdfParamsSchema,
  passwordSlot: wrappedKeySchema,
});
export type PasswordSlotUpdate = z.infer<typeof passwordSlotUpdateSchema>;

/**
 * Login protection: with `derived`, the mailbox's server secret is a login key
 * derived from the password in the browser/app (`md1_` + 32 bytes base64url), so
 * the password itself never reaches the server. `switching` is the short window
 * while that secret is being changed (resolved by the next successful sign-in).
 */
export const LOGIN_MODES = ['password', 'derived', 'switching'] as const;
export type LoginMode = (typeof LOGIN_MODES)[number];

export const loginKeySchema = z.string().regex(/^md1_[A-Za-z0-9_-]{43}$/);

export function isLoginKey(secret: string): boolean {
  return loginKeySchema.safeParse(secret).success;
}

/** POST /api/auth/prelogin answer: how to turn the typed password into a secret. */
export const preloginResponseSchema = z.discriminatedUnion('mode', [
  z.object({ mode: z.literal('password'), hosted: z.boolean() }),
  z.object({ mode: z.literal('derived'), hosted: z.literal(true), kdf: kdfParamsSchema }),
]);
export type PreloginResponse = z.infer<typeof preloginResponseSchema>;
