'use client';

import { z } from 'zod';
import { LOGIN_MODES, vaultBundleSchema, type PasswordSlotUpdate } from './vault-schema';

/** GET /api/keys/vault, validated. `owner` is the session mailbox the vault is bound to. */
export const vaultResponseSchema = z.object({
  available: z.boolean(),
  setupEnabled: z.boolean().optional(),
  owner: z.string().optional(),
  serverState: z.enum(['ok', 'pending', 'mismatch', 'weakened', 'disabled', 'unknown']).optional(),
  /** T2: the owner knowingly went on without end-to-end encryption, and when. */
  onboarding: z
    .object({ status: z.literal('declined'), at: z.string() })
    .nullable()
    .optional(),
  vault: vaultBundleSchema
    .extend({
      fingerprint: z.string(),
      encryptionEnabled: z.boolean(),
      loginMode: z.enum(LOGIN_MODES).default('password'),
      createdAt: z.string(),
    })
    .nullable(),
});
export type VaultResponse = z.infer<typeof vaultResponseSchema>;

type Fetcher = (input: string, init?: RequestInit) => Promise<Response>;

export async function fetchVault(fetcher: Fetcher): Promise<VaultResponse> {
  const res = await fetcher('/api/keys/vault');
  if (!res.ok) throw new Error('vault_fetch_failed');
  const parsed = vaultResponseSchema.safeParse(await res.json());
  if (!parsed.success) throw new Error('vault_fetch_failed');
  return parsed.data;
}

/** What a password change sends. With login protection both secrets are login keys. */
export interface PreparedPasswordChange {
  target: 'password' | 'derived';
  currentSecret: string;
  newSecret: string;
  vault: PasswordSlotUpdate | null;
}

/**
 * For a password change, in the browser: re-wraps the private key under the new
 * password. With login protection the typed passwords are turned into login keys
 * here (same vault salt), so neither password reaches the server. Throws `locked`
 * when the current password does not open the key (the user must recover first).
 */
export async function preparePasswordChange(
  fetcher: Fetcher,
  currentPassword: string,
  newPassword: string,
): Promise<PreparedPasswordChange> {
  const state = await fetchVault(fetcher);
  if (!state.available || !state.vault || !state.owner) {
    return {
      target: 'password',
      currentSecret: currentPassword,
      newSecret: newPassword,
      vault: null,
    };
  }
  const vault = state.vault;
  const { derivePasswordKeys, rewrapForPassword, rewrapWithKeys, unlockWithLockKey } =
    await import('./vault');
  const current = await derivePasswordKeys(currentPassword, vault.kdf);
  let pkcs8: Uint8Array<ArrayBuffer>;
  try {
    pkcs8 = await unlockWithLockKey(vault, state.owner, current.lockKey);
  } catch {
    throw new Error('locked');
  }
  try {
    if (vault.loginMode === 'password') {
      return {
        target: 'password',
        currentSecret: currentPassword,
        newSecret: newPassword,
        vault: await rewrapForPassword(pkcs8, state.owner, newPassword),
      };
    }
    const next = await rewrapWithKeys(pkcs8, state.owner, newPassword, vault.kdf, vault.version);
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

/**
 * The secret to re-prove "the current password" to the server: the login key for
 * a protected mailbox (derived here), the password itself otherwise.
 */
export async function serverSecret(state: VaultResponse, password: string): Promise<string> {
  if (!state.vault || state.vault.loginMode === 'password') return password;
  const { deriveLoginKey } = await import('./vault');
  return deriveLoginKey(password, state.vault.kdf);
}
