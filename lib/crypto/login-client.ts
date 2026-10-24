'use client';

import { preloginResponseSchema, type PreloginResponse } from './vault-schema';
import { fetchVault } from './vault-client';
import { setUnlockedKey } from './key-store';

/**
 * Sign-in with login protection, in the browser (Proton-style): the typed password
 * becomes a login key (sent) and a lock key (kept in this tab to open the vault).
 * For an ordinary mailbox the password is sent as typed, exactly as before.
 */
export type SignInSecret =
  | { kind: 'password'; password: string }
  | { kind: 'derived'; loginKey: string; lockKey: CryptoKey };

type Fetcher = (input: string, init?: RequestInit) => Promise<Response>;

export async function fetchPrelogin(
  email: string,
  fetcher: Fetcher = fetch,
): Promise<PreloginResponse> {
  const res = await fetcher('/api/auth/prelogin', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email }),
  });
  if (!res.ok) throw new Error('prelogin_failed');
  const parsed = preloginResponseSchema.safeParse(await res.json().catch(() => null));
  if (!parsed.success) throw new Error('prelogin_failed');
  return parsed.data;
}

// Mailboxes this browser has seen with login protection on. If the server later
// claims "plain password" for one of them, the password is NOT sent: a server that
// wants the password would do exactly that (downgrade). There is no honest reason
// left for it — protection cannot be turned off, and a forgotten password is reset
// with the recovery phrase (recovery-client.ts), never by an administrator.
const PROTECTED_KEY = 'md:login-protected:v1';

function readProtected(): string[] {
  try {
    const v: unknown = JSON.parse(localStorage.getItem(PROTECTED_KEY) ?? '[]');
    return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
  } catch {
    return [];
  }
}

function writeProtected(list: string[]): void {
  try {
    localStorage.setItem(PROTECTED_KEY, JSON.stringify(list.slice(-50)));
  } catch {
    /* private mode: the check is a best-effort extra */
  }
}

export function rememberProtected(email: string): void {
  const e = email.toLowerCase();
  const list = readProtected().filter((x) => x !== e);
  writeProtected([...list, e]);
}

export function wasProtected(email: string): boolean {
  return readProtected().includes(email.toLowerCase());
}

export type PreparedSignIn =
  | { kind: 'ready'; secret: SignInSecret }
  /**
   * The server asks for something the device refuses: the plain password for a
   * mailbox this browser knew as protected, or a weakened Argon2id cost.
   */
  | { kind: 'downgrade'; reason: 'plain' | 'weak_kdf' };

/**
 * Turns the typed password into what is sent. Never falls back to sending the
 * plain password when the discovery call fails (that would hand it to the server
 * exactly when login protection cannot be checked), and never sends it for a
 * mailbox this browser knew as protected.
 */
export async function prepareSignIn(email: string, password: string): Promise<PreparedSignIn> {
  const info = await fetchPrelogin(email);
  if (info.mode === 'derived') {
    const { derivePasswordKeys, meetsKdfFloor } = await import('./vault');
    if (!meetsKdfFloor(info.kdf)) return { kind: 'downgrade', reason: 'weak_kdf' };
    const keys = await derivePasswordKeys(password, info.kdf);
    return { kind: 'ready', secret: { kind: 'derived', ...keys } };
  }
  if (wasProtected(email)) return { kind: 'downgrade', reason: 'plain' };
  return { kind: 'ready', secret: { kind: 'password', password } };
}

/** The login request body for a prepared secret. */
export function signInBody(email: string, secret: SignInSecret, add: boolean) {
  return {
    email,
    ...(secret.kind === 'derived' ? { loginKey: secret.loginKey } : { password: secret.password }),
    ...(add ? { add: true } : {}),
  };
}

/**
 * After a protected sign-in: opens the vault with the lock key derived from the
 * same Argon2id run, so reading encrypted mail needs no second password prompt.
 * Best effort — on any problem the reader simply asks for the password later.
 */
export async function unlockAfterSignIn(email: string, lockKey: CryptoKey): Promise<void> {
  try {
    const state = await fetchVault(fetch);
    if (!state.vault || !state.owner || state.owner.toLowerCase() !== email.toLowerCase()) return;
    const { unlockWithLockKey, keyMatchesCertificate } = await import('./vault');
    const pkcs8 = await unlockWithLockKey(state.vault, state.owner, lockKey);
    if (!keyMatchesCertificate(pkcs8, state.vault.certificatePem)) {
      pkcs8.fill(0);
      return;
    }
    setUnlockedKey({ owner: state.owner, pkcs8, certificatePem: state.vault.certificatePem });
  } catch {
    /* the reader's unlock form takes over */
  }
}
