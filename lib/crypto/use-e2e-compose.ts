'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import { fetchVault, type VaultResponse } from './vault-client';
import { certificateFingerprint, lookupKeys } from './outgoing-mail';
import { checkPins, pinKeys } from './key-pins';
import { verifyAgainstLog } from './key-log';

/**
 * Whether the message being composed can go end-to-end encrypted. FAIL-CLOSED:
 * anything that is not a definite answer blocks sending and draft saving, so a
 * slow or failing lookup can never turn into a plaintext send.
 *
 *   unavailable — the server says definitely no vault (or no encryption engine):
 *                 the ordinary paths, exactly as before
 *   loading     — the sender's vault state is not known yet
 *   error       — vault or key lookup failed; nothing is sent or saved
 *   checking    — looking up the recipients' keys
 *   keyChanged  — a recipient's key differs from the one seen before (pinning)
 *   on          — every recipient has a MailDots key: the browser encrypts
 *   off         — the sender has a key, some recipient does not (or the message
 *                 carries server-side attachments); sending in the clear needs an
 *                 explicit confirmation
 * Whenever the sender has a key (`ownCert`), drafts are sealed to it.
 */
export type E2EState =
  | { status: 'unavailable' }
  | { status: 'loading' }
  | {
      status: 'error';
      reason: 'vault' | 'directory' | 'own_key' | 'transparency' | 'log_rewritten';
    }
  | { status: 'checking'; ownCert: string }
  | {
      status: 'keyChanged';
      ownCert: string;
      changed: string[];
      fingerprints: Record<string, string>;
    }
  | { status: 'on'; ownCert: string; owner: string; certs: Record<string, string> }
  | { status: 'off'; ownCert: string; missing: string[] };

const plainFetch = (input: string, init?: RequestInit) => fetch(input, init);

// One vault read per tab and minute: every compose / quick reply needs it.
let vaultCache: { at: number; value: Promise<VaultResponse> } | null = null;
function cachedVault(): Promise<VaultResponse> {
  if (!vaultCache || Date.now() - vaultCache.at > 60_000) {
    const value = fetchVault(plainFetch);
    vaultCache = { at: Date.now(), value };
    value.catch(() => {
      vaultCache = null;
    });
  }
  return vaultCache.value;
}

type Own =
  | { kind: 'loading' }
  | { kind: 'none' }
  | { kind: 'error'; reason: 'vault' | 'own_key' }
  | { kind: 'cert'; pem: string; owner: string };

export function useE2ECompose(
  recipients: string[],
  blocked: boolean,
  enabled = true,
): { state: E2EState; retry: () => void; trustChanged: () => void } {
  const [own, setOwn] = useState<Own>({ kind: 'loading' });
  const [attempt, setAttempt] = useState(0);
  const [lookup, setLookup] = useState<
    | { key: string; certs: Record<string, string>; fingerprints: Record<string, string> }
    | { key: string; error: true; transparency?: 'unverified' | 'rewritten' }
    | null
  >(null);

  useEffect(() => {
    if (!enabled) return;
    let active = true;
    cachedVault()
      .then((s) => {
        if (!active) return;
        if (!s.available || !s.vault) return setOwn({ kind: 'none' });
        // A vault whose key the mail server does not use (or uses another key for)
        // must not be encrypted to blindly: block until settings resolve it.
        if (!s.vault.encryptionEnabled || s.serverState === 'mismatch' || !s.owner) {
          return setOwn({ kind: 'error', reason: 'own_key' });
        }
        setOwn({ kind: 'cert', pem: s.vault.certificatePem, owner: s.owner });
      })
      .catch(() => active && setOwn({ kind: 'error', reason: 'vault' }));
    return () => {
      active = false;
    };
  }, [enabled, attempt]);

  const unique = useMemo(
    () => [...new Set(recipients.map((r) => r.trim().toLowerCase()).filter(Boolean))].sort(),
    [recipients],
  );
  const key = unique.join(',');
  const ownPem = own.kind === 'cert' ? own.pem : null;

  // Keyed by the sorted address list only (a new array every render must not refetch).
  useEffect(() => {
    const list = key ? key.split(',') : [];
    if (!enabled || !ownPem || list.length === 0) return;
    let active = true;
    const timer = setTimeout(() => {
      lookupKeys(plainFetch, list)
        .then(async (keys) => {
          if (!active) return;
          const certs: Record<string, string> = {};
          const fingerprints: Record<string, string> = {};
          for (const [addr, k] of Object.entries(keys)) {
            certs[addr] = k.certificatePem;
            fingerprints[addr] = await certificateFingerprint(k.certificatePem);
          }
          // T4: every served key must be the transparency log's current key for that
          // address. Otherwise nothing is encrypted to it (fail-closed).
          const kt = await verifyAgainstLog(plainFetch, fingerprints);
          if (!active) return;
          if (!kt.ok || kt.mismatched.length > 0) {
            const rewritten = !kt.ok && kt.reason === 'rewritten';
            setLookup({ key, error: true, transparency: rewritten ? 'rewritten' : 'unverified' });
            return;
          }
          setLookup({ key, certs, fingerprints });
        })
        .catch(() => active && setLookup({ key, error: true }));
    }, 400);
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [enabled, ownPem, key, attempt]);

  // Trust on first use: remember fingerprints seen for the first time (never
  // overwriting a different pinned one — that needs the user's confirmation).
  useEffect(() => {
    if (lookup && !('error' in lookup)) pinKeys(lookup.fingerprints, false);
  }, [lookup]);

  const retry = useCallback(() => {
    vaultCache = null;
    setLookup(null);
    setAttempt((n) => n + 1);
  }, []);

  const trustChanged = useCallback(() => {
    if (lookup && !('error' in lookup)) pinKeys(lookup.fingerprints, true);
    setAttempt((n) => n + 1);
  }, [lookup]);

  let state: E2EState;
  if (!enabled || own.kind === 'loading') state = { status: 'loading' };
  else if (own.kind === 'none') state = { status: 'unavailable' };
  else if (own.kind === 'error') state = { status: 'error', reason: own.reason };
  else if (blocked || unique.length === 0) state = { status: 'off', ownCert: own.pem, missing: [] };
  else if (!lookup || lookup.key !== key) state = { status: 'checking', ownCert: own.pem };
  else if ('error' in lookup) {
    state = {
      status: 'error',
      reason:
        lookup.transparency === 'rewritten'
          ? 'log_rewritten'
          : lookup.transparency
            ? 'transparency'
            : 'directory',
    };
  } else {
    const changed = checkPins(lookup.fingerprints);
    const missing = unique.filter((r) => !lookup.certs[r]);
    if (changed.length > 0) {
      state = {
        status: 'keyChanged',
        ownCert: own.pem,
        changed,
        fingerprints: lookup.fingerprints,
      };
    } else if (missing.length === 0) {
      state = { status: 'on', ownCert: own.pem, owner: own.owner, certs: lookup.certs };
    } else {
      state = { status: 'off', ownCert: own.pem, missing };
    }
  }
  return { state, retry, trustChanged };
}

/** Whether a send/draft decision can be made at all (fail-closed gate). */
export function e2eDecided(
  state: E2EState,
): state is Extract<E2EState, { status: 'unavailable' | 'on' | 'off' }> {
  return state.status === 'unavailable' || state.status === 'on' || state.status === 'off';
}
