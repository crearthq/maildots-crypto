'use client';

import { useSyncExternalStore } from 'react';
import { clearDecrypted } from './decrypted-cache';

/**
 * The unlocked private key, held ONLY in this tab's memory (never in storage, never
 * sent anywhere). Reloading or closing the tab locks the mailbox again; signing out
 * navigates away and drops it with the page.
 */
interface Unlocked {
  owner: string;
  pkcs8: Uint8Array<ArrayBuffer>;
  certificatePem: string;
}

let unlocked: Unlocked | null = null;
const listeners = new Set<() => void>();

function emit() {
  for (const l of listeners) l();
}

export function setUnlockedKey(value: Unlocked): void {
  if (unlocked && unlocked.owner.toLowerCase() !== value.owner.toLowerCase()) clearDecrypted();
  if (unlocked) unlocked.pkcs8.fill(0);
  unlocked = value;
  emit();
}

export function getUnlockedKey(owner: string): Unlocked | null {
  return unlocked && unlocked.owner.toLowerCase() === owner.toLowerCase() ? unlocked : null;
}

/** The unlocked key, if it is the one behind this certificate (the sender's own, T4). */
export function getUnlockedKeyFor(certificatePem: string): Unlocked | null {
  const norm = (pem: string) => pem.replace(/\s+/g, '');
  return unlocked && norm(unlocked.certificatePem) === norm(certificatePem) ? unlocked : null;
}

export function lockKey(): void {
  if (unlocked) unlocked.pkcs8.fill(0);
  unlocked = null;
  clearDecrypted(); // decrypted bodies kept for quoting go with the key
  emit();
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/** Re-renders when the key is unlocked or locked; returns the unlocked owner, if any. */
export function useUnlockedOwner(): string | null {
  return useSyncExternalStore(
    subscribe,
    () => unlocked?.owner ?? null,
    () => null,
  );
}
