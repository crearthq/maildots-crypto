'use client';

import type { MessageDetail } from '@/lib/server/adapters/imap/types';

/**
 * Sanitised bodies of messages decrypted in THIS tab, so a reply or forward can
 * quote them (the server only has ciphertext). Memory only; cleared when the key
 * is locked.
 */
const MAX_ENTRIES = 50;
const cache = new Map<string, string>();
const keyOf = (folder: string, uid: number) => `${folder}\u0000${uid}`;

export function rememberDecrypted(folder: string, uid: number, html: string): void {
  cache.delete(keyOf(folder, uid));
  cache.set(keyOf(folder, uid), html);
  while (cache.size > MAX_ENTRIES) cache.delete(cache.keys().next().value as string);
}

export function clearDecrypted(): void {
  cache.clear();
}

/** The detail with its decrypted body filled in when this tab has opened it. */
export function withDecryptedBody(detail: MessageDetail, folder: string): MessageDetail {
  if (!detail.encrypted) return detail;
  return { ...detail, html: cache.get(keyOf(folder, detail.uid)) ?? '' };
}
