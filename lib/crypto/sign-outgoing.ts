'use client';

import { getUnlockedKeyFor } from './key-store';

/** The sender's key is locked: an end-to-end message is never sent unsigned (T4). */
export class SigningLockedError extends Error {
  constructor() {
    super('signing_locked');
  }
}

/**
 * T4: outgoing end-to-end mail is signed with the sender's own key, then encrypted.
 * From / To / Subject and the key-log head the sender verified go inside the signed
 * part. If the key is not unlocked in this tab the send stops (SigningLockedError):
 * an unsigned message would look like one from anybody.
 */
export async function signForSending(
  entity: string,
  ownCertificatePem: string,
  headers: { from: string; to: string[]; subject: string },
): Promise<string> {
  const key = getUnlockedKeyFor(ownCertificatePem);
  if (!key) throw new SigningLockedError();
  const [{ signEntity }, { verifiedHead }] = await Promise.all([
    import('./smime-sign'),
    import('./key-log'),
  ]);
  const keyLog = await verifiedHead((input, init) => fetch(input, init)).catch(() => null);
  return signEntity(entity, key.pkcs8, key.certificatePem, { ...headers, keyLog });
}
