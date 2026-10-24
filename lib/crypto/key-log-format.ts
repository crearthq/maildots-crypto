/**
 * T4 — key transparency log format, shared by the server, the webmail and the apps.
 *
 *   addressHash = sha256hex("maildots/kt/v1|" + lowercase address)
 *   hash        = sha256hex(prevHash | seq | addressHash | fingerprint | action | at)
 *   genesis prevHash = 64 zeros
 *
 * `fingerprint` is the SHA-256 of the certificate DER (lowercase hex), "" on remove.
 * `at` is an ISO timestamp with milliseconds.
 */

export const KT_GENESIS = '0'.repeat(64);
export const KT_ADDRESS_PREFIX = 'maildots/kt/v1|';

export interface KeyLogEntryWire {
  seq: number;
  addressHash: string;
  fingerprint: string;
  action: 'add' | 'remove';
  at: string;
  prevHash: string;
  hash: string;
}

export function entryPreimage(e: Omit<KeyLogEntryWire, 'hash'>): string {
  return [e.prevHash, e.seq, e.addressHash, e.fingerprint, e.action, e.at].join('|');
}

async function sha256hex(text: string): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}

export function addressHash(address: string): Promise<string> {
  return sha256hex(KT_ADDRESS_PREFIX + address.trim().toLowerCase());
}

export function entryHash(e: Omit<KeyLogEntryWire, 'hash'>): Promise<string> {
  return sha256hex(entryPreimage(e));
}

/**
 * What a client has verified so far: the head, every address's current key, and the
 * hash at every seq it saw — so a head another user reports (inside a signed
 * message) can be compared with this client's own view (split-view witness).
 */
export interface KeyLogState {
  seq: number;
  hash: string;
  keys: Record<string, string>; // addressHash -> fingerprint
  hashes?: Record<string, string>; // seq -> hash
}

/** How many past heads this client keeps to check other users' heads against. */
export const KT_WITNESS_WINDOW = 5000;

export const EMPTY_KEY_LOG: KeyLogState = { seq: 0, hash: KT_GENESIS, keys: {}, hashes: {} };

export interface KeyLogPage {
  entries: KeyLogEntryWire[];
  head: { seq: number; hash: string };
}

const HEX64 = /^[0-9a-f]{64}$/;

function wellFormed(e: KeyLogEntryWire): boolean {
  return (
    Number.isInteger(e?.seq) &&
    HEX64.test(e.addressHash) &&
    HEX64.test(e.prevHash) &&
    HEX64.test(e.hash) &&
    (e.action === 'add'
      ? HEX64.test(e.fingerprint)
      : e.action === 'remove' && e.fingerprint === '') &&
    typeof e.at === 'string' &&
    e.at.length <= 40
  );
}

/**
 * Applies one page of entries to a verified state. The log may only grow: the page
 * must chain from the state's head, every entry must be well formed and its hash
 * recompute, and a head behind the state is a rewrite. `complete` = the state
 * reached the page's head.
 */
export async function applyLogPage(
  state: KeyLogState,
  page: KeyLogPage,
): Promise<{ ok: true; state: KeyLogState; complete: boolean } | { ok: false }> {
  if (!Number.isInteger(page.head?.seq) || page.head.seq < state.seq) return { ok: false };
  const next: KeyLogState = {
    seq: state.seq,
    hash: state.hash,
    keys: { ...state.keys },
    hashes: { ...(state.hashes ?? {}) },
  };
  for (const e of page.entries ?? []) {
    if (!wellFormed(e) || e.seq !== next.seq + 1 || e.prevHash !== next.hash) return { ok: false };
    const { hash, ...rest } = e;
    if ((await entryHash(rest)) !== hash) return { ok: false };
    if (e.action === 'add') next.keys[e.addressHash] = e.fingerprint;
    else delete next.keys[e.addressHash];
    next.seq = e.seq;
    next.hash = e.hash;
    next.hashes![String(e.seq)] = e.hash;
    // Bounded: witnesses are recent heads; an older one reads as "unknown", not red.
    delete next.hashes![String(e.seq - KT_WITNESS_WINDOW)];
  }
  if (next.seq === page.head.seq) {
    return next.hash === page.head.hash ? { ok: true, state: next, complete: true } : { ok: false };
  }
  // Behind the head but nothing new: the server withholds entries.
  if ((page.entries ?? []).length === 0) return { ok: false };
  return { ok: true, state: next, complete: false };
}

/** Addresses whose served fingerprint is not the log's current key. */
export async function mismatchedKeys(
  state: KeyLogState,
  served: Record<string, string>,
): Promise<string[]> {
  const out: string[] = [];
  for (const [address, fp] of Object.entries(served)) {
    if (state.keys[await addressHash(address)] !== fp) out.push(address);
  }
  return out;
}

/**
 * Split-view witness: does a head another client saw (seq, hash) agree with this
 * state? `unknown` = this state has not reached that seq yet.
 */
export function witnessAgrees(
  state: KeyLogState,
  seq: number,
  hash: string,
): 'agrees' | 'forked' | 'unknown' {
  if (seq === 0) return hash === KT_GENESIS ? 'agrees' : 'forked';
  const mine = state.hashes?.[String(seq)];
  if (mine === undefined) return 'unknown';
  return mine === hash ? 'agrees' : 'forked';
}
