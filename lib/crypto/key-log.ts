'use client';

import {
  applyLogPage,
  EMPTY_KEY_LOG,
  KT_WITNESS_WINDOW,
  mismatchedKeys,
  witnessAgrees,
  type KeyLogPage,
  type KeyLogState,
} from './key-log-format';

/**
 * T4 — key transparency, browser side. Keeps the last verified head of the log in
 * this browser and, on every check, fetches only the new entries, verifies the hash
 * chain from that head (the log may only grow) and replays them. A key the server
 * hands out counts only if it is the log's current key for that address.
 */

const STORAGE_KEY = 'md:key-log:v1';

type State = KeyLogState;

function load(): State {
  try {
    const raw = globalThis.localStorage?.getItem(STORAGE_KEY);
    const v = raw ? (JSON.parse(raw) as State) : null;
    if (v && Number.isInteger(v.seq) && typeof v.hash === 'string' && v.keys) {
      // Heads saved before the witness window existed are trimmed once here.
      if (v.hashes) {
        for (const k of Object.keys(v.hashes)) {
          if (Number(k) <= v.seq - KT_WITNESS_WINDOW) delete v.hashes[k];
        }
      }
      return v;
    }
  } catch {
    /* fall through */
  }
  return EMPTY_KEY_LOG;
}

function save(state: State): void {
  try {
    globalThis.localStorage?.setItem(STORAGE_KEY, JSON.stringify(state));
  } catch {
    /* private mode: verified from the start next time */
  }
}

export type LogVerdict =
  | { ok: true; mismatched: string[] } // addresses whose served key is not the log's
  | { ok: false; reason: 'unavailable' | 'rewritten' };

type Fetcher = (input: string, init?: RequestInit) => Promise<Response>;

/** Brings this browser's verified state up to the log's head. */
async function advance(
  fetcher: Fetcher,
): Promise<{ ok: true; state: State } | { ok: false; reason: 'unavailable' | 'rewritten' }> {
  let state = load();
  for (let round = 0; round < 50; round++) {
    let page: KeyLogPage;
    try {
      // No cookies: the log is public, and the server should not learn who asks
      // (a server that knows the asker could show that one person another log).
      const res = await fetcher(`/api/keys/log?after=${state.seq}`, {
        cache: 'no-store',
        credentials: 'omit',
      });
      if (!res.ok) return { ok: false, reason: 'unavailable' };
      page = (await res.json()) as KeyLogPage;
    } catch {
      return { ok: false, reason: 'unavailable' };
    }
    const applied = await applyLogPage(state, page);
    if (!applied.ok) return { ok: false, reason: 'rewritten' };
    state = applied.state;
    save(state);
    if (applied.complete) return { ok: true, state };
  }
  return { ok: false, reason: 'unavailable' };
}

/** Checks served fingerprints (address -> fingerprint) against the transparency log. */
export async function verifyAgainstLog(
  fetcher: Fetcher,
  served: Record<string, string>,
): Promise<LogVerdict> {
  const r = await advance(fetcher);
  if (!r.ok) return r;
  return { ok: true, mismatched: await mismatchedKeys(r.state, served) };
}

/** The head this browser has verified (what a signed message carries as its witness). */
export async function verifiedHead(
  fetcher: Fetcher,
): Promise<{ seq: number; hash: string } | null> {
  const r = await advance(fetcher);
  if (r.ok) return { seq: r.state.seq, hash: r.state.hash };
  // Offline: the last head this browser verified is still a valid witness.
  const local = load();
  return r.reason === 'unavailable' && local.seq > 0 ? { seq: local.seq, hash: local.hash } : null;
}

/** Has this browser seen a key for this address in the verified log? (T4, local) */
export async function knownInLog(address: string): Promise<boolean> {
  const { addressHash } = await import('./key-log-format');
  return load().keys[await addressHash(address)] !== undefined;
}

/** Does a head reported by another user (inside their signed message) match this view? */
export async function checkWitness(
  fetcher: Fetcher,
  seq: number,
  hash: string,
): Promise<'agrees' | 'forked' | 'unknown'> {
  const verdict = witnessAgrees(load(), seq, hash);
  if (verdict !== 'unknown') return verdict;
  const r = await advance(fetcher);
  if (!r.ok) return r.reason === 'rewritten' ? 'forked' : 'unknown';
  // Fully up to date and still behind what the other user verified: the log only
  // grows, so my server is hiding entries from me — a fork.
  if (r.state.seq < seq) return 'forked';
  return witnessAgrees(r.state, seq, hash);
}
