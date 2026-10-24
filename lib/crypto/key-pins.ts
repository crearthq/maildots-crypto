'use client';

/**
 * Trust-on-first-use pinning of recipients' certificates. The first fingerprint
 * seen for an address is remembered in this browser; a later, different one is
 * reported instead of being encrypted to silently — that is how a key swapped in
 * the server's directory (or database) becomes visible to the sender.
 *
 * Limit (by design): pinning protects against directory/database substitution,
 * not against a server that serves malicious JavaScript.
 */
const STORAGE_KEY = 'md:key-pins:v1';

function read(): Record<string, string> {
  try {
    const raw = globalThis.localStorage?.getItem(STORAGE_KEY);
    const parsed: unknown = raw ? JSON.parse(raw) : {};
    if (!parsed || typeof parsed !== 'object') return {};
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(parsed as Record<string, unknown>)) {
      if (typeof v === 'string' && /^[0-9a-f]{64}$/.test(v)) out[k] = v;
    }
    return out;
  } catch {
    return {};
  }
}

function write(pins: Record<string, string>): void {
  try {
    globalThis.localStorage?.setItem(STORAGE_KEY, JSON.stringify(pins));
  } catch {
    /* private mode / storage blocked: pinning is best-effort */
  }
}

/** Addresses whose current fingerprint differs from the pinned one. */
export function checkPins(current: Record<string, string>): string[] {
  const pins = read();
  return Object.entries(current)
    .filter(([addr, fp]) => pins[addr] !== undefined && pins[addr] !== fp)
    .map(([addr]) => addr);
}

/** Remembers fingerprints; `replace` also overwrites changed ones (user confirmed). */
export function pinKeys(current: Record<string, string>, replace: boolean): void {
  const pins = read();
  let dirty = false;
  for (const [addr, fp] of Object.entries(current)) {
    if (pins[addr] === fp) continue;
    if (pins[addr] !== undefined && !replace) continue;
    pins[addr] = fp;
    dirty = true;
  }
  if (dirty) write(pins);
}
