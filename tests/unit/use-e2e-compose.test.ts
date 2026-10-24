import { renderHook, waitFor } from '@testing-library/react';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createVault, type CreatedVault } from '@/lib/crypto/vault';
import { certificateFingerprint } from '@/lib/crypto/outgoing-mail';
import {
  addressHash,
  entryHash,
  KT_GENESIS,
  type KeyLogEntryWire,
} from '@/lib/crypto/key-log-format';

// A key transparency log the fake server keeps (T4).
let ktLog: KeyLogEntryWire[] = [];
async function logKey(address: string, pem: string) {
  const prev = ktLog.at(-1);
  const e = {
    seq: (prev?.seq ?? 0) + 1,
    addressHash: await addressHash(address),
    fingerprint: await certificateFingerprint(pem),
    action: 'add' as const,
    at: new Date().toISOString(),
    prevHash: prev?.hash ?? KT_GENESIS,
  };
  ktLog.push({ ...e, hash: await entryHash(e) });
}
function logResponse(url: string) {
  const after = Number(new URL(url, 'https://x').searchParams.get('after'));
  const last = ktLog.at(-1);
  return new Response(
    JSON.stringify({
      entries: ktLog.filter((e) => e.seq > after),
      head: { seq: last?.seq ?? 0, hash: last?.hash ?? KT_GENESIS },
    }),
  );
}

let me: CreatedVault;
let bob: CreatedVault;
let bob2: CreatedVault;

beforeAll(async () => {
  const cheap = { memoryKiB: 19_456, iterations: 2 };
  [me, bob, bob2] = await Promise.all([
    createVault('me@maildots.com', 'Parola-12345', cheap),
    createVault('bob@maildots.com', 'Parola-12345', cheap),
    createVault('bob@maildots.com', 'Parola-12345', cheap),
  ]);
}, 90_000);

function vaultResponse() {
  return {
    available: true,
    setupEnabled: false,
    owner: 'me@maildots.com',
    serverState: 'ok',
    vault: {
      ...me.bundle,
      fingerprint: 'x',
      encryptionEnabled: true,
      createdAt: new Date().toISOString(),
    },
  };
}

beforeEach(() => {
  localStorage.clear();
  ktLog = [];
  vi.resetModules(); // fresh tab-level vault cache per test
});
afterEach(() => vi.unstubAllGlobals());

async function load() {
  return (await import('@/lib/crypto/use-e2e-compose')).useE2ECompose;
}

describe('useE2ECompose is fail-closed', () => {
  it('refuses a key the transparency log does not hold (T4)', async () => {
    await logKey('bob@maildots.com', bob.bundle.certificatePem);
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) =>
        url === '/api/keys/vault'
          ? new Response(JSON.stringify(vaultResponse()))
          : url.startsWith('/api/keys/log')
            ? logResponse(url)
            : new Response(
                JSON.stringify({
                  // a swapped key the server did not log
                  keys: {
                    'bob@maildots.com': {
                      certificatePem: bob2.bundle.certificatePem,
                      fingerprint: 'x',
                    },
                  },
                }),
              ),
      ),
    );
    const useE2E = await load();
    const hook = renderHook(() => useE2E(['bob@maildots.com'], false));
    await waitFor(
      () =>
        expect(hook.result.current.state).toMatchObject({
          status: 'error',
          reason: 'transparency',
        }),
      { timeout: 3000 },
    );
  });

  it('is "loading" (never "unavailable") while the vault answer is pending', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => new Promise<Response>(() => {})),
    );
    const useE2E = await load();
    const { result } = renderHook(() => useE2E(['bob@maildots.com'], false));
    expect(result.current.state.status).toBe('loading');
  });

  it('is "error" when the vault cannot be read', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('boom', { status: 500 })),
    );
    const useE2E = await load();
    const { result } = renderHook(() => useE2E(['bob@maildots.com'], false));
    await waitFor(() => expect(result.current.state.status).toBe('error'));
  });

  it('is "error", not "off", when the key directory fails', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) =>
        url === '/api/keys/vault'
          ? new Response(JSON.stringify(vaultResponse()))
          : new Response('rate limited', { status: 429 }),
      ),
    );
    const useE2E = await load();
    const { result } = renderHook(() => useE2E(['bob@maildots.com'], false));
    await waitFor(() => expect(result.current.state.status).toBe('error'), { timeout: 3000 });
  });

  it('turns on with keys, and reports a later different key as "keyChanged"', async () => {
    let bobPem = bob.bundle.certificatePem;
    await logKey('bob@maildots.com', bobPem);
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) =>
        url === '/api/keys/vault'
          ? new Response(JSON.stringify(vaultResponse()))
          : url.startsWith('/api/keys/log')
            ? logResponse(url)
            : new Response(
                JSON.stringify({
                  keys: { 'bob@maildots.com': { certificatePem: bobPem, fingerprint: 'x' } },
                }),
              ),
      ),
    );
    const useE2E = await load();
    const first = renderHook(() => useE2E(['bob@maildots.com'], false));
    await waitFor(() => expect(first.result.current.state.status).toBe('on'), { timeout: 3000 });
    first.unmount();

    bobPem = bob2.bundle.certificatePem; // the directory now serves another key for bob
    await logKey('bob@maildots.com', bobPem); // …and logged it (honest server)
    const second = renderHook(() => useE2E(['bob@maildots.com'], false));
    await waitFor(() => expect(second.result.current.state.status).toBe('keyChanged'), {
      timeout: 3000,
    });
  });
});
