// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { prepareSignIn, rememberProtected, signInBody } from '@/lib/crypto/login-client';
import { newKdfParams } from '@/lib/crypto/vault';

const EMAIL = 'ali@maildots.com';

function answer(body: unknown, status = 200) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => new Response(JSON.stringify(body), { status })),
  );
}

beforeEach(() => localStorage.clear());
afterEach(() => vi.unstubAllGlobals());

describe('browser sign-in with login protection', () => {
  it('sends the password as typed for an ordinary mailbox', async () => {
    answer({ mode: 'password', hosted: true });
    const p = await prepareSignIn(EMAIL, 'parola');
    expect(p).toEqual({ kind: 'ready', secret: { kind: 'password', password: 'parola' } });
    if (p.kind !== 'ready') throw new Error('expected ready');
    expect(signInBody(EMAIL, p.secret, false)).toEqual({
      email: EMAIL,
      password: 'parola',
    });
  });

  it('sends only a login key for a protected mailbox', async () => {
    answer({ mode: 'derived', hosted: true, kdf: newKdfParams() });
    const p = await prepareSignIn(EMAIL, 'parola');
    if (p.kind !== 'ready' || p.secret.kind !== 'derived') throw new Error('expected derived');
    const body = signInBody(EMAIL, p.secret, false);
    expect(body).not.toHaveProperty('password');
    expect(JSON.stringify(body)).not.toContain('parola');
    expect('loginKey' in body ? body.loginKey : '').toMatch(/^md1_[A-Za-z0-9_-]{43}$/);
  }, 30_000);

  it('refuses a weakened Argon2id cost handed out by the server', async () => {
    answer({
      mode: 'derived',
      hosted: true,
      kdf: newKdfParams({ memoryKiB: 19_456, iterations: 2 }),
    });
    expect(await prepareSignIn(EMAIL, 'parola')).toEqual({ kind: 'downgrade', reason: 'weak_kdf' });
  });

  it('never sends the plain password for a known protected mailbox, whatever the server says', async () => {
    rememberProtected(EMAIL);
    answer({ mode: 'password', hosted: true });
    expect(await prepareSignIn(EMAIL, 'parola')).toEqual({ kind: 'downgrade', reason: 'plain' });
    expect(await prepareSignIn(EMAIL, 'parola')).toEqual({ kind: 'downgrade', reason: 'plain' });
  });

  it('never falls back to the plain password when discovery fails', async () => {
    answer({ error: 'unavailable' }, 503);
    await expect(prepareSignIn(EMAIL, 'parola')).rejects.toThrow('prelogin_failed');
  });
});
