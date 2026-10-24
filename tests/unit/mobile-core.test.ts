// @vitest-environment jsdom
import { beforeAll, describe, expect, it } from 'vitest';
import { installCore } from '@/lib/crypto/mobile-core';
import { createVault, type CreatedVault } from '@/lib/crypto/vault';

const EMAIL = 'ali@maildots.com';
const PASSWORD = 'Parola-mobil-2026';
let vault: CreatedVault;

type Core = { run(id: string, method: string, argsJson?: string): void };
const pending = new Map<string, (r: { ok: boolean; payload: unknown }) => void>();
const pulled = new Map<string, string>();
let seq = 0;

function call(
  method: string,
  args: unknown,
  pull = false,
): Promise<{ ok: boolean; payload: unknown }> {
  const id = String(++seq);
  return new Promise((resolve) => {
    pending.set(id, resolve);
    const core = (globalThis as unknown as { MailDotsCore: Core }).MailDotsCore;
    if (pull) {
      pulled.set(id, JSON.stringify(args));
      core.run(id, method);
    } else {
      core.run(id, method, JSON.stringify(args));
    }
  });
}

beforeAll(async () => {
  (globalThis as unknown as { MailDotsBridge: unknown }).MailDotsBridge = {
    args: (id: string) => pulled.get(id) ?? 'null',
    reply: (id: string, ok: boolean, payload: string) =>
      pending.get(id)?.({ ok, payload: JSON.parse(payload) }),
  };
  installCore();
  vault = await createVault(EMAIL, PASSWORD, { memoryKiB: 19_456, iterations: 2 });
}, 60_000);

describe('mobile crypto core (bridge protocol)', () => {
  it('derives the same login key as the browser and opens the vault with the raw lock key', async () => {
    const d = await call('deriveSecrets', { password: PASSWORD, kdf: vault.bundle.kdf });
    expect(d.ok).toBe(true);
    const secrets = d.payload as { loginKey: string; lockKey: string };
    expect(secrets.loginKey).toBe(vault.loginKey);
    const u = await call(
      'unlock',
      { bundle: vault.bundle, email: EMAIL, lockKey: secrets.lockKey },
      true,
    );
    expect(u.ok).toBe(true);
    expect((u.payload as { pkcs8: string }).pkcs8.length).toBeGreaterThan(1000);
  });

  it('a wrong password answers with a code only', async () => {
    const d = await call('deriveSecrets', { password: 'yanlis', kdf: vault.bundle.kdf });
    const lockKey = (d.payload as { lockKey: string }).lockKey;
    const u = await call('unlock', { bundle: vault.bundle, email: EMAIL, lockKey });
    expect(u).toEqual({ ok: false, payload: { error: 'unlock_failed' } });
  });

  it('encrypts to a certificate and decrypts it back (html + attachment), sanitised', async () => {
    const d = await call('deriveSecrets', { password: PASSWORD, kdf: vault.bundle.kdf });
    const lockKey = (d.payload as { lockKey: string }).lockKey;
    const pkcs8 = (
      (await call('unlock', { bundle: vault.bundle, email: EMAIL, lockKey })).payload as {
        pkcs8: string;
      }
    ).pkcs8;
    const check = await call('checkCertificate', {
      certificatePem: vault.bundle.certificatePem,
      address: EMAIL,
    });
    expect((check.payload as { ok: boolean }).ok).toBe(true);
    expect(
      (
        (
          await call('checkCertificate', {
            certificatePem: vault.bundle.certificatePem,
            address: 'x@y.com',
          })
        ).payload as { ok: boolean }
      ).ok,
    ).toBe(false);

    const enc = await call('encrypt', {
      html: '<p>Merhaba <b>dünya</b></p><script>alert(1)</script>',
      attachments: [
        { filename: 'not.txt', contentType: 'text/plain', contentBase64: btoa('ek icerik') },
      ],
      certificates: [vault.bundle.certificatePem],
    });
    expect(enc.ok).toBe(true);
    const ciphertext = (enc.payload as { ciphertext: string }).ciphertext;
    // What the mail server stores: headers + the S/MIME body.
    const raw =
      'From: ali@maildots.com\r\nTo: ali@maildots.com\r\nSubject: x\r\nMIME-Version: 1.0\r\n' +
      'Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name="smime.p7m"\r\n' +
      'Content-Transfer-Encoding: base64\r\n\r\n' +
      ciphertext.replace(/(.{76})/g, '$1\r\n') +
      '\r\n';
    const dec = await call(
      'decrypt',
      { raw: btoa(raw), pkcs8, certificatePem: vault.bundle.certificatePem },
      true,
    );
    expect(dec.payload).not.toHaveProperty('error');
    expect(dec.ok).toBe(true);
    const mail = dec.payload as {
      html: string;
      attachments: Array<{ filename: string; data: string }>;
    };
    expect(mail.html).toContain('dünya');
    expect(mail.html).not.toContain('script');
    expect(mail.attachments.map((a) => a.filename)).toEqual(['not.txt']);
    expect(atob(mail.attachments[0]!.data)).toBe('ek icerik');
  }, 30_000);

  it('prepares a protected password change: login keys only, same salt', async () => {
    const r = await call('passwordChange', {
      email: EMAIL,
      currentPassword: PASSWORD,
      newPassword: 'Yepyeni-parola-99',
      loginMode: 'derived',
      bundle: vault.bundle,
    });
    expect(r.ok).toBe(true);
    const p = r.payload as {
      target: string;
      currentSecret: string;
      newSecret: string;
      vault: { kdf: unknown };
    };
    expect(p.target).toBe('derived');
    expect(p.currentSecret).toBe(vault.loginKey);
    expect(p.newSecret).toMatch(/^md1_/);
    expect(p.vault.kdf).toEqual(vault.bundle.kdf);
    expect(JSON.stringify(p)).not.toContain('Yepyeni');
    const wrong = await call('passwordChange', {
      email: EMAIL,
      currentPassword: 'yanlis',
      newPassword: 'Yepyeni-parola-99',
      loginMode: 'derived',
      bundle: vault.bundle,
    });
    expect(wrong).toEqual({ ok: false, payload: { error: 'locked' } });
  });

  it('rejects unknown methods and malformed input', async () => {
    expect(await call('stealKeys', {})).toEqual({
      ok: false,
      payload: { error: 'unknown_method' },
    });
    expect(await call('decrypt', { raw: 1 })).toEqual({
      ok: false,
      payload: { error: 'invalid_input' },
    });
  });
});
