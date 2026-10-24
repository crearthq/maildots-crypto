// @vitest-environment jsdom
import { beforeAll, describe, expect, it } from 'vitest';
import { createVault, unlockWithPassword } from '@/lib/crypto/vault';
import { buildMimeEntity, certificateFingerprint, encryptEntity } from '@/lib/crypto/outgoing-mail';
import { openSignedEntity, signEntity } from '@/lib/crypto/smime-sign';
import { decryptSmimeMessage } from '@/lib/crypto/smime';

const ALI = 'ali@maildots.com';
const CHEAP = { memoryKiB: 19_456, iterations: 2 };
let ali: { pkcs8: Uint8Array; cert: string };
let mallory: { pkcs8: Uint8Array; cert: string };

beforeAll(async () => {
  const a = await createVault(ALI, 'Ali-parola-2026', CHEAP);
  ali = {
    pkcs8: await unlockWithPassword(a.bundle, ALI, 'Ali-parola-2026'),
    cert: a.bundle.certificatePem,
  };
  const m = await createVault(ALI, 'Sahte-parola-2026', CHEAP); // same address, another key
  mallory = {
    pkcs8: await unlockWithPassword(m.bundle, ALI, 'Sahte-parola-2026'),
    cert: m.bundle.certificatePem,
  };
}, 120_000);

const bytes = (s: string) => new TextEncoder().encode(s);

describe('S/MIME sign-then-encrypt (T4)', () => {
  it('signs, survives encryption, and verifies with the signer certificate and time', async () => {
    const entity = buildMimeEntity({ html: '<p>Merhaba, teklif ektedir.</p>' });
    const signed = signEntity(entity, ali.pkcs8, ali.cert);
    const ciphertext = encryptEntity(signed, [ali.cert]);
    const raw = bytes(
      `From: ${ALI}\r\nContent-Type: application/pkcs7-mime; smime-type=enveloped-data\r\nContent-Transfer-Encoding: base64\r\n\r\n${ciphertext}`,
    );
    const opened = openSignedEntity(decryptSmimeMessage(raw, ali.pkcs8, ali.cert));
    expect(opened.signature).toMatchObject({ signed: true, valid: true, signerEmails: [ALI] });
    if (!opened.signature.signed) throw new Error('signed');
    expect(opened.signature.signerFingerprint).toBe(await certificateFingerprint(ali.cert));
    expect(Date.now() - Date.parse(opened.signature.signedAt!)).toBeLessThan(60_000);
    // What is rendered is exactly the signed part.
    expect(new TextDecoder().decode(opened.entity)).toContain('multipart/alternative');
  });

  it('a changed body breaks the signature', () => {
    const signed = signEntity(
      buildMimeEntity({ html: '<p>Tutar: 100 TL</p>' }),
      ali.pkcs8,
      ali.cert,
    );
    // Swap one base64 character of the HTML part (the content an attacker would alter).
    const tampered = signed.replace(
      /(text\/html; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n)(.)/,
      (_m, h: string, c: string) => h + (c === 'P' ? 'Q' : 'P'),
    );
    expect(tampered).not.toBe(signed);
    const opened = openSignedEntity(bytes(tampered));
    expect(opened.signature).toMatchObject({ signed: true, valid: false });
  });

  it('a signature made with another key for the same address is valid math, but another fingerprint', async () => {
    const signed = signEntity(
      buildMimeEntity({ html: '<p>Ben Ali</p>' }),
      mallory.pkcs8,
      mallory.cert,
    );
    const opened = openSignedEntity(bytes(signed));
    if (!opened.signature.signed) throw new Error('signed');
    expect(opened.signature.valid).toBe(true);
    // The caller compares this with the directory / pinned key and rejects it.
    expect(opened.signature.signerFingerprint).not.toBe(await certificateFingerprint(ali.cert));
  });

  it('an unsigned entity is reported as unsigned and passed through', () => {
    const entity = buildMimeEntity({ html: '<p>imzasız</p>' });
    const opened = openSignedEntity(bytes(entity));
    expect(opened.signature).toEqual({ signed: false });
    expect(new TextDecoder().decode(opened.entity)).toBe(entity);
  });

  it('a broken signature blob is invalid, not a crash', () => {
    const signed = signEntity(buildMimeEntity({ html: '<p>x</p>' }), ali.pkcs8, ali.cert);
    const broken = signed.replace(
      /(smime\.p7s"\r\n\r\n)[A-Za-z0-9+/]{20}/,
      '$1AAAAAAAAAAAAAAAAAAAA',
    );
    expect(openSignedEntity(bytes(broken)).signature).toMatchObject({ signed: true, valid: false });
  });
});
