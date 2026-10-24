import PostalMime from 'postal-mime';
import { beforeAll, describe, expect, it } from 'vitest';
import { createVault, unlockWithPassword, type CreatedVault } from '@/lib/crypto/vault';
import { decryptSmimeMessage } from '@/lib/crypto/smime';
import { fromBase64, fromBinaryString, toBase64 } from '@/lib/crypto/encoding';
import {
  buildMimeEntity,
  certificateIsFor,
  encryptEntity,
  htmlToText,
} from '@/lib/crypto/outgoing-mail';
import { openEncryptedDraft } from '@/lib/crypto/open-draft';

const CHEAP = { memoryKiB: 19_456, iterations: 2 };
let ali: CreatedVault;
let veli: CreatedVault;
let ayse: CreatedVault;

beforeAll(async () => {
  [ali, veli, ayse] = await Promise.all([
    createVault('ali@firma.com', 'Parola-12345', CHEAP),
    createVault('veli@firma.com', 'Parola-12345', CHEAP),
    createVault('ayse@firma.com', 'Parola-12345', CHEAP),
  ]);
}, 90_000);

/** What Stalwart stores: outer headers around the browser's ciphertext. */
function asStored(ciphertextB64: string): Uint8Array {
  return fromBinaryString(
    'From: ali@firma.com\r\nTo: veli@firma.com\r\nSubject: x\r\n' +
      'Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name="smime.p7m"\r\n' +
      'Content-Transfer-Encoding: base64\r\n\r\n' +
      (ciphertextB64.match(/.{1,76}/g) ?? []).join('\r\n'),
  );
}

describe('end-to-end outgoing mail', () => {
  const attachment = {
    filename: 'Rapor ğüş (1).txt',
    contentType: 'text/plain',
    contentBase64: toBase64(new TextEncoder().encode('ek içeriği')),
  };

  it('is readable by every recipient and the sender, with text, html and attachments', async () => {
    const entity = buildMimeEntity({
      html: '<p>Merhaba <b>Veli</b>, rapor ekte.</p><script>alert(1)</script>',
      attachments: [attachment],
    });
    expect(entity).not.toContain('\n\n'); // canonical CRLF only
    const ct = encryptEntity(entity, [veli.bundle.certificatePem, ali.bundle.certificatePem]);

    for (const [v, email] of [
      [veli, 'veli@firma.com'],
      [ali, 'ali@firma.com'],
    ] as const) {
      const key = await unlockWithPassword(v.bundle, email, 'Parola-12345');
      const inner = decryptSmimeMessage(asStored(ct), key, v.bundle.certificatePem);
      const parsed = await PostalMime.parse(inner);
      expect(parsed.html).toContain('Merhaba <b>Veli</b>');
      expect(parsed.html).not.toContain('<script');
      expect(parsed.text).toContain('Merhaba Veli, rapor ekte.');
      expect(parsed.attachments.map((a) => a.filename)).toEqual(['Rapor ğüş (1).txt']);
    }

    const outsider = await unlockWithPassword(ayse.bundle, 'ayse@firma.com', 'Parola-12345');
    expect(() => decryptSmimeMessage(asStored(ct), outsider, ayse.bundle.certificatePem)).toThrow(
      'not_for_this_key',
    );
  }, 60_000);

  it('reopens an encrypted draft with its body and attachments', async () => {
    const entity = buildMimeEntity({
      html: '<p>Yarım kalan taslak</p>',
      attachments: [attachment],
    });
    const ct = encryptEntity(entity, [ali.bundle.certificatePem]);
    const key = await unlockWithPassword(ali.bundle, 'ali@firma.com', 'Parola-12345');
    const draft = await openEncryptedDraft(asStored(ct), key, ali.bundle.certificatePem);
    expect(draft.html).toContain('Yarım kalan taslak');
    expect(draft.attachments).toHaveLength(1);
    expect(draft.attachments[0]?.filename).toBe('Rapor ğüş (1).txt');
    expect(new TextDecoder().decode(fromBase64(draft.attachments[0]!.contentBase64))).toBe(
      'ek içeriği',
    );
  }, 60_000);

  it('only trusts a directory certificate that names exactly the address', () => {
    expect(certificateIsFor(veli.bundle.certificatePem, 'Veli@Firma.com')).toBe(true);
    expect(certificateIsFor(veli.bundle.certificatePem, 'ali@firma.com')).toBe(false);
    expect(certificateIsFor('garbage', 'veli@firma.com')).toBe(false);
  });

  it('derives a readable plain-text alternative', () => {
    expect(htmlToText('<p>Bir</p><p>İki<br>Üç</p>')).toBe('Bir\nİki\nÜç');
  });
});
