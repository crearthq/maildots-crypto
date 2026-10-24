import forge from 'node-forge';
import { beforeAll, describe, expect, it } from 'vitest';
import { createVault, unlockWithPassword } from '@/lib/crypto/vault';
import { openEncryptedMail, sanitizeDecryptedHtml } from '@/lib/crypto/decrypted-mail';
import { fromBinaryString } from '@/lib/crypto/encoding';

const EMAIL = 'ali@firma.com';
const PASSWORD = 'Parola-12345';
let certificatePem: string;
let pkcs8: Uint8Array<ArrayBuffer>;

beforeAll(async () => {
  const v = await createVault(EMAIL, PASSWORD, { memoryKiB: 19_456, iterations: 2 });
  certificatePem = v.bundle.certificatePem;
  pkcs8 = await unlockWithPassword(v.bundle, EMAIL, PASSWORD);
}, 60_000);

/** Outer S/MIME message (as Stalwart stores it) around `inner` (a MIME entity). */
function encrypt(inner: string): Uint8Array {
  const p7 = forge.pkcs7.createEnvelopedData();
  p7.addRecipient(forge.pki.certificateFromPem(certificatePem));
  p7.content = forge.util.createBuffer(forge.util.encodeUtf8(inner));
  p7.encrypt(undefined, forge.pki.oids['aes256-CBC']);
  const b64 = forge.util
    .encode64(forge.asn1.toDer(p7.toAsn1()).getBytes())
    .replace(/(.{76})/g, '$1\r\n');
  return fromBinaryString(
    'From: dis@ornek.com\r\nTo: ali@firma.com\r\nSubject: Gizli\r\nMIME-Version: 1.0\r\n' +
      'Content-Type: application/pkcs7-mime; name="smime.p7m"; smime-type=enveloped-data\r\n' +
      'Content-Transfer-Encoding: base64\r\n\r\n' +
      b64,
  );
}

// 1x1 transparent PNG
const PNG_B64 =
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=';

describe('sanitizeDecryptedHtml', () => {
  it('drops scripts, handlers, forms and remote content; resolves cid images', () => {
    const cid = new Map([['logo@x', 'data:image/png;base64,AAAA']]);
    const { html, usedCids, hadRemoteContent } = sanitizeDecryptedHtml(
      `<p onclick="x()">Merhaba <b>dünya</b></p>
       <script>alert(1)</script><style>p{}</style><form action="https://evil"><input></form>
       <img src="https://tracker.example/p.gif"><img src="cid:logo@x"><img src="cid:nope">
       <div style="background:url(https://evil/x)">a</div><a href="javascript:alert(1)">j</a>
       <a href="https://ornek.com">o</a><iframe src="https://evil"></iframe><svg><circle/></svg>`,
      cid,
    );
    expect(html).not.toMatch(/script|onclick|<style|<form|<input|iframe|<svg|javascript:/i);
    expect(html).not.toContain('tracker.example');
    expect(html).not.toContain('url(');
    expect(html).toContain('src="data:image/png;base64,AAAA"');
    expect(html).toContain('<b>dünya</b>');
    expect(html).toMatch(
      /<a href="https:\/\/ornek.com" target="_blank" rel="noopener noreferrer">/,
    );
    expect([...usedCids]).toEqual(['logo@x']);
    expect(hadRemoteContent).toBe(true);
  });
});

describe('sanitizeDecryptedHtml hardening', () => {
  it('drops obfuscated CSS fetches and unsafe links, keeps table layout', () => {
    const { html, hadRemoteContent } = sanitizeDecryptedHtml(
      `<div style="background-image:image-set('https://t.example/a' 1x)">a</div>
       <div style="background:u\\72l(https://t.example/b)">b</div>
       <div style="color:red">c</div>
       <a href="data:text/html,<script>1</script>">d</a><a href="vbscript:x">e</a>
       <table width="600" align="center" cellpadding="0" border="0"><tr><td colspan="2" valign="top">t</td></tr></table>`,
      new Map(),
    );
    expect(html).not.toContain('t.example');
    expect(html).toContain('style="color:red"');
    expect(html).not.toMatch(/href="(data|vbscript):/);
    expect(html).toContain('width="600"');
    expect(html).toContain('align="center"');
    expect(html).toContain('colspan="2"');
    expect(hadRemoteContent).toBe(true);
  });

  it('caps the inline image payload when one cid is referenced many times', () => {
    const big = 'data:image/png;base64,' + 'A'.repeat(1_000_000);
    const { html } = sanitizeDecryptedHtml('<img src="cid:x">'.repeat(30), new Map([['x', big]]));
    expect((html.match(/src="data:/g) ?? []).length).toBeLessThanOrEqual(8);
  });
});

describe('openEncryptedMail', () => {
  it('decrypts, parses and keeps body images out of the attachment list', async () => {
    const inner = [
      'Content-Type: multipart/mixed; boundary="M"',
      '',
      '--M',
      'Content-Type: multipart/related; boundary="R"',
      '',
      '--R',
      'Content-Type: text/html; charset=utf-8',
      '',
      '<p>Gizli rapor: ğüşıöç</p><img src="cid:logo@x"><script>alert(1)</script>',
      '--R',
      'Content-Type: image/png',
      'Content-ID: <logo@x>',
      'Content-Transfer-Encoding: base64',
      '',
      PNG_B64,
      '--R--',
      '--M',
      'Content-Type: text/html; name="sayfa.html"',
      'Content-Disposition: attachment; filename="sayfa.html"',
      '',
      '<script>alert(2)</script>',
      '--M--',
      '',
    ].join('\r\n');
    const mail = await openEncryptedMail(encrypt(inner), pkcs8, certificatePem);
    expect(mail.html).toContain('Gizli rapor: ğüşıöç');
    expect(mail.html).toContain('src="data:image/png;base64,');
    expect(mail.html).not.toContain('<script');
    expect(mail.attachments.map((a) => a.filename)).toEqual(['sayfa.html']);
    // An HTML attachment must never be openable as a page in our origin.
    expect(mail.attachments[0]?.blob.type).toBe('application/octet-stream');
    expect(mail.attachments[0]?.contentType).toBe('text/html');
  });

  it('renders a plain-text body escaped', async () => {
    const mail = await openEncryptedMail(
      encrypt('Content-Type: text/plain; charset=utf-8\r\n\r\n<b>etiket değil</b>\r\nikinci satır'),
      pkcs8,
      certificatePem,
    );
    expect(mail.html).toContain('&lt;b&gt;etiket değil&lt;/b&gt;');
    expect(mail.html).toContain('white-space:pre-wrap');
  });
});
