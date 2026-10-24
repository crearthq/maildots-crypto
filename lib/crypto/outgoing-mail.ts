/**
 * End-to-end encrypted OUTGOING mail, built in the browser.
 *
 * The message body (text + HTML alternatives and attachments) is assembled here as
 * a MIME entity and encrypted to the recipients' and the sender's own S/MIME
 * certificates (RSA key transport + AES-256-CBC — what Outlook, Apple Mail and our
 * webmail all decrypt). Only the ciphertext goes to the server.
 */
import DOMPurify from 'dompurify';
import { z } from 'zod';
import forge from 'node-forge';
import { fromBinaryString, toBase64, toBinaryString } from './encoding';

export interface OutgoingAttachment {
  filename: string;
  contentType: string;
  contentBase64: string;
}

export { MAX_ENCRYPTED_ATTACHMENT_BYTES } from './limits';

const CRLF = '\r\n';
const SAFE_TYPE = /^[a-z0-9][a-z0-9!#$&^_.+-]*\/[a-z0-9][a-z0-9!#$&^_.+-]*$/i;

function boundary(tag: string): string {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(12));
  return `=_md_${tag}_${Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')}`;
}

/** Base64 folded at 76 characters (RFC 2045). */
function fold(b64: string): string {
  return (b64.match(/.{1,76}/g) ?? []).join(CRLF);
}

function utf8Base64(text: string): string {
  return fold(toBase64(new TextEncoder().encode(text)));
}

/** RFC 2231 parameter value for any filename (UTF-8, percent-encoded). */
function rfc2231(name: string): string {
  const clean = name.replace(/[\u0000-\u001f\u007f"\\]/g, '').slice(0, 255) || 'attachment';
  return (
    "UTF-8''" +
    encodeURIComponent(clean).replace(
      /['()*]/g,
      (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`,
    )
  );
}

/** Plain-text alternative of the composed HTML. */
export function htmlToText(html: string): string {
  const doc = new DOMParser().parseFromString(`<body>${html}</body>`, 'text/html');
  doc.querySelectorAll('br').forEach((br) => br.replaceWith('\n'));
  doc.querySelectorAll('p,div,li,tr,h1,h2,h3,h4,h5,h6,blockquote').forEach((el) => {
    el.append('\n');
  });
  return (doc.body.textContent ?? '').replace(/\n{3,}/g, '\n\n').trim();
}

/** The composer's HTML, sanitised before it is sealed (recipients sanitise again). */
function sanitizeComposed(html: string): string {
  return String(
    DOMPurify().sanitize(html, {
      FORBID_TAGS: ['script', 'style', 'iframe', 'object', 'embed', 'form', 'base', 'meta', 'link'],
      FORBID_ATTR: ['srcset', 'ping'],
    }),
  );
}

/** The inner MIME entity (canonical CRLF) that gets encrypted. */
export function buildMimeEntity(input: {
  html: string;
  attachments?: OutgoingAttachment[];
}): string {
  const html = sanitizeComposed(input.html);
  const text = htmlToText(html);
  const alt = boundary('alt');
  const alternative = [
    `Content-Type: multipart/alternative; boundary="${alt}"`,
    '',
    `--${alt}`,
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: base64',
    '',
    utf8Base64(text),
    `--${alt}`,
    'Content-Type: text/html; charset=utf-8',
    'Content-Transfer-Encoding: base64',
    '',
    utf8Base64(
      `<!doctype html><html><head><meta charset="utf-8"></head><body>${html}</body></html>`,
    ),
    `--${alt}--`,
    '',
  ].join(CRLF);
  const attachments = input.attachments ?? [];
  if (attachments.length === 0) return alternative;

  const mixed = boundary('mix');
  const parts = [
    `Content-Type: multipart/mixed; boundary="${mixed}"`,
    '',
    `--${mixed}`,
    alternative,
  ];
  for (const a of attachments) {
    const type = SAFE_TYPE.test(a.contentType)
      ? a.contentType.toLowerCase()
      : 'application/octet-stream';
    const name = rfc2231(a.filename);
    parts.push(
      `--${mixed}`,
      `Content-Type: ${type}; name*=${name}`,
      `Content-Disposition: attachment; filename*=${name}`,
      'Content-Transfer-Encoding: base64',
      '',
      fold(a.contentBase64.replace(/[^A-Za-z0-9+/=]/g, '')),
    );
  }
  parts.push(`--${mixed}--`, '');
  return parts.join(CRLF);
}

/**
 * S/MIME enveloped data of `entity` for every certificate (base64, no folding).
 * Each recipient can decrypt with their own key; nobody else can.
 */
export function encryptEntity(entity: string, certificatePems: string[]): string {
  if (certificatePems.length === 0) throw new Error('no_recipients');
  const p7 = forge.pkcs7.createEnvelopedData();
  for (const pem of certificatePems) p7.addRecipient(forge.pki.certificateFromPem(pem));
  p7.content = forge.util.createBuffer(toBinaryString(new TextEncoder().encode(entity)));
  p7.encrypt(undefined, forge.pki.oids['aes256-CBC']);
  return toBase64(fromBinaryString(forge.asn1.toDer(p7.toAsn1()).getBytes()));
}

export interface DirectoryKey {
  certificatePem: string;
  fingerprint: string;
}

type Fetcher = (input: string, init?: RequestInit) => Promise<Response>;

/** Certificates of the addresses that have MailDots encryption (missing = none). */
export async function lookupKeys(
  fetcher: Fetcher,
  addresses: string[],
): Promise<Record<string, DirectoryKey>> {
  const unique = [...new Set(addresses.map((a) => a.trim().toLowerCase()).filter(Boolean))];
  if (unique.length === 0) return {};
  const res = await fetcher('/api/keys/directory', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ addresses: unique.slice(0, 100) }),
  });
  if (!res.ok) throw new Error('directory_failed');
  const parsed = directoryResponseSchema.safeParse(await res.json().catch(() => null));
  if (!parsed.success) throw new Error('directory_failed');
  const out: Record<string, DirectoryKey> = {};
  for (const [addr, key] of Object.entries(parsed.data.keys)) {
    const address = addr.toLowerCase();
    if (unique.includes(address) && certificateIsFor(key.certificatePem, address)) {
      out[address] = key;
    }
  }
  return out;
}

const directoryResponseSchema = z.object({
  keys: z.record(
    z.string(),
    z.object({ certificatePem: z.string().max(8_000), fingerprint: z.string().max(200) }),
  ),
});

const EMAIL_PROTECTION = '1.3.6.1.5.5.7.3.4';

/**
 * A directory certificate is used only if it names exactly this address, is an RSA
 * key of 2048–4096 bits, is currently valid, may protect e-mail and is not a CA.
 */
export function certificateIsFor(
  certificatePem: string,
  address: string,
  now = new Date(),
): boolean {
  try {
    const cert = forge.pki.certificateFromPem(certificatePem);
    const san = cert.getExtension('subjectAltName') as {
      altNames?: Array<{ type: number; value: string }>;
    } | null;
    const emails = (san?.altNames ?? [])
      .filter((n) => n.type === 1)
      .map((n) => n.value.toLowerCase());
    const eku = cert.getExtension('extKeyUsage') as {
      emailProtection?: boolean;
      id?: string;
    } | null;
    const basic = cert.getExtension('basicConstraints') as { cA?: boolean } | null;
    const pub = cert.publicKey as forge.pki.rsa.PublicKey;
    const bits = pub?.n?.bitLength?.() ?? 0;
    return (
      emails.length === 1 &&
      emails[0] === address.toLowerCase() &&
      bits >= 2048 &&
      bits <= 4096 &&
      !basic?.cA &&
      Boolean(eku?.emailProtection || eku?.id === EMAIL_PROTECTION) &&
      cert.validity.notBefore <= new Date(now.getTime() + 48 * 3600 * 1000) &&
      cert.validity.notAfter > now
    );
  } catch {
    return false;
  }
}

/** SHA-256 of the certificate's DER, hex — recomputed here, never taken from the server. */
export async function certificateFingerprint(certificatePem: string): Promise<string> {
  const cert = forge.pki.certificateFromPem(certificatePem);
  const der = fromBinaryString(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes());
  const digest = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', der));
  return Array.from(digest, (b) => b.toString(16).padStart(2, '0')).join('');
}
