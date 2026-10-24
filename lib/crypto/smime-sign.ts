/**
 * T4 — S/MIME signatures (RFC 5751 / CMS, RFC 5652), in the browser and the apps'
 * crypto core. Outgoing end-to-end mail is SIGNED, then encrypted: the recipient
 * learns that the content comes from the holder of the sender's key and was not
 * changed (the encryption alone — AES-CBC — proves neither).
 *
 * node-forge signs PKCS#7 but cannot verify it, so verification is done here by
 * hand: the content's SHA-256 must equal the signed `messageDigest` attribute, and
 * the RSA signature (PKCS#1 v1.5, SHA-256) must hold over the DER of the signed
 * attributes, under the certificate inside the signature. WHO that certificate
 * belongs to is decided by the caller (MailDots directory + pinning, T4).
 */
import forge from 'node-forge';
import { fromBinaryString, toBase64, toBinaryString } from './encoding';

const CRLF = '\r\n';
const OID = forge.pki.oids;

function boundary(): string {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(12));
  return `=_md_sig_${Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')}`;
}

function fold(b64: string): string {
  return (b64.match(/.{1,76}/g) ?? []).join(CRLF);
}

/** CRLF line endings: the signed bytes must be the ones the receiver sees. */
function canonical(entity: string): string {
  return entity.replace(/\r?\n/g, CRLF);
}

/**
 * Headers copied INSIDE the signed part (RFC 7508 idea): the outer From / To /
 * Subject are written by the server and not covered by the signature; these are,
 * and the reader compares them with the outer ones. `keyLog` is the head of the key
 * transparency log the sender verified — a witness the reader checks its own view
 * against (split view).
 */
export interface ProtectedHeaders {
  from: string;
  to: string[];
  subject: string;
  keyLog?: { seq: number; hash: string } | null;
}

const ADDR = /^[^\s<>",;]+@[^\s<>",;]+$/;

/**
 * The one form a subject is signed and compared in: whitespace runs to one space,
 * trimmed, empty -> "(no subject)" (what the server shows for an empty subject),
 * at most 2000 UTF-16 units.
 */
export function normalizeSubject(subject: string): string {
  return (subject.replace(/\s+/g, ' ').trim() || '(no subject)').slice(0, 2000);
}

function encodeWord(text: string): string {
  // Always B-encoded UTF-8: one unambiguous form to compare.
  return `=?UTF-8?B?${toBase64(new TextEncoder().encode(text))}?=`;
}

function decodeWords(value: string): string {
  return value.replace(/=\?utf-8\?b\?([A-Za-z0-9+/=]*)\?=/gi, (_m, b64: string) => {
    try {
      return new TextDecoder().decode(fromBinaryString(forge.util.decode64(b64)));
    } catch {
      return '';
    }
  });
}

function protectedHeaderLines(h: ProtectedHeaders): string[] {
  const addrs = (list: string[]) =>
    list.map((a) => a.trim().toLowerCase()).filter((a) => ADDR.test(a));
  const lines = [
    `From: ${addrs([h.from])[0] ?? ''}`,
    `To: ${addrs(h.to).join(', ')}`,
    `Subject: ${encodeWord(normalizeSubject(h.subject))}`,
  ];
  if (h.keyLog && Number.isInteger(h.keyLog.seq) && /^[0-9a-f]{64}$/.test(h.keyLog.hash)) {
    lines.push(`X-MailDots-KeyLog: ${h.keyLog.seq} ${h.keyLog.hash}`);
  }
  return lines;
}

/**
 * Wraps a MIME entity in multipart/signed with a detached SHA-256 signature made
 * with the sender's own key (PKCS#8 DER) and certificate. With `headers`, From /
 * To / Subject and the sender's key-log head go inside the signed part.
 */
export function signEntity(
  entity: string,
  pkcs8: Uint8Array,
  certificatePem: string,
  headers?: ProtectedHeaders,
): string {
  const withHeaders = headers
    ? `${protectedHeaderLines(headers).join(CRLF)}${CRLF}${entity}`
    : entity;
  // Exactly the bytes the receiver reads back: the part ends before the CRLF that
  // precedes the next delimiter (RFC 1847), so a trailing CRLF is not signed.
  const content = canonical(withHeaders).replace(/(\r\n)+$/, '');
  const cert = forge.pki.certificateFromPem(certificatePem);
  const key = forge.pki.privateKeyFromAsn1(forge.asn1.fromDer(toBinaryString(pkcs8)));
  const p7 = forge.pkcs7.createSignedData();
  p7.content = forge.util.createBuffer(toBinaryString(new TextEncoder().encode(content)));
  p7.addCertificate(cert);
  p7.addSigner({
    key: key as forge.pki.rsa.PrivateKey,
    certificate: cert,
    digestAlgorithm: OID.sha256!,
    authenticatedAttributes: [
      { type: OID.contentType!, value: OID.data! },
      { type: OID.messageDigest! },
      { type: OID.signingTime!, value: new Date() as unknown as string },
    ],
  });
  p7.sign({ detached: true });
  const der = forge.asn1.toDer(p7.toAsn1()).getBytes();
  const b = boundary();
  return [
    `Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256; boundary="${b}"`,
    '',
    `--${b}`,
    content,
    `--${b}`,
    'Content-Type: application/pkcs7-signature; name="smime.p7s"',
    'Content-Transfer-Encoding: base64',
    'Content-Disposition: attachment; filename="smime.p7s"',
    '',
    fold(toBase64(fromBinaryString(der))),
    `--${b}--`,
    '',
  ].join(CRLF);
}

export type SignatureCheck =
  | { signed: false }
  | {
      signed: true;
      /** The signature is mathematically valid over exactly the signed part. */
      valid: boolean;
      /** Certificate inside the signature (who signed; trust is the caller's call). */
      signerCertificatePem: string | null;
      signerEmails: string[];
      /** SHA-256 of the signer certificate (DER), lowercase hex — as the directory reports. */
      signerFingerprint: string | null;
      signedAt: string | null;
      /** Headers inside the signed part (null when the sender put none there). */
      protected: ProtectedHeaders | null;
    };

export interface OpenedSigned {
  /** The entity to render: the signed part, or the input when not signed. */
  entity: Uint8Array;
  signature: SignatureCheck;
}

function headerBlock(text: string): { headers: string; body: string } {
  const m = text.match(/\r?\n\r?\n/);
  if (!m || m.index === undefined) return { headers: text, body: '' };
  return { headers: text.slice(0, m.index), body: text.slice(m.index + m[0].length) };
}

/**
 * If the decrypted entity is multipart/signed (top level only — never mixed with
 * other parts), checks the signature and returns the signed part to render.
 */
export function openSignedEntity(decrypted: Uint8Array): OpenedSigned {
  const text = toBinaryString(decrypted);
  const { headers, body } = headerBlock(text);
  const unfolded = headers.replace(/\r?\n[ \t]+/g, ' ');
  const type = /^content-type:\s*multipart\/signed\b([^\r\n]*)/im.exec(unfolded);
  if (!type) return { entity: decrypted, signature: { signed: false } };
  const params = type[1] ?? '';
  const b = /boundary\s*=\s*"?([^";]+)"?/i.exec(params)?.[1];
  if (!b || !/application\/(x-)?pkcs7-signature/i.test(params)) {
    return { entity: decrypted, signature: { signed: false } };
  }
  // The signed bytes are exactly between the first delimiter line and the CRLF that
  // precedes the next delimiter (RFC 1847). Delimiters only count at a line start.
  const delim = `--${b}`;
  const start = body.startsWith(delim) ? 0 : body.indexOf(`\r\n${delim}`) + 2;
  const firstEnd = start < 0 ? -1 : body.indexOf('\n', start);
  const next = firstEnd < 0 ? -1 : body.indexOf(`\r\n${delim}`, firstEnd);
  if (start < 2 && !body.startsWith(delim)) return { entity: decrypted, signature: invalid() };
  if (firstEnd < 0 || next < 0) {
    return { entity: decrypted, signature: invalid() };
  }
  const signedPart = body.slice(firstEnd + 1, next);
  const sigEnd = body.indexOf(`\r\n${delim}--`, next + 2);
  const sigPart = body.slice(next + 2 + delim.length, sigEnd < 0 ? undefined : sigEnd);
  const sigBody = headerBlock(sigPart.replace(/^\r?\n/, '')).body;
  const entity = fromBinaryString(signedPart);
  try {
    const der = forge.util.decode64(sigBody.replace(/[^A-Za-z0-9+/=]/g, ''));
    const check = verifyDetached(signedPart, der);
    return {
      entity,
      signature: check.signed ? { ...check, protected: readProtected(signedPart) } : check,
    };
  } catch {
    return { entity, signature: invalid() };
  }
}

/** The protected headers at the top of the signed part, if the sender put them there. */
function readProtected(signedPart: string): ProtectedHeaders | null {
  const { headers } = headerBlock(signedPart);
  const unfolded = headers.replace(/\r?\n[ \t]+/g, ' ');
  const get = (name: string) =>
    new RegExp(`^${name}:[ \\t]*([^\\r\\n]*)`, 'im').exec(unfolded)?.[1]?.trim() ?? null;
  const from = get('From');
  const subject = get('Subject');
  if (from === null || subject === null) return null;
  const to = (get('To') ?? '')
    .split(',')
    .map((a) => a.trim().toLowerCase())
    .filter(Boolean);
  const kl = /^(\d{1,9}) ([0-9a-f]{64})$/.exec(get('X-MailDots-KeyLog') ?? '');
  return {
    from: from.toLowerCase(),
    to,
    subject: decodeWords(subject),
    keyLog: kl ? { seq: Number(kl[1]), hash: kl[2]! } : null,
  };
}

function invalid(): SignatureCheck {
  return {
    signed: true,
    valid: false,
    signerCertificatePem: null,
    signerEmails: [],
    signerFingerprint: null,
    signedAt: null,
    protected: null,
  };
}

type Asn1 = forge.asn1.Asn1;
const kids = (n: Asn1 | undefined): Asn1[] => (Array.isArray(n?.value) ? (n.value as Asn1[]) : []);
const oidOf = (n: Asn1 | undefined) => forge.asn1.derToOid(String(n?.value ?? ''));

/** RFC 5652 SignedData, one signer, detached content `signed` (binary string). */
function verifyDetached(signed: string, der: string): SignatureCheck {
  const root = forge.asn1.fromDer(der);
  // ContentInfo ::= SEQUENCE { contentType, [0] EXPLICIT SignedData }
  const sd = kids(kids(root)[1])[0];
  const parts = kids(sd);
  // SignedData ::= SEQUENCE { version, digestAlgorithms, encapContentInfo,
  //                           [0] certificates OPTIONAL, [1] crls OPTIONAL, signerInfos }
  const certsNode = parts.find(
    (p) => p.tagClass === forge.asn1.Class.CONTEXT_SPECIFIC && p.type === 0,
  );
  const signerInfos = parts[parts.length - 1];
  const signer = kids(signerInfos)[0];
  const certs = kids(certsNode).map((c) => forge.pki.certificateFromAsn1(c));
  const cert = certs[0];
  if (!signer || !cert) return invalid();

  const si = kids(signer);
  // SignerInfo ::= SEQUENCE { version, sid, digestAlgorithm, [0] signedAttrs,
  //                           signatureAlgorithm, signature, ... }
  const digestAlg = oidOf(kids(si[2])[0]);
  const attrs = si[3];
  if (!attrs || attrs.tagClass !== forge.asn1.Class.CONTEXT_SPECIFIC || attrs.type !== 0) {
    return invalid();
  }
  const signature = String(si[5]?.value ?? '');
  if (digestAlg !== OID.sha256) return invalid();

  let messageDigest = '';
  let signedAt: string | null = null;
  let contentTypeOk = false;
  for (const attr of kids(attrs)) {
    const [t, set] = kids(attr);
    const type = oidOf(t);
    const v = kids(set)[0];
    if (type === OID.messageDigest) messageDigest = String(v?.value ?? '');
    if (type === OID.contentType) contentTypeOk = oidOf(v) === OID.data;
    if (type === OID.signingTime && v) {
      const raw = String(v.value);
      const d =
        v.type === forge.asn1.Type.UTCTIME
          ? forge.asn1.utcTimeToDate(raw)
          : forge.asn1.generalizedTimeToDate(raw);
      signedAt = Number.isFinite(d.getTime()) ? d.toISOString() : null;
    }
  }

  const md = forge.md.sha256.create();
  md.update(signed);
  const digestOk =
    contentTypeOk && messageDigest !== '' && md.digest().getBytes() === messageDigest;

  // The signature covers the DER of the signed attributes as a SET OF (tag 0x31).
  const asSet = forge.asn1.create(
    forge.asn1.Class.UNIVERSAL,
    forge.asn1.Type.SET,
    true,
    kids(attrs),
  );
  const attrsMd = forge.md.sha256.create();
  attrsMd.update(forge.asn1.toDer(asSet).getBytes());
  let sigOk = false;
  try {
    sigOk = (cert.publicKey as forge.pki.rsa.PublicKey).verify(
      attrsMd.digest().getBytes(),
      signature,
    );
  } catch {
    sigOk = false;
  }

  const san = cert.getExtension('subjectAltName') as {
    altNames?: Array<{ type: number; value: string }>;
  } | null;
  const certDer = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
  const fp = forge.md.sha256.create();
  fp.update(certDer);
  return {
    signed: true,
    valid: digestOk && sigOk,
    signerCertificatePem: forge.pki.certificateToPem(cert),
    signerEmails: (san?.altNames ?? [])
      .filter((n) => n.type === 1)
      .map((n) => n.value.toLowerCase()),
    signerFingerprint: fp.digest().toHex(),
    signedAt,
    protected: null,
  };
}
