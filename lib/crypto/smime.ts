/**
 * S/MIME enveloped-data decryption — BROWSER side (the server never holds the key).
 *
 * Stalwart encrypts at rest with RSA (PKCS#1 v1.5) key transport + AES-CBC
 * content encryption, which WebCrypto cannot unwrap; node-forge does both.
 */
import forge from 'node-forge';
import { fromBinaryString, toBinaryString } from './encoding';

export class SmimeError extends Error {
  constructor(readonly code: 'not_encrypted' | 'not_for_this_key' | 'decrypt_failed') {
    super(code);
  }
}

const ENCRYPTED_TYPE = /^content-type:\s*application\/(?:x-)?pkcs7-mime\b/im;

/** Splits a raw RFC 822 message into its header block and body. */
function splitMessage(raw: string): { headers: string; body: string } {
  const m = raw.match(/\r?\n\r?\n/);
  if (!m || m.index === undefined) return { headers: raw, body: '' };
  return { headers: raw.slice(0, m.index), body: raw.slice(m.index + m[0].length) };
}

/**
 * Decrypts an S/MIME enveloped message and returns the inner MIME entity (its own
 * Content-Type, body and attachments). Outer headers (From/To/Subject/Date) are
 * not encrypted by S/MIME and stay with the caller.
 */
export function decryptSmimeMessage(
  raw: Uint8Array,
  pkcs8: Uint8Array,
  certificatePem: string,
): Uint8Array {
  const { headers, body } = splitMessage(toBinaryString(raw));
  const unfolded = headers.replace(/\r?\n[ \t]+/g, ' ');
  if (!ENCRYPTED_TYPE.test(unfolded) || /smime-type\s*=\s*"?signed-data/i.test(unfolded)) {
    throw new SmimeError('not_encrypted');
  }
  const der = /^content-transfer-encoding:\s*base64\b/im.test(unfolded)
    ? forge.util.decode64(body.replace(/[^A-Za-z0-9+/=]/g, ''))
    : body;

  let message: forge.pkcs7.PkcsEnvelopedData;
  try {
    message = forge.pkcs7.messageFromAsn1(forge.asn1.fromDer(der)) as forge.pkcs7.PkcsEnvelopedData;
  } catch {
    throw new SmimeError('decrypt_failed');
  }
  if (typeof (message as { findRecipient?: unknown }).findRecipient !== 'function') {
    throw new SmimeError('not_encrypted');
  }
  const cert = forge.pki.certificateFromPem(certificatePem);
  const recipient = message.findRecipient(cert);
  if (!recipient) throw new SmimeError('not_for_this_key');

  const privateKey = forge.pki.privateKeyFromAsn1(forge.asn1.fromDer(toBinaryString(pkcs8)));
  try {
    message.decrypt(recipient, privateKey as forge.pki.rsa.PrivateKey);
  } catch {
    throw new SmimeError('decrypt_failed');
  }
  const content = (message as unknown as { content?: forge.util.ByteStringBuffer }).content;
  if (!content) throw new SmimeError('decrypt_failed');
  return fromBinaryString(content.getBytes());
}
