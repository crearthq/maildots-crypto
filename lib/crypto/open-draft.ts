/**
 * Reopens an end-to-end encrypted DRAFT for editing, in the browser: decrypts it
 * with the unlocked key and returns the body and attachments in the compose
 * window's own shape (attachments as base64, re-encrypted on the next save).
 */
import DOMPurify from 'dompurify';
import PostalMime from 'postal-mime';
import { decryptSmimeMessage } from './smime';
import { toBase64 } from './encoding';

export interface OpenedDraft {
  html: string;
  attachments: Array<{
    filename: string;
    contentType: string;
    contentBase64: string;
    size: number;
  }>;
}

function bytesOf(content: ArrayBuffer | Uint8Array | string): Uint8Array<ArrayBuffer> {
  if (typeof content === 'string') return new TextEncoder().encode(content);
  return content instanceof Uint8Array ? new Uint8Array(content) : new Uint8Array(content);
}

export async function openEncryptedDraft(
  raw: Uint8Array,
  pkcs8: Uint8Array,
  certificatePem: string,
): Promise<OpenedDraft> {
  const inner = decryptSmimeMessage(raw, pkcs8, certificatePem);
  const parsed = await PostalMime.parse(inner, { attachmentEncoding: 'arraybuffer' });
  const body = parsed.html
    ? parsed.html.replace(/^[\s\S]*<body[^>]*>|<\/body>[\s\S]*$/gi, '')
    : `<p>${(parsed.text ?? '').replace(/[&<>]/g, (c) => `&#${c.charCodeAt(0)};`).replace(/\n/g, '<br>')}</p>`;
  // The editor only ever receives sanitised markup (it is the user's own draft, but
  // the stored copy could have been tampered with).
  const html = String(
    DOMPurify().sanitize(body, {
      FORBID_TAGS: ['script', 'style', 'iframe', 'object', 'embed', 'form', 'base', 'meta', 'link'],
    }),
  );
  return {
    html: html || '<p></p>',
    attachments: parsed.attachments.map((a) => {
      const bytes = bytesOf(a.content);
      return {
        filename: (a.filename ?? '').slice(0, 255) || 'attachment',
        contentType: a.mimeType || 'application/octet-stream',
        contentBase64: toBase64(bytes),
        size: bytes.byteLength,
      };
    }),
  };
}
