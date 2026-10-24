/**
 * Opens an end-to-end encrypted message IN THE BROWSER: S/MIME decryption, MIME
 * parsing and HTML sanitising all happen here, because the server never sees the
 * plaintext (and so cannot sanitise it).
 *
 * The output is rendered by the same sandboxed, opaque-origin iframe as any other
 * mail (strict CSP, images only from `data:`), so this sanitiser is the first line of
 * defence and the frame the second. Remote content is never loaded: there is no
 * server-side image proxy for mail the server cannot read.
 */
import DOMPurify from 'dompurify';
import PostalMime from 'postal-mime';
import { decryptSmimeMessage } from './smime';
import { openSignedEntity, type SignatureCheck } from './smime-sign';
import { toBase64 } from './encoding';

export interface DecryptedAttachment {
  filename: string;
  contentType: string;
  size: number;
  blob: Blob;
}

export interface DecryptedMail {
  /** Sanitised HTML body (inline images embedded as data: URIs). */
  html: string;
  /** Attachments not already shown inside the body. */
  attachments: DecryptedAttachment[];
  /** The body referenced remote content that was dropped. */
  hadRemoteContent: boolean;
  /** S/MIME signature inside the encryption (T4); who signed is checked by the caller. */
  signature: SignatureCheck;
}

/** Raster types shown inline (no SVG: it is a document, not just pixels). */
const INLINE_TYPES = new Set(['image/png', 'image/jpeg', 'image/jpg', 'image/gif', 'image/webp']);
const INLINE_MAX_BYTES = 2 * 1024 * 1024;
/** Total inline-image payload and count per message (memory cap for repeated cid: refs). */
const INLINE_TOTAL_MAX_BYTES = 8 * 1024 * 1024;
const INLINE_MAX_COUNT = 200;

const FORBID_TAGS = [
  'style',
  'link',
  'meta',
  'base',
  'form',
  'input',
  'button',
  'textarea',
  'select',
  'option',
  'iframe',
  'frame',
  'frameset',
  'object',
  'embed',
  'applet',
  'svg',
  'math',
  'video',
  'audio',
  'source',
  'track',
  'picture',
  'script',
  'noscript',
  'template',
  'portal',
  'dialog',
];
const FORBID_ATTR = [
  'srcset',
  'background',
  'ping',
  'formaction',
  'action',
  'poster',
  'lowsrc',
  'dynsrc',
];
/** Links that may stay clickable. */
const SAFE_HREF = /^(?:https?:|mailto:|#)/i;
/**
 * A style attribute is dropped entirely when it contains anything that can fetch or
 * execute — including obfuscations: CSS escapes (`u\72l(`), image-set(), image(),
 * cross-fade(), src(), at-rules, legacy expression() and behaviors.
 */
const UNSAFE_CSS =
  /\\|url\s*\(|image-set|image\s*\(|cross-fade|src\s*\(|@|expression\s*\(|javascript:|vbscript:|behavior\s*:|-moz-binding/i;
/** Control and bidi-override characters (spoofed names like "invoice‮fdp.exe"). */
const UNSAFE_FILENAME_CHARS = /[\u0000-\u001f\u007f‎‏‪-‮⁦-⁩]/g;

function normalizeCid(value: string): string {
  let v = value.trim().replace(/^cid:/i, '').replace(/^<|>$/g, '');
  try {
    v = decodeURIComponent(v);
  } catch {
    /* keep as is */
  }
  return v.toLowerCase();
}

function toBytes(content: ArrayBuffer | Uint8Array | string): Uint8Array<ArrayBuffer> {
  if (typeof content === 'string') return new TextEncoder().encode(content);
  return content instanceof Uint8Array ? new Uint8Array(content) : new Uint8Array(content);
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

/** Plain-text body as HTML (escaped, line breaks kept). */
function textToHtml(text: string): string {
  return `<div style="white-space:pre-wrap">${escapeHtml(text)}</div>`;
}

/**
 * Sanitises mail HTML for the reading frame. Exposed for tests. `cidImages` maps a
 * normalised Content-ID to a vetted data: URI.
 */
export function sanitizeDecryptedHtml(
  html: string,
  cidImages: Map<string, string>,
): { html: string; usedCids: Set<string>; hadRemoteContent: boolean } {
  const purify = DOMPurify();
  const usedCids = new Set<string>();
  let hadRemoteContent = false;
  let inlineBytes = 0;
  let inlineCount = 0;

  purify.addHook('afterSanitizeAttributes', (node) => {
    if (!(node instanceof Element)) return;
    const style = node.getAttribute('style');
    if (style && UNSAFE_CSS.test(style)) {
      node.removeAttribute('style');
      if (/https?:/i.test(style)) hadRemoteContent = true;
    }
    if (node.tagName === 'IMG') {
      const src = node.getAttribute('src') ?? '';
      if (/^cid:/i.test(src)) {
        const cid = normalizeCid(src);
        const data = cidImages.get(cid);
        const fits =
          data !== undefined &&
          inlineCount < INLINE_MAX_COUNT &&
          inlineBytes + data.length <= INLINE_TOTAL_MAX_BYTES;
        if (data && fits) {
          node.setAttribute('src', data);
          usedCids.add(cid);
          inlineCount += 1;
          inlineBytes += data.length;
        } else {
          node.removeAttribute('src');
        }
      } else {
        if (/^https?:/i.test(src)) hadRemoteContent = true;
        node.removeAttribute('src'); // remote images are never fetched
      }
    }
    if (node.tagName === 'A') {
      const href = node.getAttribute('href') ?? '';
      if (href && !SAFE_HREF.test(href.trim())) node.removeAttribute('href');
      node.setAttribute('target', '_blank');
      node.setAttribute('rel', 'noopener noreferrer');
    }
  });

  const clean = purify.sanitize(html, {
    FORBID_TAGS,
    FORBID_ATTR,
    // URI checks stay DOMPurify's default (a custom regexp would also strip layout
    // attributes like width/align); links and images are narrowed in the hook.
    ALLOW_DATA_ATTR: false,
    WHOLE_DOCUMENT: false,
    RETURN_TRUSTED_TYPE: false,
  });
  return { html: String(clean), usedCids, hadRemoteContent };
}

/**
 * Decrypts and renders-prepares one stored message. Throws SmimeError
 * (`not_encrypted`, `not_for_this_key`, `decrypt_failed`) from the decryption step.
 */
export async function openEncryptedMail(
  raw: Uint8Array,
  pkcs8: Uint8Array,
  certificatePem: string,
): Promise<DecryptedMail> {
  // Signed-then-encrypted (T4): only the signed part is rendered, never mixed.
  const { entity: inner, signature } = openSignedEntity(
    decryptSmimeMessage(raw, pkcs8, certificatePem),
  );
  // The decrypted entity is a MIME part (its own headers + body); parsed as a message.
  // Nested encrypted/signed parts are NOT recursively opened and merged (EFAIL-style
  // mixing of decrypted and attacker-supplied parts): they stay attachments.
  const parsed = await PostalMime.parse(inner, { attachmentEncoding: 'arraybuffer' });

  const cidImages = new Map<string, string>();
  const parts = parsed.attachments.map((a) => {
    const bytes = toBytes(a.content);
    const type = (a.mimeType || 'application/octet-stream').toLowerCase();
    const cid = a.contentId ? normalizeCid(a.contentId) : null;
    if (cid && INLINE_TYPES.has(type) && bytes.byteLength <= INLINE_MAX_BYTES) {
      cidImages.set(cid, `data:${type};base64,${toBase64(bytes)}`);
    }
    return { a, bytes, type, cid };
  });

  const body = parsed.html ? parsed.html : textToHtml(parsed.text ?? '');
  const { html, usedCids, hadRemoteContent } = sanitizeDecryptedHtml(body, cidImages);

  const attachments: DecryptedAttachment[] = parts
    .filter((p) => !(p.cid && usedCids.has(p.cid)))
    .map((p) => ({
      filename:
        (p.a.filename ?? '').replace(UNSAFE_FILENAME_CHARS, '').slice(0, 255) || 'attachment',
      contentType: p.type,
      size: p.bytes.byteLength,
      // Always an opaque download type: a blob: URL opened as a page would render in
      // OUR origin. The in-app preview re-types the bytes itself (from contentType).
      blob: new Blob([p.bytes], { type: 'application/octet-stream' }),
    }));

  return { html, attachments, hadRemoteContent, signature };
}
