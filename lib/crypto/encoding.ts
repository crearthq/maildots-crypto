/** Byte/string conversions that work in the browser (no Buffer) and in Node. */

const CHUNK = 0x8000;

/** Bytes → "binary string" (one char per byte), the form node-forge works with. */
export function toBinaryString(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i += CHUNK) {
    s += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return s;
}

export function fromBinaryString(s: string): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}

export function toBase64(bytes: Uint8Array): string {
  return btoa(toBinaryString(bytes));
}

export function fromBase64(b64: string): Uint8Array<ArrayBuffer> {
  return fromBinaryString(atob(b64));
}
