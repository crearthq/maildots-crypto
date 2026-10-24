/**
 * Size limits for end-to-end encrypted mail (kept apart from the crypto modules so
 * UI code can import them without pulling in node-forge).
 *
 * Attachments are base64-encoded twice (inside the MIME entity, then the
 * ciphertext in the request), so 9 MiB raw stays under the 25 MB request limit.
 */
export const MAX_ENCRYPTED_ATTACHMENT_BYTES = 9 * 1024 * 1024;
/** Total ciphertext (base64) of one send, all Bcc copies included. */
export const MAX_ENCRYPTED_REQUEST_B64 = 23_000_000;
