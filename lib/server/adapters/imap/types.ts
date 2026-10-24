/** Credentials used to authenticate against the user's IMAP mailbox. */
export interface MailCredentials {
  email: string;
  password: string;
}

export type ImapVerifyResult =
  | { ok: true }
  | { ok: false; reason: 'invalid_credentials' | 'connection_error'; detail?: string };

/** Minimal mailbox/folder shape — fleshed out in Phase 1+. */
export interface MailboxFolder {
  path: string;
  name: string;
  specialUse?: string;
  subscribed: boolean;
}

export interface MailAddress {
  name: string;
  address: string;
}

/** One row in the message list (no full body — built for 35k+ mailboxes). */
export interface MessageSummary {
  uid: number;
  subject: string;
  from: MailAddress | null;
  /** Envelope recipients (To). Populated by folder/search listings so OUTGOING
   *  folders (Sent/Drafts) can show the recipient instead of the sender. */
  to?: MailAddress[];
  date: string | null; // ISO
  /** When the mail server stored it (IMAP internal date), not the sender's claim. */
  receivedAt?: string | null;
  seen: boolean;
  flagged: boolean;
  hasAttachments: boolean;
  size: number;
  snippet: string;
  /** Body is encrypted (S/MIME or OpenPGP): no server-side preview. Omitted when false. */
  encrypted?: boolean;
  /** Custom IMAP keywords on the message (label keywords; system flags excluded). */
  keywords: string[];
}

/** A paginated, newest-first window over a folder. */
export interface MessageWindow {
  folder: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  messages: MessageSummary[];
}

/** A fully opened message for the reading pane (sanitized HTML). */
export interface MessageDetail {
  /** Original recipients when replying to our own Sent copy. */
  replyToAddress?: string;
  uid: number;
  subject: string;
  from: MailAddress | null;
  to: MailAddress[];
  cc: MailAddress[];
  /** Reply-To header: where the sender asked replies to go (empty = use From). */
  replyTo?: MailAddress[];
  date: string | null;
  seen: boolean;
  /** RFC822 Message-ID of this message (for reply threading). */
  messageId: string | null;
  /** Existing References chain (for reply threading). */
  references: string[];
  /** Sanitized, render-safe HTML. */
  html: string;
  /** True when remote images/content were present and (by default) blocked. */
  hasRemoteContent: boolean;
  /** Reflects whether remote content was allowed in this render. */
  remoteAllowed: boolean;
  /** Custom IMAP keywords on the message (label keywords; system flags excluded). */
  keywords: string[];
  /** Every MIME attachment, in order (the index is the download index). [inline] = shown inside the body. */
  attachments: Array<{ filename: string; contentType: string; size: number; inline?: boolean }>;
  /** Body is S/MIME/OpenPGP ciphertext: the browser decrypts it (raw endpoint); html is empty. */
  encrypted?: boolean;
}
