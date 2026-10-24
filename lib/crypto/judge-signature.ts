import type { SignatureCheck } from './smime-sign';

export type Verdict =
  | 'verified'
  | 'verified_body_only' // older signature: body signed, subject / recipients not bound
  | 'unsigned' // the sender has a MailDots key but did not sign
  | 'unknown_key' // valid, but who signed cannot be tied to the sender
  | 'not_addressed' // signed for someone else (forwarded on)
  | 'wrong_address'
  | 'wrong_key'
  | 'headers_changed' // From / Subject differ from what was signed
  | 'log_fork' // the sender saw another key log than this browser (split view)
  | 'log_rewritten' // the key log went backwards / was rewritten
  | 'broken';

export const RED: Verdict[] = [
  'wrong_key',
  'headers_changed',
  'log_fork',
  'log_rewritten',
  'broken',
];

const plainFetch = (input: string, init?: RequestInit) => fetch(input, init);

/**
 * Who signed, and what (T4). A valid signature only proves "the holder of THIS
 * certificate signed THESE bytes"; it counts as the sender's only if the
 * certificate names the sender, is the key the MailDots directory, this browser's
 * pin and the key log hold for that address, and the From / Subject signed inside
 * match the ones shown. An encrypted message from a MailDots key holder that is
 * NOT signed is flagged too: anybody can encrypt to a public key.
 */
export async function judgeSignature(
  signature: SignatureCheck,
  outer: { from: string; subject: string; me: string | null },
): Promise<Verdict | null> {
  const sender = outer.from.trim().toLowerCase();
  const { lookupKeys, certificateFingerprint } = await import('./outgoing-mail');
  if (!signature.signed) {
    // From the directory, or from what this browser already verified (a server that
    // breaks the directory for this reader cannot hide "unsigned" that way).
    const keys = await lookupKeys(plainFetch, [sender]).catch(() => null);
    if (keys?.[sender]) return 'unsigned';
    const { knownInLog } = await import('./key-log');
    return (await knownInLog(sender).catch(() => false)) ? 'unsigned' : null;
  }
  if (!signature.valid || !signature.signerFingerprint) return 'broken';
  if (!signature.signerEmails.includes(sender)) return 'wrong_address';
  const signed = signature.protected;
  const { normalizeSubject } = await import('./smime-sign');
  if (signed) {
    if (
      signed.from !== sender ||
      normalizeSubject(signed.subject) !== normalizeSubject(outer.subject)
    ) {
      return 'headers_changed';
    }
  }
  const keys = await lookupKeys(plainFetch, [sender]).catch(() => null);
  const listed = keys?.[sender];
  if (!listed) return 'unknown_key';
  const directoryFp = await certificateFingerprint(listed.certificatePem);
  if (directoryFp !== signature.signerFingerprint) return 'wrong_key';
  const { checkPins } = await import('./key-pins');
  // A pinned, different key for the sender wins over the directory.
  if (checkPins({ [sender]: directoryFp }).length > 0) return 'wrong_key';
  const { verifyAgainstLog, checkWitness } = await import('./key-log');
  const kt = await verifyAgainstLog(plainFetch, { [sender]: directoryFp });
  if (!kt.ok) return kt.reason === 'rewritten' ? 'log_rewritten' : 'unknown_key';
  if (kt.mismatched.length > 0) return 'wrong_key';
  // The sender's view of the key log must be the same log this browser sees.
  if (signed?.keyLog) {
    const w = await checkWitness(plainFetch, signed.keyLog.seq, signed.keyLog.hash);
    if (w === 'forked') return 'log_fork';
  }
  const me = outer.me?.toLowerCase() ?? null;
  if (!signed) return 'verified_body_only';
  if (me && me !== sender && !signed.to.includes(me)) return 'not_addressed';
  return 'verified';
}
