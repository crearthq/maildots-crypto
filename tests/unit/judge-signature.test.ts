// @vitest-environment jsdom
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createVault, unlockWithPassword } from '@/lib/crypto/vault';
import { buildMimeEntity, certificateFingerprint } from '@/lib/crypto/outgoing-mail';
import { openSignedEntity, signEntity, type SignatureCheck } from '@/lib/crypto/smime-sign';
import {
  addressHash,
  entryHash,
  KT_GENESIS,
  type KeyLogEntryWire,
} from '@/lib/crypto/key-log-format';
import { judgeSignature } from '@/lib/crypto/judge-signature';

const ALI = 'ali@maildots.com';
const ME = 'ben@maildots.com';
let ali: { pkcs8: Uint8Array; cert: string; fp: string };
let log: KeyLogEntryWire[] = [];
let directory: Record<string, { certificatePem: string; fingerprint: string }> = {};

async function logAdd(address: string, fp: string) {
  const prev = log.at(-1);
  const e = {
    seq: (prev?.seq ?? 0) + 1,
    addressHash: await addressHash(address),
    fingerprint: fp,
    action: 'add' as const,
    at: new Date().toISOString(),
    prevHash: prev?.hash ?? KT_GENESIS,
  };
  log.push({ ...e, hash: await entryHash(e) });
}

beforeAll(async () => {
  const v = await createVault(ALI, 'Ali-parola-2026', { memoryKiB: 19_456, iterations: 2 });
  ali = {
    pkcs8: await unlockWithPassword(v.bundle, ALI, 'Ali-parola-2026'),
    cert: v.bundle.certificatePem,
    fp: await certificateFingerprint(v.bundle.certificatePem),
  };
}, 60_000);

beforeEach(async () => {
  localStorage.clear();
  log = [];
  directory = { [ALI]: { certificatePem: ali.cert, fingerprint: 'x' } };
  await logAdd(ALI, ali.fp);
  vi.stubGlobal('fetch', async (url: string) => {
    if (url.startsWith('/api/keys/log')) {
      const after = Number(new URL(url, 'https://x').searchParams.get('after'));
      const last = log.at(-1);
      return Response.json({
        entries: log.filter((e) => e.seq > after),
        head: { seq: last?.seq ?? 0, hash: last?.hash ?? KT_GENESIS },
      });
    }
    return Response.json({ keys: directory });
  });
});
afterEach(() => vi.unstubAllGlobals());

const bytes = (s: string) => new TextEncoder().encode(s);
const signed = (headers: {
  from: string;
  to: string[];
  subject: string;
  keyLog?: { seq: number; hash: string };
}): SignatureCheck =>
  openSignedEntity(
    bytes(signEntity(buildMimeEntity({ html: '<p>x</p>' }), ali.pkcs8, ali.cert, headers)),
  ).signature;

describe('judging a signature (T4)', () => {
  it('verified when key, pin, log, signed From/Subject and witness all agree', async () => {
    const head = log.at(-1)!;
    const sig = signed({
      from: ALI,
      to: [ME],
      subject: 'Teklif ğüş',
      keyLog: { seq: head.seq, hash: head.hash },
    });
    if (!sig.signed) throw new Error('signed');
    expect(sig.protected).toMatchObject({ from: ALI, to: [ME], subject: 'Teklif ğüş' });
    expect(await judgeSignature(sig, { from: ALI, subject: 'Teklif ğüş', me: ME })).toBe(
      'verified',
    );
  });

  it('an unsigned message from a MailDots key holder is flagged, not silent', async () => {
    expect(await judgeSignature({ signed: false }, { from: ALI, subject: 's', me: ME })).toBe(
      'unsigned',
    );
    // From someone with no MailDots key: nothing to say.
    expect(
      await judgeSignature({ signed: false }, { from: 'dis@gmail.com', subject: 's', me: ME }),
    ).toBeNull();
  });

  it('a subject changed on the way is caught', async () => {
    const sig = signed({ from: ALI, to: [ME], subject: 'Öğle yemeği' });
    expect(await judgeSignature(sig, { from: ALI, subject: 'Onay: 1M transfer', me: ME })).toBe(
      'headers_changed',
    );
  });

  it('a message signed for someone else and forwarded is not "verified" for me', async () => {
    const sig = signed({ from: ALI, to: ['carol@maildots.com'], subject: 's' });
    expect(await judgeSignature(sig, { from: ALI, subject: 's', me: ME })).toBe('not_addressed');
  });

  it("the sender's key log head that differs from mine is a fork (split view)", async () => {
    const sig = signed({
      from: ALI,
      to: [ME],
      subject: 's',
      keyLog: { seq: 1, hash: 'a'.repeat(64) },
    });
    expect(await judgeSignature(sig, { from: ALI, subject: 's', me: ME })).toBe('log_fork');
  });

  it('a key the log does not hold is not the sender key', async () => {
    log = [];
    await logAdd(ALI, 'b'.repeat(64)); // the log says another key
    const sig = signed({ from: ALI, to: [ME], subject: 's' });
    expect(await judgeSignature(sig, { from: ALI, subject: 's', me: ME })).toBe('wrong_key');
  });

  it('an empty or spaced subject is not a false alarm (one normalisation)', async () => {
    const sig = signed({ from: ALI, to: [ME], subject: '  ' });
    expect(await judgeSignature(sig, { from: ALI, subject: '(no subject)', me: ME })).toBe(
      'verified',
    );
    const spaced = signed({ from: ALI, to: [ME], subject: 'Teklif\n  ve  fiyat ' });
    expect(await judgeSignature(spaced, { from: ALI, subject: 'Teklif ve fiyat', me: ME })).toBe(
      'verified',
    );
  });

  it('an older signature without protected headers is only "body"', async () => {
    const sig = openSignedEntity(
      bytes(signEntity(buildMimeEntity({ html: '<p>x</p>' }), ali.pkcs8, ali.cert)),
    ).signature;
    expect(await judgeSignature(sig, { from: ALI, subject: 'herhangi', me: ME })).toBe(
      'verified_body_only',
    );
  });

  it('a sender head my fully-updated log cannot reach is a fork (entries withheld)', async () => {
    const sig = signed({
      from: ALI,
      to: [ME],
      subject: 's',
      keyLog: { seq: 99, hash: 'c'.repeat(64) },
    });
    expect(await judgeSignature(sig, { from: ALI, subject: 's', me: ME })).toBe('log_fork');
  });
});
