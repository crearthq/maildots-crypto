// @vitest-environment node
import { X509Certificate } from 'node:crypto';
import forge from 'node-forge';
import { beforeAll, describe, expect, it } from 'vitest';
import {
  createVault,
  isValidRecoveryPhrase,
  keyMatchesCertificate,
  recoveryChallenge,
  rewrapForPassword,
  unlockWithPassword,
  unlockWithRecovery,
  type CreatedVault,
} from '@/lib/crypto/vault';
import { vaultBundleSchema } from '@/lib/crypto/vault-schema';
import { decryptSmimeMessage, SmimeError } from '@/lib/crypto/smime';
import { fromBinaryString, toBinaryString } from '@/lib/crypto/encoding';

const EMAIL = 'ali@firma.com';
const PASSWORD = 'Doğru-parola-2026';
const CHEAP = { memoryKiB: 19_456, iterations: 2 }; // fast in tests; production uses DEFAULT_KDF

let vault: CreatedVault;

beforeAll(async () => {
  vault = await createVault(EMAIL, PASSWORD, CHEAP);
}, 60_000);

describe('vault creation', () => {
  it('produces a bundle the server schema accepts, with an RSA-3072 S/MIME certificate', () => {
    expect(vaultBundleSchema.safeParse(vault.bundle).success).toBe(true);
    const cert = new X509Certificate(vault.bundle.certificatePem);
    expect(cert.subjectAltName).toBe(`email:${EMAIL}`);
    expect(cert.publicKey.asymmetricKeyDetails?.modulusLength).toBe(3072);
    expect(cert.keyUsage).toContain('1.3.6.1.5.5.7.3.4'); // emailProtection
    expect(isValidRecoveryPhrase(vault.recoveryPhrase)).toBe(true);
    expect(vault.recoveryPhrase.split(' ')).toHaveLength(24);
  });

  it('never puts the private key or the phrase in the bundle', () => {
    const json = JSON.stringify(vault.bundle);
    expect(json).not.toContain('PRIVATE KEY');
    for (const word of vault.recoveryPhrase.split(' ').slice(0, 6)) {
      expect(json.includes(` ${word} `)).toBe(false);
    }
  });
});

describe('unlocking', () => {
  it('opens with the password and with the recovery phrase, to the same key', async () => {
    const a = await unlockWithPassword(vault.bundle, EMAIL, PASSWORD);
    const b = await unlockWithRecovery(
      vault.bundle,
      EMAIL,
      `  ${vault.recoveryPhrase.toUpperCase()} `,
    );
    expect(toBinaryString(a)).toBe(toBinaryString(b));
    const key = forge.pki.privateKeyFromAsn1(forge.asn1.fromDer(toBinaryString(a)));
    const cert = forge.pki.certificateFromPem(vault.bundle.certificatePem);
    expect((key as forge.pki.rsa.PrivateKey).n.toString(16)).toBe(
      (cert.publicKey as forge.pki.rsa.PublicKey).n.toString(16),
    );
  });

  it('refuses a wrong password, a wrong phrase, or a vault moved to another mailbox', async () => {
    await expect(unlockWithPassword(vault.bundle, EMAIL, 'yanlis-parola-1')).rejects.toThrow(
      'unlock_failed',
    );
    await expect(unlockWithRecovery(vault.bundle, EMAIL, 'abandon '.repeat(24))).rejects.toThrow(
      'unlock_failed',
    );
    await expect(unlockWithPassword(vault.bundle, 'veli@firma.com', PASSWORD)).rejects.toThrow(
      'unlock_failed',
    );
  });

  it('re-wraps for a new password; the old one stops working on the new slot', async () => {
    const pkcs8 = await unlockWithPassword(vault.bundle, EMAIL, PASSWORD);
    const update = await rewrapForPassword(pkcs8, EMAIL, 'Yeni-parola-2027', CHEAP);
    expect(update.kdf.salt).not.toBe(vault.bundle.kdf.salt);
    const reopened = await unlockWithPassword(update, EMAIL, 'Yeni-parola-2027');
    expect(toBinaryString(reopened)).toBe(toBinaryString(pkcs8));
    await expect(unlockWithPassword(update, EMAIL, PASSWORD)).rejects.toThrow('unlock_failed');
  });

  it('asks back distinct word positions', () => {
    const picks = recoveryChallenge(3);
    expect(new Set(picks).size).toBe(3);
    for (const p of picks) expect(p).toBeGreaterThanOrEqual(0);
    for (const p of picks) expect(p).toBeLessThan(24);
  });
});

describe('S/MIME decryption', () => {
  function encryptedMessage(certPem: string, inner: string): Uint8Array {
    const p7 = forge.pkcs7.createEnvelopedData();
    p7.addRecipient(forge.pki.certificateFromPem(certPem));
    p7.content = forge.util.createBuffer(inner);
    p7.encrypt(undefined, forge.pki.oids['aes256-CBC']);
    const der = forge.asn1.toDer(p7.toAsn1()).getBytes();
    const b64 = forge.util.encode64(der).replace(/(.{76})/g, '$1\r\n');
    return fromBinaryString(
      'From: dis@ornek.com\r\nTo: ali@firma.com\r\nSubject: Gizli\r\n' +
        'Content-Type: application/pkcs7-mime;\r\n\tname="smime.p7m";\r\n\tsmime-type=enveloped-data\r\n' +
        'Content-Transfer-Encoding: base64\r\n\r\n' +
        b64,
    );
  }

  it('decrypts mail encrypted to the vault certificate', async () => {
    const inner = 'Content-Type: text/plain; charset=utf-8\r\n\r\nMerhaba, bu gizli.\r\n';
    const pkcs8 = await unlockWithPassword(vault.bundle, EMAIL, PASSWORD);
    const out = decryptSmimeMessage(
      encryptedMessage(vault.bundle.certificatePem, inner),
      pkcs8,
      vault.bundle.certificatePem,
    );
    expect(toBinaryString(out)).toBe(inner);
  });

  it('detects a certificate that does not belong to the unlocked key', async () => {
    const pkcs8 = await unlockWithPassword(vault.bundle, EMAIL, PASSWORD);
    expect(keyMatchesCertificate(pkcs8, vault.bundle.certificatePem)).toBe(true);
    const other = await createVault('veli@firma.com', PASSWORD, CHEAP);
    expect(keyMatchesCertificate(pkcs8, other.bundle.certificatePem)).toBe(false);
  }, 60_000);

  it('reports mail that is not encrypted, or encrypted to someone else', async () => {
    const pkcs8 = await unlockWithPassword(vault.bundle, EMAIL, PASSWORD);
    const plain = fromBinaryString('Subject: x\r\nContent-Type: text/plain\r\n\r\nhi');
    expect(() => decryptSmimeMessage(plain, pkcs8, vault.bundle.certificatePem)).toThrow(
      SmimeError,
    );

    const other = await createVault('veli@firma.com', PASSWORD, CHEAP);
    const toOther = encryptedMessage(other.bundle.certificatePem, 'x');
    expect(() => decryptSmimeMessage(toOther, pkcs8, vault.bundle.certificatePem)).toThrow(
      'not_for_this_key',
    );
  }, 60_000);
});

describe('PKCS#12 export', () => {
  it('opens with the export password to the same key and certificate', async () => {
    const { exportPkcs12 } = await import('@/lib/crypto/vault');
    const pkcs8 = await unlockWithPassword(vault.bundle, EMAIL, PASSWORD);
    const file = exportPkcs12(
      pkcs8,
      vault.bundle.certificatePem,
      'Dosya-sifresi-2026',
      'MailDots ali',
    );
    const der = forge.asn1.fromDer(toBinaryString(file));
    const p12 = forge.pkcs12.pkcs12FromAsn1(der, 'Dosya-sifresi-2026');
    const keyOid = forge.pki.oids.pkcs8ShroudedKeyBag!;
    const certOid = forge.pki.oids.certBag!;
    const key = p12.getBags({ bagType: keyOid })[keyOid]?.[0]?.key as forge.pki.rsa.PrivateKey;
    const cert = p12.getBags({ bagType: certOid })[certOid]?.[0]?.cert as forge.pki.Certificate;
    expect(key.n.equals((cert.publicKey as forge.pki.rsa.PublicKey).n)).toBe(true);
    expect(() =>
      forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(toBinaryString(file)), 'yanlis-sifre-1234'),
    ).toThrow();
    expect(() => exportPkcs12(pkcs8, vault.bundle.certificatePem, 'kisa', 'x')).toThrow(
      'weak_export_password',
    );
  }, 60_000);
});
