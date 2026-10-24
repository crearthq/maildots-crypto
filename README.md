# MailDots crypto

The end-to-end encryption code of [MailDots](https://maildots.com), a business e-mail
service. This is the code that runs in your browser (webmail) and inside the MailDots
Android app; it is published so that anyone can check it.

What MailDots can and cannot read, and the known limits, are written down openly in
[docs/security/zero-access.md](docs/security/zero-access.md) (Turkish).

## What is here

| Path                              | What it does                                                                                         |
| --------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `lib/crypto/vault.ts`             | Key pair generation; the private key sealed under a password key (Argon2id) and a 24-word phrase     |
| `lib/crypto/login-client.ts`      | Derives the login key from the password, so the password itself is not sent                          |
| `lib/crypto/smime.ts`             | Decrypting stored mail (S/MIME)                                                                      |
| `lib/crypto/outgoing-mail.ts`     | Encrypting outgoing mail to the recipients' keys                                                     |
| `lib/crypto/smime-sign.ts`        | Signing (sign, then encrypt) with sender, recipients and subject inside the signature; verification |
| `lib/crypto/judge-signature.ts`   | When a signature counts as "sender verified", and every warning case                                 |
| `lib/crypto/key-log*.ts`          | Append-only key log: the client verifies the chain itself and detects rollback or a split view       |
| `lib/crypto/decrypted-mail.ts`    | Sanitising decrypted HTML (DOMPurify); remote images are never fetched                               |
| `lib/crypto/mobile-core.ts`       | The entry point the Android app runs                                                                 |
| `scripts/build-mobile-core.mjs`   | Builds that entry point into one file                                                                |

The server side (key vault storage, key log storage, mail server) is not in this
repository.

## Check that the app runs this code

The build is reproducible: the same source gives the same bytes.

```bash
corepack pnpm install --frozen-lockfile
corepack pnpm test
corepack pnpm build        # prints: core.js … sha256-…
```

Compare the printed `sha256-…` with the `integrity` attribute in the app's
`assets/e2e/core.html` (unzip the APK) — they must be identical. Every release notes
the hash it ships.

## License

Copyright © 2026 Creart Technology LLC.

[GNU Affero General Public License v3.0](LICENSE). The MailDots name and logo are not
covered by this license. Security reports: [SECURITY.md](SECURITY.md).
