// Builds the apps' end-to-end crypto core (lib/crypto/mobile-core.ts) into one
// self-contained page: dist/mobile-core/core.html + core.js. Copy both into the
// app (Android: composeApp/src/androidMain/assets/e2e/). The page loads nothing
// from the network; its CSP forbids it anyway.
//
//   node scripts/build-mobile-core.mjs
import { build } from 'esbuild';
import { createHash } from 'node:crypto';
import { execSync } from 'node:child_process';
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const out = path.join(root, 'dist', 'mobile-core');
mkdirSync(out, { recursive: true });

let commit = 'unknown';
try {
  commit = execSync('git rev-parse --short HEAD', {
    cwd: root,
    stdio: ['ignore', 'pipe', 'ignore'],
  })
    .toString()
    .trim();
} catch {
  /* not a checkout */
}

const result = await build({
  stdin: {
    contents: "import { installCore } from './lib/crypto/mobile-core';\ninstallCore();\n",
    resolveDir: root,
    sourcefile: 'mobile-core-entry.ts',
    loader: 'ts',
  },
  bundle: true,
  format: 'iife',
  platform: 'browser',
  target: ['chrome100', 'safari15'],
  minify: true,
  legalComments: 'eof',
  metafile: true,
  alias: { '@': root },
  define: { 'process.env.NODE_ENV': '"production"' },
  outfile: path.join(out, 'core.js'),
  // No commit or date in the output: the same source must give the same bytes, so
  // anyone can rebuild the core and compare its sha256 with the one the app ships.
  banner: { js: '/* MailDots crypto core */' },
});

const js = readFileSync(path.join(out, 'core.js'));
const sha = createHash('sha256').update(js).digest('base64');
// 'self' is the app's own asset origin (nothing else is served there);
// 'wasm-unsafe-eval': Argon2id runs as WebAssembly. Nothing may connect anywhere.
const html = `<!doctype html>
<html><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'none'; img-src 'none'; style-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'">
<title>MailDots core</title></head>
<body><script src="core.js" integrity="sha256-${sha}"></script></body></html>
`;
writeFileSync(path.join(out, 'core.html'), html);

// Licence texts of every third-party package bundled into core.js (shipped next to it).
const packages = new Map();
for (const input of Object.keys(result.metafile.inputs)) {
  const m = /^(.*node_modules\/(@[^/]+\/[^/]+|[^@/][^/]*))\//.exec(input);
  if (m) packages.set(m[2], path.join(root, m[1]));
}
const notices = [...packages]
  .sort(([a], [b]) => a.localeCompare(b))
  .map(([name, dir]) => {
    const pkg = JSON.parse(readFileSync(path.join(dir, 'package.json'), 'utf8'));
    const file = readdirSync(dir).find((f) => /^licen[cs]e(\.(md|txt))?$/i.test(f));
    if (!file) throw new Error(`no licence file in ${name}`);
    const text = readFileSync(path.join(dir, file), 'utf8').trim();
    return `${name} ${pkg.version} (${pkg.license})\n${'-'.repeat(60)}\n${text}\n`;
  });
writeFileSync(
  path.join(out, 'THIRD_PARTY_NOTICES.txt'),
  `Third-party software in the MailDots crypto core (core.js)\n\n${notices.join('\n\n')}`,
);
console.log(`core.js ${(js.length / 1024).toFixed(0)} KiB, sha256-${sha}, source ${commit}`);
