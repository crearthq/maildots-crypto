/**
 * Recovery-phrase sheet as a branded A4 PDF (letterhead style): logo, account, date,
 * the 24 words as a numbered 4×6 grid, the warning and safekeeping notes. Built
 * entirely in the browser — the phrase never leaves the device. pdf-lib, fontkit and
 * the Inter fonts (pre-subset to Latin + Turkish, ~40 KB each) load only on the
 * phrase screen, in the background, before the user asks for the file.
 */

export interface RecoveryPdfText {
  label: string;
  title: string;
  account: string;
  created: string;
  warning: string;
  notes: string[];
  footer: string;
}

const INK = [0.055, 0.075, 0.19] as const; // #0E1330
const MUTED = [0.42, 0.44, 0.52] as const;
const BRAND = [0.165, 0.22, 0.925] as const; // #2A38EC
const TILE = [0.957, 0.961, 1] as const;
const TILE_LINE = [0.86, 0.87, 0.97] as const;

async function bytes(path: string): Promise<ArrayBuffer> {
  const res = await fetch(path);
  if (!res.ok) throw new Error(`asset ${path}: ${res.status}`);
  return res.arrayBuffer();
}

function loadAll() {
  return Promise.all([
    import('pdf-lib'),
    import('@pdf-lib/fontkit'),
    bytes('/fonts/pdf/Inter-Regular.ttf'),
    bytes('/fonts/pdf/Inter-SemiBold.ttf'),
    bytes('/brand/maildots-wordmark.png'),
  ]);
}
let loading: ReturnType<typeof loadAll> | null = null;

function assets(): ReturnType<typeof loadAll> {
  if (!loading) {
    loading = loadAll();
    loading.catch(() => {
      loading = null; // a failed load is retried on the next request
    });
  }
  return loading;
}

/**
 * Starts loading the library, fonts and logo in the background (called when the
 * phrase is shown) so the download button builds the file almost instantly.
 */
export function preloadRecoveryPdf(): void {
  assets().catch(() => undefined);
}

function roundedRect(x: number, y: number, w: number, h: number, r: number): string {
  // SVG path in pdf-lib's drawSvgPath space (y grows downward from the given origin).
  return `M ${x + r} ${y} H ${x + w - r} Q ${x + w} ${y} ${x + w} ${y + r} V ${y + h - r} Q ${x + w} ${y + h} ${x + w - r} ${y + h} H ${x + r} Q ${x} ${y + h} ${x} ${y + h - r} V ${y + r} Q ${x} ${y} ${x + r} ${y} Z`;
}

export async function buildRecoveryPdf(input: {
  words: string[];
  owner: string;
  date: string;
  text: RecoveryPdfText;
}): Promise<Uint8Array> {
  const [{ PDFDocument, rgb }, { default: fontkit }, regular, semibold, logo] = await assets();
  const color = (c: readonly [number, number, number]) => rgb(c[0], c[1], c[2]);

  const doc = await PDFDocument.create();
  doc.registerFontkit(fontkit);
  doc.setTitle(input.text.title);
  doc.setAuthor('MailDots');
  doc.setCreator('MailDots');
  const font = await doc.embedFont(regular, { subset: false });
  const bold = await doc.embedFont(semibold, { subset: false });
  const logoImg = await doc.embedPng(logo);

  const W = 595.28;
  const H = 841.89;
  const M = 56;
  const page = doc.addPage([W, H]);
  const { text } = input;

  const wrap = (s: string, size: number, width: number, f = font): string[] => {
    const lines: string[] = [];
    let line = '';
    for (const word of s.split(/\s+/)) {
      const next = line ? `${line} ${word}` : word;
      if (line && f.widthOfTextAtSize(next, size) > width) {
        lines.push(line);
        line = word;
      } else {
        line = next;
      }
    }
    if (line) lines.push(line);
    return lines;
  };

  // Letterhead: logo, label, hairline.
  const logoH = 22;
  const logoW = (logoImg.width / logoImg.height) * logoH;
  let y = H - M - logoH;
  page.drawImage(logoImg, { x: M, y, width: logoW, height: logoH });
  const label = text.label;
  const labelSize = 8;
  page.drawText(label, {
    x: W - M - bold.widthOfTextAtSize(label, labelSize),
    y: y + 7,
    size: labelSize,
    font: bold,
    color: color(MUTED),
  });
  y -= 18;
  page.drawLine({
    start: { x: M, y },
    end: { x: W - M, y },
    thickness: 0.6,
    color: color(TILE_LINE),
  });

  // Title and account details.
  y -= 44;
  page.drawText(text.title, { x: M, y, size: 20, font: bold, color: color(INK) });
  y -= 24;
  page.drawText(`${text.account}  ${input.owner}`, {
    x: M,
    y,
    size: 10,
    font,
    color: color(MUTED),
  });
  y -= 15;
  page.drawText(`${text.created}  ${input.date}`, { x: M, y, size: 10, font, color: color(MUTED) });

  // 4 × 6 numbered word grid.
  const cols = 4;
  const gap = 10;
  const cellW = (W - 2 * M - (cols - 1) * gap) / cols;
  const cellH = 46;
  y -= 30;
  const gridTop = y;
  input.words.forEach((word, i) => {
    const col = i % cols;
    const row = Math.floor(i / cols);
    const x = M + col * (cellW + gap);
    const top = gridTop - row * (cellH + gap);
    page.drawSvgPath(roundedRect(0, 0, cellW, cellH, 8), {
      x,
      y: top,
      color: color(TILE),
      borderColor: color(TILE_LINE),
      borderWidth: 0.75,
    });
    page.drawText(String(i + 1).padStart(2, '0'), {
      x: x + 10,
      y: top - 15,
      size: 7.5,
      font: bold,
      color: color(BRAND),
    });
    page.drawText(word, { x: x + 10, y: top - 34, size: 13, font: bold, color: color(INK) });
  });
  y = gridTop - 6 * (cellH + gap) - 8;

  // Warning box.
  const boxW = W - 2 * M;
  const warn = wrap(text.warning, 9.5, boxW - 28, bold);
  const boxH = 22 + warn.length * 13;
  page.drawSvgPath(roundedRect(0, 0, boxW, boxH, 8), {
    x: M,
    y,
    color: rgb(0.95, 0.955, 1),
    borderColor: color(BRAND),
    borderWidth: 0.75,
  });
  warn.forEach((line, i) => {
    page.drawText(line, {
      x: M + 14,
      y: y - 17 - i * 13,
      size: 9.5,
      font: bold,
      color: color(INK),
    });
  });
  y -= boxH + 24;

  // Safekeeping notes.
  for (const note of text.notes) {
    const lines = wrap(note, 9.5, boxW - 16);
    page.drawCircle({ x: M + 3, y: y + 3, size: 1.8, color: color(BRAND) });
    lines.forEach((line, i) => {
      page.drawText(line, { x: M + 14, y: y - i * 13, size: 9.5, font, color: color(INK) });
    });
    y -= lines.length * 13 + 8;
  }

  // Footer.
  page.drawLine({
    start: { x: M, y: M + 14 },
    end: { x: W - M, y: M + 14 },
    thickness: 0.6,
    color: color(TILE_LINE),
  });
  page.drawText(text.footer, { x: M, y: M, size: 8, font, color: color(MUTED) });
  const site = 'maildots.com';
  page.drawText(site, {
    x: W - M - font.widthOfTextAtSize(site, 8),
    y: M,
    size: 8,
    font: bold,
    color: color(BRAND),
  });

  return doc.save();
}
