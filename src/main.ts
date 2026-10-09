import "./style.css";
import {
  analyzeImageForensics,
  analyzePdf,
  calculateOverallRisk,
  computeEla,
  computeSha256,
  escapeHtml,
  extractImageExif,
  extractImageText,
  findRegexMatches,
  getBasicFileDetails,
  hasEditingSoftware,
  highlightRegexMatches,
  loadImage,
  verifyHash,
  type ForensicData,
  type Row,
} from "./analysis";

const input = document.querySelector<HTMLInputElement>("#file-input")!;
const dropzone = document.querySelector<HTMLLabelElement>("#dropzone")!;
const results = document.querySelector<HTMLElement>("#results")!;

const IMAGE_EXT = /\.(jpe?g|png)$/i;
const PDF_EXT = /\.pdf$/i;

let runId = 0;

input.addEventListener("change", () => {
  if (input.files?.[0]) void inspect(input.files[0]);
});
dropzone.addEventListener("dragover", (e) => {
  e.preventDefault();
  dropzone.classList.add("dragging");
});
dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragging"));
dropzone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropzone.classList.remove("dragging");
  const file = e.dataTransfer?.files[0];
  if (file) void inspect(file);
});

// ---------- Rendering helpers ----------

function el(html: string): HTMLElement {
  const t = document.createElement("template");
  t.innerHTML = html.trim();
  return t.content.firstElementChild as HTMLElement;
}

function section(title: string): HTMLElement {
  const s = el(`<div class="block"><h3>${escapeHtml(title)}</h3></div>`);
  results.append(s);
  return s;
}

function table(rows: Row[], columns?: string[]): string {
  const cols = columns ?? Object.keys(rows[0] ?? {});
  const head = cols.map((c) => `<th>${escapeHtml(c)}</th>`).join("");
  const body = rows
    .map((r) => `<tr>${cols.map((c) => `<td>${escapeHtml(String(r[c] ?? ""))}</td>`).join("")}</tr>`)
    .join("");
  return `<div class="table-wrap"><table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`;
}

function alert(kind: "info" | "success" | "warning" | "error", html: string): string {
  return `<div class="alert ${kind}">${html}</div>`;
}

function renderSummaryCards(integrityVerified: boolean, exifSoftwareFlag: boolean, forensic?: ForensicData) {
  const { score, label } = calculateOverallRisk(integrityVerified, exifSoftwareFlag, forensic);
  const visual =
    exifSoftwareFlag || (forensic && (forensic["Contrast score"] > 80 || forensic["Edge density"] > 7))
      ? "Detected"
      : "Normal";
  results.append(
    el(`
      <div class="cards">
        <div class="metric-card">
          <div class="metric-title">Integrity</div>
          <div class="metric-value">${integrityVerified ? "OK" : "Flagged"}</div>
          <div class="metric-sub">Hash verification status</div>
        </div>
        <div class="metric-card">
          <div class="metric-title">Risk Score</div>
          <div class="metric-value">${score}%</div>
          <div class="metric-sub">${label}</div>
        </div>
        <div class="metric-card">
          <div class="metric-title">Visual Signals</div>
          <div class="metric-value">${visual}</div>
          <div class="metric-sub">Metadata &amp; ELA analysis</div>
        </div>
      </div>`),
  );
}

async function renderVerification(file: File): Promise<boolean> {
  const s = section("Cryptographic Verification");
  const hash = await computeSha256(file);
  s.append(el(`<pre class="code">SHA-256: ${hash}</pre>`));

  let verified = false;
  try {
    verified = await verifyHash(hash);
  } catch (err) {
    s.append(el(alert("warning", `Could not reach the hash registry: ${escapeHtml((err as Error).message)}`)));
  }

  if (verified) {
    s.append(el(`<div class="badge verified">VERIFIED</div>`));
    s.append(el(alert("success", "The uploaded file matches a stored authentic hash in the database.")));
  } else {
    s.append(el(`<div class="badge tampered">TAMPERING DETECTED</div>`));
    s.append(el(alert("error", "The uploaded file does not match the authentic hashes stored in the database.")));
  }
  return verified;
}

function renderExtractedText(text: string) {
  const s = section("Extracted Data");
  const area = el(`<textarea readonly rows="12"></textarea>`) as HTMLTextAreaElement;
  area.value = text;
  s.append(area);

  const m = section("Detected ID / Date Matches");
  const matches = findRegexMatches(text);
  m.append(
    el(
      matches.length
        ? table(matches, ["Type", "Match"])
        : alert("info", "No obvious ID numbers or dates were detected in the extracted text."),
    ),
  );

  const h = section("Highlighted Matches");
  h.append(el(`<div class="highlighted">${highlightRegexMatches(text)}</div>`));
}

function loading(message: string): HTMLElement {
  const node = el(`<div class="loading"><span class="spinner"></span><span class="msg">${escapeHtml(message)}</span></div>`);
  results.append(node);
  return node;
}

// ---------- Pipelines ----------

async function renderImage(file: File, integrityVerified: boolean, id: number) {
  const img = await loadImage(file);

  const preview = section("Document preview");
  preview.append(el(`<figure><img class="preview" src="${img.src}" alt="" /><figcaption>${escapeHtml(file.name)}</figcaption></figure>`));

  const visual = section("Visual Forensics");
  const exifRows = await extractImageExif(file);
  const exifSoftwareFlag = hasEditingSoftware(exifRows);
  if (!exifRows.length) {
    visual.append(el(alert("info", "No EXIF metadata found in this image.")));
  } else {
    visual.append(el(table(exifRows, ["Tag", "Value"])));
    if (exifSoftwareFlag) {
      visual.append(
        el(alert("warning", "EXIF metadata suggests the image was edited with software such as Adobe Photoshop or similar tools.")),
      );
    }
  }

  const forensic = analyzeImageForensics(img);
  renderSummaryCards(integrityVerified, exifSoftwareFlag, forensic);

  const elaUrl = await computeEla(img, 0.95);
  if (id !== runId) return;
  results.append(
    el(`
      <div class="two-col">
        <figure><figcaption>Original image</figcaption><img src="${img.src}" alt="Original" /></figure>
        <figure><figcaption>ELA heatmap</figcaption><img src="${elaUrl}" alt="ELA heatmap" /></figure>
      </div>`),
  );
  results.append(
    el(alert("info", "Areas with stronger ELA contrast may indicate digital tampering, splicing, or region-based editing.")),
  );

  const ind = section("Image forensic indicators");
  ind.append(el(table([forensic as unknown as Row])));

  const flags: string[] = [];
  if (forensic["Contrast score"] > 80) flags.push("High contrast may indicate local enhancement or manipulation.");
  if (forensic["Edge density"] > 7) flags.push("Unusually high edge activity may suggest artifact injection or tampering.");
  ind.append(
    el(
      flags.length
        ? alert("warning", `<strong>Possible forgery indicators detected</strong><ul>${flags.map((f) => `<li>${f}</li>`).join("")}</ul>`)
        : alert("success", "No obvious visual anomalies detected from the basic inspection metrics."),
    ),
  );

  const ocr = loading("Running OCR…");
  const text = await extractImageText(file, (pct) => {
    ocr.querySelector(".msg")!.textContent = `Running OCR… ${pct}%`;
  });
  ocr.remove();
  if (id !== runId) return;
  renderExtractedText(text);
}

async function renderPdf(file: File, integrityVerified: boolean, id: number) {
  renderSummaryCards(integrityVerified, false);

  const s = section("PDF metadata overview");
  const busy = loading("Parsing PDF…");
  const { metadata, text } = await analyzePdf(file);
  busy.remove();
  if (id !== runId) return;
  s.append(el(table([metadata])));
  renderExtractedText(text);
}

async function inspect(file: File) {
  const id = ++runId;
  results.replaceChildren();

  if (!IMAGE_EXT.test(file.name) && !PDF_EXT.test(file.name)) {
    results.append(el(alert("warning", "Unsupported file type.")));
    return;
  }

  try {
    const details = section("File details");
    details.append(el(table([getBasicFileDetails(file)])));

    const integrityVerified = await renderVerification(file);
    if (id !== runId) return;

    if (IMAGE_EXT.test(file.name)) await renderImage(file, integrityVerified, id);
    else await renderPdf(file, integrityVerified, id);
  } catch (err) {
    if (id === runId) results.append(el(alert("error", `Analysis failed: ${escapeHtml((err as Error).message)}`)));
  }
}
