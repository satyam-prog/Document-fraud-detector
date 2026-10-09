import exifr from "exifr";
import * as pdfjs from "pdfjs-dist";
import pdfWorkerUrl from "pdfjs-dist/build/pdf.worker.min.mjs?url";
import { createWorker } from "tesseract.js";

pdfjs.GlobalWorkerOptions.workerSrc = pdfWorkerUrl;

export type Row = Record<string, string | number | boolean>;

export interface ForensicData {
  Width: number;
  Height: number;
  "Mean brightness": number;
  "Contrast score": number;
  "Edge density": number;
}

const EDITING_SOFTWARE = /Adobe|Photoshop|GIMP|Lightroom|Canva/i;

const ID_PATTERN = String.raw`\b(?:[A-Z]{2,5}[-\s]?\d{4,8}|[A-Z0-9]{6,12})\b`;
const DATE_PATTERN = String.raw`\b(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}\s+[A-Za-z]{3,9}\s+\d{4})\b`;
const COMBINED_PATTERN = String.raw`\b(?:[A-Z]{2,5}[-\s]?\d{4,8}|[A-Z0-9]{6,12}|(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}\s+[A-Za-z]{3,9}\s+\d{4}))\b`;

const round = (value: number, digits: number) => Number(value.toFixed(digits));

export function getBasicFileDetails(file: File): Row {
  return {
    Filename: file.name,
    "Size (bytes)": file.size,
    Type: file.type || "Unknown",
  };
}

export async function computeSha256(file: File): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", await file.arrayBuffer());
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

export async function verifyHash(hash: string): Promise<boolean> {
  const res = await fetch("/api/verify-hash", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ hash }),
  });
  if (!res.ok) throw new Error(`Hash verification failed (${res.status})`);
  const data = (await res.json()) as { verified: boolean };
  return data.verified;
}

export function calculateOverallRisk(
  integrityVerified: boolean,
  exifSoftwareFlag = false,
  forensicData?: ForensicData,
): { score: number; label: string } {
  let score = 0;
  if (!integrityVerified) score += 60;
  if (exifSoftwareFlag) score += 15;
  if (forensicData) {
    if (forensicData["Contrast score"] > 80) score += 10;
    if (forensicData["Edge density"] > 7) score += 10;
  }
  score = Math.min(score, 100);

  let label: string;
  if (score < 25) label = "Low Risk";
  else if (score < 60) label = "Monitor";
  else if (score < 85) label = "High Risk";
  else label = "Critical";

  return { score, label };
}

export function findRegexMatches(text: string): Row[] {
  const patterns: Record<string, string> = {
    "Potential ID / Reference": ID_PATTERN,
    "Potential Date": DATE_PATTERN,
  };
  const matches: Row[] = [];
  for (const [label, pattern] of Object.entries(patterns)) {
    for (const match of text.matchAll(new RegExp(pattern, "gi"))) {
      matches.push({ Type: label, Match: match[0] });
    }
  }
  return matches;
}

export function escapeHtml(text: string): string {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

export function highlightRegexMatches(text: string): string {
  return escapeHtml(text).replace(new RegExp(COMBINED_PATTERN, "gi"), (m) => `<mark>${m}</mark>`);
}

// ---------- Images ----------

export async function loadImage(file: File): Promise<HTMLImageElement> {
  const url = URL.createObjectURL(file);
  const img = new Image();
  img.src = url;
  await img.decode();
  return img;
}

function getPixels(source: CanvasImageSource, width: number, height: number): ImageData {
  const canvas = document.createElement("canvas");
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext("2d", { willReadFrequently: true })!;
  ctx.fillStyle = "#fff";
  ctx.fillRect(0, 0, width, height);
  ctx.drawImage(source, 0, 0, width, height);
  return ctx.getImageData(0, 0, width, height);
}

export function analyzeImageForensics(img: HTMLImageElement): ForensicData {
  const width = img.naturalWidth;
  const height = img.naturalHeight;
  const { data } = getPixels(img, width, height);

  // RGB values only (skip alpha), matching numpy over an H x W x 3 array.
  const n = width * height * 3;
  let sum = 0;
  let sumSq = 0;
  for (let i = 0; i < data.length; i += 4) {
    for (let c = 0; c < 3; c++) {
      const v = data[i + c];
      sum += v;
      sumSq += v * v;
    }
  }
  const mean = sum / n;
  const contrast = Math.sqrt(Math.max(sumSq / n - mean * mean, 0));

  // Mean absolute vertical difference between adjacent rows.
  const rowStride = width * 4;
  let edgeSum = 0;
  for (let i = 0; i < data.length - rowStride; i += 4) {
    for (let c = 0; c < 3; c++) {
      edgeSum += Math.abs(data[i + rowStride + c] - data[i + c]);
    }
  }
  const edgeCount = Math.max((height - 1) * width * 3, 1);

  return {
    Width: width,
    Height: height,
    "Mean brightness": round(mean, 2),
    "Contrast score": round(contrast, 2),
    "Edge density": round(edgeSum / edgeCount, 4),
  };
}

export async function extractImageExif(file: File): Promise<Row[]> {
  let exif: Record<string, unknown> | undefined;
  try {
    exif = await exifr.parse(file, { tiff: true, exif: true, gps: true, xmp: true, mergeOutput: true });
  } catch {
    return [];
  }
  if (!exif) return [];

  return Object.entries(exif).map(([tag, value]) => {
    let printable: string;
    try {
      printable = value instanceof Date ? value.toISOString() : typeof value === "object" ? JSON.stringify(value) : String(value);
    } catch {
      printable = "Unprintable value";
    }
    return { Tag: tag, Value: printable };
  });
}

export function hasEditingSoftware(exifRows: Row[]): boolean {
  return exifRows.some((row) => EDITING_SOFTWARE.test(String(row.Value)));
}

// JET colormap endpoints for a binary threshold image (0 -> dark blue, 255 -> dark red).
const JET_LOW = [0, 0, 128];
const JET_HIGH = [128, 0, 0];

export async function computeEla(img: HTMLImageElement, quality = 0.95): Promise<string> {
  const width = img.naturalWidth;
  const height = img.naturalHeight;
  const original = getPixels(img, width, height);

  const canvas = document.createElement("canvas");
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext("2d", { willReadFrequently: true })!;
  ctx.putImageData(original, 0, 0);

  const jpegBlob = await new Promise<Blob>((resolve, reject) =>
    canvas.toBlob((b) => (b ? resolve(b) : reject(new Error("JPEG encoding failed"))), "image/jpeg", quality),
  );
  const recompressed = getPixels(await createImageBitmap(jpegBlob), width, height);

  const out = ctx.createImageData(width, height);
  const a = original.data;
  const b = recompressed.data;
  for (let i = 0; i < a.length; i += 4) {
    const gray =
      0.299 * Math.abs(a[i] - b[i]) + 0.587 * Math.abs(a[i + 1] - b[i + 1]) + 0.114 * Math.abs(a[i + 2] - b[i + 2]);
    const color = gray > 20 ? JET_HIGH : JET_LOW;
    out.data[i] = color[0];
    out.data[i + 1] = color[1];
    out.data[i + 2] = color[2];
    out.data[i + 3] = 255;
  }
  ctx.putImageData(out, 0, 0);
  return canvas.toDataURL("image/png");
}

export async function extractImageText(file: File, onProgress?: (pct: number) => void): Promise<string> {
  try {
    const worker = await createWorker("eng", 1, {
      logger: (m) => {
        if (m.status === "recognizing text") onProgress?.(Math.round(m.progress * 100));
      },
    });
    const { data } = await worker.recognize(file);
    await worker.terminate();
    const cleaned = data.text.trim();
    return cleaned || "No readable text found in the image.";
  } catch (err) {
    return `OCR failed: ${(err as Error).message}`;
  }
}

// ---------- PDFs ----------

export async function analyzePdf(file: File): Promise<{ metadata: Row; text: string }> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  let doc: pdfjs.PDFDocumentProxy;
  try {
    doc = await pdfjs.getDocument({ data: bytes }).promise;
  } catch (err) {
    const encrypted = (err as Error).name === "PasswordException";
    return {
      metadata: { Pages: "N/A", Encrypted: encrypted },
      text: `Unable to read PDF text: ${(err as Error).message}`,
    };
  }

  const { info } = (await doc.getMetadata()) as { info: Record<string, unknown> };
  const field = (key: string) => (info?.[key] ? String(info[key]) : "N/A");
  const metadata: Row = {
    Pages: doc.numPages,
    Title: field("Title"),
    Author: field("Author"),
    Subject: field("Subject"),
    Creator: field("Creator"),
    Producer: field("Producer"),
    "Creation Date": field("CreationDate"),
    "Modification Date": field("ModDate"),
    Encrypted: Boolean(info?.IsEncrypted) || Boolean(info?.EncryptFilterName),
  };

  const pages: string[] = [];
  for (let p = 1; p <= doc.numPages; p++) {
    const page = await doc.getPage(p);
    const content = await page.getTextContent();
    const pageText = content.items
      .map((item) => ("str" in item ? item.str + (item.hasEOL ? "\n" : "") : ""))
      .join("");
    if (pageText.trim()) pages.push(pageText);
  }
  await doc.loadingTask.destroy();

  const combined = pages.join("\n\n").trim();
  return { metadata, text: combined || "No readable text found in the PDF." };
}
