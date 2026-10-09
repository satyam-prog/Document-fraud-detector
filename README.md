# Document-fraud-detector

Inspect PDFs, JPGs, and PNGs for signs of forgery: SHA-256 verification against a registry of authentic hashes, EXIF metadata checks, Error Level Analysis (ELA), basic image forensics, OCR text extraction, and ID/date pattern detection.

## Netlify app

The deployable app is a Vite site (`index.html`, `src/`) that does all document analysis in the browser
(tesseract.js for OCR, pdf.js for PDFs, exifr for EXIF). Only the file's SHA-256 hash is sent to the
`/api/verify-hash` Netlify Function, which looks it up in Netlify Database (`db/schema.ts`; migrations in
`netlify/database/migrations/`).

```bash
npm install
netlify dev
```

## Original Streamlit app

`app.py` is the original Python/Streamlit version and can still be run locally with `streamlit run app.py`.
