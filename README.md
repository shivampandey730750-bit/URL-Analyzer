# ScamLens — Scam Awareness Demo

ScamLens is a responsive educational web app for checking suspicious URLs, SMS messages, email content, and screenshot text. It also includes a prepared-response cybersecurity assistant and a small local history of recent checks.

## Features

- Scam-awareness homepage with analyzer links, recent local checks, and safety tips.
- URL pattern checks for insecure connections, IP-based hosts, lookalike brand names, reserved `.example` test domains, and suspicious prize/claim wording. HTTPS is not treated as proof that a site is trustworthy.
- SMS and email checks for common urgency, credential, prize, payment, and impersonation warning signs.
- Screenshot upload and local preview, with a text field to check content visible in the image. This demo does not perform OCR.
- A lightweight assistant with prepared educational guidance; it is not connected to a live AI service.
- Responsive layout and mobile navigation.

## Important

This is an educational demo, not a real-time threat-intelligence service or a guarantee that content is safe. Analysis runs in the browser using basic text and URL pattern checks. Screenshot files are previewed locally and are not uploaded. Do not paste real passwords, OTPs, PINs, or payment details into the app. Verify suspicious requests through an organization's official website or contact channel.

## Run locally

Requirements: Node.js 18+.

```bash
npm install
npm run dev
```

Open the local URL printed by Vite, normally `http://localhost:5173`.

## Build

```bash
npm run build
npm run preview
```
